use crate::{
    compact_formats::{CompactBlock, CompactTx, TreeState},
    grpc_connector::GrpcConnector,
    lightclient::lightclient_config::{LightClientConfig, MAX_REORG},
    lightwallet::{
        data::{BlockData, WalletTx, WitnessCache},
        wallet_txns::WalletTxns,
    },
};

use http::Uri;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{
        mpsc::{self, UnboundedSender},
        RwLock,
    },
    task::{yield_now, JoinHandle},
    time::sleep,
};
use zcash_primitives::{
    consensus::BlockHeight,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    primitives::Nullifier,
    sapling::Node,
    transaction::TxId,
};

use super::{fixed_size_buffer::FixedSizeBuffer, sync_status::SyncStatus};

pub struct BlockAndWitnessData {
    // List of all blocks and their hashes/commitment trees. Stored from smallest block height to tallest block height
    blocks: Arc<RwLock<Vec<BlockData>>>,

    // List of existing blocks in the wallet. Used for reorgs
    existing_blocks: Arc<RwLock<Vec<BlockData>>>,

    // List of sapling tree states that were fetched from the server, which need to be verified before we return from the
    // function
    verification_list: Arc<RwLock<Vec<TreeState>>>,

    // How many blocks to process at a time.
    batch_size: u64,

    // Link to the syncstatus where we can update progress
    sync_status: Arc<RwLock<SyncStatus>>,

    sapling_activation_height: u64,
}

impl BlockAndWitnessData {
    pub fn new(config: &LightClientConfig, sync_status: Arc<RwLock<SyncStatus>>) -> Self {
        Self {
            blocks: Arc::new(RwLock::new(vec![])),
            existing_blocks: Arc::new(RwLock::new(vec![])),
            verification_list: Arc::new(RwLock::new(vec![])),
            batch_size: 25_000,
            sync_status,
            sapling_activation_height: config.sapling_activation_height,
        }
    }

    #[cfg(test)]
    pub fn new_with_batchsize(config: &LightClientConfig, batch_size: u64) -> Self {
        let mut s = Self::new(config, Arc::new(RwLock::new(SyncStatus::default())));
        s.batch_size = batch_size;

        s
    }

    pub async fn setup_sync(&mut self, existing_blocks: Vec<BlockData>) {
        if !existing_blocks.is_empty() {
            if existing_blocks.first().unwrap().height < existing_blocks.last().unwrap().height {
                panic!("Blocks are in wrong order");
            }
        }
        self.verification_list.write().await.clear();

        self.blocks.write().await.clear();

        self.existing_blocks.write().await.clear();
        self.existing_blocks.write().await.extend(existing_blocks);
    }

    // Finish up the sync. This method will delete all the elements in the blocks, and return
    // the top `num` blocks
    pub async fn finish_get_blocks(&self, num: usize) -> Vec<BlockData> {
        self.verification_list.write().await.clear();

        {
            let mut blocks = self.blocks.write().await;
            blocks.extend(self.existing_blocks.write().await.drain(..));

            blocks.truncate(num);
            blocks.to_vec()
        }
    }

    pub async fn get_ctx_for_nf_at_height(&self, nullifier: &Nullifier, height: u64) -> (CompactTx, u32) {
        self.wait_for_block(height).await;

        let cb = {
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - height;
            let bd = blocks.get(pos as usize).unwrap();

            bd.cb()
        };

        for ctx in &cb.vtx {
            for cs in &ctx.spends {
                if cs.nf == nullifier.to_vec() {
                    return (ctx.clone(), cb.time);
                }
            }
        }

        panic!("Tx not found");
    }

    // Invalidate the block (and wallet txns associated with it) at the given block height
    pub async fn invalidate_block(
        reorg_height: u64,
        existing_blocks: Arc<RwLock<Vec<BlockData>>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
    ) {
        // First, pop the first block (which is the top block) in the existing_blocks.
        let top_wallet_block = existing_blocks.write().await.drain(0..1).next().unwrap();
        if top_wallet_block.height != reorg_height {
            panic!("Wrong block reorg'd");
        }

        // Remove all wallet txns at the height
        wallet_txns.write().await.remove_txns_at_height(reorg_height);
    }

    /// Start a new sync where we ingest all the blocks
    pub async fn start(
        &self,
        start_block: u64,
        end_block: u64,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        reorg_tx: UnboundedSender<Option<u64>>,
    ) -> (JoinHandle<Result<u64, String>>, UnboundedSender<CompactBlock>) {
        //info!("Starting node and witness sync");
        let batch_size = self.batch_size;

        // Create a new channel where we'll receive the blocks
        let (tx, mut rx) = mpsc::unbounded_channel::<CompactBlock>();

        let blocks = self.blocks.clone();
        let existing_blocks = self.existing_blocks.clone();

        let sync_status = self.sync_status.clone();
        sync_status.write().await.blocks_total = start_block - end_block + 1;

        // Handle 0:
        // Process the incoming compact blocks, collect them into `BlockData` and pass them on
        // for further processing.
        // We also trigger the node commitment tree update every `batch_size` blocks using the Sapling tree fetched
        // from the server temporarily, but we verify it before we return it

        let h0: JoinHandle<Result<u64, String>> = tokio::spawn(async move {
            // Temporary holding place for blocks while we process them.
            let mut blks = vec![];
            let mut earliest_block_height = 0;

            // Reorg stuff
            let mut last_block_expecting = end_block;

            // We'll process 25_000 blocks at a time.
            while let Some(cb) = rx.recv().await {
                if cb.height % batch_size == 0 {
                    if !blks.is_empty() {
                        // Add these blocks to the list
                        sync_status.write().await.blocks_done += blks.len() as u64;
                        blocks.write().await.append(&mut blks);
                    }
                }

                // Check if this is the last block we are expecting
                if cb.height == last_block_expecting {
                    // Check to see if the prev block's hash matches, and if it does, finish the task
                    let reorg_block = match existing_blocks.read().await.first() {
                        Some(top_block) => {
                            if top_block.hash() == cb.prev_hash().to_string() {
                                None
                            } else {
                                // send a reorg signal
                                Some(top_block.height)
                            }
                        }
                        None => {
                            // There is no top wallet block, so we can't really check for reorgs.
                            None
                        }
                    };

                    // If there was a reorg, then we need to invalidate the block and its associated txns
                    if let Some(reorg_height) = reorg_block {
                        Self::invalidate_block(reorg_height, existing_blocks.clone(), wallet_txns.clone()).await;
                        last_block_expecting = reorg_height;
                    }
                    reorg_tx.send(reorg_block).unwrap();
                }

                earliest_block_height = cb.height;
                blks.push(BlockData::new(cb));
            }

            if !blks.is_empty() {
                // We'll now dispatch these blocks for updating the witness
                sync_status.write().await.blocks_done += blks.len() as u64;
                blocks.write().await.append(&mut blks);
            }

            Ok(earliest_block_height)
        });

        // Handle: Final
        // Join all the handles
        let h = tokio::spawn(async move {
            let earliest_block = h0.await.map_err(|e| format!("Error processing blocks: {}", e))??;

            // Return the earlist block that was synced, accounting for all reorgs
            return Ok(earliest_block);
        });

        return (h, tx);
    }

    async fn wait_for_first_block(&self) -> u64 {
        while self.blocks.read().await.is_empty() {
            yield_now().await;
            sleep(Duration::from_millis(100)).await;

            //info!("Waiting for first block, blocks are empty!");
        }

        self.blocks.read().await.first().unwrap().height
    }

    async fn wait_for_block(&self, height: u64) {
        self.wait_for_first_block().await;

        while self.blocks.read().await.last().unwrap().height > height {
            yield_now().await;
            sleep(Duration::from_millis(100)).await;

            // info!(
            //     "Waiting for block {}, current at {}",
            //     height,
            //     self.blocks.read().await.last().unwrap().height
            // );
        }
    }

    pub(crate) async fn is_nf_spent(&self, nf: Nullifier, after_height: u64) -> Option<u64> {
        self.wait_for_block(after_height).await;

        {
            // Read Lock
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - after_height;
            let nf = nf.to_vec();

            for i in (0..pos + 1).rev() {
                let cb = &blocks.get(i as usize).unwrap().cb();
                for ctx in &cb.vtx {
                    for cs in &ctx.spends {
                        if cs.nf == nf {
                            return Some(cb.height);
                        }
                    }
                }
            }
        }

        None
    }

    pub async fn get_block_timestamp(&self, height: &BlockHeight) -> u32 {
        let height = u64::from(*height);
        self.wait_for_block(height).await;

        {
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - height;
            blocks.get(pos as usize).unwrap().cb().time
        }
    }

    pub async fn get_note_witness(
        &self,
        uri: Uri,
        height: BlockHeight,
        tx_num: usize,
        output_num: usize,
    ) -> Result<IncrementalWitness<Node>, String> {
        // Get the previous block's height, because that block's sapling tree is the tree state at the start
        // of the requested block.
        let prev_height = { u64::from(height) - 1 };

        let (cb, mut tree) = {
            // Prev height could be in the existing blocks, too, so check those before checking the current blocks.
            let existing_blocks = self.existing_blocks.read().await;
            let tree = {
                let maybe_tree = if prev_height < self.sapling_activation_height {
                    Some(CommitmentTree::empty())
                } else if !existing_blocks.is_empty() && existing_blocks.first().unwrap().height == prev_height {
                    existing_blocks.first().unwrap().tree().clone()
                } else {
                    None
                };

                match maybe_tree {
                    Some(t) => t,
                    None => {
                        let tree_state = GrpcConnector::get_sapling_tree(uri, prev_height).await?;
                        let sapling_tree = hex::decode(&tree_state.tree).unwrap();
                        self.verification_list.write().await.push(tree_state);
                        CommitmentTree::read(&sapling_tree[..]).map_err(|e| format!("{}", e))?
                    }
                }
            };

            // Get the current compact block
            let cb = {
                let height = u64::from(height);
                self.wait_for_block(height).await;

                {
                    let mut blocks = self.blocks.write().await;

                    let pos = blocks.first().unwrap().height - height;
                    let bd = blocks.get_mut(pos as usize).unwrap();
                    bd.set_tree(tree.clone());

                    bd.cb()
                }
            };

            (cb, tree)
        };

        // Go over all the outputs. Remember that all the numbers are inclusive, i.e., we have to scan upto and including
        // block_height, tx_num and output_num
        for (t_num, ctx) in cb.vtx.iter().enumerate() {
            for (o_num, co) in ctx.outputs.iter().enumerate() {
                let node = Node::new(co.cmu().unwrap().into());
                tree.append(node).unwrap();
                if t_num == tx_num && o_num == output_num {
                    return Ok(IncrementalWitness::from_tree(&tree));
                }
            }
        }

        Err("Not found!".to_string())
    }

    // Stream all the outputs start at the block till the highest block available.
    pub(crate) async fn update_witness_after_block(&self, witnesses: WitnessCache) -> WitnessCache {
        let height = witnesses.top_height + 1;

        // Check if we've already synced all the requested blocks
        if height > self.wait_for_first_block().await {
            return witnesses;
        }
        self.wait_for_block(height).await;

        let mut fsb = FixedSizeBuffer::new(MAX_REORG);

        let top_block = {
            let mut blocks = self.blocks.read().await;
            let top_block = blocks.first().unwrap().height;
            let pos = top_block - height;

            // Get the last witness, and then use that.
            let mut w = witnesses.last().unwrap().clone();
            witnesses.into_fsb(&mut fsb);

            for i in (0..pos + 1).rev() {
                let cb = &blocks.get(i as usize).unwrap().cb();
                for ctx in &cb.vtx {
                    for co in &ctx.outputs {
                        let node = Node::new(co.cmu().unwrap().into());
                        w.append(node).unwrap();
                    }
                }

                // At the end of every block, update the witness in the array
                fsb.push(w.clone());

                if i % 10_000 == 0 {
                    // Every 10k blocks, give up the lock, let other threads proceed and then re-acquire it
                    drop(blocks);
                    yield_now().await;
                    blocks = self.blocks.read().await;
                }
            }

            top_block
        };

        return WitnessCache::new(fsb.into_vec(), top_block);
    }

    pub(crate) async fn update_witness_after_pos(
        &self,
        height: &BlockHeight,
        txid: &TxId,
        output_num: u32,
        witnesses: WitnessCache,
    ) -> WitnessCache {
        let height = u64::from(*height);
        self.wait_for_block(height).await;

        // We'll update the rest of the block's witnesses here. Notice we pop the last witness, and we'll
        // add the updated one back into the array at the end of this function.
        let mut w = witnesses.last().unwrap().clone();

        {
            let blocks = self.blocks.read().await;
            let pos = blocks.first().unwrap().height - height;

            let mut txid_found = false;
            let mut output_found = false;

            let cb = &blocks.get(pos as usize).unwrap().cb();
            for ctx in &cb.vtx {
                if !txid_found && WalletTx::new_txid(&ctx.hash) == *txid {
                    txid_found = true;
                }
                for j in 0..ctx.outputs.len() as u32 {
                    // If we've already passed the txid and output_num, stream the results
                    if txid_found && output_found {
                        let co = ctx.outputs.get(j as usize).unwrap();
                        let node = Node::new(co.cmu().unwrap().into());
                        w.append(node).unwrap();
                    }

                    // Mark as found if we reach the txid and output_num. Starting with the next output,
                    // we'll stream all the data to the requester
                    if !output_found && txid_found && j == output_num {
                        output_found = true;
                    }
                }
            }

            if !txid_found || !output_found {
                panic!("Txid or output not found");
            }
        }

        // Replace the last witness in the vector with the newly computed one.
        let witnesses = WitnessCache::new(vec![w], height);

        return self.update_witness_after_block(witnesses).await;
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::blaze::sync_status::SyncStatus;
    use crate::lightwallet::wallet_txns::WalletTxns;
    use crate::{
        blaze::test_utils::{FakeCompactBlock, FakeCompactBlockList},
        lightclient::lightclient_config::LightClientConfig,
        lightwallet::data::BlockData,
    };
    use futures::future::join_all;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use tokio::sync::RwLock;
    use tokio::{sync::mpsc::unbounded_channel, task::JoinHandle};
    use zcash_primitives::block::BlockHash;

    use super::BlockAndWitnessData;

    #[tokio::test]
    async fn setup_finish_simple() {
        let mut nw = BlockAndWitnessData::new_with_batchsize(
            &LightClientConfig::create_unconnected("main".to_string(), None),
            25_000,
        );

        let cb = FakeCompactBlock::new(1, BlockHash([0u8; 32])).into_cb();
        let blks = vec![BlockData::new(cb)];

        nw.setup_sync(blks.clone()).await;
        let finished_blks = nw.finish_get_blocks(1).await;

        assert_eq!(blks[0].hash(), finished_blks[0].hash());
        assert_eq!(blks[0].height, finished_blks[0].height);
    }

    #[tokio::test]
    async fn setup_finish_large() {
        let mut nw = BlockAndWitnessData::new_with_batchsize(
            &LightClientConfig::create_unconnected("main".to_string(), None),
            25_000,
        );

        let existing_blocks = FakeCompactBlockList::new(200).into_blockdatas();
        nw.setup_sync(existing_blocks.clone()).await;
        let finished_blks = nw.finish_get_blocks(100).await;

        assert_eq!(finished_blks.len(), 100);

        for (i, finished_blk) in finished_blks.into_iter().enumerate() {
            assert_eq!(existing_blocks[i].hash(), finished_blk.hash());
            assert_eq!(existing_blocks[i].height, finished_blk.height);
        }
    }

    #[tokio::test]
    async fn from_sapling_genesis() {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let blocks = FakeCompactBlockList::new(200).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let sync_status = Arc::new(RwLock::new(SyncStatus::default()));
        let mut nw = BlockAndWitnessData::new(&config, sync_status);
        nw.setup_sync(vec![]).await;

        let (reorg_tx, mut reorg_rx) = unbounded_channel();

        let (h, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                reorg_tx,
            )
            .await;

        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            for block in blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block);

        join_all(vec![send_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn with_existing_batched() {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let mut blocks = FakeCompactBlockList::new(200).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        // Use the first 50 blocks as "existing", and then sync the other 150 blocks.
        let existing_blocks = blocks.split_off(150);

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let mut nw = BlockAndWitnessData::new_with_batchsize(&config, 25);
        nw.setup_sync(existing_blocks).await;

        let (reorg_tx, mut reorg_rx) = unbounded_channel();

        let (h, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                reorg_tx,
            )
            .await;

        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            for block in blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block);

        join_all(vec![send_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();

        let finished_blks = nw.finish_get_blocks(100).await;
        assert_eq!(finished_blks.len(), 100);
        assert_eq!(finished_blks.first().unwrap().height, start_block);
        assert_eq!(finished_blks.last().unwrap().height, start_block - 100 + 1);
    }

    #[tokio::test]
    async fn with_reorg() {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let mut blocks = FakeCompactBlockList::new(100).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        // Use the first 50 blocks as "existing", and then sync the other 50 blocks.
        let existing_blocks = blocks.split_off(50);

        // The first 5 blocks, blocks 46-50 will be reorg'd, so duplicate them
        let num_reorged = 5;
        let mut reorged_blocks = existing_blocks
            .iter()
            .take(num_reorged)
            .map(|b| b.clone())
            .collect::<Vec<_>>();

        // Reset the hashes
        for i in 0..num_reorged {
            let mut hash = [0u8; 32];
            OsRng.fill_bytes(&mut hash);

            if i == 0 {
                let mut cb = blocks.pop().unwrap().cb();
                cb.prev_hash = hash.to_vec();
                blocks.push(BlockData::new(cb));
            } else {
                let mut cb = reorged_blocks[i - 1].cb();
                cb.prev_hash = hash.to_vec();
                reorged_blocks[i - 1] = BlockData::new(cb);
            }

            let mut cb = reorged_blocks[i].cb();
            cb.hash = hash.to_vec();
            reorged_blocks[i] = BlockData::new(cb);
        }
        {
            let mut cb = reorged_blocks[4].cb();
            cb.prev_hash = existing_blocks
                .iter()
                .find(|b| b.height == 45)
                .unwrap()
                .cb()
                .hash
                .to_vec();
            reorged_blocks[4] = BlockData::new(cb);
        }

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let sync_status = Arc::new(RwLock::new(SyncStatus::default()));
        let mut nw = BlockAndWitnessData::new(&config, sync_status);
        nw.setup_sync(existing_blocks).await;

        let (reorg_tx, mut reorg_rx) = unbounded_channel();

        let (h, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                reorg_tx,
            )
            .await;

        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            // Send the normal blocks
            for block in blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }

            // Expect and send the reorg'd blocks
            let mut expecting_height = 50;
            let mut sent_ctr = 0;

            while let Some(Some(h)) = reorg_rx.recv().await {
                assert_eq!(h, expecting_height);

                expecting_height -= 1;
                sent_ctr += 1;

                cb_sender
                    .send(reorged_blocks.drain(0..1).next().unwrap().cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }

            assert_eq!(sent_ctr, num_reorged);
            assert!(reorged_blocks.is_empty());

            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block - num_reorged as u64);

        join_all(vec![send_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();

        let finished_blks = nw.finish_get_blocks(100).await;
        assert_eq!(finished_blks.len(), 100);
        assert_eq!(finished_blks.first().unwrap().height, start_block);
        assert_eq!(finished_blks.last().unwrap().height, start_block - 100 + 1);

        // Verify the hashes
        for i in 0..(finished_blks.len() - 1) {
            assert_eq!(finished_blks[i].cb().prev_hash, finished_blks[i + 1].cb().hash);
            assert_eq!(finished_blks[i].hash(), finished_blks[i].cb().hash().to_string());
        }
    }
    /*
    async fn setup_for_witness_tests(
        num_blocks: u64,
        uri_fetcher: UnboundedSender<(u64, Sender<Result<TreeState, String>>)>,
    ) -> (
        JoinHandle<Result<(), String>>,
        Vec<BlockData>,
        u64,
        u64,
        BlockAndWitnessData,
    ) {
        let mut config = LightClientConfig::create_unconnected("main".to_string(), None);
        config.sapling_activation_height = 1;

        let blocks = FakeCompactBlockList::new(num_blocks).into_blockdatas();

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let sync_status = Arc::new(RwLock::new(SyncStatus::default()));
        let mut nw = BlockAndWitnessData::new(&config, sync_status);
        nw.setup_sync(vec![]).await;

        let (reorg_tx, mut reorg_rx) = unbounded_channel();

        let (h0, cb_sender) = nw
            .start(
                start_block,
                end_block,
                Arc::new(RwLock::new(WalletTxns::new())),
                reorg_tx,
            )
            .await;

        let send_blocks = blocks.clone();
        let send_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            for block in send_blocks {
                cb_sender
                    .send(block.cb())
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        let h = tokio::spawn(async move {
            let (r1, r2) = join!(h0, send_h);
            r1.map_err(|e| format!("{}", e))??;
            r2.map_err(|e| format!("{}", e))??;
            Ok(())
        });

        (h, blocks, start_block, end_block, nw)
    }
     */

    /*
    #[tokio::test]
    async fn note_witness() {
        let (uri_fetcher, mut uri_fetcher_rx) = unbounded_channel();
        let uri_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            if let Some(_req) = uri_fetcher_rx.recv().await {
                return Err(format!("Should not have requested a TreeState from the URI fetcher!"));
            }

            Ok(())
        });

        let (send_h, blocks, _, _, nw) = setup_for_witness_tests(10, uri_fetcher).await;

        // Get note witness from the very first block
        let test_h = tokio::spawn(async move {
            // Calculate the Witnesses manually, but do it reversed, because they have to be calculated from lowest height to tallest height
            let calc_witnesses: Vec<_> = blocks
                .iter()
                .rev()
                .scan(CommitmentTree::empty(), |witness, b| {
                    for node in list_all_witness_nodes(&b.cb()) {
                        witness.append(node).unwrap();
                    }

                    Some((witness.clone(), b.height))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();

            // Test data is a triple of (block_height, tx_num and output_num). Note that block_height is the actual height
            // of the block, not the index in the blocks vec. tx_num and output_num are 0-indexed
            let test_data = vec![(1, 1, 1), (1, 0, 0), (10, 1, 1), (10, 0, 0), (5, 0, 1), (5, 1, 0)];

            for (block_height, tx_num, output_num) in test_data {
                let cb = blocks.iter().find(|b| b.height == block_height).unwrap().cb();

                // Get the previous block's tree or empty
                let prev_block_tree = calc_witnesses
                    .iter()
                    .find_map(|(w, h)| if *h == block_height - 1 { Some(w.clone()) } else { None })
                    .unwrap_or(CommitmentTree::empty());

                let expected_witness = list_all_witness_nodes(&cb)
                    .into_iter()
                    .take((tx_num) * 2 + output_num + 1)
                    .fold(prev_block_tree, |mut w, n| {
                        w.append(n).unwrap();
                        w
                    });

                assert_eq!(
                    incw_to_string(&IncrementalWitness::from_tree(&expected_witness)),
                    incw_to_string(
                        &nw.get_note_witness(BlockHeight::from_u32(block_height as u32), tx_num, output_num)
                            .await
                            .unwrap()
                    )
                );
            }

            Ok(())
        });

        join_all(vec![uri_h, send_h, test_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn note_witness_updates() {
        let (uri_fetcher, mut uri_fetcher_rx) = unbounded_channel();
        let uri_h: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            if let Some(_req) = uri_fetcher_rx.recv().await {
                return Err(format!("Should not have requested a TreeState from the URI fetcher!"));
            }

            Ok(())
        });

        let (send_h, blocks, _, _, nw) = setup_for_witness_tests(10, uri_fetcher).await;

        let test_h = tokio::spawn(async move {
            let test_data = vec![(1, 1, 1), (1, 0, 0), (10, 1, 1), (10, 0, 0), (3, 0, 1), (5, 1, 0)];

            for (block_height, tx_num, output_num) in test_data {
                println!("Testing {}, {}, {}", block_height, tx_num, output_num);
                let cb = blocks.iter().find(|b| b.height == block_height).unwrap().cb();

                // Get the Incremental witness for the note
                let witness = nw
                    .get_note_witness(BlockHeight::from_u32(block_height as u32), tx_num, output_num)
                    .await;

                // Update till end of block
                let final_witness_1 = list_all_witness_nodes(&cb)
                    .into_iter()
                    .skip((tx_num) * 2 + output_num + 1)
                    .fold(witness.clone(), |mut w, n| {
                        w.append(n).unwrap();
                        w
                    });

                // Update all subsequent blocks
                let final_witness = blocks
                    .iter()
                    .rev()
                    .skip_while(|b| b.height <= block_height)
                    .flat_map(|b| list_all_witness_nodes(&b.cb()))
                    .fold(final_witness_1, |mut w, n| {
                        w.append(n).unwrap();
                        w
                    });

                let txid = cb
                    .vtx
                    .iter()
                    .enumerate()
                    .skip_while(|(i, _)| *i < tx_num)
                    .take(1)
                    .next()
                    .unwrap()
                    .1
                    .hash
                    .clone();

                let actual_final_witness = nw
                    .update_witness_after_pos(
                        &BlockHeight::from_u32(block_height as u32),
                        &WalletTx::new_txid(&txid),
                        output_num as u32,
                        WitnessCache::new(vec![witness], block_height),
                    )
                    .await
                    .last()
                    .unwrap()
                    .clone();

                assert_eq!(incw_to_string(&actual_final_witness), incw_to_string(&final_witness));
            }

            Ok(())
        });

        join_all(vec![uri_h, send_h, test_h])
            .await
            .into_iter()
            .collect::<Result<Result<(), String>, _>>()
            .unwrap()
            .unwrap();
    }
    */
}
