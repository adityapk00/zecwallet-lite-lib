use crate::compact_formats::vec_to_array;
use crate::{
    compact_formats::{CompactBlock, CompactTx, TreeState},
    grpc_connector::GrpcConnector,
    lightclient::{
        checkpoints::get_all_main_checkpoints,
        lightclient_config::{LightClientConfig, MAX_REORG},
    },
    lightwallet::{
        data::{BlockData, WalletTx, WitnessCache},
        wallet_txns::WalletTxns,
        MERKLE_DEPTH,
    },
};
use futures::{stream::FuturesOrdered, StreamExt};
use http::Uri;
use incrementalmerkletree::{bridgetree::BridgeTree, Tree};
use log::info;
use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
use std::collections::HashMap;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{
        mpsc::{self, Sender, UnboundedSender},
        RwLock,
    },
    task::{yield_now, JoinHandle},
    time::sleep,
};
use zcash_primitives::{
    consensus::{self, BlockHeight},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::{Node, Nullifier},
    transaction::TxId,
};

use super::{fixed_size_buffer::FixedSizeBuffer, sync_status::SyncStatus};

pub struct BlockAndWitnessData {
    // List of all blocks and their hashes/commitment trees. blocks[0] is the tallest block height in this batch
    blocks: Arc<RwLock<Vec<BlockData>>>,

    // List of existing blocks in the wallet. Used for reorgs
    existing_blocks: Arc<RwLock<Vec<BlockData>>>,

    // List of sapling tree states that were fetched from the server, which need to be verified before we return from the
    // function
    verification_list: Arc<RwLock<Vec<TreeState>>>,

    // How many blocks to process at a time.
    batch_size: u64,

    // Heighest verified tree
    verified_tree: Option<TreeState>,

    // Orchard notes to track. block height -> tx_num -> output_num
    orchard_note_positions: Arc<RwLock<HashMap<u64, HashMap<usize, Vec<u32>>>>>,

    // Orchard witnesses
    orchard_witnesses: Arc<RwLock<Option<BridgeTree<MerkleHashOrchard, MERKLE_DEPTH>>>>,

    // Link to the syncstatus where we can update progress
    sync_status: Arc<RwLock<SyncStatus>>,

    sapling_activation_height: u64,
}

impl BlockAndWitnessData {
    pub fn new<P: consensus::Parameters>(config: &LightClientConfig<P>, sync_status: Arc<RwLock<SyncStatus>>) -> Self {
        Self {
            blocks: Arc::new(RwLock::new(vec![])),
            existing_blocks: Arc::new(RwLock::new(vec![])),
            verification_list: Arc::new(RwLock::new(vec![])),
            batch_size: 1_000,
            verified_tree: None,
            orchard_note_positions: Arc::new(RwLock::new(HashMap::new())),
            orchard_witnesses: Arc::new(RwLock::new(None)),
            sync_status,
            sapling_activation_height: config.sapling_activation_height,
        }
    }

    #[cfg(test)]
    pub fn new_with_batchsize<P: consensus::Parameters>(config: &LightClientConfig<P>, batch_size: u64) -> Self {
        let mut s = Self::new(config, Arc::new(RwLock::new(SyncStatus::default())));
        s.batch_size = batch_size;

        s
    }

    pub async fn setup_sync(
        &mut self,
        existing_blocks: Vec<BlockData>,
        verified_tree: Option<TreeState>,
        orchard_witnesses: Arc<RwLock<Option<BridgeTree<MerkleHashOrchard, MERKLE_DEPTH>>>>,
    ) {
        if !existing_blocks.is_empty() {
            if existing_blocks.first().unwrap().height < existing_blocks.last().unwrap().height {
                panic!("Blocks are in wrong order");
            }
        }
        self.verification_list.write().await.clear();
        self.verified_tree = verified_tree;

        self.blocks.write().await.clear();

        self.orchard_witnesses = orchard_witnesses;

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

    // Verify all the downloaded tree states
    pub async fn verify_sapling_tree(&self) -> (bool, Option<TreeState>) {
        // Verify only on the last batch
        {
            let sync_status = self.sync_status.read().await;
            if sync_status.batch_num + 1 != sync_status.batch_total {
                return (true, None);
            }
        }

        // If there's nothing to verify, return
        if self.verification_list.read().await.is_empty() {
            return (true, None);
        }

        // Sort and de-dup the verification list
        let mut verification_list = self.verification_list.write().await.split_off(0);
        verification_list.sort_by_cached_key(|ts| ts.height);
        verification_list.dedup_by_key(|ts| ts.height);

        // Remember the highest tree that will be verified, and return that.
        let heighest_tree = verification_list.last().map(|ts| ts.clone());

        let mut start_trees = vec![];

        // Collect all the checkpoints
        start_trees.extend(get_all_main_checkpoints().into_iter().map(|(h, hash, tree)| {
            let mut tree_state = TreeState::default();
            tree_state.height = h;
            tree_state.hash = hash.to_string();
            tree_state.tree = tree.to_string();

            tree_state
        }));

        // Add all the verification trees as verified, so they can be used as starting points. If any of them fails to verify, then we will
        // fail the whole thing anyway.
        start_trees.extend(verification_list.iter().map(|t| t.clone()));

        // Also add the wallet's heighest tree
        if self.verified_tree.is_some() {
            start_trees.push(self.verified_tree.as_ref().unwrap().clone());
        }

        // If there are no available start trees, there is nothing to verify.
        if start_trees.is_empty() {
            return (true, None);
        }

        // sort
        start_trees.sort_by_cached_key(|ts| ts.height);

        // Now, for each tree state that we need to verify, find the closest one
        let tree_pairs = verification_list
            .into_iter()
            .filter_map(|vt| {
                let height = vt.height;
                let closest_tree = start_trees
                    .iter()
                    .fold(None, |ct, st| if st.height < height { Some(st) } else { ct });

                if closest_tree.is_some() {
                    Some((vt, closest_tree.unwrap().clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Verify each tree pair
        let blocks = self.blocks.clone();
        let mut handles = tree_pairs
            .into_iter()
            .map(|(vt, ct)| {
                let blocks = blocks.clone();
                tokio::spawn(async move {
                    assert!(ct.height <= vt.height);

                    if ct.height == vt.height {
                        return true;
                    }
                    let mut tree = CommitmentTree::<Node>::read(&hex::decode(ct.tree).unwrap()[..]).unwrap();

                    {
                        let blocks = blocks.read().await;

                        let top_block = blocks.first().unwrap().height;
                        let start_pos = (top_block - ct.height - 1) as usize;
                        let end_pos = (top_block - vt.height) as usize;

                        if start_pos >= blocks.len() || end_pos >= blocks.len() {
                            // Blocks are not in the current sync, which means this has already been verified
                            return true;
                        }

                        for i in (end_pos..start_pos + 1).rev() {
                            let cb = &blocks.get(i as usize).unwrap().cb();
                            for ctx in &cb.vtx {
                                for co in &ctx.outputs {
                                    let node = Node::new(co.cmu().unwrap().into());
                                    tree.append(node).unwrap();
                                }
                            }
                        }
                    }
                    // Verify that the verification_tree can be calculated from the start tree
                    let mut buf = vec![];
                    tree.write(&mut buf).unwrap();

                    // Return if verified
                    hex::encode(buf) == vt.tree
                })
            })
            .collect::<FuturesOrdered<_>>();

        while let Some(r) = handles.next().await {
            if r.is_err() {
                return (false, None);
            }
        }

        return (true, heighest_tree);
    }

    // Invalidate the block (and wallet txns associated with it) at the given block height
    pub async fn invalidate_block(
        reorg_height: u64,
        existing_blocks: Arc<RwLock<Vec<BlockData>>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        orchard_witnesses: Arc<RwLock<Option<BridgeTree<MerkleHashOrchard, MERKLE_DEPTH>>>>,
    ) {
        // First, pop the first block (which is the top block) in the existing_blocks.
        let top_wallet_block = existing_blocks.write().await.drain(0..1).next().unwrap();
        if top_wallet_block.height != reorg_height {
            panic!("Wrong block reorg'd");
        }

        // Remove all wallet txns at the height
        wallet_txns.write().await.remove_txns_at_height(reorg_height);

        // Rollback one checkpoint for orchard, which corresponds to one block
        let erase_tree = orchard_witnesses
            .write()
            .await
            .as_mut()
            .map(|bt| !bt.rewind())
            .unwrap_or(false);
        if erase_tree {
            info!("Erased orchard tree");
            orchard_witnesses.write().await.take();
        }

        info!("Invalidated block {}", reorg_height);
    }

    /// Start a new sync where we ingest all the blocks
    pub async fn start(
        &self,
        start_block: u64,
        end_block: u64,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        reorg_tx: UnboundedSender<Option<u64>>,
    ) -> (JoinHandle<Result<u64, String>>, Sender<CompactBlock>) {
        //info!("Starting node and witness sync");
        let batch_size = self.batch_size;

        // Create a new channel where we'll receive the blocks
        let (tx, mut rx) = mpsc::channel::<CompactBlock>(64); // Only 64 blocks in the buffer

        let blocks = self.blocks.clone();
        let existing_blocks = self.existing_blocks.clone();

        let sync_status = self.sync_status.clone();
        sync_status.write().await.blocks_total = start_block - end_block + 1;
        let orchard_witnesses = self.orchard_witnesses.clone();

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

            while let Some(cb) = rx.recv().await {
                let orchard_witnesses = orchard_witnesses.clone();

                //println!("block_witness recieved {:?}", cb.height);
                // We'll process batch_size (1_000) blocks at a time.
                // println!("Recieved block # {}", cb.height);
                if cb.height % batch_size == 0 {
                    // println!("Batch size hit at height {} with len {}", cb.height, blks.len());
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
                        Self::invalidate_block(
                            reorg_height,
                            existing_blocks.clone(),
                            wallet_txns.clone(),
                            orchard_witnesses,
                        )
                        .await;
                        last_block_expecting = reorg_height;
                    }
                    reorg_tx.send(reorg_block).unwrap();
                }

                earliest_block_height = cb.height;
                blks.push(BlockData::new(cb));
            }

            // println!(
            //     "Final block size at earliest-height {} with len {}",
            //     earliest_block_height,
            //     blks.len()
            // );
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

    pub async fn track_orchard_note(&self, height: u64, tx_num: usize, output_num: u32) {
        // Remember this note position
        let mut block_map = self.orchard_note_positions.write().await;

        let txid_map = block_map.entry(height).or_default();
        let output_nums = txid_map.entry(tx_num).or_default();
        output_nums.push(output_num);
    }

    pub async fn update_orchard_spends_and_witnesses(
        &self,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        scan_full_txn_tx: UnboundedSender<(TxId, BlockHeight)>,
    ) {
        // Go over all the blocks
        if let Some(orchard_witnesses) = self.orchard_witnesses.write().await.as_mut() {
            // Read Lock
            let blocks = self.blocks.read().await;
            if blocks.is_empty() {
                return;
            }

            let mut orchard_note_positions = self.orchard_note_positions.write().await;

            // List of all the wallet's nullifiers
            let o_nullifiers = wallet_txns.read().await.get_unspent_o_nullifiers();

            for i in (0..blocks.len()).rev() {
                let cb = &blocks.get(i as usize).unwrap().cb();

                // Checkpoint the orchard witness tree at the start of each block
                orchard_witnesses.checkpoint();

                for (tx_num, ctx) in cb.vtx.iter().enumerate() {
                    for (output_num, action) in ctx.actions.iter().enumerate() {
                        let output_num = output_num as u32;
                        orchard_witnesses.append(&MerkleHashOrchard::from_cmx(
                            &ExtractedNoteCommitment::from_bytes(vec_to_array(&action.cmx)).unwrap(),
                        ));

                        // Check if this orchard note needs to be tracked
                        if let Some(block_map) = orchard_note_positions.get(&cb.height) {
                            if let Some(output_nums) = block_map.get(&tx_num) {
                                if output_nums.contains(&output_num) {
                                    let pos = orchard_witnesses.witness();

                                    // Update the wallet_tx with the note
                                    wallet_txns
                                        .write()
                                        .await
                                        .set_o_note_witness((cb.height, tx_num, output_num), pos);
                                    info!("Witnessing note at position {:?}", pos.unwrap());
                                }
                            }
                        }

                        // Check if the nullifier in this action belongs to us, which means it has been spent
                        for (wallet_nullifier, value, source_txid) in o_nullifiers.iter() {
                            if orchard::note::Nullifier::from_bytes(vec_to_array(&action.nullifier)).unwrap()
                                == *wallet_nullifier
                            {
                                // This was our spend.
                                let txid = WalletTx::new_txid(&ctx.hash);

                                info!("An orchard note from {} was spent in {}", source_txid, txid);

                                // 1. Mark the note as spent
                                wallet_txns.write().await.mark_txid_o_nf_spent(
                                    source_txid,
                                    &wallet_nullifier,
                                    &txid,
                                    cb.height(),
                                );

                                // 2. Update the spent notes in the wallet
                                let maybe_position = wallet_txns.write().await.add_new_o_spent(
                                    txid,
                                    cb.height(),
                                    false,
                                    cb.time,
                                    *wallet_nullifier,
                                    *value,
                                    *source_txid,
                                );

                                // 3. Remove the note from the incremental witness tree tracking.
                                if let Some(position) = maybe_position {
                                    orchard_witnesses.remove_witness(position);
                                }

                                // 4. Send the tx to be scanned for outgoing memos
                                scan_full_txn_tx.send((txid, cb.height())).unwrap();
                            }
                        }
                    }
                }
            }

            orchard_witnesses.garbage_collect();
            orchard_note_positions.clear();
        }
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
            let tree = if prev_height < self.sapling_activation_height {
                CommitmentTree::empty()
            } else {
                let tree_state = GrpcConnector::get_merkle_tree(uri, prev_height).await?;
                let sapling_tree = hex::decode(&tree_state.tree).unwrap();
                // self.verification_list.write().await.push(tree_state);
                CommitmentTree::read(&sapling_tree[..]).map_err(|e| format!("{}", e))?
            };

            // Get the current compact block
            let cb = {
                let height = u64::from(height);
                self.wait_for_block(height).await;

                {
                    let mut blocks = self.blocks.write().await;

                    let pos = blocks.first().unwrap().height - height;
                    let bd = blocks.get_mut(pos as usize).unwrap();

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

        Err(format!(
            "Note witness for tx_num {} output_num{} at height {} Not found!",
            tx_num, output_num, height
        ))
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
    use crate::lightclient::lightclient_config::UnitTestNetwork;
    use crate::lightwallet::wallet_txns::WalletTxns;
    use crate::{
        blaze::test_utils::{FakeCompactBlock, FakeCompactBlockList},
        lightclient::lightclient_config::LightClientConfig,
        lightwallet::data::BlockData,
    };
    use futures::future::try_join_all;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use tokio::sync::RwLock;
    use tokio::{sync::mpsc::unbounded_channel, task::JoinHandle};
    use zcash_primitives::block::BlockHash;

    use super::BlockAndWitnessData;

    #[tokio::test]
    async fn setup_finish_simple() {
        let mut nw = BlockAndWitnessData::new_with_batchsize(
            &LightClientConfig::create_unconnected(UnitTestNetwork, None),
            25_000,
        );

        let cb = FakeCompactBlock::new(1, BlockHash([0u8; 32])).into_cb();
        let blks = vec![BlockData::new(cb)];

        let orchard_witnesses = Arc::new(RwLock::new(None));
        nw.setup_sync(blks.clone(), None, orchard_witnesses).await;
        let finished_blks = nw.finish_get_blocks(1).await;

        assert_eq!(blks[0].hash(), finished_blks[0].hash());
        assert_eq!(blks[0].height, finished_blks[0].height);
    }

    #[tokio::test]
    async fn setup_finish_large() {
        let mut nw = BlockAndWitnessData::new_with_batchsize(
            &LightClientConfig::create_unconnected(UnitTestNetwork, None),
            25_000,
        );

        let existing_blocks = FakeCompactBlockList::new(200).into_blockdatas();

        let orchard_witnesses = Arc::new(RwLock::new(None));
        nw.setup_sync(existing_blocks.clone(), None, orchard_witnesses).await;
        let finished_blks = nw.finish_get_blocks(100).await;

        assert_eq!(finished_blks.len(), 100);

        for (i, finished_blk) in finished_blks.into_iter().enumerate() {
            assert_eq!(existing_blocks[i].hash(), finished_blk.hash());
            assert_eq!(existing_blocks[i].height, finished_blk.height);
        }
    }

    #[tokio::test]
    async fn from_sapling_genesis() {
        let mut config = LightClientConfig::create_unconnected(UnitTestNetwork, None);
        config.sapling_activation_height = 1;

        let blocks = FakeCompactBlockList::new(200).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let sync_status = Arc::new(RwLock::new(SyncStatus::default()));
        let mut nw = BlockAndWitnessData::new(&config, sync_status);

        let orchard_witnesses = Arc::new(RwLock::new(None));
        nw.setup_sync(vec![], None, orchard_witnesses).await;

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
                    .await
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block);

        try_join_all(vec![send_h]).await.unwrap();
    }

    #[tokio::test]
    async fn with_existing_batched() {
        let mut config = LightClientConfig::create_unconnected(UnitTestNetwork, None);
        config.sapling_activation_height = 1;

        let mut blocks = FakeCompactBlockList::new(200).into_blockdatas();

        // Blocks are in reverse order
        assert!(blocks.first().unwrap().height > blocks.last().unwrap().height);

        // Use the first 50 blocks as "existing", and then sync the other 150 blocks.
        let existing_blocks = blocks.split_off(150);

        let start_block = blocks.first().unwrap().height;
        let end_block = blocks.last().unwrap().height;

        let mut nw = BlockAndWitnessData::new_with_batchsize(&config, 25);

        let orchard_witnesses = Arc::new(RwLock::new(None));
        nw.setup_sync(existing_blocks, None, orchard_witnesses).await;

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
                    .await
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }
            if let Some(Some(_h)) = reorg_rx.recv().await {
                return Err(format!("Should not have requested a reorg!"));
            }
            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block);

        try_join_all(vec![send_h]).await.unwrap();

        let finished_blks = nw.finish_get_blocks(100).await;
        assert_eq!(finished_blks.len(), 100);
        assert_eq!(finished_blks.first().unwrap().height, start_block);
        assert_eq!(finished_blks.last().unwrap().height, start_block - 100 + 1);
    }

    #[tokio::test]
    async fn with_reorg() {
        let mut config = LightClientConfig::create_unconnected(UnitTestNetwork, None);
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

        let orchard_witnesses = Arc::new(RwLock::new(None));
        nw.setup_sync(existing_blocks, None, orchard_witnesses).await;

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
                    .await
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
                    .await
                    .map_err(|e| format!("Couldn't send block: {}", e))?;
            }

            assert_eq!(sent_ctr, num_reorged);
            assert!(reorged_blocks.is_empty());

            Ok(())
        });

        assert_eq!(h.await.unwrap().unwrap(), end_block - num_reorged as u64);

        try_join_all(vec![send_h]).await.unwrap();

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
}
