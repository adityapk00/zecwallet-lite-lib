use crate::lightwallet::MemoDownloadOption;
use crate::lightwallet::{data::WalletTx, wallet_txns::WalletTxns};
use std::sync::Arc;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::join;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;
use tokio::sync::RwLock;
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};

use zcash_primitives::consensus::BlockHeight;
use zcash_primitives::sapling::Nullifier;
use zcash_primitives::transaction::TxId;

use super::syncdata::BlazeSyncData;

/// A processor to update notes that we have recieved in the wallet.
/// We need to identify if this note has been spent in future blocks.
/// If YES, then:
///    - Mark this note as spent
///    - In the future Tx, add the nullifiers as spent and do the accounting
///    - In the future Tx, mark incoming notes as change
///
/// If No, then:
///    - Update the witness for this note
pub struct UpdateNotes {
    wallet_txns: Arc<RwLock<WalletTxns>>,
}

impl UpdateNotes {
    pub fn new(wallet_txns: Arc<RwLock<WalletTxns>>) -> Self {
        Self { wallet_txns }
    }

    async fn update_witnesses(
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        txid: TxId,
        nullifier: Nullifier,
        output_num: Option<u32>,
    ) {
        // Get the data first, so we don't hold on to the lock
        let wtn = wallet_txns.read().await.get_note_witness(&txid, &nullifier);

        if let Some((witnesses, created_height)) = wtn {
            if witnesses.len() == 0 {
                // No witnesses, likely a Viewkey or we don't have spending key, so don't bother
                return;
            }

            // If we were sent an output number, then we need to stream after the given position
            let witnesses = if let Some(output_num) = output_num {
                bsync_data
                    .read()
                    .await
                    .block_data
                    .update_witness_after_pos(&created_height, &txid, output_num, witnesses)
                    .await
            } else {
                // If the output_num was not present, then this is an existing note, and it needs
                // to be updating starting at the given block height
                bsync_data
                    .read()
                    .await
                    .block_data
                    .update_witness_after_block(witnesses)
                    .await
            };

            //info!("Finished updating witnesses for {}", txid);

            wallet_txns
                .write()
                .await
                .set_s_note_witnesses(&txid, &nullifier, witnesses);
        }
    }

    pub async fn start(
        &self,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        scan_full_tx_sender: UnboundedSender<(TxId, BlockHeight)>,
    ) -> (
        JoinHandle<Result<(), String>>,
        oneshot::Sender<u64>,
        Sender<(TxId, Option<Nullifier>, BlockHeight, Option<u32>)>,
    ) {
        //info!("Starting Note Update processing");
        let download_memos = bsync_data.read().await.wallet_options.download_memos;

        // Create a new channel where we'll be notified of TxIds that are to be processed
        let (tx, mut rx) = channel::<(TxId, Option<Nullifier>, BlockHeight, Option<u32>)>(4);

        // Aside from the incoming Txns, we also need to update the notes that are currently in the wallet
        let wallet_txns = self.wallet_txns.clone();
        let tx_existing = tx.clone();

        let (blocks_done_tx, blocks_done_rx) = oneshot::channel::<u64>();

        let h0: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            // First, wait for notification that the blocks are done loading, and get the earliest block from there.
            let earliest_block = blocks_done_rx
                .await
                .map_err(|e| format!("Error getting notification that blocks are done. {}", e))?;

            // Get all notes from the wallet that are already existing, i.e., the ones that are before the earliest block that the block loader loaded
            let notes = wallet_txns.read().await.get_notes_for_updating(earliest_block - 1);
            for (txid, nf) in notes {
                tx_existing
                    .send((txid, Some(nf), BlockHeight::from(earliest_block as u32), None))
                    .await
                    .map_err(|e| format!("Error sending note for updating: {}", e))?;
            }

            //info!("Finished processing all existing notes in wallet");
            Ok(())
        });

        let wallet_txns = self.wallet_txns.clone();
        let h1 = tokio::spawn(async move {
            let mut workers = FuturesUnordered::new();

            // Recieve Txns that are sent to the wallet. We need to update the notes for this.
            while let Some((txid, nf, at_height, output_num)) = rx.recv().await {
                let bsync_data = bsync_data.clone();
                let wallet_txns = wallet_txns.clone();
                let fetch_full_sender = scan_full_tx_sender.clone();

                workers.push(tokio::spawn(async move {
                    // If this nullifier was spent at a future height, fetch the TxId at the height and process it
                    if nf.is_some() {
                        let nf = nf.unwrap();
                        if let Some(spent_height) = bsync_data
                            .read()
                            .await
                            .block_data
                            .is_nf_spent(nf, at_height.into())
                            .await
                        {
                            //info!("Note was spent, just add it as spent for TxId {}", txid);
                            let (ctx, ts) = bsync_data
                                .read()
                                .await
                                .block_data
                                .get_ctx_for_nf_at_height(&nf, spent_height)
                                .await;

                            let spent_txid = WalletTx::new_txid(&ctx.hash);
                            let spent_at_height = BlockHeight::from_u32(spent_height as u32);

                            // Mark this note as being spent
                            let value = wallet_txns.write().await.mark_txid_s_nf_spent(
                                &txid,
                                &nf,
                                &spent_txid,
                                spent_at_height,
                            );

                            // Record the future tx, the one that has spent the nullifiers recieved in this Tx in the wallet
                            wallet_txns.write().await.add_new_s_spent(
                                spent_txid,
                                spent_at_height,
                                false,
                                ts,
                                nf,
                                value,
                                txid,
                            );

                            // Send the future Tx to be fetched too, in case it has only spent nullifiers and not recieved any change
                            if download_memos != MemoDownloadOption::NoMemos {
                                fetch_full_sender.send((spent_txid, spent_at_height)).unwrap();
                            }
                        } else {
                            //info!("Note was NOT spent, update its witnesses for TxId {}", txid);

                            // If this note's nullifier was not spent, then we need to update the witnesses for this.
                            Self::update_witnesses(bsync_data.clone(), wallet_txns.clone(), txid, nf, output_num).await;
                        }
                    }

                    // Send it off to get the full transaction if this is a new Tx, that is, it has an output_num
                    if output_num.is_some() && download_memos != MemoDownloadOption::NoMemos {
                        fetch_full_sender.send((txid, at_height)).unwrap();
                    }
                }));
            }

            // Wait for all the workers
            while let Some(r) = workers.next().await {
                r.unwrap();
            }

            //info!("Finished Note Update processing");
        });

        let h = tokio::spawn(async move {
            let (r0, r1) = join!(h0, h1);
            r0.map_err(|e| format!("{}", e))??;
            r1.map_err(|e| format!("{}", e))
        });

        return (h, blocks_done_tx, tx);
    }
}
