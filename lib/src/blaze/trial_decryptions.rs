use crate::{
    compact_formats::CompactBlock,
    lightwallet::{data::WalletTx, keys::Keys, wallet_txns::WalletTxns, MemoDownloadOption},
};
use futures::{stream::FuturesUnordered, StreamExt};
use log::info;
use orchard::{keys::IncomingViewingKey, note_encryption::OrchardDomain};
use std::convert::TryFrom;
use zcash_note_encryption::batch::try_compact_note_decryption;

use std::sync::Arc;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{channel, Sender, UnboundedSender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};

use zcash_primitives::{
    consensus::{self, BlockHeight},
    sapling::{self, note_encryption::SaplingDomain, SaplingIvk},
    transaction::{Transaction, TxId},
};

use super::syncdata::BlazeSyncData;

pub struct TrialDecryptions<P> {
    keys: Arc<RwLock<Keys<P>>>,
    wallet_txns: Arc<RwLock<WalletTxns>>,
}

impl<P: consensus::Parameters + Send + Sync + 'static> TrialDecryptions<P> {
    pub fn new(keys: Arc<RwLock<Keys<P>>>, wallet_txns: Arc<RwLock<WalletTxns>>) -> Self {
        Self { keys, wallet_txns }
    }

    pub async fn start(
        &self,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        detected_txid_sender: Sender<(TxId, Option<sapling::Nullifier>, BlockHeight, Option<u32>)>,
        fulltx_fetcher: UnboundedSender<(TxId, oneshot::Sender<Result<Transaction, String>>)>,
    ) -> (JoinHandle<Result<(), String>>, Sender<CompactBlock>) {
        //info!("Starting trial decrptions processor");

        // Create a new channel where we'll receive the blocks. only 64 in the queue
        let (tx, mut rx) = channel::<CompactBlock>(64);

        let keys = self.keys.clone();
        let wallet_txns = self.wallet_txns.clone();

        let h = tokio::spawn(async move {
            let mut workers = FuturesUnordered::new();
            let mut cbs = vec![];

            let s_ivks = Arc::new(
                keys.read()
                    .await
                    .zkeys
                    .iter()
                    .map(|zk| zk.extfvk().fvk.vk.ivk())
                    .collect::<Vec<_>>(),
            );

            let o_ivks = Arc::new(keys.read().await.get_all_orchard_ivks());

            while let Some(cb) = rx.recv().await {
                //println!("trial_witness recieved {:?}", cb.height);
                cbs.push(cb);

                if cbs.len() >= 50 {
                    let keys = keys.clone();
                    let s_ivks = s_ivks.clone();
                    let o_ivks = o_ivks.clone();
                    let wallet_txns = wallet_txns.clone();
                    let bsync_data = bsync_data.clone();
                    let detected_txid_sender = detected_txid_sender.clone();

                    workers.push(tokio::spawn(Self::trial_decrypt_batch(
                        cbs.split_off(0),
                        keys,
                        bsync_data,
                        s_ivks,
                        o_ivks,
                        wallet_txns,
                        detected_txid_sender,
                        fulltx_fetcher.clone(),
                    )));
                }
            }

            workers.push(tokio::spawn(Self::trial_decrypt_batch(
                cbs,
                keys,
                bsync_data,
                s_ivks,
                o_ivks,
                wallet_txns,
                detected_txid_sender,
                fulltx_fetcher,
            )));

            while let Some(r) = workers.next().await {
                match r {
                    Ok(Ok(_)) => (),
                    Ok(Err(s)) => return Err(s),
                    Err(e) => return Err(e.to_string()),
                };
            }

            //info!("Finished final trial decryptions");
            Ok(())
        });

        return (h, tx);
    }

    async fn trial_decrypt_batch(
        cbs: Vec<CompactBlock>,
        keys: Arc<RwLock<Keys<P>>>,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        s_ivks: Arc<Vec<SaplingIvk>>,
        o_ivks: Arc<Vec<IncomingViewingKey>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        detected_txid_sender: Sender<(TxId, Option<sapling::Nullifier>, BlockHeight, Option<u32>)>,
        fulltx_fetcher: UnboundedSender<(TxId, oneshot::Sender<Result<Transaction, String>>)>,
    ) -> Result<(), String> {
        // println!("Starting batch at {}", temp_start);
        let config = keys.read().await.config().clone();
        let params = config.get_params();
        let blk_count = cbs.len();
        let mut workers = FuturesUnordered::new();

        let download_memos = bsync_data.read().await.wallet_options.download_memos;

        for cb in cbs {
            let height = BlockHeight::from_u32(cb.height as u32);

            for (tx_num, ctx) in cb.vtx.into_iter().enumerate() {
                let tokio_handle = Handle::current();

                let ctx_hash = ctx.hash;
                let mut wallet_tx = false;

                {
                    // Orchard
                    let orchard_actions = ctx
                        .actions
                        .into_iter()
                        .map(|coa| {
                            (
                                OrchardDomain::for_nullifier(
                                    orchard::note::Nullifier::from_bytes(
                                        <&[u8; 32]>::try_from(&coa.nullifier[..]).unwrap(),
                                    )
                                    .unwrap(),
                                ),
                                coa,
                            )
                        })
                        .collect::<Vec<_>>();

                    // if orchard_actions.len() > 0 {
                    //     println!(
                    //         "Trial decrypting {} actions with {} o_ivks for txid {}",
                    //         orchard_actions.len(),
                    //         o_ivks.len(),
                    //         WalletTx::new_txid(&ctx_hash)
                    //     );
                    // }

                    let decrypts = try_compact_note_decryption(o_ivks.as_ref(), orchard_actions.as_ref());
                    for (output_num, maybe_decrypted) in decrypts.into_iter().enumerate() {
                        if let Some(((note, _to), ivk_num)) = maybe_decrypted {
                            // println!(
                            //     "An orchard note was decrypted! {}:{:?}",
                            //     note.value().inner(),
                            //     note.recipient()
                            // );
                            wallet_tx = true;

                            let ctx_hash = ctx_hash.clone();

                            let keys = keys.read().await;
                            let detected_txid_sender = detected_txid_sender.clone();
                            let timestamp = cb.time as u64;
                            let fvk = keys.okeys[ivk_num].fvk();
                            let have_spending_key = keys.have_orchard_spending_key(fvk);

                            // Tell the orchard witness tree to track this note.
                            bsync_data
                                .read()
                                .await
                                .block_data
                                .track_orchard_note(cb.height, tx_num, output_num as u32)
                                .await;

                            let txid = WalletTx::new_txid(&ctx_hash);
                            wallet_txns.write().await.add_new_orchard_note(
                                txid,
                                height,
                                false,
                                timestamp,
                                note,
                                (height.into(), tx_num, output_num as u32),
                                fvk,
                                have_spending_key,
                            );

                            detected_txid_sender
                                .send((txid, None, height, Some(output_num as u32)))
                                .await
                                .unwrap();
                        }
                    }
                }

                {
                    // Sapling
                    let outputs_total = ctx.outputs.len();
                    // if outputs_total < 100 {
                    let outputs = ctx
                        .outputs
                        .into_iter()
                        .map(|o| (SaplingDomain::for_height(params.clone(), height), o))
                        .collect::<Vec<_>>();

                    // Batch decryption for sapling
                    let decrypts = try_compact_note_decryption(s_ivks.as_ref(), outputs.as_ref());

                    for (dec_num, maybe_decrypted) in decrypts.into_iter().enumerate() {
                        if let Some(((note, to), ivk_num)) = maybe_decrypted {
                            wallet_tx = true;

                            let ctx_hash = ctx_hash.clone();
                            let output_num = dec_num % outputs_total;

                            let keys = keys.clone();
                            let bsync_data = bsync_data.clone();
                            let wallet_txns = wallet_txns.clone();
                            let detected_txid_sender = detected_txid_sender.clone();
                            let timestamp = cb.time as u64;

                            workers.push(tokio_handle.spawn(async move {
                                let keys = keys.read().await;
                                let extfvk = keys.zkeys[ivk_num].extfvk();
                                let have_spending_key = keys.have_sapling_spending_key(extfvk);
                                let uri = bsync_data.read().await.uri().clone();

                                // Get the witness for the note
                                let witness = bsync_data
                                    .read()
                                    .await
                                    .block_data
                                    .get_note_witness(uri, height, tx_num, output_num)
                                    .await?;

                                let txid = WalletTx::new_txid(&ctx_hash);
                                let nullifier = note.nf(&extfvk.fvk.vk.nk, witness.position() as u64);

                                wallet_txns.write().await.add_new_sapling_note(
                                    txid.clone(),
                                    height,
                                    false,
                                    timestamp,
                                    note,
                                    to,
                                    &extfvk,
                                    have_spending_key,
                                    witness,
                                );

                                info!("Trial decrypt Detected txid {}", &txid);

                                detected_txid_sender
                                    .send((txid, Some(nullifier), height, Some(output_num as u32)))
                                    .await
                                    .unwrap();

                                Ok::<_, String>(())
                            }));
                        }
                    }
                    // }
                }

                // Check option to see if we are fetching all txns.
                if !wallet_tx && download_memos == MemoDownloadOption::AllMemos {
                    let txid = WalletTx::new_txid(&ctx_hash);
                    let (tx, rx) = oneshot::channel();
                    fulltx_fetcher.send((txid, tx)).unwrap();

                    workers.push(tokio::spawn(async move {
                        // Discard the result, because this was not a wallet tx.
                        rx.await.unwrap().map(|_r| ())
                    }));
                }
            }
        }

        while let Some(r) = workers.next().await {
            r.map_err(|e| e.to_string())??;
        }

        // Update sync status
        bsync_data.read().await.sync_status.write().await.trial_dec_done += blk_count as u64;

        // Return a nothing-value
        // println!("Finished batch at {}", temp_start);
        Ok::<(), String>(())
    }
}
