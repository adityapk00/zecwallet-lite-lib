use crate::{
    compact_formats::CompactBlock,
    lightwallet::{data::WalletTx, keys::Keystores, wallet_txns::WalletTxns, MemoDownloadOption},
};
use futures::{stream::FuturesUnordered, StreamExt};
use log::info;
use std::sync::Arc;
use tokio::{
    sync::{
        mpsc::{channel, Sender, UnboundedSender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};

use zcash_primitives::{consensus::BlockHeight,
                       sapling::note_encryption::try_sapling_compact_note_decryption,
                       sapling::{self, Nullifier, SaplingIvk},
                       transaction::{Transaction, TxId},
                       consensus};

use super::syncdata::BlazeSyncData;

pub struct TrialDecryptions<P> {
    keys: Arc<RwLock<Keystores<P>>>,
    wallet_txns: Arc<RwLock<WalletTxns>>,
}

impl<P: consensus::Parameters + Send + Sync + 'static> TrialDecryptions<P> {
    pub fn new(keys: Arc<RwLock<Keystores<P>>>, wallet_txns: Arc<RwLock<WalletTxns>>) -> Self {
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

            let ivks = Arc::new(keys.read().await.get_all_ivks().await.collect::<Vec<_>>());

            while let Some(cb) = rx.recv().await {
                cbs.push(cb);

                if cbs.len() >= 50 {
                    let keys = keys.clone();
                    let ivks = ivks.clone();
                    let wallet_txns = wallet_txns.clone();
                    let bsync_data = bsync_data.clone();
                    let detected_txid_sender = detected_txid_sender.clone();

                    workers.push(tokio::spawn(Self::trial_decrypt_batch(
                        cbs.split_off(0),
                        keys,
                        bsync_data,
                        ivks,
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
                ivks,
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
        keys: Arc<RwLock<Keystores<P>>>,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
        ivks: Arc<Vec<SaplingIvk>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        detected_txid_sender: Sender<(TxId, Option<Nullifier>, BlockHeight, Option<u32>)>,
        fulltx_fetcher: UnboundedSender<(TxId, oneshot::Sender<Result<Transaction, String>>)>,
    ) -> Result<(), String> {
        let config = keys.read().await.config();
        let blk_count = cbs.len();
        let mut workers = FuturesUnordered::new();

        let download_memos = bsync_data.read().await.wallet_options.download_memos;

        for cb in cbs {
            let height = BlockHeight::from_u32(cb.height as u32);

            for (tx_num, ctx) in cb.vtx.iter().enumerate() {
                let mut wallet_tx = false;

                for (output_num, co) in ctx.outputs.iter().enumerate() {
                    let cmu = co.cmu().map_err(|_| "No CMU".to_string())?;
                    let epk = match co.epk() {
                        Err(_) => continue,
                        Ok(epk) => epk,
                    };
                    for (i, ivk) in ivks.iter().map(|k| SaplingIvk(k.0)).enumerate() {
/*                        let co_desc = CompactOutputDescription {
                            cmu: *co.cmu()?,
                            ephemeral_key: *co.epk()?,
                            enc_ciphertext: *co.ciphertext.try_into().map_err(|_| ())?,
                        };

 */
                        if let Some((note, to)) = try_sapling_compact_note_decryption(
                            &config.get_params(),
                            height,
                            &ivk,
                            co,
                        ) {
                            wallet_tx = true;

                            let keys = keys.clone();
                            let bsync_data = bsync_data.clone();
                            let wallet_txns = wallet_txns.clone();
                            let detected_txid_sender = detected_txid_sender.clone();
                            let timestamp = cb.time as u64;
                            let ctx = ctx.clone();

                            workers.push(tokio::spawn(async move {
                                let keys = keys.read().await;
                                let have_spending_key = keys.have_spending_key(&ivk).await;
                                let uri = bsync_data.read().await.uri().clone();

                                // Get the witness for the note
                                let witness = bsync_data
                                    .read()
                                    .await
                                    .block_data
                                    .get_note_witness(uri, height, tx_num, output_num)
                                    .await?;

                                let txid = WalletTx::new_txid(&ctx.hash);
                                let nullifier = keys.get_note_nullifier(&ivk, witness.position() as u64, &note).await?;

                                wallet_txns.write().await.add_new_note(
                                    txid.clone(),
                                    height,
                                    false,
                                    timestamp,
                                    note,
                                    to,
                                    &ivk,
                                    nullifier,
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

                            // No need to try the other ivks if we found one
                            break;
                        }
                    }
                }

                // Check option to see if we are fetching all txns.
                if !wallet_tx && download_memos == MemoDownloadOption::AllMemos {
                    let txid = WalletTx::new_txid(&ctx.hash);
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
        Ok::<(), String>(())
    }
}
