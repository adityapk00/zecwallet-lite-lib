use crate::{
    lightclient::lightclient_config::LightClientConfig,
    lightwallet::{
        data::OutgoingTxMetadata,
        keys::{Keys, ToBase58Check},
        wallet_txns::WalletTxns,
        LightWallet,
    },
};

use futures::{stream::FuturesUnordered, StreamExt};
use log::info;
use orchard::note_encryption::OrchardDomain;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};

use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    iter::FromIterator,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::{
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};
use zcash_client_backend::encoding::encode_payment_address;

use zcash_primitives::{
    consensus::{self, BlockHeight},
    legacy::TransparentAddress,
    memo::Memo,
    sapling::note_encryption::{try_sapling_note_decryption, try_sapling_output_recovery},
    transaction::{Transaction, TxId},
};

use super::syncdata::BlazeSyncData;

pub struct FetchFullTxns<P> {
    config: LightClientConfig<P>,
    keys: Arc<RwLock<Keys<P>>>,
    wallet_txns: Arc<RwLock<WalletTxns>>,
}

impl<P: consensus::Parameters + Send + Sync + 'static> FetchFullTxns<P> {
    pub fn new(
        config: &LightClientConfig<P>,
        keys: Arc<RwLock<Keys<P>>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
    ) -> Self {
        Self {
            config: config.clone(),
            keys,
            wallet_txns,
        }
    }

    pub async fn start(
        &self,
        fulltx_fetcher: UnboundedSender<(TxId, oneshot::Sender<Result<Transaction, String>>)>,
        bsync_data: Arc<RwLock<BlazeSyncData>>,
    ) -> (
        JoinHandle<Result<(), String>>,
        UnboundedSender<(TxId, BlockHeight)>,
        UnboundedSender<(Transaction, BlockHeight)>,
    ) {
        let wallet_txns = self.wallet_txns.clone();
        let keys = self.keys.clone();
        let config = self.config.clone();

        let start_height = bsync_data.read().await.sync_status.read().await.start_block;
        let end_height = bsync_data.read().await.sync_status.read().await.end_block;

        let bsync_data_i = bsync_data.clone();

        let (txid_tx, mut txid_rx) = unbounded_channel::<(TxId, BlockHeight)>();
        let h1: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let last_progress = Arc::new(AtomicU64::new(0));
            let mut workers = FuturesUnordered::new();

            while let Some((txid, height)) = txid_rx.recv().await {
                let config = config.clone();
                let keys = keys.clone();
                let wallet_txns = wallet_txns.clone();
                let block_time = bsync_data_i.read().await.block_data.get_block_timestamp(&height).await;
                let fulltx_fetcher = fulltx_fetcher.clone();
                let bsync_data = bsync_data_i.clone();
                let last_progress = last_progress.clone();

                workers.push(tokio::spawn(async move {
                    // It is possible that we recieve the same txid multiple times, so we keep track of all the txids that were fetched
                    let tx = {
                        // Fetch the TxId from LightwalletD and process all the parts of it.
                        let (tx, rx) = oneshot::channel();
                        fulltx_fetcher.send((txid, tx)).unwrap();
                        rx.await.unwrap()?
                    };

                    let progress = start_height - u64::from(height);
                    if progress > last_progress.load(Ordering::SeqCst) {
                        bsync_data.read().await.sync_status.write().await.txn_scan_done = progress;
                        last_progress.store(progress, Ordering::SeqCst);
                    }

                    Self::scan_full_tx(config, tx, height, false, block_time, keys, wallet_txns, None).await;

                    Ok::<_, String>(())
                }));
            }

            while let Some(r) = workers.next().await {
                r.map_err(|r| r.to_string())??;
            }

            bsync_data_i.read().await.sync_status.write().await.txn_scan_done = start_height - end_height + 1;
            //info!("Finished fetching all full transactions");

            Ok(())
        });

        let wallet_txns = self.wallet_txns.clone();
        let keys = self.keys.clone();
        let config = self.config.clone();

        let (tx_tx, mut tx_rx) = unbounded_channel::<(Transaction, BlockHeight)>();

        let h2: JoinHandle<Result<(), String>> = tokio::spawn(async move {
            let bsync_data = bsync_data.clone();

            while let Some((tx, height)) = tx_rx.recv().await {
                let config = config.clone();
                let keys = keys.clone();
                let wallet_txns = wallet_txns.clone();

                let block_time = bsync_data.read().await.block_data.get_block_timestamp(&height).await;
                Self::scan_full_tx(config, tx, height, false, block_time, keys, wallet_txns, None).await;
            }

            //info!("Finished full_tx scanning all txns");
            Ok(())
        });

        let h = tokio::spawn(async move {
            let mut f = FuturesUnordered::new();
            f.push(h1);
            f.push(h2);

            while let Some(r) = f.next().await {
                match r {
                    Ok(Ok(_)) => (),
                    Ok(Err(s)) => return Err(s),
                    Err(e) => return Err(e.to_string()),
                };
            }

            Ok(())
        });

        return (h, txid_tx, tx_tx);
    }

    pub(crate) async fn scan_full_tx(
        config: LightClientConfig<P>,
        tx: Transaction,
        height: BlockHeight,
        unconfirmed: bool,
        block_time: u32,
        keys: Arc<RwLock<Keys<P>>>,
        wallet_txns: Arc<RwLock<WalletTxns>>,
        price: Option<f64>,
    ) {
        // Collect our t-addresses for easy checking
        let taddrs = keys.read().await.get_all_taddrs();
        let taddrs_set: HashSet<_> = taddrs.iter().map(|t| t.clone()).collect();

        // Step 1: Scan all transparent outputs to see if we recieved any money
        if let Some(t_bundle) = tx.transparent_bundle() {
            for (n, vout) in t_bundle.vout.iter().enumerate() {
                match vout.script_pubkey.address() {
                    Some(TransparentAddress::PublicKey(hash)) => {
                        let output_taddr = hash.to_base58check(&config.base58_pubkey_address(), &[]);
                        if taddrs_set.contains(&output_taddr) {
                            // This is our address. Add this as an output to the txid
                            wallet_txns.write().await.add_new_taddr_output(
                                tx.txid(),
                                output_taddr.clone(),
                                height.into(),
                                unconfirmed,
                                block_time as u64,
                                &vout,
                                n as u32,
                            );

                            // Ensure that we add any new HD addresses
                            keys.write().await.ensure_hd_taddresses(&output_taddr);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Remember if this is an outgoing Tx. Useful for when we want to grab the outgoing metadata.
        let mut is_outgoing_tx = false;

        // Step 2. Scan transparent spends

        // Scan all the inputs to see if we spent any transparent funds in this tx
        let mut total_transparent_value_spent = 0;
        let mut spent_utxos = vec![];

        {
            let current = &wallet_txns.read().await.current;
            if let Some(t_bundle) = tx.transparent_bundle() {
                for vin in t_bundle.vin.iter() {
                    // Find the prev txid that was spent
                    let prev_txid = TxId::from_bytes(*vin.prevout.hash());
                    let prev_n = vin.prevout.n() as u64;

                    if let Some(wtx) = current.get(&prev_txid) {
                        // One of the tx outputs is a match
                        if let Some(spent_utxo) = wtx
                            .utxos
                            .iter()
                            .find(|u| u.txid == prev_txid && u.output_index == prev_n)
                        {
                            info!("Spent: utxo from {} was spent in {}", prev_txid, tx.txid());
                            total_transparent_value_spent += spent_utxo.value;
                            spent_utxos.push((prev_txid, prev_n as u32, tx.txid(), height));
                        }
                    }
                }
            }
        }

        // Mark all the UTXOs that were spent here back in their original txns.
        for (prev_txid, prev_n, txid, height) in spent_utxos {
            // Mark that this Tx spent some funds
            is_outgoing_tx = true;

            wallet_txns
                .write()
                .await
                .mark_txid_utxo_spent(prev_txid, prev_n, txid, height.into());
        }

        // If this Tx spent value, add the spent amount to the TxID
        if total_transparent_value_spent > 0 {
            is_outgoing_tx = true;

            wallet_txns.write().await.add_taddr_spent(
                tx.txid(),
                height,
                unconfirmed,
                block_time as u64,
                total_transparent_value_spent,
            );
        }

        // Step 3: Check if any of the nullifiers spent in this Tx are ours. We only need this for unconfirmed txns,
        // because for txns in the block, we will check the nullifiers from the blockdata
        if unconfirmed {
            let unspent_nullifiers = wallet_txns.read().await.get_unspent_s_nullifiers();
            if let Some(s_bundle) = tx.sapling_bundle() {
                for s in s_bundle.shielded_spends.iter() {
                    if let Some((nf, value, txid)) = unspent_nullifiers.iter().find(|(nf, _, _)| *nf == s.nullifier) {
                        wallet_txns.write().await.add_new_s_spent(
                            tx.txid(),
                            height,
                            unconfirmed,
                            block_time,
                            *nf,
                            *value,
                            *txid,
                        );
                    }
                }
            }
        }
        // Collect all our z addresses, to check for change
        let z_addresses: HashSet<String> = HashSet::from_iter(keys.read().await.get_all_zaddresses().into_iter());
        let u_addresses: HashSet<String> = HashSet::from_iter(keys.read().await.get_all_uaddresses().into_iter());

        // Collect all our OVKs, to scan for outputs
        let ovks: Vec<_> = keys
            .read()
            .await
            .get_all_extfvks()
            .iter()
            .map(|k| k.fvk.ovk.clone())
            .collect();

        let extfvks = Arc::new(keys.read().await.get_all_extfvks());
        let s_ivks: Vec<_> = extfvks.iter().map(|k| k.fvk.vk.ivk()).collect();

        // Step 4a: Scan shielded sapling outputs to see if anyone of them is us, and if it is, extract the memo. Note that if this
        // is invoked by a transparent transaction, and we have not seen this Tx from the trial_decryptions processor, the Note
        // might not exist, and the memo updating might be a No-Op. That's Ok, the memo will get updated when this Tx is scanned
        // a second time by the Full Tx Fetcher
        let mut outgoing_metadatas = vec![];

        if let Some(s_bundle) = tx.sapling_bundle() {
            for output in s_bundle.shielded_outputs.iter() {
                // Search all of our keys
                for (i, ivk) in s_ivks.iter().enumerate() {
                    let (note, to, memo_bytes) =
                        match try_sapling_note_decryption(&config.get_params(), height, &ivk, output) {
                            Some(ret) => ret,
                            None => continue,
                        };

                    // info!("A sapling note was received into the wallet in {}", tx.txid());
                    if unconfirmed {
                        wallet_txns.write().await.add_pending_note(
                            tx.txid(),
                            height,
                            block_time as u64,
                            note.clone(),
                            to,
                            &extfvks.get(i).unwrap(),
                        );
                    }

                    let memo = memo_bytes.clone().try_into().unwrap_or(Memo::Future(memo_bytes));
                    wallet_txns.write().await.add_memo_to_s_note(&tx.txid(), note, memo);
                }

                // Also scan the output to see if it can be decoded with our OutgoingViewKey
                // If it can, then we sent this transaction, so we should be able to get
                // the memo and value for our records

                // Search all ovks that we have
                let omds = ovks
                    .iter()
                    .filter_map(|ovk| {
                        match try_sapling_output_recovery(&config.get_params(), height, &ovk, &output) {
                            Some((note, payment_address, memo_bytes)) => {
                                // Mark this tx as an outgoing tx, so we can grab all outgoing metadata
                                is_outgoing_tx = true;

                                let address = encode_payment_address(config.hrp_sapling_address(), &payment_address);

                                // Check if this is change, and if it also doesn't have a memo, don't add
                                // to the outgoing metadata.
                                // If this is change (i.e., funds sent to ourself) AND has a memo, then
                                // presumably the users is writing a memo to themself, so we will add it to
                                // the outgoing metadata, even though it might be confusing in the UI, but hopefully
                                // the user can make sense of it.
                                match Memo::try_from(memo_bytes) {
                                    Err(_) => None,
                                    Ok(memo) => {
                                        if z_addresses.contains(&address) && memo == Memo::Empty {
                                            None
                                        } else {
                                            Some(OutgoingTxMetadata {
                                                address,
                                                value: note.value,
                                                memo,
                                            })
                                        }
                                    }
                                }
                            }
                            None => None,
                        }
                    })
                    .collect::<Vec<_>>();

                // Add it to the overall outgoing metadatas
                outgoing_metadatas.extend(omds);
            }
        }

        // Step 4b: Scan the orchard part of the bundle to see if there are any memos. We'll also scan the orchard outputs
        // with our OutgoingViewingKey, to see if we can decrypt outgoing metadata
        let o_ivks = keys.read().await.get_all_orchard_ivks();
        let o_ovk = keys.read().await.okeys[0].fvk().to_ovk(orchard::keys::Scope::External);
        if let Some(o_bundle) = tx.orchard_bundle() {
            // let orchard_actions = o_bundle
            //     .actions()
            //     .into_iter()
            //     .map(|oa| (OrchardDomain::for_action(oa), oa))
            //     .collect::<Vec<_>>();

            // let decrypts = try_note_decryption(o_ivks.as_ref(), orchard_actions.as_ref());
            for oa in o_bundle.actions() {
                let domain = OrchardDomain::for_action(oa);

                for (ivk_num, ivk) in o_ivks.iter().enumerate() {
                    if let Some((note, _address, memo_bytes)) = try_note_decryption(&domain, ivk, oa) {
                        if let Ok(memo) = Memo::from_bytes(&memo_bytes) {
                            wallet_txns.write().await.add_memo_to_o_note(
                                &tx.txid(),
                                &keys.read().await.okeys[ivk_num].fvk(),
                                note,
                                memo,
                            );
                        }
                    }
                }

                // Also attempt output recovery using ovk to see if this wan an outgoing tx.
                if let Some((note, ua_address, memo_bytes)) =
                    try_output_recovery_with_ovk(&domain, &o_ovk, oa, oa.cv_net(), &oa.encrypted_note().out_ciphertext)
                {
                    is_outgoing_tx = true;
                    let address = LightWallet::<P>::orchard_ua_address(&config, &ua_address);
                    let memo = Memo::from_bytes(&memo_bytes).unwrap_or(Memo::default());

                    info!(
                        "Recovered output note of value {} memo {:?} sent to {}",
                        note.value().inner(),
                        memo,
                        address
                    );

                    // If this is just our address with an empty memo, do nothing.
                    if !(u_addresses.contains(&address) && memo == Memo::Empty) {
                        outgoing_metadatas.push(OutgoingTxMetadata {
                            address,
                            value: note.value().inner(),
                            memo,
                        });
                    }
                }
            }
        }

        // Step 5. Process t-address outputs
        // If this Tx in outgoing, i.e., we recieved sent some money in this Tx, then we need to grab all transparent outputs
        // that don't belong to us as the outgoing metadata
        if wallet_txns.read().await.total_funds_spent_in(&tx.txid()) > 0 {
            is_outgoing_tx = true;
        }

        if is_outgoing_tx {
            if let Some(t_bundle) = tx.transparent_bundle() {
                for vout in &t_bundle.vout {
                    let taddr = keys.read().await.address_from_pubkeyhash(vout.script_pubkey.address());

                    if taddr.is_some() && !taddrs_set.contains(taddr.as_ref().unwrap()) {
                        outgoing_metadatas.push(OutgoingTxMetadata {
                            address: taddr.unwrap(),
                            value: vout.value.into(),
                            memo: Memo::Empty,
                        });
                    }
                }

                // Also, if this is an outgoing transaction, then mark all the *incoming* sapling notes to this Tx as change.
                // Note that this is also done in `WalletTxns::add_new_spent`, but that doesn't take into account transparent spends,
                // so we'll do it again here.
                wallet_txns.write().await.check_notes_mark_change(&tx.txid());
            }
        }

        if !outgoing_metadatas.is_empty() {
            wallet_txns
                .write()
                .await
                .add_outgoing_metadata(&tx.txid(), outgoing_metadatas);
        }

        // Update price if available
        if price.is_some() {
            wallet_txns.write().await.set_price(&tx.txid(), price);
        }

        //info!("Finished Fetching full tx {}", tx.txid());
    }
}
