use crate::{
    blaze::{
        block_witness_data::BlockAndWitnessData, fetch_compact_blocks::FetchCompactBlocks,
        fetch_full_tx::FetchFullTxns, fetch_taddr_txns::FetchTaddrTxns, sync_status::SyncStatus,
        syncdata::BlazeSyncData, trial_decryptions::TrialDecryptions, update_notes::UpdateNotes,
    },
    compact_formats::RawTransaction,
    grpc_connector::GrpcConnector,
    lightclient::lightclient_config::MAX_REORG,
    lightwallet::{self, message::Message, now, LightWallet, NodePosition},
};
use futures::future::{join_all, AbortHandle, Abortable};
use json::{array, object, JsonValue};
use log::{error, info, warn};
use std::{
    cmp,
    collections::HashSet,
    fs::File,
    io::{self, BufReader, Error, ErrorKind, Read, Write},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    join,
    runtime::Runtime,
    sync::{mpsc::unbounded_channel, oneshot, Mutex, RwLock},
    task::yield_now,
    time::sleep,
};
use zcash_client_backend::encoding::{decode_payment_address, encode_payment_address};
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, BranchId, MAIN_NETWORK},
    memo::{Memo, MemoBytes},
    merkle_tree::CommitmentTree,
    sapling::Node,
    transaction::{components::amount::DEFAULT_FEE, Transaction, TxId},
};
use zcash_proofs::prover::LocalTxProver;

use self::lightclient_config::LightClientConfig;

pub(crate) mod checkpoints;
pub mod lightclient_config;

#[derive(Clone, Debug)]
pub struct WalletStatus {
    pub is_syncing: bool,
    pub total_blocks: u64,
    pub synced_blocks: u64,
}

impl WalletStatus {
    pub fn new() -> Self {
        WalletStatus {
            is_syncing: false,
            total_blocks: 0,
            synced_blocks: 0,
        }
    }
}

pub struct LightClient {
    pub(crate) config: LightClientConfig,
    pub(crate) wallet: LightWallet,

    mempool_monitor: std::sync::RwLock<Option<std::thread::JoinHandle<()>>>,

    sync_lock: Mutex<()>,

    bsync_data: Arc<RwLock<BlazeSyncData>>,
}

impl LightClient {
    /// Method to create a test-only version of the LightClient
    #[allow(dead_code)]
    pub async fn test_new(config: &LightClientConfig, seed_phrase: Option<String>, height: u64) -> io::Result<Self> {
        if seed_phrase.is_some() && config.wallet_exists() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Cannot create a new wallet from seed, because a wallet already exists",
            ));
        }

        let l = LightClient {
            wallet: LightWallet::new(config.clone(), seed_phrase, height)?,
            config: config.clone(),
            mempool_monitor: std::sync::RwLock::new(None),
            bsync_data: Arc::new(RwLock::new(BlazeSyncData::new(&config))),
            sync_lock: Mutex::new(()),
        };

        l.set_wallet_initial_state(height).await;

        info!("Created new wallet!");
        info!("Created LightClient to {}", &config.server);
        Ok(l)
    }

    fn write_file_if_not_exists(dir: &Box<Path>, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut file_path = dir.to_path_buf();
        file_path.push(name);
        if !file_path.exists() {
            let mut file = File::create(&file_path)?;
            file.write_all(bytes)?;
        }

        Ok(())
    }

    #[cfg(feature = "embed_params")]
    fn read_sapling_params(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        // Read Sapling Params
        use crate::SaplingParams;
        let mut sapling_output = vec![];
        sapling_output.extend_from_slice(SaplingParams::get("sapling-output.params").unwrap().as_ref());

        let mut sapling_spend = vec![];
        sapling_spend.extend_from_slice(SaplingParams::get("sapling-spend.params").unwrap().as_ref());

        Ok((sapling_output, sapling_spend))
    }

    #[cfg(not(feature = "embed_params"))]
    fn read_sapling_params(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let path = self.config.get_zcash_params_path().map_err(|e| e.to_string())?;

        let mut path_buf = path.to_path_buf();
        path_buf.push("sapling-output.params");
        let mut file = File::open(path_buf).map_err(|e| e.to_string())?;
        let mut sapling_output = vec![];
        file.read_to_end(&mut sapling_output).map_err(|e| e.to_string())?;

        let mut path_buf = path.to_path_buf();
        path_buf.push("sapling-spend.params");
        let mut file = File::open(path_buf).map_err(|e| e.to_string())?;
        let mut sapling_spend = vec![];
        file.read_to_end(&mut sapling_spend).map_err(|e| e.to_string())?;

        Ok((sapling_output, sapling_spend))
    }

    pub fn set_sapling_params(&mut self, sapling_output: &[u8], sapling_spend: &[u8]) -> Result<(), String> {
        use sha2::{Digest, Sha256};

        // The hashes of the params need to match
        const SAPLING_OUTPUT_HASH: &str = "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";
        const SAPLING_SPEND_HASH: &str = "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

        if sapling_output.len() > 0 {
            if SAPLING_OUTPUT_HASH.to_string() != hex::encode(Sha256::digest(&sapling_output)) {
                return Err(format!(
                    "sapling-output hash didn't match. expected {}, found {}",
                    SAPLING_OUTPUT_HASH,
                    hex::encode(Sha256::digest(&sapling_output))
                ));
            }
        }

        if sapling_spend.len() > 0 {
            if SAPLING_SPEND_HASH.to_string() != hex::encode(Sha256::digest(&sapling_spend)) {
                return Err(format!(
                    "sapling-spend hash didn't match. expected {}, found {}",
                    SAPLING_SPEND_HASH,
                    hex::encode(Sha256::digest(&sapling_spend))
                ));
            }
        }

        // Ensure that the sapling params are stored on disk properly as well. Only on desktop
        match self.config.get_zcash_params_path() {
            Ok(zcash_params_dir) => {
                // Create the sapling output and spend params files
                match LightClient::write_file_if_not_exists(&zcash_params_dir, "sapling-output.params", &sapling_output)
                {
                    Ok(_) => {}
                    Err(e) => return Err(format!("Warning: Couldn't write the output params!\n{}", e)),
                };

                match LightClient::write_file_if_not_exists(&zcash_params_dir, "sapling-spend.params", &sapling_spend) {
                    Ok(_) => {}
                    Err(e) => return Err(format!("Warning: Couldn't write the spend params!\n{}", e)),
                }
            }
            Err(e) => {
                return Err(format!("{}", e));
            }
        };

        Ok(())
    }

    pub async fn set_wallet_initial_state(&self, height: u64) {
        let state = self.config.get_initial_state(height).await;

        match state {
            Some((height, hash, tree)) => {
                info!("Setting initial state to height {}, tree {}", height, tree);
                self.wallet
                    .set_initial_block(height, &hash.as_str(), &tree.as_str())
                    .await;
            }
            _ => {}
        };
    }

    /// Create a brand new wallet with a new seed phrase. Will fail if a wallet file
    /// already exists on disk
    pub fn new(config: &LightClientConfig, latest_block: u64) -> io::Result<Self> {
        #[cfg(all(not(target_os = "ios"), not(target_os = "android")))]
        {
            if config.wallet_exists() {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    "Cannot create a new wallet from seed, because a wallet already exists",
                ));
            }
        }
        let l = Runtime::new().unwrap().block_on(async move {
            let l = LightClient {
                wallet: LightWallet::new(config.clone(), None, latest_block)?,
                config: config.clone(),
                mempool_monitor: std::sync::RwLock::new(None),
                sync_lock: Mutex::new(()),
                bsync_data: Arc::new(RwLock::new(BlazeSyncData::new(&config))),
            };

            l.set_wallet_initial_state(latest_block).await;

            info!("Created new wallet with a new seed!");
            info!("Created LightClient to {}", &config.server);

            // Save
            l.do_save()
                .await
                .map_err(|s| io::Error::new(ErrorKind::PermissionDenied, s))?;

            Ok(l)
        });
        l
    }

    pub fn new_from_phrase(
        seed_phrase: String,
        config: &LightClientConfig,
        birthday: u64,
        overwrite: bool,
    ) -> io::Result<Self> {
        #[cfg(all(not(target_os = "ios"), not(target_os = "android")))]
        {
            if !overwrite && config.wallet_exists() {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    format!("Cannot create a new wallet from seed, because a wallet already exists"),
                ));
            }
        }
        let l = Runtime::new().unwrap().block_on(async move {
            let l = LightClient {
                wallet: LightWallet::new(config.clone(), Some(seed_phrase), birthday)?,
                config: config.clone(),
                mempool_monitor: std::sync::RwLock::new(None),
                sync_lock: Mutex::new(()),
                bsync_data: Arc::new(RwLock::new(BlazeSyncData::new(&config))),
            };

            println!("Setting birthday to {}", birthday);
            l.set_wallet_initial_state(birthday).await;

            info!("Created new wallet!");
            info!("Created LightClient to {}", &config.server);

            // Save
            l.do_save().await.map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
            Ok(l)
        });

        l
    }

    pub fn read_from_buffer<R: Read>(config: &LightClientConfig, mut reader: R) -> io::Result<Self> {
        let l = Runtime::new().unwrap().block_on(async move {
            let wallet = LightWallet::read(&mut reader, config).await?;

            let lc = LightClient {
                wallet: wallet,
                config: config.clone(),
                mempool_monitor: std::sync::RwLock::new(None),
                sync_lock: Mutex::new(()),
                bsync_data: Arc::new(RwLock::new(BlazeSyncData::new(&config))),
            };

            info!("Read wallet with birthday {}", lc.wallet.get_birthday().await);
            info!("Created LightClient to {}", &config.server);

            Ok(lc)
        });

        l
    }

    pub fn read_from_disk(config: &LightClientConfig) -> io::Result<Self> {
        let wallet_path = if config.wallet_exists() {
            config.get_wallet_path()
        } else {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("Cannot read wallet. No file at {}", config.get_wallet_path().display()),
            ));
        };

        let l = Runtime::new().unwrap().block_on(async move {
            let mut file_buffer = BufReader::new(File::open(wallet_path)?);

            let wallet = LightWallet::read(&mut file_buffer, config).await?;

            let lc = LightClient {
                wallet: wallet,
                config: config.clone(),
                mempool_monitor: std::sync::RwLock::new(None),
                sync_lock: Mutex::new(()),
                bsync_data: Arc::new(RwLock::new(BlazeSyncData::new(&config))),
            };

            info!("Read wallet with birthday {}", lc.wallet.get_birthday().await);
            info!("Created LightClient to {}", &config.server);

            Ok(lc)
        });

        l
    }

    pub fn init_logging(&self) -> io::Result<()> {
        // Configure logging first.
        let log_config = self.config.get_log_config()?;
        log4rs::init_config(log_config).map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;

        Ok(())
    }

    // Export private keys
    pub async fn do_export(&self, addr: Option<String>) -> Result<JsonValue, &str> {
        if !self.wallet.is_unlocked_for_spending().await {
            error!("Wallet is locked");
            return Err("Wallet is locked");
        }

        // Clone address so it can be moved into the closure
        let address = addr.clone();
        // Go over all z addresses
        let z_keys = self
            .wallet
            .keys()
            .read()
            .await
            .get_z_private_keys()
            .iter()
            .filter(move |(addr, _, _)| address.is_none() || address.as_ref() == Some(addr))
            .map(|(addr, pk, vk)| {
                object! {
                    "address"     => addr.clone(),
                    "private_key" => pk.clone(),
                    "viewing_key" => vk.clone(),
                }
            })
            .collect::<Vec<JsonValue>>();

        // Clone address so it can be moved into the closure
        let address = addr.clone();

        // Go over all t addresses
        let t_keys = self
            .wallet
            .keys()
            .read()
            .await
            .get_t_secret_keys()
            .iter()
            .filter(move |(addr, _)| address.is_none() || address.as_ref() == Some(addr))
            .map(|(addr, sk)| {
                object! {
                    "address"     => addr.clone(),
                    "private_key" => sk.clone(),
                }
            })
            .collect::<Vec<JsonValue>>();

        let mut all_keys = vec![];
        all_keys.extend_from_slice(&z_keys);
        all_keys.extend_from_slice(&t_keys);

        Ok(all_keys.into())
    }

    pub async fn do_address(&self) -> JsonValue {
        // Collect z addresses
        let z_addresses = self.wallet.keys().read().await.get_all_zaddresses();

        // Collect t addresses
        let t_addresses = self.wallet.keys().read().await.get_all_taddrs();

        object! {
            "z_addresses" => z_addresses,
            "t_addresses" => t_addresses,
        }
    }

    pub async fn do_last_txid(&self) -> JsonValue {
        object! {
            "last_txid" => self.wallet.txns().read().await.get_last_txid().map(|t| t.to_string())
        }
    }

    pub async fn do_balance(&self) -> JsonValue {
        // Collect z addresses
        let mut z_addresses = vec![];
        for zaddress in self.wallet.keys().read().await.get_all_zaddresses() {
            z_addresses.push(object! {
                "address" => zaddress.clone(),
                "zbalance" =>self.wallet.zbalance(Some(zaddress.clone())).await,
                "verified_zbalance"  =>self.wallet.verified_zbalance(Some(zaddress.clone())).await,
                "spendable_zbalance" =>self.wallet.spendable_zbalance(Some(zaddress.clone())).await,
                "unverified_zbalance"   => self.wallet.unverified_zbalance(Some(zaddress.clone())).await
            });
        }

        // Collect t addresses
        let mut t_addresses = vec![];
        for taddress in self.wallet.keys().read().await.get_all_taddrs() {
            // Get the balance for this address
            let balance = self.wallet.tbalance(Some(taddress.clone())).await;

            t_addresses.push(object! {
                "address" => taddress,
                "balance" => balance,
            });
        }

        object! {
            "zbalance"           => self.wallet.zbalance(None).await,
            "verified_zbalance"  => self.wallet.verified_zbalance(None).await,
            "spendable_zbalance" => self.wallet.spendable_zbalance(None).await,
            "unverified_zbalance"   => self.wallet.unverified_zbalance(None).await,
            "tbalance"           => self.wallet.tbalance(None).await,
            "z_addresses"        => z_addresses,
            "t_addresses"        => t_addresses,
        }
    }

    pub async fn do_save(&self) -> Result<(), String> {
        // On mobile platforms, disable the save, because the saves will be handled by the native layer, and not in rust
        if cfg!(all(not(target_os = "ios"), not(target_os = "android"))) {
            // If the wallet is encrypted but unlocked, lock it again.
            {
                if self.wallet.is_encrypted().await && self.wallet.is_unlocked_for_spending().await {
                    match self.wallet.lock().await {
                        Ok(_) => {}
                        Err(e) => {
                            let err = format!("ERR: {}", e);
                            error!("{}", err);
                            return Err(e.to_string());
                        }
                    }
                }
            }

            {
                // Prevent any overlapping syncs during save, and don't save in the middle of a sync
                let _lock = self.sync_lock.lock().await;

                let mut wallet_bytes = vec![];
                match self.wallet.write(&mut wallet_bytes).await {
                    Ok(_) => {
                        let mut file = File::create(self.config.get_wallet_path()).unwrap();
                        file.write_all(&wallet_bytes).map_err(|e| format!("{}", e))?;
                        Ok(())
                    }
                    Err(e) => {
                        let err = format!("ERR: {}", e);
                        error!("{}", err);
                        Err(e.to_string())
                    }
                }
            }
        } else {
            // On ios and android just return OK
            Ok(())
        }
    }

    pub fn do_save_to_buffer_sync(&self) -> Result<Vec<u8>, String> {
        Runtime::new()
            .unwrap()
            .block_on(async move { self.do_save_to_buffer().await })
    }

    pub async fn do_save_to_buffer(&self) -> Result<Vec<u8>, String> {
        // If the wallet is encrypted but unlocked, lock it again.
        {
            if self.wallet.is_encrypted().await && self.wallet.is_unlocked_for_spending().await {
                match self.wallet.lock().await {
                    Ok(_) => {}
                    Err(e) => {
                        let err = format!("ERR: {}", e);
                        error!("{}", err);
                        return Err(e.to_string());
                    }
                }
            }
        }

        let mut buffer: Vec<u8> = vec![];
        match self.wallet.write(&mut buffer).await {
            Ok(_) => Ok(buffer),
            Err(e) => {
                let err = format!("ERR: {}", e);
                error!("{}", err);
                Err(e.to_string())
            }
        }
    }

    pub fn get_server_uri(&self) -> http::Uri {
        self.config.server.clone()
    }

    pub async fn do_zec_price(&self) -> String {
        let mut price = self.wallet.price.read().await.clone();

        // If there is no price, try to fetch it first.
        if price.zec_price.is_none() {
            self.update_current_price().await;
            price = self.wallet.price.read().await.clone();
        }

        match price.zec_price {
            None => return "Error: No price".to_string(),
            Some((ts, p)) => {
                let o = object! {
                    "zec_price" => p,
                    "fetched_at" =>  ts,
                    "currency" => price.currency
                };

                o.pretty(2)
            }
        }
    }

    pub async fn do_info(&self) -> String {
        match GrpcConnector::get_info(self.get_server_uri()).await {
            Ok(i) => {
                let o = object! {
                    "version" => i.version,
                    "git_commit" => i.git_commit,
                    "server_uri" => self.get_server_uri().to_string(),
                    "vendor" => i.vendor,
                    "taddr_support" => i.taddr_support,
                    "chain_name" => i.chain_name,
                    "sapling_activation_height" => i.sapling_activation_height,
                    "consensus_branch_id" => i.consensus_branch_id,
                    "latest_block_height" => i.block_height
                };
                o.pretty(2)
            }
            Err(e) => e,
        }
    }

    pub async fn do_send_progress(&self) -> Result<JsonValue, String> {
        let progress = self.wallet.get_send_progress().await;

        Ok(object! {
            "id" => progress.id,
            "sending" => progress.is_send_in_progress,
            "progress" => progress.progress,
            "total" => progress.total,
            "txid" => progress.last_txid,
            "error" => progress.last_error,
        })
    }

    pub fn do_seed_phrase_sync(&self) -> Result<JsonValue, &str> {
        Runtime::new()
            .unwrap()
            .block_on(async move { self.do_seed_phrase().await })
    }

    pub async fn do_seed_phrase(&self) -> Result<JsonValue, &str> {
        if !self.wallet.is_unlocked_for_spending().await {
            error!("Wallet is locked");
            return Err("Wallet is locked");
        }

        Ok(object! {
            "seed"     => self.wallet.keys().read().await.get_seed_phrase(),
            "birthday" => self.wallet.get_birthday().await
        })
    }

    // Return a list of all notes, spent and unspent
    pub async fn do_list_notes(&self, all_notes: bool) -> JsonValue {
        let mut unspent_notes: Vec<JsonValue> = vec![];
        let mut spent_notes: Vec<JsonValue> = vec![];
        let mut pending_notes: Vec<JsonValue> = vec![];

        let anchor_height = BlockHeight::from_u32(self.wallet.get_anchor_height().await);

        {
            // First, collect all extfvk's that are spendable (i.e., we have the private key)
            let spendable_address: HashSet<String> = self
                .wallet
                .keys()
                .read()
                .await
                .get_all_spendable_zaddresses()
                .into_iter()
                .collect();

            // Collect Sapling notes
            self.wallet.txns.read().await.current.iter()
                .flat_map( |(txid, wtx)| {
                    let spendable_address = spendable_address.clone();
                    wtx.notes.iter().filter_map(move |nd|
                        if !all_notes && nd.spent.is_some() {
                            None
                        } else {
                            let address = LightWallet::note_address(self.config.hrp_sapling_address(), nd);
                            let spendable = address.is_some() &&
                                                    spendable_address.contains(&address.clone().unwrap()) &&
                                                    wtx.block <= anchor_height && nd.spent.is_none() && nd.unconfirmed_spent.is_none();

                            let created_block:u32 = wtx.block.into();
                            Some(object!{
                                "created_in_block"   => created_block,
                                "datetime"           => wtx.datetime,
                                "created_in_txid"    => format!("{}", txid),
                                "value"              => nd.note.value,
                                "unconfirmed"        => wtx.unconfirmed,
                                "is_change"          => nd.is_change,
                                "address"            => address,
                                "spendable"          => spendable,
                                "spent"              => nd.spent.map(|(spent_txid, _)| format!("{}", spent_txid)),
                                "spent_at_height"    => nd.spent.map(|(_, h)| h),
                                "unconfirmed_spent"  => nd.unconfirmed_spent.map(|(spent_txid, _)| format!("{}", spent_txid)),
                            })
                        }
                    )
                })
                .for_each( |note| {
                    if note["spent"].is_null() && note["unconfirmed_spent"].is_null() {
                        unspent_notes.push(note);
                    } else if !note["spent"].is_null() {
                        spent_notes.push(note);
                    } else {
                        pending_notes.push(note);
                    }
                });
        }

        let mut unspent_utxos: Vec<JsonValue> = vec![];
        let mut spent_utxos: Vec<JsonValue> = vec![];
        let mut pending_utxos: Vec<JsonValue> = vec![];

        {
            self.wallet.txns.read().await.current.iter()
                .flat_map( |(txid, wtx)| {
                    wtx.utxos.iter().filter_map(move |utxo|
                        if !all_notes && utxo.spent.is_some() {
                            None
                        } else {
                            let created_block:u32 = wtx.block.into();

                            Some(object!{
                                "created_in_block"   => created_block,
                                "datetime"           => wtx.datetime,
                                "created_in_txid"    => format!("{}", txid),
                                "value"              => utxo.value,
                                "scriptkey"          => hex::encode(utxo.script.clone()),
                                "is_change"          => false, // TODO: Identify notes as change if we send change to our own taddrs
                                "address"            => utxo.address.clone(),
                                "spent_at_height"    => utxo.spent_at_height,
                                "spent"              => utxo.spent.map(|spent_txid| format!("{}", spent_txid)),
                                "unconfirmed_spent"  => utxo.unconfirmed_spent.map(|(spent_txid, _)| format!("{}", spent_txid)),
                            })
                        }
                    )
                })
                .for_each( |utxo| {
                    if utxo["spent"].is_null() && utxo["unconfirmed_spent"].is_null() {
                        unspent_utxos.push(utxo);
                    } else if !utxo["spent"].is_null() {
                        spent_utxos.push(utxo);
                    } else {
                        pending_utxos.push(utxo);
                    }
                });
        }

        let mut res = object! {
            "unspent_notes" => unspent_notes,
            "pending_notes" => pending_notes,
            "utxos"         => unspent_utxos,
            "pending_utxos" => pending_utxos,
        };

        if all_notes {
            res["spent_notes"] = JsonValue::Array(spent_notes);
            res["spent_utxos"] = JsonValue::Array(spent_utxos);
        }

        res
    }

    pub fn do_encrypt_message(&self, to_address_str: String, memo: Memo) -> JsonValue {
        let to = match decode_payment_address(self.config.hrp_sapling_address(), &to_address_str) {
            Ok(Some(to)) => to,
            _ => {
                return object! {"error" => format!("Couldn't parse {} as a z-address", to_address_str) };
            }
        };

        match Message::new(to, memo).encrypt() {
            Ok(v) => {
                object! {"encrypted_base64" => base64::encode(v) }
            }
            Err(e) => {
                object! {"error" => format!("Couldn't encrypt. Error was {}", e)}
            }
        }
    }

    pub async fn do_decrypt_message(&self, enc_base64: String) -> JsonValue {
        let data = match base64::decode(enc_base64) {
            Ok(v) => v,
            Err(e) => return object! {"error" => format!("Couldn't decode base64. Error was {}", e)},
        };

        match self.wallet.decrypt_message(data).await {
            Some(m) => {
                let memo_bytes: MemoBytes = m.memo.clone().into();
                object! {
                    "to" => encode_payment_address(self.config.hrp_sapling_address(), &m.to),
                    "memo" => LightWallet::memo_str(Some(m.memo)),
                    "memohex" => hex::encode(memo_bytes.as_slice())
                }
            }
            None => object! { "error" => "Couldn't decrypt with any of the wallet's keys"},
        }
    }

    pub async fn do_encryption_status(&self) -> JsonValue {
        object! {
            "encrypted" => self.wallet.is_encrypted().await,
            "locked"    => !self.wallet.is_unlocked_for_spending().await
        }
    }

    pub async fn do_list_transactions(&self, include_memo_hex: bool) -> JsonValue {
        // Create a list of TransactionItems from wallet txns
        let mut tx_list = self
            .wallet
            .txns
            .read()
            .await
            .current
            .iter()
            .flat_map(|(_k, v)| {
                let mut txns: Vec<JsonValue> = vec![];

                if v.total_sapling_value_spent + v.total_transparent_value_spent > 0 {
                    // If money was spent, create a transaction. For this, we'll subtract
                    // all the change notes + Utxos
                    let total_change = v
                        .notes
                        .iter()
                        .filter(|nd| nd.is_change)
                        .map(|nd| nd.note.value)
                        .sum::<u64>()
                        + v.utxos.iter().map(|ut| ut.value).sum::<u64>();

                    // Collect outgoing metadata
                    let outgoing_json = v
                        .outgoing_metadata
                        .iter()
                        .map(|om| {
                            let mut o = object! {
                                "address" => om.address.clone(),
                                "value"   => om.value,
                                "memo"    => LightWallet::memo_str(Some(om.memo.clone()))
                            };

                            if include_memo_hex {
                                let memo_bytes: MemoBytes = om.memo.clone().into();
                                o.insert("memohex", hex::encode(memo_bytes.as_slice())).unwrap();
                            }

                            return o;
                        })
                        .collect::<Vec<JsonValue>>();

                    let block_height: u32 = v.block.into();
                    txns.push(object! {
                        "block_height" => block_height,
                        "unconfirmed" => v.unconfirmed,
                        "datetime"     => v.datetime,
                        "txid"         => format!("{}", v.txid),
                        "zec_price"    => v.zec_price,
                        "amount"       => total_change as i64
                                            - v.total_sapling_value_spent as i64
                                            - v.total_transparent_value_spent as i64,
                        "outgoing_metadata" => outgoing_json,
                    });
                }

                // For each sapling note that is not a change, add a Tx.
                txns.extend(v.notes.iter().filter(|nd| !nd.is_change).enumerate().map(|(i, nd)| {
                    let block_height: u32 = v.block.into();
                    let mut o = object! {
                        "block_height" => block_height,
                        "unconfirmed" => v.unconfirmed,
                        "datetime"     => v.datetime,
                        "position"     => i,
                        "txid"         => format!("{}", v.txid),
                        "zec_price"    => v.zec_price,
                        "amount"       => nd.note.value as i64,
                        "address"      => LightWallet::note_address(self.config.hrp_sapling_address(), nd),
                        "memo"         => LightWallet::memo_str(nd.memo.clone())
                    };

                    if include_memo_hex {
                        o.insert(
                            "memohex",
                            match &nd.memo {
                                Some(m) => {
                                    let memo_bytes: MemoBytes = m.into();
                                    hex::encode(memo_bytes.as_slice())
                                }
                                _ => "".to_string(),
                            },
                        )
                        .unwrap();
                    }

                    return o;
                }));

                // Get the total transparent received
                let total_transparent_received = v.utxos.iter().map(|u| u.value).sum::<u64>();
                if total_transparent_received > v.total_transparent_value_spent {
                    // Create an input transaction for the transparent value as well.
                    let block_height: u32 = v.block.into();
                    txns.push(object! {
                        "block_height" => block_height,
                        "unconfirmed" => v.unconfirmed,
                        "datetime"     => v.datetime,
                        "txid"         => format!("{}", v.txid),
                        "zec_price"    => v.zec_price,
                        "amount"       => total_transparent_received as i64 - v.total_transparent_value_spent as i64,
                        "address"      => v.utxos.iter().map(|u| u.address.clone()).collect::<Vec<String>>().join(","),
                        "memo"         => None::<String>
                    })
                }

                txns
            })
            .collect::<Vec<JsonValue>>();

        tx_list.sort_by(|a, b| {
            if a["block_height"] == b["block_height"] {
                a["txid"].as_str().cmp(&b["txid"].as_str())
            } else {
                a["block_height"].as_i32().cmp(&b["block_height"].as_i32())
            }
        });

        JsonValue::Array(tx_list)
    }

    /// Create a new address, deriving it from the seed.
    pub async fn do_new_address(&self, addr_type: &str) -> Result<JsonValue, String> {
        if !self.wallet.is_unlocked_for_spending().await {
            error!("Wallet is locked");
            return Err("Wallet is locked".to_string());
        }

        let new_address = {
            let addr = match addr_type {
                "z" => self.wallet.keys().write().await.add_zaddr(),
                "t" => self.wallet.keys().write().await.add_taddr(),
                _ => {
                    let e = format!("Unrecognized address type: {}", addr_type);
                    error!("{}", e);
                    return Err(e);
                }
            };

            if addr.starts_with("Error") {
                let e = format!("Error creating new address: {}", addr);
                error!("{}", e);
                return Err(e);
            }

            addr
        };

        self.do_save().await?;

        Ok(array![new_address])
    }

    /// Convinence function to determine what type of key this is and import it
    pub async fn do_import_key(&self, key: String, birthday: u64) -> Result<JsonValue, String> {
        if key.starts_with(self.config.hrp_sapling_private_key()) {
            self.do_import_sk(key, birthday).await
        } else if key.starts_with(self.config.hrp_sapling_viewing_key()) {
            self.do_import_vk(key, birthday).await
        } else {
            Err(format!("'{}' was not recognized as either a spending key or a viewing key because it didn't start with either '{}' or '{}'", 
                key, self.config.hrp_sapling_private_key(), self.config.hrp_sapling_viewing_key()))
        }
    }

    /// Import a new private key
    pub async fn do_import_sk(&self, sk: String, birthday: u64) -> Result<JsonValue, String> {
        if !self.wallet.is_unlocked_for_spending().await {
            error!("Wallet is locked");
            return Err("Wallet is locked".to_string());
        }

        let new_address = {
            let addr = self.wallet.add_imported_sk(sk, birthday).await;
            if addr.starts_with("Error") {
                let e = format!("Error creating new address{}", addr);
                error!("{}", e);
                return Err(e);
            }

            addr
        };

        self.do_save().await?;

        Ok(array![new_address])
    }

    /// Import a new viewing key
    pub async fn do_import_vk(&self, vk: String, birthday: u64) -> Result<JsonValue, String> {
        if !self.wallet.is_unlocked_for_spending().await {
            error!("Wallet is locked");
            return Err("Wallet is locked".to_string());
        }

        let new_address = {
            let addr = self.wallet.add_imported_vk(vk, birthday).await;
            if addr.starts_with("Error") {
                let e = format!("Error creating new address{}", addr);
                error!("{}", e);
                return Err(e);
            }

            addr
        };

        self.do_save().await?;

        Ok(array![new_address])
    }

    pub async fn clear_state(&self) {
        // First, clear the state from the wallet
        self.wallet.clear_all().await;

        // Then set the initial block
        let birthday = self.wallet.get_birthday().await;
        self.set_wallet_initial_state(birthday).await;
        info!("Cleared wallet state, with birthday at {}", birthday);
    }

    pub async fn do_rescan(&self) -> Result<JsonValue, String> {
        if !self.wallet.is_unlocked_for_spending().await {
            warn!("Wallet is locked, new HD addresses won't be added!");
        }

        info!("Rescan starting");

        self.clear_state().await;

        // Then, do a sync, which will force a full rescan from the initial state
        let response = self.do_sync(true).await;

        if response.is_ok() {
            // At the end of a rescan, remove unused addresses.
            self.wallet.remove_unused_taddrs().await;
            self.wallet.remove_unused_zaddrs().await;

            self.do_save().await?;
        }

        info!("Rescan finished");

        response
    }

    pub async fn do_verify_from_last_checkpoint(&self) -> Result<bool, String> {
        // If there are no blocks in the wallet, then we are starting from scratch, so no need to verify anything.
        let last_height = self.wallet.last_scanned_height().await;
        if last_height == self.config.sapling_activation_height - 1 {
            info!(
                "Reset the sapling tree verified to true. (Block height is at the begining ({}))",
                last_height
            );
            self.wallet.set_sapling_tree_verified();

            return Ok(true);
        }

        // Get the oldest block's details, and make sure we can compute it from the last checkpoint
        // Note that we get the oldest block in the wallet (Not the latest one). This is expected to be tip - 100 blocks.
        // We use this block to prevent any reorg risk.
        let (end_height, _, end_tree) = match self.wallet.get_wallet_sapling_tree(NodePosition::Oldest).await {
            Ok(r) => r,
            Err(e) => return Err(format!("No wallet block found: {}", e)),
        };

        // Get the last checkpoint
        let (start_height, _, start_tree) =
            match checkpoints::get_closest_checkpoint(&self.config.chain_name, end_height as u64) {
                Some(r) => r,
                None => return Err(format!("No checkpoint found")),
            };

        // If the height is the same as the checkpoint, then just compare directly
        if end_height as u64 == start_height {
            let verified = end_tree == start_tree;

            if verified {
                info!("Reset the sapling tree verified to true");
                self.wallet.set_sapling_tree_verified();
            } else {
                warn!("Sapling tree verification failed!");
                let e = format!(
                    "Verification Results:\nCalculated\n{}\nExpected\n{}\n",
                    start_tree, end_tree
                );
                warn!("{}", e);
                return Err(e);
            }

            return Ok(verified);
        }

        let sapling_tree = hex::decode(start_tree).unwrap();

        // The comupted commitment tree will be here.
        let commit_tree_computed = Arc::new(RwLock::new(
            CommitmentTree::read(&sapling_tree[..]).map_err(|e| format!("{}", e))?,
        ));

        let uri = self.get_server_uri();
        let (tx, mut rx) = unbounded_channel();

        let h1 = tokio::spawn(async move {
            let grpc_conn = GrpcConnector::new(uri);
            // Since both start and end block are inclusive, do start_height+1 to end_height
            grpc_conn.get_block_range(start_height + 1, end_height, tx).await
        });

        let commit_tree = commit_tree_computed.clone();
        let h2 = tokio::spawn(async move {
            while let Some(cb) = rx.recv().await {
                // Go over all tx, all outputs. No need to do any processing, just update the commitment tree
                for tx in cb.vtx.iter() {
                    for so in tx.outputs.iter() {
                        let node = Node::new(so.cmu().ok().unwrap().into());
                        commit_tree.write().await.append(node).unwrap();
                    }
                }

                // Write updates every now and then.
                if cb.height % 10000 == 0 {
                    info!("Verification at block {}", cb.height);
                }
            }
        });

        let (r1, r2) = join!(h1, h2);
        r1.map_err(|e| format!("{}", e))??;
        r2.map_err(|e| format!("{}", e))?;

        // Get the string version of the tree
        let mut write_buf = vec![];
        commit_tree_computed
            .write()
            .await
            .write(&mut write_buf)
            .map_err(|e| format!("{}", e))?;
        let computed_tree = hex::encode(write_buf);

        let verified = computed_tree == end_tree;
        if verified {
            info!("Reset the sapling tree verified to true");
            self.wallet.set_sapling_tree_verified();
        } else {
            warn!("Sapling tree verification failed!");
            let e = format!(
                "Verification Results:\nComputed@{}-{}\n{}\nExpected@{}\n{}\n",
                start_height + 1,
                end_height,
                computed_tree,
                end_height,
                end_tree
            );
            warn!("{}", e);
            return Err(e);
        }

        return Ok(verified);
    }

    /// Return the syncing status of the wallet
    // pub fn do_scan_status(&self) -> WalletStatus {
    //     self.sync_status.read().unwrap().clone()
    // }

    async fn update_current_price(&self) {
        // Get the zec price from the server
        match GrpcConnector::get_current_zec_price(self.get_server_uri()).await {
            Ok(p) => {
                self.wallet.set_latest_zec_price(p.price).await;
            }
            Err(s) => error!("Error fetching latest price: {}", s),
        }
    }

    // Update the historical prices in the wallet, if any are present.
    async fn update_historical_prices(&self) {
        let price = self.wallet.price.read().await.clone();

        // Gather all transactions that need historical prices
        let txids_to_fetch = self
            .wallet
            .txns
            .read()
            .await
            .current
            .iter()
            .filter_map(|(txid, wtx)| match wtx.zec_price {
                None => Some((txid.clone(), wtx.datetime)),
                Some(_) => None,
            })
            .collect::<Vec<(TxId, u64)>>();

        if txids_to_fetch.is_empty() {
            return;
        }

        info!("Fetching historical prices for {} txids", txids_to_fetch.len());

        let retry_count_increase =
            match GrpcConnector::get_historical_zec_prices(self.get_server_uri(), txids_to_fetch, price.currency).await
            {
                Ok(prices) => {
                    let mut any_failed = false;

                    for (txid, p) in prices {
                        match p {
                            None => any_failed = true,
                            Some(p) => {
                                // Update the price
                                // info!("Historical price at txid {} was {}", txid, p);
                                self.wallet.txns.write().await.current.get_mut(&txid).unwrap().zec_price = Some(p);
                            }
                        }
                    }

                    // If any of the txids failed, increase the retry_count by 1.
                    if any_failed {
                        1
                    } else {
                        0
                    }
                }
                Err(_) => 1,
            };

        {
            let mut p = self.wallet.price.write().await;
            p.last_historical_prices_fetched_at = Some(lightwallet::now());
            p.historical_prices_retry_count += retry_count_increase;
        }
    }

    pub async fn do_sync_status(&self) -> SyncStatus {
        self.bsync_data.read().await.sync_status.read().await.clone()
    }

    pub fn start_mempool_monitor(lc: Arc<LightClient>) {
        if !lc.config.monitor_mempool {
            return;
        }

        if lc.mempool_monitor.read().unwrap().is_some() {
            return;
        }

        let config = lc.config.clone();
        let uri = config.server.clone();
        let lci = lc.clone();

        info!("Mempool monitoring starting");

        // Start monitoring the mempool in a new thread
        let h = std::thread::spawn(move || {
            // Start a new async runtime, which is fine because we are in a new thread.
            Runtime::new().unwrap().block_on(async move {
                let (mempool_tx, mut mempool_rx) = unbounded_channel::<RawTransaction>();
                let lc1 = lci.clone();

                let h1 = tokio::spawn(async move {
                    let keys = lc1.wallet.keys();
                    let wallet_txns = lc1.wallet.txns.clone();
                    let price = lc1.wallet.price.clone();

                    while let Some(rtx) = mempool_rx.recv().await {
                        if let Ok(tx) = Transaction::read(&rtx.data[..]) {
                            let price = price.read().await.clone();
                            //info!("Mempool attempting to scan {}", tx.txid());

                            FetchFullTxns::scan_full_tx(
                                config.clone(),
                                tx,
                                BlockHeight::from_u32(rtx.height as u32),
                                true,
                                now() as u32,
                                keys.clone(),
                                wallet_txns.clone(),
                                &price,
                            )
                            .await;
                        }
                    }
                });

                let h2 = tokio::spawn(async move {
                    loop {
                        //info!("Monitoring mempool");
                        let r = GrpcConnector::monitor_mempool(uri.clone(), mempool_tx.clone()).await;

                        if r.is_err() {
                            warn!("Mempool monitor returned {:?}, will restart listening", r);
                            sleep(Duration::from_secs(10)).await;
                        } else {
                            let _ = lci.do_sync(false).await;
                        }
                    }
                });

                let (_, _) = join!(h1, h2);
            });
        });

        *lc.mempool_monitor.write().unwrap() = Some(h);
    }

    pub async fn do_sync(&self, print_updates: bool) -> Result<JsonValue, String> {
        // Remember the previous sync id first
        let prev_sync_id = self.bsync_data.read().await.sync_status.read().await.sync_id;

        // Start the sync with an abortable handle
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let r_fut = Abortable::new(self.start_sync(), abort_registration);

        // If printing updates, start a new task to print updates every 2 seconds.
        let sync_result = if print_updates {
            let sync_status = self.bsync_data.read().await.sync_status.clone();
            let (tx, mut rx) = oneshot::channel::<i32>();

            tokio::spawn(async move {
                while sync_status.read().await.sync_id == prev_sync_id {
                    yield_now().await;
                    sleep(Duration::from_secs(1)).await;
                }

                let mut prev_progress = format!("");
                let mut stuck_ctr = 0;
                loop {
                    if let Ok(_t) = rx.try_recv() {
                        break;
                    }

                    let progress = format!("{}", sync_status.read().await);
                    if print_updates {
                        println!("{}", progress);
                    }

                    // Check to see if we're making any progress
                    if prev_progress != progress {
                        stuck_ctr = 0;
                        prev_progress = progress;
                    } else {
                        info!("Sync stuck for {} secs", stuck_ctr * 2);
                        stuck_ctr += 1;
                    }

                    // Abort if we're stuck for more than 60*2 seconds
                    if stuck_ctr > 60 {
                        abort_handle.abort();
                    }

                    yield_now().await;
                    sleep(Duration::from_secs(2)).await;
                }
            });

            let r = r_fut.await;
            tx.send(1).unwrap();
            r
        } else {
            r_fut.await
        };

        // Mark the sync data as finished, which should clear everything
        self.bsync_data.read().await.finish().await;

        match sync_result {
            Ok(r) => r,
            Err(a) => {
                let errstr = format!("{}", a);
                warn!("Aborted! {}", errstr);
                self.bsync_data.read().await.sync_status.write().await.last_error = Some(errstr.clone());
                Ok(object! {
                    "result" => "aborted",
                    "error" => errstr
                })
            }
        }
    }

    /// Start syncing in batches with the max size, so we don't consume memory more than
    // wha twe can handle.
    async fn start_sync(&self) -> Result<JsonValue, String> {
        // We can only do one sync at a time because we sync blocks in serial order
        // If we allow multiple syncs, they'll all get jumbled up.
        let _lock = self.sync_lock.lock().await;

        // See if we need to verify first
        if !self.wallet.is_sapling_tree_verified() {
            match self.do_verify_from_last_checkpoint().await {
                Err(e) => {
                    return Err(format!(
                        "Checkpoint failed to verify with eror:{}.\nYou should rescan.",
                        e
                    ))
                }
                Ok(false) => {
                    return Err(format!(
                        "Checkpoint failed to verify: Verification returned false.\nYou should rescan."
                    ))
                }
                _ => {}
            }
        }

        // The top of the wallet
        let last_scanned_height = self.wallet.last_scanned_height().await;

        let uri = self.config.server.clone();
        let latest_blockid = GrpcConnector::get_latest_block(uri.clone()).await?;
        if latest_blockid.height < last_scanned_height {
            let w = format!(
                "Server's latest block({}) is behind ours({})",
                latest_blockid.height, last_scanned_height
            );
            warn!("{}", w);
            return Err(w);
        }

        if latest_blockid.height == last_scanned_height {
            if !latest_blockid.hash.is_empty()
                && BlockHash::from_slice(&latest_blockid.hash).to_string() != self.wallet.last_scanned_hash().await
            {
                warn!("One block reorg at height {}", last_scanned_height);
                // This is a one-block reorg, so pop the last block. Even if there are more blocks to reorg, this is enough
                // to trigger a sync, which will then reorg the remaining blocks
                BlockAndWitnessData::invalidate_block(
                    last_scanned_height,
                    self.wallet.blocks.clone(),
                    self.wallet.txns.clone(),
                )
                .await;
            }
        }

        // Re-read the last scanned height
        let last_scanned_height = self.wallet.last_scanned_height().await;
        let batch_size = 500_000;

        let mut latest_block_batches = vec![];
        let mut prev = last_scanned_height;
        while latest_block_batches.is_empty() || prev != latest_blockid.height {
            let batch = cmp::min(latest_blockid.height, prev + batch_size);
            prev = batch;
            latest_block_batches.push(batch);
        }

        //println!("Batches are {:?}", latest_block_batches);

        // Increment the sync ID so the caller can determine when it is over
        self.bsync_data
            .write()
            .await
            .sync_status
            .write()
            .await
            .start_new(latest_block_batches.len());

        let mut res = Err("No batches were run!".to_string());
        for (batch_num, batch_latest_block) in latest_block_batches.into_iter().enumerate() {
            res = self.start_sync_batch(batch_latest_block, batch_num).await;
            if res.is_err() {
                return res;
            }
        }

        res
    }

    /// start_sync will start synchronizing the blockchain from the wallet's last height. This function will return immediately after starting the sync
    /// Use the `sync_status` command to get the status of the sync
    async fn start_sync_batch(&self, latest_block: u64, batch_num: usize) -> Result<JsonValue, String> {
        let uri = self.config.server.clone();

        // The top of the wallet
        let last_scanned_height = self.wallet.last_scanned_height().await;

        info!(
            "Latest block is {}, wallet block is {}",
            latest_block, last_scanned_height
        );

        if last_scanned_height == latest_block {
            info!("Already at latest block, not syncing");
            return Ok(object! { "result" => "success" });
        }

        let bsync_data = self.bsync_data.clone();

        let start_block = latest_block;
        let end_block = last_scanned_height + 1;

        // Before we start, we need to do a few things
        // 1. Pre-populate the last 100 blocks, in case of reorgs
        bsync_data
            .write()
            .await
            .setup_for_sync(start_block, end_block, batch_num, self.wallet.get_blocks().await)
            .await;

        // 2. Update the current price
        self.update_current_price().await;
        let price = self.wallet.price.read().await.clone();

        // Sapling Tree GRPC Fetcher
        let grpc_connector = GrpcConnector::new(uri.clone());

        // A signal to detect reorgs, and if so, ask the block_fetcher to fetch new blocks.
        let (reorg_tx, reorg_rx) = unbounded_channel();

        // Node and Witness Data Cache
        let (block_and_witness_handle, block_and_witness_data_tx) = bsync_data
            .read()
            .await
            .block_data
            .start(start_block, end_block, self.wallet.txns(), reorg_tx)
            .await;

        // Full Tx GRPC fetcher
        let (fulltx_fetcher_handle, fulltx_fetcher_tx) = grpc_connector.start_fulltx_fetcher().await;

        // Transparent Transactions Fetcher
        let (taddr_fetcher_handle, taddr_fetcher_tx) = grpc_connector.start_taddr_txn_fetcher().await;

        // The processor to fetch the full transactions, and decode the memos and the outgoing metadata
        let fetch_full_tx_processor =
            FetchFullTxns::new(&self.config, self.wallet.keys(), self.wallet.txns(), price.clone());
        let (fetch_full_txns_handle, fetch_full_txn_tx, fetch_taddr_txns_tx) = fetch_full_tx_processor
            .start(fulltx_fetcher_tx, bsync_data.clone())
            .await;

        // The processor to process Transactions detected by the trial decryptions processor
        let update_notes_processor = UpdateNotes::new(self.wallet.txns(), price.clone());
        let (update_notes_handle, blocks_done_tx, detected_txns_tx) = update_notes_processor
            .start(bsync_data.clone(), fetch_full_txn_tx)
            .await;

        // Do Trial decryptions of all the sapling outputs, and pass on the successful ones to the update_notes processor
        let trial_decryptions_processor = TrialDecryptions::new(self.wallet.keys(), self.wallet.txns(), price.clone());
        let (trial_decrypts_handle, trial_decrypts_tx) = trial_decryptions_processor
            .start(uri.clone(), bsync_data.clone(), detected_txns_tx)
            .await;

        // Fetch Compact blocks and send them to nullifier cache, node-and-witness cache and the trial-decryption processor
        let fetch_compact_blocks = Arc::new(FetchCompactBlocks::new(&self.config));
        let fetch_compact_blocks_handle = tokio::spawn(async move {
            fetch_compact_blocks
                .start(
                    vec![block_and_witness_data_tx, trial_decrypts_tx],
                    start_block,
                    end_block,
                    reorg_rx,
                )
                .await
        });

        // We wait first for the node's to be updated. This is where reorgs will be handled, so all the steps done after this phase will
        // assume that the reorgs are done.
        let earliest_block = block_and_witness_handle.await.unwrap().unwrap();

        // 1. Fetch the transparent txns only after reorgs are done.
        let taddr_txns_handle = FetchTaddrTxns::new(self.wallet.keys())
            .start(start_block, earliest_block, taddr_fetcher_tx, fetch_taddr_txns_tx)
            .await;

        // 2. Notify the notes updater that the blocks are done updating
        blocks_done_tx.send(earliest_block).unwrap();

        // Wait for everything to finish

        // Await all the futures
        let r1 = tokio::spawn(async move {
            join_all(vec![trial_decrypts_handle, fulltx_fetcher_handle, taddr_fetcher_handle])
                .await
                .into_iter()
                .map(|r| r.map_err(|e| format!("{}", e)))
                .collect::<Result<(), _>>()
        });

        join_all(vec![
            update_notes_handle,
            taddr_txns_handle,
            fetch_compact_blocks_handle,
            fetch_full_txns_handle,
            r1,
        ])
        .await
        .into_iter()
        .map(|r| r.map_err(|e| format!("{}", e))?)
        .collect::<Result<(), String>>()?;

        info!("Sync finished, doing post-processing");

        // Post sync, we have to do a bunch of stuff
        // 1. Get the last 100 blocks and store it into the wallet, needed for future re-orgs
        let blocks = bsync_data.read().await.block_data.finish_get_blocks(MAX_REORG).await;
        self.wallet.set_blocks(blocks).await;

        // 2. If sync was successfull, also try to get historical prices
        self.update_historical_prices().await;

        // 3. Mark the sync finished, which will clear the nullifier cache etc...
        bsync_data.read().await.finish().await;

        // 4. Remove the witnesses for spent notes more than 100 blocks old, since now there
        // is no risk of reorg
        self.wallet.txns().write().await.clear_old_witnesses(latest_block);

        // 5. Remove expired mempool transactions, if any
        self.wallet.txns().write().await.clear_expired_mempool(latest_block);

        Ok(object! {
            "result" => "success",
            "latest_block" => latest_block,
            "total_blocks_synced" => start_block - end_block + 1,
        })
    }

    pub async fn do_shield(&self, address: Option<String>) -> Result<String, String> {
        let fee = u64::from(DEFAULT_FEE);
        let tbal = self.wallet.tbalance(None).await;

        // Make sure there is a balance, and it is greated than the amount
        if tbal <= fee {
            return Err(format!(
                "Not enough transparent balance to shield. Have {} zats, need more than {} zats to cover tx fee",
                tbal, fee
            ));
        }

        let addr = address
            .or(self
                .wallet
                .keys()
                .read()
                .await
                .get_all_zaddresses()
                .get(0)
                .map(|s| s.clone()))
            .unwrap();
        let branch_id = self.consensus_branch_id().await;

        let result = {
            let _lock = self.sync_lock.lock().await;
            let (sapling_spend, sapling_output) = self.read_sapling_params()?;

            let prover = LocalTxProver::from_bytes(&sapling_spend, &sapling_output);

            self.wallet
                .send_to_address(branch_id, prover, true, vec![(&addr, tbal - fee, None)], |txbytes| {
                    GrpcConnector::send_transaction(self.get_server_uri(), txbytes)
                })
                .await
        };

        result.map(|(txid, _)| txid)
    }

    async fn consensus_branch_id(&self) -> u32 {
        let height = self.wallet.last_scanned_height().await;
        let branch: BranchId = BranchId::for_height(&MAIN_NETWORK, BlockHeight::from_u32(height as u32));
        let branch_id: u32 = u32::from(branch);

        branch_id
    }

    pub async fn do_send(&self, addrs: Vec<(&str, u64, Option<String>)>) -> Result<String, String> {
        // First, get the concensus branch ID
        let branch_id = self.consensus_branch_id().await;
        info!("Creating transaction");

        let result = {
            let _lock = self.sync_lock.lock().await;
            let (sapling_output, sapling_spend) = self.read_sapling_params()?;

            let prover = LocalTxProver::from_bytes(&sapling_spend, &sapling_output);

            self.wallet
                .send_to_address(branch_id, prover, false, addrs, |txbytes| {
                    GrpcConnector::send_transaction(self.get_server_uri(), txbytes)
                })
                .await
        };

        result.map(|(txid, _)| txid)
    }

    #[cfg(test)]
    pub async fn test_do_send(&self, addrs: Vec<(&str, u64, Option<String>)>) -> Result<String, String> {
        // First, get the concensus branch ID
        let branch_id = self.consensus_branch_id().await;
        info!("Creating transaction");

        let result = {
            let _lock = self.sync_lock.lock().await;
            let prover = crate::blaze::test_utils::FakeTxProver {};

            self.wallet
                .send_to_address(branch_id, prover, false, addrs, |txbytes| {
                    GrpcConnector::send_transaction(self.get_server_uri(), txbytes)
                })
                .await
        };

        result.map(|(txid, _)| txid)
    }
}

#[cfg(test)]
pub mod tests;

#[cfg(test)]
pub(crate) mod test_server;
