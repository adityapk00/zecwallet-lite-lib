use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use futures::Future;
use log::{error, info, warn};
use std::{
    cmp,
    collections::HashMap,
    convert::TryFrom,
    io::{self, Error, ErrorKind, Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicU64},
        mpsc::channel,
        Arc,
    },
    time::SystemTime,
};
use tokio::sync::RwLock;
use zcash_client_backend::{
    address,
    encoding::{decode_extended_full_viewing_key, decode_extended_spending_key, encode_payment_address},
};
use zcash_primitives::{
    consensus::{BlockHeight, BranchId, MAIN_NETWORK},
    legacy::Script,
    memo::Memo,
    merkle_tree::CommitmentTree,
    prover::TxProver,
    serialize::Vector,
    transaction::{
        builder::Builder,
        components::{amount::DEFAULT_FEE, Amount, OutPoint, TxOut},
    },
    zip32::ExtendedFullViewingKey,
};

use crate::{
    blaze::fetch_full_tx::FetchFullTxns,
    lightclient::lightclient_config::LightClientConfig,
    lightwallet::{
        data::SpendableNote,
        walletzkey::{WalletZKey, WalletZKeyType},
    },
};

use self::{
    data::{BlockData, SaplingNoteData, Utxo, WalletZecPriceInfo},
    keys::Keys,
    message::Message,
    wallet_txns::WalletTxns,
};

pub(crate) mod data;
mod extended_key;
pub(crate) mod keys;
pub(crate) mod message;
pub(crate) mod utils;
pub(crate) mod wallet_txns;
mod walletzkey;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Clone)]
pub struct SendProgress {
    pub id: u32,
    pub is_send_in_progress: bool,
    pub progress: u32,
    pub total: u32,
    pub last_error: Option<String>,
    pub last_txid: Option<String>,
}

impl SendProgress {
    fn new(id: u32) -> Self {
        SendProgress {
            id,
            is_send_in_progress: false,
            progress: 0,
            total: 0,
            last_error: None,
            last_txid: None,
        }
    }
}

// Enum to refer to the first or last position of the Node
pub enum NodePosition {
    Oldest,
    Highest,
}

pub struct LightWallet {
    // All the keys in the wallet
    keys: Arc<RwLock<Keys>>,

    // The block at which this wallet was born. Rescans
    // will start from here.
    birthday: AtomicU64,

    // The last 100 blocks, used if something gets re-orged
    pub(super) blocks: Arc<RwLock<Vec<BlockData>>>,

    // List of all txns
    pub(crate) txns: Arc<RwLock<WalletTxns>>,

    // Non-serialized fields
    config: LightClientConfig,

    // If this wallet's initial block was verified
    sapling_tree_verified: AtomicBool,

    // Progress of an outgoing tx
    send_progress: Arc<RwLock<SendProgress>>,

    // The current price of ZEC. (time_fetched, price in USD)
    pub price: Arc<RwLock<WalletZecPriceInfo>>,
}

impl LightWallet {
    pub fn serialized_version() -> u64 {
        return 21;
    }

    pub fn new(config: LightClientConfig, seed_phrase: Option<String>, height: u64) -> io::Result<Self> {
        let keys = Keys::new(&config, seed_phrase).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        Ok(Self {
            keys: Arc::new(RwLock::new(keys)),
            txns: Arc::new(RwLock::new(WalletTxns::new())),
            blocks: Arc::new(RwLock::new(vec![])),
            config,
            birthday: AtomicU64::new(height),
            sapling_tree_verified: AtomicBool::new(false),
            send_progress: Arc::new(RwLock::new(SendProgress::new(0))),
            price: Arc::new(RwLock::new(WalletZecPriceInfo::new())),
        })
    }

    pub async fn read<R: Read>(mut reader: R, config: &LightClientConfig) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        if version > Self::serialized_version() {
            let e = format!(
                "Don't know how to read wallet version {}. Do you have the latest version?",
                version
            );
            error!("{}", e);
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }

        info!("Reading wallet version {}", version);

        let keys = if version <= 14 {
            Keys::read_old(version, &mut reader, config)
        } else {
            Keys::read(&mut reader, config)
        }?;

        let mut blocks = Vector::read(&mut reader, |r| BlockData::read(r))?;
        if version <= 14 {
            // Reverse the order, since after version 20, we need highest-block-first
            blocks = blocks.into_iter().rev().collect();
        }

        let mut txns = if version <= 14 {
            WalletTxns::read_old(&mut reader)
        } else {
            WalletTxns::read(&mut reader)
        }?;

        let chain_name = utils::read_string(&mut reader)?;

        if chain_name != config.chain_name {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Wallet chain name {} doesn't match expected {}",
                    chain_name, config.chain_name
                ),
            ));
        }

        let birthday = reader.read_u64::<LittleEndian>()?;

        let sapling_tree_verified = if version <= 12 { true } else { reader.read_u8()? == 1 };

        // If version <= 8, adjust the "is_spendable" status of each note data
        if version <= 8 {
            // Collect all spendable keys
            let spendable_keys: Vec<_> = keys
                .get_all_extfvks()
                .into_iter()
                .filter(|extfvk| keys.have_spending_key(extfvk))
                .collect();

            txns.adjust_spendable_status(spendable_keys);
        }

        let price = if version <= 13 {
            WalletZecPriceInfo::new()
        } else {
            WalletZecPriceInfo::read(&mut reader)?
        };

        let mut lw = Self {
            keys: Arc::new(RwLock::new(keys)),
            txns: Arc::new(RwLock::new(txns)),
            blocks: Arc::new(RwLock::new(blocks)),
            config: config.clone(),
            birthday: AtomicU64::new(birthday),
            sapling_tree_verified: AtomicBool::new(sapling_tree_verified),
            send_progress: Arc::new(RwLock::new(SendProgress::new(0))),
            price: Arc::new(RwLock::new(price)),
        };

        // For old wallets, remove unused addresses
        if version <= 14 {
            lw.remove_unused_taddrs().await;
            lw.remove_unused_zaddrs().await;
        }

        if version <= 14 {
            lw.set_witness_block_heights().await;
        }

        Ok(lw)
    }

    pub async fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.keys.read().await.encrypted && self.keys.read().await.unlocked {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Cannot write while wallet is unlocked while encrypted."),
            ));
        }

        // Write the version
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // Write all the keys
        self.keys.read().await.write(&mut writer)?;

        Vector::write(&mut writer, &self.blocks.read().await, |w, b| b.write(w))?;

        self.txns.read().await.write(&mut writer)?;

        utils::write_string(&mut writer, &self.config.chain_name)?;

        // While writing the birthday, get it from the fn so we recalculate it properly
        // in case of rescans etc...
        writer.write_u64::<LittleEndian>(self.get_birthday().await)?;

        // If the sapling tree was verified
        writer.write_u8(if self.is_sapling_tree_verified() { 1 } else { 0 })?;

        // Price info
        self.price.read().await.write(&mut writer)?;

        Ok(())
    }

    // Before version 20, witnesses didn't store their height, so we need to update them.
    pub async fn set_witness_block_heights(&mut self) {
        let top_height = self.last_scanned_height().await;
        self.txns.write().await.current.iter_mut().for_each(|(_, wtx)| {
            wtx.notes.iter_mut().for_each(|nd| {
                nd.witnesses.top_height = top_height;
            });
        });
    }

    pub fn keys(&self) -> Arc<RwLock<Keys>> {
        self.keys.clone()
    }

    pub fn txns(&self) -> Arc<RwLock<WalletTxns>> {
        self.txns.clone()
    }

    pub fn is_sapling_tree_verified(&self) -> bool {
        self.sapling_tree_verified.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_sapling_tree_verified(&self) {
        self.sapling_tree_verified
            .store(true, std::sync::atomic::Ordering::SeqCst)
    }

    // Get the latest sapling commitment tree. It will return the height and the hex-encoded sapling commitment tree at that height
    pub async fn get_wallet_sapling_tree(&self, block_pos: NodePosition) -> Result<(u64, String, String), String> {
        let blocks = self.blocks.read().await;

        let block = match block_pos {
            NodePosition::Highest => blocks.first(),
            NodePosition::Oldest => blocks.last(),
        };

        if block.is_none() {
            return Err("Couldn't get a block height!".to_string());
        }

        let block = block.unwrap();
        let mut write_buf = vec![];
        block
            .tree()
            .as_ref()
            .map(|t| t.write(&mut write_buf))
            .ok_or(format!("No Commitment tree"))?
            .map_err(|e| format!("Error writing commitment tree {}", e))?;

        Ok((block.height, block.hash().clone(), hex::encode(write_buf)))
    }

    pub async fn set_blocks(&self, new_blocks: Vec<BlockData>) {
        let mut blocks = self.blocks.write().await;
        blocks.clear();
        blocks.extend_from_slice(&new_blocks[..]);
    }

    /// Return a copy of the blocks currently in the wallet, needed to process possible reorgs
    pub async fn get_blocks(&self) -> Vec<BlockData> {
        self.blocks.read().await.iter().map(|b| b.clone()).collect()
    }

    pub fn note_address(hrp: &str, note: &SaplingNoteData) -> Option<String> {
        match note.extfvk.fvk.vk.to_payment_address(note.diversifier) {
            Some(pa) => Some(encode_payment_address(hrp, &pa)),
            None => None,
        }
    }

    pub async fn get_birthday(&self) -> u64 {
        let birthday = self.birthday.load(std::sync::atomic::Ordering::SeqCst);
        if birthday == 0 {
            self.get_first_tx_block().await
        } else {
            cmp::min(self.get_first_tx_block().await, birthday)
        }
    }

    pub async fn set_latest_zec_price(&self, price: f64) {
        if price <= 0 as f64 {
            warn!("Tried to set a bad current zec price {}", price);
            return;
        }

        self.price.write().await.zec_price = Some((now(), price));
        info!("Set current ZEC Price to USD {}", price);
    }

    // Get the current sending status.
    pub async fn get_send_progress(&self) -> SendProgress {
        self.send_progress.read().await.clone()
    }

    // Set the previous send's status as an error
    async fn set_send_error(&self, e: String) {
        let mut p = self.send_progress.write().await;

        p.is_send_in_progress = false;
        p.last_error = Some(e);
    }

    // Set the previous send's status as success
    async fn set_send_success(&self, txid: String) {
        let mut p = self.send_progress.write().await;

        p.is_send_in_progress = false;
        p.last_txid = Some(txid);
    }

    // Reset the send progress status to blank
    async fn reset_send_progress(&self) {
        let mut g = self.send_progress.write().await;
        let next_id = g.id + 1;

        // Discard the old value, since we are replacing it
        let _ = std::mem::replace(&mut *g, SendProgress::new(next_id));
    }

    pub async fn is_unlocked_for_spending(&self) -> bool {
        self.keys.read().await.is_unlocked_for_spending()
    }

    pub async fn is_encrypted(&self) -> bool {
        self.keys.read().await.is_encrypted()
    }

    // Get the first block that this wallet has a tx in. This is often used as the wallet's "birthday"
    // If there are no Txns, then the actual birthday (which is recorder at wallet creation) is returned
    // If no birthday was recorded, return the sapling activation height
    pub async fn get_first_tx_block(&self) -> u64 {
        // Find the first transaction
        let earliest_block = self
            .txns
            .read()
            .await
            .current
            .values()
            .map(|wtx| u64::from(wtx.block))
            .min();

        let birthday = self.birthday.load(std::sync::atomic::Ordering::SeqCst);
        earliest_block // Returns optional, so if there's no txns, it'll get the activation height
            .unwrap_or(cmp::max(birthday, self.config.sapling_activation_height))
    }

    fn adjust_wallet_birthday(&self, new_birthday: u64) {
        let mut wallet_birthday = self.birthday.load(std::sync::atomic::Ordering::SeqCst);
        if new_birthday < wallet_birthday {
            wallet_birthday = cmp::max(new_birthday, self.config.sapling_activation_height);
            self.birthday
                .store(wallet_birthday, std::sync::atomic::Ordering::SeqCst);
        }
    }

    // Add a new imported spending key to the wallet
    /// NOTE: This will not rescan the wallet
    pub async fn add_imported_sk(&self, sk: String, birthday: u64) -> String {
        if self.keys.read().await.encrypted {
            return "Error: Can't import spending key while wallet is encrypted".to_string();
        }

        // First, try to interpret the key
        let extsk = match decode_extended_spending_key(self.config.hrp_sapling_private_key(), &sk) {
            Ok(Some(k)) => k,
            Ok(None) => return format!("Error: Couldn't decode spending key"),
            Err(e) => return format!("Error importing spending key: {}", e),
        };

        // Make sure the key doesn't already exist
        if self
            .keys
            .read()
            .await
            .zkeys
            .iter()
            .find(|&wk| wk.extsk.is_some() && wk.extsk.as_ref().unwrap() == &extsk.clone())
            .is_some()
        {
            return "Error: Key already exists".to_string();
        }

        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let zaddress = {
            let zkeys = &mut self.keys.write().await.zkeys;
            let maybe_existing_zkey = zkeys.iter_mut().find(|wk| wk.extfvk == extfvk);

            // If the viewing key exists, and is now being upgraded to the spending key, replace it in-place
            if maybe_existing_zkey.is_some() {
                let mut existing_zkey = maybe_existing_zkey.unwrap();
                existing_zkey.extsk = Some(extsk);
                existing_zkey.keytype = WalletZKeyType::ImportedSpendingKey;
                existing_zkey.zaddress.clone()
            } else {
                let newkey = WalletZKey::new_imported_sk(extsk);
                zkeys.push(newkey.clone());
                newkey.zaddress
            }
        };

        // Adjust wallet birthday
        self.adjust_wallet_birthday(birthday);

        encode_payment_address(self.config.hrp_sapling_address(), &zaddress)
    }

    // Add a new imported viewing key to the wallet
    /// NOTE: This will not rescan the wallet
    pub async fn add_imported_vk(&self, vk: String, birthday: u64) -> String {
        if !self.keys().read().await.unlocked {
            return "Error: Can't add key while wallet is locked".to_string();
        }

        // First, try to interpret the key
        let extfvk = match decode_extended_full_viewing_key(self.config.hrp_sapling_viewing_key(), &vk) {
            Ok(Some(k)) => k,
            Ok(None) => return format!("Error: Couldn't decode viewing key"),
            Err(e) => return format!("Error importing viewing key: {}", e),
        };

        // Make sure the key doesn't already exist
        if self
            .keys()
            .read()
            .await
            .zkeys
            .iter()
            .find(|wk| wk.extfvk == extfvk.clone())
            .is_some()
        {
            return "Error: Key already exists".to_string();
        }

        let newkey = WalletZKey::new_imported_viewkey(extfvk);
        self.keys().write().await.zkeys.push(newkey.clone());

        // Adjust wallet birthday
        self.adjust_wallet_birthday(birthday);

        encode_payment_address(self.config.hrp_sapling_address(), &newkey.zaddress)
    }

    /// Clears all the downloaded blocks and resets the state back to the initial block.
    /// After this, the wallet's initial state will need to be set
    /// and the wallet will need to be rescanned
    pub async fn clear_all(&self) {
        self.blocks.write().await.clear();
        self.txns.write().await.clear();
    }

    pub async fn set_initial_block(&self, height: u64, hash: &str, sapling_tree: &str) -> bool {
        let mut blocks = self.blocks.write().await;
        if !blocks.is_empty() {
            return false;
        }

        let sapling_tree = match hex::decode(sapling_tree) {
            Ok(tree) => tree,
            Err(e) => {
                eprintln!("{}", e);
                return false;
            }
        };

        // Reset the verification status
        info!("Reset the sapling tree verified to false");
        self.sapling_tree_verified
            .store(false, std::sync::atomic::Ordering::SeqCst);

        if let Ok(tree) = CommitmentTree::read(&sapling_tree[..]) {
            blocks.push(BlockData::new_with(height, hash, Some(tree)));
            true
        } else {
            false
        }
    }

    pub async fn last_scanned_height(&self) -> u64 {
        self.blocks
            .read()
            .await
            .first()
            .map(|block| block.height)
            .unwrap_or(self.config.sapling_activation_height - 1)
    }

    pub async fn last_scanned_hash(&self) -> String {
        self.blocks
            .read()
            .await
            .first()
            .map(|block| block.hash())
            .unwrap_or_default()
    }

    async fn get_target_height(&self) -> Option<u32> {
        self.blocks.read().await.first().map(|block| block.height as u32 + 1)
    }

    /// Determines the target height for a transaction, and the offset from which to
    /// select anchors, based on the current synchronised block chain.
    async fn get_target_height_and_anchor_offset(&self) -> Option<(u32, usize)> {
        match {
            let blocks = self.blocks.read().await;
            (
                blocks.last().map(|block| block.height as u32),
                blocks.first().map(|block| block.height as u32),
            )
        } {
            (Some(min_height), Some(max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = cmp::max(
                    target_height.saturating_sub(*self.config.anchor_offset.last().unwrap()),
                    min_height,
                );

                Some((target_height, (target_height - anchor_height) as usize))
            }
            _ => None,
        }
    }

    /// Get the height of the anchor block
    pub async fn get_anchor_height(&self) -> u32 {
        match self.get_target_height_and_anchor_offset().await {
            Some((height, anchor_offset)) => height - anchor_offset as u32 - 1,
            None => return 0,
        }
    }

    pub fn memo_str(memo: Option<Memo>) -> Option<String> {
        match memo {
            Some(Memo::Text(m)) => Some(m.to_string()),
            _ => None,
        }
    }

    pub async fn zbalance(&self, addr: Option<String>) -> u64 {
        self.txns
            .read()
            .await
            .current
            .values()
            .map(|tx| {
                tx.notes
                    .iter()
                    .filter(|nd| match addr.as_ref() {
                        Some(a) => {
                            *a == encode_payment_address(
                                self.config.hrp_sapling_address(),
                                &nd.extfvk.fvk.vk.to_payment_address(nd.diversifier).unwrap(),
                            )
                        }
                        None => true,
                    })
                    .map(|nd| {
                        if nd.spent.is_none() && nd.unconfirmed_spent.is_none() {
                            nd.note.value
                        } else {
                            0
                        }
                    })
                    .sum::<u64>()
            })
            .sum::<u64>()
    }

    // Get all (unspent) utxos. Unconfirmed spent utxos are included
    pub async fn get_utxos(&self) -> Vec<Utxo> {
        self.txns
            .read()
            .await
            .current
            .values()
            .flat_map(|tx| tx.utxos.iter().filter(|utxo| utxo.spent.is_none()))
            .map(|utxo| utxo.clone())
            .collect::<Vec<Utxo>>()
    }

    pub async fn tbalance(&self, addr: Option<String>) -> u64 {
        self.get_utxos()
            .await
            .iter()
            .filter(|utxo| match addr.as_ref() {
                Some(a) => utxo.address == *a,
                None => true,
            })
            .map(|utxo| utxo.value)
            .sum::<u64>()
    }

    pub async fn unverified_zbalance(&self, addr: Option<String>) -> u64 {
        let anchor_height = self.get_anchor_height().await;

        let keys = self.keys.read().await;

        self.txns
            .read()
            .await
            .current
            .values()
            .map(|tx| {
                tx.notes
                    .iter()
                    .filter(|nd| nd.spent.is_none() && nd.unconfirmed_spent.is_none())
                    .filter(|nd| {
                        // Check to see if we have this note's spending key.
                        keys.have_spending_key(&nd.extfvk)
                    })
                    .filter(|nd| match addr.clone() {
                        Some(a) => {
                            a == encode_payment_address(
                                self.config.hrp_sapling_address(),
                                &nd.extfvk.fvk.vk.to_payment_address(nd.diversifier).unwrap(),
                            )
                        }
                        None => true,
                    })
                    .map(|nd| {
                        if tx.block <= BlockHeight::from_u32(anchor_height) {
                            // If confirmed, then unconfirmed is 0
                            0
                        } else {
                            // If confirmed but dont have anchor yet, it is unconfirmed
                            nd.note.value
                        }
                    })
                    .sum::<u64>()
            })
            .sum::<u64>()
    }

    pub async fn verified_zbalance(&self, addr: Option<String>) -> u64 {
        let anchor_height = self.get_anchor_height().await;

        self.txns
            .read()
            .await
            .current
            .values()
            .map(|tx| {
                if tx.block <= BlockHeight::from_u32(anchor_height) {
                    tx.notes
                        .iter()
                        .filter(|nd| nd.spent.is_none() && nd.unconfirmed_spent.is_none())
                        .filter(|nd| match addr.as_ref() {
                            Some(a) => {
                                *a == encode_payment_address(
                                    self.config.hrp_sapling_address(),
                                    &nd.extfvk.fvk.vk.to_payment_address(nd.diversifier).unwrap(),
                                )
                            }
                            None => true,
                        })
                        .map(|nd| nd.note.value)
                        .sum::<u64>()
                } else {
                    0
                }
            })
            .sum::<u64>()
    }

    pub async fn spendable_zbalance(&self, addr: Option<String>) -> u64 {
        let anchor_height = self.get_anchor_height().await;

        let keys = self.keys.read().await;

        self.txns
            .read()
            .await
            .current
            .values()
            .map(|tx| {
                if tx.block <= BlockHeight::from_u32(anchor_height) {
                    tx.notes
                        .iter()
                        .filter(|nd| nd.spent.is_none() && nd.unconfirmed_spent.is_none())
                        .filter(|nd| {
                            // Check to see if we have this note's spending key and witnesses
                            keys.have_spending_key(&nd.extfvk) && nd.witnesses.len() > 0
                        })
                        .filter(|nd| match addr.as_ref() {
                            Some(a) => {
                                *a == encode_payment_address(
                                    self.config.hrp_sapling_address(),
                                    &nd.extfvk.fvk.vk.to_payment_address(nd.diversifier).unwrap(),
                                )
                            }
                            None => true,
                        })
                        .map(|nd| nd.note.value)
                        .sum::<u64>()
                } else {
                    0
                }
            })
            .sum::<u64>()
    }

    pub async fn remove_unused_taddrs(&self) {
        let taddrs = self.keys.read().await.get_all_taddrs();
        if taddrs.len() <= 1 {
            return;
        }

        let highest_account = self
            .txns
            .read()
            .await
            .current
            .values()
            .flat_map(|wtx| {
                wtx.utxos.iter().map(|u| {
                    taddrs
                        .iter()
                        .position(|taddr| *taddr == u.address)
                        .unwrap_or(taddrs.len())
                })
            })
            .max();

        if highest_account.is_none() {
            return;
        }

        if highest_account.unwrap() == 0 {
            // Remove unused addresses
            self.keys.write().await.tkeys.truncate(1);
            self.keys.write().await.taddresses.truncate(1);
        }
    }

    pub async fn remove_unused_zaddrs(&self) {
        let zaddrs = self.keys.read().await.get_all_zaddresses();
        if zaddrs.len() <= 1 {
            return;
        }

        let highest_account = self
            .txns
            .read()
            .await
            .current
            .values()
            .flat_map(|wtx| {
                wtx.notes.iter().map(|n| {
                    let (_, pa) = n.extfvk.default_address().unwrap();
                    let zaddr = encode_payment_address(self.config.hrp_sapling_address(), &pa);
                    zaddrs.iter().position(|za| *za == zaddr).unwrap_or(zaddrs.len())
                })
            })
            .max();

        if highest_account.is_none() {
            return;
        }

        if highest_account.unwrap() == 0 {
            // Remove unused addresses
            self.keys().write().await.zkeys.truncate(1);
        }
    }

    pub async fn decrypt_message(&self, enc: Vec<u8>) -> Option<Message> {
        // Collect all the ivks in the wallet
        let ivks: Vec<_> = self
            .keys
            .read()
            .await
            .get_all_extfvks()
            .iter()
            .map(|extfvk| extfvk.fvk.vk.ivk())
            .collect();

        // Attempt decryption with all available ivks, one at a time. This is pretty fast, so need need for fancy multithreading
        for ivk in ivks {
            if let Ok(msg) = Message::decrypt(&enc, &ivk) {
                // If decryption succeeded for this IVK, return the decrypted memo and the matched address
                return Some(msg);
            }
        }

        // If nothing matched
        None
    }

    // Add the spent_at_height for each sapling note that has been spent. This field was added in wallet version 8,
    // so for older wallets, it will need to be added
    pub async fn fix_spent_at_height(&self) {
        // First, build an index of all the txids and the heights at which they were spent.
        let spent_txid_map: HashMap<_, _> = self
            .txns
            .read()
            .await
            .current
            .iter()
            .map(|(txid, wtx)| (txid.clone(), wtx.block))
            .collect();

        // Go over all the sapling notes that might need updating
        self.txns.write().await.current.values_mut().for_each(|wtx| {
            wtx.notes
                .iter_mut()
                .filter(|nd| nd.spent.is_some() && nd.spent.unwrap().1 == 0)
                .for_each(|nd| {
                    let txid = nd.spent.unwrap().0;
                    if let Some(height) = spent_txid_map.get(&txid).map(|b| *b) {
                        nd.spent = Some((txid, height.into()));
                    }
                })
        });

        // Go over all the Utxos that might need updating
        self.txns.write().await.current.values_mut().for_each(|wtx| {
            wtx.utxos
                .iter_mut()
                .filter(|utxo| utxo.spent.is_some() && utxo.spent_at_height.is_none())
                .for_each(|utxo| {
                    utxo.spent_at_height = spent_txid_map.get(&utxo.spent.unwrap()).map(|b| u32::from(*b) as i32);
                })
        });
    }

    async fn select_notes_and_utxos(
        &self,
        target_amount: Amount,
        transparent_only: bool,
        shield_transparenent: bool,
    ) -> (Vec<SpendableNote>, Vec<Utxo>, Amount) {
        // First, if we are allowed to pick transparent value, pick them all
        let utxos = if transparent_only || shield_transparenent {
            self.get_utxos()
                .await
                .iter()
                .filter(|utxo| utxo.unconfirmed_spent.is_none() && utxo.spent.is_none())
                .map(|utxo| utxo.clone())
                .collect::<Vec<_>>()
        } else {
            vec![]
        };

        // Check how much we've selected
        let transparent_value_selected = utxos.iter().fold(Amount::zero(), |prev, utxo| {
            prev + Amount::from_u64(utxo.value).unwrap()
        });

        // If we are allowed only transparent funds or we've selected enough then return
        if transparent_only || transparent_value_selected >= target_amount {
            return (vec![], utxos, transparent_value_selected);
        }

        // Start collecting sapling funds at every allowed offset
        for anchor_offset in &self.config.anchor_offset {
            let keys = self.keys.read().await;
            let mut candidate_notes = self
                .txns
                .read()
                .await
                .current
                .iter()
                .flat_map(|(txid, tx)| tx.notes.iter().map(move |note| (*txid, note)))
                .filter(|(_, note)| note.note.value > 0)
                .filter_map(|(txid, note)| {
                    // Filter out notes that are already spent
                    if note.spent.is_some() || note.unconfirmed_spent.is_some() {
                        None
                    } else {
                        // Get the spending key for the selected fvk, if we have it
                        let extsk = keys.get_extsk_for_extfvk(&note.extfvk);
                        SpendableNote::from(txid, note, *anchor_offset as usize, &extsk)
                    }
                })
                .collect::<Vec<_>>();
            candidate_notes.sort_by(|a, b| b.note.value.cmp(&a.note.value));

            // Select the minimum number of notes required to satisfy the target value
            let notes = candidate_notes
                .into_iter()
                .scan(Amount::zero(), |running_total, spendable| {
                    if *running_total >= target_amount - transparent_value_selected {
                        None
                    } else {
                        *running_total += Amount::from_u64(spendable.note.value).unwrap();
                        Some(spendable)
                    }
                })
                .collect::<Vec<_>>();
            let sapling_value_selected = notes.iter().fold(Amount::zero(), |prev, sn| {
                prev + Amount::from_u64(sn.note.value).unwrap()
            });

            if sapling_value_selected + transparent_value_selected >= target_amount {
                return (notes, utxos, sapling_value_selected + transparent_value_selected);
            }
        }

        // If we can't select enough, then we need to return empty handed
        (vec![], vec![], Amount::zero())
    }

    pub async fn send_to_address<F, Fut, P: TxProver>(
        &self,
        consensus_branch_id: u32,
        prover: P,
        transparent_only: bool,
        tos: Vec<(&str, u64, Option<String>)>,
        broadcast_fn: F,
    ) -> Result<(String, Vec<u8>), String>
    where
        F: Fn(Box<[u8]>) -> Fut,
        Fut: Future<Output = Result<String, String>>,
    {
        // Reset the progress to start. Any errors will get recorded here
        self.reset_send_progress().await;

        // Call the internal function
        match self
            .send_to_address_internal(consensus_branch_id, prover, transparent_only, tos, broadcast_fn)
            .await
        {
            Ok((txid, rawtx)) => {
                self.set_send_success(txid.clone()).await;
                Ok((txid, rawtx))
            }
            Err(e) => {
                self.set_send_error(format!("{}", e)).await;
                Err(e)
            }
        }
    }

    async fn send_to_address_internal<F, Fut, P: TxProver>(
        &self,
        consensus_branch_id: u32,
        prover: P,
        transparent_only: bool,
        tos: Vec<(&str, u64, Option<String>)>,
        broadcast_fn: F,
    ) -> Result<(String, Vec<u8>), String>
    where
        F: Fn(Box<[u8]>) -> Fut,
        Fut: Future<Output = Result<String, String>>,
    {
        if !self.keys.read().await.unlocked {
            return Err("Cannot spend while wallet is locked".to_string());
        }

        let start_time = now();
        if tos.len() == 0 {
            return Err("Need at least one destination address".to_string());
        }

        let total_value = tos.iter().map(|to| to.1).sum::<u64>();
        println!(
            "0: Creating transaction sending {} ztoshis to {} addresses",
            total_value,
            tos.len()
        );

        // Convert address (str) to RecepientAddress and value to Amount
        let recepients = tos
            .iter()
            .map(|to| {
                let ra = match address::RecipientAddress::decode(&MAIN_NETWORK, to.0) {
                    Some(to) => to,
                    None => {
                        let e = format!("Invalid recipient address: '{}'", to.0);
                        error!("{}", e);
                        return Err(e);
                    }
                };

                let value = Amount::from_u64(to.1).unwrap();

                Ok((ra, value, to.2.clone()))
            })
            .collect::<Result<Vec<(address::RecipientAddress, Amount, Option<String>)>, String>>()?;

        // Select notes to cover the target value
        println!("{}: Selecting notes", now() - start_time);

        let target_amount = Amount::from_u64(total_value).unwrap() + DEFAULT_FEE;
        let target_height = match self.get_target_height().await {
            Some(h) => BlockHeight::from_u32(h),
            None => return Err("No blocks in wallet to target, please sync first".to_string()),
        };

        let mut builder = Builder::new(MAIN_NETWORK.clone(), target_height);

        // Create a map from address -> sk for all taddrs, so we can spend from the
        // right address
        let address_to_sk = self.keys.read().await.get_taddr_to_sk_map();

        let (notes, utxos, selected_value) = self.select_notes_and_utxos(target_amount, transparent_only, true).await;
        if selected_value < target_amount {
            let e = format!(
                "Insufficient verified funds. Have {} zats, need {} zats. NOTE: funds need at least {} confirmations before they can be spent.",
                u64::from(selected_value), u64::from(target_amount), self.config.anchor_offset.last().unwrap() + 1
            );
            error!("{}", e);
            return Err(e);
        }

        // Create the transaction
        println!(
            "{}: Adding {} notes and {} utxos",
            now() - start_time,
            notes.len(),
            utxos.len()
        );

        // Add all tinputs
        utxos
            .iter()
            .map(|utxo| {
                let outpoint: OutPoint = utxo.to_outpoint();

                let coin = TxOut {
                    value: Amount::from_u64(utxo.value).unwrap(),
                    script_pubkey: Script { 0: utxo.script.clone() },
                };

                match address_to_sk.get(&utxo.address) {
                    Some(sk) => builder.add_transparent_input(*sk, outpoint.clone(), coin.clone()),
                    None => {
                        // Something is very wrong
                        let e = format!("Couldn't find the secreykey for taddr {}", utxo.address);
                        error!("{}", e);

                        Err(zcash_primitives::transaction::builder::Error::InvalidAddress)
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{:?}", e))?;

        for selected in notes.iter() {
            if let Err(e) = builder.add_sapling_spend(
                selected.extsk.clone(),
                selected.diversifier,
                selected.note.clone(),
                selected.witness.path().unwrap(),
            ) {
                let e = format!("Error adding note: {:?}", e);
                error!("{}", e);
                return Err(e);
            }
        }

        // If no Sapling notes were added, add the change address manually. That is,
        // send the change to our sapling address manually. Note that if a sapling note was spent,
        // the builder will automatically send change to that address
        if notes.len() == 0 {
            builder.send_change_to(
                self.keys.read().await.zkeys[0].extfvk.fvk.ovk,
                self.keys.read().await.zkeys[0].zaddress.clone(),
            );
        }

        // We'll use the first ovk to encrypt outgoing Txns
        let ovk = self.keys.read().await.zkeys[0].extfvk.fvk.ovk;
        let mut total_z_recepients = 0u32;
        for (to, value, memo) in recepients {
            // Compute memo if it exists
            let encoded_memo = match memo {
                None => None,
                Some(s) => {
                    // If the string starts with an "0x", and contains only hex chars ([a-f0-9]+) then
                    // interpret it as a hex
                    match utils::interpret_memo_string(s) {
                        Ok(m) => Some(m),
                        Err(e) => {
                            error!("{}", e);
                            return Err(e);
                        }
                    }
                }
            };

            println!("{}: Adding output", now() - start_time);

            if let Err(e) = match to {
                address::RecipientAddress::Shielded(to) => {
                    total_z_recepients += 1;
                    builder.add_sapling_output(Some(ovk), to.clone(), value, encoded_memo)
                }
                address::RecipientAddress::Transparent(to) => builder.add_transparent_output(&to, value),
            } {
                let e = format!("Error adding output: {:?}", e);
                error!("{}", e);
                return Err(e);
            }
        }

        // Set up a channel to recieve updates on the progress of building the transaction.
        let (tx, rx) = channel::<u32>();
        let progress = self.send_progress.clone();

        // Use a separate thread to handle sending from std::mpsc to tokio::sync::mpsc
        let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            while let Ok(r) = rx.recv() {
                tx2.send(r).unwrap();
            }
        });

        let progress_handle = tokio::spawn(async move {
            while let Some(r) = rx2.recv().await {
                println!("Progress: {}", r);
                progress.write().await.progress = r;
            }

            progress.write().await.is_send_in_progress = false;
        });

        {
            let mut p = self.send_progress.write().await;
            p.is_send_in_progress = true;
            p.progress = 0;
            p.total = notes.len() as u32 + total_z_recepients;
        }

        println!("{}: Building transaction", now() - start_time);
        let (tx, _) = match builder.build_with_progress_notifier(
            BranchId::try_from(consensus_branch_id).unwrap(),
            &prover,
            Some(tx),
        ) {
            Ok(res) => res,
            Err(e) => {
                let e = format!("Error creating transaction: {:?}", e);
                error!("{}", e);
                self.send_progress.write().await.is_send_in_progress = false;
                return Err(e);
            }
        };

        // Wait for all the progress to be updated
        progress_handle.await.unwrap();

        println!("{}: Transaction created", now() - start_time);
        println!("Transaction ID: {}", tx.txid());

        {
            self.send_progress.write().await.is_send_in_progress = false;
        }

        // Create the TX bytes
        let mut raw_tx = vec![];
        tx.write(&mut raw_tx).unwrap();

        let txid = broadcast_fn(raw_tx.clone().into_boxed_slice()).await?;

        // Mark notes as spent.
        {
            // Mark sapling notes as unconfirmed spent
            let mut txs = self.txns.write().await;
            for selected in notes {
                let mut spent_note = txs
                    .current
                    .get_mut(&selected.txid)
                    .unwrap()
                    .notes
                    .iter_mut()
                    .find(|nd| nd.nullifier == selected.nullifier)
                    .unwrap();
                spent_note.unconfirmed_spent = Some((tx.txid(), u32::from(target_height)));
            }

            // Mark this utxo as unconfirmed spent
            for utxo in utxos {
                let mut spent_utxo = txs
                    .current
                    .get_mut(&utxo.txid)
                    .unwrap()
                    .utxos
                    .iter_mut()
                    .find(|u| utxo.txid == u.txid && utxo.output_index == u.output_index)
                    .unwrap();
                spent_utxo.unconfirmed_spent = Some((tx.txid(), u32::from(target_height)));
            }
        }

        // Add this Tx to the mempool structure
        {
            let price = self.price.read().await.clone();

            FetchFullTxns::scan_full_tx(
                self.config.clone(),
                tx,
                target_height.into(),
                true,
                now() as u32,
                self.keys.clone(),
                self.txns.clone(),
                &price,
            )
            .await;
        }

        Ok((txid, raw_tx))
    }

    pub async fn encrypt(&self, passwd: String) -> io::Result<()> {
        self.keys.write().await.encrypt(passwd)
    }

    pub async fn lock(&self) -> io::Result<()> {
        self.keys.write().await.lock()
    }

    pub async fn unlock(&self, passwd: String) -> io::Result<()> {
        self.keys.write().await.unlock(passwd)
    }

    pub async fn remove_encryption(&self, passwd: String) -> io::Result<()> {
        self.keys.write().await.remove_encryption(passwd)
    }
}

#[cfg(test)]
mod test {
    use secp256k1::{PublicKey, Secp256k1};
    use zcash_primitives::transaction::components::Amount;

    use crate::{
        blaze::test_utils::{incw_to_string, FakeCompactBlockList, FakeTransaction},
        lightclient::{
            test_server::{create_test_server, mine_pending_blocks, mine_random_blocks},
            LightClient,
        },
    };

    #[tokio::test]
    async fn z_t_note_selection() {
        let (data, config, ready_rx, stop_tx, h1) = create_test_server().await;
        ready_rx.await.unwrap();

        let mut lc = LightClient::test_new(&config, None, 0).await.unwrap();

        let mut fcbl = FakeCompactBlockList::new(0);

        // 1. Mine 10 blocks
        mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
        assert_eq!(lc.wallet.last_scanned_height().await, 10);

        // 2. Send an incoming tx to fill the wallet
        let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
        let value = 100_000;
        let (tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
        mine_pending_blocks(&mut fcbl, &data, &lc).await;

        assert_eq!(lc.wallet.last_scanned_height().await, 11);

        // 3. With one confirmation, we should be able to select the note
        let amt = Amount::from_u64(10_000).unwrap();
        // Reset the anchor offsets
        lc.wallet.config.anchor_offset = [9, 4, 2, 1, 0];
        let (notes, utxos, selected) = lc.wallet.select_notes_and_utxos(amt, false, false).await;
        assert!(selected >= amt);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note.value, value);
        assert_eq!(utxos.len(), 0);
        assert_eq!(
            incw_to_string(&notes[0].witness),
            incw_to_string(
                lc.wallet.txns.read().await.current.get(&tx.txid()).unwrap().notes[0]
                    .witnesses
                    .last()
                    .unwrap()
            )
        );

        // With min anchor_offset at 1, we can't select any notes
        lc.wallet.config.anchor_offset = [9, 4, 2, 1, 1];
        let (notes, utxos, _selected) = lc.wallet.select_notes_and_utxos(amt, false, false).await;
        assert_eq!(notes.len(), 0);
        assert_eq!(utxos.len(), 0);

        // Mine 1 block, then it should be selectable
        mine_random_blocks(&mut fcbl, &data, &lc, 1).await;

        let (notes, utxos, selected) = lc.wallet.select_notes_and_utxos(amt, false, false).await;
        assert!(selected >= amt);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note.value, value);
        assert_eq!(utxos.len(), 0);
        assert_eq!(
            incw_to_string(&notes[0].witness),
            incw_to_string(
                lc.wallet.txns.read().await.current.get(&tx.txid()).unwrap().notes[0]
                    .witnesses
                    .get_from_last(1)
                    .unwrap()
            )
        );

        // Mine 15 blocks, then selecting the note should result in witness only 10 blocks deep
        mine_random_blocks(&mut fcbl, &data, &lc, 15).await;
        lc.wallet.config.anchor_offset = [9, 4, 2, 1, 1];
        let (notes, utxos, selected) = lc.wallet.select_notes_and_utxos(amt, false, true).await;
        assert!(selected >= amt);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note.value, value);
        assert_eq!(utxos.len(), 0);
        assert_eq!(
            incw_to_string(&notes[0].witness),
            incw_to_string(
                lc.wallet.txns.read().await.current.get(&tx.txid()).unwrap().notes[0]
                    .witnesses
                    .get_from_last(9)
                    .unwrap()
            )
        );

        // Trying to select a large amount will fail
        let amt = Amount::from_u64(1_000_000).unwrap();
        let (notes, utxos, _selected) = lc.wallet.select_notes_and_utxos(amt, false, false).await;
        assert_eq!(notes.len(), 0);
        assert_eq!(utxos.len(), 0);

        // 4. Get an incoming tx to a t address
        let secp = Secp256k1::new();
        let sk = lc.wallet.keys().read().await.tkeys[0];
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let taddr = lc.wallet.keys().read().await.address_from_sk(&sk);
        let tvalue = 100_000;

        let mut ftx = FakeTransaction::new();
        ftx.add_t_output(&pk, taddr.clone(), tvalue);
        let (_ttx, _) = fcbl.add_ftx(ftx);
        mine_pending_blocks(&mut fcbl, &data, &lc).await;

        // Trying to select a large amount will now succeed
        let amt = Amount::from_u64(value + tvalue - 10_000).unwrap();
        let (notes, utxos, selected) = lc.wallet.select_notes_and_utxos(amt, false, true).await;
        assert_eq!(selected, Amount::from_u64(value + tvalue).unwrap());
        assert_eq!(notes.len(), 1);
        assert_eq!(utxos.len(), 1);

        // If we set transparent-only = true, only the utxo should be selected
        let amt = Amount::from_u64(tvalue - 10_000).unwrap();
        let (notes, utxos, selected) = lc.wallet.select_notes_and_utxos(amt, true, true).await;
        assert_eq!(selected, Amount::from_u64(tvalue).unwrap());
        assert_eq!(notes.len(), 0);
        assert_eq!(utxos.len(), 1);

        // Set min confs to 5, so the sapling note will not be selected
        lc.wallet.config.anchor_offset = [9, 4, 4, 4, 4];
        let amt = Amount::from_u64(tvalue - 10_000).unwrap();
        let (notes, utxos, selected) = lc.wallet.select_notes_and_utxos(amt, false, true).await;
        assert_eq!(selected, Amount::from_u64(tvalue).unwrap());
        assert_eq!(notes.len(), 0);
        assert_eq!(utxos.len(), 1);

        // Shutdown everything cleanly
        stop_tx.send(true).unwrap();
        h1.await.unwrap();
    }
}
