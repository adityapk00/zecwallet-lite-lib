use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use ledger_transport::Exchange;
use ledger_transport_hid::{LedgerHIDError, TransportNativeHID};
use ledger_zcash::{
    builder::{Builder as ZBuilder, BuilderError},
    LedgerAppError, ZcashApp,
};
use rand::rngs::OsRng;
use secp256k1::PublicKey as SecpPublicKey;
use tokio::sync::{mpsc, RwLock};
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::{
    consensus::{BlockHeight, BranchId, Network, Parameters},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    primitives::{Diversifier, Note, Nullifier, PaymentAddress, SaplingIvk},
    sapling::Node,
    transaction::{
        components::{amount::DEFAULT_FEE, Amount, OutPoint, TxOut},
        Transaction,
    },
    zip32::{ChildIndex, DiversifierIndex},
};
use zx_bip44::BIP44Path;

use crate::{
    lightclient::lightclient_config::{LightClientConfig, GAP_RULE_UNUSED_ADDRESSES},
    lightwallet::utils::compute_taddr,
};

use super::{Builder, InMemoryKeys, Keystore, KeystoreBuilderLifetime, TransactionMetadata, TxProver};

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Error: unable to create keystore")]
    InitializationError(#[from] LedgerHIDError),

    #[error("Error: error from inner builder: {}", .0)]
    Builder(#[from] BuilderError),
    #[error("Error: error when communicating with ledger: {}", .0)]
    Ledger(#[from] LedgerAppError<<TransportNativeHID as Exchange>::Error>),

    #[error("Error: the provided derivation path length was invalid, expected {} elements", .0)]
    InvalidPathLength(usize),
    #[error("Error: unable to parse public key returned from ledger")]
    InvalidPublicKey,

    #[error("Error: attempted to overflow diversifier index")]
    DiversifierIndexOverflow,

    #[error("Error: requested key was not found in keystore")]
    KeyNotFound,
}

impl From<LedgerError> for std::io::Error {
    fn from(err: LedgerError) -> Self {
        use std::io::ErrorKind;

        let kind = match &err {
            LedgerError::InitializationError(_) => ErrorKind::InvalidInput,
            LedgerError::Ledger(_) => ErrorKind::BrokenPipe,
            LedgerError::Builder(_)
            | LedgerError::InvalidPathLength(_)
            | LedgerError::InvalidPublicKey
            | LedgerError::DiversifierIndexOverflow
            | LedgerError::KeyNotFound => ErrorKind::InvalidData,
        };

        std::io::Error::new(kind, err)
    }
}

//we use btreemap so we can get an ordered list when iterating by key
pub struct LedgerKeystore {
    pub config: LightClientConfig,

    app: ZcashApp<TransportNativeHID>,
    //this is a public key with a specific path
    // used to "identify" a ledger
    // this is useful to detect when a different ledger
    // is connected instead of the one used with the keystore
    // originally
    ledger_id: SecpPublicKey,

    transparent_addrs: RwLock<BTreeMap<[u32; 5], SecpPublicKey>>,

    //associated a path with an ivk and the default diversifier
    shielded_addrs: RwLock<BTreeMap<[u32; 3], (SaplingIvk, Diversifier, OutgoingViewingKey)>>,
}

impl LedgerKeystore {
    /// Retrieve the connected ledger's "ID"
    ///
    /// Uses 44'/1'/0/0/0 derivation path
    async fn get_id(app: &ZcashApp<TransportNativeHID>) -> Result<SecpPublicKey, LedgerError> {
        app.get_address_unshielded(&BIP44Path([44 + 0x8000_0000, 1 + 0x8000_0000, 0, 0, 0]), false)
            .await
            .map_err(Into::into)
            .and_then(|addr| SecpPublicKey::from_slice(&addr.public_key).map_err(|_| LedgerError::InvalidPublicKey))
    }

    /// Attempt to create a handle to a ledger zcash ap
    ///
    /// Will attempt to connect to the first available device,
    /// but won't verify that the correct app is open or that is a "known" device
    fn connect_ledger() -> Result<ZcashApp<TransportNativeHID>, LedgerError> {
        let hidapi = ledger_transport_hid::hidapi::HidApi::new().map_err(|hid| LedgerHIDError::Hid(hid))?;

        let transport = TransportNativeHID::new(&hidapi)?;
        let app = ZcashApp::new(transport);

        Ok(app)
    }

    /// Create a new [`LedgerKeystore`]
    ///
    /// Will error if there are no available devices or
    /// if the wrong app is open on the ledger device.
    pub async fn new(config: LightClientConfig) -> Result<Self, LedgerError> {
        let app = Self::connect_ledger()?;
        let ledger_id = Self::get_id(&app).await?;

        Ok(Self {
            app,
            config,
            ledger_id,
            transparent_addrs: Default::default(),
            shielded_addrs: Default::default(),
        })
    }

    fn path_slice_to_bip44(path: &[ChildIndex]) -> Result<BIP44Path, LedgerError> {
        let path = path
            .iter()
            .map(|index| match index {
                ChildIndex::NonHardened(idx) => *idx,
                ChildIndex::Hardened(idx) => *idx + (1 << 31),
            })
            .take(5)
            .collect::<Vec<_>>();

        BIP44Path::from_slice(&path).map_err(|_| LedgerError::InvalidPathLength(5))
    }

    /// Attempt to lookup stored data for given path and compute payment address thereafter
    pub async fn payment_address_from_path(&self, path: &[u32; 3]) -> Option<PaymentAddress> {
        self.shielded_addrs
            .read()
            .await
            .get(path)
            .and_then(|(ivk, d, _)| ivk.to_payment_address(*d))
    }

    /// Retrieve the defualt diversifier from a given device and path
    ///
    /// The defualt diversifier is the first valid diversifier starting
    /// from index 0
    async fn get_default_div_from(app: &ZcashApp<TransportNativeHID>, idx: u32) -> Result<Diversifier, LedgerError> {
        let mut index = DiversifierIndex::new();

        loop {
            let divs = app.get_div_list(idx, &index.0).await?;
            let divs: &[[u8; 11]] = bytemuck::cast_slice(&divs);

            //find the first div that is not all 0s
            // all 0s is when it's an invalid diversifier
            for div in divs {
                if div != &[0; 11] {
                    return Ok(Diversifier(*div));
                }

                //increment the index for each diversifier returned
                index.increment().map_err(|_| LedgerError::DiversifierIndexOverflow)?;
            }
        }
    }

    /// Retrieve the default diversifier for a given path
    ///
    /// The default diversifier is the first valid diversifier starting from
    /// index 0
    pub async fn get_default_div(&self, idx: u32) -> Result<Diversifier, LedgerError> {
        Self::get_default_div_from(&self.app, idx).await
    }

    /// Retrieve all the cached/known IVKs
    pub async fn get_all_ivks(&self) -> impl Iterator<Item = (SaplingIvk, Diversifier)> {
        let guard = self.shielded_addrs.read().await;

        guard
            .values()
            .map(|(ivk, d, _)| (SaplingIvk(ivk.0.clone()), d.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Retrieve all the cached/known OVKs
    pub async fn get_all_ovks(&self) -> impl Iterator<Item = OutgoingViewingKey> {
        let guard = self.shielded_addrs.read().await;

        guard
            .values()
            .map(|(_, _, ovk)| ovk.clone())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Retrieve all the cached/known ZAddrs
    pub async fn get_all_zaddresses(&self) -> impl Iterator<Item = String> {
        let hrp = self.config.hrp_sapling_address();

        self.get_all_ivks()
            .await
            .map(|(ivk, d)| {
                ivk.to_payment_address(d)
                    .expect("known ivk and div to get payment addres")
            })
            .map(move |addr| encode_payment_address(&hrp, &addr))
    }

    /// Retrieve all the cached/known transparent public keys
    pub async fn get_all_tkeys(&self) -> impl Iterator<Item = SecpPublicKey> {
        let guard = self.transparent_addrs.read().await;

        guard.values().cloned().collect::<Vec<_>>().into_iter()
    }

    /// Retrieve all the cached/known transparent addresses
    ///
    /// Convenient wrapper over `get_all_tkeys`
    pub async fn get_all_taddrs(&self) -> impl Iterator<Item = String> {
        let prefix = self.config.base58_pubkey_address();
        self.get_all_tkeys().await.map(move |k| compute_taddr(&k, &prefix, &[]))
    }

    /// Retrieve a HashMap of transparent addresses to public key
    pub async fn taddr_to_key_map(&self) -> HashMap<String, SecpPublicKey> {
        self.transparent_addrs
            .read()
            .await
            .values()
            .map(|key| {
                (
                    compute_taddr(key, &self.config.base58_pubkey_address(), &[]),
                    key.clone(),
                )
            })
            .collect()
    }

    /// Retrieve the first shielded key present in the keystore
    pub async fn first_shielded(&self) -> Option<[u32; 3]> {
        //retrieve the first key
        self.shielded_addrs.read().await.keys().next().cloned()
    }

    pub async fn compute_nullifier(
        &self,
        ivk: &SaplingIvk,
        position: u64,
        commitment: jubjub::AffinePoint,
    ) -> Result<Nullifier, LedgerError> {
        let path = {
            let ivk_repr = ivk.to_repr();

            let guard = self.shielded_addrs.read().await;
            guard
                .iter()
                .find(move |(_, (k, _, _))| k.to_repr() == ivk_repr)
                .map(|(p, _)| *p)
                .ok_or(LedgerError::KeyNotFound)?
        };

        let commitment = commitment.to_bytes();

        self.app
            .get_nullifier(path[2], position, &commitment)
            .await
            .map_err(Into::into)
    }
}

//in-memory keystore compatibility methods
impl LedgerKeystore {
    /// Retrieve the OVK of a given path
    pub async fn get_ovk_of(&self, path: &[u32; 3]) -> Option<OutgoingViewingKey> {
        self.shielded_addrs
            .read()
            .await
            .get(path)
            .map(|(_, _, ovk)| ovk.clone())
    }

    /// Given an address, verify that we have N addresses
    /// after that one (if present in the cache)
    pub async fn ensure_hd_taddresses(&mut self, address: &str) {
        if GAP_RULE_UNUSED_ADDRESSES == 0 {
            return;
        }

        let prefix = self.config.base58_pubkey_address();

        let last_address_used_pos = self
            .transparent_addrs
            .get_mut()
            .iter()
            .rev()
            //get the last N addresses
            .take(GAP_RULE_UNUSED_ADDRESSES)
            //get the transparent address of each
            .map(move |(path, key)| (*path, compute_taddr(&key, &prefix, &[])))
            .enumerate()
            //find the one that matches the needle
            .find(|(_, (_, s))| s == address);

        //if we find the given address in the last N
        if let Some((i, (path, _))) = last_address_used_pos {
            // then we should cache/generate N - i addresses
            for i in 0..(GAP_RULE_UNUSED_ADDRESSES - i) {
                //increase the last index by i
                // +1 for the 0th i
                let path = [
                    ChildIndex::from_index(path[0]),
                    ChildIndex::from_index(path[1]),
                    ChildIndex::from_index(path[2]),
                    ChildIndex::from_index(path[3]),
                    ChildIndex::from_index(path[4] + 1 + i as u32),
                ];

                //add the new key
                //TODO: report errors? stop at first error?
                let _ = self.get_t_pubkey(&path).await;
            }
        }
    }

    /// Given an address, verify that we have N addresses
    /// after that one (if present in the cache)
    pub async fn ensure_hd_zaddresses(&mut self, address: &str) {
        if GAP_RULE_UNUSED_ADDRESSES == 0 {
            return;
        }

        let hrp = self.config.hrp_sapling_address();

        let last_address_used_pos = self
            .shielded_addrs
            .get_mut()
            .iter()
            .rev()
            //get the last N addresses
            .take(GAP_RULE_UNUSED_ADDRESSES)
            //get the payment address of each
            .map(move |(path, (ivk, d, _))| {
                (
                    *path,
                    ivk.to_payment_address(*d)
                        .expect("known ivk and diversifier to get payment address"),
                )
            })
            //get the bech32 encoded address of each
            .map(move |(path, zaddr)| (path, encode_payment_address(hrp, &zaddr)))
            .enumerate()
            //find the one that matches the needle
            .find(|(_, (_, s))| s == address);

        //if we find the given address in the last N
        if let Some((i, (path, _))) = last_address_used_pos {
            // then we should cache/generate N - i addresses
            for i in 0..(GAP_RULE_UNUSED_ADDRESSES - i) {
                //increase the last index by i
                // +1 for the 0th i
                let path = [
                    ChildIndex::from_index(path[0]),
                    ChildIndex::from_index(path[1]),
                    ChildIndex::from_index(path[2] + 1 + i as u32),
                ];

                //add the new key
                //TODO: report errors? stop at first error?
                let _ = self.get_z_payment_address(&path).await;
            }
        }
    }

    /// Create a new transparent address with path +1 from the latest one
    pub async fn add_taddr(&mut self) -> String {
        //find the highest path we have
        let path = self
            .transparent_addrs
            .get_mut()
            .keys()
            .last()
            .cloned()
            .map(|path| {
                [
                    ChildIndex::from_index(path[0]),
                    ChildIndex::from_index(path[1]),
                    ChildIndex::from_index(path[2]),
                    ChildIndex::from_index(path[3]),
                    ChildIndex::from_index(path[4] + 1),
                ]
            })
            .unwrap_or_else(|| InMemoryKeys::t_derivation_path(self.config.get_coin_type(), 0));

        let key = self.get_t_pubkey(&path).await;

        match key {
            Ok(key) => compute_taddr(&key, &self.config.base58_pubkey_address(), &[]),
            Err(e) => format!("Error: {:?}", e),
        }
    }

    /// Create a new shielded address with path +1 from the latest one
    pub async fn add_zaddr(&mut self) -> String {
        //find the highest path we have
        let path = self
            .shielded_addrs
            .get_mut()
            .keys()
            .last()
            .cloned()
            .map(|path| {
                [
                    ChildIndex::from_index(path[0]),
                    ChildIndex::from_index(path[1]),
                    ChildIndex::from_index(path[2] + 1),
                ]
            })
            .unwrap_or_else(|| InMemoryKeys::z_derivation_path(self.config.get_coin_type(), 0));

        let addr = self.get_z_payment_address(&path).await;

        match addr {
            Ok(addr) => encode_payment_address(self.config.hrp_sapling_address(), &addr),
            Err(e) => format!("Error: {:?}", e),
        }
    }
}

//serialization and deserialization stuff
impl LedgerKeystore {
    /// Keystore version
    ///
    /// Increase for any change in the format
    const VERSION: u64 = 0;

    /// Serialize the keystore to a writer
    pub async fn write<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        use byteorder::{LittleEndian, WriteBytesExt};

        writer.write_u64::<LittleEndian>(Self::VERSION)?;

        //write the ledger "id"
        let id = self.ledger_id.serialize();
        writer.write_all(&id)?;

        //write the transparent paths
        let transparent_paths = self
            .transparent_addrs
            .read()
            .await
            .keys()
            .map(|path| {
                [
                    path[0].to_le_bytes(),
                    path[1].to_le_bytes(),
                    path[2].to_le_bytes(),
                    path[3].to_le_bytes(),
                    path[4].to_le_bytes(),
                ]
            })
            .map(|path_bytes| bytemuck::cast(path_bytes))
            .collect::<Vec<[u8; 4 * 5]>>();

        writer.write_u64::<LittleEndian>(transparent_paths.len() as u64)?;
        for path in transparent_paths {
            writer.write_all(&path)?;
        }

        //write the shielded paths
        let shielded_paths = self
            .shielded_addrs
            .read()
            .await
            .keys()
            .map(|path| [path[0].to_le_bytes(), path[1].to_le_bytes(), path[2].to_le_bytes()])
            .map(|path_bytes| bytemuck::cast(path_bytes))
            .collect::<Vec<[u8; 4 * 3]>>();

        writer.write_u64::<LittleEndian>(shielded_paths.len() as u64)?;
        for path in shielded_paths {
            writer.write_all(&path)?;
        }

        Ok(())
    }

    pub async fn read<R: std::io::Read>(mut reader: R, config: &LightClientConfig) -> std::io::Result<Self> {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::{self, ErrorKind};

        //read version and verify it's compatible with the code
        let version = reader.read_u64::<LittleEndian>()?;
        if version > Self::VERSION {
            let e = format!(
                "Don't know how to read ledger wallet version {}. Do you have the latest version?",
                version
            );
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }

        //retrieve the ledger id and verify it matches with the aocnnected device
        let ledger_id = {
            let mut buf = [0; secp256k1::constants::PUBLIC_KEY_SIZE];
            reader.read_exact(&mut buf)?;

            SecpPublicKey::from_slice(&buf).map_err(|e| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("Bad public key stored for ledger id: {:?}", e),
                )
            })?
        };

        let app = Self::connect_ledger()?;
        if ledger_id != Self::get_id(&app).await? {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Detected different ledger than used previously"),
            ));
        }

        //read the transparent paths
        // the keys will be retrieved one by one from the device
        let transparent_addrs_len = reader.read_u64::<LittleEndian>()?;
        let mut transparent_addrs = BTreeMap::new();
        for _ in 0..transparent_addrs_len {
            let path = {
                let mut buf = [0; 4 * 5];
                reader.read_exact(&mut buf)?;

                let path_bytes: [[u8; 4]; 5] = bytemuck::cast(buf);
                [
                    u32::from_le_bytes(path_bytes[0]),
                    u32::from_le_bytes(path_bytes[1]),
                    u32::from_le_bytes(path_bytes[2]),
                    u32::from_le_bytes(path_bytes[3]),
                    u32::from_le_bytes(path_bytes[4]),
                ]
            };

            let key = app
                .get_address_unshielded(&BIP44Path(path), false)
                .await
                .map_err(LedgerError::Ledger)?
                .public_key;
            let key = SecpPublicKey::from_slice(&key).map_err(|_| LedgerError::InvalidPublicKey)?;

            transparent_addrs.insert(path, key);
        }

        //read the transparent paths
        // the keys and the diversifiers
        // will be retrieved one by one from the device
        let shielded_addrs_len = reader.read_u64::<LittleEndian>()?;
        let mut shielded_addrs = BTreeMap::new();
        for _ in 0..shielded_addrs_len {
            let path = {
                let mut buf = [0; 4 * 3];
                reader.read_exact(&mut buf)?;

                let path_bytes: [[u8; 4]; 3] = bytemuck::cast(buf);
                [
                    u32::from_le_bytes(path_bytes[0]),
                    u32::from_le_bytes(path_bytes[1]),
                    u32::from_le_bytes(path_bytes[2]),
                ]
            };

            //ZIP32 uses fixed path, so the actual index
            // is only the latest element
            let idx = path[2];

            let ivk = app
                .get_ivk(idx)
                .await
                .map(|ivk| SaplingIvk(ivk))
                .map_err(LedgerError::Ledger)?;

            let div = Self::get_default_div_from(&app, idx).await?;

            let ovk = app
                .get_ovk(idx)
                .await
                .map(|ovk| OutgoingViewingKey(ovk.0))
                .map_err(LedgerError::Ledger)?;

            shielded_addrs.insert(path, (ivk, div, ovk));
        }

        Ok(Self {
            config: config.clone(),
            app,
            ledger_id,
            transparent_addrs: RwLock::new(transparent_addrs),
            shielded_addrs: RwLock::new(shielded_addrs),
        })
    }
}

#[async_trait]
impl Keystore for LedgerKeystore {
    type Error = LedgerError;

    async fn get_t_pubkey(&self, path: &[ChildIndex]) -> Result<SecpPublicKey, Self::Error> {
        let path = Self::path_slice_to_bip44(path)?;
        //avoid keeping the read guard so we can get the write guard later if necessary
        // without causing a deadlock
        let cached = self.transparent_addrs.read().await.get(&path.0).map(|k| k.clone());

        match cached {
            Some(key) => Ok(key),
            None => {
                let addr = self.app.get_address_unshielded(&path, false).await?;

                let pkey = SecpPublicKey::from_slice(&addr.public_key).map_err(|_| LedgerError::InvalidPublicKey)?;
                self.transparent_addrs.write().await.insert(path.0, pkey);
                Ok(pkey)
            }
        }
    }

    /// Retrieve the shielded payment address for a given path
    async fn get_z_payment_address(&self, path: &[ChildIndex]) -> Result<PaymentAddress, Self::Error> {
        if path.len() != 3 {
            return Err(LedgerError::InvalidPathLength(3));
        }

        let path = {
            let elements = path
                .iter()
                .map(|ci| match ci {
                    ChildIndex::NonHardened(i) => *i,
                    ChildIndex::Hardened(i) => *i + (1 << 31),
                })
                .enumerate();

            let mut array = [0; 3];
            for (i, e) in elements {
                array[i] = e;
            }

            array
        };

        match self.payment_address_from_path(&path).await {
            Some(key) => Ok(key),
            None => {
                let ivk = self.app.get_ivk(path[2]).await.map(|ivk| SaplingIvk(ivk))?;

                let div = self.get_default_div(path[2]).await?;

                let ovk = self.app.get_ovk(path[2]).await.map(|ovk| OutgoingViewingKey(ovk.0))?;

                let addr = ivk
                    .to_payment_address(div)
                    .expect("guaranteed valid diversifier should get a payment address");

                self.shielded_addrs.write().await.insert(path, (ivk, div, ovk));
                Ok(addr)
            }
        }
    }

    /// Retrieve an initialized builder for the current keystore
    fn txbuilder(
        &mut self,
        target_height: BlockHeight,
    ) -> Result<<Self as KeystoreBuilderLifetime<'_>>::Builder, Self::Error> {
        Ok(LedgerBuilder::new(self.config.get_params(), target_height, self))
    }
}

impl<'this> KeystoreBuilderLifetime<'this> for LedgerKeystore {
    type Builder = LedgerBuilder<'this, Network>;
}

pub struct LedgerBuilder<'k, P: Parameters> {
    keystore: &'k mut LedgerKeystore,
    params: P,
    target_height: BlockHeight,
    inner: ZBuilder,
}

impl<'a, P: Parameters> LedgerBuilder<'a, P> {
    pub fn new(params: P, target_height: BlockHeight, keystore: &'a mut LedgerKeystore) -> Self {
        Self {
            keystore,
            params,
            target_height,
            inner: ZBuilder::new(),
        }
    }

    /// Attempt to lookup the corresponding path in the keystore, given a viewing key
    pub fn lookup_shielded_from_ivk(&mut self, ivk: &SaplingIvk) -> Result<[u32; 3], LedgerError> {
        let ivk = ivk.to_repr();

        self.keystore
            .shielded_addrs
            .get_mut()
            .iter()
            .find(|(_, (k, _, _))| k.to_repr() == ivk)
            .map(|(p, _)| *p)
            .ok_or(LedgerError::KeyNotFound)
    }

    pub fn lookup_transparent_from_pubkey(&mut self, pkey: &SecpPublicKey) -> Result<[u32; 5], LedgerError> {
        self.keystore
            .transparent_addrs
            .get_mut()
            .iter()
            .find(|(_, k)| k == &pkey)
            .map(|(p, _)| *p)
            .ok_or(LedgerError::KeyNotFound)
    }
}

#[async_trait]
impl<'a, P: Parameters + Send + Sync> Builder for LedgerBuilder<'a, P> {
    type Error = LedgerError;

    fn add_sapling_spend(
        &mut self,
        key: &SaplingIvk,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<&mut Self, Self::Error> {
        let path = self.lookup_shielded_from_ivk(&key)?;

        self.inner.add_sapling_spend(path[2], diversifier, note, merkle_path)?;

        Ok(self)
    }

    fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<&mut Self, Self::Error> {
        self.inner.add_sapling_output(ovk, to, value, memo)?;
        Ok(self)
    }

    fn add_transparent_input(
        &mut self,
        key: SecpPublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<&mut Self, Self::Error> {
        let path = self.lookup_transparent_from_pubkey(&key)?;

        self.inner.add_transparent_input(BIP44Path(path), key, utxo, coin)?;

        Ok(self)
    }

    fn add_transparent_output(&mut self, to: &TransparentAddress, value: Amount) -> Result<&mut Self, Self::Error> {
        self.inner.add_transparent_output(to, value)?;

        Ok(self)
    }

    fn send_change_to(&mut self, ovk: OutgoingViewingKey, to: PaymentAddress) -> &mut Self {
        self.inner.send_change_to(ovk, to);

        self
    }

    async fn build<TX: TxProver + Send + Sync>(
        self,
        consensus_branch_id: BranchId,
        prover: &TX,
        progress: Option<mpsc::Sender<usize>>,
    ) -> Result<(Transaction, TransactionMetadata), Self::Error> {
        let tx = self
            .inner
            .build(
                &mut self.keystore.app,
                self.params,
                prover,
                DEFAULT_FEE.into(),
                &mut OsRng,
                self.target_height.into(),
                consensus_branch_id,
                progress,
            )
            .await?;

        Ok(tx)
    }
}
