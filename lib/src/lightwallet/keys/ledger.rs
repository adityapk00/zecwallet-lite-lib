use std::collections::HashMap;

use async_trait::async_trait;
use ledger_transport::Exchange;
use ledger_transport_hid::TransportNativeHID;
use ledger_zcash::{
    builder::{Builder as ZBuilder, BuilderError},
    LedgerAppError, ZcashApp,
};
use rand::rngs::OsRng;
use secp256k1::PublicKey as SecpPublicKey;
use tokio::sync::{mpsc, RwLock};
use zcash_primitives::{
    consensus::{BlockHeight, BranchId, Network, Parameters},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    primitives::{Diversifier, Note, PaymentAddress, SaplingIvk, ViewingKey},
    sapling::Node,
    transaction::{
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
    zip32::{ChildIndex, DiversifierIndex},
};
use zx_bip44::BIP44Path;

use crate::lightclient::lightclient_config::LightClientConfig;

use super::{Builder, Keystore, KeystoreBuilderLifetime, TransactionMetadata, TxProver};

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
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

pub struct LedgerKeystore {
    config: LightClientConfig,
    app: ZcashApp<TransportNativeHID>,
    transparent_addrs: RwLock<HashMap<[u32; 5], SecpPublicKey>>,

    //associated a path with an ivk and the default diversifier
    shielded_addrs: RwLock<HashMap<[u32; 3], (SaplingIvk, Diversifier)>>,
}

impl LedgerKeystore {
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
            .and_then(|(ivk, d)| ivk.to_payment_address(*d))
    }

    /// Retrieve the default diversifier for a given path
    ///
    /// The default diversifier is the first valid diversifier starting with
    /// index 0
    pub async fn get_default_div(&self, idx: u32) -> Result<Diversifier, LedgerError> {
        let mut index = DiversifierIndex::new();

        loop {
            let divs = self.app.get_div_list(idx, &index.0).await?;
            let divs: &[[u8; 11]] = bytemuck::cast_slice(&divs);

            //find the first div that is not all 0s
            // all 0s is when it's an invalid diversifier
            for div in divs {
                if div != &[0; 11] {
                    return Ok(Diversifier(*div));
                }
            }

            //increment the index by 20, as the app calculates
            // 20 diversifiers
            for _ in 0..20 {
                index.increment().map_err(|_| LedgerError::DiversifierIndexOverflow)?;
            }
        }
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

                let addr = ivk
                    .to_payment_address(div)
                    .expect("guaranteed valid diversifier should get a payment address");

                self.shielded_addrs.write().await.insert(path, (ivk, div));
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
    pub fn lookup_shielded_from_ivk(&mut self, vk: &ViewingKey) -> Result<[u32; 3], LedgerError> {
        let ivk = vk.ivk().to_repr();

        self.keystore
            .shielded_addrs
            .get_mut()
            .iter()
            .find(|(_, (k, _))| k.to_repr() == ivk)
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
        key: &ViewingKey,
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
        todo!()
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
                0,
                &mut OsRng,
                self.target_height.into(),
                consensus_branch_id,
            )
            .await?;

        Ok(tx)
    }
}
