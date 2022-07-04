use std::{
    collections::HashMap,
    io::{self, ErrorKind},
};

use async_trait::async_trait;
use derive_more::From;
use secp256k1::PublicKey as SecpPublicKey;
use thiserror::Error;
use tokio::sync::mpsc;
use zcash_primitives::{
    consensus::{BlockHeight, BranchId, Network, Parameters},
    keys::OutgoingViewingKey,
    primitives::{PaymentAddress, SaplingIvk},
    transaction::Transaction,
};

use crate::lightwallet::keys::{
    in_memory::{InMemoryBuilder, InMemoryBuilderError, InMemoryKeys},
    Builder, TransactionMetadata, TxProver,
};

#[cfg(feature = "ledger-support")]
use crate::lightwallet::keys::ledger::{LedgerBuilder, LedgerError, LedgerKeystore};

use super::Keystore;

#[derive(From)]
pub enum Keystores {
    Memory(InMemoryKeys),
    #[cfg(feature = "ledger-support")]
    Ledger(LedgerKeystore),
}

#[derive(From)]
pub enum Builders<'ks, P: Parameters> {
    Memory(InMemoryBuilder<'ks, P>),
    #[cfg(feature = "ledger-support")]
    Ledger(LedgerBuilder<'ks, P>),
}

#[derive(Debug, Error)]
pub enum BuildersError {
    #[error(transparent)]
    Memory(#[from] InMemoryBuilderError),
    #[cfg(feature = "ledger-support")]
    #[error(transparent)]
    Ledger(#[from] LedgerError),
}

impl Keystores {
    pub fn in_memory(&self) -> Result<&InMemoryKeys, io::Error> {
        match self {
            Self::Memory(this) => Ok(this),
            _ => Err(io::Error::new(
                ErrorKind::Unsupported,
                "incompatible keystore requested",
            )),
        }
    }

    pub fn in_memory_mut(&mut self) -> Result<&mut InMemoryKeys, io::Error> {
        match self {
            Self::Memory(this) => Ok(this),
            _ => Err(io::Error::new(
                ErrorKind::Unsupported,
                "incompatible keystore requested",
            )),
        }
    }
}

#[cfg(feature = "ledger-support")]
impl Keystores {
    pub fn ledger(&self) -> Result<&LedgerKeystore, io::Error> {
        match self {
            Self::Ledger(this) => Ok(this),
            _ => Err(io::Error::new(
                ErrorKind::Unsupported,
                "incompatible keystore requested",
            )),
        }
    }

    pub fn ledger_mut(&mut self) -> Result<&mut LedgerKeystore, io::Error> {
        match self {
            Self::Ledger(this) => Ok(this),
            _ => Err(io::Error::new(
                ErrorKind::Unsupported,
                "incompatible keystore requested",
            )),
        }
    }
}

impl Keystores {
    pub async fn get_all_ivks(&self) -> impl Iterator<Item = SaplingIvk> {
        //this is some hard to read rust trickery, but in short we are
        // an iterator for all the ivks in the keystore
        // using options and iterator methods to unify the type to return into 1
        // so we can use `impl` and not `dyn`
        //
        // To add future variants (if ever), add an element to the tuple,
        // set it to `None` on all branches except the new one where the
        // new variant is matched against
        //
        // Finally, add `.chain(new_tuple_item.into_iter().flatten())`
        // at the bottom expression

        let (memory, ledger) = match self {
            Keystores::Memory(this) => (
                Some(this.get_all_extfvks().into_iter().map(|key| key.fvk.vk.ivk())),
                None,
            ),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => (None, Some(this.get_all_ivks().await)),
        };

        memory.into_iter().flatten().chain(ledger.into_iter().flatten())
    }

    pub async fn get_taddr_to_key_map(&self) -> HashMap<String, SecpPublicKey> {
        match self {
            Self::Memory(this) => this.get_taddr_to_key_map(),
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this.taddr_to_key_map().await,
        }
    }

    pub fn tx_builder(&mut self, target_height: BlockHeight) -> Builders<'_, Network> {
        match self {
            Self::Memory(this) => this.txbuilder(target_height).expect("infallible").into(),
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this.txbuilder(target_height).expect("infallible").into(),
        }
    }

    /// Returns the first stored shielded OVK and payment address of the keystore
    pub async fn first_zkey(&self) -> Option<(OutgoingViewingKey, PaymentAddress)> {
        match self {
            Keystores::Memory(this) => this.zkeys.get(0).map(|zk| (zk.extfvk.fvk.ovk, zk.zaddress.clone())),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => {
                let path = this.first_shielded().await?;
                let ovk = this.get_ovk_of(&path).await.ok()?;
                let zaddr = this
                    .payment_address_from_path(&path)
                    .await
                    .expect("path must have been cached already");
                Some((ovk, zaddr))
            }
        }
    }
}

#[async_trait]
impl<'ks, P: Parameters + Send + Sync> Builder for Builders<'ks, P> {
    type Error = BuildersError;

    fn add_sapling_spend(
        &mut self,
        key: &zcash_primitives::primitives::ViewingKey,
        diversifier: zcash_primitives::primitives::Diversifier,
        note: zcash_primitives::primitives::Note,
        merkle_path: zcash_primitives::merkle_tree::MerklePath<zcash_primitives::sapling::Node>,
    ) -> Result<&mut Self, Self::Error> {
        match &mut self {
            Self::Memory(this) => this
                .add_sapling_spend(key, diversifier, note, merkle_path)
                .map(|_| ())?,
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this
                .add_sapling_spend(key, diversifier, note, merkle_path)
                .map(|_| ())?,
        };

        Ok(self)
    }

    fn add_sapling_output(
        &mut self,
        ovk: Option<zcash_primitives::keys::OutgoingViewingKey>,
        to: zcash_primitives::primitives::PaymentAddress,
        value: zcash_primitives::transaction::components::Amount,
        memo: Option<zcash_primitives::memo::MemoBytes>,
    ) -> Result<&mut Self, Self::Error> {
        match &mut self {
            Self::Memory(this) => this.add_sapling_output(ovk, to, value, memo).map(|_| ())?,
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this.add_sapling_output(ovk, to, value, memo).map(|_| ())?,
        };

        Ok(self)
    }

    fn add_transparent_input(
        &mut self,
        key: SecpPublicKey,
        utxo: zcash_primitives::transaction::components::OutPoint,
        coin: zcash_primitives::transaction::components::TxOut,
    ) -> Result<&mut Self, Self::Error> {
        match &mut self {
            Self::Memory(this) => this.add_transparent_input(key, utxo, coin).map(|_| ())?,
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this.add_transparent_input(key, utxo, coin).map(|_| ())?,
        };

        Ok(self)
    }

    fn add_transparent_output(
        &mut self,
        to: &zcash_primitives::legacy::TransparentAddress,
        value: zcash_primitives::transaction::components::Amount,
    ) -> Result<&mut Self, Self::Error> {
        match &mut self {
            Self::Memory(this) => this.add_transparent_output(to, value).map(|_| ())?,
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this.add_transparent_output(to, value).map(|_| ())?,
        };

        Ok(self)
    }

    fn send_change_to(
        &mut self,
        ovk: zcash_primitives::keys::OutgoingViewingKey,
        to: zcash_primitives::primitives::PaymentAddress,
    ) -> &mut Self {
        match &mut self {
            Self::Memory(this) => {
                this.send_change_to(ovk, to);
            }
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => {
                this.send_change_to(ovk, to);
            }
        };

        self
    }

    async fn build<TX: TxProver + Send + Sync>(
        self,
        consensus: BranchId,
        prover: &TX,
        progress: Option<mpsc::Sender<usize>>,
    ) -> Result<(Transaction, TransactionMetadata), Self::Error> {
        match self {
            Self::Memory(this) => this.build(consensus, prover, progress).await.map_err(Into::into),
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this.build(consensus, prover, progress).await.map_err(Into::into),
        }
    }
}
