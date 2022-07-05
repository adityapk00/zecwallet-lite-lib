use std::{
    collections::HashMap,
    io::{self, ErrorKind},
};

use async_trait::async_trait;
use derive_more::From;
use secp256k1::PublicKey as SecpPublicKey;
use thiserror::Error;
use tokio::sync::mpsc;
use zcash_client_backend::encoding::encode_payment_address;
use zcash_primitives::{
    consensus::{BlockHeight, BranchId, Network, Parameters},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    primitives::{PaymentAddress, SaplingIvk},
    transaction::Transaction,
};

use crate::{
    lightclient::lightclient_config::LightClientConfig,
    lightwallet::keys::{
        in_memory::{InMemoryBuilder, InMemoryBuilderError, InMemoryKeys},
        Builder, ToBase58Check, TransactionMetadata, TxProver,
    },
};

#[cfg(feature = "ledger-support")]
use crate::lightwallet::keys::ledger::{LedgerBuilder, LedgerError, LedgerKeystore};

use super::Keystore;

#[derive(From)]
/// Provide enum-based dispatch to different keystores
pub enum Keystores {
    Memory(InMemoryKeys),
    #[cfg(feature = "ledger-support")]
    Ledger(LedgerKeystore),
}

#[derive(From)]
/// Enum based dispatcher for different transaction builders
///
/// Should be instantiated with [`Keystores::tx_builder`]
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
    pub fn config(&self) -> LightClientConfig {
        match self {
            Keystores::Memory(this) => this.config(),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.config.clone(),
        }
    }

    /// Retrieve all known IVKs in the keystore
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
            Keystores::Ledger(this) => (None, Some(this.get_all_ivks().await.map(|(ivk, _)| ivk))),
        };

        memory.into_iter().flatten().chain(ledger.into_iter().flatten())
    }

    /// Retrieve all known OVKs in the keystore
    pub async fn get_all_ovks(&self) -> impl Iterator<Item = OutgoingViewingKey> {
        //see comment inside `get_all_ivks`

        let (memory, ledger) = match self {
            Keystores::Memory(this) => (Some(this.get_all_extfvks().into_iter().map(|k| k.fvk.ovk)), None),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => (None, Some(this.get_all_ovks().await)),
        };

        memory.into_iter().flatten().chain(ledger.into_iter().flatten())
    }

    /// Retrieve all known transparent addresses in the keystore
    pub async fn get_all_taddrs(&self) -> impl Iterator<Item = String> {
        //see comment inside `get_all_ivks`

        let (memory, ledger) = match self {
            Keystores::Memory(this) => (Some(this.get_all_taddrs().into_iter()), None),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => (None, Some(this.get_all_taddrs().await)),
        };

        memory.into_iter().flatten().chain(ledger.into_iter().flatten())
    }

    /// Retrieve all known ZAddrs in the keystore
    pub async fn get_all_zaddresses(&self) -> impl Iterator<Item = String> {
        //see comment inside `get_all_ivks`

        let (memory, ledger) = match self {
            Keystores::Memory(this) => (Some(this.get_all_zaddresses().into_iter()), None),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => (None, Some(this.get_all_zaddresses().await)),
        };

        memory.into_iter().flatten().chain(ledger.into_iter().flatten())
    }

    /// Retrieve all ZAddrs in the keystore which we have the spending key for
    pub async fn get_all_spendable_zaddresses(&self) -> impl Iterator<Item = String> {
        //see comment inside `get_all_ivks`

        let (memory, ledger) = match self {
            Keystores::Memory(this) => (Some(this.get_all_spendable_zaddresses().into_iter()), None),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => (None, Some(this.get_all_zaddresses().await)),
        };

        memory.into_iter().flatten().chain(ledger.into_iter().flatten())
    }

    /// Retrieve a HashMap to lookup a public key from the transparent address
    pub async fn get_taddr_to_key_map(&self) -> HashMap<String, SecpPublicKey> {
        match self {
            Self::Memory(this) => this.get_taddr_to_key_map(),
            #[cfg(feature = "ledger-support")]
            Self::Ledger(this) => this.taddr_to_key_map().await,
        }
    }

    /// Retrieve the transaction builder for the keystore
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

    /// Perform bech32 encoding of the given address
    pub fn encode_zaddr(&self, addr: PaymentAddress) -> String {
        let hrp = match self {
            Keystores::Memory(this) => this.config().hrp_sapling_address(),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.config.hrp_sapling_address(),
        };

        encode_payment_address(hrp, &addr)
    }

    /// Compute the transparent address of a pubkey hash
    pub fn address_from_pubkeyhash(&self, addr: Option<TransparentAddress>) -> Option<String> {
        let prefix = match self {
            Keystores::Memory(this) => this.config().base58_pubkey_address(),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.config.base58_pubkey_address(),
        };

        match addr {
            Some(TransparentAddress::PublicKey(hash)) | Some(TransparentAddress::Script(hash)) => {
                Some(hash.to_base58check(&prefix, &[]))
            }
            _ => None,
        }
    }

    /// Ensure we have available N generated keys via HD after the given address
    ///
    /// This is for the transparent addresses
    pub async fn ensure_hd_taddresses(&mut self, addr: &str) {
        match self {
            Keystores::Memory(this) => this.ensure_hd_taddresses(addr),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.ensure_hd_taddresses(addr).await,
        }
    }

    /// Ensure we have available N generated keys via HD after the given address
    ///
    /// This is for the shielded addresses
    pub async fn ensure_hd_zaddresses(&mut self, addr: &str) {
        match self {
            Keystores::Memory(this) => this.ensure_hd_zaddresses(addr),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.ensure_hd_zaddresses(addr).await,
        }
    }

    /// Ensure we have the spending key of the given viewing key in the keystore
    pub async fn have_spending_key(&self, ivk: &SaplingIvk) -> bool {
        match self {
            Keystores::Memory(this) => this.have_spending_key(ivk),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.get_all_ivks().await.find(|(k, _)| ivk.0 == k.0).is_some(),
        }
    }

    /// Create a new transparent address
    pub async fn add_taddr(&mut self) -> String {
        match self {
            Keystores::Memory(this) => this.add_taddr(),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.add_taddr().await,
        }
    }

    /// Create a new shielded address
    pub async fn add_zaddr(&mut self) -> String {
        match self {
            Keystores::Memory(this) => this.add_zaddr(),
            #[cfg(feature = "ledger-support")]
            Keystores::Ledger(this) => this.add_zaddr().await,
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
        match self {
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
        match self {
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
        match self {
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
        match self {
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
        match self {
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
