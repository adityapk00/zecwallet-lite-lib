use rand::rngs::OsRng;
use secp256k1::PublicKey as SecpPublicKey;
use tokio::sync::mpsc;
use zcash_primitives::{
    consensus::{BlockHeight, BranchId, Parameters},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    primitives::{Diversifier, Note, PaymentAddress, ViewingKey},
    sapling::Node,
    transaction::{
        builder::{Builder as ZBuilder, Error as ZBuilderError, TransactionMetadata},
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
};

cfg_if::cfg_if! {
    if #[cfg(feature = "hsm-compat")] {
        mod txprover_trait {
            use zcash_primitives::prover::TxProver;
            use zcash_hsmbuilder::txprover::HsmTxProver;

            /// This trait is a marker trait used to identify tx provers
            /// that are HSM compatible as well as normal tx provers
            ///
            /// Automatically implemented by a type if the constraits are satisfied
            /// via blanket impl
            pub trait BothTxProver: TxProver + HsmTxProver {}

            impl<T: TxProver + HsmTxProver> BothTxProver for T {}
        }

        pub use txprover_trait::BothTxProver as TxProver;
    } else {
        pub use zcash_primitives::prover::TxProver;
    }
}

use super::InMemoryKeys;

/// This trait represents the functionality that a ZCash transaction builder should expose
///
/// Will be used as common interface between [`zcash_primitives::transaction::builder::Builder`]
/// and other builders
#[async_trait::async_trait]
pub trait Builder {
    type Error;

    fn add_sapling_spend(
        &mut self,
        key: &ViewingKey,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<&mut Self, Self::Error>;

    fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<&mut Self, Self::Error>;

    fn add_transparent_input(
        &mut self,
        key: SecpPublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<&mut Self, Self::Error>;

    fn add_transparent_output(&mut self, to: &TransparentAddress, value: Amount) -> Result<&mut Self, Self::Error>;

    fn send_change_to(&mut self, ovk: OutgoingViewingKey, to: PaymentAddress) -> &mut Self;

    /// This will take care of building the transaction with the inputs given so far
    ///
    /// The `progress` is an optional argument for a mpsc channel to allow the builder
    /// to send the number of items processed so far
    async fn build<TX: TxProver + Send + Sync>(
        self,
        consensus_branch_id: BranchId,
        prover: &TX,
        progress: Option<mpsc::Sender<usize>>,
    ) -> Result<(Transaction, TransactionMetadata), Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Error: No extended spending key found for the given payment address")]
    NoAssociatedSpendingKey,
    #[error("Error: No private key found for the given address")]
    NoAssociatedPrivateKey,
    #[error("Error: from ZCash Tx Builder")]
    Inner(#[from] ZBuilderError),
}

pub struct InMemoryBuilder<'a, P: Parameters> {
    inner: ZBuilder<'a, P, OsRng>,
    keystore: &'a mut InMemoryKeys,
}

impl<'a, P: Parameters> InMemoryBuilder<'a, P> {
    pub fn new(params: P, target_height: BlockHeight, keystore: &'a mut InMemoryKeys) -> Self {
        Self {
            inner: ZBuilder::new(params, target_height),
            keystore,
        }
    }
}

#[async_trait::async_trait]
impl<'a, P: Parameters + Send + Sync> Builder for InMemoryBuilder<'a, P> {
    type Error = BuilderError;

    fn add_sapling_spend(
        &mut self,
        key: &ViewingKey,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<&mut Self, Self::Error> {
        let key = key.ivk().to_repr();
        let key = self
            .keystore
            .zkeys
            .iter()
            .find(|zk| zk.extfvk.fvk.vk.ivk().to_repr() == key)
            .map(|zk| zk.extsk.clone())
            .flatten()
            .ok_or(BuilderError::NoAssociatedSpendingKey)?;

        self.inner.add_sapling_spend(key, diversifier, note, merkle_path)?;

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
        let map = self.keystore.get_taddr_to_sk_map();
        let key = {
            use super::ToBase58Check;
            use ripemd160::Digest;
            use sha2::Sha256;

            let mut hasher = ripemd160::Ripemd160::new();
            hasher.update(Sha256::digest(&key.serialize().to_vec()));
            //compute pubkey address
            let addr = hasher
                .finalize()
                .to_base58check(&self.keystore.config().base58_pubkey_address(), &[]);

            //then do the lookup in the map
            map.get(&addr).cloned().ok_or(BuilderError::NoAssociatedPrivateKey)?
        };

        self.inner.add_transparent_input(key, utxo, coin)?;

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
        let progress = if let Some(progress) = progress {
            //wrap given channel with the one expected by the builder
            let (tx, rx) = std::sync::mpsc::channel();
            tokio::task::spawn_blocking(move || {
                while let Ok(num) = rx.recv() {
                    let progress = progress.clone();
                    let _ = tokio::spawn(async move { progress.send(num as usize).await });
                }
            });

            Some(tx)
        } else {
            None
        };

        self.inner
            .build_with_progress_notifier(consensus_branch_id, prover, progress)
            .map_err(Into::into)
    }
}
