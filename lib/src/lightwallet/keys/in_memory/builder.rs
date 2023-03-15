use rand::rngs::OsRng;
use secp256k1::PublicKey as SecpPublicKey;
use std::sync::mpsc;
use zcash_primitives::{
    consensus::{BlockHeight, Parameters},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    sapling::{Diversifier, Node, Note, PaymentAddress, SaplingIvk},
    transaction::{
        builder::{Builder as ZBuilder, Error as ZBuilderError},
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
};
use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::builder::Progress;

use crate::lightwallet::{keys::{
    in_memory::InMemoryKeys,
    txbuilder::{SaplingMetadata, TxProver},
    Builder,
}, utils::compute_taddr};

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
    keystore: &'a mut InMemoryKeys<P>,
}

impl<'a, P: Parameters> InMemoryBuilder<'a, P> {
    pub fn new(params: P, target_height: BlockHeight, keystore: &'a mut InMemoryKeys<P>) -> Self {
        Self {
            inner: ZBuilder::new(params, target_height),
            keystore,
        }
    }
}

#[async_trait::async_trait]
impl<'a, P: Parameters + Send + Sync + 'static> Builder for InMemoryBuilder<'a, P> {
    type Error = BuilderError;

    fn add_sapling_spend(
        &mut self,
        key: &SaplingIvk,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<&mut Self, Self::Error> {
        let key = key.to_repr();
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
        // Compute memo if it exists
        let encoded_memo = match memo {
            None => MemoBytes::empty(),
            Some(s) => s,
        };
        self.inner.add_sapling_output(ovk, to, value, encoded_memo)?;
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
            let addr = compute_taddr(&key, &self.keystore.config.base58_pubkey_address(), &[]);

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

    fn with_progress_notifier(&mut self, progress_notifier: Option<mpsc::Sender<Progress>>) {
        let progress_notifier = if let Some(progress_notifier) = progress_notifier {
            //wrap given channel with the one expected by the builder
            let (tx, rx) = mpsc::channel();
            tokio::task::spawn_blocking(move || {
                while let Ok(num) = rx.recv() {
                    let progress_notifier = progress_notifier.clone();
                    let _ = tokio::spawn(async move { progress_notifier.send(num) });
                }
            });

            Some(tx)
        } else {
            None
        };
        self.inner.with_progress_notifier(progress_notifier.unwrap());
    }

    async fn build(
        mut self,
        _: BranchId,
        prover: &(impl TxProver + Send + Sync),
    ) -> Result<(Transaction, SaplingMetadata), Self::Error> {
        self.inner
            .build(prover)
            .map(|(tx, meta)| (tx, meta.into()))
            .map_err(Into::into)
    }
}
