use secp256k1::PublicKey as SecpPublicKey;
use tokio::sync::mpsc;
use zcash_primitives::{
    consensus::BranchId,
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    sapling::{Diversifier, Node, Note, PaymentAddress, SaplingIvk},
    transaction::{
        components::{Amount, OutPoint, TxOut},
        Transaction,
    },
};

cfg_if::cfg_if! {
    if #[cfg(feature = "hsm-compat")] {
        mod txprover_trait {
            use zcash_primitives::sapling::prover::TxProver;
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
        pub use zcash_hsmbuilder::txbuilder::SaplingMetadata;
    } else {
        pub use zcash_primitives::sapling::prover::TxProver;
        pub use zcash_primitives::transaction::builder::SaplingMetadata;
    }
}

/// This trait represents the functionality that a ZCash transaction builder should expose
///
/// Will be used as common interface between [`zcash_primitives::transaction::builder::Builder`]
/// and other builders
#[async_trait::async_trait]
pub trait Builder {
    type Error;

    fn add_sapling_spend(
        &mut self,
        key: &SaplingIvk,
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

    /// Sets the notifier channel, where progress of building the transaction is sent.
    ///
    /// An update is sent after every Spend or Output is computed, and the `u32` sent
    /// represents the total steps completed so far. It will eventually send number of
    /// spends + outputs. If there's an error building the transaction, the channel is
    /// closed.
    fn with_progress_notifier(&mut self, progress_notifier: Option<mpsc::Sender<usize>>);

    /// This will take care of building the transaction with the inputs given so far
    ///
    /// The `progress` is an optional argument for a mpsc channel to allow the builder
    /// to send the number of items processed so far
    async fn build(
        mut self,
        consensus: BranchId,
        prover: &(impl TxProver + Send + Sync),
    ) -> Result<(Transaction, SaplingMetadata), Self::Error> ;
}
