use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};

// Create a fake tx data
pub fn new_transactiondata() -> TransactionData<Authorized> {
    let td: TransactionData<zcash_primitives::transaction::Authorized> = TransactionData::from_parts(
        TxVersion::Sapling,
        BranchId::Sapling,
        0,
        0u32.into(),
        None,
        None,
        None,
        None,
    );

    td
}

pub fn clone_transactiondata(
    t: TransactionData<Authorized>,
) -> (TransactionData<Authorized>, TransactionData<Authorized>) {
    let sapling_bundle = if t.sapling_bundle().is_some() {
        Some(t.sapling_bundle().unwrap().clone())
    } else {
        None
    };

    let transparent_bundle = if t.transparent_bundle().is_some() {
        Some(t.transparent_bundle().unwrap().clone())
    } else {
        None
    };

    let td1: TransactionData<zcash_primitives::transaction::Authorized> = TransactionData::from_parts(
        TxVersion::Sapling,
        BranchId::Sapling,
        0,
        0u32.into(),
        transparent_bundle.clone(),
        None,
        sapling_bundle.clone(),
        None,
    );

    let td2: TransactionData<zcash_primitives::transaction::Authorized> = TransactionData::from_parts(
        TxVersion::Sapling,
        BranchId::Sapling,
        0,
        0u32.into(),
        transparent_bundle,
        None,
        sapling_bundle,
        None,
    );

    (td1, td2)
}
