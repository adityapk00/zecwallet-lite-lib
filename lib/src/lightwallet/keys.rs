use std::io::{self, ErrorKind};

use base58::{FromBase58, ToBase58};
use ripemd160::Digest;
use sha2::Sha256;
use zcash_primitives::{
    consensus::BlockHeight,
    primitives::PaymentAddress,
    zip32::{ChildIndex, ExtendedSpendingKey},
};

mod txbuilder;
pub use txbuilder::{Builder, InMemoryBuilder, TransactionMetadata, TxProver};

/// Sha256(Sha256(value))
pub fn double_sha256(payload: &[u8]) -> Vec<u8> {
    let h1 = Sha256::digest(&payload);
    let h2 = Sha256::digest(&h1);
    h2.to_vec()
}

/// A trait for converting a [u8] to base58 encoded string.
pub trait ToBase58Check {
    /// Converts a value of `self` to a base58 value, returning the owned string.
    /// The version is a coin-specific prefix that is added.
    /// The suffix is any bytes that we want to add at the end (like the "iscompressed" flag for
    /// Secret key encoding)
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String;
}

impl ToBase58Check for [u8] {
    fn to_base58check(&self, version: &[u8], suffix: &[u8]) -> String {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(version);
        payload.extend_from_slice(self);
        payload.extend_from_slice(suffix);

        let checksum = double_sha256(&payload);
        payload.append(&mut checksum[..4].to_vec());
        payload.to_base58()
    }
}

/// A trait for converting base58check encoded values.
pub trait FromBase58Check {
    /// Convert a value of `self`, interpreted as base58check encoded data, into the tuple with version and payload as bytes vector.
    fn from_base58check(&self) -> io::Result<(u8, Vec<u8>)>;
}

impl FromBase58Check for str {
    fn from_base58check(&self) -> io::Result<(u8, Vec<u8>)> {
        let mut payload: Vec<u8> = match self.from_base58() {
            Ok(payload) => payload,
            Err(error) => return Err(io::Error::new(ErrorKind::InvalidData, format!("{:?}", error))),
        };
        if payload.len() < 5 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Invalid Checksum length"),
            ));
        }

        let checksum_index = payload.len() - 4;
        let provided_checksum = payload.split_off(checksum_index);
        let checksum = double_sha256(&payload)[..4].to_vec();
        if checksum != provided_checksum {
            return Err(io::Error::new(ErrorKind::InvalidData, format!("Invalid Checksum")));
        }
        Ok((payload[0], payload[1..].to_vec()))
    }
}

//GAT workaround, see:
// https://sabrinajewson.org/blog/the-better-alternative-to-lifetime-gats#the-better-gats
mod sealed {
    pub trait Sealed: Sized {}
    pub struct Bounds<T>(T);
    impl<T> Sealed for Bounds<T> {}
}

pub trait KeystoreBuilderLifetime<'this, ImplicitBounds: sealed::Sealed = sealed::Bounds<&'this Self>> {
    type Builder: txbuilder::Builder;
}

#[async_trait::async_trait]
pub trait Keystore
where
    Self: for<'this> KeystoreBuilderLifetime<'this>,
{
    type Error;

    /// Retrieve the unshielded public key for a given path
    async fn get_t_pubkey(&self, path: &[ChildIndex]) -> Result<secp256k1::PublicKey, Self::Error>;

    /// Retrieve the shielded payment address for a given path
    async fn get_z_payment_address(&self, path: &[ChildIndex]) -> Result<PaymentAddress, Self::Error>;

    /// Retrieve an initialized builder for the current keystore
    fn txbuilder(
        &mut self,
        target_height: BlockHeight,
    ) -> Result<<Self as KeystoreBuilderLifetime<'_>>::Builder, Self::Error>;
}

#[async_trait::async_trait]
pub trait InsecureKeystore {
    type Error;

    /// Retrieve bip39 seed phrase used in key generation
    async fn get_seed_phrase(&self) -> Result<String, Self::Error>;

    /// Retrieve the shielded spending key for a given path
    async fn get_z_private_spending_key(&self, path: &[ChildIndex]) -> Result<ExtendedSpendingKey, Self::Error>;

    /// Retrieve the unshielded secret key for a given path
    async fn get_t_secret_key(&self, path: &[ChildIndex]) -> Result<secp256k1::SecretKey, Self::Error>;
}

pub trait CachingKeysManager {}

mod in_memory;
pub use in_memory::InMemoryKeys;

#[cfg(feature = "ledger-support")]
mod ledger;
#[cfg(feature = "ledger-support")]
pub use ledger::LedgerKeystore;
