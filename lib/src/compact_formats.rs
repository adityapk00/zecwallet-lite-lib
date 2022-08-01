use ff::PrimeField;
use group::GroupEncoding;
use orchard::note_encryption::OrchardDomain;
use std::convert::TryInto;

use std::convert::TryFrom;
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput};
use zcash_primitives::{
    block::{BlockHash, BlockHeader},
    consensus::{BlockHeight, Parameters},
    sapling::note_encryption::SaplingDomain,
};

tonic::include_proto!("cash.z.wallet.sdk.rpc");

impl CompactBlock {
    /// Returns the [`BlockHash`] for this block.
    ///
    /// # Panics
    ///
    /// This function will panic if [`CompactBlock.header`] is not set and
    /// [`CompactBlock.hash`] is not exactly 32 bytes.
    ///
    /// [`CompactBlock.header`]: #structfield.header
    /// [`CompactBlock.hash`]: #structfield.hash
    pub fn hash(&self) -> BlockHash {
        if let Some(header) = self.header() {
            header.hash()
        } else {
            BlockHash::from_slice(&self.hash)
        }
    }

    /// Returns the [`BlockHash`] for this block's parent.
    ///
    /// # Panics
    ///
    /// This function will panic if [`CompactBlock.header`] is not set and
    /// [`CompactBlock.prevHash`] is not exactly 32 bytes.
    ///
    /// [`CompactBlock.header`]: #structfield.header
    /// [`CompactBlock.prevHash`]: #structfield.prevHash
    pub fn prev_hash(&self) -> BlockHash {
        if let Some(header) = self.header() {
            header.prev_block
        } else {
            BlockHash::from_slice(&self.prev_hash)
        }
    }

    /// Returns the [`BlockHeader`] for this block if present.
    ///
    /// A convenience method that parses [`CompactBlock.header`] if present.
    ///
    /// [`CompactBlock.header`]: #structfield.header
    pub fn header(&self) -> Option<BlockHeader> {
        if self.header.is_empty() {
            None
        } else {
            BlockHeader::read(&self.header[..]).ok()
        }
    }

    /// Returns the [`BlockHeight`] for this block.
    ///
    /// A convenience method that wraps [`CompactBlock.height`]
    ///
    /// [`CompactBlock.height`]: #structfield.height
    pub fn height(&self) -> BlockHeight {
        BlockHeight::from(self.height as u32)
    }
}

impl CompactSaplingOutput {
    /// Returns the note commitment for this output.
    ///
    /// A convenience method that parses [`CompactSaplingOutput.cmu`].
    ///
    /// [`CompactSaplingOutput.cmu`]: #structfield.cmu
    pub fn cmu(&self) -> Result<bls12_381::Scalar, ()> {
        let mut repr = [0; 32];
        repr.as_mut().copy_from_slice(&self.cmu[..]);
        let r = bls12_381::Scalar::from_repr(repr);
        if bool::from(r.is_some()) {
            Ok(r.unwrap())
        } else {
            Err(())
        }
    }

    /// Returns the ephemeral public key for this output.
    ///
    /// A convenience method that parses [`CompactSaplingOutput.epk`].
    ///
    /// [`CompactSaplingOutput.epk`]: #structfield.epk
    pub fn epk(&self) -> Result<jubjub::ExtendedPoint, ()> {
        let p = jubjub::ExtendedPoint::from_bytes(&self.epk[..].try_into().map_err(|_| ())?);
        if p.is_some().into() {
            Ok(p.unwrap())
        } else {
            Err(())
        }
    }
}

impl<P: Parameters> ShieldedOutput<SaplingDomain<P>, 52_usize> for CompactSaplingOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(*vec_to_array(&self.epk))
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        *vec_to_array(&self.cmu)
    }
    fn enc_ciphertext(&self) -> &[u8; 52] {
        vec_to_array(&self.ciphertext)
    }
}

pub fn vec_to_array<'a, T, const N: usize>(vec: &'a Vec<T>) -> &'a [T; N] {
    <&[T; N]>::try_from(&vec[..]).unwrap()
}

impl ShieldedOutput<OrchardDomain, 52_usize> for CompactOrchardAction {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes::from(*vec_to_array(&self.ephemeral_key))
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        *vec_to_array(&self.cmx)
    }

    fn enc_ciphertext(&self) -> &[u8; 52] {
        vec_to_array(&self.ciphertext)
    }
}
