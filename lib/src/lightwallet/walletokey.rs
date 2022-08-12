use std::io::{self, ErrorKind, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zcash_address::unified::{Address as UnifiedAddress, Encoding, Receiver};
use zcash_encoding::{Optional, Vector};

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum WalletOKeyType {
    HdKey = 0,
    ImportedSpendingKey = 1,
    ImportedFullViewKey = 2,
}

// A struct that holds orchard private keys or view keys
#[derive(Clone, Debug)]
pub struct WalletOKey {
    locked: bool,

    pub(crate) keytype: WalletOKeyType,
    pub(crate) sk: Option<SpendingKey>,
    pub(crate) fvk: FullViewingKey,
    pub(crate) unified_address: UnifiedAddress,

    // If this is a HD key, what is the key number
    pub(crate) hdkey_num: Option<u32>,

    // If locked, the encrypted private key is stored here
    enc_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl WalletOKey {
    pub fn new_hdkey(hdkey_num: u32, spending_key: SpendingKey) -> Self {
        let fvk = FullViewingKey::from(&spending_key);
        let address = fvk.address_at(0u64, Scope::External);
        let orchard_container = Receiver::Orchard(address.to_raw_address_bytes());
        let unified_address = UnifiedAddress::try_from_items(vec![orchard_container]).unwrap();

        WalletOKey {
            keytype: WalletOKeyType::HdKey,
            sk: Some(spending_key),
            fvk,
            locked: false,
            unified_address,
            hdkey_num: Some(hdkey_num),
            enc_key: None,
            nonce: None,
        }
    }

    // pub fn new_locked_hdkey(hdkey_num: u32, fvk: FullViewingKey) -> Self {
    //     let address = fvk.address_at(0u64, Scope::External);
    //     let orchard_container = Receiver::Orchard(address.to_raw_address_bytes());
    //     let unified_address = UnifiedAddress::try_from_items(vec![orchard_container]).unwrap();

    //     WalletOKey {
    //         keytype: WalletOKeyType::HdKey,
    //         sk: None,
    //         fvk,
    //         locked: true,
    //         unified_address,
    //         hdkey_num: Some(hdkey_num),
    //         enc_key: None,
    //         nonce: None,
    //     }
    // }

    // pub fn new_imported_sk(sk: SpendingKey) -> Self {
    //     let fvk = FullViewingKey::from(&sk);
    //     let address = fvk.address_at(0u64, Scope::External);
    //     let orchard_container = Receiver::Orchard(address.to_raw_address_bytes());
    //     let unified_address = UnifiedAddress::try_from_items(vec![orchard_container]).unwrap();

    //     Self {
    //         keytype: WalletOKeyType::ImportedSpendingKey,
    //         sk: Some(sk),
    //         fvk,
    //         locked: false,
    //         unified_address,
    //         hdkey_num: None,
    //         enc_key: None,
    //         nonce: None,
    //     }
    // }

    // pub fn new_imported_fullviewkey(fvk: FullViewingKey) -> Self {
    //     let address = fvk.address_at(0u64, Scope::External);
    //     let orchard_container = Receiver::Orchard(address.to_raw_address_bytes());
    //     let unified_address = UnifiedAddress::try_from_items(vec![orchard_container]).unwrap();

    //     WalletOKey {
    //         keytype: WalletOKeyType::ImportedFullViewKey,
    //         sk: None,
    //         fvk,
    //         locked: false,
    //         unified_address,
    //         hdkey_num: None,
    //         enc_key: None,
    //         nonce: None,
    //     }
    // }

    pub fn have_spending_key(&self) -> bool {
        self.sk.is_some() || self.enc_key.is_some() || self.hdkey_num.is_some()
    }

    pub fn orchard_address(&self) -> orchard::Address {
        self.fvk.address_at(0u64, Scope::External)
    }

    pub fn fvk(&self) -> &'_ FullViewingKey {
        &self.fvk
    }

    fn serialized_version() -> u8 {
        return 1;
    }

    pub fn read<R: Read>(mut inp: R) -> io::Result<Self> {
        let version = inp.read_u8()?;
        assert!(version <= Self::serialized_version());

        let keytype = match inp.read_u32::<LittleEndian>()? {
            0 => Ok(WalletOKeyType::HdKey),
            1 => Ok(WalletOKeyType::ImportedSpendingKey),
            2 => Ok(WalletOKeyType::ImportedFullViewKey),
            n => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown okey type {}", n),
            )),
        }?;

        let locked = inp.read_u8()? > 0;

        // HDKey num
        let hdkey_num = Optional::read(&mut inp, |r| r.read_u32::<LittleEndian>())?;

        // FVK
        let fvk = FullViewingKey::read(&mut inp)?;

        // SK (Read as 32 bytes)
        let sk = Optional::read(&mut inp, |r| {
            let mut bytes = [0u8; 32];
            r.read_exact(&mut bytes)?;
            Ok(SpendingKey::from_bytes(bytes).unwrap())
        })?;

        // Derive unified address
        let address = fvk.address_at(0u64, Scope::External);
        let orchard_container = Receiver::Orchard(address.to_raw_address_bytes());
        let unified_address = UnifiedAddress::try_from_items(vec![orchard_container]).unwrap();

        // enc_key
        let enc_key = Optional::read(&mut inp, |r| Vector::read(r, |r| r.read_u8()))?;

        // None
        let nonce = Optional::read(&mut inp, |r| Vector::read(r, |r| r.read_u8()))?;

        Ok(WalletOKey {
            locked,
            keytype,
            sk,
            fvk,
            unified_address,
            hdkey_num,
            enc_key,
            nonce,
        })
    }

    pub fn write<W: Write>(&self, mut out: W) -> io::Result<()> {
        out.write_u8(Self::serialized_version())?;

        out.write_u32::<LittleEndian>(self.keytype.clone() as u32)?;

        out.write_u8(self.locked as u8)?;

        // HDKey num
        Optional::write(&mut out, self.hdkey_num, |o, n| o.write_u32::<LittleEndian>(n))?;

        // Note that the Unified address is not written, it is derived from the FVK/SK on reading.

        // FVK
        FullViewingKey::write(&self.fvk, &mut out)?;

        // SK (written as just bytes)
        Optional::write(&mut out, self.sk.as_ref(), |w, sk| {
            // SK is 32 bytes
            w.write_all(sk.to_bytes())
        })?;

        // Write enc_key
        Optional::write(&mut out, self.enc_key.as_ref(), |o, v| {
            Vector::write(o, &v[..], |o, n| o.write_u8(*n))
        })?;

        // Write nonce
        Optional::write(&mut out, self.nonce.as_ref(), |o, v| {
            Vector::write(o, &v[..], |o, n| o.write_u8(*n))
        })
    }
}
