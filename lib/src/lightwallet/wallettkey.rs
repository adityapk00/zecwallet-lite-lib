use std::io::{self, Error, ErrorKind, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ripemd160::Digest;
use secp256k1::SecretKey;
use sha2::Sha256;
use sodiumoxide::crypto::secretbox;
use zcash_encoding::{Optional, Vector};
use zcash_primitives::consensus;

use crate::{
    lightclient::lightclient_config::LightClientConfig,
    lightwallet::extended_key::{ExtendedPrivKey, KeyIndex},
};

use super::{
    keys::{FromBase58Check, ToBase58Check},
    utils,
};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum WalletTKeyType {
    HdKey = 0,
    ImportedKey = 1,
}

#[derive(Debug, Clone)]
pub struct WalletTKey {
    pub(super) keytype: WalletTKeyType,
    locked: bool,
    pub(super) key: Option<secp256k1::SecretKey>,
    pub(crate) address: String,

    // If this is a HD key, what is the key number
    pub(super) hdkey_num: Option<u32>,

    // If locked, the encrypted private key is stored here
    enc_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl WalletTKey {
    pub fn get_taddr_from_bip39seed<P: consensus::Parameters + 'static>(config: &LightClientConfig<P>, bip39_seed: &[u8], pos: u32) -> secp256k1::SecretKey {
        assert_eq!(bip39_seed.len(), 64);

        let ext_t_key = ExtendedPrivKey::with_seed(bip39_seed).unwrap();
        ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(config.get_coin_type()).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::Normal(0))
            .unwrap()
            .derive_private_key(KeyIndex::Normal(pos))
            .unwrap()
            .private_key
    }

    pub fn address_from_prefix_sk(prefix: &[u8; 2], sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Encode into t address
        let mut hash160 = ripemd160::Ripemd160::new();
        hash160.update(Sha256::digest(&pk.serialize()[..].to_vec()));

        hash160.finalize().to_base58check(prefix, &[])
    }

    pub fn from_raw(sk: &secp256k1::SecretKey, taddr: &String, num: u32) -> Self {
        WalletTKey {
            keytype: WalletTKeyType::HdKey,
            key: Some(sk.clone()),
            address: taddr.clone(),
            hdkey_num: Some(num),
            locked: false,
            enc_key: None,
            nonce: None,
        }
    }

    pub fn from_sk_string<P: consensus::Parameters + 'static>(config: &LightClientConfig<P>, sks: String) -> io::Result<Self> {
        let (_v, mut bytes) = sks.as_str().from_base58check()?;
        let suffix = bytes.split_off(32);

        // Assert the suffix
        if suffix.len() != 1 || suffix[0] != 0x01 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Invalid Suffix: {:?}", suffix),
            ));
        }

        let key = SecretKey::from_slice(&bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let address = Self::address_from_prefix_sk(&config.base58_pubkey_address(), &key);

        Ok(WalletTKey {
            keytype: WalletTKeyType::ImportedKey,
            key: Some(key),
            address,
            hdkey_num: None,
            locked: false,
            enc_key: None,
            nonce: None,
        })
    }

    pub fn new_hdkey(base58_pubkey_addr_prefix: &[u8; 2], hdkey_num: u32, sk: secp256k1::SecretKey) -> Self {
        let _pos = hdkey_num;

        let address = Self::address_from_prefix_sk(base58_pubkey_addr_prefix, &sk);

        WalletTKey {
            keytype: WalletTKeyType::HdKey,
            key: Some(sk),
            address,
            hdkey_num: Some(hdkey_num),
            locked: false,
            enc_key: None,
            nonce: None,
        }
    }

    // Return the wallet string representation of a secret key
    pub fn sk_as_string<P: consensus::Parameters + 'static>(&self, config: &LightClientConfig<P>) -> io::Result<String> {
        if self.key.is_none() {
            return Err(io::Error::new(ErrorKind::NotFound, "Wallet locked"));
        }

        Ok(self.key.as_ref().unwrap()[..].to_base58check(&config.base58_secretkey_prefix(), &[0x01]))
    }

    #[cfg(test)]
    pub fn empty(ta: &String) -> Self {
        WalletTKey {
            keytype: WalletTKeyType::HdKey,
            key: None,
            address: ta.clone(),
            hdkey_num: None,
            locked: false,
            enc_key: None,
            nonce: None,
        }
    }

    #[cfg(test)]
    pub fn pubkey(&self) -> io::Result<secp256k1::PublicKey> {
        if self.key.is_none() {
            return Err(io::Error::new(ErrorKind::NotFound, "Wallet locked"));
        }

        Ok(secp256k1::PublicKey::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &self.key.unwrap(),
        ))
    }

    fn serialized_version() -> u8 {
        return 1;
    }

    pub fn read<R: Read>(mut inp: R) -> io::Result<Self> {
        let version = inp.read_u8()?;
        assert!(version <= Self::serialized_version());

        let keytype: WalletTKeyType = match inp.read_u32::<LittleEndian>()? {
            0 => Ok(WalletTKeyType::HdKey),
            1 => Ok(WalletTKeyType::ImportedKey),
            n => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown zkey type {}", n),
            )),
        }?;

        let locked = inp.read_u8()? > 0;

        let key = Optional::read(&mut inp, |r| {
            let mut tpk_bytes = [0u8; 32];
            r.read_exact(&mut tpk_bytes)?;
            secp256k1::SecretKey::from_slice(&tpk_bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
        })?;
        let address = utils::read_string(&mut inp)?;

        let hdkey_num = Optional::read(&mut inp, |r| r.read_u32::<LittleEndian>())?;

        let enc_key = Optional::read(&mut inp, |r| Vector::read(r, |r| r.read_u8()))?;
        let nonce = Optional::read(&mut inp, |r| Vector::read(r, |r| r.read_u8()))?;

        Ok(WalletTKey {
            keytype,
            locked,
            key,
            address,
            hdkey_num,
            enc_key,
            nonce,
        })
    }

    pub fn write<W: Write>(&self, mut out: W) -> io::Result<()> {
        out.write_u8(Self::serialized_version())?;

        out.write_u32::<LittleEndian>(self.keytype.clone() as u32)?;

        out.write_u8(self.locked as u8)?;

        Optional::write(&mut out, self.key, |w, sk| w.write_all(&sk[..]))?;
        utils::write_string(&mut out, &self.address)?;

        Optional::write(&mut out, self.hdkey_num, |o, n| o.write_u32::<LittleEndian>(n))?;

        // Write enc_key
        Optional::write(&mut out, self.enc_key.as_ref(), |o, v| {
            Vector::write(o, v, |o, n| o.write_u8(*n))
        })?;

        // Write nonce
        Optional::write(&mut out, self.nonce.as_ref(), |o, v| Vector::write(o, v, |o, n| o.write_u8(*n)))
    }

    pub fn lock(&mut self) -> io::Result<()> {
        match self.keytype {
            WalletTKeyType::HdKey => {
                // For HD keys, just empty out the keys, since they will be reconstructed from the hdkey_num
                self.key = None;
                self.locked = true;
            }
            WalletTKeyType::ImportedKey => {
                // For imported keys, encrypt the key into enckey
                // assert that we have the encrypted key.
                if self.enc_key.is_none() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "Can't lock when imported key is not encrypted",
                    ));
                }
                self.key = None;
                self.locked = true;
            }
        }

        Ok(())
    }

    pub fn unlock<P: consensus::Parameters + 'static>(&mut self, config: &LightClientConfig<P>, bip39_seed: &[u8], key: &secretbox::Key) -> io::Result<()> {
        match self.keytype {
            WalletTKeyType::HdKey => {
                let sk = Self::get_taddr_from_bip39seed(&config, &bip39_seed, self.hdkey_num.unwrap());
                let address = Self::address_from_prefix_sk(&config.base58_pubkey_address(), &sk);

                if address != self.address {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "address mismatch at {}. {:?} vs {:?}",
                            self.hdkey_num.unwrap(),
                            address,
                            self.address
                        ),
                    ));
                }

                self.key = Some(sk)
            }
            WalletTKeyType::ImportedKey => {
                // For imported keys, we need to decrypt from the encrypted key
                let nonce = secretbox::Nonce::from_slice(&self.nonce.as_ref().unwrap()).unwrap();
                let sk_bytes = match secretbox::open(&self.enc_key.as_ref().unwrap(), &nonce, &key) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "Decryption failed. Is your password correct?",
                        ));
                    }
                };

                let key = secp256k1::SecretKey::from_slice(&sk_bytes[..])
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                self.key = Some(key);
            }
        };

        self.locked = false;
        Ok(())
    }

    pub fn encrypt(&mut self, key: &secretbox::Key) -> io::Result<()> {
        match self.keytype {
            WalletTKeyType::HdKey => {
                // For HD keys, we don't need to do anything, since the hdnum has all the info to recreate this key
            }
            WalletTKeyType::ImportedKey => {
                // For imported keys, encrypt the key into enckey
                let nonce = secretbox::gen_nonce();

                let sk_bytes = &self.key.as_ref().unwrap()[..];

                self.enc_key = Some(secretbox::seal(&sk_bytes, &nonce, &key));
                self.nonce = Some(nonce.as_ref().to_vec());
            }
        }

        // Also lock after encrypt
        self.lock()
    }

    pub fn remove_encryption(&mut self) -> io::Result<()> {
        if self.locked {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Can't remove encryption while locked",
            ));
        }

        match self.keytype {
            WalletTKeyType::HdKey => {
                // For HD keys, we don't need to do anything, since the hdnum has all the info to recreate this key
                Ok(())
            }
            WalletTKeyType::ImportedKey => {
                self.enc_key = None;
                self.nonce = None;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test {

    use rand::{rngs::OsRng, Rng};
    use secp256k1::SecretKey;

    use crate::lightclient::lightclient_config::LightClientConfig;

    use super::WalletTKey;

    #[test]
    fn tkey_encode_decode() {
        let config = LightClientConfig::create_unconnected("main".to_string(), None);

        for _i in 0..10 {
            let mut b = [0u8; 32];

            // Gen random key
            OsRng.fill(&mut b);
            let sk = SecretKey::from_slice(&b).unwrap();
            let address = WalletTKey::address_from_prefix_sk(&config.base58_pubkey_address(), &sk);
            let wtk = WalletTKey::from_raw(&sk, &address, 0);

            // export private key
            let sks = wtk.sk_as_string(&config).unwrap();
            // println!("key:{}", sks);

            // Import it back
            let wtk2 = WalletTKey::from_sk_string(&config, sks).unwrap();

            // Make sure they're the same
            assert_eq!(wtk.address, wtk2.address);
            assert_eq!(wtk.key.unwrap(), wtk2.key.unwrap());
        }
    }
}
