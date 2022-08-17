use std::io::{self, Read, Write};
use std::io::{Error, ErrorKind};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use sodiumoxide::crypto::secretbox;

use zcash_encoding::{Optional, Vector};
use zcash_primitives::consensus;
use zcash_primitives::{
    sapling::PaymentAddress,
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
};

use crate::lightclient::lightclient_config::LightClientConfig;

use super::keys::Keys;

#[derive(PartialEq, Debug, Clone)]
pub enum WalletZKeyType {
    HdKey = 0,
    ImportedSpendingKey = 1,
    ImportedViewKey = 2,
}

// A struct that holds z-address private keys or view keys
#[derive(Clone, Debug, PartialEq)]
pub struct WalletZKey {
    pub(super) keytype: WalletZKeyType,
    locked: bool,
    pub(super) extsk: Option<ExtendedSpendingKey>,
    pub(super) extfvk: ExtendedFullViewingKey,
    pub(super) zaddress: PaymentAddress,

    // If this is a HD key, what is the key number
    pub(super) hdkey_num: Option<u32>,

    // If locked, the encrypted private key is stored here
    enc_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl WalletZKey {
    pub fn new_hdkey(hdkey_num: u32, extsk: ExtendedSpendingKey) -> Self {
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let zaddress = extfvk.default_address().1;

        WalletZKey {
            keytype: WalletZKeyType::HdKey,
            locked: false,
            extsk: Some(extsk),
            extfvk,
            zaddress,
            hdkey_num: Some(hdkey_num),
            enc_key: None,
            nonce: None,
        }
    }

    pub fn new_locked_hdkey(hdkey_num: u32, extfvk: ExtendedFullViewingKey) -> Self {
        let zaddress = extfvk.default_address().1;

        WalletZKey {
            keytype: WalletZKeyType::HdKey,
            locked: true,
            extsk: None,
            extfvk,
            zaddress,
            hdkey_num: Some(hdkey_num),
            enc_key: None,
            nonce: None,
        }
    }

    pub fn new_imported_sk(extsk: ExtendedSpendingKey) -> Self {
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let zaddress = extfvk.default_address().1;

        WalletZKey {
            keytype: WalletZKeyType::ImportedSpendingKey,
            locked: false,
            extsk: Some(extsk),
            extfvk,
            zaddress,
            hdkey_num: None,
            enc_key: None,
            nonce: None,
        }
    }

    pub fn new_imported_viewkey(extfvk: ExtendedFullViewingKey) -> Self {
        let zaddress = extfvk.default_address().1;

        WalletZKey {
            keytype: WalletZKeyType::ImportedViewKey,
            locked: false,
            extsk: None,
            extfvk,
            zaddress,
            hdkey_num: None,
            enc_key: None,
            nonce: None,
        }
    }

    pub fn have_spending_key(&self) -> bool {
        self.extsk.is_some() || self.enc_key.is_some() || self.hdkey_num.is_some()
    }

    pub fn extfvk(&self) -> &'_ ExtendedFullViewingKey {
        &self.extfvk
    }

    fn serialized_version() -> u8 {
        return 1;
    }

    pub fn read<R: Read>(mut inp: R) -> io::Result<Self> {
        let version = inp.read_u8()?;
        assert!(version <= Self::serialized_version());

        let keytype: WalletZKeyType = match inp.read_u32::<LittleEndian>()? {
            0 => Ok(WalletZKeyType::HdKey),
            1 => Ok(WalletZKeyType::ImportedSpendingKey),
            2 => Ok(WalletZKeyType::ImportedViewKey),
            n => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown zkey type {}", n),
            )),
        }?;

        let locked = inp.read_u8()? > 0;

        let extsk = Optional::read(&mut inp, |r| ExtendedSpendingKey::read(r))?;
        let extfvk = ExtendedFullViewingKey::read(&mut inp)?;
        let zaddress = extfvk.default_address().1;

        let hdkey_num = Optional::read(&mut inp, |r| r.read_u32::<LittleEndian>())?;

        let enc_key = Optional::read(&mut inp, |r| Vector::read(r, |r| r.read_u8()))?;
        let nonce = Optional::read(&mut inp, |r| Vector::read(r, |r| r.read_u8()))?;

        Ok(WalletZKey {
            keytype,
            locked,
            extsk,
            extfvk,
            zaddress,
            hdkey_num,
            enc_key,
            nonce,
        })
    }

    pub fn write<W: Write>(&self, mut out: W) -> io::Result<()> {
        out.write_u8(Self::serialized_version())?;

        out.write_u32::<LittleEndian>(self.keytype.clone() as u32)?;

        out.write_u8(self.locked as u8)?;

        Optional::write(&mut out, self.extsk.as_ref(), |w, sk| {
            ExtendedSpendingKey::write(&sk, w)
        })?;

        ExtendedFullViewingKey::write(&self.extfvk, &mut out)?;

        Optional::write(&mut out, self.hdkey_num, |o, n| o.write_u32::<LittleEndian>(n))?;

        // Write enc_key
        Optional::write(&mut out, self.enc_key.as_ref(), |o, v| {
            Vector::write(o, &v[..], |o, n| o.write_u8(*n))
        })?;

        // Write nonce
        Optional::write(&mut out, self.nonce.as_ref(), |o, v| {
            Vector::write(o, &v[..], |o, n| o.write_u8(*n))
        })
    }

    pub fn lock(&mut self) -> io::Result<()> {
        match self.keytype {
            WalletZKeyType::HdKey => {
                // For HD keys, just empty out the keys, since they will be reconstructed from the hdkey_num
                self.extsk = None;
                self.locked = true;
            }
            WalletZKeyType::ImportedSpendingKey => {
                // For imported keys, encrypt the key into enckey
                // assert that we have the encrypted key.
                if self.enc_key.is_none() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "Can't lock when imported key is not encrypted",
                    ));
                }
                self.extsk = None;
                self.locked = true;
            }
            WalletZKeyType::ImportedViewKey => {
                // For viewing keys, there is nothing to lock, so just return true
                self.locked = true;
            }
        }

        Ok(())
    }

    pub fn unlock<P: consensus::Parameters>(
        &mut self,
        config: &LightClientConfig<P>,
        bip39_seed: &[u8],
        key: &secretbox::Key,
    ) -> io::Result<()> {
        match self.keytype {
            WalletZKeyType::HdKey => {
                let (extsk, extfvk, address) =
                    Keys::get_zaddr_from_bip39seed(config, &bip39_seed, self.hdkey_num.unwrap());

                if address != self.zaddress {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "zaddress mismatch at {}. {:?} vs {:?}",
                            self.hdkey_num.unwrap(),
                            address,
                            self.zaddress
                        ),
                    ));
                }

                if extfvk != self.extfvk {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "fvk mismatch at {}. {:?} vs {:?}",
                            self.hdkey_num.unwrap(),
                            extfvk,
                            self.extfvk
                        ),
                    ));
                }

                self.extsk = Some(extsk);
            }
            WalletZKeyType::ImportedSpendingKey => {
                // For imported keys, we need to decrypt from the encrypted key
                let nonce = secretbox::Nonce::from_slice(&self.nonce.as_ref().unwrap()).unwrap();
                let extsk_bytes = match secretbox::open(&self.enc_key.as_ref().unwrap(), &nonce, &key) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "Decryption failed. Is your password correct?",
                        ));
                    }
                };

                self.extsk = Some(ExtendedSpendingKey::read(&extsk_bytes[..])?);
            }
            WalletZKeyType::ImportedViewKey => {
                // Viewing key unlocking is basically a no op
            }
        };

        self.locked = false;
        Ok(())
    }

    pub fn encrypt(&mut self, key: &secretbox::Key) -> io::Result<()> {
        match self.keytype {
            WalletZKeyType::HdKey => {
                // For HD keys, we don't need to do anything, since the hdnum has all the info to recreate this key
            }
            WalletZKeyType::ImportedSpendingKey => {
                // For imported keys, encrypt the key into enckey
                let nonce = secretbox::gen_nonce();

                let mut sk_bytes = vec![];
                self.extsk.as_ref().unwrap().write(&mut sk_bytes)?;

                self.enc_key = Some(secretbox::seal(&sk_bytes, &nonce, &key));
                self.nonce = Some(nonce.as_ref().to_vec());
            }
            WalletZKeyType::ImportedViewKey => {
                // Encrypting a viewing key is a no-op
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
            WalletZKeyType::HdKey => {
                // For HD keys, we don't need to do anything, since the hdnum has all the info to recreate this key
                Ok(())
            }
            WalletZKeyType::ImportedSpendingKey => {
                self.enc_key = None;
                self.nonce = None;
                Ok(())
            }
            WalletZKeyType::ImportedViewKey => {
                // Removing encryption is a no-op for viewing keys
                Ok(())
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use sodiumoxide::crypto::secretbox;
    use zcash_client_backend::encoding::{
        decode_extended_full_viewing_key, decode_extended_spending_key, encode_payment_address,
    };

    use super::WalletZKey;
    use crate::lightclient::lightclient_config::{LightClientConfig, UnitTestNetwork};

    fn get_config() -> LightClientConfig<UnitTestNetwork> {
        LightClientConfig {
            server: "0.0.0.0:0".parse().unwrap(),
            chain_name: "zs".to_string(),
            monitor_mempool: false,
            sapling_activation_height: 0,
            anchor_offset: 0,
            data_dir: None,
            params: UnitTestNetwork,
        }
    }

    #[test]
    fn test_serialize() {
        let config = get_config();

        // Priv Key's address is "zs1fxgluwznkzm52ux7jkf4st5znwzqay8zyz4cydnyegt2rh9uhr9458z0nk62fdsssx0cqhy6lyv"
        let privkey = "secret-extended-key-main1q0p44m9zqqqqpqyxfvy5w2vq6ahvxyrwsk2w4h2zleun4cft4llmnsjlv77lhuuknv6x9jgu5g2clf3xq0wz9axxxq8klvv462r5pa32gjuj5uhxnvps6wsrdg6xll05unwks8qpgp4psmvy5e428uxaggn4l29duk82k3sv3njktaaj453fdmfmj2fup8rls4egqxqtj2p5a3yt4070khn99vzxj5ag5qjngc4v2kq0ctl9q2rpc2phu4p3e26egu9w88mchjf83sqgh3cev";

        let esk = decode_extended_spending_key(config.hrp_sapling_private_key(), privkey)
            .unwrap()
            .unwrap();
        let wzk = WalletZKey::new_imported_sk(esk);
        assert_eq!(
            encode_payment_address(config.hrp_sapling_address(), &wzk.zaddress),
            "zs1fxgluwznkzm52ux7jkf4st5znwzqay8zyz4cydnyegt2rh9uhr9458z0nk62fdsssx0cqhy6lyv".to_string()
        );

        let mut v: Vec<u8> = vec![];
        // Serialize
        wzk.write(&mut v).unwrap();
        // Read it right back
        let wzk2 = WalletZKey::read(&v[..]).unwrap();

        {
            assert_eq!(wzk, wzk2);
            assert_eq!(wzk.extsk, wzk2.extsk);
            assert_eq!(wzk.extfvk, wzk2.extfvk);
            assert_eq!(wzk.zaddress, wzk2.zaddress);
        }
    }

    #[test]
    fn test_encrypt_decrypt_sk() {
        let config = get_config();

        // Priv Key's address is "zs1fxgluwznkzm52ux7jkf4st5znwzqay8zyz4cydnyegt2rh9uhr9458z0nk62fdsssx0cqhy6lyv"
        let privkey = "secret-extended-key-main1q0p44m9zqqqqpqyxfvy5w2vq6ahvxyrwsk2w4h2zleun4cft4llmnsjlv77lhuuknv6x9jgu5g2clf3xq0wz9axxxq8klvv462r5pa32gjuj5uhxnvps6wsrdg6xll05unwks8qpgp4psmvy5e428uxaggn4l29duk82k3sv3njktaaj453fdmfmj2fup8rls4egqxqtj2p5a3yt4070khn99vzxj5ag5qjngc4v2kq0ctl9q2rpc2phu4p3e26egu9w88mchjf83sqgh3cev";

        let esk = decode_extended_spending_key(config.hrp_sapling_private_key(), privkey)
            .unwrap()
            .unwrap();
        let mut wzk = WalletZKey::new_imported_sk(esk);
        assert_eq!(
            encode_payment_address(config.hrp_sapling_address(), &wzk.zaddress),
            "zs1fxgluwznkzm52ux7jkf4st5znwzqay8zyz4cydnyegt2rh9uhr9458z0nk62fdsssx0cqhy6lyv".to_string()
        );

        // Can't lock without encryption
        assert!(wzk.lock().is_err());

        // Encryption key
        let key = secretbox::Key::from_slice(&[0; 32]).unwrap();

        // Encrypt, but save the extsk first
        let orig_extsk = wzk.extsk.clone().unwrap();
        wzk.encrypt(&key).unwrap();
        {
            assert!(wzk.enc_key.is_some());
            assert!(wzk.nonce.is_some());
        }

        // Now lock
        assert!(wzk.lock().is_ok());
        {
            assert!(wzk.extsk.is_none());
            assert_eq!(wzk.locked, true);
            assert_eq!(wzk.zaddress, wzk.extfvk.default_address().1);
        }

        // Can't remove encryption without unlocking
        assert!(wzk.remove_encryption().is_err());

        // Unlock
        assert!(wzk.unlock(&config, &[], &key).is_ok());
        {
            assert_eq!(wzk.extsk, Some(orig_extsk));
        }

        // Remove encryption
        assert!(wzk.remove_encryption().is_ok());
        {
            assert_eq!(wzk.enc_key, None);
            assert_eq!(wzk.nonce, None);
        }
    }

    #[test]
    fn test_encrypt_decrypt_vk() {
        let config = get_config();

        // Priv Key's address is "zs1va5902apnzlhdu0pw9r9q7ca8s4vnsrp2alr6xndt69jnepn2v2qrj9vg3wfcnjyks5pg65g9dc"
        let viewkey = "zxviews1qvvx7cqdqyqqpqqte7292el2875kw2fgvnkmlmrufyszlcy8xgstwarnumqye3tr3d9rr3ydjm9zl9464majh4pa3ejkfy779dm38sfnkar67et7ykxkk0z9rfsmf9jclfj2k85xt2exkg4pu5xqyzyxzlqa6x3p9wrd7pwdq2uvyg0sal6zenqgfepsdp8shestvkzxuhm846r2h3m4jvsrpmxl8pfczxq87886k0wdasppffjnd2eh47nlmkdvrk6rgyyl0ekh3ycqtvvje";

        let extfvk = decode_extended_full_viewing_key(config.hrp_sapling_viewing_key(), viewkey)
            .unwrap()
            .unwrap();
        let mut wzk = WalletZKey::new_imported_viewkey(extfvk);

        assert_eq!(
            encode_payment_address(config.hrp_sapling_address(), &wzk.zaddress),
            "zs1va5902apnzlhdu0pw9r9q7ca8s4vnsrp2alr6xndt69jnepn2v2qrj9vg3wfcnjyks5pg65g9dc".to_string()
        );

        // Encryption key
        let key = secretbox::Key::from_slice(&[0; 32]).unwrap();

        // Encrypt
        wzk.encrypt(&key).unwrap();
        {
            assert!(wzk.enc_key.is_none());
            assert!(wzk.nonce.is_none());
        }

        // Now lock
        assert!(wzk.lock().is_ok());
        {
            assert!(wzk.extsk.is_none());
            assert_eq!(wzk.locked, true);
            assert_eq!(wzk.zaddress, wzk.extfvk.default_address().1);
        }

        // Can't remove encryption without unlocking
        assert!(wzk.remove_encryption().is_err());

        // Unlock
        assert!(wzk.unlock(&config, &[], &key).is_ok());
        {
            assert_eq!(wzk.extsk, None);
        }

        // Remove encryption
        assert!(wzk.remove_encryption().is_ok());
        {
            assert_eq!(wzk.enc_key, None);
            assert_eq!(wzk.nonce, None);
        }
    }
}
