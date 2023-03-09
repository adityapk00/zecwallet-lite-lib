use byteorder::ReadBytesExt;
use bytes::{Buf, Bytes, IntoBuf};
use ff::Field;
use group::GroupEncoding;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::{
    convert::TryInto,
    io::{self, ErrorKind, Read},
};
use jubjub::ExtendedPoint;
use zcash_primitives::{
    consensus::{BlockHeight, MAIN_NETWORK},
    keys::OutgoingViewingKey,
    memo::Memo,
    sapling::note_encryption::{prf_ock, try_sapling_note_decryption},
    sapling::{PaymentAddress, Rseed, SaplingIvk, ValueCommitment},
};

use zcash_note_encryption::{NoteEncryption, OutgoingCipherKey, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE, EphemeralKeyBytes};
use zcash_primitives::transaction::components::{GROTH_PROOF_SIZE, OutputDescription};

pub struct Message {
    pub to: PaymentAddress,
    pub memo: Memo,
}

impl Message {
    pub fn new(to: PaymentAddress, memo: Memo) -> Self {
        Self { to, memo }
    }

    fn serialized_version() -> u8 {
        1
    }

    fn magic_word() -> String {
        return "ZcashOfflineMemo".to_string();
    }

    // Internal method that does the actual encryption
    fn encrypt_message_to<R: RngCore + CryptoRng>(
        &self,
        ovk: Option<OutgoingViewingKey>,
        mut rng: &mut R,
    ) -> Result<
        (
            Option<OutgoingCipherKey>,
            jubjub::ExtendedPoint,
            bls12_381::Scalar,
            jubjub::ExtendedPoint,
            [u8; ENC_CIPHERTEXT_SIZE],
            [u8; OUT_CIPHERTEXT_SIZE],
        ),
        String,
    > {
        // 0-value note
        let value = 0;

        // Construct the value commitment, used if an OVK was supplied to create out_ciphertext
        let value_commitment = ValueCommitment {
            value,
            randomness: jubjub::Fr::random(&mut rng),
        };
        let cv = value_commitment.commitment().into();

        // Use a rseed from pre-canopy. It doesn't really matter, but this is what is tested out.
        let rseed = Rseed::BeforeZip212(jubjub::Fr::random(&mut rng));

        // 0-value note with the rseed
        let note = self.to.create_note(value, rseed).unwrap();

        // CMU is used in the out_cuphertext. Technically this is not needed to recover the note
        // by the receiver, but it is needed to recover the note by the sender.
        let cmu = note.cmu();

        // Create the note encrytion object
        let mut ne = NoteEncryption::new(ovk, note, self.to.clone(), self.memo.clone().into());

        // EPK, which needs to be sent to the reciever.
        let epk = EphemeralKeyBytes::from(ne.epk().to_bytes());

        // enc_ciphertext is the encrypted note, out_ciphertext is the outgoing cipher text that the
        // sender can recover
        let enc_ciphertext = ne.encrypt_note_plaintext();
        let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);

        // OCK is used to recover outgoing encrypted notes
        let ock = if ovk.is_some() {
            Some(prf_ock(&ovk.unwrap(), &cv, &cmu.to_bytes(), &epk))
        } else {
            None
        };

        Ok((ock, cv, cmu, *ne.epk(), enc_ciphertext, out_ciphertext))
    }

    pub fn encrypt(&self) -> Result<Vec<u8>, String> {
        let mut rng = OsRng;

        // Encrypt To address. We're using a 'NONE' OVK here, so the out_ciphertext is not recoverable.
        let (_ock, _cv, cmu, epk, enc_ciphertext, _out_ciphertext) = self.encrypt_message_to(None, &mut rng)?;

        // We'll encode the message on the wire as a series of bytes
        // u8 -> serialized version
        // [u8; 32] -> cmu
        // [u8; 32] -> epk
        // [u8; ENC_CIPHERTEXT_SIZE] -> encrypted bytes
        let mut data = vec![];
        data.extend_from_slice(Message::magic_word().as_bytes());
        data.push(Message::serialized_version());
        data.extend_from_slice(&cmu.to_bytes());
        data.extend_from_slice(&epk.to_bytes());
        data.extend_from_slice(&enc_ciphertext);

        Ok(data)
    }

    pub fn decrypt(data: &[u8], ivk: &SaplingIvk) -> io::Result<Message> {
        if data.len() != 1 + Message::magic_word().len() + 32 + 32 + ENC_CIPHERTEXT_SIZE {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Incorrect encrypred payload size".to_string(),
            ));
        }

        let mut reader = Bytes::from(data).into_buf().reader();
        let mut magic_word_bytes = vec![0u8; Message::magic_word().len()];
        reader.read_exact(&mut magic_word_bytes)?;
        let read_magic_word = String::from_utf8(magic_word_bytes)
            .map_err(|e| return io::Error::new(ErrorKind::InvalidData, format!("{}", e)))?;
        if read_magic_word != Message::magic_word() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Bad magic words. Wanted:{}, but found {}",
                    Message::magic_word(),
                    read_magic_word
                ),
            ));
        }

        let version = reader.read_u8()?;
        if version > Message::serialized_version() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("Can't read version {}", version),
            ));
        }

        let mut cmu_bytes = [0u8; 32];
        reader.read_exact(&mut cmu_bytes)?;
        let cmu = bls12_381::Scalar::from_bytes(&cmu_bytes);
        if cmu.is_none().into() {
            return Err(io::Error::new(ErrorKind::InvalidData, format!("Can't read CMU bytes")));
        }

        let mut epk_bytes = [0u8; 32];
        reader.read_exact(&mut epk_bytes)?;
        let epk = jubjub::ExtendedPoint::from_bytes(&epk_bytes);
        if epk.is_none().into() {
            return Err(io::Error::new(ErrorKind::InvalidData, format!("Can't read EPK bytes")));
        }

        let mut enc_bytes = [0u8; ENC_CIPHERTEXT_SIZE];
        reader.read_exact(&mut enc_bytes)?;

        // Attempt decryption. We attempt at main_network at 1,000,000 height, but it doesn't
        // really apply, since this note is not spendable anyway, so the rseed and the note iteself
        // are not usable.
        match try_sapling_note_decryption(
            &MAIN_NETWORK,
            BlockHeight::from_u32(1_000_000),
            &ivk,
            &OutputDescription {
                cmu: cmu.unwrap(),
                ephemeral_key: EphemeralKeyBytes::from(epk_bytes),
                enc_ciphertext: enc_bytes,
                cv: ExtendedPoint::identity(),
                out_ciphertext: [0u8; 80],
                zkproof: [0; GROTH_PROOF_SIZE],
            },
        ) {
            Some((_note, address, memo)) => Ok(Self::new(
                address,
                memo.try_into()
                    .map_err(|_e| io::Error::new(ErrorKind::InvalidData, format!("Failed to decrypt")))?,
            )),
            None => Err(io::Error::new(ErrorKind::InvalidData, format!("Failed to decrypt"))),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use ff::Field;
    use group::GroupEncoding;
    use rand::{rngs::OsRng, Rng};
    use zcash_primitives::{
        memo::Memo,
        sapling::{PaymentAddress, Rseed, SaplingIvk},
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use super::{Message, ENC_CIPHERTEXT_SIZE};

    fn get_random_zaddr() -> (ExtendedSpendingKey, SaplingIvk, PaymentAddress) {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);

        let extsk = ExtendedSpendingKey::master(&seed);
        let ivk = ExtendedFullViewingKey::from(&extsk);
        let (_, addr) = ivk.default_address().unwrap();

        (extsk, ivk.fvk.vk.ivk(), addr)
    }

    #[test]
    fn test_encrpyt_decrypt() {
        let (_, ivk, to) = get_random_zaddr();

        let msg = Memo::from_bytes("Hello World with some value!".to_string().as_bytes()).unwrap();

        let enc = Message::new(to.clone(), msg.clone()).encrypt().unwrap();
        let dec_msg = Message::decrypt(&enc.clone(), &ivk).unwrap();

        assert_eq!(dec_msg.memo, msg);
        assert_eq!(dec_msg.to, to);

        // Also attempt decryption with all addresses
        let dec_msg = Message::decrypt(&enc, &ivk).unwrap();
        assert_eq!(dec_msg.memo, msg);
        assert_eq!(dec_msg.to, to);

        // Raw memo of 512 bytes
        let msg = Memo::from_bytes(&[255u8; 512]).unwrap();
        let enc = Message::new(to.clone(), msg.clone()).encrypt().unwrap();
        let dec_msg = Message::decrypt(&enc.clone(), &ivk).unwrap();

        assert_eq!(dec_msg.memo, msg);
        assert_eq!(dec_msg.to, to);
    }

    #[test]
    fn test_bad_inputs() {
        let (_, ivk1, to1) = get_random_zaddr();
        let (_, ivk2, _) = get_random_zaddr();

        let msg = Memo::from_bytes("Hello World with some value!".to_string().as_bytes()).unwrap();

        let enc = Message::new(to1.clone(), msg.clone()).encrypt().unwrap();
        let dec_success = Message::decrypt(&enc.clone(), &ivk2);
        assert!(dec_success.is_err());

        let dec_success = Message::decrypt(&enc.clone(), &ivk1).unwrap();

        assert_eq!(dec_success.memo, msg);
        assert_eq!(dec_success.to, to1);
    }

    #[test]
    fn test_enc_dec_bad_epk_cmu() {
        let mut rng = OsRng;

        let magic_len = Message::magic_word().len();
        let prefix_len = magic_len + 1; // version byte

        let (_, ivk, to) = get_random_zaddr();
        let msg_str = "Hello World with some value!";
        let msg = Memo::from_bytes(msg_str.to_string().as_bytes()).unwrap();

        let enc = Message::new(to.clone(), msg).encrypt().unwrap();

        // Mad magic word
        let mut bad_enc = enc.clone();
        bad_enc.splice(..magic_len, [1u8; 16].to_vec());
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Bad version
        let mut bad_enc = enc.clone();
        bad_enc.splice(magic_len..magic_len + 1, [Message::serialized_version() + 1].to_vec());
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Create a new, random EPK
        let note = to
            .create_note(0, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let esk = note.generate_or_derive_esk(&mut rng);
        let epk_bad: jubjub::ExtendedPoint = (note.g_d * esk).into();

        let mut bad_enc = enc.clone();
        bad_enc.splice(prefix_len..prefix_len + 33, epk_bad.to_bytes().to_vec());
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Bad CMU should fail
        let mut bad_enc = enc.clone();
        bad_enc.splice(prefix_len + 33..prefix_len + 65, [1u8; 32].to_vec());
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Bad EPK and CMU should fail
        let mut bad_enc = enc.clone();
        bad_enc.splice(prefix_len + 1..prefix_len + 33, [0u8; 32].to_vec());
        bad_enc.splice(prefix_len + 33..prefix_len + 65, [1u8; 32].to_vec());
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Bad payload 1
        let mut bad_enc = enc.clone();
        bad_enc.splice(prefix_len + 65.., [0u8; ENC_CIPHERTEXT_SIZE].to_vec());
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Bad payload 2
        let mut bad_enc = enc.clone();
        bad_enc.reverse();
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Bad payload 3
        let c = enc.clone();
        let (bad_enc, _) = c.split_at(bad_enc.len() - 1);
        let dec_success = Message::decrypt(&bad_enc, &ivk);
        assert!(dec_success.is_err());

        // Bad payload 4
        let dec_success = Message::decrypt(&[], &ivk);
        assert!(dec_success.is_err());

        // This should finally work.
        let dec_success = Message::decrypt(&enc, &ivk);
        assert!(dec_success.is_ok());
        if let Memo::Text(memo) = dec_success.unwrap().memo {
            assert_eq!(memo.to_string(), msg_str.to_string());
        } else {
            panic!("Wrong memo");
        }
    }

    #[test]
    fn test_individual_bytes() {
        let (_, ivk, to) = get_random_zaddr();
        let msg_str = "Hello World with some value!";
        let msg = Memo::from_bytes(msg_str.to_string().as_bytes()).unwrap();

        let enc = Message::new(to.clone(), msg.clone()).encrypt().unwrap();

        // Replace each individual byte and make sure it breaks. i.e., each byte is important
        for i in 0..enc.len() {
            let byte = enc.get(i).unwrap();
            let mut bad_enc = enc.clone();
            bad_enc.splice(i..i + 1, [!byte].to_vec());

            let dec_success = Message::decrypt(&bad_enc, &ivk);
            assert!(dec_success.is_err());
        }

        let dec_success = Message::decrypt(&enc.clone(), &ivk).unwrap();

        assert_eq!(dec_success.memo, msg);
        assert_eq!(dec_success.to, to);
    }
}
