use crate::lightwallet::keys::ToBase58Check;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ripemd160::{Digest, Ripemd160};
use secp256k1::PublicKey;
use sha2::Sha256;
use std::io::{self, Read, Write};
use zcash_primitives::memo::MemoBytes;

pub fn read_string<R: Read>(mut reader: R) -> io::Result<String> {
    // Strings are written as <littleendian> len + bytes
    let str_len = reader.read_u64::<LittleEndian>()?;
    let mut str_bytes = vec![0; str_len as usize];
    reader.read_exact(&mut str_bytes)?;

    let str = String::from_utf8(str_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(str)
}

pub fn write_string<W: Write>(mut writer: W, s: &String) -> io::Result<()> {
    // Strings are written as len + utf8
    writer.write_u64::<LittleEndian>(s.as_bytes().len() as u64)?;
    writer.write_all(s.as_bytes())
}

// Interpret a string or hex-encoded memo, and return a Memo object
pub fn interpret_memo_string(memo_str: String) -> Result<MemoBytes, String> {
    // If the string starts with an "0x", and contains only hex chars ([a-f0-9]+) then
    // interpret it as a hex
    let s_bytes = if memo_str.to_lowercase().starts_with("0x") {
        match hex::decode(&memo_str[2..memo_str.len()]) {
            Ok(data) => data,
            Err(_) => Vec::from(memo_str.as_bytes()),
        }
    } else {
        Vec::from(memo_str.as_bytes())
    };

    MemoBytes::from_bytes(&s_bytes).map_err(|_| format!("Error creating output. Memo '{:?}' is too long", memo_str))
}

pub fn compute_taddr(key: &PublicKey, version: &[u8], suffix: &[u8]) -> String {
    let mut hasher = Ripemd160::new();
    hasher.update(Sha256::digest(&key.serialize().to_vec()));

    hasher.finalize().to_base58check(version, suffix)
}
