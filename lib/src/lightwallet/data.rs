use crate::compact_formats::CompactBlock;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use incrementalmerkletree::Position;
use orchard::keys::FullViewingKey;
use orchard::note::RandomSeed;
use orchard::value::NoteValue;
use orchard::Address;
use prost::Message;
use std::convert::TryFrom;
use std::io::{self, Read, Write};
use std::usize;
use zcash_encoding::{Optional, Vector};
use zcash_primitives::memo::MemoBytes;
use zcash_primitives::sapling;

use crate::blaze::fixed_size_buffer::FixedSizeBuffer;
use zcash_primitives::{consensus::BlockHeight, zip32::ExtendedSpendingKey};
use zcash_primitives::{
    memo::Memo,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::Node,
    sapling::{Diversifier, Rseed},
    transaction::{components::OutPoint, TxId},
    zip32::ExtendedFullViewingKey,
};

#[derive(Clone)]
pub struct BlockData {
    pub(crate) ecb: Vec<u8>,
    pub height: u64,
}

impl BlockData {
    pub fn serialized_version() -> u64 {
        return 20;
    }

    pub(crate) fn new_with(height: u64, hash: &str) -> Self {
        let mut cb = CompactBlock::default();
        cb.hash = hex::decode(hash).unwrap().into_iter().rev().collect::<Vec<_>>();

        let mut ecb = vec![];
        cb.encode(&mut ecb).unwrap();

        Self { ecb, height }
    }

    pub(crate) fn new(mut cb: CompactBlock) -> Self {
        for ctx in &mut cb.vtx {
            for co in &mut ctx.outputs {
                co.ciphertext.clear();
                co.epk.clear();
            }
        }

        cb.header.clear();
        let height = cb.height;

        let mut ecb = vec![];
        cb.encode(&mut ecb).unwrap();

        Self { ecb, height }
    }

    pub(crate) fn cb(&self) -> CompactBlock {
        let b = self.ecb.clone();
        CompactBlock::decode(&b[..]).unwrap()
    }

    pub(crate) fn hash(&self) -> String {
        self.cb().hash().to_string()
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let height = reader.read_i32::<LittleEndian>()? as u64;

        let mut hash_bytes = [0; 32];
        reader.read_exact(&mut hash_bytes)?;
        hash_bytes.reverse();
        let hash = hex::encode(hash_bytes);

        // We don't need this, but because of a quirk, the version is stored later, so we can't actually
        // detect the version here. So we write an empty tree and read it back here
        let tree = CommitmentTree::<Node>::read(&mut reader)?;
        let _tree = if tree.size() == 0 { None } else { Some(tree) };

        let version = reader.read_u64::<LittleEndian>()?;

        let ecb = if version <= 11 {
            vec![]
        } else {
            Vector::read(&mut reader, |r| r.read_u8())?
        };

        if ecb.is_empty() {
            Ok(BlockData::new_with(height, hash.as_str()))
        } else {
            Ok(BlockData { ecb, height })
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i32::<LittleEndian>(self.height as i32)?;

        let hash_bytes: Vec<_> = hex::decode(self.hash()).unwrap().into_iter().rev().collect();
        writer.write_all(&hash_bytes[..])?;

        CommitmentTree::<Node>::empty().write(&mut writer)?;
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // Write the ecb as well
        Vector::write(&mut writer, &self.ecb, |w, b| w.write_u8(*b))?;

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct WitnessCache {
    witnesses: Vec<IncrementalWitness<Node>>,
    pub(crate) top_height: u64,
}

impl WitnessCache {
    pub fn new(witnesses: Vec<IncrementalWitness<Node>>, top_height: u64) -> Self {
        Self { witnesses, top_height }
    }

    pub fn empty() -> Self {
        Self {
            witnesses: vec![],
            top_height: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }

    pub fn clear(&mut self) {
        self.witnesses.clear();
    }

    pub fn get(&self, i: usize) -> Option<&IncrementalWitness<Node>> {
        self.witnesses.get(i)
    }

    #[cfg(test)]
    pub fn get_from_last(&self, i: usize) -> Option<&IncrementalWitness<Node>> {
        self.witnesses.get(self.len() - i - 1)
    }

    pub fn last(&self) -> Option<&IncrementalWitness<Node>> {
        self.witnesses.last()
    }

    pub fn into_fsb(self, fsb: &mut FixedSizeBuffer<IncrementalWitness<Node>>) {
        self.witnesses.into_iter().for_each(|w| fsb.push(w));
    }

    pub fn pop(&mut self, at_height: u64) {
        while !self.witnesses.is_empty() && self.top_height >= at_height {
            self.witnesses.pop();
            self.top_height -= 1;
        }
    }

    // pub fn get_as_string(&self, i: usize) -> String {
    //     if i >= self.witnesses.len() {
    //         return "".to_string();
    //     }

    //     let mut buf = vec![];
    //     self.get(i).unwrap().write(&mut buf).unwrap();
    //     return hex::encode(buf);
    // }
}

pub struct OrchardNoteData {
    pub(super) fvk: FullViewingKey,

    pub note: orchard::Note,

    // (Block number, tx_num, output_num)
    pub created_at: (u64, usize, u32),
    pub witness_position: Option<Position>,

    // Info needed to recreate note
    pub spent: Option<(TxId, u32)>, // If this note was confirmed spent

    // If this note was spent in a send, but has not yet been confirmed.
    // Contains the txid and height at which it was broadcast
    pub unconfirmed_spent: Option<(TxId, u32)>,
    pub memo: Option<Memo>,
    pub is_change: bool,

    // If the spending key is available in the wallet (i.e., whether to keep witness up-to-date)
    pub have_spending_key: bool,
}

impl OrchardNoteData {
    fn serialized_version() -> u64 {
        22
    }

    // Reading a note also needs the corresponding address to read from.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        assert!(version <= Self::serialized_version());

        let fvk = FullViewingKey::read(&mut reader)?;

        // Read the parts of the note
        // Raw address bytes is 43
        let mut address_bytes = [0u8; 43];
        reader.read_exact(&mut address_bytes)?;
        let note_address = Address::from_raw_address_bytes(&address_bytes).unwrap();
        let note_value = reader.read_u64::<LittleEndian>()?;
        let mut rho_bytes = [0u8; 32];
        reader.read_exact(&mut rho_bytes)?;
        let note_rho = orchard::note::Nullifier::from_bytes(&rho_bytes).unwrap();
        let mut note_rseed_bytes = [0u8; 32];
        reader.read_exact(&mut note_rseed_bytes)?;
        let note_rseed = RandomSeed::from_bytes(note_rseed_bytes, &note_rho).unwrap();

        let note = orchard::Note::from_parts(note_address, NoteValue::from_raw(note_value), note_rho, note_rseed);

        let witness_position = Optional::read(&mut reader, |r| {
            let pos = r.read_u64::<LittleEndian>()?;
            Ok(Position::from(pos as usize))
        })?;

        let spent = Optional::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;
            let height = r.read_u32::<LittleEndian>()?;
            Ok((TxId::from_bytes(txid_bytes), height))
        })?;

        let unconfirmed_spent = Optional::read(&mut reader, |r| {
            let mut txbytes = [0u8; 32];
            r.read_exact(&mut txbytes)?;

            let height = r.read_u32::<LittleEndian>()?;
            Ok((TxId::from_bytes(txbytes), height))
        })?;

        let memo = Optional::read(&mut reader, |r| {
            let mut memo_bytes = [0u8; 512];
            r.read_exact(&mut memo_bytes)?;

            // Attempt to read memo, first as text, else as arbitrary 512 bytes
            match MemoBytes::from_bytes(&memo_bytes) {
                Ok(mb) => match Memo::try_from(mb.clone()) {
                    Ok(m) => Ok(m),
                    Err(_) => Ok(Memo::Future(mb)),
                },
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Couldn't create memo: {}", e),
                )),
            }
        })?;

        let is_change: bool = reader.read_u8()? > 0;

        let have_spending_key = reader.read_u8()? > 0;

        Ok(OrchardNoteData {
            fvk,
            note,
            created_at: (0, 0, 0),
            witness_position,
            spent,
            unconfirmed_spent,
            memo,
            is_change,
            have_spending_key,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write a version number first, so we can later upgrade this if needed.
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        self.fvk.write(&mut writer)?;

        // Write the components of the note
        writer.write_all(&self.note.recipient().to_raw_address_bytes())?;
        writer.write_u64::<LittleEndian>(self.note.value().inner())?;
        writer.write_all(&self.note.rho().to_bytes())?;
        writer.write_all(self.note.rseed().as_bytes())?;

        // We don't write the created_at, because it should be temporary
        Optional::write(&mut writer, self.witness_position, |w, p| {
            w.write_u64::<LittleEndian>(p.into())
        })?;

        Optional::write(&mut writer, self.spent, |w, (txid, h)| {
            w.write_all(txid.as_ref())?;
            w.write_u32::<LittleEndian>(h)
        })?;

        Optional::write(&mut writer, self.unconfirmed_spent, |w, (txid, height)| {
            w.write_all(txid.as_ref())?;
            w.write_u32::<LittleEndian>(height)
        })?;

        Optional::write(&mut writer, self.memo.as_ref(), |w, m| {
            w.write_all(m.encode().as_array())
        })?;

        writer.write_u8(if self.is_change { 1 } else { 0 })?;

        writer.write_u8(if self.have_spending_key { 1 } else { 0 })?;

        // Note that we don't write the unconfirmed_spent field, because if the wallet is restarted,
        // we don't want to be beholden to any expired txns

        Ok(())
    }
}

pub struct SaplingNoteData {
    // Technically, this should be recoverable from the account number,
    // but we're going to refactor this in the future, so I'll write it again here.
    pub(super) extfvk: ExtendedFullViewingKey,

    pub diversifier: Diversifier,
    pub note: sapling::Note,

    // Witnesses for the last 100 blocks. witnesses.last() is the latest witness
    pub(crate) witnesses: WitnessCache,
    pub(super) nullifier: sapling::Nullifier,
    pub spent: Option<(TxId, u32)>, // If this note was confirmed spent

    // If this note was spent in a send, but has not yet been confirmed.
    // Contains the txid and height at which it was broadcast
    pub unconfirmed_spent: Option<(TxId, u32)>,
    pub memo: Option<Memo>,
    pub is_change: bool,

    // If the spending key is available in the wallet (i.e., whether to keep witness up-to-date)
    pub have_spending_key: bool,
}

// Reading a note also needs the corresponding address to read from.
fn read_rseed<R: Read>(mut reader: R) -> io::Result<Rseed> {
    let note_type = reader.read_u8()?;

    let mut r_bytes: [u8; 32] = [0; 32];
    reader.read_exact(&mut r_bytes)?;

    let r = match note_type {
        1 => Rseed::BeforeZip212(jubjub::Fr::from_bytes(&r_bytes).unwrap()),
        2 => Rseed::AfterZip212(r_bytes),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Bad note type")),
    };

    Ok(r)
}

fn write_rseed<W: Write>(mut writer: W, rseed: &Rseed) -> io::Result<()> {
    let note_type = match rseed {
        Rseed::BeforeZip212(_) => 1,
        Rseed::AfterZip212(_) => 2,
    };
    writer.write_u8(note_type)?;

    match rseed {
        Rseed::BeforeZip212(fr) => writer.write_all(&fr.to_bytes()),
        Rseed::AfterZip212(b) => writer.write_all(b),
    }
}

impl SaplingNoteData {
    fn serialized_version() -> u64 {
        20
    }

    // Reading a note also needs the corresponding address to read from.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;

        let _account = if version <= 5 {
            reader.read_u64::<LittleEndian>()?
        } else {
            0
        };

        let extfvk = ExtendedFullViewingKey::read(&mut reader)?;

        let mut diversifier_bytes = [0u8; 11];
        reader.read_exact(&mut diversifier_bytes)?;
        let diversifier = Diversifier { 0: diversifier_bytes };

        // To recover the note, read the value and r, and then use the payment address
        // to recreate the note
        let (value, rseed) = if version <= 3 {
            let value = reader.read_u64::<LittleEndian>()?;

            let mut r_bytes: [u8; 32] = [0; 32];
            reader.read_exact(&mut r_bytes)?;

            let r = jubjub::Fr::from_bytes(&r_bytes).unwrap();

            (value, Rseed::BeforeZip212(r))
        } else {
            let value = reader.read_u64::<LittleEndian>()?;
            let rseed = read_rseed(&mut reader)?;

            (value, rseed)
        };

        let maybe_note = extfvk
            .fvk
            .vk
            .to_payment_address(diversifier)
            .unwrap()
            .create_note(value, rseed);

        let note = match maybe_note {
            Some(n) => Ok(n),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Couldn't create the note for the address",
            )),
        }?;

        let witnesses_vec = Vector::read(&mut reader, |r| IncrementalWitness::<Node>::read(r))?;
        let top_height = if version < 20 {
            0
        } else {
            reader.read_u64::<LittleEndian>()?
        };
        let witnesses = WitnessCache::new(witnesses_vec, top_height);

        let mut nullifier = [0u8; 32];
        reader.read_exact(&mut nullifier)?;
        let nullifier = sapling::Nullifier(nullifier);

        // Note that this is only the spent field, we ignore the unconfirmed_spent field.
        // The reason is that unconfirmed spents are only in memory, and we need to get the actual value of spent
        // from the blockchain anyway.
        let spent = if version <= 5 {
            let spent = Optional::read(&mut reader, |r| {
                let mut txid_bytes = [0u8; 32];
                r.read_exact(&mut txid_bytes)?;
                Ok(TxId::from_bytes(txid_bytes))
            })?;

            let spent_at_height = if version >= 2 {
                Optional::read(&mut reader, |r| r.read_i32::<LittleEndian>())?
            } else {
                None
            };

            if spent.is_some() && spent_at_height.is_some() {
                Some((spent.unwrap(), spent_at_height.unwrap() as u32))
            } else {
                None
            }
        } else {
            Optional::read(&mut reader, |r| {
                let mut txid_bytes = [0u8; 32];
                r.read_exact(&mut txid_bytes)?;
                let height = r.read_u32::<LittleEndian>()?;
                Ok((TxId::from_bytes(txid_bytes), height))
            })?
        };

        let unconfirmed_spent = if version <= 4 {
            None
        } else {
            Optional::read(&mut reader, |r| {
                let mut txbytes = [0u8; 32];
                r.read_exact(&mut txbytes)?;

                let height = r.read_u32::<LittleEndian>()?;
                Ok((TxId::from_bytes(txbytes), height))
            })?
        };

        let memo = Optional::read(&mut reader, |r| {
            let mut memo_bytes = [0u8; 512];
            r.read_exact(&mut memo_bytes)?;

            // Attempt to read memo, first as text, else as arbitrary 512 bytes
            match MemoBytes::from_bytes(&memo_bytes) {
                Ok(mb) => match Memo::try_from(mb.clone()) {
                    Ok(m) => Ok(m),
                    Err(_) => Ok(Memo::Future(mb)),
                },
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Couldn't create memo: {}", e),
                )),
            }
        })?;

        let is_change: bool = reader.read_u8()? > 0;

        let have_spending_key = if version <= 2 {
            true // Will get populated in the lightwallet::read() method, for now assume true
        } else {
            reader.read_u8()? > 0
        };

        Ok(SaplingNoteData {
            extfvk,
            diversifier,
            note,
            witnesses,
            nullifier,
            spent,
            unconfirmed_spent,
            memo,
            is_change,
            have_spending_key,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write a version number first, so we can later upgrade this if needed.
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        self.extfvk.write(&mut writer)?;

        writer.write_all(&self.diversifier.0)?;

        // Writing the note means writing the note.value and note.r. The Note is recoverable
        // from these 2 values and the Payment address.
        writer.write_u64::<LittleEndian>(self.note.value)?;

        write_rseed(&mut writer, &self.note.rseed)?;

        Vector::write(&mut writer, &self.witnesses.witnesses, |wr, wi| wi.write(wr))?;
        writer.write_u64::<LittleEndian>(self.witnesses.top_height)?;

        writer.write_all(&self.nullifier.0)?;

        Optional::write(&mut writer, self.spent, |w, (txid, h)| {
            w.write_all(txid.as_ref())?;
            w.write_u32::<LittleEndian>(h)
        })?;

        Optional::write(&mut writer, self.unconfirmed_spent, |w, (txid, height)| {
            w.write_all(txid.as_ref())?;
            w.write_u32::<LittleEndian>(height)
        })?;

        Optional::write(&mut writer, self.memo.as_ref(), |w, m| {
            w.write_all(m.encode().as_array())
        })?;

        writer.write_u8(if self.is_change { 1 } else { 0 })?;

        writer.write_u8(if self.have_spending_key { 1 } else { 0 })?;

        // Note that we don't write the unconfirmed_spent field, because if the wallet is restarted,
        // we don't want to be beholden to any expired txns

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Utxo {
    pub address: String,
    pub txid: TxId,
    pub output_index: u64,
    pub script: Vec<u8>,
    pub value: u64,
    pub height: i32,

    pub spent_at_height: Option<i32>,
    pub spent: Option<TxId>, // If this utxo was confirmed spent

    // If this utxo was spent in a send, but has not yet been confirmed.
    // Contains the txid and height at which the Tx was broadcast
    pub unconfirmed_spent: Option<(TxId, u32)>,
}

impl Utxo {
    pub fn serialized_version() -> u64 {
        return 3;
    }

    pub fn to_outpoint(&self) -> OutPoint {
        OutPoint::new(*self.txid.as_ref(), self.output_index as u32)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;

        let address_len = reader.read_i32::<LittleEndian>()?;
        let mut address_bytes = vec![0; address_len as usize];
        reader.read_exact(&mut address_bytes)?;
        let address = String::from_utf8(address_bytes).unwrap();
        assert_eq!(address.chars().take(1).collect::<Vec<char>>()[0], 't');

        let mut txid_bytes = [0; 32];
        reader.read_exact(&mut txid_bytes)?;
        let txid = TxId::from_bytes(txid_bytes);

        let output_index = reader.read_u64::<LittleEndian>()?;
        let value = reader.read_u64::<LittleEndian>()?;
        let height = reader.read_i32::<LittleEndian>()?;

        let script = Vector::read(&mut reader, |r| {
            let mut byte = [0; 1];
            r.read_exact(&mut byte)?;
            Ok(byte[0])
        })?;

        let spent = Optional::read(&mut reader, |r| {
            let mut txbytes = [0u8; 32];
            r.read_exact(&mut txbytes)?;
            Ok(TxId::from_bytes(txbytes))
        })?;

        let spent_at_height = if version <= 1 {
            None
        } else {
            Optional::read(&mut reader, |r| r.read_i32::<LittleEndian>())?
        };

        let unconfirmed_spent = if version <= 2 {
            None
        } else {
            Optional::read(&mut reader, |r| {
                let mut txbytes = [0u8; 32];
                r.read_exact(&mut txbytes)?;

                let height = r.read_u32::<LittleEndian>()?;
                Ok((TxId::from_bytes(txbytes), height))
            })?
        };

        Ok(Utxo {
            address,
            txid,
            output_index,
            script,
            value,
            height,
            spent_at_height,
            spent,
            unconfirmed_spent,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        writer.write_u32::<LittleEndian>(self.address.as_bytes().len() as u32)?;
        writer.write_all(self.address.as_bytes())?;

        writer.write_all(self.txid.as_ref())?;

        writer.write_u64::<LittleEndian>(self.output_index)?;
        writer.write_u64::<LittleEndian>(self.value)?;
        writer.write_i32::<LittleEndian>(self.height)?;

        Vector::write(&mut writer, &self.script, |w, b| w.write_all(&[*b]))?;

        Optional::write(&mut writer, self.spent, |w, txid| w.write_all(txid.as_ref()))?;

        Optional::write(&mut writer, self.spent_at_height, |w, s| w.write_i32::<LittleEndian>(s))?;

        Optional::write(&mut writer, self.unconfirmed_spent, |w, (txid, height)| {
            w.write_all(txid.as_ref())?;
            w.write_u32::<LittleEndian>(height)
        })?;

        Ok(())
    }
}

#[derive(PartialEq)]
pub struct OutgoingTxMetadata {
    pub address: String,
    pub value: u64,
    pub memo: Memo,
}

impl OutgoingTxMetadata {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let address_len = reader.read_u64::<LittleEndian>()?;
        let mut address_bytes = vec![0; address_len as usize];
        reader.read_exact(&mut address_bytes)?;
        let address = String::from_utf8(address_bytes).unwrap();

        let value = reader.read_u64::<LittleEndian>()?;

        let mut memo_bytes = [0u8; 512];
        reader.read_exact(&mut memo_bytes)?;
        let memo = match MemoBytes::from_bytes(&memo_bytes) {
            Ok(mb) => match Memo::try_from(mb.clone()) {
                Ok(m) => Ok(m),
                Err(_) => Ok(Memo::Future(mb)),
            },
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Couldn't create memo: {}", e),
            )),
        }?;

        Ok(OutgoingTxMetadata { address, value, memo })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Strings are written as len + utf8
        writer.write_u64::<LittleEndian>(self.address.as_bytes().len() as u64)?;
        writer.write_all(self.address.as_bytes())?;

        writer.write_u64::<LittleEndian>(self.value)?;
        writer.write_all(self.memo.encode().as_array())
    }
}

pub struct WalletTx {
    // Block in which this tx was included
    pub block: BlockHeight,

    // Is this Tx unconfirmed (i.e., not yet mined)
    pub unconfirmed: bool,

    // Timestamp of Tx. Added in v4
    pub datetime: u64,

    // Txid of this transaction. It's duplicated here (It is also the Key in the HashMap that points to this
    // WalletTx in LightWallet::txs)
    pub txid: TxId,

    // List of all nullifiers spent in this Tx. These nullifiers belong to the wallet.
    pub s_spent_nullifiers: Vec<sapling::Nullifier>,

    // List of all orchard nullifiers spent in this Tx.
    pub o_spent_nullifiers: Vec<orchard::note::Nullifier>,

    // List of all notes received in this tx. Some of these might be change notes.
    pub s_notes: Vec<SaplingNoteData>,

    // List of all orchard notes recieved in this tx. Some of these might be change.
    pub o_notes: Vec<OrchardNoteData>,

    // List of all Utxos received in this Tx. Some of these might be change notes
    pub utxos: Vec<Utxo>,

    // Total value of all orchard nullifiers that were spent in this Tx
    pub total_orchard_value_spent: u64,

    // Total value of all the sapling nullifiers that were spent in this Tx
    pub total_sapling_value_spent: u64,

    // Total amount of transparent funds that belong to us that were spent in this Tx.
    pub total_transparent_value_spent: u64,

    // All outgoing sapling sends to addresses outside this wallet
    pub outgoing_metadata: Vec<OutgoingTxMetadata>,

    // Whether this TxID was downloaded from the server and scanned for Memos
    pub full_tx_scanned: bool,

    // Price of Zec when this Tx was created
    pub zec_price: Option<f64>,
}

impl WalletTx {
    pub fn serialized_version() -> u64 {
        return 23;
    }

    pub fn new_txid(txid: &Vec<u8>) -> TxId {
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(txid);
        TxId::from_bytes(txid_bytes)
    }

    pub fn get_price(datetime: u64, price: &WalletZecPriceInfo) -> Option<f64> {
        match price.zec_price {
            None => None,
            Some((t, p)) => {
                // If the price was fetched within 24 hours of this Tx, we use the "current" price
                // else, we mark it as None, for the historical price fetcher to get
                if (t as i64 - datetime as i64).abs() < 24 * 60 * 60 {
                    Some(p)
                } else {
                    None
                }
            }
        }
    }

    pub fn new(height: BlockHeight, datetime: u64, txid: &TxId, unconfirmed: bool) -> Self {
        WalletTx {
            block: height,
            unconfirmed,
            datetime,
            txid: txid.clone(),
            o_spent_nullifiers: vec![],
            s_spent_nullifiers: vec![],
            s_notes: vec![],
            o_notes: vec![],
            utxos: vec![],
            total_transparent_value_spent: 0,
            total_sapling_value_spent: 0,
            total_orchard_value_spent: 0,
            outgoing_metadata: vec![],
            full_tx_scanned: false,
            zec_price: None,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;

        let block = BlockHeight::from_u32(reader.read_i32::<LittleEndian>()? as u32);

        let unconfirmed = if version <= 20 { false } else { reader.read_u8()? == 1 };

        let datetime = if version >= 4 {
            reader.read_u64::<LittleEndian>()?
        } else {
            0
        };

        let mut txid_bytes = [0u8; 32];
        reader.read_exact(&mut txid_bytes)?;

        let txid = TxId::from_bytes(txid_bytes);

        let s_notes = Vector::read(&mut reader, |r| SaplingNoteData::read(r))?;
        let utxos = Vector::read(&mut reader, |r| Utxo::read(r))?;

        let total_orchard_value_spent = if version <= 22 {
            0
        } else {
            reader.read_u64::<LittleEndian>()?
        };
        let total_sapling_value_spent = reader.read_u64::<LittleEndian>()?;
        let total_transparent_value_spent = reader.read_u64::<LittleEndian>()?;

        // Outgoing metadata was only added in version 2
        let outgoing_metadata = Vector::read(&mut reader, |r| OutgoingTxMetadata::read(r))?;

        let full_tx_scanned = reader.read_u8()? > 0;

        let zec_price = if version <= 4 {
            None
        } else {
            Optional::read(&mut reader, |r| r.read_f64::<LittleEndian>())?
        };

        let s_spent_nullifiers = if version <= 5 {
            vec![]
        } else {
            Vector::read(&mut reader, |r| {
                let mut n = [0u8; 32];
                r.read_exact(&mut n)?;
                Ok(sapling::Nullifier(n))
            })?
        };

        let o_notes = if version <= 21 {
            vec![]
        } else {
            Vector::read(&mut reader, |r| OrchardNoteData::read(r))?
        };

        let o_spent_nullifiers = if version <= 21 {
            vec![]
        } else {
            Vector::read(&mut reader, |r| {
                let mut rho_bytes = [0u8; 32];
                r.read_exact(&mut rho_bytes)?;
                Ok(orchard::note::Nullifier::from_bytes(&rho_bytes).unwrap())
            })?
        };

        Ok(Self {
            block,
            unconfirmed,
            datetime,
            txid,
            s_notes,
            o_notes,
            utxos,
            s_spent_nullifiers,
            o_spent_nullifiers,
            total_sapling_value_spent,
            total_orchard_value_spent,
            total_transparent_value_spent,
            outgoing_metadata,
            full_tx_scanned,
            zec_price,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        let block: u32 = self.block.into();
        writer.write_i32::<LittleEndian>(block as i32)?;

        writer.write_u8(if self.unconfirmed { 1 } else { 0 })?;

        writer.write_u64::<LittleEndian>(self.datetime)?;

        writer.write_all(self.txid.as_ref())?;

        Vector::write(&mut writer, &self.s_notes, |w, nd| nd.write(w))?;
        Vector::write(&mut writer, &self.utxos, |w, u| u.write(w))?;

        writer.write_u64::<LittleEndian>(self.total_orchard_value_spent)?;
        writer.write_u64::<LittleEndian>(self.total_sapling_value_spent)?;
        writer.write_u64::<LittleEndian>(self.total_transparent_value_spent)?;

        // Write the outgoing metadata
        Vector::write(&mut writer, &self.outgoing_metadata, |w, om| om.write(w))?;

        writer.write_u8(if self.full_tx_scanned { 1 } else { 0 })?;

        Optional::write(&mut writer, self.zec_price, |w, p| w.write_f64::<LittleEndian>(p))?;

        Vector::write(&mut writer, &self.s_spent_nullifiers, |w, n| w.write_all(&n.0))?;

        Vector::write(&mut writer, &self.o_notes, |w, n| n.write(w))?;

        Vector::write(&mut writer, &self.o_spent_nullifiers, |w, n| w.write_all(&n.to_bytes()))?;

        Ok(())
    }

    pub fn total_funds_spent(&self) -> u64 {
        self.total_orchard_value_spent + self.total_sapling_value_spent + self.total_transparent_value_spent
    }
}

pub struct SpendableOrchardNote {
    pub txid: TxId,
    pub sk: orchard::keys::SpendingKey,
    pub note: orchard::Note,
    pub merkle_path: orchard::tree::MerklePath,
}

pub struct SpendableSaplingNote {
    pub txid: TxId,
    pub nullifier: sapling::Nullifier,
    pub diversifier: Diversifier,
    pub note: sapling::Note,
    pub witness: IncrementalWitness<Node>,
    pub extsk: ExtendedSpendingKey,
}

impl SpendableSaplingNote {
    pub fn from(
        txid: TxId,
        nd: &SaplingNoteData,
        anchor_offset: usize,
        extsk: &Option<ExtendedSpendingKey>,
    ) -> Option<Self> {
        // Include only notes that haven't been spent, or haven't been included in an unconfirmed spend yet.
        if nd.spent.is_none()
            && nd.unconfirmed_spent.is_none()
            && extsk.is_some()
            && nd.witnesses.len() >= (anchor_offset + 1)
        {
            let witness = nd.witnesses.get(nd.witnesses.len() - anchor_offset - 1);

            witness.map(|w| SpendableSaplingNote {
                txid,
                nullifier: nd.nullifier,
                diversifier: nd.diversifier,
                note: nd.note.clone(),
                witness: w.clone(),
                extsk: extsk.clone().unwrap(),
            })
        } else {
            None
        }
    }
}

// Struct that tracks the latest and historical price of ZEC in the wallet
#[derive(Clone, Debug)]
pub struct WalletZecPriceInfo {
    // Latest price of ZEC and when it was fetched
    pub zec_price: Option<(u64, f64)>,

    // Wallet's currency. All the prices are in this currency
    pub currency: String,

    // When the last time historical prices were fetched
    pub last_historical_prices_fetched_at: Option<u64>,

    // Historical prices retry count
    pub historical_prices_retry_count: u64,
}

impl WalletZecPriceInfo {
    pub fn new() -> Self {
        Self {
            zec_price: None,
            currency: "USD".to_string(), // Only USD is supported right now.
            last_historical_prices_fetched_at: None,
            historical_prices_retry_count: 0,
        }
    }

    pub fn serialized_version() -> u64 {
        return 20;
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        if version > Self::serialized_version() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Can't read ZecPriceInfo because of incorrect version",
            ));
        }

        // The "current" zec price is not persisted, since it is almost certainly outdated
        let zec_price = None;

        // Currency is only USD for now
        let currency = "USD".to_string();

        let last_historical_prices_fetched_at = Optional::read(&mut reader, |r| r.read_u64::<LittleEndian>())?;
        let historical_prices_retry_count = reader.read_u64::<LittleEndian>()?;

        Ok(Self {
            zec_price,
            currency,
            last_historical_prices_fetched_at,
            historical_prices_retry_count,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // We don't write the currency zec price or the currency yet.
        Optional::write(&mut writer, self.last_historical_prices_fetched_at, |w, t| {
            w.write_u64::<LittleEndian>(t)
        })?;
        writer.write_u64::<LittleEndian>(self.historical_prices_retry_count)?;

        Ok(())
    }
}
