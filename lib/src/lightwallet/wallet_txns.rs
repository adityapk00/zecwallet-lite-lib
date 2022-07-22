use std::{
    collections::HashMap,
    io::{self, Read, Write},
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log::error;
use zcash_primitives::{
    consensus::BlockHeight,
    memo::Memo,
    merkle_tree::IncrementalWitness,
    primitives::{Note, Nullifier, PaymentAddress, SaplingIvk},
    sapling::Node,
    serialize::Vector,
    transaction::{components::TxOut, TxId},
    zip32::ExtendedFullViewingKey,
};

use crate::lightclient::lightclient_config::MAX_REORG;

use super::data::{OutgoingTxMetadata, SaplingNoteData, Utxo, WalletTx, WitnessCache};

/// List of all transactions in a wallet.
/// Note that the parent is expected to hold a RwLock, so we will assume that all accesses to
/// this struct are threadsafe/locked properly.
#[derive(Default)]
pub struct WalletTxns {
    pub(crate) current: HashMap<TxId, WalletTx>,
    pub(crate) last_txid: Option<TxId>,
}

impl WalletTxns {
    pub fn serialized_version() -> u64 {
        return 21;
    }

    pub fn new() -> Self {
        Default::default()
    }

    pub fn read_old<R: Read>(mut reader: R) -> io::Result<Self> {
        let txs_tuples = Vector::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;

            Ok((TxId { 0: txid_bytes }, WalletTx::read(r).unwrap()))
        })?;

        let txs = txs_tuples.into_iter().collect::<HashMap<TxId, WalletTx>>();

        Ok(Self {
            current: txs,
            last_txid: None,
        })
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;
        if version > Self::serialized_version() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Can't read wallettxns because of incorrect version",
            ));
        }

        let txs_tuples = Vector::read(&mut reader, |r| {
            let mut txid_bytes = [0u8; 32];
            r.read_exact(&mut txid_bytes)?;

            Ok((TxId { 0: txid_bytes }, WalletTx::read(r).unwrap()))
        })?;

        let current = txs_tuples.into_iter().collect::<HashMap<TxId, WalletTx>>();
        let last_txid = current
            .values()
            .fold(None, |c: Option<(TxId, BlockHeight)>, w| {
                if c.is_none() || w.block > c.unwrap().1 {
                    Some((w.txid.clone(), w.block))
                } else {
                    c
                }
            })
            .map(|v| v.0);

        let _mempool = if version <= 20 {
            Vector::read(&mut reader, |r| {
                let mut txid_bytes = [0u8; 32];
                r.read_exact(&mut txid_bytes)?;
                let wtx = WalletTx::read(r)?;

                Ok((TxId { 0: txid_bytes }, wtx))
            })?
            .into_iter()
            .collect()
        } else {
            vec![]
        };

        Ok(Self { current, last_txid })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write the version
        writer.write_u64::<LittleEndian>(Self::serialized_version())?;

        // The hashmap, write as a set of tuples. Store them sorted so that wallets are
        // deterministically saved
        {
            let mut txns = self.current.iter().collect::<Vec<(&TxId, &WalletTx)>>();
            txns.sort_by(|a, b| a.0.partial_cmp(b.0).unwrap());

            Vector::write(&mut writer, &txns, |w, (k, v)| {
                w.write_all(&k.0)?;
                v.write(w)
            })?;
        }

        Ok(())
    }

    pub fn clear(&mut self) {
        self.current.clear();
    }

    pub fn adjust_spendable_status(&mut self, spendable_keys: Vec<SaplingIvk>) {
        self.current.values_mut().for_each(|tx| {
            tx.notes.iter_mut().for_each(|nd| {
                nd.have_spending_key = spendable_keys
                    .iter()
                    .find(|ivk| ivk.to_repr() == nd.ivk.to_repr())
                    .is_some();
                if !nd.have_spending_key {
                    nd.witnesses.clear();
                }
            })
        });
    }

    pub fn remove_txids(&mut self, txids_to_remove: Vec<TxId>) {
        for txid in &txids_to_remove {
            self.current.remove(&txid);
        }

        // We also need to update any sapling note data and utxos in existing transactions that
        // were spent in any of the txids that were removed
        self.current.values_mut().for_each(|wtx| {
            // Update notes to rollback any spent notes
            wtx.notes.iter_mut().for_each(|nd| {
                // Mark note as unspent if the txid being removed spent it.
                if nd.spent.is_some() && txids_to_remove.contains(&nd.spent.unwrap().0) {
                    nd.spent = None;
                }

                // Remove unconfirmed spends too
                if nd.unconfirmed_spent.is_some() && txids_to_remove.contains(&nd.unconfirmed_spent.unwrap().0) {
                    nd.unconfirmed_spent = None;
                }
            });

            // Update UTXOs to rollback any spent utxos
            wtx.utxos.iter_mut().for_each(|utxo| {
                if utxo.spent.is_some() && txids_to_remove.contains(&utxo.spent.unwrap()) {
                    utxo.spent = None;
                    utxo.spent_at_height = None;
                }

                if utxo.unconfirmed_spent.is_some() && txids_to_remove.contains(&utxo.unconfirmed_spent.unwrap().0) {
                    utxo.unconfirmed_spent = None;
                }
            })
        });
    }

    // During reorgs, we need to remove all txns at a given height, and all spends that refer to any removed txns.
    pub fn remove_txns_at_height(&mut self, reorg_height: u64) {
        let reorg_height = BlockHeight::from_u32(reorg_height as u32);

        // First, collect txids that need to be removed
        let txids_to_remove = self
            .current
            .values()
            .filter_map(|wtx| {
                if wtx.block >= reorg_height {
                    Some(wtx.txid.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        self.remove_txids(txids_to_remove);

        // Of the notes that still remain, unroll the witness.
        // Trim all witnesses for the invalidated blocks
        for tx in self.current.values_mut() {
            // We only want to trim the witness for "existing" notes, i.e., notes that were created before the block that is being removed
            if tx.block < reorg_height {
                for nd in tx.notes.iter_mut() {
                    // The latest witness is at the last() position, so just pop() it.
                    // We should be checking if there is a witness at all, but if there is none, it is an
                    // empty vector, for which pop() is a no-op.
                    let _discard = nd.witnesses.pop(u64::from(reorg_height));
                }
            }
        }
    }

    pub fn get_last_txid(&self) -> &'_ Option<TxId> {
        &self.last_txid
    }

    pub fn get_notes_for_updating(&self, before_block: u64) -> Vec<(TxId, Nullifier)> {
        let before_block = BlockHeight::from_u32(before_block as u32);

        self.current
            .iter()
            .filter(|(_, wtx)| !wtx.unconfirmed) // Update only confirmed notes
            .flat_map(|(txid, wtx)| {
                // Fetch notes that are before the before_block.
                wtx.notes.iter().filter_map(move |snd| {
                    if wtx.block <= before_block
                        && snd.have_spending_key
                        && snd.witnesses.len() > 0
                        && snd.spent.is_none()
                    {
                        Some((txid.clone(), snd.nullifier.clone()))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    pub fn total_funds_spent_in(&self, txid: &TxId) -> u64 {
        self.current
            .get(&txid)
            .map(|t| t.total_sapling_value_spent + t.total_transparent_value_spent)
            .unwrap_or(0)
    }

    pub fn get_unspent_nullifiers(&self) -> Vec<(Nullifier, u64, TxId)> {
        self.current
            .iter()
            .flat_map(|(_, wtx)| {
                wtx.notes
                    .iter()
                    .filter(|nd| nd.spent.is_none())
                    .map(move |nd| (nd.nullifier.clone(), nd.note.value, wtx.txid.clone()))
            })
            .collect()
    }

    pub(crate) fn get_note_witness(&self, txid: &TxId, nullifier: &Nullifier) -> Option<(WitnessCache, BlockHeight)> {
        self.current.get(txid).map(|wtx| {
            wtx.notes
                .iter()
                .find(|nd| nd.nullifier == *nullifier)
                .map(|nd| (nd.witnesses.clone(), wtx.block))
        })?
    }

    pub(crate) fn set_note_witnesses(&mut self, txid: &TxId, nullifier: &Nullifier, witnesses: WitnessCache) {
        self.current
            .get_mut(txid)
            .unwrap()
            .notes
            .iter_mut()
            .find(|nd| nd.nullifier == *nullifier)
            .unwrap()
            .witnesses = witnesses;
    }

    pub(crate) fn clear_old_witnesses(&mut self, latest_height: u64) {
        let cutoff = (latest_height.saturating_sub(MAX_REORG as u64)) as u32;

        self.current.iter_mut().for_each(|(_, wtx)| {
            wtx.notes
                .iter_mut()
                .filter(|n| !n.witnesses.is_empty() && n.spent.is_some() && n.spent.unwrap().1 < cutoff)
                .for_each(|n| n.witnesses.clear());
        });
    }

    pub(crate) fn clear_expired_mempool(&mut self, latest_height: u64) {
        let cutoff = BlockHeight::from_u32((latest_height.saturating_sub(MAX_REORG as u64)) as u32);

        let txids_to_remove = self
            .current
            .iter()
            .filter(|(_, wtx)| wtx.unconfirmed && wtx.block < cutoff)
            .map(|(_, wtx)| wtx.txid.clone())
            .collect::<Vec<_>>();

        txids_to_remove
            .iter()
            .for_each(|t| println!("Removing expired mempool tx {}", t));

        self.remove_txids(txids_to_remove);
    }

    // Will mark the nullifier of the given txid as spent. Returns the amount of the nullifier
    pub fn mark_txid_nf_spent(
        &mut self,
        txid: TxId,
        nullifier: &Nullifier,
        spent_txid: &TxId,
        spent_at_height: BlockHeight,
    ) -> u64 {
        let mut note_data = self
            .current
            .get_mut(&txid)
            .unwrap()
            .notes
            .iter_mut()
            .find(|n| n.nullifier == *nullifier)
            .unwrap();

        note_data.spent = Some((spent_txid.clone(), spent_at_height.into()));
        note_data.unconfirmed_spent = None;
        note_data.note.value
    }

    // Check this transaction to see if it is an outgoing transaction, and if it is, mark all recieved notes in this
    // transction as change. i.e., If any funds were spent in this transaction, all recieved notes are change notes.
    pub fn check_notes_mark_change(&mut self, txid: &TxId) {
        if self.total_funds_spent_in(txid) > 0 {
            self.current.get_mut(txid).map(|wtx| {
                wtx.notes.iter_mut().for_each(|n| {
                    n.is_change = true;
                })
            });
        }
    }

    fn get_or_create_tx(
        &mut self,
        txid: &TxId,
        height: BlockHeight,
        unconfirmed: bool,
        datetime: u64,
    ) -> &'_ mut WalletTx {
        if !self.current.contains_key(&txid) {
            self.current.insert(
                txid.clone(),
                WalletTx::new(BlockHeight::from(height), datetime, &txid, unconfirmed),
            );
            self.last_txid = Some(txid.clone());
        }
        let wtx = self.current.get_mut(&txid).expect("Txid should be present");

        // Make sure the unconfirmed status matches
        if wtx.unconfirmed != unconfirmed {
            wtx.unconfirmed = unconfirmed;
            wtx.block = height;
            wtx.datetime = datetime;
        }

        wtx
    }

    pub fn set_price(&mut self, txid: &TxId, price: Option<f64>) {
        price.map(|p| self.current.get_mut(txid).map(|tx| tx.zec_price = Some(p)));
    }

    // Records a TxId as having spent some nullifiers from the wallet.
    pub fn add_new_spent(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        unconfirmed: bool,
        timestamp: u32,
        nullifier: Nullifier,
        value: u64,
        source_txid: TxId,
    ) {
        // Record this Tx as having spent some funds
        {
            let wtx = self.get_or_create_tx(&txid, BlockHeight::from(height), unconfirmed, timestamp as u64);

            // Mark the height correctly, in case this was previously a mempool or unconfirmed tx.
            wtx.block = height;

            if wtx.spent_nullifiers.iter().find(|nf| **nf == nullifier).is_none() {
                wtx.spent_nullifiers.push(nullifier);
                wtx.total_sapling_value_spent += value;
            }
        }

        // Since this Txid has spent some funds, output notes in this Tx that are sent to us are actually change.
        self.check_notes_mark_change(&txid);

        // Mark the source note's nullifier as spent
        if !unconfirmed {
            let wtx = self.current.get_mut(&source_txid).expect("Txid should be present");

            wtx.notes.iter_mut().find(|n| n.nullifier == nullifier).map(|nd| {
                // Record the spent height
                nd.spent = Some((txid, height.into()));
            });
        }
    }

    pub fn add_taddr_spent(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        unconfirmed: bool,
        timestamp: u64,
        total_transparent_value_spent: u64,
    ) {
        let wtx = self.get_or_create_tx(&txid, BlockHeight::from(height), unconfirmed, timestamp);
        wtx.total_transparent_value_spent = total_transparent_value_spent;

        self.check_notes_mark_change(&txid);
    }

    pub fn mark_txid_utxo_spent(
        &mut self,
        spent_txid: TxId,
        output_num: u32,
        source_txid: TxId,
        source_height: u32,
    ) -> u64 {
        // Find the UTXO
        let value = if let Some(utxo_wtx) = self.current.get_mut(&spent_txid) {
            if let Some(spent_utxo) = utxo_wtx
                .utxos
                .iter_mut()
                .find(|u| u.txid == spent_txid && u.output_index == output_num as u64)
            {
                // Mark this one as spent
                spent_utxo.spent = Some(source_txid.clone());
                spent_utxo.spent_at_height = Some(source_height as i32);
                spent_utxo.unconfirmed_spent = None;

                spent_utxo.value
            } else {
                error!("Couldn't find UTXO that was spent");
                0
            }
        } else {
            error!("Couldn't find TxID that was spent!");
            0
        };

        // Return the value of the note that was spent.
        value
    }

    pub fn add_new_taddr_output(
        &mut self,
        txid: TxId,
        taddr: String,
        height: u32,
        unconfirmed: bool,
        timestamp: u64,
        vout: &TxOut,
        output_num: u32,
    ) {
        // Read or create the current TxId
        let wtx = self.get_or_create_tx(&txid, BlockHeight::from(height), unconfirmed, timestamp);

        // Add this UTXO if it doesn't already exist
        if let Some(utxo) = wtx
            .utxos
            .iter_mut()
            .find(|utxo| utxo.txid == txid && utxo.output_index == output_num as u64)
        {
            // If it already exists, it is likely an mempool tx, so update the height
            utxo.height = height as i32
        } else {
            wtx.utxos.push(Utxo {
                address: taddr,
                txid: txid.clone(),
                output_index: output_num as u64,
                script: vout.script_pubkey.0.clone(),
                value: vout.value.into(),
                height: height as i32,
                spent_at_height: None,
                spent: None,
                unconfirmed_spent: None,
            });
        }
    }

    pub fn add_pending_note(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        timestamp: u64,
        note: Note,
        to: PaymentAddress,
        ivk: &SaplingIvk,
    ) {
        // Check if this is a change note
        let is_change = self.total_funds_spent_in(&txid) > 0;

        let wtx = self.get_or_create_tx(&txid, BlockHeight::from(height), true, timestamp);
        // Update the block height, in case this was a mempool or unconfirmed tx.
        wtx.block = height;

        match wtx.notes.iter_mut().find(|n| n.note == note) {
            None => {
                let nd = SaplingNoteData {
                    ivk: SaplingIvk(ivk.0.clone()),
                    diversifier: *to.diversifier(),
                    note,
                    witnesses: WitnessCache::empty(),
                    nullifier: Nullifier { 0: [0u8; 32] },
                    spent: None,
                    unconfirmed_spent: None,
                    memo: None,
                    is_change,
                    have_spending_key: false,
                };

                wtx.notes.push(nd);
            }
            Some(_) => {}
        }
    }

    pub fn add_new_note(
        &mut self,
        txid: TxId,
        height: BlockHeight,
        unconfirmed: bool,
        timestamp: u64,
        note: Note,
        to: PaymentAddress,
        ivk: &SaplingIvk,
        nullifier: Nullifier,
        have_spending_key: bool,
        witness: IncrementalWitness<Node>,
    ) {
        // Check if this is a change note
        let is_change = self.total_funds_spent_in(&txid) > 0;

        let wtx = self.get_or_create_tx(&txid, BlockHeight::from(height), unconfirmed, timestamp);
        // Update the block height, in case this was a mempool or unconfirmed tx.
        wtx.block = height;

        let witnesses = if have_spending_key {
            WitnessCache::new(vec![witness], u64::from(height))
        } else {
            WitnessCache::empty()
        };

        match wtx.notes.iter_mut().find(|n| n.nullifier == nullifier) {
            None => {
                let nd = SaplingNoteData {
                    ivk: SaplingIvk(ivk.0.clone()),
                    diversifier: *to.diversifier(),
                    note,
                    witnesses,
                    nullifier,
                    spent: None,
                    unconfirmed_spent: None,
                    memo: None,
                    is_change,
                    have_spending_key,
                };

                wtx.notes.push(nd);

                // Also remove any pending notes.
                wtx.notes.retain(|n| n.nullifier.0 != [0u8; 32]);
            }
            Some(n) => {
                // If this note already exists, then just reset the witnesses, because we'll start scanning the witnesses
                // again after this.
                // This is likely to happen if the previous wallet wasn't synced properly or was aborted in the middle of a sync,
                // and has some dangling witnesses
                n.witnesses = witnesses;
            }
        }
    }

    // Update the memo for a note if it already exists. If the note doesn't exist, then nothing happens.
    pub fn add_memo_to_note(&mut self, txid: &TxId, note: Note, memo: Memo) {
        self.current.get_mut(txid).map(|wtx| {
            wtx.notes
                .iter_mut()
                .find(|n| n.note == note)
                .map(|n| n.memo = Some(memo));
        });
    }

    pub fn add_outgoing_metadata(&mut self, txid: &TxId, outgoing_metadata: Vec<OutgoingTxMetadata>) {
        if let Some(wtx) = self.current.get_mut(txid) {
            // This is n^2 search, but this is likely very small struct, limited by the protocol, so...
            let new_omd: Vec<_> = outgoing_metadata
                .into_iter()
                .filter(|om| wtx.outgoing_metadata.iter().find(|o| **o == *om).is_none())
                .collect();

            wtx.outgoing_metadata.extend(new_omd);
        } else {
            error!("TxId {} should be present while adding metadata, but wasn't", txid);
        }
    }
}
