use std::fs;
use std::path::Path;

use ff::{Field, PrimeField};
use group::GroupEncoding;
use json::JsonValue;
use rand::rngs::OsRng;
use rand::RngCore;
use tempdir::TempDir;
use tokio::runtime::Runtime;
use tonic::transport::Channel;
use tonic::Request;

use zcash_client_backend::address::RecipientAddress;
use zcash_client_backend::encoding::{
    encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
};
use zcash_note_encryption::{EphemeralKeyBytes, NoteEncryption};
use zcash_primitives::consensus::{BlockHeight, BranchId, TEST_NETWORK};
use zcash_primitives::memo::Memo;
use zcash_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use zcash_primitives::sapling::note_encryption::SaplingDomain;
use zcash_primitives::sapling::redjubjub::Signature;
use zcash_primitives::transaction::components::{sapling, Amount};

use zcash_primitives::sapling::Node;
use zcash_primitives::sapling::{Note, Rseed, ValueCommitment};
use zcash_primitives::transaction::components::amount::DEFAULT_FEE;
use zcash_primitives::transaction::components::{OutputDescription, GROTH_PROOF_SIZE};
use zcash_primitives::transaction::{Transaction, TransactionData};
use zcash_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};

use crate::blaze::fetch_full_tx::FetchFullTxns;
use crate::blaze::test_utils::{FakeCompactBlockList, FakeTransaction};
use crate::compact_formats::compact_tx_streamer_client::CompactTxStreamerClient;

use crate::compact_formats::{CompactSaplingOutput, CompactTx, Empty};
use crate::lightclient::faketx::new_transactiondata;
use crate::lightclient::test_server::{create_test_server, mine_pending_blocks, mine_random_blocks};
use crate::lightclient::LightClient;
use crate::lightwallet::data::WalletTx;

use super::checkpoints;
use super::lightclient_config::{LightClientConfig, UnitTestNetwork};

#[test]
fn new_wallet_from_phrase() {
    let temp_dir = TempDir::new("test").unwrap();
    let data_dir = temp_dir
        .into_path()
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let config = LightClientConfig::create_unconnected(UnitTestNetwork, Some(data_dir));
    let lc = LightClient::new_from_phrase(TEST_SEED.to_string(), &config, 0, false).unwrap();

    // The first t address and z address should be derived
    Runtime::new().unwrap().block_on(async move {
        let addresses = lc.do_address().await;

        assert_eq!(
            "zs1q6xk3q783t5k92kjqt2rkuuww8pdw2euzy5rk6jytw97enx8fhpazdv3th4xe7vsk6e9sfpawfg".to_string(),
            addresses["z_addresses"][0]
        );
        assert_eq!(
            "t1eQ63fwkQ4n4Eo5uCrPGaAV8FWB2tmx7ui".to_string(),
            addresses["t_addresses"][0]
        );
        println!("z {}", lc.do_export(None).await.unwrap().pretty(2));
    });
}

#[test]
fn new_wallet_from_sk() {
    let temp_dir = TempDir::new("test").unwrap();
    let data_dir = temp_dir
        .into_path()
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let config = LightClientConfig::create_unconnected(UnitTestNetwork, Some(data_dir));
    let sk = "secret-extended-key-main1qvpa0qr8qqqqpqxn4l054nzxpxzp3a8r2djc7sekdek5upce8mc2j2z0arzps4zv940qeg706hd0wq6g5snzvhp332y6vhwyukdn8dhekmmsk7fzvzkqm6ypc99uy63tpesqwxhpre78v06cx8k5xpp9mrhtgqs5dvp68cqx2yrvthflmm2ynl8c0506dekul0f6jkcdmh0292lpphrksyc5z3pxwws97zd5els3l2mjt2s7hntap27mlmt6w0drtfmz36vz8pgu7ec0twfrq";
    let lc = LightClient::new_from_phrase(sk.to_string(), &config, 0, false).unwrap();
    Runtime::new().unwrap().block_on(async move {
        let addresses = lc.do_address().await;
        assert_eq!(addresses["z_addresses"].len(), 1);
        assert_eq!(addresses["t_addresses"].len(), 1);
        assert_eq!(
            "zs1q6xk3q783t5k92kjqt2rkuuww8pdw2euzy5rk6jytw97enx8fhpazdv3th4xe7vsk6e9sfpawfg".to_string(),
            addresses["z_addresses"][0]
        );

        // New address should be derived from the seed
        lc.do_new_address("z").await.unwrap();

        let addresses = lc.do_address().await;
        assert_eq!(addresses["z_addresses"].len(), 2);
        assert_ne!(
            "zs1q6xk3q783t5k92kjqt2rkuuww8pdw2euzy5rk6jytw97enx8fhpazdv3th4xe7vsk6e9sfpawfg".to_string(),
            addresses["z_addresses"][1]
        );
    });
}

#[test]
fn new_wallet_from_vk() {
    let temp_dir = TempDir::new("test").unwrap();
    let data_dir = temp_dir
        .into_path()
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let config = LightClientConfig::create_unconnected(UnitTestNetwork, Some(data_dir));
    let vk = "zxviews1qvpa0qr8qqqqpqxn4l054nzxpxzp3a8r2djc7sekdek5upce8mc2j2z0arzps4zv9kdvg28gjzvxd47ant6jn4svln5psw3htx93cq93ahw4e7lptrtlq7he5r6p6rcm3s0z6l24ype84sgqfrmghu449htrjspfv6qg2zfx2yrvthflmm2ynl8c0506dekul0f6jkcdmh0292lpphrksyc5z3pxwws97zd5els3l2mjt2s7hntap27mlmt6w0drtfmz36vz8pgu7ecrxzsls";
    let lc = LightClient::new_from_phrase(vk.to_string(), &config, 0, false).unwrap();

    Runtime::new().unwrap().block_on(async move {
        let addresses = lc.do_address().await;
        assert_eq!(addresses["z_addresses"].len(), 1);
        assert_eq!(addresses["t_addresses"].len(), 1);
        assert_eq!(
            "zs1q6xk3q783t5k92kjqt2rkuuww8pdw2euzy5rk6jytw97enx8fhpazdv3th4xe7vsk6e9sfpawfg".to_string(),
            addresses["z_addresses"][0]
        );

        // New address should be derived from the seed
        lc.do_new_address("z").await.unwrap();

        let addresses = lc.do_address().await;
        assert_eq!(addresses["z_addresses"].len(), 2);
        assert_ne!(
            "zs1q6xk3q783t5k92kjqt2rkuuww8pdw2euzy5rk6jytw97enx8fhpazdv3th4xe7vsk6e9sfpawfg".to_string(),
            addresses["z_addresses"][1]
        );
    });
}

#[tokio::test]
async fn basic_no_wallet_txns() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let uri = config.server.clone();
    let mut client = CompactTxStreamerClient::new(Channel::builder(uri).connect().await.unwrap());

    let r = client
        .get_lightd_info(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner();
    println!("{:?}", r);

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_incoming_z_outgoing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    assert_eq!(lc.wallet.last_scanned_height().await, 11);

    println!("{}", lc.do_list_notes(true).await.pretty(2));

    // 3. Check the balance is correct, and we recieved the incoming tx from outside
    let b = lc.do_balance().await;
    assert_eq!(b["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["unverified_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["spendable_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(
        b["z_addresses"][0]["address"],
        lc.wallet.keys().read().await.get_all_zaddresses()[0]
    );
    assert_eq!(b["z_addresses"][0]["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["unverified_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["spendable_zbalance"].as_u64().unwrap(), 0);

    let list = lc.do_list_transactions(false).await;
    if let JsonValue::Array(list) = list {
        assert_eq!(list.len(), 1);
        let jv = list[0].clone();

        assert_eq!(jv["txid"], tx.txid().to_string());
        assert_eq!(jv["amount"].as_u64().unwrap(), value);
        assert_eq!(jv["address"], lc.wallet.keys().read().await.get_all_zaddresses()[0]);
        assert_eq!(jv["block_height"].as_u64().unwrap(), 11);
    } else {
        panic!("Expecting an array");
    }

    // 4. Then add another 5 blocks, so the funds will become confirmed
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;
    let b = lc.do_balance().await;
    assert_eq!(b["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["unverified_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(b["spendable_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["spendable_zbalance"].as_u64().unwrap(), value);
    assert_eq!(b["z_addresses"][0]["unverified_zbalance"].as_u64().unwrap(), 0);

    // 5. Send z-to-z tx to external z address with a memo
    let sent_value = 2000;
    let outgoing_memo = "Outgoing Memo".to_string();

    let sent_txid = lc
        .test_do_send(vec![(EXT_ZADDR, sent_value, Some(outgoing_memo.clone()))])
        .await
        .unwrap();

    // 6. Check the unconfirmed txn is present
    // 6.1 Check notes

    let notes = lc.do_list_notes(true).await;
    // Has a new (unconfirmed) unspent note (the change)
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(notes["unspent_notes"][0]["unconfirmed"].as_bool().unwrap(), true);

    assert_eq!(notes["spent_notes"].len(), 0);
    assert_eq!(notes["pending_notes"].len(), 1);
    assert_eq!(notes["pending_notes"][0]["created_in_txid"], tx.txid().to_string());
    assert_eq!(notes["pending_notes"][0]["unconfirmed_spent"], sent_txid);
    assert_eq!(notes["pending_notes"][0]["spent"].is_null(), true);
    assert_eq!(notes["pending_notes"][0]["spent_at_height"].is_null(), true);

    // Check txn list
    let list = lc.do_list_transactions(false).await;

    assert_eq!(list.len(), 2);
    let jv = list.members().find(|jv| jv["txid"] == sent_txid).unwrap();

    assert_eq!(jv["txid"], sent_txid);
    assert_eq!(
        jv["amount"].as_i64().unwrap(),
        -(sent_value as i64 + i64::from(DEFAULT_FEE))
    );
    assert_eq!(jv["unconfirmed"].as_bool().unwrap(), true);
    assert_eq!(jv["block_height"].as_u64().unwrap(), 17);

    assert_eq!(jv["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(jv["outgoing_metadata"][0]["memo"], outgoing_memo);
    assert_eq!(jv["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // 7. Mine the sent transaction
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let list = lc.do_list_transactions(false).await;

    assert_eq!(list.len(), 2);
    let jv = list.members().find(|jv| jv["txid"] == sent_txid).unwrap();

    assert_eq!(jv.contains("unconfirmed"), false);
    assert_eq!(jv["block_height"].as_u64().unwrap(), 17);

    // 8. Check the notes to see that we have one spent note and one unspent note (change)
    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 17);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        value - sent_value - u64::from(DEFAULT_FEE)
    );
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(notes["unspent_notes"][0]["spendable"].as_bool().unwrap(), false); // Not yet spendable

    assert_eq!(notes["spent_notes"].len(), 1);
    assert_eq!(notes["spent_notes"][0]["created_in_block"].as_u64().unwrap(), 11);
    assert_eq!(notes["spent_notes"][0]["value"].as_u64().unwrap(), value);
    assert_eq!(notes["spent_notes"][0]["is_change"].as_bool().unwrap(), false);
    assert_eq!(notes["spent_notes"][0]["spendable"].as_bool().unwrap(), false); // Already spent
    assert_eq!(notes["spent_notes"][0]["spent"], sent_txid);
    assert_eq!(notes["spent_notes"][0]["spent_at_height"].as_u64().unwrap(), 17);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn multiple_incoming_same_tx() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Construct the Fake tx.
    let to = extfvk1.default_address().1;

    // Create fake note for the account
    let mut ctx = CompactTx::default();
    let mut td = new_transactiondata();

    // Add 4 outputs
    for i in 0..4 {
        let mut rng = OsRng;
        let value = value + i;

        let mut rseed_bytes = [0u8; 32];
        rng.fill_bytes(&mut rseed_bytes);

        let note = Note {
            g_d: to.diversifier().g_d().unwrap(),
            pk_d: to.pk_d().clone(),
            value,
            rseed: Rseed::AfterZip212(rseed_bytes),
        };

        let encryptor = NoteEncryption::<SaplingDomain<zcash_primitives::consensus::Network>>::new(
            None,
            note.clone(),
            to.clone(),
            Memo::default().into(),
        );

        let mut rng = OsRng;
        let rcv = jubjub::Fr::random(&mut rng);
        let cv = ValueCommitment {
            value,
            randomness: rcv.clone(),
        };

        let cmu = note.cmu();
        let od = OutputDescription {
            cv: cv.commitment().into(),
            cmu: note.cmu(),
            ephemeral_key: EphemeralKeyBytes(encryptor.epk().to_bytes()),
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv.commitment().into(), &cmu, &mut rng),
            zkproof: [0; GROTH_PROOF_SIZE],
        };

        let mut cmu = vec![];
        cmu.extend_from_slice(&note.cmu().to_repr());
        let mut epk = vec![];
        epk.extend_from_slice(&encryptor.epk().to_bytes());
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cout = CompactSaplingOutput::default();
        cout.cmu = cmu;
        cout.epk = epk;
        cout.ciphertext = enc_ciphertext[..52].to_vec();
        ctx.outputs.push(cout);

        let mut sapling_bundle = if td.sapling_bundle().is_some() {
            td.sapling_bundle().unwrap().clone()
        } else {
            sapling::Bundle {
                shielded_spends: vec![],
                shielded_outputs: vec![],
                value_balance: Amount::zero(),
                authorization: sapling::Authorized {
                    binding_sig: Signature::read(&vec![0u8; 64][..]).expect("Signature error"),
                },
            }
        };

        sapling_bundle.shielded_outputs.push(od);

        td = TransactionData::from_parts(
            td.version(),
            td.consensus_branch_id(),
            td.lock_time(),
            td.expiry_height(),
            td.transparent_bundle().cloned(),
            td.sprout_bundle().cloned(),
            Some(sapling_bundle),
            td.orchard_bundle().cloned(),
        );
    }

    // td.binding_sig = Signature::read(&vec![0u8; 64][..]).ok();
    let tx = td.freeze().unwrap();
    let txid = tx.txid().to_string();
    ctx.hash = tx.txid().as_ref().to_vec();

    // Add and mine the block
    fcbl.txns.push((tx, fcbl.next_height, vec![]));
    fcbl.add_empty_block().add_txs(vec![ctx]);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 11);

    // 2. Check the notes - that we recieved 4 notes
    let notes = lc.do_list_notes(true).await;
    let txns = lc.do_list_transactions(false).await;

    if let JsonValue::Array(mut unspent_notes) = notes["unspent_notes"].clone() {
        unspent_notes.sort_by_cached_key(|j| j["value"].as_u64().unwrap());

        for i in 0..4 {
            assert_eq!(unspent_notes[i]["created_in_block"].as_u64().unwrap(), 11);
            assert_eq!(unspent_notes[i]["value"].as_u64().unwrap(), value + i as u64);
            assert_eq!(unspent_notes[i]["is_change"].as_bool().unwrap(), false);
            assert_eq!(
                unspent_notes[i]["address"],
                lc.wallet.keys().read().await.get_all_zaddresses()[0]
            );
        }
    } else {
        panic!("unspent notes not found");
    }

    if let JsonValue::Array(mut sorted_txns) = txns.clone() {
        sorted_txns.sort_by_cached_key(|t| t["amount"].as_u64().unwrap());

        for i in 0..4 {
            assert_eq!(sorted_txns[i]["txid"], txid);
            assert_eq!(sorted_txns[i]["block_height"].as_u64().unwrap(), 11);
            assert_eq!(
                sorted_txns[i]["address"],
                lc.wallet.keys().read().await.get_all_zaddresses()[0]
            );
            assert_eq!(sorted_txns[i]["amount"].as_u64().unwrap(), value + i as u64);
        }
    } else {
        panic!("txns is not array");
    }

    // 3. Send a big tx, so all the value is spent
    let sent_value = value * 3 + u64::from(DEFAULT_FEE);
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await; // make the funds spentable
    let sent_txid = lc.test_do_send(vec![(EXT_ZADDR, sent_value, None)]).await.unwrap();

    // 4. Mine the sent transaction
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 5. Check the notes - that we spent all 4 notes
    let notes = lc.do_list_notes(true).await;
    let txns = lc.do_list_transactions(false).await;
    for i in 0..4 {
        assert_eq!(notes["spent_notes"][i]["spent"], sent_txid);
        assert_eq!(notes["spent_notes"][i]["spent_at_height"].as_u64().unwrap(), 17);
    }
    assert_eq!(txns[4]["txid"], sent_txid);
    assert_eq!(txns[4]["block_height"], 17);
    assert_eq!(
        txns[4]["amount"].as_i64().unwrap(),
        -(sent_value as i64) - i64::from(DEFAULT_FEE)
    );
    assert_eq!(txns[4]["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(txns[4]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);
    assert_eq!(txns[4]["outgoing_metadata"][0]["memo"].is_null(), true);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_incoming_multiz_outgoing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (_tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. send a txn to multiple addresses
    let tos = vec![
        (EXT_ZADDR, 1, Some("ext1-1".to_string())),
        (EXT_ZADDR, 2, Some("ext1-2".to_string())),
        (EXT_ZADDR2, 20, Some("ext2-20".to_string())),
    ];
    let sent_txid = lc.test_do_send(tos.clone()).await.unwrap();
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Check the outgoing txn list
    let list = lc.do_list_transactions(false).await;

    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 17);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(
        list[1]["amount"].as_i64().unwrap(),
        -i64::from(DEFAULT_FEE) - (tos.iter().map(|(_, a, _)| *a).sum::<u64>() as i64)
    );

    for (addr, amt, memo) in &tos {
        // Find the correct value, since the outgoing metadata can be shuffled
        let jv = list[1]["outgoing_metadata"]
            .members()
            .find(|j| j["value"].as_u64().unwrap() == *amt)
            .unwrap();
        assert_eq!(jv["memo"], *memo.as_ref().unwrap());
        assert_eq!(jv["address"], addr.to_string());
    }

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_to_z_scan_together() {
    // Create an incoming tx, and then send that tx, and scan everything together, to make sure it works.
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Start with 10 blocks that are unmined
    fcbl.add_blocks(10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (tx, _height, note) = fcbl.add_tx_paying(&extfvk1, value);

    // 3. Calculate witness so we can get the nullifier without it getting mined
    let tree = fcbl
        .blocks
        .iter()
        .fold(CommitmentTree::<Node>::empty(), |mut tree, fcb| {
            for tx in &fcb.block.vtx {
                for co in &tx.outputs {
                    tree.append(Node::new(co.cmu().unwrap().into())).unwrap();
                }
            }

            tree
        });
    let witness = IncrementalWitness::from_tree(&tree);
    let nf = note.nf(&extfvk1.fvk.vk.nk, witness.position() as u64);

    let pa = if let Some(RecipientAddress::Shielded(pa)) = RecipientAddress::decode(&config.get_params(), EXT_ZADDR) {
        pa
    } else {
        panic!("Couldn't parse address")
    };
    let spent_value = 250;
    let spent_tx = fcbl.add_tx_spending(&nf, spent_value, &extfvk1.fvk.ovk, &pa);

    // 4. Mine the blocks and sync the lightwallet
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 5. Check the tx list to make sure we got all txns
    let list = lc.do_list_transactions(false).await;

    assert_eq!(list[0]["block_height"].as_u64().unwrap(), 11);
    assert_eq!(list[0]["txid"], tx.txid().to_string());

    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], spent_tx.txid().to_string());
    assert_eq!(list[1]["amount"].as_i64().unwrap(), -(value as i64));
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), spent_value);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn z_incoming_viewkey() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), 0);

    // 2. Create a new Viewkey and import it
    let iextsk = ExtendedSpendingKey::master(&[1u8; 32]);
    let iextfvk = ExtendedFullViewingKey::from(&iextsk);
    let iaddr = encode_payment_address(config.hrp_sapling_address(), &iextfvk.default_address().1);
    let addrs = lc
        .do_import_vk(
            encode_extended_full_viewing_key(config.hrp_sapling_viewing_key(), &iextfvk),
            1,
        )
        .await
        .unwrap();
    // Make sure address is correct
    assert_eq!(addrs[0], iaddr);

    let value = 100_000;
    let (tx, _height, _) = fcbl.add_tx_paying(&iextfvk, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Test that we have the txn
    let list = lc.do_list_transactions(false).await;
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(list[0]["txid"], tx.txid().to_string());
    assert_eq!(list[0]["amount"].as_u64().unwrap(), value);
    assert_eq!(list[0]["address"], iaddr);

    // 4. Also do a rescan, just for fun
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    lc.do_rescan().await.unwrap();
    // Test all the same values
    let list = lc.do_list_transactions(false).await;
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(list[0]["txid"], tx.txid().to_string());
    assert_eq!(list[0]["amount"].as_u64().unwrap(), value);
    assert_eq!(list[0]["address"], iaddr);

    // 5. Import the corresponding spending key.
    let sk_addr = lc
        .do_import_sk(
            encode_extended_spending_key(config.hrp_sapling_private_key(), &iextsk),
            1,
        )
        .await
        .unwrap();

    assert_eq!(sk_addr[0], iaddr);
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), 0);

    // 6. Rescan to make the funds spendable (i.e., update witnesses)
    lc.do_rescan().await.unwrap();
    assert_eq!(lc.do_balance().await["zbalance"].as_u64().unwrap(), value);
    assert_eq!(lc.do_balance().await["spendable_zbalance"].as_u64().unwrap(), value);

    // 7. Spend funds from the now-imported private key.
    let sent_value = 3000;
    let outgoing_memo = "Outgoing Memo".to_string();

    let sent_txid = lc
        .test_do_send(vec![(EXT_ZADDR, sent_value, Some(outgoing_memo.clone()))])
        .await
        .unwrap();
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 8. Make sure tx is present
    let list = lc.do_list_transactions(false).await;
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(
        list[1]["amount"].as_i64().unwrap(),
        -((sent_value + u64::from(DEFAULT_FEE)) as i64)
    );
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_ZADDR.to_string());
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn t_incoming_t_outgoing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;

    // 2. Get an incoming tx to a t address
    let sk = lc.wallet.keys().read().await.tkeys[0].clone();
    let pk = sk.pubkey().unwrap();
    let taddr = sk.address;
    let value = 100_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), value);
    let (tx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 3. Test the list
    let list = lc.do_list_transactions(false).await;
    println!("{}", list.pretty(2));
    assert_eq!(list[0]["block_height"].as_u64().unwrap(), 11);
    assert_eq!(list[0]["txid"], tx.txid().to_string());
    assert_eq!(list[0]["address"], taddr);
    assert_eq!(list[0]["amount"].as_u64().unwrap(), value);

    // 4. We can spend the funds immediately, since this is a taddr
    let sent_value = 20_000;
    let sent_txid = lc.test_do_send(vec![(EXT_TADDR, sent_value, None)]).await.unwrap();

    // 5. Test the unconfirmed send.
    let list = lc.do_list_transactions(false).await;
    println!("{}", list.pretty(2));
    println!("{}", lc.do_list_notes(true).await.pretty(2));
    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(
        list[1]["amount"].as_i64().unwrap(),
        -(sent_value as i64 + i64::from(DEFAULT_FEE))
    );
    assert_eq!(list[1]["unconfirmed"].as_bool().unwrap(), true);
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_TADDR);
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // 7. Mine the sent transaction
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["spent_utxos"][0]["created_in_block"].as_u64().unwrap(), 11);
    assert_eq!(notes["spent_utxos"][0]["spent_at_height"].as_u64().unwrap(), 12);
    assert_eq!(notes["spent_utxos"][0]["spent"], sent_txid);

    // Change shielded note
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 12);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        value - sent_value - u64::from(DEFAULT_FEE)
    );

    let list = lc.do_list_transactions(false).await;

    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(list[1]["unconfirmed"].as_bool().unwrap(), false);
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_TADDR);
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    // Make sure everything is fine even after the rescan

    lc.do_rescan().await.unwrap();

    let list = lc.do_list_transactions(false).await;
    assert_eq!(list[1]["block_height"].as_u64().unwrap(), 12);
    assert_eq!(list[1]["txid"], sent_txid);
    assert_eq!(list[1]["unconfirmed"].as_bool().unwrap(), false);
    assert_eq!(list[1]["outgoing_metadata"][0]["address"], EXT_TADDR);
    assert_eq!(list[1]["outgoing_metadata"][0]["value"].as_u64().unwrap(), sent_value);

    let notes = lc.do_list_notes(true).await;
    // Change shielded note
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 12);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        value - sent_value - u64::from(DEFAULT_FEE)
    );

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn mixed_txn() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let zvalue = 100_000;
    let (_ztx, _height, _) = fcbl.add_tx_paying(&extfvk1, zvalue);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Send an incoming t-address txn
    let sk = lc.wallet.keys().read().await.tkeys[0].clone();
    let pk = sk.pubkey().unwrap();
    let taddr = sk.address;
    let tvalue = 200_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), tvalue);
    let (_ttx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Send a tx to both external t-addr and external z addr and mine it
    let sent_zvalue = 80_000;
    let sent_tvalue = 140_000;
    let sent_zmemo = "Ext z".to_string();
    let tos = vec![
        (EXT_ZADDR, sent_zvalue, Some(sent_zmemo.clone())),
        (EXT_TADDR, sent_tvalue, None),
    ];
    lc.test_do_send(tos).await.unwrap();

    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let notes = lc.do_list_notes(true).await;
    let list = lc.do_list_transactions(false).await;

    // 5. Check everything
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_block"].as_u64().unwrap(), 18);
    assert_eq!(notes["unspent_notes"][0]["is_change"].as_bool().unwrap(), true);
    assert_eq!(
        notes["unspent_notes"][0]["value"].as_u64().unwrap(),
        tvalue + zvalue - sent_tvalue - sent_zvalue - u64::from(DEFAULT_FEE)
    );

    assert_eq!(notes["spent_notes"].len(), 1);
    assert_eq!(
        notes["spent_notes"][0]["spent"],
        notes["unspent_notes"][0]["created_in_txid"]
    );

    assert_eq!(notes["pending_notes"].len(), 0);
    assert_eq!(notes["utxos"].len(), 0);
    assert_eq!(notes["pending_utxos"].len(), 0);

    assert_eq!(notes["spent_utxos"].len(), 1);
    assert_eq!(
        notes["spent_utxos"][0]["spent"],
        notes["unspent_notes"][0]["created_in_txid"]
    );

    assert_eq!(list.len(), 3);
    assert_eq!(list[2]["block_height"].as_u64().unwrap(), 18);
    assert_eq!(
        list[2]["amount"].as_i64().unwrap(),
        0 - (sent_tvalue + sent_zvalue + u64::from(DEFAULT_FEE)) as i64
    );
    assert_eq!(list[2]["txid"], notes["unspent_notes"][0]["created_in_txid"]);
    assert_eq!(
        list[2]["outgoing_metadata"]
            .members()
            .find(|j| j["address"].to_string() == EXT_ZADDR && j["value"].as_u64().unwrap() == sent_zvalue)
            .unwrap()["memo"]
            .to_string(),
        sent_zmemo
    );
    assert_eq!(
        list[2]["outgoing_metadata"]
            .members()
            .find(|j| j["address"].to_string() == EXT_TADDR)
            .unwrap()["value"]
            .as_u64()
            .unwrap(),
        sent_tvalue
    );

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn aborted_resync() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let zvalue = 100_000;
    let (_ztx, _height, _) = fcbl.add_tx_paying(&extfvk1, zvalue);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Send an incoming t-address txn
    let sk = lc.wallet.keys().read().await.tkeys[0].clone();
    let pk = sk.pubkey().unwrap();
    let taddr = sk.address;
    let tvalue = 200_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), tvalue);
    let (_ttx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Send a tx to both external t-addr and external z addr and mine it
    let sent_zvalue = 80_000;
    let sent_tvalue = 140_000;
    let sent_zmemo = "Ext z".to_string();
    let tos = vec![
        (EXT_ZADDR, sent_zvalue, Some(sent_zmemo.clone())),
        (EXT_TADDR, sent_tvalue, None),
    ];
    let sent_txid = lc.test_do_send(tos).await.unwrap();

    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    let notes_before = lc.do_list_notes(true).await;
    let list_before = lc.do_list_transactions(false).await;
    let witness_before = lc
        .wallet
        .txns
        .read()
        .await
        .current
        .get(&WalletTx::new_txid(
            &hex::decode(sent_txid.clone()).unwrap().into_iter().rev().collect(),
        ))
        .unwrap()
        .s_notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();

    // 5. Now, we'll manually remove some of the blocks in the wallet, pretending that the sync was aborted in the middle.
    // We'll remove the top 20 blocks, so now the wallet only has the first 3 blocks
    lc.wallet.blocks.write().await.drain(0..20);
    assert_eq!(lc.wallet.last_scanned_height().await, 3);

    // 6. Do a sync again
    lc.do_sync(true).await.unwrap();
    assert_eq!(lc.wallet.last_scanned_height().await, 23);

    // 7. Should be exactly the same
    let notes_after = lc.do_list_notes(true).await;
    let list_after = lc.do_list_transactions(false).await;
    let witness_after = lc
        .wallet
        .txns
        .read()
        .await
        .current
        .get(&WalletTx::new_txid(
            &hex::decode(sent_txid).unwrap().into_iter().rev().collect(),
        ))
        .unwrap()
        .s_notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();

    assert_eq!(notes_before, notes_after);
    assert_eq!(list_before, list_after);
    assert_eq!(witness_before.top_height, witness_after.top_height);
    assert_eq!(witness_before.len(), witness_after.len());
    for i in 0..witness_before.len() {
        let mut before_bytes = vec![];
        witness_before.get(i).unwrap().write(&mut before_bytes).unwrap();

        let mut after_bytes = vec![];
        witness_after.get(i).unwrap().write(&mut after_bytes).unwrap();

        assert_eq!(hex::encode(before_bytes), hex::encode(after_bytes));
    }

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn no_change() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    lc.init_logging().unwrap();

    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let zvalue = 100_000;
    let (_ztx, _height, _) = fcbl.add_tx_paying(&extfvk1, zvalue);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    let notes = lc.do_list_notes(true).await;
    println!("{}", notes.pretty(2));

    // 3. Send an incoming t-address txn
    let sk = lc.wallet.keys().read().await.tkeys[0].clone();
    let pk = sk.pubkey().unwrap();
    let taddr = sk.address;
    let tvalue = 200_000;

    let mut ftx = FakeTransaction::new();
    ftx.add_t_output(&pk, taddr.clone(), tvalue);
    let (_ttx, _) = fcbl.add_ftx(ftx);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // 4. Send a tx to both external t-addr and external z addr and mine it
    let sent_zvalue = tvalue + zvalue - u64::from(DEFAULT_FEE);
    let tos = vec![(EXT_ZADDR, sent_zvalue, None)];
    let sent_txid = lc.test_do_send(tos).await.unwrap();

    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let notes = lc.do_list_notes(true).await;
    assert_eq!(notes["unspent_notes"].len(), 0);
    assert_eq!(notes["pending_notes"].len(), 0);
    assert_eq!(notes["utxos"].len(), 0);
    assert_eq!(notes["pending_utxos"].len(), 0);

    assert_eq!(notes["spent_notes"].len(), 1);
    assert_eq!(notes["spent_utxos"].len(), 1);
    assert_eq!(notes["spent_notes"][0]["spent"], sent_txid);
    assert_eq!(notes["spent_utxos"][0]["spent"], sent_txid);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn recover_at_checkpoint() {
    // 1. Wait for test server to start
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;
    ready_rx.await.unwrap();

    // Get checkpoint at 1220000
    let (ckpt_height, hash, tree) = checkpoints::get_all_main_checkpoints()
        .into_iter()
        .find(|(h, _, _)| *h == 1220000)
        .unwrap();
    // Manually insert the checkpoint at -100, so the test server can return it.
    data.write()
        .await
        .tree_states
        .push((ckpt_height, hash.to_string(), tree.to_string()));

    // 2. Mine 110 blocks after 1220000
    let mut fcbl = FakeCompactBlockList::new(0);
    fcbl.next_height = ckpt_height + 1;
    {
        let blk = fcbl.add_empty_block();
        blk.block.prev_hash = hex::decode(hash).unwrap().into_iter().rev().collect();
    }
    let cbs = fcbl.add_blocks(109).into_compact_blocks();
    data.write().await.add_blocks(cbs.clone());

    // 4. Test1: create a new lightclient, restoring at exactly the checkpoint
    let lc = LightClient::test_new(&config, Some(TEST_SEED.to_string()), ckpt_height)
        .await
        .unwrap();
    //lc.init_logging().unwrap();
    assert_eq!(
        json::parse(lc.do_info().await.as_str()).unwrap()["latest_block_height"]
            .as_u64()
            .unwrap(),
        ckpt_height + 110
    );

    lc.do_sync(true).await.unwrap();

    // Check the trees
    assert_eq!(
        lc.wallet.blocks.read().await.first().map(|b| b.clone()).unwrap().height,
        1220110
    );

    // 5: Test2: Create a new lightwallet, restoring at checkpoint + 100
    // First remove the old wallet
    fs::remove_file(Path::new(config.data_dir.as_ref().unwrap()).join("zecwallet-light-wallet.dat")).unwrap();
    let lc = LightClient::test_new(&config, Some(TEST_SEED.to_string()), ckpt_height + 100)
        .await
        .unwrap();

    assert_eq!(
        json::parse(lc.do_info().await.as_str()).unwrap()["latest_block_height"]
            .as_u64()
            .unwrap(),
        ckpt_height + 110
    );

    lc.do_sync(true).await.unwrap();

    // Check the trees
    assert_eq!(
        lc.wallet.blocks.read().await.first().map(|b| b.clone()).unwrap().height,
        1220110
    );
    // assert_eq!(
    //     tree_to_string(
    //         &lc.wallet
    //             .blocks
    //             .read()
    //             .await
    //             .first()
    //             .map(|b| b.clone())
    //             .unwrap()
    //             .tree()
    //             .unwrap()
    //     ),
    //     tree_to_string(&tree)
    // );

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn witness_clearing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    //lc.init_logging().unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;

    // 3. Send z-to-z tx to external z address with a memo
    let sent_value = 2000;
    let outgoing_memo = "Outgoing Memo".to_string();

    let _sent_txid = lc
        .test_do_send(vec![(EXT_ZADDR, sent_value, Some(outgoing_memo.clone()))])
        .await
        .unwrap();

    // Tx is not yet mined, so witnesses should still be there
    let witnesses = lc
        .wallet
        .txns()
        .read()
        .await
        .current
        .get(&tx.txid())
        .unwrap()
        .s_notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();
    assert_eq!(witnesses.len(), 6);

    // 4. Mine the sent transaction
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    // Tx is now mined, but witnesses should still be there because not 100 blocks yet (i.e., could get reorged)
    let witnesses = lc
        .wallet
        .txns()
        .read()
        .await
        .current
        .get(&tx.txid())
        .unwrap()
        .s_notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();
    assert_eq!(witnesses.len(), 6);

    // 5. Mine 50 blocks, witness should still be there
    mine_random_blocks(&mut fcbl, &data, &lc, 50).await;
    let witnesses = lc
        .wallet
        .txns()
        .read()
        .await
        .current
        .get(&tx.txid())
        .unwrap()
        .s_notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();
    assert_eq!(witnesses.len(), 6);

    // 5. Mine 100 blocks, witness should now disappear
    mine_random_blocks(&mut fcbl, &data, &lc, 100).await;
    let witnesses = lc
        .wallet
        .txns()
        .read()
        .await
        .current
        .get(&tx.txid())
        .unwrap()
        .s_notes
        .get(0)
        .unwrap()
        .witnesses
        .clone();
    assert_eq!(witnesses.len(), 0);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn mempool_clearing() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    //lc.init_logging().unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
    let orig_txid = tx.txid().to_string();
    mine_pending_blocks(&mut fcbl, &data, &lc).await;
    mine_random_blocks(&mut fcbl, &data, &lc, 5).await;
    assert_eq!(lc.do_last_txid().await["last_txid"], orig_txid);

    // 3. Send z-to-z tx to external z address with a memo
    let sent_value = 2000;
    let outgoing_memo = "Outgoing Memo".to_string();

    let sent_txid = lc
        .test_do_send(vec![(EXT_ZADDR, sent_value, Some(outgoing_memo.clone()))])
        .await
        .unwrap();

    // 4. The tx is not yet sent, it is just sitting in the test GRPC server, so remove it from there to make sure it doesn't get mined.
    assert_eq!(lc.do_last_txid().await["last_txid"], sent_txid);
    let mut sent_txns = data.write().await.sent_txns.drain(..).collect::<Vec<_>>();
    assert_eq!(sent_txns.len(), 1);
    let sent_tx = sent_txns.remove(0);

    // 5. At this point, the rawTx is already been parsed, but we'll parse it again just to make sure it doesn't create any duplicates.
    let notes_before = lc.do_list_notes(true).await;
    let txns_before = lc.do_list_transactions(false).await;

    let tx = Transaction::read(
        &sent_tx.data[..],
        BranchId::for_height(&TEST_NETWORK, BlockHeight::from_u32(sent_tx.height as u32)),
    )
    .unwrap();
    FetchFullTxns::scan_full_tx(
        config,
        tx,
        BlockHeight::from_u32(17),
        true,
        0,
        lc.wallet.keys(),
        lc.wallet.txns(),
        Some(140.5),
    )
    .await;

    let notes_after = lc.do_list_notes(true).await;
    let txns_after = lc.do_list_transactions(false).await;

    assert_eq!(notes_before.pretty(2), notes_after.pretty(2));
    assert_eq!(txns_before.pretty(2), txns_after.pretty(2));

    // 6. Mine 10 blocks, the unconfirmed tx should still be there.
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 26);

    let notes = lc.do_list_notes(true).await;
    let txns = lc.do_list_transactions(false).await;

    // There is 1 unspent note, which is the unconfirmed tx
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], sent_txid);
    assert_eq!(notes["unspent_notes"][0]["unconfirmed"].as_bool().unwrap(), true);
    assert_eq!(txns.len(), 2);

    // 7. Mine 100 blocks, so the mempool expires
    mine_random_blocks(&mut fcbl, &data, &lc, 100).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 126);

    let notes = lc.do_list_notes(true).await;
    let txns = lc.do_list_transactions(false).await;

    // There is now again 1 unspent note, but it is the original (confirmed) note.
    assert_eq!(notes["unspent_notes"].len(), 1);
    assert_eq!(notes["unspent_notes"][0]["created_in_txid"], orig_txid);
    assert_eq!(notes["unspent_notes"][0]["unconfirmed"].as_bool().unwrap(), false);
    assert_eq!(notes["pending_notes"].len(), 0);
    assert_eq!(txns.len(), 1);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

#[tokio::test]
async fn mempool_and_balance() {
    let (data, config, ready_rx, stop_tx, h1) = create_test_server(UnitTestNetwork).await;

    ready_rx.await.unwrap();

    let lc = LightClient::test_new(&config, None, 0).await.unwrap();
    let mut fcbl = FakeCompactBlockList::new(0);

    // 1. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    assert_eq!(lc.wallet.last_scanned_height().await, 10);

    // 2. Send an incoming tx to fill the wallet
    let extfvk1 = lc.wallet.keys().read().await.get_all_extfvks()[0].clone();
    let value = 100_000;
    let (_tx, _height, _) = fcbl.add_tx_paying(&extfvk1, value);
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let bal = lc.do_balance().await;
    assert_eq!(bal["zbalance"].as_u64().unwrap(), value);
    assert_eq!(bal["verified_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(bal["unverified_zbalance"].as_u64().unwrap(), value);

    // 3. Mine 10 blocks
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    let bal = lc.do_balance().await;
    assert_eq!(bal["zbalance"].as_u64().unwrap(), value);
    assert_eq!(bal["verified_zbalance"].as_u64().unwrap(), value);
    assert_eq!(bal["unverified_zbalance"].as_u64().unwrap(), 0);

    // 4. Spend the funds
    let sent_value = 2000;
    let outgoing_memo = "Outgoing Memo".to_string();

    let _sent_txid = lc
        .test_do_send(vec![(EXT_ZADDR, sent_value, Some(outgoing_memo.clone()))])
        .await
        .unwrap();

    let bal = lc.do_balance().await;

    // Even though the tx is not mined (in the mempool) the balances should be updated to reflect the spent funds
    let new_bal = value - (sent_value + u64::from(DEFAULT_FEE));
    assert_eq!(bal["zbalance"].as_u64().unwrap(), new_bal);
    assert_eq!(bal["verified_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(bal["unverified_zbalance"].as_u64().unwrap(), new_bal);

    // 5. Mine the pending block, but the balances should remain the same.
    fcbl.add_pending_sends(&data).await;
    mine_pending_blocks(&mut fcbl, &data, &lc).await;

    let bal = lc.do_balance().await;
    assert_eq!(bal["zbalance"].as_u64().unwrap(), new_bal);
    assert_eq!(bal["verified_zbalance"].as_u64().unwrap(), 0);
    assert_eq!(bal["unverified_zbalance"].as_u64().unwrap(), new_bal);

    // 6. Mine 10 more blocks, making the funds verified and spendable.
    mine_random_blocks(&mut fcbl, &data, &lc, 10).await;
    let bal = lc.do_balance().await;

    assert_eq!(bal["zbalance"].as_u64().unwrap(), new_bal);
    assert_eq!(bal["verified_zbalance"].as_u64().unwrap(), new_bal);
    assert_eq!(bal["unverified_zbalance"].as_u64().unwrap(), 0);

    // Shutdown everything cleanly
    stop_tx.send(true).unwrap();
    h1.await.unwrap();
}

pub const EXT_TADDR: &str = "t1NoS6ZgaUTpmjkge2cVpXGcySasdYDrXqh";
pub const EXT_ZADDR: &str = "zs1va5902apnzlhdu0pw9r9q7ca8s4vnsrp2alr6xndt69jnepn2v2qrj9vg3wfcnjyks5pg65g9dc";
pub const EXT_ZADDR2: &str = "zs1fxgluwznkzm52ux7jkf4st5znwzqay8zyz4cydnyegt2rh9uhr9458z0nk62fdsssx0cqhy6lyv";
pub const TEST_SEED: &str = "chimney better bulb horror rebuild whisper improve intact letter giraffe brave rib appear bulk aim burst snap salt hill sad merge tennis phrase raise";
