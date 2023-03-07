use crate::compact_formats::RawTransaction;

use crate::lightwallet::keys::Keystores;
use std::sync::Arc;
use tokio::{
    join,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot, RwLock,
    },
    task::JoinHandle,
};
use zcash_primitives::{consensus::{BranchId, BlockHeight}, consensus, transaction::Transaction};

pub struct FetchTaddrTxns<P> {
    keys: Arc<RwLock<Keystores<P>>>,
}

impl <P: consensus::Parameters + Send + Sync + 'static> FetchTaddrTxns<P> {
    pub fn new(keys: Arc<RwLock<Keystores<P>>>) -> Self {
        Self { keys }
    }

    pub async fn start(
        &self,
        start_height: u64,
        end_height: u64,
        taddr_fetcher: oneshot::Sender<(
            (Vec<String>, u64, u64),
            oneshot::Sender<Vec<UnboundedReceiver<Result<RawTransaction, String>>>>,
        )>,
        full_tx_scanner: UnboundedSender<(Transaction, BlockHeight)>,
        network: P,
    ) -> JoinHandle<Result<(), String>> {
        let keys = self.keys.clone();

        tokio::spawn(async move {
            let taddrs = keys.read().await.get_all_taddrs().await.collect::<Vec<_>>();

            // Fetch all transactions for all t-addresses in parallel, and process them in height order
            let req = (taddrs, start_height, end_height);
            let (res_tx, res_rx) = oneshot::channel::<Vec<UnboundedReceiver<Result<RawTransaction, String>>>>();
            taddr_fetcher.send((req, res_tx)).unwrap();

            let (ordered_rtx_tx, mut ordered_rtx_rx) = unbounded_channel();

            // Process every transparent address transaction, in order of height
            let h1: JoinHandle<Result<(), String>> = tokio::spawn(async move {
                // Now, read the transactions one-at-a-time, and then dispatch them in height order
                let mut txns_top = vec![];

                // Fill the array with the first transaction for every taddress
                let mut tx_rs = res_rx.await.unwrap();
                for tx_r in tx_rs.iter_mut() {
                    if let Some(Ok(txn)) = tx_r.recv().await {
                        txns_top.push(Some(txn));
                    } else {
                        txns_top.push(None);
                    }
                }

                // While at least one of them is still returning transactions
                while txns_top.iter().any(|t| t.is_some()) {
                    // Find the txn with the lowest height
                    let (_height, idx) =
                        txns_top
                            .iter()
                            .enumerate()
                            .fold((u64::MAX, 0), |(prev_height, prev_idx), (idx, t)| {
                                if let Some(txn) = t {
                                    if txn.height < prev_height {
                                        (txn.height, idx)
                                    } else {
                                        (prev_height, prev_idx)
                                    }
                                } else {
                                    (prev_height, prev_idx)
                                }
                            });

                    // Grab the tx at the index
                    let txn = txns_top[idx].as_ref().unwrap().clone();

                    // Replace the tx at the index that was just grabbed
                    if let Some(Ok(txn)) = tx_rs[idx].recv().await {
                        txns_top[idx] = Some(txn);
                    } else {
                        txns_top[idx] = None;
                    }

                    // Dispatch the result only if it is in out scan range
                    if txn.height <= start_height && txn.height >= end_height {
                        ordered_rtx_tx.send(txn).unwrap();
                    }
                }

                //info!("Finished fetching all t-addr txns");

                Ok(())
            });

            let h2: JoinHandle<Result<(), String>> = tokio::spawn(async move {
                let mut prev_height = 0;

                while let Some(rtx) = ordered_rtx_rx.recv().await {
                    // We should be reciving transactions strictly in height order, so make sure
                    if rtx.height < prev_height {
                        return Err(format!(
                            "Wrong height order while processing transparent transactions!. Was {}, prev={}",
                            rtx.height, prev_height
                        ));
                    }
                    prev_height = rtx.height;

                    let tx = Transaction::read(
                        &rtx.data[..],
                        BranchId::for_height(&network, BlockHeight::from_u32(rtx.height as u32)),
                    ).map_err(|e| format!("Error reading Tx: {}", e))?;
                    full_tx_scanner
                        .send((tx, BlockHeight::from_u32(rtx.height as u32)))
                        .unwrap();
                }

                //info!("Finished scanning all t-addr txns");
                Ok(())
            });

            let (r1, r2) = join!(h1, h2);
            r1.map_err(|e| format!("{}", e))??;
            r2.map_err(|e| format!("{}", e))??;

            Ok(())
        })
    }
}

#[cfg(test)]
mod test {
    use futures::future::join_all;
    use rand::Rng;
    use std::sync::Arc;
    use tokio::join;
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio::task::JoinError;

    use tokio::sync::oneshot::{self};
    use tokio::sync::RwLock;
    use tokio::{sync::mpsc::unbounded_channel, task::JoinHandle};
    use zcash_primitives::consensus::BlockHeight;
    use crate::compact_formats::RawTransaction;
    use crate::lightclient::lightclient_config::UnitTestNetwork;
    use zcash_primitives::transaction::{Transaction, TransactionData};

    use crate::lightwallet::keys::InMemoryKeys;
    use crate::lightwallet::wallettkey::WalletTKey;

    use super::FetchTaddrTxns;

    #[tokio::test]
    async fn out_of_order_txns() {
        // 5 t addresses
        let mut keys = InMemoryKeys::<P>::new_empty();
        let gened_taddrs: Vec<_> = (0..5).into_iter().map(|n| format!("taddr{}", n)).collect();
        keys.tkeys = gened_taddrs.iter().map(|ta| WalletTKey::empty(ta)).collect::<Vec<_>>();

        let ftt = FetchTaddrTxns::new(Arc::new(RwLock::new(keys.into())));

        let (taddr_fetcher_tx, taddr_fetcher_rx) = oneshot::channel::<(
            (Vec<String>, u64, u64),
            oneshot::Sender<Vec<UnboundedReceiver<Result<RawTransaction, String>>>>,
        )>();

        let h1: JoinHandle<Result<i32, String>> = tokio::spawn(async move {
            let mut tx_rs = vec![];
            let mut tx_rs_workers: Vec<JoinHandle<i32>> = vec![];

            let ((taddrs, _, _), result_tx) = taddr_fetcher_rx.await.unwrap();
            assert_eq!(taddrs, gened_taddrs);

            // Create a stream for every t-addr
            for _taddr in taddrs {
                let (tx_s, tx_r) = unbounded_channel();
                tx_rs.push(tx_r);
                tx_rs_workers.push(tokio::spawn(async move {
                    // Send 100 RawTxns at a random (but sorted) heights
                    let mut rng = rand::thread_rng();

                    // Generate between 50 and 200 txns per taddr
                    let num_txns = rng.gen_range(50, 200);

                    let mut rtxs = (0..num_txns)
                        .into_iter()
                        .map(|_| rng.gen_range(1, 100))
                        .map(|h| {
                            let mut rtx = RawTransaction::default();
                            rtx.height = h;

                            let mut b = vec![];
                            TransactionData::new().freeze().unwrap().write(&mut b).unwrap();
                            rtx.data = b;

                            rtx
                        })
                        .collect::<Vec<_>>();
                    rtxs.sort_by_key(|r| r.height);

                    for rtx in rtxs {
                        tx_s.send(Ok(rtx)).unwrap();
                    }

                    num_txns
                }));
            }

            // Dispatch a set of recievers
            result_tx.send(tx_rs).unwrap();

            let total = join_all(tx_rs_workers)
                .await
                .into_iter()
                .collect::<Result<Vec<i32>, JoinError>>()
                .map_err(|e| format!("{}", e))?
                .iter()
                .sum();

            Ok(total)
        });

        let (full_tx_scanner_tx, mut full_tx_scanner_rx) = unbounded_channel::<(Transaction, BlockHeight)>();
        let h2: JoinHandle<Result<i32, String>> = tokio::spawn(async move {
            let mut prev_height = BlockHeight::from_u32(0);
            let mut total = 0;
            while let Some((_tx, h)) = full_tx_scanner_rx.recv().await {
                if h < prev_height {
                    return Err(format!("Wrong height. prev = {}, current = {}", prev_height, h));
                }
                prev_height = h;
                total += 1;
            }
            Ok(total)
        });

        let h3 = ftt.start(100, 1, taddr_fetcher_tx, full_tx_scanner_tx).await;

        let (total_sent, total_recieved) = join!(h1, h2);
        assert_eq!(total_sent.unwrap().unwrap(), total_recieved.unwrap().unwrap());

        h3.await.unwrap().unwrap();
    }
}
