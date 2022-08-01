use std::collections::HashMap;
use std::sync::Arc;

use crate::compact_formats::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::compact_formats::{
    BlockId, BlockRange, ChainSpec, CompactBlock, Empty, LightdInfo, PriceRequest, PriceResponse, RawTransaction,
    TransparentAddressBlockFilter, TreeState, TxFilter,
};
use crate::ServerCert;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::warn;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use tonic::transport::{Certificate, ClientTlsConfig};
use tonic::{
    transport::{Channel, Error},
    Request,
};
use zcash_primitives::consensus::{self, BlockHeight, BranchId};
use zcash_primitives::transaction::{Transaction, TxId};

#[derive(Clone)]
pub struct GrpcConnector {
    uri: http::Uri,
}

impl GrpcConnector {
    pub fn new(uri: http::Uri) -> Self {
        Self { uri }
    }

    async fn get_client(&self) -> Result<CompactTxStreamerClient<Channel>, Error> {
        let channel = if self.uri.scheme_str() == Some("http") {
            //println!("http");
            Channel::builder(self.uri.clone()).connect().await?
        } else {
            //println!("https");
            let mut tls = ClientTlsConfig::new().domain_name(self.uri.host().unwrap());

            let server_cert = ServerCert::get("fullchain.pem").unwrap().data;
            if server_cert.len() > 0 {
                let server_root_ca_cert = Certificate::from_pem(server_cert);
                tls = tls.ca_certificate(server_root_ca_cert);
            }

            Channel::builder(self.uri.clone())
                .tls_config(tls)?
                // .timeout(Duration::from_secs(10))
                // .connect_timeout(Duration::from_secs(10))
                .connect()
                .await?
        };

        Ok(CompactTxStreamerClient::new(channel))
    }

    pub async fn start_saplingtree_fetcher(
        &self,
    ) -> (
        JoinHandle<()>,
        UnboundedSender<(u64, oneshot::Sender<Result<TreeState, String>>)>,
    ) {
        let (tx, mut rx) = unbounded_channel::<(u64, oneshot::Sender<Result<TreeState, String>>)>();
        let uri = self.uri.clone();

        let h = tokio::spawn(async move {
            let uri = uri.clone();
            while let Some((height, result_tx)) = rx.recv().await {
                result_tx
                    .send(Self::get_merkle_tree(uri.clone(), height).await)
                    .unwrap()
            }
        });

        (h, tx)
    }

    pub async fn start_taddr_txn_fetcher(
        &self,
    ) -> (
        JoinHandle<Result<(), String>>,
        oneshot::Sender<(
            (Vec<String>, u64, u64),
            oneshot::Sender<Vec<UnboundedReceiver<Result<RawTransaction, String>>>>,
        )>,
    ) {
        let (tx, rx) = oneshot::channel::<(
            (Vec<String>, u64, u64),
            oneshot::Sender<Vec<UnboundedReceiver<Result<RawTransaction, String>>>>,
        )>();
        let uri = self.uri.clone();

        let h = tokio::spawn(async move {
            let uri = uri.clone();
            if let Ok(((taddrs, start_height, end_height), result_tx)) = rx.await {
                let mut tx_rs = vec![];
                let mut tx_rs_workers = FuturesUnordered::new();

                // Create a stream for every t-addr
                for taddr in taddrs {
                    let (tx_s, tx_r) = unbounded_channel();
                    tx_rs.push(tx_r);
                    tx_rs_workers.push(tokio::spawn(Self::get_taddr_txns(
                        uri.clone(),
                        taddr,
                        start_height,
                        end_height,
                        tx_s,
                    )));
                }

                // Dispatch a set of recievers
                result_tx.send(tx_rs).unwrap();

                // Wait for all the t-addr transactions to be fetched from LightwalletD and sent to the h1 handle.
                while let Some(r) = tx_rs_workers.next().await {
                    match r {
                        Ok(Ok(_)) => continue,
                        Ok(Err(s)) => return Err(s),
                        Err(r) => return Err(r.to_string()),
                    }
                }
            }
            Ok(())
        });

        (h, tx)
    }

    pub async fn start_fulltx_fetcher<P: consensus::Parameters + Send + Sync + 'static>(
        &self,
        parameters: P,
    ) -> (
        JoinHandle<Result<(), String>>,
        UnboundedSender<(TxId, oneshot::Sender<Result<Transaction, String>>)>,
    ) {
        let (tx, mut rx) = unbounded_channel::<(TxId, oneshot::Sender<Result<Transaction, String>>)>();
        let uri = self.uri.clone();

        let h = tokio::spawn(async move {
            let mut workers = FuturesUnordered::new();
            while let Some((txid, result_tx)) = rx.recv().await {
                let uri = uri.clone();
                let parameters = parameters.clone();
                workers.push(tokio::spawn(async move {
                    result_tx
                        .send(Self::get_full_tx(uri.clone(), &txid, parameters).await)
                        .unwrap()
                }));

                // Do only 16 API calls in parallel, otherwise it might overflow OS's limit of
                // number of simultaneous connections
                if workers.len() > 16 {
                    while let Some(_r) = workers.next().await {
                        // Do nothing
                    }
                }
            }

            Ok(())
        });

        (h, tx)
    }

    pub async fn get_block_range(
        &self,
        start_height: u64,
        end_height: u64,
        receivers: &[Sender<CompactBlock>; 2],
    ) -> Result<(), String> {
        let mut client = self.get_client().await.map_err(|e| format!("{}", e))?;

        let bs = BlockId {
            height: start_height,
            hash: vec![],
        };
        let be = BlockId {
            height: end_height,
            hash: vec![],
        };

        let request = Request::new(BlockRange {
            start: Some(bs),
            end: Some(be),
        });

        let mut response = client
            .get_block_range(request)
            .await
            .map_err(|e| format!("{}", e))?
            .into_inner();

        // First download all blocks and save them locally, so we don't timeout
        let mut block_cache = Vec::new();

        while let Some(block) = response.message().await.map_err(|e| {
            // println!("first error");
            format!("{}", e)
        })? {
            block_cache.push(block);
        }

        // Send all the blocks to the recievers
        for block in block_cache {
            //println!("grpc connector Sent {}", block.height);
            receivers[0].send(block.clone()).await.map_err(|e| format!("{}", e))?;
            receivers[1].send(block).await.map_err(|e| format!("{}", e))?;
        }

        Ok(())
    }

    async fn get_full_tx<P: consensus::Parameters + Send + Sync + 'static>(
        uri: http::Uri,
        txid: &TxId,
        parameters: P,
    ) -> Result<Transaction, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let request = Request::new(TxFilter {
            block: None,
            index: 0,
            hash: txid.as_ref().to_vec(),
        });

        log::info!("Full fetching {}", txid);

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let response = client.get_transaction(request).await.map_err(|e| format!("{}", e))?;

        let height = response.get_ref().height as u32;
        Transaction::read(
            &response.into_inner().data[..],
            BranchId::for_height(&parameters, BlockHeight::from_u32(height)),
        )
        .map_err(|e| format!("Error parsing Transaction: {}", e))
    }

    async fn get_taddr_txns(
        uri: http::Uri,
        taddr: String,
        start_height: u64,
        end_height: u64,
        txns_sender: UnboundedSender<Result<RawTransaction, String>>,
    ) -> Result<(), String> {
        let client = Arc::new(GrpcConnector::new(uri));

        // Make sure start_height is smaller than end_height, because the API expects it like that
        let (start_height, end_height) = if start_height < end_height {
            (start_height, end_height)
        } else {
            (end_height, start_height)
        };

        let start = Some(BlockId {
            height: start_height,
            hash: vec![],
        });
        let end = Some(BlockId {
            height: end_height,
            hash: vec![],
        });

        let args = TransparentAddressBlockFilter {
            address: taddr,
            range: Some(BlockRange { start, end }),
        };
        let request = Request::new(args.clone());

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let maybe_response = match client.get_taddress_txids(request).await {
            Ok(r) => r,
            Err(e) => {
                if e.code() == tonic::Code::Unimplemented {
                    // Try the old, legacy API
                    let request = Request::new(args);
                    client.get_address_txids(request).await.map_err(|e| format!("{}", e))?
                } else {
                    return Err(format!("{}", e));
                }
            }
        };

        let mut response = maybe_response.into_inner();

        while let Some(tx) = response.message().await.map_err(|e| format!("{}", e))? {
            txns_sender.send(Ok(tx)).unwrap();
        }

        Ok(())
    }

    pub async fn get_info(uri: http::Uri) -> Result<LightdInfo, String> {
        let client = Arc::new(GrpcConnector::new(uri));

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(Empty {});

        let response = client
            .get_lightd_info(request)
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;
        Ok(response.into_inner())
    }

    pub async fn monitor_mempool(uri: http::Uri, mempool_tx: UnboundedSender<RawTransaction>) -> Result<(), String> {
        let client = Arc::new(GrpcConnector::new(uri));

        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(Empty {});

        let mut response = client
            .get_mempool_stream(request)
            .await
            .map_err(|e| format!("{}", e))?
            .into_inner();
        while let Some(rtx) = response.message().await.map_err(|e| format!("{}", e))? {
            mempool_tx.send(rtx).map_err(|e| format!("{}", e))?;
        }

        Ok(())
    }

    pub async fn get_merkle_tree(uri: http::Uri, height: u64) -> Result<TreeState, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let b = BlockId {
            height: height as u64,
            hash: vec![],
        };
        let response = client
            .get_tree_state(Request::new(b))
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;

        Ok(response.into_inner())
    }

    pub async fn get_current_zec_price(uri: http::Uri) -> Result<PriceResponse, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;
        let request = Request::new(Empty {});

        let response = client
            .get_current_zec_price(request)
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;

        Ok(response.into_inner())
    }

    pub async fn get_historical_zec_prices(
        uri: http::Uri,
        txids: Vec<(TxId, u64)>,
        currency: String,
    ) -> Result<HashMap<TxId, Option<f64>>, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let mut prices = HashMap::new();
        let mut error_count: u32 = 0;

        for (txid, ts) in txids {
            if error_count < 10 {
                let r = Request::new(PriceRequest {
                    timestamp: ts,
                    currency: currency.clone(),
                });
                match client.get_zec_price(r).await {
                    Ok(response) => {
                        let price_response = response.into_inner();
                        prices.insert(txid, Some(price_response.price));
                    }
                    Err(e) => {
                        // If the server doesn't support this, bail
                        if e.code() == tonic::Code::Unimplemented {
                            return Err(format!("Unsupported by server"));
                        }

                        // Ignore other errors, these are probably just for the particular date/time
                        // and will be retried anyway
                        warn!("Ignoring grpc error: {}", e);
                        error_count += 1;
                        prices.insert(txid, None);
                    }
                }
            } else {
                // If there are too many errors, don't bother querying the server, just return none
                prices.insert(txid, None);
            }
        }

        Ok(prices)
    }

    // get_latest_block GRPC call
    pub async fn get_latest_block(uri: http::Uri) -> Result<BlockId, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(ChainSpec {});

        let response = client
            .get_latest_block(request)
            .await
            .map_err(|e| format!("Error with response: {:?}", e))?;

        Ok(response.into_inner())
    }

    pub async fn send_transaction(uri: http::Uri, tx_bytes: Box<[u8]>) -> Result<String, String> {
        let client = Arc::new(GrpcConnector::new(uri));
        let mut client = client
            .get_client()
            .await
            .map_err(|e| format!("Error getting client: {:?}", e))?;

        let request = Request::new(RawTransaction {
            data: tx_bytes.to_vec(),
            height: 0,
        });

        let response = client
            .send_transaction(request)
            .await
            .map_err(|e| format!("Send Error: {}", e))?;

        let sendresponse = response.into_inner();
        if sendresponse.error_code == 0 {
            let mut txid = sendresponse.error_message;
            if txid.starts_with("\"") && txid.ends_with("\"") {
                txid = txid[1..txid.len() - 1].to_string();
            }

            Ok(txid)
        } else {
            Err(format!("Error: {:?}", sendresponse))
        }
    }
}
