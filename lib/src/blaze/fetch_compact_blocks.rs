use std::{cmp::max, sync::Arc};

use crate::{
    compact_formats::CompactBlock, grpc_connector::GrpcConnector, lightclient::lightclient_config::LightClientConfig,
};
use log::info;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use zcash_primitives::consensus;

pub struct FetchCompactBlocks<P> {
    config: LightClientConfig<P>,
}

impl<P: consensus::Parameters> FetchCompactBlocks<P> {
    pub fn new(config: &LightClientConfig<P>) -> Self {
        Self { config: config.clone() }
    }
    async fn fetch_blocks_range(
        &self,
        receivers: &[Sender<CompactBlock>; 2],
        start_block: u64,
        end_block: u64,
        spam_filter_threshold: i64,
    ) -> Result<(), String> {
        let grpc_client = Arc::new(GrpcConnector::new(self.config.server.clone()));
        const STEP: u64 = 10_000;

        // We need the `rev()` here because rust ranges can only go up
        for b in (end_block..(start_block + 1)).rev().step_by(STEP as usize) {
            let start = b;
            let end = max((b as i64) - (STEP as i64) + 1, end_block as i64) as u64;
            if start < end {
                return Err(format!("Wrong block order"));
            }

            info!("Fetching blocks {}-{}", start, end);

            grpc_client.get_block_range(start, end,spam_filter_threshold, receivers).await?;
        }

        Ok(())
    }

    // Load all the blocks from LightwalletD
    pub async fn start(
        &self,
        receivers: [Sender<CompactBlock>; 2],
        start_block: u64,
        end_block: u64,
        spam_filter_threshold: i64,
        mut reorg_rx: UnboundedReceiver<Option<u64>>,
    ) -> Result<(), String> {
        if start_block < end_block {
            return Err(format!("Expected blocks in reverse order"));
        }

        //info!("Starting fetch compact blocks");
        self.fetch_blocks_range(&receivers, start_block, end_block,spam_filter_threshold).await?;

        // After fetching all the normal blocks, we actually wait to see if any re-org'd blocks are recieved
        while let Some(Some(reorg_block)) = reorg_rx.recv().await {
            // Fetch the additional block.
            self.fetch_blocks_range(&receivers, reorg_block, reorg_block,spam_filter_threshold).await?;
        }

        //info!("Finished fetch compact blocks, closing channels");
        Ok(())
    }
}
