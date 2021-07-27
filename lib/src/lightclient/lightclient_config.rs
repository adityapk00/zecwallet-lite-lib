use std::{
    io::{self, Error, ErrorKind},
    path::{Path, PathBuf},
};

use log::{error, info, LevelFilter};
use log4rs::{
    append::rolling_file::{
        policy::compound::{roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger, CompoundPolicy},
        RollingFileAppender,
    },
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
    Config,
};
use tokio::runtime::Runtime;
use zcash_primitives::constants::{mainnet, regtest, testnet};

use crate::{grpc_connector::GrpcConnector, lightclient::checkpoints};

pub const DEFAULT_SERVER: &str = "https://lwdv3.zecwallet.co";
pub const WALLET_NAME: &str = "zecwallet-light-wallet.dat";
pub const LOGFILE_NAME: &str = "zecwallet-light-wallet.debug.log";
pub const ANCHOR_OFFSET: [u32; 5] = [9, 4, 2, 1, 0];
pub const MAX_REORG: usize = 100;
pub const GAP_RULE_UNUSED_ADDRESSES: usize = if cfg!(any(target_os = "ios", target_os = "android")) {
    0
} else {
    5
};

#[derive(Clone, Debug)]
pub struct LightClientConfig {
    pub server: http::Uri,
    pub chain_name: String,
    pub sapling_activation_height: u64,
    pub anchor_offset: [u32; 5],
    pub monitor_mempool: bool,
    pub data_dir: Option<String>,
}

impl LightClientConfig {
    // Create an unconnected (to any server) config to test for local wallet etc...
    #[cfg(test)]
    pub fn create_unconnected(chain_name: String, dir: Option<String>) -> LightClientConfig {
        LightClientConfig {
            server: http::Uri::default(),
            chain_name: chain_name,
            sapling_activation_height: 1,
            monitor_mempool: false,
            anchor_offset: [4u32; 5],
            data_dir: dir,
        }
    }

    pub fn create(server: http::Uri) -> io::Result<(LightClientConfig, u64)> {
        use std::net::ToSocketAddrs;

        let lc = Runtime::new().unwrap().block_on(async move {
            // Test for a connection first
            format!("{}:{}", server.host().unwrap(), server.port().unwrap())
                .to_socket_addrs()?
                .next()
                .ok_or(std::io::Error::new(
                    ErrorKind::ConnectionRefused,
                    "Couldn't resolve server!",
                ))?;

            // Do a getinfo first, before opening the wallet
            let info = GrpcConnector::get_info(server.clone())
                .await
                .map_err(|e| std::io::Error::new(ErrorKind::ConnectionRefused, e))?;

            // Create a Light Client Config
            let config = LightClientConfig {
                server,
                chain_name: info.chain_name,
                monitor_mempool: true,
                sapling_activation_height: info.sapling_activation_height,
                anchor_offset: ANCHOR_OFFSET,
                data_dir: None,
            };

            Ok((config, info.block_height))
        });

        lc
    }

    pub fn set_data_dir(&mut self, dir_str: String) {
        self.data_dir = Some(dir_str);
    }

    /// Build the Logging config
    pub fn get_log_config(&self) -> io::Result<Config> {
        let window_size = 3; // log0, log1, log2
        let fixed_window_roller = FixedWindowRoller::builder()
            .build("zecwallet-light-wallet-log{}", window_size)
            .unwrap();
        let size_limit = 5 * 1024 * 1024; // 5MB as max log file size to roll
        let size_trigger = SizeTrigger::new(size_limit);
        let compound_policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));

        Config::builder()
            .appender(
                Appender::builder()
                    .filter(Box::new(ThresholdFilter::new(LevelFilter::Info)))
                    .build(
                        "logfile",
                        Box::new(
                            RollingFileAppender::builder()
                                .encoder(Box::new(PatternEncoder::new("{d} {l}::{m}{n}")))
                                .build(self.get_log_path(), Box::new(compound_policy))?,
                        ),
                    ),
            )
            .build(Root::builder().appender("logfile").build(LevelFilter::Debug))
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", e)))
    }

    pub fn get_zcash_data_path(&self) -> Box<Path> {
        if cfg!(target_os = "ios") || cfg!(target_os = "android") {
            PathBuf::from(&self.data_dir.as_ref().unwrap()).into_boxed_path()
        } else {
            let mut zcash_data_location;
            if self.data_dir.is_some() {
                zcash_data_location = PathBuf::from(&self.data_dir.as_ref().unwrap());
            } else {
                if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
                    zcash_data_location = dirs::data_dir().expect("Couldn't determine app data directory!");
                    zcash_data_location.push("Zcash");
                } else {
                    if dirs::home_dir().is_none() {
                        info!("Couldn't determine home dir!");
                    }
                    zcash_data_location = dirs::home_dir().expect("Couldn't determine home directory!");
                    zcash_data_location.push(".zcash");
                };

                match &self.chain_name[..] {
                    "main" => {}
                    "test" => zcash_data_location.push("testnet3"),
                    "regtest" => zcash_data_location.push("regtest"),
                    c => panic!("Unknown chain {}", c),
                };
            }

            // Create directory if it doesn't exist on non-mobile platforms
            match std::fs::create_dir_all(zcash_data_location.clone()) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Couldn't create zcash directory!\n{}", e);
                    panic!("Couldn't create zcash directory!");
                }
            };

            zcash_data_location.into_boxed_path()
        }
    }

    pub fn get_zcash_params_path(&self) -> io::Result<Box<Path>> {
        if cfg!(target_os = "ios") || cfg!(target_os = "android") {
            Ok(PathBuf::from(&self.data_dir.as_ref().unwrap()).into_boxed_path())
        } else {
            if dirs::home_dir().is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Couldn't determine Home Dir",
                ));
            }

            let mut zcash_params = self.get_zcash_data_path().into_path_buf();
            zcash_params.push("..");
            if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
                zcash_params.push("ZcashParams");
            } else {
                zcash_params.push(".zcash-params");
            }

            match std::fs::create_dir_all(zcash_params.clone()) {
                Ok(_) => Ok(zcash_params.into_boxed_path()),
                Err(e) => {
                    eprintln!("Couldn't create zcash params directory\n{}", e);
                    Err(e)
                }
            }
        }
    }

    pub fn get_wallet_path(&self) -> Box<Path> {
        let mut wallet_location = self.get_zcash_data_path().into_path_buf();
        wallet_location.push(WALLET_NAME);

        wallet_location.into_boxed_path()
    }

    pub fn wallet_exists(&self) -> bool {
        return self.get_wallet_path().exists();
    }

    pub fn backup_existing_wallet(&self) -> Result<String, String> {
        if !self.wallet_exists() {
            return Err(format!(
                "Couldn't find existing wallet to backup. Looked in {:?}",
                self.get_wallet_path().to_str()
            ));
        }
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut backup_file_path = self.get_zcash_data_path().into_path_buf();
        backup_file_path.push(&format!(
            "zecwallet-light-wallet.backup.{}.dat",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        ));

        let backup_file_str = backup_file_path.to_string_lossy().to_string();
        std::fs::copy(self.get_wallet_path(), backup_file_path).map_err(|e| format!("{}", e))?;

        Ok(backup_file_str)
    }

    pub fn get_log_path(&self) -> Box<Path> {
        let mut log_path = self.get_zcash_data_path().into_path_buf();
        log_path.push(LOGFILE_NAME);
        //println!("LogFile:\n{}", log_path.to_str().unwrap());

        log_path.into_boxed_path()
    }

    pub async fn get_initial_state(&self, height: u64) -> Option<(u64, String, String)> {
        if height <= self.sapling_activation_height {
            return None;
        }

        info!("Getting sapling tree from LightwalletD at height {}", height);
        match GrpcConnector::get_sapling_tree(self.server.clone(), height).await {
            Ok(tree_state) => {
                let hash = tree_state.hash.clone();
                let tree = tree_state.tree.clone();
                Some((tree_state.height, hash, tree))
            }
            Err(e) => {
                error!("Error getting sapling tree:{}\nWill return checkpoint instead.", e);
                match checkpoints::get_closest_checkpoint(&self.chain_name, height) {
                    Some((height, hash, tree)) => Some((height, hash.to_string(), tree.to_string())),
                    None => None,
                }
            }
        }
    }

    pub fn get_server_or_default(server: Option<String>) -> http::Uri {
        match server {
            Some(s) => {
                let mut s = if s.starts_with("http") {
                    s
                } else {
                    "http://".to_string() + &s
                };
                let uri: http::Uri = s.parse().unwrap();
                if uri.port().is_none() {
                    s = s + ":443";
                }
                s
            }
            None => DEFAULT_SERVER.to_string(),
        }
        .parse()
        .unwrap()
    }

    pub fn get_coin_type(&self) -> u32 {
        match &self.chain_name[..] {
            "main" => mainnet::COIN_TYPE,
            "test" => testnet::COIN_TYPE,
            "regtest" => regtest::COIN_TYPE,
            c => panic!("Unknown chain {}", c),
        }
    }

    pub fn hrp_sapling_address(&self) -> &str {
        match &self.chain_name[..] {
            "main" => mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "test" => testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "regtest" => regtest::HRP_SAPLING_PAYMENT_ADDRESS,
            c => panic!("Unknown chain {}", c),
        }
    }

    pub fn hrp_sapling_private_key(&self) -> &str {
        match &self.chain_name[..] {
            "main" => mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "test" => testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            "regtest" => regtest::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            c => panic!("Unknown chain {}", c),
        }
    }

    pub fn hrp_sapling_viewing_key(&self) -> &str {
        match &self.chain_name[..] {
            "main" => mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            "test" => testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            "regtest" => regtest::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            c => panic!("Unknown chain {}", c),
        }
    }

    pub fn base58_pubkey_address(&self) -> [u8; 2] {
        match &self.chain_name[..] {
            "main" => mainnet::B58_PUBKEY_ADDRESS_PREFIX,
            "test" => testnet::B58_PUBKEY_ADDRESS_PREFIX,
            "regtest" => regtest::B58_PUBKEY_ADDRESS_PREFIX,
            c => panic!("Unknown chain {}", c),
        }
    }

    pub fn base58_script_address(&self) -> [u8; 2] {
        match &self.chain_name[..] {
            "main" => mainnet::B58_SCRIPT_ADDRESS_PREFIX,
            "test" => testnet::B58_SCRIPT_ADDRESS_PREFIX,
            "regtest" => regtest::B58_SCRIPT_ADDRESS_PREFIX,
            c => panic!("Unknown chain {}", c),
        }
    }

    pub fn base58_secretkey_prefix(&self) -> [u8; 1] {
        match &self.chain_name[..] {
            "main" => [0x80],
            "test" => [0xEF],
            "regtest" => [0xEF],
            c => panic!("Unknown chain {}", c),
        }
    }
}
