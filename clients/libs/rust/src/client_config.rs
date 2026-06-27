use std::env;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use bitcoin::Network;
use config::Config;
use sqlx::{migrate::MigrateDatabase, Sqlite, SqlitePool};

use crate::chain::{ChainClient, CoreRpcAuth, CoreRpcConfig};

/// Config struct storing all StataChain Entity config
pub struct ClientConfig {
    /// Active lockbox server addresses
    pub statechain_entity: String,
    /// Selected blockchain backend. Only `core` is supported.
    pub chain_backend: String,
    /// Active chain backend client
    pub chain_client: ChainClient,
    /// Bitcoin Core RPC url
    pub core_rpc_url: Option<String>,
    /// Bitcoin Core RPC auth strategy, e.g. `userpass` or `cookie`
    pub core_rpc_auth: Option<String>,
    /// Bitcoin Core RPC username when using password auth
    pub core_rpc_user: Option<String>,
    /// Bitcoin Core RPC password when using password auth
    pub core_rpc_password: Option<String>,
    /// Bitcoin Core RPC cookie file when using cookie auth
    pub core_rpc_cookie_file: Option<String>,
    /// Bitcoin network name (testnet, regtest, mainnet)
    pub network: Network,
    /// Fee rate tolerance
    pub fee_rate_tolerance: f64,
    /// Confirmation target
    pub confirmation_target: u32,
    /// Database connection pool
    pub pool: sqlx::Pool<Sqlite>,
    /// Tor SOCKS5 proxy address
    pub tor_proxy: Option<String>,
    /// Confirmation target
    pub max_fee_rate: f64,
}

fn check_and_set_settings() -> String {
    if let Ok(value) = env::var("ML_SETTINGS_FILE") {
        if !value.trim().is_empty() {
            return value;
        }
    }

    if let Ok(value) = env::var("ML_NETWORK") {
        if value == "regtest" {
            return String::from("regtest.Settings");
        }
    }
    "Settings".to_string()
}

fn settings_path(settings_filename: &str) -> PathBuf {
    let path = PathBuf::from(settings_filename);

    if path.extension().is_some() || settings_filename.contains('/') {
        path
    } else {
        PathBuf::from(format!("{}.toml", settings_filename))
    }
}

fn resolve_relative_to_settings(settings_dir: &Path, value: Option<String>) -> Option<String> {
    value.map(|value| {
        let path = PathBuf::from(&value);

        if path.is_absolute() {
            value
        } else {
            settings_dir.join(path).to_string_lossy().into_owned()
        }
    })
}

fn build_core_rpc_config(
    core_rpc_url: &Option<String>,
    core_rpc_auth: &Option<String>,
    core_rpc_user: &Option<String>,
    core_rpc_password: &Option<String>,
    core_rpc_cookie_file: &Option<String>,
) -> Result<CoreRpcConfig> {
    let url = core_rpc_url
        .clone()
        .ok_or_else(|| anyhow!("Bitcoin Core backend selected without core_rpc_url"))?;

    let auth = match core_rpc_auth.as_deref() {
        Some("none") => CoreRpcAuth::None,
        Some("userpass") => CoreRpcAuth::UserPass {
            username: core_rpc_user.clone().ok_or_else(|| {
                anyhow!("Bitcoin Core userpass auth selected without core_rpc_user")
            })?,
            password: core_rpc_password.clone().ok_or_else(|| {
                anyhow!("Bitcoin Core userpass auth selected without core_rpc_password")
            })?,
        },
        Some("cookie") => {
            CoreRpcAuth::CookieFile(PathBuf::from(core_rpc_cookie_file.clone().ok_or_else(
                || anyhow!("Bitcoin Core cookie auth selected without core_rpc_cookie_file"),
            )?))
        }
        Some(other) => return Err(anyhow!("Unsupported Bitcoin Core auth strategy: {}", other)),
        None => match (
            core_rpc_user.as_ref(),
            core_rpc_password.as_ref(),
            core_rpc_cookie_file.as_ref(),
        ) {
            (Some(username), Some(password), _) => CoreRpcAuth::UserPass {
                username: username.clone(),
                password: password.clone(),
            },
            (_, _, Some(cookie_file)) => CoreRpcAuth::CookieFile(PathBuf::from(cookie_file)),
            _ => CoreRpcAuth::None,
        },
    };

    Ok(CoreRpcConfig { url, auth })
}

fn ensure_supported_chain_backend(chain_backend: &str) -> Result<()> {
    match chain_backend {
        "core" => Ok(()),
        other => Err(anyhow!("Unsupported chain backend: {}", other)),
    }
}

impl ClientConfig {
    pub async fn load() -> Self {
        let settings_filename = check_and_set_settings();
        let settings_path = settings_path(&settings_filename);
        let settings_dir = settings_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let settings_source = config::File::from(settings_path.as_path());

        let settings = Config::builder()
            .add_source(settings_source)
            .build()
            .unwrap();

        let statechain_entity = settings.get_string("statechain_entity").unwrap();
        let chain_backend = settings
            .get_string("chain_backend")
            .unwrap_or_else(|_| "core".to_string());
        ensure_supported_chain_backend(&chain_backend).unwrap();
        let core_rpc_url = settings.get_string("core_rpc_url").ok();
        let core_rpc_auth = settings.get_string("core_rpc_auth").ok();
        let core_rpc_user = settings.get_string("core_rpc_user").ok();
        let core_rpc_password = settings.get_string("core_rpc_password").ok();
        let core_rpc_cookie_file = resolve_relative_to_settings(
            &settings_dir,
            settings.get_string("core_rpc_cookie_file").ok(),
        );
        let network = settings.get_string("network").unwrap();
        let fee_rate_tolerance = settings.get_int("fee_rate_tolerance").unwrap() as f64;
        let database_file = settings.get_string("database_file").unwrap();
        let confirmation_target = settings.get_int("confirmation_target").unwrap() as u32;
        let max_fee_rate = settings.get_int("max_fee_rate").unwrap() as f64;

        let tor_proxy = match settings.get_string("tor_proxy") {
            Ok(proxy) => Some(proxy.to_string()),
            Err(_) => None,
        };
        // Open database connection pool

        if !Sqlite::database_exists(&database_file)
            .await
            .unwrap_or(false)
        {
            match Sqlite::create_database(&database_file).await {
                Ok(_) => {}
                Err(error) => panic!("error: {}", error),
            }
        }

        let pool: sqlx::Pool<Sqlite> = SqlitePool::connect(&database_file).await.unwrap();

        sqlx::migrate!("./migrations").run(&pool).await.unwrap();

        // Convert network string to Network enum

        let network = match network.as_str() {
            "signet" => Network::Signet,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            "bitcoin" => Network::Bitcoin,
            _ => panic!("Invalid network name"),
        };

        // Create Core/Inquisition chain client

        let core_rpc_config = build_core_rpc_config(
            &core_rpc_url,
            &core_rpc_auth,
            &core_rpc_user,
            &core_rpc_password,
            &core_rpc_cookie_file,
        )
        .unwrap();
        let chain_client = ChainClient::new(core_rpc_config).unwrap();

        ClientConfig {
            statechain_entity,
            chain_backend,
            chain_client,
            core_rpc_url,
            core_rpc_auth,
            core_rpc_user,
            core_rpc_password,
            core_rpc_cookie_file,
            network,
            fee_rate_tolerance,
            confirmation_target,
            pool,
            tor_proxy,
            max_fee_rate,
        }
    }

    pub fn get_reqwest_client(&self) -> Result<reqwest::Client> {
        match self.tor_proxy {
            Some(ref proxy) => {
                let proxy = reqwest::Proxy::all(proxy)?;
                Ok(reqwest::Client::builder().proxy(proxy).build()?)
            }
            None => Ok(reqwest::Client::new()),
        }
    }
}

pub async fn load() -> ClientConfig {
    let client_config = ClientConfig::load().await;
    client_config
}
