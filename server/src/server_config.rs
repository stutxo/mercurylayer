use config::{Config as ConfigRs, File};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgConnectOptions;
use std::env;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enclave {
    pub url: String,
    pub allow_deposit: bool,
    #[serde(default)]
    pub pcr0: Option<String>,
    #[serde(default)]
    pub pcr1: Option<String>,
    #[serde(default)]
    pub pcr2: Option<String>,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub allow_unattested: bool,
}

/// Config struct storing all StataChain Entity config
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bitcoin network name (testnet, regtest, mainnet)
    pub network: String,
    /// Batch timeout
    pub batch_timeout: u32,
    /// Enclave server list
    pub enclaves: Vec<Enclave>,
    /// Database user
    pub db_user: String,
    /// Database password
    pub db_password: String,
    /// Database host
    pub db_host: String,
    /// Database port
    pub db_port: u16,
    /// Database name
    pub db_name: String,
    /// URL of the token server
    pub token_server_url: Option<String>,
}

impl ServerConfig {
    pub fn load() -> Self {
        let settings: Option<ConfigRs> = ConfigRs::builder()
            .add_source(File::with_name("Settings"))
            .build()
            .ok();

        // Function to fetch a setting from the environment or fallback to the config file
        let get_env_or_config = |key: &str, env_var: &str| -> String {
            env::var(env_var)
                .unwrap_or_else(|_| settings.as_ref().unwrap().get_string(key).unwrap())
        };

        let get_env_or_config_enclave = |key: &str, env_var: &str| -> Vec<Enclave> {
            match env::var(env_var) {
                Ok(value) => serde_json::from_str::<Vec<Enclave>>(&value).unwrap(),
                Err(_) => settings.as_ref().unwrap().get::<Vec<Enclave>>(key).unwrap(),
            }
        };

        let get_optional_env_or_config = |key: &str, env_var: &str| -> Option<String> {
            env::var(env_var)
                .ok()
                .or_else(|| settings.as_ref()?.get::<String>(key).ok())
        };

        ServerConfig {
            network: get_env_or_config("network", "BITCOIN_NETWORK"),
            batch_timeout: get_env_or_config("batch_timeout", "BATCH_TIMEOUT")
                .parse::<u32>()
                .unwrap(),
            enclaves: get_env_or_config_enclave("enclaves", "ENCLAVES"),
            db_user: get_env_or_config("db_user", "DB_USER"),
            db_password: get_env_or_config("db_password", "DB_PASSWORD"),
            db_host: get_env_or_config("db_host", "DB_HOST"),
            db_port: get_env_or_config("db_port", "DB_PORT")
                .parse::<u16>()
                .unwrap(),
            db_name: get_env_or_config("db_name", "DB_NAME"),
            token_server_url: get_optional_env_or_config("token_server_url", "TOKEN_SERVER_URL"),
        }
    }

    pub fn build_postgres_connection_string(&self) -> PgConnectOptions {
        PgConnectOptions::new()
            .host(&self.db_host)
            .username(&self.db_user)
            .password(&self.db_password)
            .port(self.db_port)
            .database(&self.db_name)
    }
}
