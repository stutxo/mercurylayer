use config::{Config as ConfigRs, File};
use sqlx::postgres::PgConnectOptions;
use std::env;

/// Config struct storing all StataChain Entity config
pub struct ServerConfig {
    /// Public key descriptor for onchain addresses
    pub public_key_descriptor: String,
    /// Bitcoin network
    pub network: String,
    /// Electrum client
    pub electrum_server_url: String,
    /// Token fee value (satoshis)
    pub fee: u64,
    /// Confirmation target
    pub confirmation_target: u32,
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

        let electrum_server_url = get_env_or_config("electrum_server", "ELECTRUM_SERVER");
        // let electrum_client: electrum_client::Client = electrum_client::Client::new(electrum_server_url.as_str()).unwrap();

        ServerConfig {
            db_user: get_env_or_config("db_user", "DB_USER"),
            db_password: get_env_or_config("db_password", "DB_PASSWORD"),
            db_host: get_env_or_config("db_host", "DB_HOST"),
            db_port: get_env_or_config("db_port", "DB_PORT")
                .parse::<u16>()
                .unwrap(),
            db_name: get_env_or_config("db_name", "DB_NAME"),
            public_key_descriptor: get_env_or_config(
                "public_key_descriptor",
                "PUBLIC_KEY_DESCRIPTOR",
            ),
            network: get_env_or_config("network", "BITCOIN_NETWORK"),
            electrum_server_url,
            fee: get_env_or_config("fee", "FEE").parse::<u64>().unwrap(),
            confirmation_target: get_env_or_config("confirmation_target", "CONFIRMATION_TARGET")
                .parse::<u32>()
                .unwrap(),
        }
    }

    pub fn get_electrum_client(&self) -> electrum_client::Client {
        electrum_client::Client::new(&self.electrum_server_url.as_str()).unwrap()
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
