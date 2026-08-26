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

impl Default for ServerConfig {
    fn default() -> ServerConfig {
        ServerConfig {
            network: String::from("regtest"),
            batch_timeout: 120,
            enclaves: vec![
                Enclave {
                    url: "http://0.0.0.0:18080".to_string(),
                    allow_deposit: true,
                    pcr0: None,
                    pcr1: None,
                    pcr2: None,
                    debug: false,
                },
                Enclave {
                    url: "http://0.0.0.0:18080".to_string(),
                    allow_deposit: false,
                    pcr0: None,
                    pcr1: None,
                    pcr2: None,
                    debug: false,
                },
            ],
            db_user: String::from("postgres"),
            db_password: String::from("postgres"),
            db_host: String::from("db_server"),
            db_port: 5432,
            db_name: String::from("mercury"),
            token_server_url: None,
        }
    }
}

/* impl From<ConfigRs> for ServerConfig {
    fn from(config: ConfigRs) -> Self {
        ServerConfig {
            network: config.get::<String>("network").unwrap_or_else(|_| String::new()),
            batch_timeout: config.get::<u32>("batch_timeout").unwrap_or(0),
            enclaves: config.get::<Vec<Enclave>>("enclaves").unwrap_or_else(|_| Vec::new()),
            db_user: config.get::<String>("db_user").unwrap_or_else(|_| String::new()),
            db_password: config.get::<String>("db_password").unwrap_or_else(|_| String::new()),
            db_host: config.get::<String>("db_host").unwrap_or_else(|_| String::new()),
            db_port: config.get::<u16>("db_port").unwrap_or(0),
            db_name: config.get::<String>("db_name").unwrap_or_else(|_| String::new()),
        }
    }
} */

impl ServerConfig {
    pub fn load() -> Self {
        let mut conf_rs = ConfigRs::default();
        let _ = conf_rs
            // First merge struct default config
            .merge(ConfigRs::try_from(&ServerConfig::default()).unwrap());
        // Override with settings in file Settings.toml if exists
        conf_rs.merge(File::with_name("Settings").required(false));
        // Override with settings in file Rocket.toml if exists
        conf_rs.merge(File::with_name("Rocket").required(false));

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
            let env_enclaves = env::var(env_var);

            if env_enclaves.is_ok() {
                return serde_json::from_str::<Vec<Enclave>>(&env_enclaves.unwrap()).unwrap();
            }

            settings.as_ref().unwrap().get::<Vec<Enclave>>(key).unwrap()
        };

        let get_optional_env_or_config = |key: &str, env_var: &str| -> Option<String> {
            let env_var = env::var(env_var);

            if env_var.is_ok() {
                return Some(env_var.unwrap());
            }

            if settings.as_ref().is_none() {
                return None;
            }

            let res = settings.as_ref().unwrap().get::<String>(key);

            if res.is_ok() {
                return Some(res.unwrap());
            }

            return None;
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
