use config::{Config as ConfigRs, File};
use sqlx::postgres::PgConnectOptions;
use std::{env, path::PathBuf};

use crate::core_rpc::{CoreRpcAuth, CoreRpcConfig, TokenWalletConfig};

/// Config struct storing all StataChain Entity config
pub struct ServerConfig {
    /// Public key descriptor for onchain addresses
    pub public_key_descriptor: String,
    /// Bitcoin network
    pub network: String,
    /// Bitcoin Core/Inquisition RPC connection.
    pub core_rpc: CoreRpcConfig,
    /// Dedicated token payment wallet configuration.
    pub token_wallet: TokenWalletConfig,
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

        let get_optional_env_or_config = |key: &str, env_var: &str| -> Option<String> {
            env::var(env_var).ok().or_else(|| {
                settings
                    .as_ref()
                    .and_then(|config| config.get_string(key).ok())
            })
        };

        let get_bool_env_or_config = |key: &str, env_var: &str, default: bool| -> bool {
            get_optional_env_or_config(key, env_var)
                .map(|value| value.parse::<bool>().unwrap())
                .unwrap_or(default)
        };

        let core_rpc_url = get_env_or_config("core_rpc_url", "CORE_RPC_URL");
        let core_rpc_auth = get_optional_env_or_config("core_rpc_auth", "CORE_RPC_AUTH");
        let core_rpc_user = get_optional_env_or_config("core_rpc_user", "CORE_RPC_USER");
        let core_rpc_password =
            get_optional_env_or_config("core_rpc_password", "CORE_RPC_PASSWORD");
        let core_rpc_cookie_file =
            get_optional_env_or_config("core_rpc_cookie_file", "CORE_RPC_COOKIE_FILE");

        let core_rpc_auth = match core_rpc_auth.as_deref() {
            Some("none") => CoreRpcAuth::None,
            Some("userpass") => CoreRpcAuth::UserPass {
                username: core_rpc_user
                    .clone()
                    .expect("CORE_RPC_AUTH=userpass requires CORE_RPC_USER"),
                password: core_rpc_password
                    .clone()
                    .expect("CORE_RPC_AUTH=userpass requires CORE_RPC_PASSWORD"),
            },
            Some("cookie") => CoreRpcAuth::CookieFile(PathBuf::from(
                core_rpc_cookie_file
                    .clone()
                    .expect("CORE_RPC_AUTH=cookie requires CORE_RPC_COOKIE_FILE"),
            )),
            Some(other) => panic!("Unsupported Bitcoin Core auth strategy: {}", other),
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

        let token_wallet = TokenWalletConfig {
            name: get_optional_env_or_config("core_rpc_wallet", "CORE_RPC_WALLET")
                .unwrap_or_else(|| "mercury_tokens".to_string()),
            create: get_bool_env_or_config(
                "core_rpc_wallet_create",
                "CORE_RPC_WALLET_CREATE",
                true,
            ),
        };

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
            core_rpc: CoreRpcConfig {
                url: core_rpc_url,
                auth: core_rpc_auth,
            },
            token_wallet,
            fee: get_env_or_config("fee", "FEE").parse::<u64>().unwrap(),
            confirmation_target: get_env_or_config("confirmation_target", "CONFIRMATION_TARGET")
                .parse::<u32>()
                .unwrap(),
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
