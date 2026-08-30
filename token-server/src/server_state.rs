use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use crate::core_rpc::CoreRpcClient;
use crate::server_config::{self, ServerConfig};

pub struct TokenServerState {
    pub pool: Pool<Postgres>,
    pub server_config: ServerConfig,
    pub core_rpc_client: CoreRpcClient,
}

impl TokenServerState {
    pub async fn new() -> Self {
        let server_config = server_config::ServerConfig::load();
        let core_rpc_client = CoreRpcClient::new(server_config.core_rpc.clone()).unwrap();

        core_rpc_client
            .ensure_wallet(
                &server_config.token_wallet,
                &server_config.public_key_descriptor,
            )
            .await
            .unwrap();

        let connection_string = server_config.build_postgres_connection_string();

        let pool = PgPoolOptions::new()
            // .max_connections(5)
            .connect_with(connection_string)
            .await
            .unwrap();

        TokenServerState {
            pool,
            server_config,
            core_rpc_client,
        }
    }
}
