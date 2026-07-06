use std::time::Duration;

use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use crate::server_config::ServerConfig;

pub struct StateChainEntity {
    pub pool: Pool<Postgres>,
    pub config: ServerConfig,
    pub http_client: reqwest::Client,
}

impl StateChainEntity {
    pub async fn new(config: ServerConfig) -> Self {
        let connection_string = config.build_postgres_connection_string();

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30)) // Increase the timeout duration
            .connect_with(connection_string)
            .await
            .unwrap();

        StateChainEntity {
            pool,
            config,
            http_client: reqwest::Client::new(),
        }
    }
}
