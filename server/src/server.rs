use std::{env, time::Duration};

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use crate::{lockbox_client::LockboxClients, server_config::ServerConfig};

pub struct StateChainEntity {
    pub pool: Pool<Postgres>,
    pub config: ServerConfig,
    pub http_client: reqwest::Client,
    pub lockboxes: LockboxClients,
}

impl StateChainEntity {
    pub async fn new(config: ServerConfig) -> Result<Self> {
        let connection_string = config.build_postgres_connection_string();
        let auth_token = env::var("LOCKBOX_AUTH_TOKEN").ok();
        let lockboxes =
            LockboxClients::connect(&config.enclaves, auth_token.as_deref(), &config.network)
                .await?;

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(connection_string)
            .await
            .context("connecting to the Mercury database")?;

        Ok(StateChainEntity {
            pool,
            config,
            http_client: reqwest::Client::new(),
            lockboxes,
        })
    }
}
