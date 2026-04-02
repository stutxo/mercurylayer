use std::{str::FromStr, sync::Mutex};

use miniscript::{Descriptor, DescriptorPublicKey};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use crate::server_config::{self, ServerConfig};

use sqlx::Row;

pub struct TokenServerState {
    pub pool: Pool<Postgres>,
    pub key_index: Mutex<u64>,
    pub server_config: ServerConfig,
    pub checksum: String,
}

pub async fn get_descriptor_index(pool: &sqlx::PgPool, checksum: &str) -> i32 {
    let row = sqlx::query(
        "SELECT MAX(onchain_address_index) \
        FROM public.tokens \
        WHERE descriptor_checksum = $1",
    )
    .bind(checksum)
    .fetch_one(pool)
    .await;

    if row.is_err() {
        return 0;
    }

    let row = row.unwrap();

    let index: Option<i32> = row.get(0);
    index.map(|i| i).unwrap_or(0)
}

impl TokenServerState {
    pub async fn new() -> Self {
        let server_config = server_config::ServerConfig::load();

        let descriptor =
            Descriptor::<DescriptorPublicKey>::from_str(&server_config.public_key_descriptor)
                .unwrap();
        let desc_str = descriptor.to_string();
        let checksum = desc_str.split('#').nth(1).unwrap();

        let connection_string = server_config.build_postgres_connection_string();

        let pool = PgPoolOptions::new()
            // .max_connections(5)
            .connect_with(connection_string)
            .await
            .unwrap();

        let index = get_descriptor_index(&pool, checksum).await;

        TokenServerState {
            pool,
            key_index: Mutex::new(index as u64),
            server_config,
            checksum: checksum.to_string(),
        }
    }
}
