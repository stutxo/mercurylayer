use chrono::{DateTime, Duration, Utc};

pub mod bip448_sign;
pub mod deposit;
pub mod lightning_latch;
pub mod sign;
pub mod transfer_receiver;
pub mod transfer_sender;
pub mod utils;
pub mod withdraw;

fn is_batch_expired(batch_time: DateTime<Utc>) -> bool {
    let config = crate::server_config::ServerConfig::load();

    let batch_timeout = config.batch_timeout;

    let expiration_time = batch_time + Duration::seconds(batch_timeout as i64);

    let now = chrono::Utc::now();

    return now > expiration_time;
}
