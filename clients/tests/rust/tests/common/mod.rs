use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::Result;
use mercuryrustlib::client_config::ClientConfig;

pub mod bitcoin_core;
pub mod chain;
pub mod lockbox;
pub mod mercury;
pub mod utils;

static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

pub fn test_guard() -> MutexGuard<'static, ()> {
    TEST_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub async fn prepare_test_env() -> Result<ClientConfig> {
    cleanup_wallet_db()?;
    std::env::set_var("ML_NETWORK", "regtest");
    Ok(mercuryrustlib::client_config::load().await)
}

fn cleanup_wallet_db() -> Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    for file_name in ["wallet.db", "wallet.db-shm", "wallet.db-wal"] {
        let path = manifest_dir.join(file_name);

        if let Err(err) = fs::remove_file(&path) {
            if err.kind() != ErrorKind::NotFound {
                return Err(err.into());
            }
        }
    }

    Ok(())
}
