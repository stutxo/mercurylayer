use std::fs;
use std::io::ErrorKind;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::{bail, Result};
use mercuryrustlib::client_config::ClientConfig;

pub use rust::stack;

pub mod bip448_activation;
pub mod bip448_regtest;
pub mod bitcoin_core;
pub mod chain;
pub mod lockbox;
pub mod mercury;
pub mod utils;

static TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

pub fn test_guard() -> MutexGuard<'static, ()> {
    let _ = (
        mercury::url(),
        mercury::database_url(),
        lockbox::url(),
        lockbox::database_url(),
    );
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
    for path in stack::current().wallet_artifact_paths() {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let file_type = metadata.file_type();
                if file_type.is_symlink() || !file_type.is_file() {
                    bail!(
                        "refusing to remove non-regular wallet artifact {}",
                        path.display()
                    );
                }
                fs::remove_file(&path)?;
            }
            Err(error) => {
                if error.kind() != ErrorKind::NotFound {
                    return Err(error.into());
                }
            }
        }
    }

    Ok(())
}
