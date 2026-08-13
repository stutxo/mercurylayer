use crate::bip448_funding::Bip448TransferIntentKind;
use anyhow::Result;

#[cfg(feature = "test-hooks")]
use anyhow::{anyhow, Context};

#[cfg(feature = "test-hooks")]
use std::{path::Path, thread, time::Duration};

mod api;
mod cancellation;
mod driver;
mod message;
mod preflight;
mod signing;

pub use api::{transfer_bip448_sender, transfer_bip448_sender_with_options};
pub use cancellation::cancel_bip448_transfer;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip448TransferOptions {
    pub acknowledge_cooperative_duplicates: bool,
    pub intent: Bip448TransferIntentKind,
}

#[cfg(feature = "test-hooks")]
fn bip448_process_checkpoint(checkpoint: &str) {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() == Ok("1")
        && std::env::var("ML_BIP448_TEST_CHECKPOINT").as_deref() == Ok(checkpoint)
    {
        std::process::exit(86);
    }
}

#[cfg(not(feature = "test-hooks"))]
fn bip448_process_checkpoint(_checkpoint: &str) {}

#[cfg(feature = "test-hooks")]
fn bip448_test_barrier(checkpoint: &str) -> Result<()> {
    if std::env::var("ML_BIP448_TEST_BARRIER").as_deref() != Ok(checkpoint) {
        return Ok(());
    }
    let reached = std::env::var("ML_BIP448_TEST_BARRIER_REACHED")
        .context("BIP448 test barrier reached path is missing")?;
    let release = std::env::var("ML_BIP448_TEST_BARRIER_RELEASE")
        .context("BIP448 test barrier release path is missing")?;
    std::fs::write(&reached, checkpoint.as_bytes())
        .context("failed to publish BIP448 test barrier")?;
    for _ in 0..6_000 {
        if Path::new(&release).try_exists()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(anyhow!("timed out waiting for BIP448 test barrier release"))
}

#[cfg(not(feature = "test-hooks"))]
fn bip448_test_barrier(_checkpoint: &str) -> Result<()> {
    Ok(())
}
