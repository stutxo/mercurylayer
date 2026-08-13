mod common;
use anyhow::{anyhow, Context, Result};
use common::bip448_regtest::FUNDING_AMOUNT_SATS;
use mercurylib::transfer::{
    bip448::decrypt_bip448_transfer_msg, receiver::GetMsgAddrResponsePayload,
};
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::Duration,
};
#[path = "bip448_transfer_sender/cancellation.rs"]
mod cancellation;
#[path = "bip448_transfer_sender/restart.rs"]
mod restart;
#[path = "bip448_transfer_sender/retarget.rs"]
mod retarget;
#[path = "bip448_transfer_sender/rotation.rs"]
mod rotation;
#[path = "bip448_transfer_sender/support.rs"]
mod support;

#[tokio::test]
#[ignore = "internal child entry point for the BIP448 transfer restart test"]
async fn bip448_transfer_restart_child() -> Result<()> {
    restart::bip448_transfer_restart_child().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_transfer_survives_signing_and_upload_restarts() -> Result<()> {
    restart::bip448_transfer_survives_signing_and_upload_restarts().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_sender_finishes_after_receiver_rotates_auth_key() -> Result<()> {
    rotation::bip448_sender_finishes_after_receiver_rotates_auth_key().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_retarget_before_signing_reuses_next_state() -> Result<()> {
    retarget::bip448_retarget_before_signing_reuses_next_state().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_retarget_after_signing_preserves_superseded_history() -> Result<()> {
    retarget::bip448_retarget_after_signing_preserves_superseded_history().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_cancel_returns_coin_and_allows_real_transfer() -> Result<()> {
    cancellation::bip448_cancel_returns_coin_and_allows_real_transfer().await
}
