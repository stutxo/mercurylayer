mod common;

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    absolute, blockdata::opcodes::all::OP_CLTV, consensus::encode, script::Builder,
    taproot::ControlBlock, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
};
use common::bip448_regtest::{
    fund_address_output, fund_p2a_fee_input, FEE_INPUT_AMOUNT_SATS, FUNDING_AMOUNT_SATS,
};
use mercurylib::bip448_statechain::{
    deposit::BIP448_COIN_PROTOCOL,
    package::{
        build_anchor_cpfp_package, build_latest_state_recovery_package, Bip448CpfpFeeInput,
        Bip448RecoveryPackage,
    },
    signing::csfs_script_witness,
    storage::{Bip448RecoveryTemplateRole, Bip448StatechainRecord},
    transaction::{self, pay_to_anchor_script, FeePolicy},
};
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use secp256k1::schnorr;
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, Row};
#[path = "bip448_deposit/discovery.rs"]
mod discovery;
#[path = "bip448_deposit/recovery.rs"]
mod recovery;
#[path = "bip448_deposit/restart.rs"]
mod restart;
#[path = "bip448_deposit/stale_state.rs"]
mod stale_state;
#[path = "bip448_deposit/support.rs"]
mod support;
#[path = "bip448_deposit/transfer.rs"]
mod transfer;

#[tokio::test]
#[ignore = "internal child entry point for the BIP448 process-restart test"]
async fn bip448_client_restart_child() -> Result<()> {
    restart::bip448_client_restart_child().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_deposit_survives_client_process_restarts() -> Result<()> {
    restart::bip448_deposit_survives_client_process_restarts().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_deposit_recovers_through_update_and_settlement_packages() -> Result<()> {
    recovery::bip448_deposit_recovers_through_update_and_settlement_packages().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_client_submitter_broadcasts_recovery_package() -> Result<()> {
    recovery::bip448_client_submitter_broadcasts_recovery_package().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_owner_recovery_survives_restart_mid_broadcast() -> Result<()> {
    recovery::bip448_owner_recovery_survives_restart_mid_broadcast().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_cli_wallet_funded_and_keyless_recovery_packages() -> Result<()> {
    recovery::bip448_cli_wallet_funded_and_keyless_recovery_packages().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_transfer_address_reuse_accepts_two_distinct_statechains() -> Result<()> {
    transfer::bip448_transfer_address_reuse_accepts_two_distinct_statechains().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_one_hop_transfer_accepts_and_recovers_state_two() -> Result<()> {
    transfer::bip448_one_hop_transfer_accepts_and_recovers_state_two().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_two_hop_transfer_accepts_and_recovers_state_three() -> Result<()> {
    transfer::bip448_two_hop_transfer_accepts_and_recovers_state_three().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_ten_hop_transfer_advances_to_state_eleven() -> Result<()> {
    transfer::bip448_ten_hop_transfer_advances_to_state_eleven().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_same_wallet_second_hop_advances_to_state_three() -> Result<()> {
    transfer::bip448_same_wallet_second_hop_advances_to_state_three().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_same_wallet_transfer_advances_the_accepted_record_to_state_two() -> Result<()> {
    transfer::bip448_same_wallet_transfer_advances_the_accepted_record_to_state_two().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_latest_state_fast_forwards_over_confirmed_old_state() -> Result<()> {
    stale_state::bip448_latest_state_fast_forwards_over_confirmed_old_state().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Bitcoin Core descriptor activity RPCs"]
async fn bip448_discovery_cursor_reorg_and_restart_state() -> Result<()> {
    discovery::bip448_discovery_cursor_reorg_and_restart_state().await
}
