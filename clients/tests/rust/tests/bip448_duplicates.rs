#[path = "common/mod.rs"]
mod common;

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    str::FromStr,
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use bitcoin::{
    hashes::{sha256, Hash},
    Address, OutPoint, Txid,
};
use common::bip448_regtest::{
    fund_address_output, fund_p2a_fee_input, FundingOutput, FUNDING_AMOUNT_SATS,
};
use mercurylib::{
    bip448_statechain::{
        package::{
            build_anchor_cpfp_package, build_latest_state_recovery_package, Bip448CpfpFeeInput,
            Bip448RecoveryPackage,
        },
        signing_api::{Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload},
        storage::Bip448RecoveryTemplateRole,
        transaction::{self, FeePolicy},
        withdraw::{
            aggregate_bip448_keypath_signature, build_bip448_withdrawal_signing_data,
            create_bip448_keypath_nonces, finalize_bip448_keypath_transaction,
        },
    },
    transfer::bip448::Bip448TransferMsg,
    wallet::Coin,
};
use mercuryrustlib::{
    bip448_funding::{
        Bip448BindingObservation, Bip448BindingRole, Bip448BroadcastStatus, Bip448CompletionStatus,
        Bip448FundingBinding, Bip448ObservationStatus, Bip448OwnershipStatus, Bip448SyncReport,
        Bip448TransferIntentKind, Bip448WithdrawalAttempt, Bip448WithdrawalAttemptKind,
        Bip448WithdrawalPhase,
    },
    client_config::ClientConfig,
    sqlite_manager::Bip448ScanCursor,
    CoinStatus,
};
use reqwest::{Client, StatusCode};
use secp256k1::{PublicKey, Secp256k1};
#[path = "bip448_duplicates/canonical_close.rs"]
mod canonical_close;
#[path = "bip448_duplicates/dust.rs"]
mod dust;
#[path = "bip448_duplicates/inventory.rs"]
mod inventory;
#[path = "bip448_duplicates/post_acceptance.rs"]
mod post_acceptance;
#[path = "bip448_duplicates/repeated_funding.rs"]
mod repeated_funding;
#[path = "bip448_duplicates/restart.rs"]
mod restart;
#[path = "bip448_duplicates/same_wallet.rs"]
mod same_wallet;
#[path = "bip448_duplicates/support.rs"]
mod support;
#[path = "bip448_duplicates/transfer.rs"]
mod transfer;

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_repeated_funding_preserves_canonical_state_and_signature_count() -> Result<()> {
    repeated_funding::bip448_repeated_funding_preserves_canonical_state_and_signature_count().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_inventory_is_stable_across_restart_reorg_and_spend() -> Result<()> {
    inventory::bip448_duplicate_inventory_is_stable_across_restart_reorg_and_spend().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary() -> Result<()> {
    restart::bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last() -> Result<()> {
    canonical_close::bip448_duplicate_sweeps_are_one_input_and_canonical_closes_last().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_receiver_post_acceptance_duplicate_rescan_is_retryable() -> Result<()> {
    post_acceptance::bip448_receiver_post_acceptance_duplicate_rescan_is_retryable().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers() -> Result<()> {
    transfer::bip448_duplicate_transfer_requires_ack_and_receiver_rediscovers().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_same_wallet_cancel_reassigns_current_owner() -> Result<()> {
    same_wallet::bip448_duplicate_same_wallet_cancel_reassigns_current_owner().await
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_duplicate_dust_remains_visible_and_blocks_close() -> Result<()> {
    dust::bip448_duplicate_dust_remains_visible_and_blocks_close().await
}
