mod common;

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use bitcoin::{hashes::Hash, sighash::TemplateHash, PrivateKey};
use mercurylib::{
    bip448_statechain::{
        signing::{CsfsSigningRole, CsfsSigningSession},
        signing_api::{
            Bip448CompressedPublicKey, Bip448KeyGeneration,
            Bip448LockboxPartialSignatureRequestPayload, Bip448LockboxSignFirstRequestPayload,
            Bip448OperationId, Bip448PartialSignatureRequestPayload, Bip448ProtocolVersionV1,
            Bip448SchnorrSignature, Bip448SecretScalar, Bip448SignFirstRequestPayload,
            Bip448SignatureCount, Bip448StatechainId,
        },
    },
    transfer::receiver::{
        bip448_transfer_unlock_auth_digest, Bip448TransferUnlockRole,
        TransferReceiverRequestPayloadV1, TransferUnlockRequestPayload,
    },
    transfer::sender::{
        bip448_transfer_update_msg_auth_digest, TransferSenderResponsePayload,
        TransferUpdateMsgRequestPayload,
    },
    withdraw::WithdrawCompletePayload,
};
use reqwest::StatusCode;
use secp256k1::{
    musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId, PublicNonce},
    rand, schnorr, KeyPair, PublicKey, Secp256k1, SecretKey,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use tokio::{
    sync::Barrier,
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};

use crate::common::{lockbox, mercury};
#[path = "lockbox_compatibility/concurrency.rs"]
mod concurrency;
#[path = "lockbox_compatibility/deletion.rs"]
mod deletion;
#[path = "lockbox_compatibility/deterministic.rs"]
mod deterministic;
#[path = "lockbox_compatibility/keyupdate.rs"]
mod keyupdate;
#[path = "lockbox_compatibility/keyupdate_fences.rs"]
mod keyupdate_fences;
#[path = "lockbox_compatibility/mercury_routes.rs"]
mod mercury_routes;
#[path = "lockbox_compatibility/schema.rs"]
mod schema;
#[path = "lockbox_compatibility/signing.rs"]
mod signing;
#[path = "lockbox_compatibility/support.rs"]
mod support;
#[path = "lockbox_compatibility/validation.rs"]
mod validation;

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn get_public_key_requires_statechain_id() -> Result<()> {
    validation::get_public_key_requires_statechain_id().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_get_public_nonce_requires_existing_statechain() -> Result<()> {
    validation::bip448_get_public_nonce_requires_existing_statechain().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_get_partial_signature_validates_session_length() -> Result<()> {
    validation::bip448_get_partial_signature_validates_session_length().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_get_partial_signature_requires_existing_nonce_state() -> Result<()> {
    validation::bip448_get_partial_signature_requires_existing_nonce_state().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_validates_t2_and_x1_lengths() -> Result<()> {
    validation::keyupdate_validates_t2_and_x1_lengths().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_requires_existing_statechain() -> Result<()> {
    validation::keyupdate_requires_existing_statechain().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn signature_count_for_missing_statechain_returns_not_found() -> Result<()> {
    validation::signature_count_for_missing_statechain_returns_not_found().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count(
) -> Result<()> {
    signing::bip448_signing_lifecycle_returns_a_valid_partial_signature_and_increments_signature_count().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn bip448_nonce_state_replays_after_restart_and_rejects_conflicting_challenge() -> Result<()>
{
    signing::bip448_nonce_state_replays_after_restart_and_rejects_conflicting_challenge().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_signing_routes_nonce_and_partial_signature_through_lockbox() -> Result<()> {
    signing::mercury_signing_routes_nonce_and_partial_signature_through_lockbox().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_returns_the_expected_server_pubkey_and_statechain_remains_usable() -> Result<()>
{
    keyupdate::keyupdate_returns_the_expected_server_pubkey_and_statechain_remains_usable().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn keyupdate_state_survives_lockbox_restart() -> Result<()> {
    keyupdate::keyupdate_state_survives_lockbox_restart().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_transfer_receiver_routes_keyupdate_to_lockbox() -> Result<()> {
    keyupdate::mercury_transfer_receiver_routes_keyupdate_to_lockbox().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn delete_statechain_is_idempotent_and_deleted_statechain_cannot_be_used() -> Result<()> {
    deletion::delete_statechain_is_idempotent_and_deleted_statechain_cannot_be_used().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_withdraw_complete_preserves_rows_when_lockbox_delete_fails() -> Result<()> {
    deletion::mercury_withdraw_complete_preserves_rows_when_lockbox_delete_fails().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn deterministic_lockbox_vectors_match_golden_outputs() -> Result<()> {
    deterministic::deterministic_lockbox_vectors_match_golden_outputs().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn parallel_statechains_can_sign_independently() -> Result<()> {
    concurrency::parallel_statechains_can_sign_independently().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn concurrent_exact_bip448_partial_replays_increment_signature_count_once() -> Result<()> {
    concurrency::concurrent_exact_bip448_partial_replays_increment_signature_count_once().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn concurrent_keyupdate_replays_return_the_same_server_pubkey() -> Result<()> {
    concurrency::concurrent_keyupdate_replays_return_the_same_server_pubkey().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_deposit_init_creates_a_lockbox_backed_statechain() -> Result<()> {
    mercury_routes::mercury_deposit_init_creates_a_lockbox_backed_statechain().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn mercury_statechain_info_returns_ordered_bip448_rows_and_transfer_clears_them() -> Result<()>
{
    mercury_routes::mercury_statechain_info_returns_ordered_bip448_rows_and_transfer_clears_them()
        .await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn fresh_lockbox_schema_has_only_bip448_nonce_state_columns() -> Result<()> {
    schema::fresh_lockbox_schema_has_only_bip448_nonce_state_columns().await
}

#[tokio::test]
#[ignore = "requires lockbox docker stack"]
async fn fresh_mercury_schema_has_exact_bip448_tables_and_lease_columns() -> Result<()> {
    schema::fresh_mercury_schema_has_exact_bip448_tables_and_lease_columns().await
}
