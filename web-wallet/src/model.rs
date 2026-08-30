use std::collections::BTreeMap;

use mercurylib::{
    bip448_statechain::{
        signing_api::Bip448PartialSignatureRequestPayload,
        storage::{Bip448RecoveryTemplateRole, Bip448StatechainRecord},
    },
    transfer::{
        bip448::{Bip448StateHistoryEntry, Bip448TransferMsg},
        receiver::TransferReceiverRequestPayloadV1,
    },
    wallet::{Activity, Coin, Wallet},
};
use serde::{Deserialize, Serialize};

pub const SNAPSHOT_VERSION: u32 = 1;
pub const DEFAULT_STATECHAIN_ENDPOINT: &str = "https://bip448.cash";
pub const DEFAULT_CHAIN_ENDPOINT: &str = "https://mutinynet.com/api";
pub const DEFAULT_EXPLORER_ENDPOINT: &str = "https://mutinynet.com";
pub const DEFAULT_ENCLAVIA_PROXY_ENDPOINT: &str =
    "https://11b69774-3ba1-4911-8897-ab2380488cdb.enclaves.beta.enclavia.io";
pub const DEFAULT_ENCLAVIA_PCR0: &str =
    "4adae8229127fb7e2403ab0651fd6bc5f13cf72c95938a3b4d5fbf2f86f5529f12b97c124a7eb1832ae223d48aafc737";
pub const DEFAULT_ENCLAVIA_PCR1: &str =
    "20167032afc54a578d7fa4509dd79e880d504a9d933d820d55a45a8a06880843176a9be7c6ddd375efc5557c2ad8370d";
pub const DEFAULT_ENCLAVIA_PCR2: &str =
    "624a5ff2de7daa1a1105837719d0dfc870ccca4ad519a2bc4a96fe53c368b9cd20b1e934f24f36236dd59ae5b3ab997e";
pub const NETWORK: &str = "signet";
pub const CONFIRMATION_TARGET: u32 = 2;
pub const MIN_DEPOSIT_AMOUNT: u32 = 1_000;
pub const MIN_FEE_RATE: f64 = 0.1;
pub const MAX_FEE_RATE: f64 = 10.0;
pub const STORAGE_KEY: &str = "mercury-bip448-mutinynet-browser-wallet-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentConfig {
    pub mercury_url: String,
    pub chain_url: String,
    pub explorer_url: String,
    #[serde(default)]
    pub enclavia_proxy_url: String,
    #[serde(default)]
    pub expected_pcr0: String,
    #[serde(default)]
    pub expected_pcr1: String,
    #[serde(default)]
    pub expected_pcr2: String,
    #[serde(default)]
    pub enclavia_debug: bool,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            mercury_url: DEFAULT_STATECHAIN_ENDPOINT.to_string(),
            chain_url: DEFAULT_CHAIN_ENDPOINT.to_string(),
            explorer_url: DEFAULT_EXPLORER_ENDPOINT.to_string(),
            enclavia_proxy_url: DEFAULT_ENCLAVIA_PROXY_ENDPOINT.to_string(),
            expected_pcr0: DEFAULT_ENCLAVIA_PCR0.to_string(),
            expected_pcr1: DEFAULT_ENCLAVIA_PCR1.to_string(),
            expected_pcr2: DEFAULT_ENCLAVIA_PCR2.to_string(),
            enclavia_debug: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBip448Signing {
    pub funding_txid: String,
    pub funding_vout: u32,
    pub funding_value_sats: u64,
    pub state_locktime: u32,
    pub update_template_hash: String,
    pub settlement_template_hash: String,
    pub signing_id: String,
    pub client_secret_nonce: String,
    pub client_public_nonce: String,
    pub blinding_factor: String,
    pub server_public_nonce: Option<String>,
    #[serde(default)]
    pub second_armed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeposit {
    pub token_id: String,
    pub amount: u32,
    pub coin: Coin,
    #[serde(default)]
    pub funding_confirmations: u32,
    #[serde(default)]
    pub signing: Option<PendingBip448Signing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryFeeUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub confirmations: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOutgoingTransfer {
    pub statechain_id: String,
    pub recipient_address: String,
    pub receiver_user_pubkey: String,
    pub recipient_auth_pubkey: String,
    #[serde(default)]
    pub x1: Option<String>,
    #[serde(default)]
    pub signing: Option<PendingBip448Signing>,
    #[serde(default)]
    pub update_signature: Option<String>,
    #[serde(default)]
    pub message: Option<Bip448TransferMsg>,
    #[serde(default)]
    pub encrypted_message: Option<String>,
    #[serde(default)]
    pub batch_id: Option<String>,
    #[serde(default)]
    pub acknowledge_cooperative_duplicates: bool,
    #[serde(default = "default_transfer_intent_kind")]
    pub intent_kind: String,
    #[serde(default)]
    pub predecessor_message: Option<Bip448TransferMsg>,
    pub delivered: bool,
}

fn default_transfer_intent_kind() -> String {
    "user_transfer".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingIncomingTransfer {
    pub receiver_auth_pubkey: String,
    pub encrypted_message: String,
    pub operation_id: String,
    #[serde(default)]
    pub receiver_request: Option<TransferReceiverRequestPayloadV1>,
    #[serde(default)]
    pub expected_server_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryAttempt {
    pub statechain_id: String,
    pub role: Bip448RecoveryTemplateRole,
    pub parent_tx_hex: String,
    pub child_tx_hex: String,
    pub parent_txid: String,
    pub child_txid: String,
    pub package_fee_sats: u64,
    pub package_vbytes: usize,
    pub package_feerate_sat_per_vbyte: f64,
    pub status: String,
    #[serde(default)]
    pub parent_confirmations: u32,
    #[serde(default)]
    pub response: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalKind {
    Canonical,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalPhase {
    Prepared,
    FirstArmed,
    NonceStored,
    SecondArmed,
    Signed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalBroadcastStatus {
    NotBroadcast,
    Accepted,
    Confirmed,
    NeedsRebroadcast,
    Conflicting,
    Conflicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalCompletionStatus {
    NotApplicable,
    Open,
    CloseArmed,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FundingBinding {
    pub statechain_id: String,
    pub binding_index: u32,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub observation_status: String,
    pub funding_height: Option<u32>,
    pub spend_txid: Option<String>,
    pub spend_height: Option<u32>,
    pub owner_user_pubkey: String,
    pub owner_state_number: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalAttempt {
    pub statechain_id: String,
    pub binding_index: u32,
    pub kind: WithdrawalKind,
    pub owner_user_pubkey: String,
    pub owner_state_number: u32,
    pub source_txid: String,
    pub source_vout: u32,
    pub source_value_sats: u64,
    pub source_script_pubkey: String,
    pub destination_address: String,
    pub destination_script_pubkey: String,
    pub fee_rate_sat_per_vbyte: f64,
    pub fee_sats: u64,
    pub lock_time: u32,
    pub unsigned_tx_hex: String,
    pub signing_id: String,
    pub signed_statechain_id: String,
    pub client_secret_nonce: String,
    pub client_public_nonce: String,
    pub blinding_factor: String,
    pub server_public_nonce: Option<String>,
    pub message_hex: Option<String>,
    pub output_pubkey: Option<String>,
    pub client_partial_sig: Option<String>,
    pub encoded_session: Option<String>,
    pub sign_second_payload: Option<Bip448PartialSignatureRequestPayload>,
    pub server_partial_sig: Option<String>,
    pub aggregate_signature: Option<String>,
    pub signed_tx_hex: Option<String>,
    pub txid: Option<String>,
    pub phase: WithdrawalPhase,
    pub broadcast_status: WithdrawalBroadcastStatus,
    pub completion_status: WithdrawalCompletionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveVerification {
    #[serde(default)]
    pub verification_method: String,
    pub statechain_id: String,
    pub verified_at: String,
    pub challenge: String,
    pub server_pubkey: String,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub trust_model: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveRuntimeProof {
    #[serde(default)]
    pub verification_method: String,
    pub checked_at: String,
    pub endpoint: String,
    pub mode: String,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub authentication: String,
    pub trust_model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub snapshot_version: u32,
    pub wallet: Wallet,
    pub deployment: DeploymentConfig,
    #[serde(default)]
    pub statechains: Vec<Bip448StatechainRecord>,
    #[serde(default)]
    pub state_histories: BTreeMap<String, Vec<Bip448StateHistoryEntry>>,
    #[serde(default)]
    pub pending_deposits: Vec<PendingDeposit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cancelled_deposits: Vec<PendingDeposit>,
    #[serde(default)]
    pub recovery_attempts: Vec<RecoveryAttempt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_fee_utxos: Vec<RecoveryFeeUtxo>,
    #[serde(default)]
    pub enclave_verification: Option<EnclaveVerification>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enclave_verifications: Vec<EnclaveVerification>,
    #[serde(default)]
    pub pending_outgoing_transfer: Option<PendingOutgoingTransfer>,
    #[serde(default)]
    pub pending_incoming_transfer: Option<PendingIncomingTransfer>,
    #[serde(default)]
    pub enclave_runtime_proof: Option<EnclaveRuntimeProof>,
    #[serde(default)]
    pub funding_bindings: Vec<FundingBinding>,
    #[serde(default)]
    pub withdrawal_attempts: Vec<WithdrawalAttempt>,
}

impl WalletSnapshot {
    pub fn statechain(&self, statechain_id: &str) -> Option<&Bip448StatechainRecord> {
        self.statechains
            .iter()
            .find(|record| record.statechain_id == statechain_id)
    }

    pub fn state_history(&self, statechain_id: &str) -> Option<&[Bip448StateHistoryEntry]> {
        self.state_histories.get(statechain_id).map(Vec::as_slice)
    }

    pub fn recovery_attempt(
        &self,
        statechain_id: &str,
        role: Bip448RecoveryTemplateRole,
    ) -> Option<&RecoveryAttempt> {
        self.recovery_attempts
            .iter()
            .find(|attempt| attempt.statechain_id == statechain_id && attempt.role == role)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletView {
    pub network: &'static str,
    pub deployment: DeploymentConfig,
    pub recovery_fee_address: String,
    pub recovery_fee_utxo: Option<RecoveryFeeUtxoView>,
    pub coins: Vec<CoinView>,
    pub activities: Vec<Activity>,
    pub pending_deposits: Vec<PendingDepositView>,
    pub recovery_attempts: Vec<RecoveryAttempt>,
    pub enclave_verifications: Vec<EnclaveVerification>,
    pub receive_addresses: Vec<TransferAddressView>,
    pub pending_outgoing_transfer: Option<PendingOutgoingTransferView>,
    pub pending_incoming: bool,
    pub enclave_runtime_proof: Option<EnclaveRuntimeProof>,
    pub withdrawal_attempts: Vec<WithdrawalAttempt>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingDepositView {
    pub statechain_id: String,
    pub address: String,
    pub amount: u32,
    pub funding_txid: String,
    pub confirmation_blocks_remaining: u32,
    pub signing_started: bool,
    pub second_armed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryFeeUtxoView {
    pub txid: String,
    pub amount_sats: u64,
    pub confirmation_blocks_remaining: u32,
    pub ready: bool,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferAddressView {
    pub address: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingOutgoingTransferView {
    pub statechain_id: String,
    pub recipient_address: String,
    pub status: String,
    pub batch_id: Option<String>,
    pub intent_kind: String,
    pub acknowledge_cooperative_duplicates: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateView {
    pub duplicate_index: u32,
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub observation_status: String,
    pub sweep_phase: Option<WithdrawalPhase>,
    pub broadcast_status: Option<WithdrawalBroadcastStatus>,
    pub spend_txid: Option<String>,
    pub cooperative_only: bool,
    pub server_dependent: bool,
    pub can_sweep: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoinView {
    pub statechain_id: String,
    pub amount: u64,
    pub status: String,
    pub deposit_address: String,
    pub funding_txid: String,
    pub funding_vout: u32,
    pub latest_state_number: u32,
    pub challenge_delay_blocks: u16,
    pub update_txid: String,
    pub settlement_txid: String,
    pub update_tx_hex: String,
    pub settlement_tx_hex: String,
    pub update_confirmations: u32,
    pub settlement_confirmations: u32,
    pub settlement_blocks_remaining: u32,
    pub can_start_unilateral_exit: bool,
    pub can_settle_unilateral_exit: bool,
    pub can_send_offchain: bool,
    pub offchain_transfer_status: Option<String>,
    pub exit_only: bool,
    pub can_withdraw: bool,
    pub can_cancel_transfer: bool,
    pub withdrawal_status: Option<String>,
    pub duplicates: Vec<DuplicateView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositResult {
    pub statechain_id: String,
    pub deposit_address: String,
    pub amount: u32,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferAddressResult {
    pub address: String,
    pub batch_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatecoinSendResult {
    pub statechain_id: String,
    pub recipient_address: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCancellationResult {
    pub statechain_id: String,
    pub state_number: u32,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatecoinReceiveResult {
    pub checked_addresses: usize,
    pub received_statechain_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalResult {
    pub statechain_id: String,
    pub duplicate_index: u32,
    pub source_outpoint: String,
    pub amount_sats: u64,
    pub destination_address: String,
    pub txid: String,
    pub broadcast_status: WithdrawalBroadcastStatus,
    pub exit_only: bool,
    pub statechain_closed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    pub accepted_statechain_ids: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitResult {
    pub statechain_id: String,
    pub role: String,
    pub parent_txid: String,
    pub child_txid: String,
    pub package_fee_sats: u64,
    pub package_vbytes: usize,
    pub package_feerate_sat_per_vbyte: f64,
    pub response: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn javascript_visible_nested_fields_are_camel_case() {
        let deployment = serde_json::to_value(DeploymentConfig::default()).unwrap();
        assert!(deployment.get("mercuryUrl").is_some());
        assert_eq!(deployment["enclaviaDebug"], false);
        assert!(deployment.get("mercury_url").is_none());

        let attempt = RecoveryAttempt {
            statechain_id: "statechain".to_string(),
            role: Bip448RecoveryTemplateRole::FundingUpdate,
            parent_tx_hex: "00".to_string(),
            child_tx_hex: "00".to_string(),
            parent_txid: "11".repeat(32),
            child_txid: "22".repeat(32),
            package_fee_sats: 1,
            package_vbytes: 2,
            package_feerate_sat_per_vbyte: 0.5,
            status: "prepared".to_string(),
            parent_confirmations: 3,
            response: None,
        };
        let attempt = serde_json::to_value(attempt).unwrap();
        assert_eq!(attempt["statechainId"], "statechain");
        assert_eq!(attempt["parentConfirmations"], 3);
    }
}
