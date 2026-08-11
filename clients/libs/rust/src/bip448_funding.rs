use std::{fmt, str::FromStr};

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    consensus::{deserialize, serialize},
    BlockHash, Transaction, Txid,
};
use mercurylib::bip448_statechain::signing_api::{
    Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload,
};
use secp256k1::{musig::Session as MusigSession, PublicKey, Scalar, SecretKey, XOnlyPublicKey};
use serde::{
    de::{DeserializeOwned, Error as DeError, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

pub const BIP448_MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;
pub const BIP448_ONE_INPUT_ONE_OUTPUT_VBYTES: u64 = 112;

const BIP448_MUSIG_SESSION_SERIALIZED_SIZE: usize = 133;
const BIP448_MUSIG_SESSION_MAGIC: [u8; 4] = [0x9d, 0xed, 0xe9, 0x17];
const BIP448_MUSIG_FINAL_NONCE_RANGE: std::ops::Range<usize> = 5..37;
const BIP448_MUSIG_SCALAR_RANGES: [std::ops::Range<usize>; 3] = [37..69, 69..101, 101..133];

fn decode_bip448_full_musig_session(encoded_session: &str) -> Result<MusigSession> {
    require_canonical_hex(encoded_session, Some(BIP448_MUSIG_SESSION_SERIALIZED_SIZE))?;
    let session_bytes: [u8; BIP448_MUSIG_SESSION_SERIALIZED_SIZE] = hex::decode(encoded_session)?
        .try_into()
        .map_err(|_| anyhow!("invalid BIP448 full MuSig session length"))?;

    // `Session::from_slice` reconstructs the checked dependency's legacy
    // typed representation from a fixed array. Validate that representation
    // before invoking an operation that expects its internal cache marker.
    if session_bytes[..BIP448_MUSIG_SESSION_MAGIC.len()] != BIP448_MUSIG_SESSION_MAGIC
        || !matches!(session_bytes[4], 0 | 1)
    {
        return Err(anyhow!("invalid BIP448 full MuSig session encoding"));
    }
    let final_nonce: [u8; 32] = session_bytes[BIP448_MUSIG_FINAL_NONCE_RANGE]
        .try_into()
        .map_err(|_| anyhow!("invalid BIP448 full MuSig final nonce length"))?;
    XOnlyPublicKey::from_byte_array(final_nonce)
        .context("invalid BIP448 full MuSig final nonce")?;
    for scalar_range in BIP448_MUSIG_SCALAR_RANGES {
        let scalar: [u8; 32] = session_bytes[scalar_range]
            .try_into()
            .map_err(|_| anyhow!("invalid BIP448 full MuSig scalar length"))?;
        Scalar::from_be_bytes(scalar)
            .map_err(|_| anyhow!("invalid BIP448 full MuSig scalar encoding"))?;
    }

    let session = MusigSession::from_slice(session_bytes);
    if session.serialize() != session_bytes {
        return Err(anyhow!("BIP448 full MuSig session did not round-trip"));
    }
    Ok(session)
}

pub(crate) fn derive_bip448_blinded_session(encoded_session: &str) -> Result<String> {
    let session = decode_bip448_full_musig_session(encoded_session)?;
    Ok(hex::encode(
        session.remove_fin_nonce_from_session().serialize(),
    ))
}

pub(crate) fn require_bip448_session_relationship(
    encoded_session: &str,
    blinded_session: &str,
) -> Result<()> {
    let expected_blinded_session = derive_bip448_blinded_session(encoded_session)?;
    require_canonical_hex(blinded_session, Some(BIP448_MUSIG_SESSION_SERIALIZED_SIZE))?;
    if hex::decode(blinded_session)? != hex::decode(expected_blinded_session)? {
        return Err(anyhow!(
            "BIP448 blinded MuSig session does not derive from the persisted full session"
        ));
    }
    Ok(())
}

pub fn bip448_one_output_fee_and_value(
    source_value_sats: u64,
    fee_rate_sat_per_vbyte: f64,
    destination_dust_sats: u64,
) -> Result<(u64, u64)> {
    if source_value_sats > BIP448_MAX_MONEY_SATS
        || !fee_rate_sat_per_vbyte.is_finite()
        || fee_rate_sat_per_vbyte <= 0.0
    {
        return Err(anyhow!("invalid BIP448 one-output fee inputs"));
    }
    let fee = 112.0_f64 * fee_rate_sat_per_vbyte;
    if !fee.is_finite() || fee >= 18_446_744_073_709_551_616.0_f64 {
        return Err(anyhow!("BIP448 one-output fee exceeds the u64 domain"));
    }
    let fee_sats = fee
        .ceil()
        .to_string()
        .parse::<u64>()
        .context("BIP448 one-output fee is not a checked u64")?;
    let output_value = source_value_sats
        .checked_sub(fee_sats)
        .ok_or_else(|| anyhow!("BIP448 fee exceeds the source value"))?;
    if output_value < destination_dust_sats {
        return Err(anyhow!("BIP448 destination output is below dust"));
    }
    Ok((fee_sats, output_value))
}

macro_rules! parsed_enum {
    ($name:ident { $($variant:ident => $literal:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $literal),+
                }
            }

            pub fn parse(value: &str) -> Result<Self> {
                value.parse()
            }
        }

        impl FromStr for $name {
            type Err = anyhow::Error;

            fn from_str(value: &str) -> Result<Self> {
                match value {
                    $($literal => Ok(Self::$variant),)+
                    _ => Err(anyhow!(concat!("invalid ", stringify!($name), " literal: {}"), value)),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

parsed_enum!(Bip448BindingRole {
    Canonical => "Canonical",
    Duplicate => "Duplicate",
});

parsed_enum!(Bip448ObservationStatus {
    Mempool => "Mempool",
    Unconfirmed => "Unconfirmed",
    Confirmed => "Confirmed",
    SpentMempool => "SpentMempool",
    SpentUnconfirmed => "SpentUnconfirmed",
    SpentConfirmed => "SpentConfirmed",
    Absent => "Absent",
});

parsed_enum!(Bip448OwnershipStatus {
    Current => "Current",
    Previous => "Previous",
});

parsed_enum!(Bip448WithdrawalAttemptKind {
    Duplicate => "Duplicate",
    Canonical => "Canonical",
});

parsed_enum!(Bip448WithdrawalPhase {
    Prepared => "Prepared",
    FirstArmed => "FirstArmed",
    NonceStored => "NonceStored",
    SecondArmed => "SecondArmed",
    Signed => "Signed",
});

parsed_enum!(Bip448BroadcastStatus {
    NotBroadcast => "NotBroadcast",
    Accepted => "Accepted",
    Confirmed => "Confirmed",
    NeedsRebroadcast => "NeedsRebroadcast",
    Conflicting => "Conflicting",
    Conflicted => "Conflicted",
});

parsed_enum!(Bip448CompletionStatus {
    NotApplicable => "NotApplicable",
    Open => "Open",
    CloseArmed => "CloseArmed",
    Closed => "Closed",
});

parsed_enum!(Bip448TransferIntentKind {
    UserTransfer => "UserTransfer",
    Cancellation => "Cancellation",
});

parsed_enum!(Bip448TransferIntentActivityStatus {
    Active => "Active",
    Superseded => "Superseded",
});

parsed_enum!(Bip448TransferIntentPhase {
    Prepared => "Prepared",
    SenderArmed => "SenderArmed",
    X1Stored => "X1Stored",
    SenderFinished => "SenderFinished",
    ReceiverAccepted => "ReceiverAccepted",
});

parsed_enum!(Bip448TransferStateSigningPhase {
    NotStarted => "NotStarted",
    FirstArmed => "FirstArmed",
    NonceStored => "NonceStored",
    SecondArmed => "SecondArmed",
    Signed => "Signed",
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448FundingBinding {
    pub wallet_name: String,
    pub statechain_id: String,
    pub binding_index: u32,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey: String,
    pub role: Bip448BindingRole,
    pub observation_status: Bip448ObservationStatus,
    pub funding_height: Option<u32>,
    pub spend_txid: Option<String>,
    pub spend_height: Option<u32>,
    pub last_scanned_height: u32,
    pub owner_user_pubkey: String,
    pub owner_state_number: u32,
    pub ownership_status: Bip448OwnershipStatus,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448BindingObservation {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey: String,
    pub observation_status: Bip448ObservationStatus,
    pub funding_height: Option<u32>,
    pub spend_txid: Option<String>,
    pub spend_height: Option<u32>,
    pub last_scanned_height: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bip448WithdrawalAttempt {
    pub wallet_name: String,
    pub statechain_id: String,
    pub binding_index: u32,
    pub attempt_kind: Bip448WithdrawalAttemptKind,
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
    pub sign_first_payload_json: String,
    pub client_secret_nonce: String,
    pub client_public_nonce: String,
    pub blinding_factor: String,
    pub server_public_nonce: Option<String>,
    pub message_hex: Option<String>,
    pub output_pubkey: Option<String>,
    pub client_partial_sig: Option<String>,
    pub encoded_session: Option<String>,
    pub sign_second_payload_json: Option<String>,
    pub server_partial_sig: Option<String>,
    pub aggregate_signature: Option<String>,
    pub signed_tx_hex: Option<String>,
    pub txid: Option<String>,
    pub phase: Bip448WithdrawalPhase,
    pub broadcast_status: Bip448BroadcastStatus,
    pub completion_status: Bip448CompletionStatus,
    pub closing_tip_height: Option<u32>,
    pub closing_tip_hash: Option<String>,
    pub closing_bindings_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448TransferIntent {
    pub wallet_name: String,
    pub statechain_id: String,
    pub intent_id: String,
    pub predecessor_intent_id: Option<String>,
    pub activity_status: Bip448TransferIntentActivityStatus,
    pub intent_kind: Bip448TransferIntentKind,
    pub acknowledge_cooperative_duplicates: bool,
    pub recipient_address: String,
    pub receiver_user_pubkey: String,
    pub recipient_auth_pubkey: String,
    pub batch_id: Option<String>,
    pub sender_signed_statechain_id: String,
    pub planned_state_number: u32,
    pub expected_signature_count: u32,
    pub previous_locktime: u32,
    pub prior_pending_signing_id: Option<String>,
    pub prior_transfer_recipient_auth_pubkey: Option<String>,
    pub prior_transfer_msg_hash: Option<String>,
    pub reuse_pending: bool,
    pub reuse_signed_state: bool,
    pub clear_local_attempt: bool,
    pub generated_coin_user_pubkey: Option<String>,
    pub generated_coin_auth_pubkey: Option<String>,
    pub generated_coin_address: Option<String>,
    pub phase: Bip448TransferIntentPhase,
    pub server_x1: Option<String>,
    pub current_pending_signing_id: Option<String>,
    pub state_signing_phase: Bip448TransferStateSigningPhase,
    pub server_partial_sig: Option<String>,
    pub update_signature: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip448ClosingResolution {
    SignedAttempt {
        signing_id: String,
        sweep_txid: String,
        conflict_spend_txid: Option<String>,
    },
    IndependentSpend {
        spend_txid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448ClosingBinding {
    pub binding_index: u32,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub owner_user_pubkey: String,
    pub owner_state_number: u32,
    pub resolution: Bip448ClosingResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip448CloseBlockReason {
    ActiveTransferIntent {
        intent_id: String,
    },
    InvalidTransferIntentLineage {
        detail: String,
    },
    PendingTransferSigning,
    OutgoingTransferMessage {
        recipient_auth_pubkey: String,
    },
    CoinInTransfer,
    BindingObservation {
        binding_index: u32,
        observation_status: Bip448ObservationStatus,
    },
    AttemptPhase {
        binding_index: u32,
        phase: Bip448WithdrawalPhase,
    },
    AttemptBroadcast {
        binding_index: u32,
        broadcast_status: Bip448BroadcastStatus,
    },
    AttemptIdentity {
        binding_index: u32,
    },
    ConflictIdentity {
        binding_index: u32,
    },
    BindingOutsideFrozenSnapshot {
        binding_index: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip448CloseGate {
    Ready {
        closing_bindings: Vec<Bip448ClosingBinding>,
        closing_bindings_json: String,
    },
    Blocked {
        reasons: Vec<Bip448CloseBlockReason>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448AppliedScanRevision {
    pub script_pubkey: String,
    pub scan_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip448SyncBase {
    pub wallet_name: String,
    pub script_pubkey: String,
    pub raw_wallet_json: String,
    pub pending_deposit_rows: Vec<String>,
    pub accepted_record_rows: Vec<String>,
    pub state_history_rows: Vec<String>,
    pub cursor_rows: Vec<String>,
    pub scan_cache_rows: Vec<String>,
    pub funding_binding_rows: Vec<String>,
    pub withdrawal_attempt_rows: Vec<String>,
    pub transfer_intent_rows: Vec<String>,
    pub pending_transfer_rows: Vec<String>,
    pub outgoing_transfer_message_rows: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bip448SyncReport {
    pub tip_height: u32,
    pub tip_hash: String,
    pub bindings: Vec<Bip448FundingBinding>,
    pub attempts: Vec<Bip448WithdrawalAttempt>,
    pub applied_scan_revisions: Vec<Bip448AppliedScanRevision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip448SignatureCountExpectation {
    pub settled_count: u64,
    pub second_armed_landed_count: Option<u64>,
}

pub(crate) fn canonical_txid(value: &str) -> Result<String> {
    Ok(Txid::from_str(value)
        .context("invalid BIP448 txid")?
        .to_string())
}

pub(crate) fn require_canonical_txid(value: &str) -> Result<()> {
    if canonical_txid(value)? != value {
        return Err(anyhow!("BIP448 txid is not canonical lowercase hex"));
    }
    Ok(())
}

pub(crate) fn canonical_block_hash(value: &str) -> Result<String> {
    Ok(BlockHash::from_str(value)
        .context("invalid BIP448 block hash")?
        .to_string())
}

pub(crate) fn require_canonical_block_hash(value: &str) -> Result<()> {
    if canonical_block_hash(value)? != value {
        return Err(anyhow!("BIP448 block hash is not canonical lowercase hex"));
    }
    Ok(())
}

pub(crate) fn require_canonical_hex(value: &str, byte_length: Option<usize>) -> Result<()> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        || value.len() % 2 != 0
    {
        return Err(anyhow!("BIP448 hex value is not canonical lowercase hex"));
    }
    if byte_length.is_some_and(|length| value.len() != length.saturating_mul(2)) {
        return Err(anyhow!("BIP448 hex value has the wrong length"));
    }
    hex::decode(value).context("invalid BIP448 hex value")?;
    Ok(())
}

pub(crate) fn require_canonical_script(value: &str) -> Result<()> {
    require_canonical_hex(value, None).context("invalid BIP448 script_pubkey")
}

pub(crate) fn canonical_xonly_public_key(value: &str) -> Result<String> {
    Ok(XOnlyPublicKey::from_str(value)
        .context("invalid BIP448 x-only public key")?
        .to_string())
}

pub(crate) fn require_canonical_xonly_public_key(value: &str) -> Result<()> {
    if canonical_xonly_public_key(value)? != value {
        return Err(anyhow!(
            "BIP448 x-only public key is not canonical lowercase hex"
        ));
    }
    Ok(())
}

pub(crate) fn canonical_public_key(value: &str) -> Result<String> {
    Ok(PublicKey::from_str(value)
        .context("invalid BIP448 public key")?
        .to_string())
}

pub(crate) fn require_canonical_public_key(value: &str) -> Result<()> {
    if canonical_public_key(value)? != value {
        return Err(anyhow!(
            "BIP448 public key is not canonical lowercase compressed hex"
        ));
    }
    Ok(())
}

fn parse_canonical_json<T>(value: &str, description: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let mut deserializer = serde_json::Deserializer::from_str(value);
    let parsed =
        T::deserialize(&mut deserializer).with_context(|| format!("invalid {description} JSON"))?;
    deserializer
        .end()
        .with_context(|| format!("invalid trailing data in {description} JSON"))?;
    if serde_json::to_string(&parsed)? != value {
        return Err(anyhow!("{description} JSON is not canonical compact JSON"));
    }
    Ok(parsed)
}

pub(crate) fn parse_canonical_sign_first_payload(
    value: &str,
) -> Result<Bip448SignFirstRequestPayload> {
    parse_canonical_json(value, "BIP448 sign/first payload")
}

pub(crate) fn parse_canonical_sign_second_payload(
    value: &str,
) -> Result<Bip448PartialSignatureRequestPayload> {
    parse_canonical_json(value, "BIP448 sign/second payload")
}

pub(crate) fn validate_observation(
    status: Bip448ObservationStatus,
    funding_height: Option<u32>,
    spend_txid: Option<&str>,
    spend_height: Option<u32>,
) -> Result<()> {
    match status {
        Bip448ObservationStatus::Mempool if funding_height.is_some() => {
            return Err(anyhow!("Mempool funding observation cannot have a height"));
        }
        Bip448ObservationStatus::Unconfirmed
        | Bip448ObservationStatus::Confirmed
        | Bip448ObservationStatus::SpentUnconfirmed
        | Bip448ObservationStatus::SpentConfirmed
            if funding_height.is_none() =>
        {
            return Err(anyhow!(
                "mined BIP448 funding observation requires a funding height"
            ));
        }
        _ => {}
    }

    match status {
        Bip448ObservationStatus::SpentMempool => {
            let spend_txid = spend_txid
                .ok_or_else(|| anyhow!("spent BIP448 observation requires a spend txid"))?;
            require_canonical_txid(spend_txid)?;
            if spend_height.is_some() {
                return Err(anyhow!("mempool BIP448 spend cannot have a height"));
            }
        }
        Bip448ObservationStatus::SpentUnconfirmed | Bip448ObservationStatus::SpentConfirmed => {
            let spend_txid = spend_txid
                .ok_or_else(|| anyhow!("spent BIP448 observation requires a spend txid"))?;
            require_canonical_txid(spend_txid)?;
            if spend_height.is_none() {
                return Err(anyhow!("mined BIP448 spend requires a spend height"));
            }
        }
        _ if spend_txid.is_some() || spend_height.is_some() => {
            return Err(anyhow!(
                "unspent or absent BIP448 observation cannot have spend fields"
            ));
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn validate_binding(binding: &Bip448FundingBinding) -> Result<()> {
    require_canonical_txid(&binding.txid)?;
    require_canonical_script(&binding.script_pubkey)?;
    require_canonical_xonly_public_key(&binding.owner_user_pubkey)?;
    if binding.value_sats > BIP448_MAX_MONEY_SATS {
        return Err(anyhow!("BIP448 binding value exceeds the SQLite domain"));
    }
    if binding.owner_state_number == 0 {
        return Err(anyhow!(
            "BIP448 binding owner state number must be positive"
        ));
    }
    match (binding.binding_index, binding.role) {
        (0, Bip448BindingRole::Canonical) => {}
        (1.., Bip448BindingRole::Duplicate) => {}
        _ => return Err(anyhow!("BIP448 binding index and role disagree")),
    }
    validate_observation(
        binding.observation_status,
        binding.funding_height,
        binding.spend_txid.as_deref(),
        binding.spend_height,
    )
}

pub(crate) fn validate_binding_observation(observation: &Bip448BindingObservation) -> Result<()> {
    require_canonical_txid(&observation.txid)?;
    require_canonical_script(&observation.script_pubkey)?;
    if observation.value_sats > BIP448_MAX_MONEY_SATS {
        return Err(anyhow!("BIP448 binding value exceeds the SQLite domain"));
    }
    validate_observation(
        observation.observation_status,
        observation.funding_height,
        observation.spend_txid.as_deref(),
        observation.spend_height,
    )
}

fn option_group_is_all_some(values: &[bool]) -> bool {
    values.iter().all(|value| *value)
}

fn option_group_is_all_none(values: &[bool]) -> bool {
    values.iter().all(|value| !*value)
}

fn parse_canonical_transaction(value: &str, description: &str) -> Result<Transaction> {
    require_canonical_hex(value, None)?;
    let bytes = hex::decode(value)?;
    let transaction: Transaction =
        deserialize(&bytes).with_context(|| format!("invalid {description}"))?;
    if serialize(&transaction) != bytes {
        return Err(anyhow!("{description} is not canonical consensus encoding"));
    }
    Ok(transaction)
}

fn validate_unsigned_attempt_transaction(attempt: &Bip448WithdrawalAttempt) -> Result<Transaction> {
    let transaction =
        parse_canonical_transaction(&attempt.unsigned_tx_hex, "BIP448 unsigned transaction")?;
    let expected_output_value = attempt
        .source_value_sats
        .checked_sub(attempt.fee_sats)
        .ok_or_else(|| anyhow!("BIP448 attempt fee exceeds its source value"))?;
    if transaction.version != 2
        || transaction.lock_time.to_consensus_u32() != attempt.lock_time
        || transaction.input.len() != 1
        || transaction.output.len() != 1
        || transaction.input[0].previous_output.txid.to_string() != attempt.source_txid
        || transaction.input[0].previous_output.vout != attempt.source_vout
        || !transaction.input[0].script_sig.is_empty()
        || transaction.input[0].sequence.to_consensus_u32() != 0
        || !transaction.input[0].witness.is_empty()
        || transaction.output[0].value != expected_output_value
        || hex::encode(transaction.output[0].script_pubkey.as_bytes())
            != attempt.destination_script_pubkey
    {
        return Err(anyhow!(
            "BIP448 unsigned transaction does not match its immutable attempt fields"
        ));
    }
    Ok(transaction)
}

pub(crate) fn expected_withdrawal_txid(attempt: &Bip448WithdrawalAttempt) -> Result<String> {
    Ok(validate_unsigned_attempt_transaction(attempt)?
        .txid()
        .to_string())
}

pub(crate) fn validate_withdrawal_attempt(attempt: &Bip448WithdrawalAttempt) -> Result<()> {
    require_canonical_xonly_public_key(&attempt.owner_user_pubkey)?;
    require_canonical_txid(&attempt.source_txid)?;
    require_canonical_script(&attempt.source_script_pubkey)?;
    require_canonical_script(&attempt.destination_script_pubkey)?;
    let unsigned_transaction = validate_unsigned_attempt_transaction(attempt)?;
    require_canonical_hex(&attempt.signing_id, Some(32))?;
    require_canonical_hex(&attempt.signed_statechain_id, Some(64))?;
    let sign_first = parse_canonical_sign_first_payload(&attempt.sign_first_payload_json)?;
    if sign_first.statechain_id != attempt.statechain_id
        || sign_first.signed_statechain_id != attempt.signed_statechain_id
        || sign_first.signing_id != attempt.signing_id
    {
        return Err(anyhow!(
            "BIP448 sign/first payload does not match the attempt identity"
        ));
    }
    require_canonical_hex(&attempt.client_secret_nonce, Some(132))?;
    require_canonical_hex(&attempt.client_public_nonce, Some(66))?;
    require_canonical_hex(&attempt.blinding_factor, Some(32))?;
    if attempt.source_value_sats > BIP448_MAX_MONEY_SATS
        || attempt.fee_sats > BIP448_MAX_MONEY_SATS
        || attempt.owner_state_number == 0
        || attempt.lock_time > 499_999_999
        || !attempt.fee_rate_sat_per_vbyte.is_finite()
        || attempt.fee_rate_sat_per_vbyte <= 0.0
        || attempt.destination_address.is_empty()
    {
        return Err(anyhow!(
            "invalid BIP448 withdrawal attempt immutable fields"
        ));
    }

    match (attempt.binding_index, attempt.attempt_kind) {
        (0, Bip448WithdrawalAttemptKind::Canonical) => {
            if attempt.completion_status == Bip448CompletionStatus::NotApplicable {
                return Err(anyhow!(
                    "canonical BIP448 attempt requires close completion state"
                ));
            }
            let height = attempt
                .closing_tip_height
                .ok_or_else(|| anyhow!("canonical BIP448 attempt requires a closing tip"))?;
            let _ = height;
            require_canonical_block_hash(
                attempt
                    .closing_tip_hash
                    .as_deref()
                    .ok_or_else(|| anyhow!("canonical BIP448 attempt requires a closing tip"))?,
            )?;
            let bytes = attempt.closing_bindings_json.as_deref().ok_or_else(|| {
                anyhow!("canonical BIP448 attempt requires a closing binding snapshot")
            })?;
            decode_bip448_closing_bindings(bytes)?;
        }
        (1.., Bip448WithdrawalAttemptKind::Duplicate) => {
            if attempt.completion_status != Bip448CompletionStatus::NotApplicable
                || attempt.closing_tip_height.is_some()
                || attempt.closing_tip_hash.is_some()
                || attempt.closing_bindings_json.is_some()
            {
                return Err(anyhow!(
                    "duplicate BIP448 attempt cannot contain canonical close fields"
                ));
            }
        }
        _ => return Err(anyhow!("BIP448 attempt index and kind disagree")),
    }

    let nonce_fields = [
        attempt.server_public_nonce.is_some(),
        attempt.message_hex.is_some(),
        attempt.output_pubkey.is_some(),
        attempt.client_partial_sig.is_some(),
        attempt.encoded_session.is_some(),
        attempt.sign_second_payload_json.is_some(),
    ];
    if matches!(
        attempt.phase,
        Bip448WithdrawalPhase::Prepared | Bip448WithdrawalPhase::FirstArmed
    ) {
        if !option_group_is_all_none(&nonce_fields) {
            return Err(anyhow!(
                "pre-nonce BIP448 attempt cannot contain nonce/session artifacts"
            ));
        }
    } else if !option_group_is_all_some(&nonce_fields) {
        return Err(anyhow!(
            "post-nonce BIP448 attempt requires complete nonce/session artifacts"
        ));
    }
    if let Some(value) = &attempt.server_public_nonce {
        require_canonical_hex(value, Some(66))?;
    }
    require_optional_hex(attempt.message_hex.as_deref(), 32)?;
    require_optional_hex(attempt.client_partial_sig.as_deref(), 32)?;
    if let Some(value) = &attempt.output_pubkey {
        require_canonical_public_key(value)?;
    }
    let derived_blinded_session = attempt
        .encoded_session
        .as_deref()
        .map(derive_bip448_blinded_session)
        .transpose()?;
    if let Some(value) = &attempt.sign_second_payload_json {
        let sign_second = parse_canonical_sign_second_payload(value)?;
        require_bip448_session_relationship(
            attempt
                .encoded_session
                .as_deref()
                .ok_or_else(|| anyhow!("post-nonce BIP448 attempt has no full MuSig session"))?,
            &sign_second.session,
        )?;
        if sign_second.statechain_id != attempt.statechain_id
            || sign_second.signed_statechain_id != attempt.signed_statechain_id
            || sign_second.signing_id != attempt.signing_id
            || attempt.server_public_nonce.as_deref() != Some(sign_second.server_pub_nonce.as_str())
            || derived_blinded_session.as_deref() != Some(sign_second.session.as_str())
            || !matches!(sign_second.negate_seckey, 0 | 1)
        {
            return Err(anyhow!(
                "BIP448 sign/second payload does not match the persisted session"
            ));
        }
    }

    let signed_fields = [
        attempt.server_partial_sig.is_some(),
        attempt.aggregate_signature.is_some(),
        attempt.signed_tx_hex.is_some(),
        attempt.txid.is_some(),
    ];
    if attempt.phase == Bip448WithdrawalPhase::Signed {
        if !option_group_is_all_some(&signed_fields) {
            return Err(anyhow!(
                "Signed BIP448 attempt requires complete signed artifacts"
            ));
        }
    } else if !option_group_is_all_none(&signed_fields) {
        return Err(anyhow!(
            "pre-Signed BIP448 attempt cannot contain signed artifacts"
        ));
    }
    require_optional_hex(attempt.server_partial_sig.as_deref(), 32)?;
    require_optional_hex(attempt.aggregate_signature.as_deref(), 64)?;
    if let Some(value) = &attempt.signed_tx_hex {
        let signed_transaction = parse_canonical_transaction(value, "BIP448 signed transaction")?;
        let aggregate_signature = hex::decode(
            attempt
                .aggregate_signature
                .as_deref()
                .ok_or_else(|| anyhow!("BIP448 signed transaction is missing its signature"))?,
        )?;
        let mut stripped = signed_transaction.clone();
        for input in &mut stripped.input {
            input.witness = bitcoin::Witness::default();
        }
        let witness = &signed_transaction.input[0].witness;
        let expected_witness = aggregate_signature
            .iter()
            .copied()
            .chain(std::iter::once(0x01))
            .collect::<Vec<_>>();
        if stripped != unsigned_transaction
            || witness.len() != 1
            || witness
                .iter()
                .next()
                .is_none_or(|item| item != expected_witness.as_slice())
        {
            return Err(anyhow!(
                "BIP448 signed transaction does not exactly finalize the persisted unsigned bytes"
            ));
        }
        if attempt.txid.as_deref() != Some(signed_transaction.txid().to_string().as_str()) {
            return Err(anyhow!("BIP448 signed transaction txid does not match"));
        }
    }
    if let Some(txid) = &attempt.txid {
        require_canonical_txid(txid)?;
    }
    if attempt.phase != Bip448WithdrawalPhase::Signed
        && attempt.broadcast_status != Bip448BroadcastStatus::NotBroadcast
    {
        return Err(anyhow!("pre-Signed BIP448 attempt cannot be broadcast"));
    }
    if matches!(
        attempt.completion_status,
        Bip448CompletionStatus::CloseArmed | Bip448CompletionStatus::Closed
    ) && (attempt.phase != Bip448WithdrawalPhase::Signed
        || attempt.broadcast_status == Bip448BroadcastStatus::NotBroadcast)
    {
        return Err(anyhow!(
            "BIP448 completion state is not armed by accepted bytes"
        ));
    }
    Ok(())
}

fn require_optional_hex(value: Option<&str>, length: usize) -> Result<()> {
    if let Some(value) = value {
        require_canonical_hex(value, Some(length))?;
    }
    Ok(())
}

pub(crate) fn validate_transfer_intent(intent: &Bip448TransferIntent) -> Result<()> {
    require_canonical_hex(&intent.intent_id, Some(32))?;
    require_optional_hex(intent.predecessor_intent_id.as_deref(), 32)?;
    if intent.predecessor_intent_id.as_deref() == Some(intent.intent_id.as_str()) {
        return Err(anyhow!(
            "BIP448 transfer intent cannot name itself as predecessor"
        ));
    }
    require_canonical_public_key(&intent.receiver_user_pubkey)?;
    require_canonical_public_key(&intent.recipient_auth_pubkey)?;
    require_canonical_hex(&intent.sender_signed_statechain_id, Some(64))?;
    require_optional_hex(intent.prior_pending_signing_id.as_deref(), 32)?;
    require_optional_hex(intent.prior_transfer_msg_hash.as_deref(), 32)?;
    if let Some(value) = &intent.prior_transfer_recipient_auth_pubkey {
        require_canonical_public_key(value)?;
    }
    if intent.prior_transfer_recipient_auth_pubkey.is_some()
        != intent.prior_transfer_msg_hash.is_some()
    {
        return Err(anyhow!(
            "BIP448 transfer message recipient and hash fingerprint must be paired"
        ));
    }
    if intent.planned_state_number == 0
        || intent.expected_signature_count == 0
        || !(500_000_000..=4_294_967_294).contains(&intent.previous_locktime)
    {
        return Err(anyhow!("invalid BIP448 transfer state/count plan"));
    }
    if intent.reuse_pending && intent.prior_pending_signing_id.is_none() {
        return Err(anyhow!("BIP448 reuse_pending requires a prior signing id"));
    }
    if intent.reuse_signed_state && !intent.reuse_pending {
        return Err(anyhow!("BIP448 signed-state reuse requires pending reuse"));
    }
    let expected_planned = if intent.reuse_signed_state {
        intent.expected_signature_count
    } else {
        intent
            .expected_signature_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("BIP448 planned state number overflows"))?
    };
    if intent.planned_state_number != expected_planned {
        return Err(anyhow!(
            "BIP448 planned state number does not match signature count"
        ));
    }
    if intent.reuse_pending && intent.clear_local_attempt {
        return Err(anyhow!(
            "BIP448 pending reuse cannot clear the same local attempt"
        ));
    }
    if intent.clear_local_attempt
        && intent.prior_pending_signing_id.is_none()
        && intent.prior_transfer_msg_hash.is_none()
    {
        return Err(anyhow!(
            "BIP448 local-attempt clearing requires an exact prior fingerprint"
        ));
    }
    if intent.intent_kind == Bip448TransferIntentKind::Cancellation && intent.batch_id.is_some() {
        return Err(anyhow!("BIP448 cancellation cannot use a batch id"));
    }
    if intent.intent_kind == Bip448TransferIntentKind::UserTransfer
        && matches!(
            intent.phase,
            Bip448TransferIntentPhase::SenderFinished | Bip448TransferIntentPhase::ReceiverAccepted
        )
    {
        return Err(anyhow!(
            "BIP448 user-transfer intent cannot enter cancellation phases"
        ));
    }

    match intent.intent_kind {
        Bip448TransferIntentKind::UserTransfer => {
            if intent.generated_coin_user_pubkey.is_some()
                || intent.generated_coin_auth_pubkey.is_some()
                || intent.generated_coin_address.is_some()
            {
                return Err(anyhow!(
                    "BIP448 user-transfer intent cannot contain a generated Coin identity"
                ));
            }
        }
        Bip448TransferIntentKind::Cancellation => {
            let generated_user = intent
                .generated_coin_user_pubkey
                .as_deref()
                .ok_or_else(|| anyhow!("BIP448 cancellation requires a generated Coin identity"))?;
            let generated_auth = intent
                .generated_coin_auth_pubkey
                .as_deref()
                .ok_or_else(|| anyhow!("BIP448 cancellation requires a generated Coin identity"))?;
            let generated_address = intent
                .generated_coin_address
                .as_deref()
                .ok_or_else(|| anyhow!("BIP448 cancellation requires a generated Coin identity"))?;
            require_canonical_public_key(generated_user)?;
            require_canonical_public_key(generated_auth)?;
            if generated_user != intent.receiver_user_pubkey
                || generated_auth != intent.recipient_auth_pubkey
                || generated_address != intent.recipient_address
            {
                return Err(anyhow!(
                    "BIP448 cancellation generated Coin does not match its recipient"
                ));
            }
            let decoded =
                std::panic::catch_unwind(|| mercurylib::decode_transfer_address(generated_address))
                    .map_err(|_| anyhow!("invalid BIP448 cancellation transfer address"))?
                    .map_err(|_| anyhow!("invalid BIP448 cancellation transfer address"))?;
            if decoded.0 != 0
                || decoded.1.to_string() != generated_user
                || decoded.2.to_string() != generated_auth
            {
                return Err(anyhow!(
                    "BIP448 cancellation address does not encode its generated keys"
                ));
            }
        }
    }

    match intent.phase {
        Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed => {
            if intent.server_x1.is_some() {
                return Err(anyhow!("pre-X1 BIP448 transfer intent cannot contain x1"));
            }
        }
        _ => {
            let x1 = intent
                .server_x1
                .as_deref()
                .ok_or_else(|| anyhow!("post-X1 BIP448 transfer intent requires x1"))?;
            require_canonical_hex(x1, Some(32))?;
            SecretKey::from_str(x1).context("invalid BIP448 transfer x1 scalar")?;
        }
    }

    match (intent.phase, intent.state_signing_phase) {
        (Bip448TransferIntentPhase::Prepared | Bip448TransferIntentPhase::SenderArmed, phase)
            if phase != Bip448TransferStateSigningPhase::NotStarted =>
        {
            return Err(anyhow!(
                "pre-X1 BIP448 transfer intent cannot have started state signing"
            ));
        }
        (
            Bip448TransferIntentPhase::SenderFinished | Bip448TransferIntentPhase::ReceiverAccepted,
            phase,
        ) if intent.intent_kind != Bip448TransferIntentKind::Cancellation
            || phase != Bip448TransferStateSigningPhase::Signed =>
        {
            return Err(anyhow!(
                "terminal BIP448 cancellation requires a Signed state"
            ));
        }
        _ => {}
    }

    match intent.state_signing_phase {
        Bip448TransferStateSigningPhase::NotStarted => {
            if intent.current_pending_signing_id.is_some()
                || intent.server_partial_sig.is_some()
                || intent.update_signature.is_some()
            {
                return Err(anyhow!(
                    "unstarted BIP448 state signing cannot contain signing results"
                ));
            }
        }
        Bip448TransferStateSigningPhase::FirstArmed
        | Bip448TransferStateSigningPhase::NonceStored
        | Bip448TransferStateSigningPhase::SecondArmed => {
            require_optional_hex(intent.current_pending_signing_id.as_deref(), 32)?;
            if intent.reuse_signed_state
                || intent.current_pending_signing_id.is_none()
                || intent.server_partial_sig.is_some()
                || intent.update_signature.is_some()
            {
                return Err(anyhow!(
                    "active BIP448 state signing has incoherent artifacts"
                ));
            }
        }
        Bip448TransferStateSigningPhase::Signed => {
            require_optional_hex(intent.current_pending_signing_id.as_deref(), 32)?;
            require_optional_hex(intent.server_partial_sig.as_deref(), 32)?;
            require_optional_hex(intent.update_signature.as_deref(), 64)?;
            if intent.current_pending_signing_id.is_none()
                || intent.update_signature.is_none()
                || (intent.reuse_signed_state && intent.server_partial_sig.is_some())
                || (!intent.reuse_signed_state && intent.server_partial_sig.is_none())
            {
                return Err(anyhow!(
                    "Signed BIP448 state intent has incomplete artifacts"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn withdrawal_attempt_immutable_eq(
    left: &Bip448WithdrawalAttempt,
    right: &Bip448WithdrawalAttempt,
) -> bool {
    left.wallet_name == right.wallet_name
        && left.statechain_id == right.statechain_id
        && left.binding_index == right.binding_index
        && left.attempt_kind == right.attempt_kind
        && left.owner_user_pubkey == right.owner_user_pubkey
        && left.owner_state_number == right.owner_state_number
        && left.source_txid == right.source_txid
        && left.source_vout == right.source_vout
        && left.source_value_sats == right.source_value_sats
        && left.source_script_pubkey == right.source_script_pubkey
        && left.destination_address == right.destination_address
        && left.destination_script_pubkey == right.destination_script_pubkey
        && left.fee_rate_sat_per_vbyte.to_bits() == right.fee_rate_sat_per_vbyte.to_bits()
        && left.fee_sats == right.fee_sats
        && left.lock_time == right.lock_time
        && left.unsigned_tx_hex == right.unsigned_tx_hex
        && left.signing_id == right.signing_id
        && left.signed_statechain_id == right.signed_statechain_id
        && left.sign_first_payload_json == right.sign_first_payload_json
        && left.client_secret_nonce == right.client_secret_nonce
        && left.client_public_nonce == right.client_public_nonce
        && left.blinding_factor == right.blinding_factor
        && left.closing_tip_height == right.closing_tip_height
        && left.closing_tip_hash == right.closing_tip_hash
        && left.closing_bindings_json == right.closing_bindings_json
}

pub(crate) fn transfer_intent_immutable_eq(
    left: &Bip448TransferIntent,
    right: &Bip448TransferIntent,
) -> bool {
    left.wallet_name == right.wallet_name
        && left.statechain_id == right.statechain_id
        && left.intent_id == right.intent_id
        && left.predecessor_intent_id == right.predecessor_intent_id
        && left.intent_kind == right.intent_kind
        && left.acknowledge_cooperative_duplicates == right.acknowledge_cooperative_duplicates
        && left.recipient_address == right.recipient_address
        && left.receiver_user_pubkey == right.receiver_user_pubkey
        && left.recipient_auth_pubkey == right.recipient_auth_pubkey
        && left.batch_id == right.batch_id
        && left.sender_signed_statechain_id == right.sender_signed_statechain_id
        && left.planned_state_number == right.planned_state_number
        && left.expected_signature_count == right.expected_signature_count
        && left.previous_locktime == right.previous_locktime
        && left.prior_pending_signing_id == right.prior_pending_signing_id
        && left.prior_transfer_recipient_auth_pubkey == right.prior_transfer_recipient_auth_pubkey
        && left.prior_transfer_msg_hash == right.prior_transfer_msg_hash
        && left.reuse_pending == right.reuse_pending
        && left.reuse_signed_state == right.reuse_signed_state
        && left.clear_local_attempt == right.clear_local_attempt
        && left.generated_coin_user_pubkey == right.generated_coin_user_pubkey
        && left.generated_coin_auth_pubkey == right.generated_coin_auth_pubkey
        && left.generated_coin_address == right.generated_coin_address
}

struct StrictClosingResolution(Bip448ClosingResolution);

impl<'de> Deserialize<'de> for StrictClosingResolution {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResolutionVisitor;

        impl<'de> Visitor<'de> for ResolutionVisitor {
            type Value = StrictClosingResolution;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical BIP448 close resolution")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                require_next_key::<A>(&mut map, "kind")?;
                let kind: String = map.next_value()?;
                let resolution = match kind.as_str() {
                    "SignedAttempt" => {
                        require_next_key::<A>(&mut map, "signing_id")?;
                        let signing_id = map.next_value()?;
                        require_next_key::<A>(&mut map, "sweep_txid")?;
                        let sweep_txid = map.next_value()?;
                        require_next_key::<A>(&mut map, "conflict_spend_txid")?;
                        let conflict_spend_txid = map.next_value()?;
                        Bip448ClosingResolution::SignedAttempt {
                            signing_id,
                            sweep_txid,
                            conflict_spend_txid,
                        }
                    }
                    "IndependentSpend" => {
                        require_next_key::<A>(&mut map, "spend_txid")?;
                        let spend_txid = map.next_value()?;
                        Bip448ClosingResolution::IndependentSpend { spend_txid }
                    }
                    _ => return Err(A::Error::custom("invalid BIP448 close resolution kind")),
                };
                if map.next_key::<String>()?.is_some() {
                    return Err(A::Error::custom(
                        "extra, duplicate, or reordered BIP448 close resolution field",
                    ));
                }
                Ok(StrictClosingResolution(resolution))
            }
        }

        deserializer.deserialize_map(ResolutionVisitor)
    }
}

struct StrictClosingBinding(Bip448ClosingBinding);

impl<'de> Deserialize<'de> for StrictClosingBinding {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BindingVisitor;

        impl<'de> Visitor<'de> for BindingVisitor {
            type Value = StrictClosingBinding;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical BIP448 closing binding")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                require_next_key::<A>(&mut map, "binding_index")?;
                let binding_index = map.next_value()?;
                require_next_key::<A>(&mut map, "txid")?;
                let txid = map.next_value()?;
                require_next_key::<A>(&mut map, "vout")?;
                let vout = map.next_value()?;
                require_next_key::<A>(&mut map, "value_sats")?;
                let value_sats = map.next_value()?;
                require_next_key::<A>(&mut map, "owner_user_pubkey")?;
                let owner_user_pubkey = map.next_value()?;
                require_next_key::<A>(&mut map, "owner_state_number")?;
                let owner_state_number = map.next_value()?;
                require_next_key::<A>(&mut map, "resolution")?;
                let StrictClosingResolution(resolution) = map.next_value()?;
                if map.next_key::<String>()?.is_some() {
                    return Err(A::Error::custom(
                        "extra, duplicate, or reordered BIP448 closing binding field",
                    ));
                }
                Ok(StrictClosingBinding(Bip448ClosingBinding {
                    binding_index,
                    txid,
                    vout,
                    value_sats,
                    owner_user_pubkey,
                    owner_state_number,
                    resolution,
                }))
            }
        }

        deserializer.deserialize_map(BindingVisitor)
    }
}

fn require_next_key<'de, A>(
    map: &mut A,
    expected: &'static str,
) -> std::result::Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    let actual = map
        .next_key::<String>()?
        .ok_or_else(|| A::Error::custom(format!("missing BIP448 close field {expected}")))?;
    if actual != expected {
        return Err(A::Error::custom(format!(
            "expected BIP448 close field {expected}, found {actual}"
        )));
    }
    Ok(())
}

fn validate_closing_binding(binding: &Bip448ClosingBinding) -> Result<()> {
    if binding.binding_index == 0
        || binding.value_sats > BIP448_MAX_MONEY_SATS
        || binding.owner_state_number == 0
    {
        return Err(anyhow!("invalid BIP448 closing binding integer domain"));
    }
    require_canonical_txid(&binding.txid)?;
    require_canonical_xonly_public_key(&binding.owner_user_pubkey)?;
    match &binding.resolution {
        Bip448ClosingResolution::SignedAttempt {
            signing_id,
            sweep_txid,
            conflict_spend_txid,
        } => {
            require_canonical_hex(signing_id, Some(32))?;
            require_canonical_txid(sweep_txid)?;
            if let Some(spend_txid) = conflict_spend_txid {
                require_canonical_txid(spend_txid)?;
                if spend_txid == sweep_txid {
                    return Err(anyhow!(
                        "BIP448 conflict spend must differ from the sweep txid"
                    ));
                }
            }
        }
        Bip448ClosingResolution::IndependentSpend { spend_txid } => {
            require_canonical_txid(spend_txid)?;
        }
    }
    Ok(())
}

fn encode_bip448_closing_bindings(bindings: &[Bip448ClosingBinding]) -> Result<String> {
    let mut previous = None;
    let mut encoded = String::from("[");
    for (offset, binding) in bindings.iter().enumerate() {
        validate_closing_binding(binding)?;
        if previous.is_some_and(|index| binding.binding_index <= index) {
            return Err(anyhow!(
                "BIP448 closing bindings must be strictly sorted by binding_index"
            ));
        }
        previous = Some(binding.binding_index);
        if offset != 0 {
            encoded.push(',');
        }
        encoded.push_str(&format!(
            "{{\"binding_index\":{},\"txid\":\"{}\",\"vout\":{},\"value_sats\":{},\"owner_user_pubkey\":\"{}\",\"owner_state_number\":{},\"resolution\":",
            binding.binding_index,
            binding.txid,
            binding.vout,
            binding.value_sats,
            binding.owner_user_pubkey,
            binding.owner_state_number,
        ));
        match &binding.resolution {
            Bip448ClosingResolution::SignedAttempt {
                signing_id,
                sweep_txid,
                conflict_spend_txid,
            } => {
                encoded.push_str(&format!(
                    "{{\"kind\":\"SignedAttempt\",\"signing_id\":\"{}\",\"sweep_txid\":\"{}\",\"conflict_spend_txid\":",
                    signing_id, sweep_txid,
                ));
                match conflict_spend_txid {
                    Some(txid) => encoded.push_str(&format!("\"{txid}\"")),
                    None => encoded.push_str("null"),
                }
                encoded.push('}');
            }
            Bip448ClosingResolution::IndependentSpend { spend_txid } => {
                encoded.push_str(&format!(
                    "{{\"kind\":\"IndependentSpend\",\"spend_txid\":\"{}\"}}",
                    spend_txid,
                ));
            }
        }
        encoded.push('}');
    }
    encoded.push(']');
    Ok(encoded)
}

pub(crate) fn decode_bip448_closing_bindings(encoded: &str) -> Result<Vec<Bip448ClosingBinding>> {
    let strict: Vec<StrictClosingBinding> = serde_json::from_str(encoded)
        .context("invalid canonical BIP448 closing binding snapshot")?;
    let bindings = strict
        .into_iter()
        .map(|StrictClosingBinding(binding)| binding)
        .collect::<Vec<_>>();
    let canonical = encode_bip448_closing_bindings(&bindings)?;
    if canonical.as_bytes() != encoded.as_bytes() {
        return Err(anyhow!(
            "BIP448 closing binding snapshot is not the canonical byte encoding"
        ));
    }
    Ok(bindings)
}

pub fn bip448_signature_count_expectation(
    latest_state_number: u32,
    attempts: &[Bip448WithdrawalAttempt],
) -> Result<Bip448SignatureCountExpectation> {
    if latest_state_number == 0 {
        return Err(anyhow!("BIP448 latest state number must be positive"));
    }
    let signed_count = u64::try_from(
        attempts
            .iter()
            .filter(|attempt| attempt.phase == Bip448WithdrawalPhase::Signed)
            .count(),
    )?;
    let settled_count = u64::from(latest_state_number)
        .checked_add(signed_count)
        .ok_or_else(|| anyhow!("BIP448 signature count overflows"))?;
    let active_second_armed = attempts
        .iter()
        .filter(|attempt| attempt.phase == Bip448WithdrawalPhase::SecondArmed)
        .count();
    let active_count = attempts
        .iter()
        .filter(|attempt| attempt.phase != Bip448WithdrawalPhase::Signed)
        .count();
    if active_second_armed > 1 || active_count > 1 {
        return Err(anyhow!("multiple active BIP448 withdrawal signings"));
    }
    let second_armed_landed_count = if active_second_armed == 1 {
        Some(
            settled_count
                .checked_add(1)
                .ok_or_else(|| anyhow!("BIP448 signature count overflows"))?,
        )
    } else {
        None
    };
    Ok(Bip448SignatureCountExpectation {
        settled_count,
        second_armed_landed_count,
    })
}

pub fn bip448_attempts_are_exit_only(attempts: &[Bip448WithdrawalAttempt]) -> bool {
    attempts.iter().any(|attempt| {
        matches!(
            attempt.phase,
            Bip448WithdrawalPhase::SecondArmed | Bip448WithdrawalPhase::Signed
        )
    })
}

pub fn evaluate_bip448_close_gate(
    bindings: &[Bip448FundingBinding],
    attempts: &[Bip448WithdrawalAttempt],
) -> Result<Bip448CloseGate> {
    let mut bindings = bindings
        .iter()
        .filter(|binding| {
            binding.role == Bip448BindingRole::Duplicate
                && binding.ownership_status == Bip448OwnershipStatus::Current
        })
        .collect::<Vec<_>>();
    bindings.sort_by_key(|binding| binding.binding_index);
    let mut reasons = Vec::new();
    let mut closing = Vec::new();

    for binding in bindings {
        let mut matches = attempts
            .iter()
            .filter(|attempt| attempt.binding_index == binding.binding_index);
        let attempt = matches.next();
        if matches.next().is_some() {
            reasons.push(Bip448CloseBlockReason::AttemptIdentity {
                binding_index: binding.binding_index,
            });
            continue;
        }
        if let Some(attempt) = attempt {
            if attempt.wallet_name != binding.wallet_name
                || attempt.statechain_id != binding.statechain_id
                || attempt.attempt_kind != Bip448WithdrawalAttemptKind::Duplicate
                || attempt.owner_user_pubkey != binding.owner_user_pubkey
                || attempt.owner_state_number != binding.owner_state_number
                || attempt.source_txid != binding.txid
                || attempt.source_vout != binding.vout
                || attempt.source_value_sats != binding.value_sats
                || attempt.source_script_pubkey != binding.script_pubkey
            {
                reasons.push(Bip448CloseBlockReason::AttemptIdentity {
                    binding_index: binding.binding_index,
                });
                continue;
            }
            if attempt.phase != Bip448WithdrawalPhase::Signed {
                reasons.push(Bip448CloseBlockReason::AttemptPhase {
                    binding_index: binding.binding_index,
                    phase: attempt.phase,
                });
                continue;
            }
            match attempt.broadcast_status {
                Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed => {
                    let sweep_txid = attempt
                        .txid
                        .clone()
                        .ok_or_else(|| anyhow!("Signed BIP448 attempt is missing txid"))?;
                    if matches!(
                        binding.observation_status,
                        Bip448ObservationStatus::SpentMempool
                            | Bip448ObservationStatus::SpentUnconfirmed
                            | Bip448ObservationStatus::SpentConfirmed
                    ) && binding.spend_txid.as_deref() != Some(sweep_txid.as_str())
                    {
                        reasons.push(Bip448CloseBlockReason::ConflictIdentity {
                            binding_index: binding.binding_index,
                        });
                        continue;
                    }
                    closing.push(Bip448ClosingBinding {
                        binding_index: binding.binding_index,
                        txid: binding.txid.clone(),
                        vout: binding.vout,
                        value_sats: binding.value_sats,
                        owner_user_pubkey: binding.owner_user_pubkey.clone(),
                        owner_state_number: binding.owner_state_number,
                        resolution: Bip448ClosingResolution::SignedAttempt {
                            signing_id: attempt.signing_id.clone(),
                            sweep_txid,
                            conflict_spend_txid: None,
                        },
                    });
                }
                Bip448BroadcastStatus::Conflicted => {
                    let sweep_txid = attempt
                        .txid
                        .clone()
                        .ok_or_else(|| anyhow!("Signed BIP448 attempt is missing txid"))?;
                    let conflict = binding.spend_txid.clone();
                    if binding.observation_status != Bip448ObservationStatus::SpentConfirmed
                        || conflict.as_deref() == Some(sweep_txid.as_str())
                        || conflict.is_none()
                    {
                        reasons.push(Bip448CloseBlockReason::ConflictIdentity {
                            binding_index: binding.binding_index,
                        });
                        continue;
                    }
                    closing.push(Bip448ClosingBinding {
                        binding_index: binding.binding_index,
                        txid: binding.txid.clone(),
                        vout: binding.vout,
                        value_sats: binding.value_sats,
                        owner_user_pubkey: binding.owner_user_pubkey.clone(),
                        owner_state_number: binding.owner_state_number,
                        resolution: Bip448ClosingResolution::SignedAttempt {
                            signing_id: attempt.signing_id.clone(),
                            sweep_txid,
                            conflict_spend_txid: conflict,
                        },
                    });
                }
                status => reasons.push(Bip448CloseBlockReason::AttemptBroadcast {
                    binding_index: binding.binding_index,
                    broadcast_status: status,
                }),
            }
        } else if binding.observation_status == Bip448ObservationStatus::SpentConfirmed {
            closing.push(Bip448ClosingBinding {
                binding_index: binding.binding_index,
                txid: binding.txid.clone(),
                vout: binding.vout,
                value_sats: binding.value_sats,
                owner_user_pubkey: binding.owner_user_pubkey.clone(),
                owner_state_number: binding.owner_state_number,
                resolution: Bip448ClosingResolution::IndependentSpend {
                    spend_txid: binding.spend_txid.clone().ok_or_else(|| {
                        anyhow!("SpentConfirmed BIP448 binding is missing spender")
                    })?,
                },
            });
        } else {
            reasons.push(Bip448CloseBlockReason::BindingObservation {
                binding_index: binding.binding_index,
                observation_status: binding.observation_status,
            });
        }
    }

    if reasons.is_empty() {
        let closing_bindings_json = encode_bip448_closing_bindings(&closing)?;
        Ok(Bip448CloseGate::Ready {
            closing_bindings: closing,
            closing_bindings_json,
        })
    } else {
        Ok(Bip448CloseGate::Blocked { reasons })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn every_storage_enum_has_exact_literal_roundtrip_and_rejects_debug_aliases() {
        macro_rules! check {
            ($type:ty, [$($variant:expr),+ $(,)?]) => {{
                $(assert_eq!(<$type>::parse($variant.as_str()).unwrap(), $variant);)+
                assert!(<$type>::parse("canonical").is_err());
                assert!(<$type>::parse("Unknown").is_err());
                assert!(<$type>::parse("").is_err());
            }};
        }
        check!(
            Bip448BindingRole,
            [Bip448BindingRole::Canonical, Bip448BindingRole::Duplicate]
        );
        check!(
            Bip448ObservationStatus,
            [
                Bip448ObservationStatus::Mempool,
                Bip448ObservationStatus::Unconfirmed,
                Bip448ObservationStatus::Confirmed,
                Bip448ObservationStatus::SpentMempool,
                Bip448ObservationStatus::SpentUnconfirmed,
                Bip448ObservationStatus::SpentConfirmed,
                Bip448ObservationStatus::Absent
            ]
        );
        check!(
            Bip448OwnershipStatus,
            [
                Bip448OwnershipStatus::Current,
                Bip448OwnershipStatus::Previous
            ]
        );
        check!(
            Bip448WithdrawalAttemptKind,
            [
                Bip448WithdrawalAttemptKind::Duplicate,
                Bip448WithdrawalAttemptKind::Canonical
            ]
        );
        check!(
            Bip448WithdrawalPhase,
            [
                Bip448WithdrawalPhase::Prepared,
                Bip448WithdrawalPhase::FirstArmed,
                Bip448WithdrawalPhase::NonceStored,
                Bip448WithdrawalPhase::SecondArmed,
                Bip448WithdrawalPhase::Signed
            ]
        );
        check!(
            Bip448BroadcastStatus,
            [
                Bip448BroadcastStatus::NotBroadcast,
                Bip448BroadcastStatus::Accepted,
                Bip448BroadcastStatus::Confirmed,
                Bip448BroadcastStatus::NeedsRebroadcast,
                Bip448BroadcastStatus::Conflicting,
                Bip448BroadcastStatus::Conflicted
            ]
        );
        check!(
            Bip448CompletionStatus,
            [
                Bip448CompletionStatus::NotApplicable,
                Bip448CompletionStatus::Open,
                Bip448CompletionStatus::CloseArmed,
                Bip448CompletionStatus::Closed
            ]
        );
        check!(
            Bip448TransferIntentKind,
            [
                Bip448TransferIntentKind::UserTransfer,
                Bip448TransferIntentKind::Cancellation
            ]
        );
        check!(
            Bip448TransferIntentActivityStatus,
            [
                Bip448TransferIntentActivityStatus::Active,
                Bip448TransferIntentActivityStatus::Superseded
            ]
        );
        check!(
            Bip448TransferIntentPhase,
            [
                Bip448TransferIntentPhase::Prepared,
                Bip448TransferIntentPhase::SenderArmed,
                Bip448TransferIntentPhase::X1Stored,
                Bip448TransferIntentPhase::SenderFinished,
                Bip448TransferIntentPhase::ReceiverAccepted
            ]
        );
        check!(
            Bip448TransferStateSigningPhase,
            [
                Bip448TransferStateSigningPhase::NotStarted,
                Bip448TransferStateSigningPhase::FirstArmed,
                Bip448TransferStateSigningPhase::NonceStored,
                Bip448TransferStateSigningPhase::SecondArmed,
                Bip448TransferStateSigningPhase::Signed
            ]
        );
    }

    #[test]
    fn canonical_close_snapshot_roundtrips_both_literal_shapes_and_rejects_mutations() {
        let signed = format!("{{\"binding_index\":1,\"txid\":\"{}\",\"vout\":0,\"value_sats\":123,\"owner_user_pubkey\":\"{}\",\"owner_state_number\":3,\"resolution\":{{\"kind\":\"SignedAttempt\",\"signing_id\":\"{}\",\"sweep_txid\":\"{}\",\"conflict_spend_txid\":null}}}}", "11".repeat(32), OWNER, "22".repeat(32), "33".repeat(32));
        let independent = format!("{{\"binding_index\":2,\"txid\":\"{}\",\"vout\":1,\"value_sats\":456,\"owner_user_pubkey\":\"{}\",\"owner_state_number\":3,\"resolution\":{{\"kind\":\"IndependentSpend\",\"spend_txid\":\"{}\"}}}}", "44".repeat(32), OWNER, "55".repeat(32));
        let exact = format!("[{signed},{independent}]");
        let decoded = decode_bip448_closing_bindings(&exact).unwrap();
        assert_eq!(encode_bip448_closing_bindings(&decoded).unwrap(), exact);
        assert_eq!(encode_bip448_closing_bindings(&[]).unwrap(), "[]");

        let conflict = exact.replacen(
            "\"conflict_spend_txid\":null",
            &format!("\"conflict_spend_txid\":\"{}\"", "66".repeat(32)),
            1,
        );
        assert_eq!(
            encode_bip448_closing_bindings(&decode_bip448_closing_bindings(&conflict).unwrap())
                .unwrap(),
            conflict
        );
        for malformed in [
            exact.replacen(
                &format!("{{\"binding_index\":1,\"txid\":\"{}\"", "11".repeat(32)),
                &format!("{{\"txid\":\"{}\",\"binding_index\":1", "11".repeat(32)),
                1,
            ),
            exact.replacen(&"11".repeat(32), &"AA".repeat(32), 1),
            exact.replacen(
                "\"binding_index\":1",
                "\"binding_index\":1,\"binding_index\":1",
                1,
            ),
            exact.replacen("\"value_sats\":123,", "", 1),
            exact.replacen("\"vout\":0", "\"vout\":0,\"extra\":0", 1),
            exact.replacen(
                "\"kind\":\"SignedAttempt\"",
                "\"kind\":\"signedattempt\"",
                1,
            ),
            exact.replacen("\"sweep_txid\"", "\"unknown\":null,\"sweep_txid\"", 1),
            exact.replacen(
                "\"conflict_spend_txid\":null",
                "\"conflict_spend_txid\":null,\"conflict_spend_txid\":null",
                1,
            ),
            exact.replacen(&format!(",\"sweep_txid\":\"{}\"", "33".repeat(32)), "", 1),
            format!(" {exact}"),
            format!("[{independent},{signed}]"),
        ] {
            assert!(
                decode_bip448_closing_bindings(&malformed).is_err(),
                "accepted malformed snapshot: {malformed}"
            );
        }
    }

    #[test]
    fn observation_height_and_spend_coherence_is_exact() {
        assert!(validate_observation(Bip448ObservationStatus::Mempool, None, None, None).is_ok());
        assert!(
            validate_observation(Bip448ObservationStatus::Unconfirmed, Some(1), None, None).is_ok()
        );
        assert!(
            validate_observation(Bip448ObservationStatus::Confirmed, Some(1), None, None).is_ok()
        );
        assert!(validate_observation(
            Bip448ObservationStatus::SpentMempool,
            None,
            Some(&"11".repeat(32)),
            None
        )
        .is_ok());
        assert!(validate_observation(
            Bip448ObservationStatus::SpentMempool,
            Some(1),
            Some(&"11".repeat(32)),
            None
        )
        .is_ok());
        assert!(validate_observation(
            Bip448ObservationStatus::SpentUnconfirmed,
            Some(1),
            Some(&"11".repeat(32)),
            Some(2)
        )
        .is_ok());
        assert!(validate_observation(
            Bip448ObservationStatus::SpentConfirmed,
            Some(1),
            Some(&"11".repeat(32)),
            Some(2)
        )
        .is_ok());
        assert!(validate_observation(Bip448ObservationStatus::Absent, None, None, None).is_ok());
        assert!(validate_observation(Bip448ObservationStatus::Absent, Some(1), None, None).is_ok());
        assert!(
            validate_observation(Bip448ObservationStatus::Unconfirmed, None, None, None).is_err()
        );
        assert!(
            validate_observation(Bip448ObservationStatus::Confirmed, None, None, None).is_err()
        );
        assert!(
            validate_observation(Bip448ObservationStatus::SpentMempool, None, None, None).is_err()
        );
        assert!(validate_observation(
            Bip448ObservationStatus::SpentConfirmed,
            Some(1),
            Some(&"11".repeat(32)),
            None
        )
        .is_err());
        assert!(validate_observation(
            Bip448ObservationStatus::Absent,
            Some(1),
            Some(&"11".repeat(32)),
            None
        )
        .is_err());
    }

    #[test]
    fn one_output_fee_uses_112_vbytes_checked_ceil_subtraction_and_dust() {
        assert_eq!(
            bip448_one_output_fee_and_value(10_000, 1.001, 330).unwrap(),
            (113, 9_887)
        );
        assert!(bip448_one_output_fee_and_value(10_000, 0.0, 330).is_err());
        assert!(bip448_one_output_fee_and_value(10_000, f64::NAN, 330).is_err());
        assert!(bip448_one_output_fee_and_value(100, 1.0, 0).is_err());
        assert!(bip448_one_output_fee_and_value(500, 1.0, 400).is_err());
        assert!(bip448_one_output_fee_and_value(BIP448_MAX_MONEY_SATS + 1, 1.0, 0).is_err());
    }

    fn count_only_attempt(phase: Bip448WithdrawalPhase) -> Bip448WithdrawalAttempt {
        Bip448WithdrawalAttempt {
            wallet_name: String::new(),
            statechain_id: String::new(),
            binding_index: 1,
            attempt_kind: Bip448WithdrawalAttemptKind::Duplicate,
            owner_user_pubkey: String::new(),
            owner_state_number: 1,
            source_txid: String::new(),
            source_vout: 0,
            source_value_sats: 0,
            source_script_pubkey: String::new(),
            destination_address: String::new(),
            destination_script_pubkey: String::new(),
            fee_rate_sat_per_vbyte: 1.0,
            fee_sats: 0,
            lock_time: 0,
            unsigned_tx_hex: String::new(),
            signing_id: String::new(),
            signed_statechain_id: String::new(),
            sign_first_payload_json: String::new(),
            client_secret_nonce: String::new(),
            client_public_nonce: String::new(),
            blinding_factor: String::new(),
            server_public_nonce: None,
            message_hex: None,
            output_pubkey: None,
            client_partial_sig: None,
            encoded_session: None,
            sign_second_payload_json: None,
            server_partial_sig: None,
            aggregate_signature: None,
            signed_tx_hex: None,
            txid: None,
            phase,
            broadcast_status: Bip448BroadcastStatus::NotBroadcast,
            completion_status: Bip448CompletionStatus::NotApplicable,
            closing_tip_height: None,
            closing_tip_hash: None,
            closing_bindings_json: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn signature_count_ranges_are_exact_and_exit_only_is_monotonic() {
        assert!(bip448_signature_count_expectation(0, &[]).is_err());
        assert_eq!(
            bip448_signature_count_expectation(u32::MAX, &[])
                .unwrap()
                .settled_count,
            u64::from(u32::MAX)
        );
        let signed = count_only_attempt(Bip448WithdrawalPhase::Signed);
        let second_armed = count_only_attempt(Bip448WithdrawalPhase::SecondArmed);
        let expectation =
            bip448_signature_count_expectation(3, &[signed.clone(), second_armed.clone()]).unwrap();
        assert_eq!(expectation.settled_count, 4);
        assert_eq!(expectation.second_armed_landed_count, Some(5));
        assert!(bip448_attempts_are_exit_only(&[second_armed.clone()]));
        assert!(bip448_attempts_are_exit_only(&[signed]));
        assert!(!bip448_attempts_are_exit_only(&[count_only_attempt(
            Bip448WithdrawalPhase::NonceStored
        )]));
        assert!(
            bip448_signature_count_expectation(3, &[second_armed.clone(), second_armed]).is_err()
        );
        assert!(bip448_signature_count_expectation(
            3,
            &[
                count_only_attempt(Bip448WithdrawalPhase::Prepared),
                count_only_attempt(Bip448WithdrawalPhase::FirstArmed)
            ]
        )
        .is_err());
    }
}
