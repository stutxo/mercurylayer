use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use secp256k1::SecretKey;

use super::{
    canonical::require_optional_hex,
    enums::{
        Bip448TransferIntentActivityStatus, Bip448TransferIntentKind, Bip448TransferIntentPhase,
        Bip448TransferStateSigningPhase,
    },
    require_canonical_hex, require_canonical_public_key,
};

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
