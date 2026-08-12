use anyhow::{anyhow, Result};

use super::{
    enums::{Bip448BindingRole, Bip448ObservationStatus, Bip448OwnershipStatus},
    require_canonical_script, require_canonical_txid, require_canonical_xonly_public_key,
    withdrawal::{Bip448WithdrawalAttempt, BIP448_MAX_MONEY_SATS},
};

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
    super::validate_observation(
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
    super::validate_observation(
        observation.observation_status,
        observation.funding_height,
        observation.spend_txid.as_deref(),
        observation.spend_height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
