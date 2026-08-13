use std::collections::BTreeMap;

use anyhow::{anyhow, Result};

use crate::{
    bip448_funding::{Bip448FundingBinding, Bip448ObservationStatus, Bip448SyncBase},
    chain::ChainUtxo,
};

#[derive(Clone)]
pub(super) struct Bip448ReceiveFact {
    pub(super) value_sats: u64,
    pub(super) funding_height: Option<u32>,
}

#[derive(Clone)]
pub(super) struct Bip448SpendFact {
    pub(super) spend_txid: String,
    pub(super) spend_height: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Bip448ResolvedObservation {
    pub(super) observation_status: Bip448ObservationStatus,
    pub(super) funding_height: Option<u32>,
    pub(super) spend_txid: Option<String>,
    pub(super) spend_height: Option<u32>,
}

fn funding_status_at_tip(
    height: Option<u32>,
    tip_height: u32,
    confirmation_target: u32,
    spent: bool,
) -> Result<Bip448ObservationStatus> {
    let confirmations = match height {
        Some(height) => tip_height
            .checked_sub(height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or_else(|| anyhow!("BIP448 observation height exceeds the stable scan tip"))?,
        None => 0,
    };
    Ok(
        match (spent, height, confirmations >= confirmation_target) {
            (false, None, _) => Bip448ObservationStatus::Mempool,
            (false, Some(_), true) => Bip448ObservationStatus::Confirmed,
            (false, Some(_), false) => Bip448ObservationStatus::Unconfirmed,
            (true, None, _) => Bip448ObservationStatus::SpentMempool,
            (true, Some(_), true) => Bip448ObservationStatus::SpentConfirmed,
            (true, Some(_), false) => Bip448ObservationStatus::SpentUnconfirmed,
        },
    )
}

pub(super) fn height_from_confirmations(
    tip_height: u32,
    confirmations: u32,
) -> Result<Option<u32>> {
    if confirmations == 0 {
        return Ok(None);
    }
    tip_height
        .checked_sub(confirmations - 1)
        .map(Some)
        .ok_or_else(|| anyhow!("BIP448 gettxout confirmations exceed the stable scan tip"))
}

fn retained_observation_status_at_tip(
    status: Bip448ObservationStatus,
    spend_height: Option<u32>,
    tip_height: u32,
    confirmation_target: u32,
) -> Result<Bip448ObservationStatus> {
    if status != Bip448ObservationStatus::SpentUnconfirmed {
        return Ok(status);
    }
    let spend_height = spend_height
        .ok_or_else(|| anyhow!("SpentUnconfirmed BIP448 observation is missing spend height"))?;
    funding_status_at_tip(Some(spend_height), tip_height, confirmation_target, true)
}

pub(super) fn resolve_bip448_observation_at_tip(
    current: Option<&ChainUtxo>,
    spend: Option<&Bip448SpendFact>,
    receive: Option<&Bip448ReceiveFact>,
    existing: Option<&Bip448FundingBinding>,
    authoritative_full_scan: bool,
    tip_height: u32,
    confirmation_target: u32,
) -> Result<Option<Bip448ResolvedObservation>> {
    if let Some(current) = current {
        let funding_height = (current.height != 0).then_some(current.height);
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: funding_status_at_tip(
                funding_height,
                tip_height,
                confirmation_target,
                false,
            )?,
            funding_height,
            spend_txid: None,
            spend_height: None,
        }));
    }
    if let Some(spend) = spend {
        // A fresh receive fact, including an explicit mempool receive, is
        // authoritative for the funding height. Fall back to the durable
        // height only when this incremental interval contains no receive.
        let funding_height = receive.map_or_else(
            || existing.and_then(|binding| binding.funding_height),
            |receive| receive.funding_height,
        );
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: funding_status_at_tip(
                spend.spend_height,
                tip_height,
                confirmation_target,
                true,
            )?,
            funding_height,
            spend_txid: Some(spend.spend_txid.clone()),
            spend_height: spend.spend_height,
        }));
    }
    if let Some(receive) = receive {
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: funding_status_at_tip(
                receive.funding_height,
                tip_height,
                confirmation_target,
                false,
            )?,
            funding_height: receive.funding_height,
            spend_txid: None,
            spend_height: None,
        }));
    }
    if authoritative_full_scan {
        return Ok(Some(Bip448ResolvedObservation {
            observation_status: Bip448ObservationStatus::Absent,
            funding_height: None,
            spend_txid: None,
            spend_height: None,
        }));
    }
    let Some(existing) = existing else {
        return Ok(None);
    };
    Ok(Some(Bip448ResolvedObservation {
        observation_status: retained_observation_status_at_tip(
            existing.observation_status,
            existing.spend_height,
            tip_height,
            confirmation_target,
        )?,
        funding_height: existing.funding_height,
        spend_txid: existing.spend_txid.clone(),
        spend_height: existing.spend_height,
    }))
}

pub(super) fn insert_receive_fact(
    receives: &mut BTreeMap<(String, u32), Bip448ReceiveFact>,
    key: (String, u32),
    fact: Bip448ReceiveFact,
) -> Result<()> {
    if let Some(existing) = receives.get(&key) {
        if existing.value_sats != fact.value_sats || existing.funding_height != fact.funding_height
        {
            return Err(anyhow!("conflicting BIP448 receive observations"));
        }
        return Ok(());
    }
    receives.insert(key, fact);
    Ok(())
}

fn spend_fact_order(fact: &Bip448SpendFact) -> (bool, u32, &str) {
    (
        fact.spend_height.is_none(),
        fact.spend_height.unwrap_or(u32::MAX),
        fact.spend_txid.as_str(),
    )
}

pub(super) fn insert_spend_fact(
    spends: &mut BTreeMap<(String, u32), Bip448SpendFact>,
    key: (String, u32),
    fact: Bip448SpendFact,
) {
    match spends.get(&key) {
        Some(existing) if spend_fact_order(existing) <= spend_fact_order(&fact) => {}
        _ => {
            spends.insert(key, fact);
        }
    }
}

pub(super) fn disappeared_mempool_receive_requires_authoritative_replay(
    authoritative: bool,
    existing_status: Bip448ObservationStatus,
    current: bool,
    receive: bool,
    spend: bool,
) -> bool {
    !authoritative
        && existing_status == Bip448ObservationStatus::Mempool
        && !current
        && !receive
        && !spend
}

pub(super) fn require_stable_authoritative_replay_base(
    incremental: &Bip448SyncBase,
    replay: &Bip448SyncBase,
) -> Result<()> {
    if incremental != replay {
        return Err(anyhow!(
            "BIP448 synchronization base changed during authoritative mempool replay"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip448_funding::{Bip448BindingRole, Bip448OwnershipStatus};
    use anyhow::Context;

    #[test]
    fn incremental_positive_spend_reaches_the_confirmation_target() -> Result<()> {
        assert_eq!(
            retained_observation_status_at_tip(
                Bip448ObservationStatus::SpentUnconfirmed,
                Some(100),
                104,
                6,
            )?,
            Bip448ObservationStatus::SpentUnconfirmed
        );
        assert_eq!(
            retained_observation_status_at_tip(
                Bip448ObservationStatus::SpentUnconfirmed,
                Some(100),
                105,
                6,
            )?,
            Bip448ObservationStatus::SpentConfirmed
        );
        assert!(retained_observation_status_at_tip(
            Bip448ObservationStatus::SpentUnconfirmed,
            None,
            105,
            6,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn reorged_and_reappeared_mempool_receives_clear_historical_heights() -> Result<()> {
        let mut existing = Bip448FundingBinding {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            binding_index: 1,
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 70_000,
            script_pubkey: "51".to_string(),
            role: Bip448BindingRole::Duplicate,
            observation_status: Bip448ObservationStatus::Confirmed,
            funding_height: Some(100),
            spend_txid: None,
            spend_height: None,
            last_scanned_height: 110,
            owner_user_pubkey: "22".repeat(32),
            owner_state_number: 1,
            ownership_status: Bip448OwnershipStatus::Current,
            first_seen_at: "first".to_string(),
            last_seen_at: "last".to_string(),
        };
        let mempool_current = ChainUtxo {
            txid: existing.txid.clone(),
            vout: existing.vout,
            value: existing.value_sats,
            height: 0,
        };
        let mempool_receive = Bip448ReceiveFact {
            value_sats: existing.value_sats,
            funding_height: None,
        };
        let expected_mempool = Bip448ResolvedObservation {
            observation_status: Bip448ObservationStatus::Mempool,
            funding_height: None,
            spend_txid: None,
            spend_height: None,
        };

        assert_eq!(
            resolve_bip448_observation_at_tip(
                Some(&mempool_current),
                None,
                Some(&mempool_receive),
                Some(&existing),
                false,
                110,
                6,
            )?,
            Some(expected_mempool)
        );

        // A retained historical height is permitted for Absent storage, but a
        // positive mempool reappearance must still replace it with None.
        existing.observation_status = Bip448ObservationStatus::Absent;
        assert_eq!(
            resolve_bip448_observation_at_tip(
                Some(&mempool_current),
                None,
                None,
                Some(&existing),
                false,
                110,
                6,
            )?
            .context("mempool reappearance must resolve")?
            .funding_height,
            None
        );

        Ok(())
    }

    #[test]
    fn authoritative_absence_and_incremental_retention_are_status_height_coherent() -> Result<()> {
        let existing = Bip448FundingBinding {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            binding_index: 1,
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 70_000,
            script_pubkey: "51".to_string(),
            role: Bip448BindingRole::Duplicate,
            observation_status: Bip448ObservationStatus::Mempool,
            funding_height: None,
            spend_txid: None,
            spend_height: None,
            last_scanned_height: 110,
            owner_user_pubkey: "22".repeat(32),
            owner_state_number: 1,
            ownership_status: Bip448OwnershipStatus::Current,
            first_seen_at: "first".to_string(),
            last_seen_at: "last".to_string(),
        };

        assert_eq!(
            resolve_bip448_observation_at_tip(None, None, None, Some(&existing), false, 110, 6,)?,
            Some(Bip448ResolvedObservation {
                observation_status: Bip448ObservationStatus::Mempool,
                funding_height: None,
                spend_txid: None,
                spend_height: None,
            })
        );
        assert_eq!(
            resolve_bip448_observation_at_tip(None, None, None, Some(&existing), true, 110, 6,)?,
            Some(Bip448ResolvedObservation {
                observation_status: Bip448ObservationStatus::Absent,
                funding_height: None,
                spend_txid: None,
                spend_height: None,
            })
        );

        Ok(())
    }

    #[test]
    fn fresh_receive_height_overrides_spend_fallback_but_incremental_spend_retains_it() -> Result<()>
    {
        let existing = Bip448FundingBinding {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            binding_index: 1,
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 70_000,
            script_pubkey: "51".to_string(),
            role: Bip448BindingRole::Duplicate,
            observation_status: Bip448ObservationStatus::Confirmed,
            funding_height: Some(100),
            spend_txid: None,
            spend_height: None,
            last_scanned_height: 110,
            owner_user_pubkey: "22".repeat(32),
            owner_state_number: 1,
            ownership_status: Bip448OwnershipStatus::Current,
            first_seen_at: "first".to_string(),
            last_seen_at: "last".to_string(),
        };
        let spend = Bip448SpendFact {
            spend_txid: "33".repeat(32),
            spend_height: None,
        };
        let mempool_receive = Bip448ReceiveFact {
            value_sats: existing.value_sats,
            funding_height: None,
        };

        let fresh = resolve_bip448_observation_at_tip(
            None,
            Some(&spend),
            Some(&mempool_receive),
            Some(&existing),
            false,
            110,
            6,
        )?
        .context("fresh spend observation")?;
        assert_eq!(
            fresh.observation_status,
            Bip448ObservationStatus::SpentMempool
        );
        assert_eq!(fresh.funding_height, None);

        let incremental = resolve_bip448_observation_at_tip(
            None,
            Some(&spend),
            None,
            Some(&existing),
            false,
            110,
            6,
        )?
        .context("incremental spend observation")?;
        assert_eq!(
            incremental.observation_status,
            Bip448ObservationStatus::SpentMempool
        );
        assert_eq!(incremental.funding_height, Some(100));

        Ok(())
    }

    #[test]
    fn vanished_mempool_receive_requires_one_authoritative_replay_only() {
        assert!(disappeared_mempool_receive_requires_authoritative_replay(
            false,
            Bip448ObservationStatus::Mempool,
            false,
            false,
            false,
        ));
        for (authoritative, status, current, receive, spend) in [
            (true, Bip448ObservationStatus::Mempool, false, false, false),
            (
                false,
                Bip448ObservationStatus::Confirmed,
                false,
                false,
                false,
            ),
            (false, Bip448ObservationStatus::Mempool, true, false, false),
            (false, Bip448ObservationStatus::Mempool, false, true, false),
            (false, Bip448ObservationStatus::Mempool, false, false, true),
        ] {
            assert!(!disappeared_mempool_receive_requires_authoritative_replay(
                authoritative,
                status,
                current,
                receive,
                spend,
            ));
        }
    }

    #[test]
    fn authoritative_mempool_replay_rejects_any_full_base_race() {
        let base = Bip448SyncBase {
            wallet_name: "wallet".to_string(),
            script_pubkey: "51".to_string(),
            raw_wallet_json: "wallet-bytes".to_string(),
            pending_deposit_rows: vec!["pending".to_string()],
            accepted_record_rows: vec!["record".to_string()],
            state_history_rows: vec!["history".to_string()],
            cursor_rows: vec!["cursor".to_string()],
            scan_cache_rows: vec!["cache".to_string()],
            funding_binding_rows: vec!["binding".to_string()],
            withdrawal_attempt_rows: vec!["attempt".to_string()],
            transfer_intent_rows: vec!["intent".to_string()],
            pending_transfer_rows: vec!["transfer-pending".to_string()],
            outgoing_transfer_message_rows: vec!["message".to_string()],
        };
        require_stable_authoritative_replay_base(&base, &base).unwrap();
        for mutate in 0..4 {
            let mut raced = base.clone();
            match mutate {
                0 => raced.raw_wallet_json.push_str("-changed"),
                1 => raced.cursor_rows.push("new-cursor".to_string()),
                2 => raced.funding_binding_rows.push("new-binding".to_string()),
                3 => raced.state_history_rows.push("new-history".to_string()),
                _ => unreachable!(),
            }
            assert!(require_stable_authoritative_replay_base(&base, &raced).is_err());
        }
    }
}
