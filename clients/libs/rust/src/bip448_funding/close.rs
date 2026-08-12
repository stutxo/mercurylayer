use std::fmt;

use anyhow::{anyhow, Context, Result};
use serde::{
    de::{Error as DeError, MapAccess, Visitor},
    Deserialize, Deserializer,
};

use super::{
    bindings::Bip448FundingBinding,
    enums::{
        Bip448BindingRole, Bip448BroadcastStatus, Bip448ObservationStatus, Bip448OwnershipStatus,
        Bip448WithdrawalAttemptKind, Bip448WithdrawalPhase,
    },
    require_canonical_hex, require_canonical_txid, require_canonical_xonly_public_key,
    withdrawal::{Bip448WithdrawalAttempt, BIP448_MAX_MONEY_SATS},
};

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
}
