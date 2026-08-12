use anyhow::{anyhow, Context, Result};
use bitcoin::Transaction;
use secp256k1::{musig::Session as MusigSession, Scalar, XOnlyPublicKey};

use super::{
    canonical::{parse_canonical_transaction, require_optional_hex},
    close::decode_bip448_closing_bindings,
    enums::{
        Bip448BroadcastStatus, Bip448CompletionStatus, Bip448WithdrawalAttemptKind,
        Bip448WithdrawalPhase,
    },
    parse_canonical_sign_first_payload, parse_canonical_sign_second_payload,
    require_canonical_block_hash, require_canonical_hex, require_canonical_public_key,
    require_canonical_script, require_canonical_txid, require_canonical_xonly_public_key,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip448SignatureCountExpectation {
    pub settled_count: u64,
    pub second_armed_landed_count: Option<u64>,
}
fn option_group_is_all_some(values: &[bool]) -> bool {
    values.iter().all(|value| *value)
}

fn option_group_is_all_none(values: &[bool]) -> bool {
    values.iter().all(|value| !*value)
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

#[cfg(test)]
mod tests {
    use super::*;

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
