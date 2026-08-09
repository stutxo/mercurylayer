//! Wire payloads and request validation for the BIP448 signing API.
//!
//! The BIP448 signing routes (`/bip448-statechain/sign/first` and
//! `/bip448-statechain/sign/second`) preserve the blind-server property. The
//! Mercury server sees only an opaque client-generated `signing_id`, never the
//! state number, signing role, template hash, transaction contents, outputs,
//! or settlement hash. The BIP448 lockbox contract makes nonce idempotency
//! authoritative by opaque id without learning transaction metadata.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

/// Request payload for `/bip448-statechain/sign/first`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448SignFirstRequestPayload {
    pub statechain_id: String,
    pub signed_statechain_id: String,
    /// Opaque client-generated 32-byte hex identifier for this blind signing
    /// round. It must be random and must not be derived from transaction data.
    pub signing_id: String,
}

/// Response payload for `/bip448-statechain/sign/first`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448SignFirstResponsePayload {
    pub server_pubnonce: String,
}

/// Request payload for `/bip448-statechain/sign/second`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448PartialSignatureRequestPayload {
    pub statechain_id: String,
    pub signed_statechain_id: String,
    /// Opaque client-generated 32-byte hex identifier from sign/first.
    pub signing_id: String,
    /// The CSFS share-negation flag derived from the untweaked aggregate
    /// point `P_full` (see `signing::csfs_negate_seckey`). This is CSFS
    /// parity metadata, distinct from the legacy Taproot key-path tweak
    /// parity; it is stored with the BIP448 signature record and must be
    /// identical on exact retries.
    pub negate_seckey: u8,
    /// The blinded MuSig session (final nonce removed), hex encoded.
    pub session: String,
    pub server_pub_nonce: String,
}

/// Response payload for `/bip448-statechain/sign/second`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448PartialSignatureResponsePayload {
    pub partial_sig: String,
}

/// Request payload forwarded from Mercury to the BIP448 lockbox nonce route.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448LockboxSignFirstRequestPayload {
    pub statechain_id: String,
    /// Opaque 32-byte hex id. This is random retry/idempotency metadata, not a
    /// transaction-derived value.
    pub signing_id: String,
}

/// Request payload forwarded from Mercury to the BIP448 lockbox partial-signing
/// route. It intentionally excludes auth signatures and transaction metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448LockboxPartialSignatureRequestPayload {
    pub statechain_id: String,
    pub signing_id: String,
    pub negate_seckey: u8,
    pub session: String,
    pub server_pub_nonce: String,
}

/// Response payload for `/bip448-statechain/signature-count/<statechain_id>`,
/// so a receiver can independently verify how many BIP448 update partial
/// signatures the server has produced for a statechain.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448SignatureCountResponsePayload {
    pub sig_count: u64,
}

impl Bip448SignFirstRequestPayload {
    /// The BIP448-specific payload forwarded to the lockbox. It contains only
    /// the opaque idempotency id and statechain scope.
    pub fn to_lockbox_payload(&self) -> Bip448LockboxSignFirstRequestPayload {
        Bip448LockboxSignFirstRequestPayload {
            statechain_id: self.statechain_id.clone(),
            signing_id: self.signing_id.clone(),
        }
    }
}

impl Bip448PartialSignatureRequestPayload {
    /// The BIP448-specific payload forwarded to the lockbox. The lockbox sees
    /// only blinded signing material and opaque retry metadata.
    pub fn to_lockbox_payload(&self) -> Bip448LockboxPartialSignatureRequestPayload {
        Bip448LockboxPartialSignatureRequestPayload {
            statechain_id: self.statechain_id.clone(),
            signing_id: self.signing_id.clone(),
            negate_seckey: self.negate_seckey,
            session: self.session.clone(),
            server_pub_nonce: self.server_pub_nonce.clone(),
        }
    }
}

#[derive(Debug)]
pub enum Bip448SigningRequestError {
    InvalidSigningId,
    InvalidNegateSeckeyFlag { value: u8 },
}

impl fmt::Display for Bip448SigningRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bip448SigningRequestError::InvalidSigningId => f.write_str(
                "BIP448 signing_id must be an opaque client-generated 32-byte hex identifier",
            ),
            Bip448SigningRequestError::InvalidNegateSeckeyFlag { value } => {
                write!(f, "BIP448 negate_seckey flag must be 0 or 1, got {value}")
            }
        }
    }
}

impl Error for Bip448SigningRequestError {}

/// Validates and canonicalizes the opaque signing identifier.
pub fn validate_signing_id(signing_id: &str) -> Result<String, Bip448SigningRequestError> {
    let bytes = hex::decode(signing_id).map_err(|_| Bip448SigningRequestError::InvalidSigningId)?;

    if bytes.len() != 32 {
        return Err(Bip448SigningRequestError::InvalidSigningId);
    }

    Ok(hex::encode(bytes))
}

/// Validates the wire `negate_seckey` flag (must be exactly 0 or 1).
pub fn validate_negate_seckey_flag(value: u8) -> Result<bool, Bip448SigningRequestError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(Bip448SigningRequestError::InvalidNegateSeckeyFlag { value: other }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_ID: &str = "d1f1955b1327167cb7ae3dc39d52c277be39d75737b9cb80514ce6e825fd8eea";

    fn sample_first_payload() -> Bip448SignFirstRequestPayload {
        Bip448SignFirstRequestPayload {
            statechain_id: "sc-1".to_string(),
            signed_statechain_id: "sig-1".to_string(),
            signing_id: SIGNING_ID.to_string(),
        }
    }

    fn assert_no_consensus_template_metadata(json: &str) {
        for forbidden in [
            "state_locktime",
            "locktime",
            "state_number",
            "template_hash",
            "random_offset",
            "stride",
            "500000000",
            "1000000000",
        ] {
            assert!(
                !json.contains(forbidden),
                "serialized signing payload exposed forbidden value {forbidden}: {json}"
            );
        }
        for forbidden_value in [
            "700000042".to_string(),
            "11".repeat(32),
            "22".repeat(32),
            "02000000deadbeef".to_string(),
            "b175cecbcc".to_string(),
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(&forbidden_value),
                "serialized signing payload exposed template value {forbidden_value}: {json}"
            );
        }
    }

    #[test]
    fn signing_id_validation_canonicalizes_hex_case() {
        let validated = validate_signing_id(&SIGNING_ID.to_uppercase()).unwrap();

        assert_eq!(validated, SIGNING_ID);
    }

    #[test]
    fn signing_id_validation_rejects_invalid_identifiers() {
        assert!(matches!(
            validate_signing_id("not-hex"),
            Err(Bip448SigningRequestError::InvalidSigningId)
        ));
        assert!(matches!(
            validate_signing_id("abcd"),
            Err(Bip448SigningRequestError::InvalidSigningId)
        ));
        assert!(matches!(
            validate_signing_id(&"aa".repeat(31)),
            Err(Bip448SigningRequestError::InvalidSigningId)
        ));
    }

    #[test]
    fn negate_seckey_flag_must_be_binary() {
        assert!(!validate_negate_seckey_flag(0).unwrap());
        assert!(validate_negate_seckey_flag(1).unwrap());
        assert!(matches!(
            validate_negate_seckey_flag(2),
            Err(Bip448SigningRequestError::InvalidNegateSeckeyFlag { value: 2 })
        ));
    }

    #[test]
    fn lockbox_payloads_exclude_auth_and_transaction_metadata() {
        let first = sample_first_payload();
        let lockbox_first = first.to_lockbox_payload();
        let first_json = serde_json::to_string(&lockbox_first).unwrap();
        assert_no_consensus_template_metadata(&first_json);
        assert_eq!(lockbox_first.statechain_id, first.statechain_id);
        assert_eq!(lockbox_first.signing_id, first.signing_id);
        assert!(!first_json.contains("signed_statechain_id"));
        assert!(!first_json.contains("state_number"));
        assert!(!first_json.contains("signature_role"));
        assert!(!first_json.contains("template_hash"));

        let second = Bip448PartialSignatureRequestPayload {
            statechain_id: "sc-1".to_string(),
            signed_statechain_id: "sig-1".to_string(),
            signing_id: SIGNING_ID.to_string(),
            negate_seckey: 1,
            session: "aa".repeat(133),
            server_pub_nonce: "bb".repeat(66),
        };
        let lockbox_second = second.to_lockbox_payload();
        let second_json = serde_json::to_string(&lockbox_second).unwrap();
        assert_no_consensus_template_metadata(&second_json);
        assert_eq!(lockbox_second.statechain_id, second.statechain_id);
        assert_eq!(lockbox_second.signing_id, second.signing_id);
        assert_eq!(lockbox_second.negate_seckey, second.negate_seckey);
        assert_eq!(lockbox_second.session, second.session);
        assert_eq!(lockbox_second.server_pub_nonce, second.server_pub_nonce);
        assert!(!second_json.contains("signed_statechain_id"));
        assert!(!second_json.contains("state_number"));
        assert!(!second_json.contains("signature_role"));
        assert!(!second_json.contains("template_hash"));
    }

    #[test]
    fn payloads_round_trip_through_serde() {
        let first = sample_first_payload();
        let json = serde_json::to_string(&first).unwrap();
        assert_no_consensus_template_metadata(&json);
        assert!(!json.contains("state_number"));
        assert!(!json.contains("signature_role"));
        assert!(!json.contains("template_hash"));

        let back: Bip448SignFirstRequestPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signing_id, first.signing_id);

        let first_response = Bip448SignFirstResponsePayload {
            server_pubnonce: "aa".repeat(66),
        };
        let json = serde_json::to_string(&first_response).unwrap();
        assert_no_consensus_template_metadata(&json);
        let back: Bip448SignFirstResponsePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server_pubnonce, first_response.server_pubnonce);

        let second = Bip448PartialSignatureRequestPayload {
            statechain_id: "sc-1".to_string(),
            signed_statechain_id: "sig-1".to_string(),
            signing_id: SIGNING_ID.to_string(),
            negate_seckey: 1,
            session: "bb".repeat(133),
            server_pub_nonce: "cc".repeat(66),
        };
        let json = serde_json::to_string(&second).unwrap();
        assert_no_consensus_template_metadata(&json);
        let back: Bip448PartialSignatureRequestPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signing_id, second.signing_id);

        let second_response = Bip448PartialSignatureResponsePayload {
            partial_sig: "dd".repeat(32),
        };
        let json = serde_json::to_string(&second_response).unwrap();
        assert_no_consensus_template_metadata(&json);
        let back: Bip448PartialSignatureResponsePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.partial_sig, second_response.partial_sig);

        let count = Bip448SignatureCountResponsePayload { sig_count: 3 };
        let json = serde_json::to_string(&count).unwrap();
        assert_no_consensus_template_metadata(&json);
        let back: Bip448SignatureCountResponsePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sig_count, 3);
    }
}
