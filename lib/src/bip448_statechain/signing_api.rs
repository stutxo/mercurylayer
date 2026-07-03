//! Wire payloads and request validation for the Phase 5 versioned BIP448
//! signing API.
//!
//! The BIP448 signing routes (`/bip448-statechain/sign/first` and
//! `/bip448-statechain/sign/second`) are separate from the legacy `/sign/*`
//! routes and must preserve the legacy blind-server property. The Mercury
//! server sees only an opaque client-generated `signing_id`, never the state
//! number, signing role, template hash, transaction contents, outputs, or
//! settlement hash. The lockbox enclave contract is unchanged: the enclave
//! signs a blinded challenge and cannot distinguish a BIP448 `TemplateHash`
//! from a legacy `TapSighash`, so each BIP448 payload converts to the exact
//! legacy enclave payload via [`Bip448SignFirstRequestPayload::to_enclave_payload`]
//! and [`Bip448PartialSignatureRequestPayload::to_enclave_payload`].

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::transaction::{PartialSignatureRequestPayload, SignFirstRequestPayload};

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

/// Response payload for `/bip448-statechain/signature-count/<statechain_id>`,
/// so a receiver can independently verify how many BIP448 update partial
/// signatures the server has produced for a statechain.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bip448SignatureCountResponsePayload {
    pub sig_count: u64,
}

impl Bip448SignFirstRequestPayload {
    /// The exact legacy payload forwarded to the unchanged lockbox enclave.
    pub fn to_enclave_payload(&self) -> SignFirstRequestPayload {
        SignFirstRequestPayload {
            statechain_id: self.statechain_id.clone(),
            signed_statechain_id: self.signed_statechain_id.clone(),
        }
    }
}

impl Bip448PartialSignatureRequestPayload {
    /// The exact legacy payload forwarded to the unchanged lockbox enclave.
    pub fn to_enclave_payload(&self) -> PartialSignatureRequestPayload {
        PartialSignatureRequestPayload {
            statechain_id: self.statechain_id.clone(),
            negate_seckey: self.negate_seckey,
            session: self.session.clone(),
            signed_statechain_id: self.signed_statechain_id.clone(),
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
    fn enclave_payloads_match_the_unchanged_legacy_contract() {
        let first = sample_first_payload();
        let enclave_first = first.to_enclave_payload();
        assert_eq!(enclave_first.statechain_id, first.statechain_id);
        assert_eq!(
            enclave_first.signed_statechain_id,
            first.signed_statechain_id
        );

        let second = Bip448PartialSignatureRequestPayload {
            statechain_id: "sc-1".to_string(),
            signed_statechain_id: "sig-1".to_string(),
            signing_id: SIGNING_ID.to_string(),
            negate_seckey: 1,
            session: "aa".repeat(133),
            server_pub_nonce: "bb".repeat(66),
        };
        let enclave_second = second.to_enclave_payload();
        assert_eq!(enclave_second.statechain_id, second.statechain_id);
        assert_eq!(enclave_second.negate_seckey, second.negate_seckey);
        assert_eq!(enclave_second.session, second.session);
        assert_eq!(
            enclave_second.signed_statechain_id,
            second.signed_statechain_id
        );
        assert_eq!(enclave_second.server_pub_nonce, second.server_pub_nonce);
    }

    #[test]
    fn payloads_round_trip_through_serde() {
        let first = sample_first_payload();
        let json = serde_json::to_string(&first).unwrap();
        assert!(!json.contains("state_number"));
        assert!(!json.contains("signature_role"));
        assert!(!json.contains("template_hash"));

        let back: Bip448SignFirstRequestPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signing_id, first.signing_id);

        let count = Bip448SignatureCountResponsePayload { sig_count: 3 };
        let json = serde_json::to_string(&count).unwrap();
        let back: Bip448SignatureCountResponsePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sig_count, 3);
    }
}
