//! Wire payloads and request validation for the BIP448 signing API.
//!
//! The BIP448 signing routes (`/bip448-statechain/sign/first` and
//! `/bip448-statechain/sign/second`) preserve the blind-server property. The
//! Mercury server sees only an opaque client-generated `signing_id`, never the
//! state number, signing role, template hash, transaction contents, outputs,
//! or settlement hash. The BIP448 lockbox contract makes nonce idempotency
//! authoritative by opaque id without learning transaction metadata.

use std::{error::Error, fmt};

use bitcoin::hashes::{sha256, Hash};
use secp256k1::{
    musig::{PublicNonce as MusigPublicNonce, Session as MusigSession},
    PublicKey, Scalar, SecretKey,
};
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};

pub const BIP448_PROTOCOL_VERSION_V2: u8 = 2;

const BIP448_LOCKBOX_KEYUPDATE_V2_DOMAIN: &[u8] = b"BIP448/lockbox-keyupdate/v2\0";
const BIP448_MUSIG_SESSION_SERIALIZED_SIZE: usize = 133;
const BIP448_MUSIG_SESSION_MAGIC: [u8; 4] = [0x9d, 0xed, 0xe9, 0x17];
const BIP448_MUSIG_FINAL_NONCE_RANGE: std::ops::Range<usize> = 5..37;
const BIP448_MUSIG_SCALAR_RANGES: [std::ops::Range<usize>; 3] = [37..69, 69..101, 101..133];
const SECP256K1_FIELD_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];
const SECP256K1_GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bip448WireError {
    InvalidProtocolVersion {
        value: u8,
    },
    InvalidStatechainId,
    InvalidCanonicalHex {
        field: &'static str,
        expected_bytes: usize,
    },
    InvalidCanonicalScalar,
    InvalidSecretScalar,
    ZeroSecretScalar,
    InvalidCompressedPublicKey,
    InvalidSchnorrSignature,
    InvalidPublicNonce,
    InvalidBlindedSession,
    InvalidNegateSeckeyFlag {
        value: u8,
    },
    StateNumberOverflow {
        value: u64,
    },
    NegativeDatabaseInteger {
        field: &'static str,
        value: i64,
    },
    DatabaseIntegerOverflow {
        field: &'static str,
        value: u64,
    },
    StatechainIdLengthOverflow,
}

impl fmt::Display for Bip448WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProtocolVersion { value } => {
                write!(f, "BIP448 protocol version must be 2, got {value}")
            }
            Self::InvalidStatechainId => f.write_str(
                "BIP448 statechain_id must contain between 1 and 50 UTF-8 bytes",
            ),
            Self::InvalidCanonicalHex {
                field,
                expected_bytes,
            } => write!(
                f,
                "BIP448 {field} must be exactly {expected_bytes} bytes of lowercase, prefix-free hex"
            ),
            Self::InvalidCanonicalScalar => {
                f.write_str("BIP448 scalar must be canonical for secp256k1")
            }
            Self::InvalidSecretScalar => {
                f.write_str("BIP448 secret scalar must be canonical for secp256k1")
            }
            Self::ZeroSecretScalar => f.write_str("BIP448 secret scalar must be nonzero"),
            Self::InvalidCompressedPublicKey => {
                f.write_str("BIP448 public key must be a canonical compressed secp256k1 key")
            }
            Self::InvalidSchnorrSignature => {
                f.write_str("BIP448 signature must be a canonical 64-byte Schnorr signature")
            }
            Self::InvalidPublicNonce => {
                f.write_str("BIP448 public nonce must be a canonical 66-byte MuSig nonce")
            }
            Self::InvalidBlindedSession => {
                f.write_str("BIP448 blinded session must be the canonical 133-byte encoding")
            }
            Self::InvalidNegateSeckeyFlag { value } => {
                write!(f, "BIP448 negate_seckey flag must be 0 or 1, got {value}")
            }
            Self::StateNumberOverflow { value } => {
                write!(f, "BIP448 signature count {value} exceeds the u32 state-number range")
            }
            Self::NegativeDatabaseInteger { field, value } => {
                write!(f, "BIP448 database {field} must be nonnegative, got {value}")
            }
            Self::DatabaseIntegerOverflow { field, value } => {
                write!(f, "BIP448 {field} {value} exceeds the signed database range")
            }
            Self::StatechainIdLengthOverflow => {
                f.write_str("BIP448 statechain_id length exceeds the u32 wire range")
            }
        }
    }
}

impl Error for Bip448WireError {}

fn decode_canonical_lower_hex<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], Bip448WireError> {
    let expected_len = N
        .checked_mul(2)
        .ok_or(Bip448WireError::InvalidCanonicalHex {
            field,
            expected_bytes: N,
        })?;
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Bip448WireError::InvalidCanonicalHex {
            field,
            expected_bytes: N,
        });
    }

    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Bip448WireError::InvalidCanonicalHex {
        field,
        expected_bytes: N,
    })?;
    Ok(bytes)
}

macro_rules! canonical_hex_newtype {
    ($name:ident, $size:expr, $field:literal) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; $size] {
                self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Bip448WireError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Ok(Self(decode_canonical_lower_hex::<$size>(value, $field)?))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&hex::encode(self.0))
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&hex::encode(self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value.as_str()).map_err(de::Error::custom)
            }
        }
    };
}

canonical_hex_newtype!(Bip448OperationId, 32, "operation_id");
canonical_hex_newtype!(Bip448RequestHash, 32, "request_hash");
canonical_hex_newtype!(Bip448SigningId, 32, "signing_id");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip448ProtocolVersionV2;

impl Serialize for Bip448ProtocolVersionV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(BIP448_PROTOCOL_VERSION_V2)
    }
}

impl<'de> Deserialize<'de> for Bip448ProtocolVersionV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        if value == BIP448_PROTOCOL_VERSION_V2 {
            Ok(Self)
        } else {
            Err(de::Error::custom(Bip448WireError::InvalidProtocolVersion {
                value,
            }))
        }
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Bip448StatechainId(String);

impl Bip448StatechainId {
    pub fn new(value: String) -> Result<Self, Bip448WireError> {
        if value.is_empty() || value.len() > 50 || value.contains('\0') {
            return Err(Bip448WireError::InvalidStatechainId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl TryFrom<&str> for Bip448StatechainId {
    type Error = Bip448WireError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_owned())
    }
}

impl fmt::Display for Bip448StatechainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Bip448StatechainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Bip448StatechainId").field(&self.0).finish()
    }
}

impl Serialize for Bip448StatechainId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bip448StatechainId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

macro_rules! nonnegative_counter_newtype {
    ($name:ident, $database_field:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl TryFrom<i64> for $name {
            type Error = Bip448WireError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                let value =
                    u64::try_from(value).map_err(|_| Bip448WireError::NegativeDatabaseInteger {
                        field: $database_field,
                        value,
                    })?;
                Ok(Self(value))
            }
        }

        impl TryFrom<$name> for i64 {
            type Error = Bip448WireError;

            fn try_from(value: $name) -> Result<Self, Self::Error> {
                i64::try_from(value.0).map_err(|_| Bip448WireError::DatabaseIntegerOverflow {
                    field: $database_field,
                    value: value.0,
                })
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u64(self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Ok(Self(u64::deserialize(deserializer)?))
            }
        }
    };
}

nonnegative_counter_newtype!(Bip448SignatureCount, "sig_count");
nonnegative_counter_newtype!(Bip448KeyGeneration, "key_generation");

impl TryFrom<Bip448SignatureCount> for u32 {
    type Error = Bip448WireError;

    fn try_from(value: Bip448SignatureCount) -> Result<Self, Self::Error> {
        u32::try_from(value.get())
            .map_err(|_| Bip448WireError::StateNumberOverflow { value: value.get() })
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Bip448CanonicalScalar([u8; 32]);

impl Bip448CanonicalScalar {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Bip448WireError> {
        Scalar::from_be_bytes(bytes).map_err(|_| Bip448WireError::InvalidCanonicalScalar)?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&str> for Bip448CanonicalScalar {
    type Error = Bip448WireError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_bytes(decode_canonical_lower_hex(value, "scalar")?)
    }
}

impl fmt::Debug for Bip448CanonicalScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Bip448CanonicalScalar")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl Serialize for Bip448CanonicalScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Bip448CanonicalScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Bip448SecretScalar([u8; 32]);

impl Bip448SecretScalar {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Bip448WireError> {
        Scalar::from_be_bytes(bytes).map_err(|_| Bip448WireError::InvalidSecretScalar)?;
        if bytes == [0_u8; 32] {
            return Err(Bip448WireError::ZeroSecretScalar);
        }
        let parsed = SecretKey::from_secret_bytes(bytes)
            .map_err(|_| Bip448WireError::InvalidSecretScalar)?;
        if parsed.to_secret_bytes() != bytes {
            return Err(Bip448WireError::InvalidSecretScalar);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&str> for Bip448SecretScalar {
    type Error = Bip448WireError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_bytes(decode_canonical_lower_hex(value, "secret scalar")?)
    }
}

impl fmt::Debug for Bip448SecretScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bip448SecretScalar([REDACTED])")
    }
}

impl Serialize for Bip448SecretScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Bip448SecretScalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

macro_rules! checked_hex_newtype {
    ($name:ident, $size:expr, $field:literal, $validate:expr) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl $name {
            pub fn from_bytes(bytes: [u8; $size]) -> Result<Self, Bip448WireError> {
                ($validate)(&bytes)?;
                Ok(Self(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Bip448WireError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::from_bytes(decode_canonical_lower_hex(value, $field)?)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&hex::encode(self.0))
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&hex::encode(self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value.as_str()).map_err(de::Error::custom)
            }
        }
    };
}

fn validate_compressed_public_key(bytes: &[u8; 33]) -> Result<(), Bip448WireError> {
    let key =
        PublicKey::from_slice(bytes).map_err(|_| Bip448WireError::InvalidCompressedPublicKey)?;
    if key.serialize() != *bytes {
        return Err(Bip448WireError::InvalidCompressedPublicKey);
    }
    Ok(())
}

fn validate_schnorr_signature(bytes: &[u8; 64]) -> Result<(), Bip448WireError> {
    let r: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| Bip448WireError::InvalidSchnorrSignature)?;
    let s: [u8; 32] = bytes[32..]
        .try_into()
        .map_err(|_| Bip448WireError::InvalidSchnorrSignature)?;
    if r >= SECP256K1_FIELD_PRIME || s >= SECP256K1_GROUP_ORDER {
        return Err(Bip448WireError::InvalidSchnorrSignature);
    }
    Ok(())
}

fn validate_public_nonce(bytes: &[u8; 66]) -> Result<(), Bip448WireError> {
    let nonce =
        MusigPublicNonce::from_slice(bytes).map_err(|_| Bip448WireError::InvalidPublicNonce)?;
    if nonce.serialize() != *bytes {
        return Err(Bip448WireError::InvalidPublicNonce);
    }
    Ok(())
}

checked_hex_newtype!(
    Bip448CompressedPublicKey,
    33,
    "compressed public key",
    validate_compressed_public_key
);
checked_hex_newtype!(
    Bip448SchnorrSignature,
    64,
    "Schnorr signature",
    validate_schnorr_signature
);
checked_hex_newtype!(Bip448PublicNonce, 66, "public nonce", validate_public_nonce);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Bip448BlindedSession([u8; BIP448_MUSIG_SESSION_SERIALIZED_SIZE]);

impl Bip448BlindedSession {
    pub fn from_bytes(
        bytes: [u8; BIP448_MUSIG_SESSION_SERIALIZED_SIZE],
    ) -> Result<Self, Bip448WireError> {
        if bytes[..BIP448_MUSIG_SESSION_MAGIC.len()] != BIP448_MUSIG_SESSION_MAGIC
            || !matches!(bytes[4], 0 | 1)
            || bytes[BIP448_MUSIG_FINAL_NONCE_RANGE]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(Bip448WireError::InvalidBlindedSession);
        }
        for range in BIP448_MUSIG_SCALAR_RANGES {
            let scalar: [u8; 32] = bytes[range]
                .try_into()
                .map_err(|_| Bip448WireError::InvalidBlindedSession)?;
            Scalar::from_be_bytes(scalar).map_err(|_| Bip448WireError::InvalidBlindedSession)?;
        }

        // The dependency's legacy parser is infallible and assumes its cache
        // marker/scalars are valid. Invoke it only after the independent wire
        // checks above, then require byte-identical round-trip behavior.
        let session = MusigSession::from_slice(bytes);
        if session.serialize() != bytes {
            return Err(Bip448WireError::InvalidBlindedSession);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; BIP448_MUSIG_SESSION_SERIALIZED_SIZE] {
        &self.0
    }
}

impl TryFrom<&str> for Bip448BlindedSession {
    type Error = Bip448WireError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_bytes(decode_canonical_lower_hex(value, "blinded session")?)
    }
}

impl fmt::Debug for Bip448BlindedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bip448BlindedSession([REDACTED])")
    }
}

impl Serialize for Bip448BlindedSession {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Bip448BlindedSession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value.as_str()).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip448NegateSeckeyFlag(bool);

impl Bip448NegateSeckeyFlag {
    pub const fn get(self) -> bool {
        self.0
    }
}

impl TryFrom<u8> for Bip448NegateSeckeyFlag {
    type Error = Bip448WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self(false)),
            1 => Ok(Self(true)),
            other => Err(Bip448WireError::InvalidNegateSeckeyFlag { value: other }),
        }
    }
}

impl Serialize for Bip448NegateSeckeyFlag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(u8::from(self.0))
    }
}

impl<'de> Deserialize<'de> for Bip448NegateSeckeyFlag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(u8::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bip448LockboxStateResponsePayloadV2 {
    pub protocol_version: Bip448ProtocolVersionV2,
    pub statechain_id: Bip448StatechainId,
    pub sig_count: Bip448SignatureCount,
    pub key_generation: Bip448KeyGeneration,
    pub server_pubkey: Bip448CompressedPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bip448LockboxSignFirstRequestPayloadV2 {
    pub statechain_id: Bip448StatechainId,
    pub signing_id: Bip448SigningId,
    pub expected_key_generation: Bip448KeyGeneration,
    pub expected_server_pubkey: Bip448CompressedPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bip448LockboxPartialSignatureRequestPayloadV2 {
    pub statechain_id: Bip448StatechainId,
    pub signing_id: Bip448SigningId,
    pub negate_seckey: Bip448NegateSeckeyFlag,
    pub session: Bip448BlindedSession,
    pub server_pub_nonce: Bip448PublicNonce,
    pub expected_key_generation: Bip448KeyGeneration,
    pub expected_server_pubkey: Bip448CompressedPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bip448LockboxKeyUpdateRequestPayloadV2 {
    pub protocol_version: Bip448ProtocolVersionV2,
    pub operation_id: Bip448OperationId,
    pub statechain_id: Bip448StatechainId,
    pub t2: Bip448SecretScalar,
    pub x1: Bip448SecretScalar,
    pub expected_sig_count: Bip448SignatureCount,
    pub expected_key_generation: Bip448KeyGeneration,
    pub expected_server_pubkey: Bip448CompressedPublicKey,
}

impl Bip448LockboxKeyUpdateRequestPayloadV2 {
    pub fn canonical_request_preimage(&self) -> Result<Vec<u8>, Bip448WireError> {
        let statechain_id = self.statechain_id.as_str().as_bytes();
        let statechain_id_len = u32::try_from(statechain_id.len())
            .map_err(|_| Bip448WireError::StatechainIdLengthOverflow)?;
        let mut preimage = Vec::with_capacity(
            BIP448_LOCKBOX_KEYUPDATE_V2_DOMAIN.len()
                + 1
                + 32
                + 4
                + statechain_id.len()
                + 32
                + 32
                + 8
                + 8
                + 33,
        );
        preimage.extend_from_slice(BIP448_LOCKBOX_KEYUPDATE_V2_DOMAIN);
        preimage.push(BIP448_PROTOCOL_VERSION_V2);
        preimage.extend_from_slice(self.operation_id.as_bytes());
        preimage.extend_from_slice(&statechain_id_len.to_be_bytes());
        preimage.extend_from_slice(statechain_id);
        preimage.extend_from_slice(self.t2.as_bytes());
        preimage.extend_from_slice(self.x1.as_bytes());
        preimage.extend_from_slice(&self.expected_sig_count.get().to_be_bytes());
        preimage.extend_from_slice(&self.expected_key_generation.get().to_be_bytes());
        preimage.extend_from_slice(self.expected_server_pubkey.as_bytes());
        Ok(preimage)
    }

    pub fn request_hash(&self) -> Result<Bip448RequestHash, Bip448WireError> {
        Ok(Bip448RequestHash::from_bytes(
            sha256::Hash::hash(&self.canonical_request_preimage()?).to_byte_array(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip448AppliedStatus;

impl Serialize for Bip448AppliedStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("applied")
    }
}

impl<'de> Deserialize<'de> for Bip448AppliedStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == "applied" {
            Ok(Self)
        } else {
            Err(de::Error::unknown_variant(&value, &["applied"]))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bip448KeyUpdateAppliedReceiptPayloadV2 {
    pub protocol_version: Bip448ProtocolVersionV2,
    pub operation_id: Bip448OperationId,
    pub statechain_id: Bip448StatechainId,
    pub status: Bip448AppliedStatus,
    pub accepted_sig_count: Bip448SignatureCount,
    pub previous_key_generation: Bip448KeyGeneration,
    pub resulting_key_generation: Bip448KeyGeneration,
    pub previous_server_pubkey: Bip448CompressedPublicKey,
    pub resulting_server_pubkey: Bip448CompressedPublicKey,
    pub transfer_generation_pubkey: Bip448CompressedPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bip448StatechainInfoV2 {
    pub statechain_id: Bip448StatechainId,
    pub server_pubnonce: Bip448PublicNonce,
    pub challenge: Bip448CanonicalScalar,
    pub tx_n: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bip448StatechainInfoResponsePayloadV2 {
    pub protocol_version: Bip448ProtocolVersionV2,
    pub enclave_public_key: Bip448CompressedPublicKey,
    pub num_sigs: Bip448SignatureCount,
    pub lockbox_key_generation: Bip448KeyGeneration,
    pub statechain_info: Vec<Bip448StatechainInfoV2>,
    pub x1_pub: Bip448CompressedPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq)]
pub enum Bip448HandoffErrorCode {
    #[serde(rename = "bip448_signature_count_mismatch")]
    SignatureCountMismatch,
    #[serde(rename = "bip448_key_generation_mismatch")]
    KeyGenerationMismatch,
    #[serde(rename = "bip448_server_key_mismatch")]
    ServerKeyMismatch,
    #[serde(rename = "bip448_operation_conflict")]
    OperationConflict,
    #[serde(rename = "bip448_transfer_generation_mismatch")]
    TransferGenerationMismatch,
    #[serde(rename = "bip448_keyupdate_rejected")]
    KeyupdateRejected,
    #[serde(rename = "bip448_keyupdate_pending")]
    KeyupdatePending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bip448HandoffErrorClass {
    Conflict,
    Pending,
}

impl Bip448HandoffErrorCode {
    pub const fn class(self) -> Bip448HandoffErrorClass {
        match self {
            Self::SignatureCountMismatch
            | Self::KeyGenerationMismatch
            | Self::ServerKeyMismatch
            | Self::OperationConflict
            | Self::TransferGenerationMismatch
            | Self::KeyupdateRejected => Bip448HandoffErrorClass::Conflict,
            Self::KeyupdatePending => Bip448HandoffErrorClass::Pending,
        }
    }

    pub const fn later_http_status(self) -> u16 {
        match self.class() {
            Bip448HandoffErrorClass::Conflict => 409,
            Bip448HandoffErrorClass::Pending => 503,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip448HandoffErrorResponsePayloadV2 {
    pub code: Bip448HandoffErrorCode,
    pub message: String,
    pub operation_id: Option<Bip448OperationId>,
    pub expected_sig_count: Option<Bip448SignatureCount>,
    pub actual_sig_count: Option<Bip448SignatureCount>,
    pub expected_key_generation: Option<Bip448KeyGeneration>,
    pub actual_key_generation: Option<Bip448KeyGeneration>,
}

impl Bip448HandoffErrorResponsePayloadV2 {
    fn validate(&self) -> Result<(), &'static str> {
        if self.code == Bip448HandoffErrorCode::KeyupdatePending && self.operation_id.is_none() {
            return Err("bip448_keyupdate_pending requires operation_id");
        }
        Ok(())
    }
}

impl Serialize for Bip448HandoffErrorResponsePayloadV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        let optional_count = [
            self.operation_id.is_some(),
            self.expected_sig_count.is_some(),
            self.actual_sig_count.is_some(),
            self.expected_key_generation.is_some(),
            self.actual_key_generation.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        let mut state = serializer
            .serialize_struct("Bip448HandoffErrorResponsePayloadV2", 2 + optional_count)?;
        state.serialize_field("code", &self.code)?;
        state.serialize_field("message", &self.message)?;
        if let Some(value) = self.operation_id {
            state.serialize_field("operation_id", &value)?;
        }
        if let Some(value) = self.expected_sig_count {
            state.serialize_field("expected_sig_count", &value)?;
        }
        if let Some(value) = self.actual_sig_count {
            state.serialize_field("actual_sig_count", &value)?;
        }
        if let Some(value) = self.expected_key_generation {
            state.serialize_field("expected_key_generation", &value)?;
        }
        if let Some(value) = self.actual_key_generation {
            state.serialize_field("actual_key_generation", &value)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for Bip448HandoffErrorResponsePayloadV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorEnvelopeVisitor;

        impl<'de> Visitor<'de> for ErrorEnvelopeVisitor {
            type Value = Bip448HandoffErrorResponsePayloadV2;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a canonical BIP448 handoff v2 error envelope")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut code = None;
                let mut message = None;
                let mut operation_id = None;
                let mut expected_sig_count = None;
                let mut actual_sig_count = None;
                let mut expected_key_generation = None;
                let mut actual_key_generation = None;

                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "code" => {
                            if code.is_some() {
                                return Err(de::Error::duplicate_field("code"));
                            }
                            code = Some(map.next_value()?);
                        }
                        "message" => {
                            if message.is_some() {
                                return Err(de::Error::duplicate_field("message"));
                            }
                            message = Some(map.next_value()?);
                        }
                        "operation_id" => {
                            if operation_id.is_some() {
                                return Err(de::Error::duplicate_field("operation_id"));
                            }
                            operation_id = Some(map.next_value()?);
                        }
                        "expected_sig_count" => {
                            if expected_sig_count.is_some() {
                                return Err(de::Error::duplicate_field("expected_sig_count"));
                            }
                            expected_sig_count = Some(map.next_value()?);
                        }
                        "actual_sig_count" => {
                            if actual_sig_count.is_some() {
                                return Err(de::Error::duplicate_field("actual_sig_count"));
                            }
                            actual_sig_count = Some(map.next_value()?);
                        }
                        "expected_key_generation" => {
                            if expected_key_generation.is_some() {
                                return Err(de::Error::duplicate_field("expected_key_generation"));
                            }
                            expected_key_generation = Some(map.next_value()?);
                        }
                        "actual_key_generation" => {
                            if actual_key_generation.is_some() {
                                return Err(de::Error::duplicate_field("actual_key_generation"));
                            }
                            actual_key_generation = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &field,
                                &[
                                    "code",
                                    "message",
                                    "operation_id",
                                    "expected_sig_count",
                                    "actual_sig_count",
                                    "expected_key_generation",
                                    "actual_key_generation",
                                ],
                            ));
                        }
                    }
                }

                let value = Bip448HandoffErrorResponsePayloadV2 {
                    code: code.ok_or_else(|| de::Error::missing_field("code"))?,
                    message: message.ok_or_else(|| de::Error::missing_field("message"))?,
                    operation_id,
                    expected_sig_count,
                    actual_sig_count,
                    expected_key_generation,
                    actual_key_generation,
                };
                value.validate().map_err(de::Error::custom)?;
                Ok(value)
            }
        }

        deserializer.deserialize_map(ErrorEnvelopeVisitor)
    }
}

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

    const OPERATION_ID: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SERVER_KEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const TRANSFER_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const PUBLIC_NONCE: &str = "032f7d30ca4641d314418be9e8e11ef28e079ce684f7271bceab6e9f835adea05303b1b76528c43918e991aa847abb7b6df753dc116de95a9d811bc9b35a7f020dfb";
    const BLINDED_SESSION: &str = "9dede917000000000000000000000000000000000000000000000000000000000000000000b59faf7e0a44057b41d273e70cc0a59194347b286c8108fef3519bb52fe64b0729641b33afc4d71464ccde0ca4b0471ed2fda81a39056745ed7b1f4f90790dfd3ee2e8c6c5937a7f4dd30e9e78ec2096433ff32ea89ffca29a40b02b03b4e7eb";
    const SCHNORR_SIGNATURE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    fn operation_id() -> Bip448OperationId {
        Bip448OperationId::try_from(OPERATION_ID).unwrap()
    }

    fn statechain_id() -> Bip448StatechainId {
        Bip448StatechainId::try_from("statechain-vector-v2").unwrap()
    }

    fn server_key() -> Bip448CompressedPublicKey {
        Bip448CompressedPublicKey::try_from(SERVER_KEY).unwrap()
    }

    fn transfer_key() -> Bip448CompressedPublicKey {
        Bip448CompressedPublicKey::try_from(TRANSFER_KEY).unwrap()
    }

    fn secret(byte: u8) -> Bip448SecretScalar {
        Bip448SecretScalar::from_bytes([byte; 32]).unwrap()
    }

    fn keyupdate_request() -> Bip448LockboxKeyUpdateRequestPayloadV2 {
        Bip448LockboxKeyUpdateRequestPayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            operation_id: operation_id(),
            statechain_id: statechain_id(),
            t2: secret(0x11),
            x1: secret(0x22),
            expected_sig_count: Bip448SignatureCount::new(0x0102_0304_0506_0708),
            expected_key_generation: Bip448KeyGeneration::new(0x1112_1314_1516_1718),
            expected_server_pubkey: server_key(),
        }
    }

    fn json_keys<T: Serialize>(value: &T) -> std::collections::BTreeSet<String> {
        serde_json::to_value(value)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    fn assert_lockbox_privacy(json: &str) {
        for forbidden in [
            "transaction",
            "txid",
            "outpoint",
            "amount",
            "script",
            "destination",
            "state_number",
            "signing_role",
            "template",
            "recovery_address",
            "fee_policy",
            "unblinded",
        ] {
            assert!(
                !json.contains(forbidden),
                "v2 lockbox payload exposed forbidden field sentinel {forbidden}: {json}"
            );
        }
        for forbidden_value in [
            "02000000deadbeef",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:7",
            "5120bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ] {
            assert!(
                !json.contains(forbidden_value),
                "v2 lockbox payload exposed forbidden value sentinel {forbidden_value}: {json}"
            );
        }
    }

    #[test]
    fn bip448_statechain_id_rejects_embedded_nul_without_normalizing() {
        for invalid in ["\0", "\0a", "a\0b", "a\0"] {
            assert!(matches!(
                Bip448StatechainId::new(invalid.to_owned()),
                Err(Bip448WireError::InvalidStatechainId)
            ));
            assert!(matches!(
                Bip448StatechainId::try_from(invalid),
                Err(Bip448WireError::InvalidStatechainId)
            ));
        }

        assert!(serde_json::from_str::<Bip448StatechainId>(r#""a\u0000b""#).is_err());

        let lockbox_json = format!(
            r#"{{"statechain_id":"lockbox\u0000id","signing_id":"{SIGNING_ID}","expected_key_generation":0,"expected_server_pubkey":"{SERVER_KEY}"}}"#
        );
        assert!(lockbox_json.contains(r"\u0000"));
        assert!(
            serde_json::from_str::<Bip448LockboxSignFirstRequestPayloadV2>(&lockbox_json).is_err()
        );

        let one_byte = "a";
        let fifty_bytes = "b".repeat(50);
        let fifty_one_bytes = "c".repeat(51);
        assert!(Bip448StatechainId::new(one_byte.to_owned()).is_ok());
        assert!(Bip448StatechainId::new(fifty_bytes.clone()).is_ok());
        assert!(matches!(
            Bip448StatechainId::new(fifty_one_bytes),
            Err(Bip448WireError::InvalidStatechainId)
        ));

        let composed_source = "é";
        let decomposed_source = "e\u{301}";
        let composed = Bip448StatechainId::new(composed_source.to_owned()).unwrap();
        let decomposed = Bip448StatechainId::new(decomposed_source.to_owned()).unwrap();
        assert_ne!(composed, decomposed);
        assert_eq!(
            serde_json::to_string(&composed).unwrap().as_bytes(),
            b"\"\xc3\xa9\""
        );
        assert_eq!(
            serde_json::to_string(&decomposed).unwrap().as_bytes(),
            b"\"e\xcc\x81\""
        );

        for valid in [
            one_byte.to_owned(),
            fifty_bytes,
            composed_source.to_owned(),
            decomposed_source.to_owned(),
        ] {
            let statechain_id = Bip448StatechainId::new(valid.clone()).unwrap();
            let json = serde_json::to_string(&statechain_id).unwrap();
            let round_trip: Bip448StatechainId = serde_json::from_str(&json).unwrap();
            assert_eq!(round_trip.as_str().as_bytes(), valid.as_bytes());
            assert_eq!(serde_json::to_string(&round_trip).unwrap(), json);
        }
    }

    #[test]
    fn v2_wire_primitives_reject_noncanonical_input_without_normalizing() {
        assert_eq!(
            serde_json::to_string(&Bip448ProtocolVersionV2).unwrap(),
            "2"
        );
        assert!(serde_json::from_str::<Bip448ProtocolVersionV2>("1").is_err());
        assert!(serde_json::from_str::<Bip448ProtocolVersionV2>("\"2\"").is_err());

        for invalid in [
            OPERATION_ID.to_uppercase(),
            format!("0x{OPERATION_ID}"),
            "00".repeat(31),
            "00".repeat(33),
            format!("{}g", &OPERATION_ID[..63]),
        ] {
            assert!(Bip448OperationId::try_from(invalid.as_str()).is_err());
            assert!(Bip448RequestHash::try_from(invalid.as_str()).is_err());
            assert!(Bip448SigningId::try_from(invalid.as_str()).is_err());
        }

        assert!(Bip448StatechainId::try_from("").is_err());
        assert!(Bip448StatechainId::try_from("é".repeat(25).as_str()).is_ok());
        assert!(Bip448StatechainId::try_from("é".repeat(26).as_str()).is_err());
        let composed = Bip448StatechainId::try_from("é").unwrap();
        let decomposed = Bip448StatechainId::try_from("e\u{301}").unwrap();
        assert_ne!(composed, decomposed);
        assert_eq!(serde_json::to_string(&composed).unwrap(), "\"é\"");
        assert_eq!(serde_json::to_string(&decomposed).unwrap(), "\"é\"");

        assert!(Bip448CanonicalScalar::from_bytes([0_u8; 32]).is_ok());
        assert!(matches!(
            Bip448SecretScalar::from_bytes([0_u8; 32]),
            Err(Bip448WireError::ZeroSecretScalar)
        ));
        let curve_order =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(Bip448CanonicalScalar::from_bytes(curve_order).is_err());
        assert!(Bip448SecretScalar::from_bytes(curve_order).is_err());

        assert!(Bip448CompressedPublicKey::try_from(SERVER_KEY).is_ok());
        assert!(Bip448CompressedPublicKey::try_from(SERVER_KEY.to_uppercase().as_str()).is_err());
        assert!(
            Bip448CompressedPublicKey::try_from(format!("04{}", &SERVER_KEY[2..]).as_str())
                .is_err()
        );
        assert!(Bip448SchnorrSignature::try_from(SCHNORR_SIGNATURE).is_ok());
        assert!(Bip448SchnorrSignature::try_from("ff".repeat(63).as_str()).is_err());
        assert!(Bip448PublicNonce::try_from(PUBLIC_NONCE).is_ok());
        assert!(Bip448PublicNonce::try_from("00".repeat(66).as_str()).is_err());
    }

    #[test]
    fn schnorr_signature_enforces_bip340_structural_ranges() {
        const R_EQUALS_FIELD_PRIME: &str = concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        const R_EXCEEDS_FIELD_PRIME: &str = concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        const S_EQUALS_GROUP_ORDER: &str = concat!(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        );
        const S_EXCEEDS_GROUP_ORDER: &str = concat!(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
        );
        const ALL_FF: &str = concat!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        const MAX_STRUCTURALLY_VALID: &str = concat!(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        );

        for invalid in [
            R_EQUALS_FIELD_PRIME,
            R_EXCEEDS_FIELD_PRIME,
            S_EQUALS_GROUP_ORDER,
            S_EXCEEDS_GROUP_ORDER,
            ALL_FF,
        ] {
            assert!(matches!(
                Bip448SchnorrSignature::try_from(invalid),
                Err(Bip448WireError::InvalidSchnorrSignature)
            ));
        }
        for valid in [SCHNORR_SIGNATURE, MAX_STRUCTURALLY_VALID] {
            let signature = Bip448SchnorrSignature::try_from(valid).unwrap();
            assert_eq!(
                serde_json::to_string(&signature).unwrap(),
                format!("\"{valid}\"")
            );
        }
    }

    #[test]
    fn blinded_session_is_prevalidated_round_tripped_and_redacted() {
        let parsed = Bip448BlindedSession::try_from(BLINDED_SESSION).unwrap();
        assert_eq!(hex::encode(parsed.as_bytes()), BLINDED_SESSION);
        assert_eq!(format!("{parsed:?}"), "Bip448BlindedSession([REDACTED])");
        assert_eq!(
            format!("{:?}", secret(0x11)),
            "Bip448SecretScalar([REDACTED])"
        );

        let mut malformed = Vec::new();
        malformed.push(String::new());
        malformed.push(BLINDED_SESSION.to_uppercase());
        malformed.push(format!("0x{BLINDED_SESSION}"));
        malformed.push(BLINDED_SESSION[..BLINDED_SESSION.len() - 2].to_owned());
        for index in [0_usize, 4, 5, 36] {
            let mut bytes: [u8; BIP448_MUSIG_SESSION_SERIALIZED_SIZE] =
                hex::decode(BLINDED_SESSION).unwrap().try_into().unwrap();
            bytes[index] = match index {
                4 => 2,
                5 | 36 => 1,
                _ => 0xff,
            };
            malformed.push(hex::encode(bytes));
        }
        let mut invalid_scalar: [u8; BIP448_MUSIG_SESSION_SERIALIZED_SIZE] =
            hex::decode(BLINDED_SESSION).unwrap().try_into().unwrap();
        invalid_scalar[37..69].copy_from_slice(
            &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap(),
        );
        malformed.push(hex::encode(invalid_scalar));

        for value in malformed {
            let result =
                std::panic::catch_unwind(|| Bip448BlindedSession::try_from(value.as_str()));
            assert!(result.is_ok(), "public blinded-session parser panicked");
            assert!(result.unwrap().is_err(), "accepted malformed session");
        }
    }

    #[test]
    fn keyupdate_request_hash_matches_independent_literal_vector() {
        const PREIMAGE_HEX: &str = "4249503434382f6c6f636b626f782d6b65797570646174652f76320002000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000147374617465636861696e2d766563746f722d7632111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220102030405060708111213141516171802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        const REQUEST_HASH: &str =
            "d606e6ff89eb0ef045af4a807b1bdfd030f1f60eea127cd4c7762f9f9facd343";

        let request = keyupdate_request();
        assert_eq!(
            hex::encode(request.canonical_request_preimage().unwrap()),
            PREIMAGE_HEX
        );
        assert_eq!(request.request_hash().unwrap().to_string(), REQUEST_HASH);

        let mut mutations = Vec::new();
        let mut changed = request.clone();
        changed.operation_id = Bip448OperationId::from_bytes([0x44; 32]);
        mutations.push(changed);
        let mut changed = request.clone();
        changed.statechain_id = Bip448StatechainId::try_from("statechain-vector-v3").unwrap();
        mutations.push(changed);
        let mut changed = request.clone();
        changed.t2 = secret(0x12);
        mutations.push(changed);
        let mut changed = request.clone();
        changed.x1 = secret(0x23);
        mutations.push(changed);
        let mut changed = request.clone();
        changed.expected_sig_count =
            Bip448SignatureCount::new(request.expected_sig_count.get().checked_add(1).unwrap());
        mutations.push(changed);
        let mut changed = request.clone();
        changed.expected_key_generation = Bip448KeyGeneration::new(
            request
                .expected_key_generation
                .get()
                .checked_add(1)
                .unwrap(),
        );
        mutations.push(changed);
        let mut changed = request.clone();
        changed.expected_server_pubkey = transfer_key();
        mutations.push(changed);
        for changed in mutations {
            assert_ne!(
                changed.request_hash().unwrap(),
                request.request_hash().unwrap()
            );
        }
    }

    #[test]
    fn v2_lockbox_payloads_have_exact_private_key_sets() {
        let first = Bip448LockboxSignFirstRequestPayloadV2 {
            statechain_id: statechain_id(),
            signing_id: Bip448SigningId::try_from(SIGNING_ID).unwrap(),
            expected_key_generation: Bip448KeyGeneration::new(7),
            expected_server_pubkey: server_key(),
        };
        assert_eq!(
            json_keys(&first),
            [
                "expected_key_generation",
                "expected_server_pubkey",
                "signing_id",
                "statechain_id",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_lockbox_privacy(&serde_json::to_string(&first).unwrap());

        let second = Bip448LockboxPartialSignatureRequestPayloadV2 {
            statechain_id: statechain_id(),
            signing_id: Bip448SigningId::try_from(SIGNING_ID).unwrap(),
            negate_seckey: Bip448NegateSeckeyFlag::try_from(1).unwrap(),
            session: Bip448BlindedSession::try_from(BLINDED_SESSION).unwrap(),
            server_pub_nonce: Bip448PublicNonce::try_from(PUBLIC_NONCE).unwrap(),
            expected_key_generation: Bip448KeyGeneration::new(7),
            expected_server_pubkey: server_key(),
        };
        assert_eq!(
            json_keys(&second),
            [
                "expected_key_generation",
                "expected_server_pubkey",
                "negate_seckey",
                "server_pub_nonce",
                "session",
                "signing_id",
                "statechain_id",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_lockbox_privacy(&serde_json::to_string(&second).unwrap());

        let keyupdate = keyupdate_request();
        assert_eq!(
            json_keys(&keyupdate),
            [
                "expected_key_generation",
                "expected_server_pubkey",
                "expected_sig_count",
                "operation_id",
                "protocol_version",
                "statechain_id",
                "t2",
                "x1",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_lockbox_privacy(&serde_json::to_string(&keyupdate).unwrap());
    }

    #[test]
    fn v2_models_reject_unknown_missing_and_noncanonical_fields() {
        let request = keyupdate_request();
        let mut value = serde_json::to_value(&request).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("state_number".to_owned(), serde_json::json!(9));
        assert!(serde_json::from_value::<Bip448LockboxKeyUpdateRequestPayloadV2>(value).is_err());

        let mut value = serde_json::to_value(&request).unwrap();
        value.as_object_mut().unwrap().remove("expected_sig_count");
        assert!(serde_json::from_value::<Bip448LockboxKeyUpdateRequestPayloadV2>(value).is_err());

        let mut value = serde_json::to_value(&request).unwrap();
        value["protocol_version"] = serde_json::json!(3);
        assert!(serde_json::from_value::<Bip448LockboxKeyUpdateRequestPayloadV2>(value).is_err());

        let mut value = serde_json::to_value(&request).unwrap();
        value["operation_id"] = serde_json::json!(OPERATION_ID.to_uppercase());
        assert!(serde_json::from_value::<Bip448LockboxKeyUpdateRequestPayloadV2>(value).is_err());
    }

    #[test]
    fn v2_receipt_and_mercury_observation_use_exact_typed_fields() {
        let receipt = Bip448KeyUpdateAppliedReceiptPayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            operation_id: operation_id(),
            statechain_id: statechain_id(),
            status: Bip448AppliedStatus,
            accepted_sig_count: Bip448SignatureCount::new(3),
            previous_key_generation: Bip448KeyGeneration::new(7),
            resulting_key_generation: Bip448KeyGeneration::new(8),
            previous_server_pubkey: server_key(),
            resulting_server_pubkey: transfer_key(),
            transfer_generation_pubkey: transfer_key(),
        };
        assert_eq!(
            json_keys(&receipt),
            [
                "accepted_sig_count",
                "operation_id",
                "previous_key_generation",
                "previous_server_pubkey",
                "protocol_version",
                "resulting_key_generation",
                "resulting_server_pubkey",
                "statechain_id",
                "status",
                "transfer_generation_pubkey",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        assert!(receipt_json.contains("\"status\":\"applied\""));
        assert_eq!(
            serde_json::from_str::<Bip448KeyUpdateAppliedReceiptPayloadV2>(&receipt_json).unwrap(),
            receipt
        );

        let observation = Bip448StatechainInfoResponsePayloadV2 {
            protocol_version: Bip448ProtocolVersionV2,
            enclave_public_key: server_key(),
            num_sigs: Bip448SignatureCount::new(1),
            lockbox_key_generation: Bip448KeyGeneration::new(7),
            statechain_info: vec![Bip448StatechainInfoV2 {
                statechain_id: statechain_id(),
                server_pubnonce: Bip448PublicNonce::try_from(PUBLIC_NONCE).unwrap(),
                challenge: Bip448CanonicalScalar::from_bytes([0_u8; 32]).unwrap(),
                tx_n: 1,
            }],
            x1_pub: transfer_key(),
        };
        let observation_json = serde_json::to_string(&observation).unwrap();
        assert_eq!(
            serde_json::from_str::<Bip448StatechainInfoResponsePayloadV2>(&observation_json)
                .unwrap(),
            observation
        );
        let mut unknown = serde_json::to_value(&observation).unwrap();
        unknown["batch_data"] = serde_json::json!(null);
        assert!(serde_json::from_value::<Bip448StatechainInfoResponsePayloadV2>(unknown).is_err());
    }

    #[test]
    fn checked_count_generation_and_state_conversions_are_distinct() {
        assert_eq!(Bip448SignatureCount::try_from(7_i64).unwrap().get(), 7);
        assert!(matches!(
            Bip448SignatureCount::try_from(-1_i64),
            Err(Bip448WireError::NegativeDatabaseInteger {
                field: "sig_count",
                value: -1
            })
        ));
        assert!(matches!(
            i64::try_from(Bip448KeyGeneration::new(u64::MAX)),
            Err(Bip448WireError::DatabaseIntegerOverflow {
                field: "key_generation",
                value: u64::MAX
            })
        ));
        assert_eq!(
            u32::try_from(Bip448SignatureCount::new(u64::from(u32::MAX))).unwrap(),
            u32::MAX
        );
        assert!(matches!(
            u32::try_from(Bip448SignatureCount::new(
                u64::from(u32::MAX).checked_add(1).unwrap()
            )),
            Err(Bip448WireError::StateNumberOverflow { .. })
        ));
    }

    #[test]
    fn exact_handoff_error_codes_classify_and_envelope_is_canonical() {
        let cases = [
            (
                Bip448HandoffErrorCode::SignatureCountMismatch,
                "bip448_signature_count_mismatch",
                409,
            ),
            (
                Bip448HandoffErrorCode::KeyGenerationMismatch,
                "bip448_key_generation_mismatch",
                409,
            ),
            (
                Bip448HandoffErrorCode::ServerKeyMismatch,
                "bip448_server_key_mismatch",
                409,
            ),
            (
                Bip448HandoffErrorCode::OperationConflict,
                "bip448_operation_conflict",
                409,
            ),
            (
                Bip448HandoffErrorCode::TransferGenerationMismatch,
                "bip448_transfer_generation_mismatch",
                409,
            ),
            (
                Bip448HandoffErrorCode::KeyupdateRejected,
                "bip448_keyupdate_rejected",
                409,
            ),
            (
                Bip448HandoffErrorCode::KeyupdatePending,
                "bip448_keyupdate_pending",
                503,
            ),
        ];
        for (code, wire, status) in cases {
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{wire}\""));
            assert_eq!(code.later_http_status(), status);
        }

        let conflict = Bip448HandoffErrorResponsePayloadV2 {
            code: Bip448HandoffErrorCode::SignatureCountMismatch,
            message: "signature count changed".to_owned(),
            operation_id: None,
            expected_sig_count: Some(Bip448SignatureCount::new(4)),
            actual_sig_count: Some(Bip448SignatureCount::new(5)),
            expected_key_generation: None,
            actual_key_generation: None,
        };
        let json = serde_json::to_string(&conflict).unwrap();
        assert_eq!(
            json_keys(&conflict),
            ["actual_sig_count", "code", "expected_sig_count", "message"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert!(!json.contains("null"));
        assert_eq!(
            serde_json::from_str::<Bip448HandoffErrorResponsePayloadV2>(&json).unwrap(),
            conflict
        );

        let pending = Bip448HandoffErrorResponsePayloadV2 {
            code: Bip448HandoffErrorCode::KeyupdatePending,
            message: "operation pending".to_owned(),
            operation_id: Some(operation_id()),
            expected_sig_count: None,
            actual_sig_count: None,
            expected_key_generation: None,
            actual_key_generation: None,
        };
        assert!(serde_json::to_string(&pending)
            .unwrap()
            .contains(OPERATION_ID));

        let pending_without_id = Bip448HandoffErrorResponsePayloadV2 {
            operation_id: None,
            ..pending.clone()
        };
        assert!(serde_json::to_string(&pending_without_id).is_err());
        assert!(serde_json::from_str::<Bip448HandoffErrorResponsePayloadV2>(
            r#"{"code":"bip448_keyupdate_pending","message":"pending"}"#
        )
        .is_err());
        for optional in [
            "operation_id",
            "expected_sig_count",
            "actual_sig_count",
            "expected_key_generation",
            "actual_key_generation",
        ] {
            let value = format!(
                "{{\"code\":\"bip448_signature_count_mismatch\",\"message\":\"conflict\",\"{optional}\":null}}"
            );
            assert!(
                serde_json::from_str::<Bip448HandoffErrorResponsePayloadV2>(&value).is_err(),
                "explicit null accepted for {optional}"
            );
        }
        assert!(serde_json::from_str::<Bip448HandoffErrorResponsePayloadV2>(
            r#"{"code":"bip448_keyupdate_rejected","message":"no","extra":1}"#
        )
        .is_err());
    }
}
