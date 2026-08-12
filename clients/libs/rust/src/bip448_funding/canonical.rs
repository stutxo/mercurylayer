use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    consensus::{deserialize, serialize},
    BlockHash, Transaction, Txid,
};
use mercurylib::bip448_statechain::signing_api::{
    Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload,
};
use secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) fn canonical_txid(value: &str) -> Result<String> {
    Ok(Txid::from_str(value)
        .context("invalid BIP448 txid")?
        .to_string())
}

pub(crate) fn require_canonical_txid(value: &str) -> Result<()> {
    if super::canonical_txid(value)? != value {
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
    if super::canonical_block_hash(value)? != value {
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

pub(super) fn require_optional_hex(value: Option<&str>, length: usize) -> Result<()> {
    if let Some(value) = value {
        require_canonical_hex(value, Some(length))?;
    }
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
    if super::canonical_xonly_public_key(value)? != value {
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
    if super::canonical_public_key(value)? != value {
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

pub(super) fn parse_canonical_transaction(value: &str, description: &str) -> Result<Transaction> {
    require_canonical_hex(value, None)?;
    let bytes = hex::decode(value)?;
    let transaction: Transaction =
        deserialize(&bytes).with_context(|| format!("invalid {description}"))?;
    if serialize(&transaction) != bytes {
        return Err(anyhow!("{description} is not canonical consensus encoding"));
    }
    Ok(transaction)
}
