use chrono::{DateTime, Duration, Utc};
use rocket::{http::Status, response::status, serde::json::Json};
use secp256k1::musig::Session as MusigSession;
use serde_json::{json, Value};

const OUTBOUND_REQUEST_TIMEOUT_SECONDS: u64 = 20;
const MUSIG_SESSION_MAGIC: [u8; 4] = [0x9d, 0xed, 0xe9, 0x17];

pub mod bip448_sign;
pub mod deposit;
pub mod lightning_latch;
pub mod transfer_receiver;
pub mod transfer_sender;
pub mod utils;
pub mod withdraw;

pub(crate) fn outbound_request_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(OUTBOUND_REQUEST_TIMEOUT_SECONDS)
}

pub(crate) fn error_response(status: Status, message: String) -> status::Custom<Json<Value>> {
    status::Custom(status, Json(json!({ "message": message })))
}

/// Extracts the blinded challenge committed by a valid 133-byte hex MuSig session.
pub(crate) fn challenge_from_session_hex(session_hex: &str) -> Option<String> {
    let session_bytes: [u8; 133] = hex::decode(session_hex).ok()?.try_into().ok()?;

    if session_bytes[..4] != MUSIG_SESSION_MAGIC {
        return None;
    }

    Some(hex::encode(
        MusigSession::from_slice(session_bytes).get_challenge_from_session(),
    ))
}

fn is_batch_expired(batch_time: DateTime<Utc>) -> bool {
    let config = crate::server_config::ServerConfig::load();

    let batch_timeout = config.batch_timeout;

    let expiration_time = batch_time + Duration::seconds(batch_timeout as i64);

    let now = chrono::Utc::now();

    return now > expiration_time;
}
