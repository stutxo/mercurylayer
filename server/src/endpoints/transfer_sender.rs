use std::str::FromStr;

use mercurylib::transfer::sender::{
    TransferSenderRequestPayload, TransferSenderResponsePayload, TransferUpdateMsgRequestPayload,
};
use rocket::{http::Status, response::status, serde::json::Json, State};
use secp256k1::PublicKey;
use serde_json::{json, Value};

use crate::server::StateChainEntity;

#[post(
    "/transfer/sender",
    format = "json",
    data = "<transfer_sender_request_payload>"
)]
pub async fn transfer_sender(
    statechain_entity: &State<StateChainEntity>,
    transfer_sender_request_payload: Json<TransferSenderRequestPayload>,
) -> status::Custom<Json<Value>> {
    let statechain_id = transfer_sender_request_payload.0.statechain_id.clone();
    let signed_statechain_id = transfer_sender_request_payload.0.auth_sig.clone();
    let batch_id = transfer_sender_request_payload.0.batch_id.clone();

    let new_user_auth_key =
        match PublicKey::from_str(&transfer_sender_request_payload.0.new_user_auth_key) {
            Ok(key) => key,
            Err(_) => {
                return status::Custom(
                    Status::BadRequest,
                    Json(json!({"message": "Invalid new_user_auth_key."})),
                );
            }
        };

    let result = crate::database::transfer_sender::insert_new_transfer_or_replay_exact(
        &statechain_entity.pool,
        &signed_statechain_id,
        &statechain_id,
        &new_user_auth_key,
        &batch_id,
    )
    .await;

    let x1 = match result {
        Ok(crate::database::transfer_sender::InsertTransferResult::Success(x1)) => x1,
        Ok(crate::database::transfer_sender::InsertTransferResult::AuthenticationFailed) => {
            return status::Custom(
                Status::InternalServerError,
                Json(json!({"message": "Signature does not match authentication key."})),
            );
        }
        Ok(crate::database::transfer_sender::InsertTransferResult::StatecoinBatchLocked(
            message,
        ))
        | Ok(crate::database::transfer_sender::InsertTransferResult::ExpiredBatchTime(message)) => {
            return status::Custom(Status::BadRequest, Json(json!({"message": message})));
        }
        Err(_) => {
            return status::Custom(
                Status::InternalServerError,
                Json(json!({"message": "Failed to initialize transfer."})),
            );
        }
    };

    let transfer_sender_response_payload = TransferSenderResponsePayload {
        x1: hex::encode(x1),
    };

    let response_body = json!(transfer_sender_response_payload);

    return status::Custom(Status::Ok, Json(response_body));
}

#[post(
    "/transfer/update_msg",
    format = "json",
    data = "<transfer_update_msg_request_payload>"
)]
pub async fn transfer_update_msg(
    statechain_entity: &State<StateChainEntity>,
    transfer_update_msg_request_payload: Json<TransferUpdateMsgRequestPayload>,
) -> status::Custom<Json<Value>> {
    let statechain_id = transfer_update_msg_request_payload.0.statechain_id.clone();
    let generation_error = || {
        status::Custom(
            Status::InternalServerError,
            Json(json!({
                "error": "Internal Server Error",
                "message": "Transfer message generation does not match current state."
            })),
        )
    };
    let new_user_auth_key =
        match PublicKey::from_str(&transfer_update_msg_request_payload.0.new_user_auth_key) {
            Ok(key)
                if key.to_string() == transfer_update_msg_request_payload.0.new_user_auth_key =>
            {
                key
            }
            _ => return generation_error(),
        };
    let x1_pub = match PublicKey::from_str(&transfer_update_msg_request_payload.0.x1_pub) {
        Ok(key) if key.to_string() == transfer_update_msg_request_payload.0.x1_pub => key,
        _ => return generation_error(),
    };
    let enc_transfer_msg =
        match hex::decode(&transfer_update_msg_request_payload.0.enc_transfer_msg) {
            Ok(bytes) => bytes,
            Err(_) => return generation_error(),
        };

    let result = crate::database::transfer_sender::update_transfer_msg_for_generation_exact(
        &statechain_entity.pool,
        &statechain_id,
        &transfer_update_msg_request_payload.0.auth_sig,
        &new_user_auth_key,
        &x1_pub,
        &enc_transfer_msg,
    )
    .await;

    match result {
        Ok(crate::database::transfer_sender::UpdateTransferMessageResult::Success) => {}
        Ok(crate::database::transfer_sender::UpdateTransferMessageResult::AuthenticationFailed) => {
            return status::Custom(
                Status::InternalServerError,
                Json(json!({
                    "error": "Internal Server Error",
                    "message": "Signature does not match authentication key."
                })),
            );
        }
        Ok(crate::database::transfer_sender::UpdateTransferMessageResult::GenerationMismatch) => {
            return generation_error();
        }
        Err(_) => {
            return status::Custom(
                Status::InternalServerError,
                Json(json!({
                    "error": "Internal Server Error",
                    "message": "Failed to update transfer message."
                })),
            );
        }
    }

    let response_body = json!({
        "updated": true,
    });

    return status::Custom(Status::Ok, Json(response_body));
}
