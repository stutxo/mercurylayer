use std::{fmt::Display, future::Future};

use rocket::{http::Status, response::status, serde::json::Json, State};
use serde_json::{json, Value};

use crate::server::StateChainEntity;

enum LockboxDeleteOutcome {
    Response { status: u16, body: String },
    TransportFailure(String),
}

fn classify_lockbox_delete_response(outcome: &LockboxDeleteOutcome) -> Result<(), String> {
    match outcome {
        LockboxDeleteOutcome::Response { status, body }
            if (200..300).contains(status) && body == "Statechain deleted." =>
        {
            Ok(())
        }
        LockboxDeleteOutcome::Response { status, body } if !(200..300).contains(status) => Err(
            format!("lockbox delete_statechain returned {status}: {body}"),
        ),
        LockboxDeleteOutcome::Response { status, body } => Err(format!(
            "lockbox delete_statechain returned unexpected successful response {status}: {body}"
        )),
        LockboxDeleteOutcome::TransportFailure(message) => Err(message.clone()),
    }
}

async fn delete_mercury_statechain_after_lockbox<F, Fut, E>(
    outcome: LockboxDeleteOutcome,
    delete_mercury_statechain: F,
) -> Result<(), String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: Display,
{
    classify_lockbox_delete_response(&outcome)?;
    delete_mercury_statechain()
        .await
        .map_err(|err| format!("failed to delete Mercury statechain: {err}"))
}

async fn delete_statechain_db(
    pool: &sqlx::PgPool,
    statechain_id: &String,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;

    let _ = sqlx::query("DELETE FROM statechain_transfer WHERE statechain_id = $1")
        .bind(statechain_id)
        .execute(&mut *transaction)
        .await?;

    let _ = sqlx::query("DELETE FROM signing_nonce_leases WHERE statechain_id = $1")
        .bind(statechain_id)
        .execute(&mut *transaction)
        .await?;

    let _ = sqlx::query("DELETE FROM bip448_signature_data WHERE statechain_id = $1")
        .bind(statechain_id)
        .execute(&mut *transaction)
        .await?;

    let _ = sqlx::query("DELETE FROM statechain_data WHERE statechain_id = $1")
        .bind(statechain_id)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    Ok(())
}

#[post(
    "/withdraw/complete",
    format = "json",
    data = "<delete_statechain_payload>"
)]
pub async fn withdraw_complete(
    statechain_entity: &State<StateChainEntity>,
    delete_statechain_payload: Json<mercurylib::withdraw::WithdrawCompletePayload>,
) -> status::Custom<Json<Value>> {
    let statechain_id = delete_statechain_payload.0.statechain_id.clone();
    let signed_statechain_id = delete_statechain_payload.0.signed_statechain_id.clone();

    let signature_failure_status = match crate::endpoints::utils::try_validate_signature(
        &statechain_entity.pool,
        &signed_statechain_id,
        &statechain_id,
    )
    .await
    {
        Ok(true) => None,
        Ok(false) => Some(Status::InternalServerError),
        Err(_) => Some(Status::InternalServerError),
    };

    if let Some(signature_failure_status) = signature_failure_status {
        let response_body = json!({
            "message": "Signature does not match authentication key."
        });

        return status::Custom(signature_failure_status, Json(response_body));
    }

    let enclave_index = crate::database::utils::get_enclave_index_from_database(
        &statechain_entity.pool,
        &statechain_id,
    )
    .await;

    let enclave_index = match enclave_index {
        Some(index) => index as usize,
        None => {
            let response_body = json!({
                "message": format!("Enclave index for statechain {} ID not found.", statechain_id)
            });

            return status::Custom(Status::InternalServerError, Json(response_body));
        }
    };
    if statechain_entity
        .config
        .enclaves
        .get(enclave_index)
        .is_none()
    {
        return status::Custom(
            Status::InternalServerError,
            Json(json!({
                "message": format!("Enclave index {enclave_index} is not configured.")
            })),
        );
    }

    let lockbox_outcome = match statechain_entity
        .lockboxes
        .delete_raw(
            enclave_index,
            &format!("/delete_statechain/{statechain_id}"),
        )
        .await
    {
        Ok(response) => LockboxDeleteOutcome::Response {
            status: response.status,
            body: response.body,
        },
        Err(error) => LockboxDeleteOutcome::TransportFailure(error.to_string()),
    };

    if let Err(error) = delete_mercury_statechain_after_lockbox(lockbox_outcome, || {
        delete_statechain_db(&statechain_entity.pool, &statechain_id)
    })
    .await
    {
        log::error!("Lockbox statechain deletion failed: {error}");
        let response_body = json!({
            "error": "Bad Gateway",
            "message": "Signing enclave request failed.",
        });

        return status::Custom(Status::BadGateway, Json(response_body));
    }

    let response_body = json!({
        "message": "Statechain deleted.",
    });

    status::Custom(Status::Ok, Json(response_body))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use rocket::tokio::runtime::Builder;

    use super::*;

    fn block_on<F: Future>(future: F) -> F::Output {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn assert_rejected_before_mercury_delete(outcome: LockboxDeleteOutcome) {
        let delete_called = Cell::new(false);
        let result = block_on(delete_mercury_statechain_after_lockbox(outcome, || async {
            delete_called.set(true);
            Ok::<(), &'static str>(())
        }));

        assert!(result.is_err());
        assert!(!delete_called.get());
    }

    #[test]
    fn exact_lockbox_delete_success_permits_mercury_delete() {
        let delete_called = Cell::new(false);
        let result = block_on(delete_mercury_statechain_after_lockbox(
            LockboxDeleteOutcome::Response {
                status: 200,
                body: "Statechain deleted.".to_string(),
            },
            || async {
                delete_called.set(true);
                Ok::<(), &'static str>(())
            },
        ));

        assert!(result.is_ok());
        assert!(delete_called.get());
    }

    #[test]
    fn lockbox_delete_transport_failure_rejects_before_mercury_delete() {
        assert_rejected_before_mercury_delete(LockboxDeleteOutcome::TransportFailure(
            "lockbox transport failed".to_string(),
        ));
    }

    #[test]
    fn every_lockbox_delete_non_success_rejects_before_mercury_delete() {
        for status in 100..=599 {
            if (200..300).contains(&status) {
                continue;
            }
            assert_rejected_before_mercury_delete(LockboxDeleteOutcome::Response {
                status,
                body: "failure".to_string(),
            });
        }
    }

    #[test]
    fn unexpected_lockbox_delete_success_body_rejects_before_mercury_delete() {
        assert_rejected_before_mercury_delete(LockboxDeleteOutcome::Response {
            status: 200,
            body: "unexpected".to_string(),
        });
    }

    #[test]
    fn mercury_delete_failure_is_returned_after_exact_lockbox_success() {
        let delete_called = Cell::new(false);
        let result = block_on(delete_mercury_statechain_after_lockbox(
            LockboxDeleteOutcome::Response {
                status: 200,
                body: "Statechain deleted.".to_string(),
            },
            || async {
                delete_called.set(true);
                Err::<(), _>("database commit failed")
            },
        ));

        assert_eq!(
            result.unwrap_err(),
            "failed to delete Mercury statechain: database commit failed"
        );
        assert!(delete_called.get());
    }
}
