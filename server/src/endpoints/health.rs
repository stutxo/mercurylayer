use std::time::Duration;

use rocket::{http::Status, response::status, serde::json::Json, tokio::time::timeout, State};
use serde_json::{json, Value};

use crate::server::StateChainEntity;

const LOCKBOX_READINESS_TIMEOUT: Duration = Duration::from_secs(5);

#[get("/health/ready")]
pub async fn ready(statechain_entity: &State<StateChainEntity>) -> status::Custom<Json<Value>> {
    for enclave_index in 0..statechain_entity.lockboxes.len() {
        let response = match timeout(
            LOCKBOX_READINESS_TIMEOUT,
            statechain_entity
                .lockboxes
                .get(enclave_index, "/health/ready"),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                log::error!(
                    "lockbox readiness request failed for enclave {enclave_index}: {error:?}"
                );
                return unavailable();
            }
            Err(_) => {
                log::error!("lockbox readiness request timed out for enclave {enclave_index}");
                return unavailable();
            }
        };

        if response.status != 200 {
            log::error!(
                "lockbox enclave {enclave_index} returned readiness status {}",
                response.status
            );
            return unavailable();
        }

        let body: Value = match serde_json::from_str(&response.body) {
            Ok(body) => body,
            Err(error) => {
                log::error!(
                    "lockbox returned invalid readiness JSON for enclave {enclave_index}: {error}"
                );
                return unavailable();
            }
        };
        if body.get("status").and_then(Value::as_str) != Some("ready") {
            log::error!("lockbox enclave {enclave_index} did not report ready");
            return unavailable();
        }
    }

    ready_response()
}

fn ready_response() -> status::Custom<Json<Value>> {
    status::Custom(Status::Ok, Json(json!({ "status": "ready" })))
}

fn unavailable() -> status::Custom<Json<Value>> {
    status::Custom(
        Status::ServiceUnavailable,
        Json(json!({ "status": "unavailable" })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_response_exposes_only_status() {
        let response = ready_response();

        assert_eq!(response.0, Status::Ok);
        assert_eq!(response.1 .0, json!({ "status": "ready" }));
    }

    #[test]
    fn unavailable_response_exposes_only_status() {
        let response = unavailable();

        assert_eq!(response.0, Status::ServiceUnavailable);
        assert_eq!(response.1 .0, json!({ "status": "unavailable" }));
    }
}
