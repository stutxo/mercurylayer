use std::time::Duration;

use rocket::{http::Status, response::status, serde::json::Json, tokio::time::timeout, State};
use serde_json::{json, Value};

use crate::{server::StateChainEntity, server_config::Enclave};

const LOCKBOX_READINESS_TIMEOUT: Duration = Duration::from_secs(5);

#[get("/health/ready")]
pub async fn ready(statechain_entity: &State<StateChainEntity>) -> status::Custom<Json<Value>> {
    let mut lockboxes = Vec::with_capacity(statechain_entity.lockboxes.len());
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
                return unavailable(format!(
                    "lockbox enclave {enclave_index} readiness request failed"
                ));
            }
            Err(_) => {
                return unavailable(format!(
                    "lockbox enclave {enclave_index} readiness request timed out"
                ));
            }
        };

        if response.status != 200 {
            return unavailable(format!(
                "lockbox enclave {enclave_index} returned readiness status {}",
                response.status
            ));
        }

        let body: Value = match serde_json::from_str(&response.body) {
            Ok(body) => body,
            Err(error) => {
                log::error!(
                    "lockbox returned invalid readiness JSON for enclave {enclave_index}: {error}"
                );
                return unavailable(format!(
                    "lockbox enclave {enclave_index} returned invalid readiness JSON"
                ));
            }
        };
        if body.get("status").and_then(Value::as_str) != Some("ready") {
            return unavailable(format!(
                "lockbox enclave {enclave_index} did not report ready"
            ));
        }

        let Some(enclave) = statechain_entity.config.enclaves.get(enclave_index) else {
            return unavailable(format!(
                "lockbox enclave {enclave_index} is missing from configuration"
            ));
        };
        lockboxes.push(lockbox_readiness(
            enclave_index,
            enclave,
            statechain_entity.lockboxes.uses_enclavia(enclave_index),
            statechain_entity.lockboxes.uses_authentication(),
        ));
    }

    status::Custom(
        Status::Ok,
        Json(json!({
            "status": "ready",
            "lockboxes": lockboxes,
        })),
    )
}

fn lockbox_readiness(
    enclave_index: usize,
    enclave: &Enclave,
    uses_enclavia: bool,
    uses_authentication: bool,
) -> Value {
    let attestation = if uses_enclavia {
        json!({
            "verified": true,
            "mode": if enclave.debug { "debug" } else { "production" },
            "pcrs": {
                "pcr0": enclave.pcr0.as_deref(),
                "pcr1": enclave.pcr1.as_deref(),
                "pcr2": enclave.pcr2.as_deref(),
            },
        })
    } else {
        Value::Null
    };

    json!({
        "index": enclave_index,
        "status": "ready",
        "endpoint": &enclave.url,
        "transport": if uses_enclavia { "enclavia" } else { "http" },
        "authentication": if uses_authentication { "bearer" } else { "none" },
        "attestation": attestation,
    })
}

fn unavailable(message: String) -> status::Custom<Json<Value>> {
    status::Custom(
        Status::ServiceUnavailable,
        Json(json!({
            "status": "unavailable",
            "message": message,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_response_has_stable_contract() {
        let response = unavailable("not ready".to_owned());

        assert_eq!(response.0, Status::ServiceUnavailable);
        assert_eq!(response.1["status"], "unavailable");
        assert_eq!(response.1["message"], "not ready");
    }

    fn configured_enclave(url: &str, debug: bool) -> Enclave {
        Enclave {
            url: url.to_owned(),
            allow_deposit: true,
            pcr0: Some("a".repeat(96)),
            pcr1: Some("b".repeat(96)),
            pcr2: Some("c".repeat(96)),
            debug,
        }
    }

    #[test]
    fn readiness_describes_verified_production_enclavia() {
        let metadata = lockbox_readiness(
            0,
            &configured_enclave(
                "wss://01234567-89ab-cdef-0123-456789abcdef.enclaves.beta.enclavia.io",
                false,
            ),
            true,
            true,
        );

        assert_eq!(metadata["index"], 0);
        assert_eq!(metadata["status"], "ready");
        assert_eq!(metadata["transport"], "enclavia");
        assert_eq!(metadata["authentication"], "bearer");
        assert_eq!(metadata["attestation"]["verified"], true);
        assert_eq!(metadata["attestation"]["mode"], "production");
        assert_eq!(metadata["attestation"]["pcrs"]["pcr0"], "a".repeat(96));
    }

    #[test]
    fn readiness_marks_plain_http_as_unattested() {
        let metadata = lockbox_readiness(
            1,
            &configured_enclave("http://lockbox:18080", false),
            false,
            false,
        );

        assert_eq!(metadata["transport"], "http");
        assert_eq!(metadata["authentication"], "none");
        assert!(metadata["attestation"].is_null());
    }
}
