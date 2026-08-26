use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rocket::tokio::time::timeout;
use serde::{de::DeserializeOwned, Serialize};

use crate::server_config::Enclave;

const LOCKBOX_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const LOCKBOX_AUTH_TOKEN_HEX_LENGTH: usize = 64;

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Delete,
}

enum Transport {
    Http {
        base_url: String,
        client: reqwest::Client,
    },
    Enclavia(enclavia::Client),
}

pub struct LockboxResponse {
    pub status: u16,
    pub body: String,
}

pub struct LockboxClients {
    clients: Vec<Transport>,
    authorization: Option<String>,
}

enum TransportConfig {
    Http {
        base_url: String,
    },
    Enclavia {
        url: String,
        pcrs: enclavia::Pcrs,
        debug: bool,
    },
}

impl LockboxClients {
    /// Validate every endpoint and establish every attested connection before
    /// Mercury starts accepting requests.
    pub async fn connect(enclaves: &[Enclave], auth_token: Option<&str>) -> Result<Self> {
        if enclaves.is_empty() {
            bail!("at least one lockbox enclave must be configured");
        }

        let configs = enclaves
            .iter()
            .enumerate()
            .map(|(index, enclave)| validate_transport(enclave, index))
            .collect::<Result<Vec<_>>>()?;
        let requires_auth = configs
            .iter()
            .any(|config| matches!(config, TransportConfig::Enclavia { .. }));
        let authorization = build_authorization_header(requires_auth, auth_token)?;

        let mut clients = Vec::with_capacity(configs.len());
        for (index, config) in configs.into_iter().enumerate() {
            let transport = match config {
                TransportConfig::Http { base_url } => Transport::Http {
                    base_url,
                    client: reqwest::Client::builder()
                        .timeout(LOCKBOX_OPERATION_TIMEOUT)
                        .build()
                        .context("building the lockbox HTTP client")?,
                },
                TransportConfig::Enclavia { url, pcrs, debug } => {
                    let client = timeout(
                        LOCKBOX_OPERATION_TIMEOUT,
                        enclavia::Client::builder(&url)
                            .pcrs(pcrs)
                            .debug_mode(debug)
                            .build(),
                    )
                    .await
                    .with_context(|| {
                        format!("timed out connecting to lockbox enclave {index} at {url}")
                    })?
                    .with_context(|| {
                        format!("connecting to and attesting lockbox enclave {index} at {url}")
                    })?;
                    Transport::Enclavia(client)
                }
            };
            clients.push(transport);
        }

        Ok(Self {
            clients,
            authorization,
        })
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub(crate) fn uses_enclavia(&self, enclave_index: usize) -> bool {
        matches!(
            self.clients.get(enclave_index),
            Some(Transport::Enclavia(_))
        )
    }

    pub(crate) fn uses_authentication(&self) -> bool {
        self.authorization.is_some()
    }

    pub async fn get(&self, enclave_index: usize, path: &str) -> Result<LockboxResponse> {
        let response = self.get_raw(enclave_index, path).await?;
        require_success(response, enclave_index, &normalized_path(path))
    }

    pub async fn get_raw(&self, enclave_index: usize, path: &str) -> Result<LockboxResponse> {
        self.send_raw(enclave_index, Method::Get, path, None).await
    }

    pub async fn post_json<B, R>(&self, enclave_index: usize, path: &str, payload: &B) -> Result<R>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let response = self.post_json_raw(enclave_index, path, payload).await?;
        let response = require_success(response, enclave_index, &normalized_path(path))?;
        decode_json(response, enclave_index, path)
    }

    pub async fn post_json_raw<B>(
        &self,
        enclave_index: usize,
        path: &str,
        payload: &B,
    ) -> Result<LockboxResponse>
    where
        B: Serialize + ?Sized,
    {
        let body = serde_json::to_vec(payload).context("serializing lockbox request as JSON")?;
        self.send_raw(enclave_index, Method::Post, path, Some(body))
            .await
    }

    pub async fn delete_raw(&self, enclave_index: usize, path: &str) -> Result<LockboxResponse> {
        self.send_raw(enclave_index, Method::Delete, path, None)
            .await
    }

    async fn send_raw(
        &self,
        enclave_index: usize,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<LockboxResponse> {
        let client = self.clients.get(enclave_index).ok_or_else(|| {
            anyhow!(
                "lockbox enclave index {enclave_index} is out of range (configured: {})",
                self.clients.len()
            )
        })?;
        let path = normalized_path(path);

        let response = match client {
            Transport::Http { base_url, client } => {
                let url = format!("{base_url}{path}");
                let mut request = match method {
                    Method::Get => client.get(&url),
                    Method::Post => client.post(&url),
                    Method::Delete => client.delete(&url),
                };
                if let Some(authorization) = &self.authorization {
                    request = request.header(reqwest::header::AUTHORIZATION, authorization);
                }
                if let Some(body) = body {
                    request = request
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(body);
                }

                let response = request
                    .send()
                    .await
                    .with_context(|| format!("sending lockbox request to {url}"))?;
                let status = response.status().as_u16();
                let body = response
                    .text()
                    .await
                    .with_context(|| format!("reading lockbox response from {url}"))?;
                LockboxResponse { status, body }
            }
            Transport::Enclavia(client) => {
                let mut request = match method {
                    Method::Get => client.get(&path),
                    Method::Post => client.post(&path),
                    Method::Delete => client.delete(&path),
                };
                if let Some(authorization) = &self.authorization {
                    request = request.header("Authorization", authorization);
                }
                if let Some(body) = body {
                    request = request
                        .header("Content-Type", "application/json")
                        .body(body);
                }

                let response = timeout(LOCKBOX_OPERATION_TIMEOUT, request.send())
                    .await
                    .with_context(|| {
                        format!(
                            "lockbox request through attested enclave {enclave_index} timed out"
                        )
                    })?
                    .with_context(|| {
                        format!("sending lockbox request through attested enclave {enclave_index}")
                    })?;
                let status = response.status();
                let body = response
                    .text()
                    .context("decoding lockbox response as UTF-8")?
                    .to_owned();
                LockboxResponse { status, body }
            }
        };

        Ok(response)
    }
}

fn require_success(
    response: LockboxResponse,
    enclave_index: usize,
    path: &str,
) -> Result<LockboxResponse> {
    if !(200..300).contains(&response.status) {
        bail!(
            "lockbox enclave {enclave_index} returned HTTP {} for {path}: {}",
            response.status,
            response.body
        );
    }

    Ok(response)
}

fn decode_json<T: DeserializeOwned>(
    response: LockboxResponse,
    enclave_index: usize,
    path: &str,
) -> Result<T> {
    serde_json::from_str(&response.body).with_context(|| {
        format!(
            "decoding JSON response from lockbox enclave {enclave_index} for {}",
            normalized_path(path)
        )
    })
}

fn build_authorization_header(required: bool, auth_token: Option<&str>) -> Result<Option<String>> {
    let Some(token) = auth_token else {
        if required {
            bail!("LOCKBOX_AUTH_TOKEN is required for Enclavia Lockbox transports");
        }
        return Ok(None);
    };
    if token.len() != LOCKBOX_AUTH_TOKEN_HEX_LENGTH
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("LOCKBOX_AUTH_TOKEN must contain exactly 64 hexadecimal characters");
    }
    Ok(Some(format!("Bearer {token}")))
}

fn validate_transport(enclave: &Enclave, index: usize) -> Result<TransportConfig> {
    let parsed = reqwest::Url::parse(&enclave.url)
        .with_context(|| format!("lockbox enclave {index} has an invalid URL"))?;

    if parsed.host_str().is_none() {
        bail!("lockbox enclave {index} URL must include a host");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("lockbox enclave {index} URL must not include a query or fragment");
    }

    match parsed.scheme() {
        "http" | "https" => Ok(TransportConfig::Http {
            base_url: enclave.url.trim_end_matches('/').to_owned(),
        }),
        "ws" | "wss" => {
            let required = |value: &Option<String>, name: &str| -> Result<String> {
                value
                    .as_ref()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| value.trim().to_owned())
                    .ok_or_else(|| anyhow!("lockbox enclave {index} using WSS requires {name}"))
            };
            let pcr0 = required(&enclave.pcr0, "pcr0")?;
            let pcr1 = required(&enclave.pcr1, "pcr1")?;
            let pcr2 = required(&enclave.pcr2, "pcr2")?;
            let pcrs = enclavia::Pcrs::from_hex(&pcr0, &pcr1, &pcr2)
                .with_context(|| format!("lockbox enclave {index} has invalid PCR values"))?;

            Ok(TransportConfig::Enclavia {
                url: enclave.url.trim_end_matches('/').to_owned(),
                pcrs,
                debug: enclave.debug,
            })
        }
        scheme => bail!(
            "lockbox enclave {index} URL uses unsupported scheme {scheme:?}; expected http(s) or \
             ws(s)"
        ),
    }
}

fn normalized_path(path: &str) -> String {
    format!("/{}", path.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enclave(url: &str) -> Enclave {
        Enclave {
            url: url.to_owned(),
            allow_deposit: true,
            pcr0: None,
            pcr1: None,
            pcr2: None,
            debug: false,
        }
    }

    #[test]
    fn accepts_legacy_http_configuration_without_pcrs() {
        let config = validate_transport(&enclave("http://lockbox:18080/"), 0).unwrap();
        match config {
            TransportConfig::Http { base_url } => assert_eq!(base_url, "http://lockbox:18080"),
            TransportConfig::Enclavia { .. } => panic!("expected HTTP transport"),
        }
    }

    #[test]
    fn requires_all_pcrs_for_direct_enclavia_transport() {
        let error = validate_transport(
            &enclave("wss://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io"),
            2,
        )
        .err()
        .expect("missing PCRs should fail");

        assert!(error.to_string().contains("enclave 2"));
        assert!(error.to_string().contains("pcr0"));
    }

    #[test]
    fn accepts_complete_direct_enclavia_configuration() {
        let pcr = "ab".repeat(48);
        let mut config =
            enclave("wss://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io");
        config.pcr0 = Some(pcr.clone());
        config.pcr1 = Some(pcr.clone());
        config.pcr2 = Some(pcr);
        config.debug = true;

        match validate_transport(&config, 0).unwrap() {
            TransportConfig::Enclavia { debug, .. } => assert!(debug),
            TransportConfig::Http { .. } => panic!("expected direct Enclavia transport"),
        }
    }

    #[test]
    fn normalizes_paths_for_both_transports() {
        assert_eq!(normalized_path("health/ready"), "/health/ready");
        assert_eq!(normalized_path("/get_public_key"), "/get_public_key");
    }

    #[test]
    fn requires_authentication_for_enclavia_transports() {
        assert!(build_authorization_header(false, None).unwrap().is_none());
        assert!(build_authorization_header(true, None).is_err());
        assert_eq!(
            build_authorization_header(true, Some(&"a".repeat(64))).unwrap(),
            Some(format!("Bearer {}", "a".repeat(64)))
        );
        assert!(build_authorization_header(true, Some("short")).is_err());
        assert!(build_authorization_header(true, Some(&"z".repeat(64))).is_err());
    }

    #[test]
    fn rejects_non_success_responses_before_endpoint_code_consumes_them() {
        let error = require_success(
            LockboxResponse {
                status: 500,
                body: "database write failed".to_owned(),
            },
            1,
            "/delete_statechain/example",
        )
        .err()
        .expect("HTTP 500 must be rejected");

        let message = error.to_string();
        assert!(message.contains("enclave 1"));
        assert!(message.contains("HTTP 500"));
        assert!(message.contains("database write failed"));
    }

    #[test]
    fn rejects_malformed_json_responses() {
        let error = decode_json::<serde_json::Value>(
            LockboxResponse {
                status: 200,
                body: "not-json".to_owned(),
            },
            0,
            "/get_public_key",
        )
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("lockbox enclave 0"));
        assert!(message.contains("/get_public_key"));
    }
}
