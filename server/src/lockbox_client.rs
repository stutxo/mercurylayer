use std::{env, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use rocket::tokio::{
    sync::RwLock,
    time::{interval_at, timeout, Instant, MissedTickBehavior},
};
use serde::{de::DeserializeOwned, Serialize};

use crate::server_config::Enclave;

const LOCKBOX_READY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
const LOCKBOX_READY_ATTEMPTS: usize = 3;
const LOCKBOX_REQUEST_ATTEMPTS: usize = 3;
const LOCKBOX_OPERATION_TIMEOUT: Duration = Duration::from_secs(8);
const LOCKBOX_AUTH_TOKEN_HEX_LENGTH: usize = 64;
const LOCKBOX_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const LOCKBOX_KEEPALIVE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const LOCKBOX_KEEPALIVE_RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Delete,
}

#[derive(Clone, Copy)]
enum HealthCheck {
    Live,
    Ready,
}

impl HealthCheck {
    fn path(self) -> &'static str {
        match self {
            Self::Live => "/health/live",
            Self::Ready => "/health/ready",
        }
    }

    fn expected_status(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Ready => "ready",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Live => "liveness",
            Self::Ready => "readiness",
        }
    }
}

struct EnclaviaSession {
    generation: u64,
    client: enclavia::Client,
}

struct EnclaviaTransport {
    url: String,
    pcrs: enclavia::Pcrs,
    debug: bool,
    session: RwLock<EnclaviaSession>,
}

enum Transport {
    Http {
        base_url: String,
        client: reqwest::Client,
    },
    Enclavia(EnclaviaTransport),
}

pub struct LockboxResponse {
    pub status: u16,
    pub body: String,
}

struct LockboxClientsInner {
    clients: Vec<Transport>,
    authorization: String,
}

#[derive(Clone)]
pub struct LockboxClients {
    inner: Arc<LockboxClientsInner>,
}

enum TransportConfig {
    Http {
        base_url: String,
        tls: bool,
    },
    Enclavia {
        url: String,
        pcrs: enclavia::Pcrs,
        debug: bool,
    },
}

impl LockboxClients {
    /// Validate every endpoint and verify an attested readiness response before
    /// Mercury starts accepting requests.
    pub async fn connect(
        enclaves: &[Enclave],
        auth_token: Option<&str>,
        network: &str,
    ) -> Result<Self> {
        if enclaves.is_empty() {
            bail!("at least one lockbox enclave must be configured");
        }

        let allow_debug_enclaves = debug_enclaves_allowed()?;
        let configs = enclaves
            .iter()
            .enumerate()
            .map(|(index, enclave)| {
                validate_transport(enclave, index, network, allow_debug_enclaves)
            })
            .collect::<Result<Vec<_>>>()?;
        let authorization = build_authorization_header(auth_token)?;

        let mut clients = Vec::with_capacity(configs.len());
        for (index, config) in configs.into_iter().enumerate() {
            let transport = match config {
                TransportConfig::Http { base_url, tls } => {
                    log::warn!(
                        "lockbox enclave {index} uses {} without enclave attestation",
                        if tls { "HTTPS" } else { "regtest HTTP" }
                    );
                    Transport::Http {
                        base_url,
                        client: reqwest::Client::builder()
                            .timeout(LOCKBOX_OPERATION_TIMEOUT)
                            .build()
                            .context("building the lockbox HTTP client")?,
                    }
                }
                TransportConfig::Enclavia { url, pcrs, debug } => {
                    let client = connect_enclavia_after_health_check(
                        &url,
                        &pcrs,
                        debug,
                        &authorization,
                        index,
                        HealthCheck::Ready,
                    )
                    .await?;
                    if debug {
                        log::warn!(
                            "lockbox enclave {index} uses debug attestation under the explicit \
                             regtest latch"
                        );
                    } else {
                        log::info!("lockbox enclave {index} passed production attestation");
                    }
                    Transport::Enclavia(EnclaviaTransport {
                        url,
                        pcrs,
                        debug,
                        session: RwLock::new(EnclaviaSession {
                            generation: 0,
                            client,
                        }),
                    })
                }
            };
            clients.push(transport);
        }

        let clients = Self {
            inner: Arc::new(LockboxClientsInner {
                clients,
                authorization,
            }),
        };
        clients.spawn_attested_keepalive();
        Ok(clients)
    }

    pub fn len(&self) -> usize {
        self.inner.clients.len()
    }

    fn spawn_attested_keepalive(&self) {
        if !self
            .inner
            .clients
            .iter()
            .any(|transport| matches!(transport, Transport::Enclavia(_)))
        {
            return;
        }

        let inner = Arc::downgrade(&self.inner);
        rocket::tokio::spawn(async move {
            let mut timer = interval_at(
                Instant::now() + LOCKBOX_KEEPALIVE_INTERVAL,
                LOCKBOX_KEEPALIVE_INTERVAL,
            );
            timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                Self { inner }.keep_attested_sessions_alive().await;
            }
        });
    }

    async fn keep_attested_sessions_alive(&self) {
        for enclave_index in 0..self.inner.clients.len() {
            if !matches!(self.inner.clients[enclave_index], Transport::Enclavia(_)) {
                continue;
            }

            let health = self.check_liveness_once(enclave_index).await;
            if health.is_ok() {
                log::debug!("kept Lockbox enclave {enclave_index} attested channel active");
                continue;
            }

            log::warn!(
                "Lockbox enclave {enclave_index} keepalive failed: {}; reconnecting and \
                 re-attesting",
                health.unwrap_err()
            );
            match timeout(
                LOCKBOX_KEEPALIVE_RECOVERY_TIMEOUT,
                self.recover_attested_session(enclave_index),
            )
            .await
            {
                Ok(Ok(())) => {
                    log::info!("Lockbox enclave {enclave_index} attested channel recovered")
                }
                Ok(Err(error)) => log::error!(
                    "Lockbox enclave {enclave_index} attested channel recovery failed: {error}"
                ),
                Err(_) => log::error!(
                    "Lockbox enclave {enclave_index} attested channel recovery timed out after \
                     {:.3}s",
                    LOCKBOX_KEEPALIVE_RECOVERY_TIMEOUT.as_secs_f64()
                ),
            }
        }
    }
    async fn check_liveness_once(&self, enclave_index: usize) -> Result<()> {
        let response = self
            .get_raw_once(
                enclave_index,
                HealthCheck::Live.path(),
                LOCKBOX_KEEPALIVE_ATTEMPT_TIMEOUT,
            )
            .await?;
        validate_health_response(response, enclave_index, HealthCheck::Live)
    }

    pub async fn recover_attested_session(&self, enclave_index: usize) -> Result<()> {
        let transport = self.inner.clients.get(enclave_index).ok_or_else(|| {
            anyhow!(
                "lockbox enclave index {enclave_index} is out of range (configured: {})",
                self.inner.clients.len()
            )
        })?;
        let Transport::Enclavia(transport) = transport else {
            return Ok(());
        };
        let generation = transport.session.read().await.generation;
        replace_enclavia_session(
            transport,
            generation,
            &self.inner.authorization,
            enclave_index,
        )
        .await
    }

    pub async fn get(&self, enclave_index: usize, path: &str) -> Result<LockboxResponse> {
        let response = self.get_raw(enclave_index, path).await?;
        require_success(response, enclave_index, &normalized_path(path))
    }

    pub async fn get_raw(&self, enclave_index: usize, path: &str) -> Result<LockboxResponse> {
        self.send_raw(enclave_index, Method::Get, path, None).await
    }

    pub async fn get_raw_once(
        &self,
        enclave_index: usize,
        path: &str,
        operation_timeout: Duration,
    ) -> Result<LockboxResponse> {
        self.send_raw_with_options(
            enclave_index,
            Method::Get,
            path,
            None,
            operation_timeout,
            false,
        )
        .await
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

    pub async fn post_json_once<B, R>(
        &self,
        enclave_index: usize,
        path: &str,
        payload: &B,
        operation_timeout: Duration,
    ) -> Result<R>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let body = serde_json::to_vec(payload).context("serializing lockbox request as JSON")?;
        let response = self
            .send_raw_with_options(
                enclave_index,
                Method::Post,
                path,
                Some(body),
                operation_timeout,
                false,
            )
            .await?;
        let response = require_success(response, enclave_index, &normalized_path(path))?;
        decode_json(response, enclave_index, path)
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
        self.send_raw_with_options(
            enclave_index,
            method,
            path,
            body,
            LOCKBOX_OPERATION_TIMEOUT,
            true,
        )
        .await
    }

    async fn send_raw_with_options(
        &self,
        enclave_index: usize,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        operation_timeout: Duration,
        allow_retries: bool,
    ) -> Result<LockboxResponse> {
        let client = self.inner.clients.get(enclave_index).ok_or_else(|| {
            anyhow!(
                "lockbox enclave index {enclave_index} is out of range (configured: {})",
                self.inner.clients.len()
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
                }
                .timeout(operation_timeout);
                request = request.header(reqwest::header::AUTHORIZATION, &self.inner.authorization);
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
            Transport::Enclavia(transport) => {
                send_enclavia_request(
                    transport,
                    method,
                    &path,
                    body.as_deref(),
                    &self.inner.authorization,
                    enclave_index,
                    operation_timeout,
                    allow_retries,
                )
                .await?
            }
        };

        Ok(response)
    }
}
async fn send_enclavia_request(
    transport: &EnclaviaTransport,
    method: Method,
    path: &str,
    body: Option<&[u8]>,
    authorization: &str,
    enclave_index: usize,
    operation_timeout: Duration,
    allow_retries: bool,
) -> Result<LockboxResponse> {
    let replay_safe = enclavia_request_is_replay_safe(method, path);
    let attempts = if allow_retries {
        LOCKBOX_REQUEST_ATTEMPTS
    } else {
        1
    };
    for attempt in 1..=attempts {
        let (generation, client) = {
            let session = transport.session.read().await;
            (session.generation, session.client.clone())
        };
        let mut request = match method {
            Method::Get => client.get(path),
            Method::Post => client.post(path),
            Method::Delete => client.delete(path),
        }
        .header("Authorization", authorization);
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body);
        }

        let (error, timed_out) = match timeout(operation_timeout, request.send()).await {
            Ok(Ok(response)) => {
                let status = response.status();
                let body = response
                    .text()
                    .context("decoding lockbox response as UTF-8")?
                    .to_owned();
                return Ok(LockboxResponse { status, body });
            }
            Ok(Err(error)) if error.is_retryable() => (
                anyhow!("sending {path} through attested enclave {enclave_index} failed: {error}"),
                false,
            ),
            Ok(Err(error)) => {
                return Err(error).with_context(|| {
                    format!("sending {path} through attested enclave {enclave_index}")
                });
            }
            Err(_) => (
                anyhow!(
                    "lockbox request {path} through attested enclave {enclave_index} timed out \
                     after {:.3}s",
                    operation_timeout.as_secs_f64()
                ),
                true,
            ),
        };

        if !allow_retries {
            return Err(error);
        }
        let recovery_error = if timed_out {
            replace_enclavia_session(transport, generation, authorization, enclave_index)
                .await
                .err()
        } else {
            None
        };
        if !replay_safe || attempt == attempts {
            return match recovery_error {
                Some(recovery_error) => Err(error.context(format!(
                    "attested channel recovery also failed: {recovery_error}"
                ))),
                None => Err(error),
            };
        }
        match recovery_error {
            Some(recovery_error) => log::warn!(
                "lockbox request {path} through attested enclave {enclave_index} failed on \
                 attempt {attempt}/{attempts}: {error}; channel recovery also failed: \
                 {recovery_error}; retrying the exact request"
            ),
            None => log::warn!(
                "lockbox request {path} through attested enclave {enclave_index} failed on \
                 attempt {attempt}/{attempts}: {error}; retrying the exact request"
            ),
        }
    }

    unreachable!("the lockbox request attempt count is nonzero")
}

async fn replace_enclavia_session(
    transport: &EnclaviaTransport,
    failed_generation: u64,
    authorization: &str,
    enclave_index: usize,
) -> Result<()> {
    let mut session = transport.session.write().await;
    if session.generation != failed_generation {
        return Ok(());
    }
    let client = connect_enclavia_after_health_check(
        &transport.url,
        &transport.pcrs,
        transport.debug,
        authorization,
        enclave_index,
        HealthCheck::Live,
    )
    .await?;
    session.client = client;
    session.generation = session.generation.wrapping_add(1);
    Ok(())
}

fn enclavia_request_is_replay_safe(method: Method, path: &str) -> bool {
    match method {
        Method::Get | Method::Delete => true,
        Method::Post => matches!(
            path,
            "/get_public_key"
                | "/bip448/get_public_nonce"
                | "/bip448/get_partial_signature"
                | "/keyupdate"
        ),
    }
}

async fn connect_enclavia_after_health_check(
    url: &str,
    pcrs: &enclavia::Pcrs,
    debug: bool,
    authorization: &str,
    enclave_index: usize,
    health_check: HealthCheck,
) -> Result<enclavia::Client> {
    let mut last_error = None;
    for attempt in 1..=LOCKBOX_READY_ATTEMPTS {
        let result = timeout(LOCKBOX_READY_ATTEMPT_TIMEOUT, async {
            let client = enclavia::Client::builder(url)
                .pcrs(pcrs.clone())
                .debug_mode(debug)
                .build()
                .await
                .with_context(|| {
                    format!("connecting to and attesting lockbox enclave {enclave_index} at {url}")
                })?;
            let response = client
                .get(health_check.path())
                .header("Authorization", authorization)
                .send()
                .await
                .with_context(|| {
                    format!(
                        "checking {} of lockbox enclave {enclave_index}",
                        health_check.name()
                    )
                })?;
            let response = LockboxResponse {
                status: response.status(),
                body: response
                    .text()
                    .with_context(|| {
                        format!("decoding lockbox {} response as UTF-8", health_check.name())
                    })?
                    .to_owned(),
            };
            validate_health_response(response, enclave_index, health_check)?;
            Ok::<_, anyhow::Error>(client)
        })
        .await;
        let result = match result {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "lockbox enclave {enclave_index} {} attempt {attempt} timed out after {}s",
                health_check.name(),
                LOCKBOX_READY_ATTEMPT_TIMEOUT.as_secs()
            )),
        };
        match result {
            Ok(client) => return Ok(client),
            Err(error) => {
                if attempt < LOCKBOX_READY_ATTEMPTS {
                    log::warn!(
                        "lockbox enclave {enclave_index} {} attempt \
                         {attempt}/{LOCKBOX_READY_ATTEMPTS} failed: {error}",
                        health_check.name()
                    );
                }
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("lockbox enclave health check failed"))).with_context(
        || {
            format!(
                "lockbox enclave {enclave_index} did not pass {} after \
                 {LOCKBOX_READY_ATTEMPTS} attempts",
                health_check.name()
            )
        },
    )
}
fn validate_health_response(
    response: LockboxResponse,
    enclave_index: usize,
    health_check: HealthCheck,
) -> Result<()> {
    if response.status != 200 {
        bail!(
            "lockbox enclave {enclave_index} {} returned HTTP {}: {}",
            health_check.name(),
            response.status,
            response.body
        );
    }
    let health: serde_json::Value = serde_json::from_str(&response.body)
        .with_context(|| format!("decoding lockbox {} response", health_check.name()))?;
    if health.get("status").and_then(serde_json::Value::as_str)
        != Some(health_check.expected_status())
    {
        bail!(
            "lockbox enclave {enclave_index} returned an unexpected {} response",
            health_check.name()
        );
    }
    Ok(())
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

fn build_authorization_header(auth_token: Option<&str>) -> Result<String> {
    let token = auth_token.context("LOCKBOX_AUTH_TOKEN is required for every Lockbox transport")?;
    if token.len() != LOCKBOX_AUTH_TOKEN_HEX_LENGTH
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("LOCKBOX_AUTH_TOKEN must contain exactly 64 hexadecimal characters");
    }
    Ok(format!("Bearer {token}"))
}

fn debug_enclaves_allowed() -> Result<bool> {
    match env::var("MERCURY_ALLOW_DEBUG_ENCLAVES") {
        Ok(value) => parse_debug_enclave_latch(&value),
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => {
            bail!("MERCURY_ALLOW_DEBUG_ENCLAVES must be valid UTF-8")
        }
    }
}

fn parse_debug_enclave_latch(value: &str) -> Result<bool> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => bail!("MERCURY_ALLOW_DEBUG_ENCLAVES must be 0 or 1"),
    }
}

fn validate_transport(
    enclave: &Enclave,
    index: usize,
    network: &str,
    allow_debug_enclaves: bool,
) -> Result<TransportConfig> {
    let parsed = reqwest::Url::parse(&enclave.url)
        .with_context(|| format!("lockbox enclave {index} has an invalid URL"))?;

    if parsed.host_str().is_none() {
        bail!("lockbox enclave {index} URL must include a host");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("lockbox enclave {index} URL must not include a query or fragment");
    }
    if enclave.debug && (network != "regtest" || !allow_debug_enclaves) {
        bail!(
            "lockbox enclave {index} debug attestation requires BITCOIN_NETWORK=regtest and \
             MERCURY_ALLOW_DEBUG_ENCLAVES=1"
        );
    }

    match parsed.scheme() {
        "http" => {
            if enclave.debug {
                bail!("lockbox enclave {index} debug is valid only for ws(s) transports");
            }
            if network != "regtest" {
                bail!(
                    "lockbox enclave {index} uses cleartext HTTP outside regtest; use an attested \
                     ws(s) endpoint"
                );
            }
            Ok(TransportConfig::Http {
                base_url: enclave.url.trim_end_matches('/').to_owned(),
                tls: false,
            })
        }
        "https" => {
            if enclave.debug {
                bail!("lockbox enclave {index} debug is valid only for ws(s) transports");
            }
            if network != "regtest" && !enclave.allow_unattested {
                bail!(
                    "lockbox enclave {index} uses HTTPS without enclave attestation; set \
                     allow_unattested=true only after explicit review or use ws(s)"
                );
            }
            Ok(TransportConfig::Http {
                base_url: enclave.url.trim_end_matches('/').to_owned(),
                tls: true,
            })
        }
        "ws" | "wss" => {
            if enclave.allow_unattested {
                bail!(
                    "lockbox enclave {index} allow_unattested is valid only for HTTPS transports"
                );
            }
            let required = |value: &Option<String>, name: &str| -> Result<String> {
                value
                    .as_ref()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| value.trim().to_owned())
                    .ok_or_else(|| anyhow!("lockbox enclave {index} using ws(s) requires {name}"))
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
    use rocket::tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn enclave(url: &str) -> Enclave {
        Enclave {
            url: url.to_owned(),
            allow_deposit: true,
            pcr0: None,
            pcr1: None,
            pcr2: None,
            debug: false,
            allow_unattested: false,
        }
    }

    fn attested_enclave(debug: bool) -> Enclave {
        let pcr = "ab".repeat(48);
        let mut enclave =
            enclave("wss://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io");
        enclave.pcr0 = Some(pcr.clone());
        enclave.pcr1 = Some(pcr.clone());
        enclave.pcr2 = Some(pcr);
        enclave.debug = debug;
        enclave
    }

    #[test]
    fn accepts_http_only_for_regtest() {
        let config =
            validate_transport(&enclave("http://lockbox:18080/"), 0, "regtest", false).unwrap();
        match config {
            TransportConfig::Http { base_url, tls } => {
                assert_eq!(base_url, "http://lockbox:18080");
                assert!(!tls);
            }
            TransportConfig::Enclavia { .. } => panic!("expected HTTP transport"),
        }

        assert!(validate_transport(&enclave("http://lockbox:18080"), 0, "signet", false).is_err());
    }

    #[test]
    fn requires_explicit_opt_in_for_unattested_https_outside_regtest() {
        let mut config = enclave("https://lockbox.example");
        assert!(validate_transport(&config, 0, "signet", false).is_err());

        config.allow_unattested = true;
        match validate_transport(&config, 0, "signet", false).unwrap() {
            TransportConfig::Http { tls, .. } => assert!(tls),
            TransportConfig::Enclavia { .. } => panic!("expected HTTPS transport"),
        }
    }

    #[test]
    fn requires_all_pcrs_for_direct_enclavia_transport() {
        let error = validate_transport(
            &enclave("wss://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io"),
            2,
            "signet",
            false,
        )
        .err()
        .expect("missing PCRs should fail");

        assert!(error.to_string().contains("enclave 2"));
        assert!(error.to_string().contains("pcr0"));
    }

    #[test]
    fn accepts_production_attestation_outside_regtest() {
        match validate_transport(&attested_enclave(false), 0, "signet", false).unwrap() {
            TransportConfig::Enclavia { debug, .. } => assert!(!debug),
            TransportConfig::Http { .. } => panic!("expected direct Enclavia transport"),
        }
    }

    #[test]
    fn debug_attestation_requires_regtest_and_explicit_latch() {
        let config = attested_enclave(true);
        assert!(validate_transport(&config, 0, "signet", true).is_err());
        assert!(validate_transport(&config, 0, "regtest", false).is_err());

        match validate_transport(&config, 0, "regtest", true).unwrap() {
            TransportConfig::Enclavia { debug, .. } => assert!(debug),
            TransportConfig::Http { .. } => panic!("expected direct Enclavia transport"),
        }
    }

    #[test]
    fn attested_transport_rejects_unattested_override() {
        let mut config = attested_enclave(false);
        config.allow_unattested = true;

        assert!(validate_transport(&config, 0, "signet", false).is_err());
    }

    #[test]
    fn normalizes_paths_for_both_transports() {
        assert_eq!(normalized_path("health/ready"), "/health/ready");
        assert_eq!(normalized_path("/get_public_key"), "/get_public_key");
    }

    #[test]
    fn retries_only_known_replay_safe_operations() {
        assert!(enclavia_request_is_replay_safe(Method::Get, "/any"));
        assert!(enclavia_request_is_replay_safe(
            Method::Post,
            "/get_public_key"
        ));
        assert!(enclavia_request_is_replay_safe(
            Method::Post,
            "/bip448/get_public_nonce"
        ));
        assert!(enclavia_request_is_replay_safe(
            Method::Post,
            "/bip448/get_partial_signature"
        ));
        assert!(enclavia_request_is_replay_safe(Method::Post, "/keyupdate"));
        assert!(!enclavia_request_is_replay_safe(
            Method::Post,
            "/unknown_mutation"
        ));
    }

    #[test]
    fn liveness_probe_uses_the_authenticated_shared_transport() {
        let runtime = rocket::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let auth_token = "ab".repeat(32);
            let expected_authorization = format!("authorization: bearer {auth_token}");
            let server = rocket::tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    request.extend_from_slice(&chunk[..read]);
                    if read == 0 || request.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.starts_with("get /health/live http/1.1\r\n"));
                assert!(request.contains(&expected_authorization));

                let body = r#"{"status":"live"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });

            let clients = LockboxClients::connect(
                &[enclave(&format!("http://{address}"))],
                Some(&auth_token),
                "regtest",
            )
            .await
            .unwrap();
            clients.check_liveness_once(0).await.unwrap();
            server.await.unwrap();
        });
    }

    #[test]
    fn requires_authentication_for_every_transport() {
        assert!(build_authorization_header(None).is_err());
        assert_eq!(
            build_authorization_header(Some(&"a".repeat(64))).unwrap(),
            format!("Bearer {}", "a".repeat(64))
        );
        assert!(build_authorization_header(Some("short")).is_err());
        assert!(build_authorization_header(Some(&"z".repeat(64))).is_err());
    }

    #[test]
    fn parses_debug_latch_strictly() {
        assert!(!parse_debug_enclave_latch("0").unwrap());
        assert!(parse_debug_enclave_latch("1").unwrap());
        assert!(parse_debug_enclave_latch("true").is_err());
        assert!(parse_debug_enclave_latch("").is_err());
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
