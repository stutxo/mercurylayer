use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

use super::super::argv::{ArgvCommand, CommandRunner};
use super::super::model::StackMetadata;
use super::contract::{
    required_health, service_port, service_readiness, ReadinessKind, RequiredHealth, SERVICES,
};
use super::docker::{Container, Observation};
use super::report::ReadinessReport;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HTTP_BYTES: u64 = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum HttpAttempt {
    Response(HttpResponse),
    ConnectionMiss(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HttpResponse {
    pub(super) status: u16,
    pub(super) body: Value,
}

pub(super) trait HostProbe {
    fn port_is_free(&mut self, port: u16) -> Result<bool>;
    fn http_json(
        &mut self,
        port: u16,
        path: &str,
        authorization: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<HttpAttempt>;
    fn now_millis(&self) -> u64;
    fn sleep(&mut self, duration: Duration);
}

pub(super) struct SystemHostProbe {
    started: Instant,
}

impl SystemHostProbe {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl HostProbe for SystemHostProbe {
    fn port_is_free(&mut self, port: u16) -> Result<bool> {
        match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)) {
            Ok(listener) => {
                drop(listener);
                Ok(true)
            }
            Err(error) if error.kind() == ErrorKind::AddrInUse => Ok(false),
            Err(error) => Err(error).with_context(|| format!("probe host port {port}")),
        }
    }

    fn http_json(
        &mut self,
        port: u16,
        path: &str,
        authorization: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<HttpAttempt> {
        http_json(port, path, authorization, body)
    }

    fn now_millis(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Attempt {
    Ready(String),
    Retry(String),
}

pub(super) fn sample(
    repo_root: &Path,
    metadata: &StackMetadata,
    observation: &Observation,
    runner: &mut impl CommandRunner,
    host: &mut impl HostProbe,
    strict: bool,
) -> Result<(BTreeMap<String, ReadinessReport>, bool)> {
    let mut reports = BTreeMap::new();
    let mut all_ready = true;
    for service in SERVICES {
        let Some(container) = observation.containers.get(service) else {
            all_ready = false;
            reports.insert(
                service.into(),
                ReadinessReport {
                    ready: false,
                    detail: "container_absent".into(),
                },
            );
            continue;
        };
        let attempt = match static_attempt(service, container, strict)? {
            Attempt::Ready(_) => probe_service(repo_root, metadata, container, runner, host)?,
            retry => retry,
        };
        let report = match attempt {
            Attempt::Ready(detail) => ReadinessReport {
                ready: true,
                detail,
            },
            Attempt::Retry(detail) => {
                all_ready = false;
                ReadinessReport {
                    ready: false,
                    detail,
                }
            }
        };
        reports.insert(service.into(), report);
    }
    let complete = reports.len() == SERVICES.len();
    Ok((reports, all_ready && complete))
}

fn static_attempt(service: &str, container: &Container, strict: bool) -> Result<Attempt> {
    if container.dead || container.restarting {
        if strict {
            bail!("service {service} is dead or restarting");
        }
        return Ok(Attempt::Retry("container_dead_or_restarting".into()));
    }
    if !container.running || container.state != "running" {
        if strict {
            bail!("service {service} is not running");
        }
        return Ok(Attempt::Retry(format!("container_{}", container.state)));
    }
    match (required_health(service)?, container.health.as_deref()) {
        (RequiredHealth::Healthy, Some("healthy")) => {}
        (RequiredHealth::Healthy, Some("starting")) => {
            return Ok(Attempt::Retry("health_starting".into()));
        }
        (RequiredHealth::Healthy, Some("unhealthy")) => {
            if strict {
                bail!("service {service} is unhealthy");
            }
            return Ok(Attempt::Retry("health_unhealthy".into()));
        }
        (RequiredHealth::Healthy, _) if strict => {
            bail!("service {service} has malformed health state")
        }
        (RequiredHealth::Healthy, _) => {
            return Ok(Attempt::Retry("health_malformed".into()));
        }
        (RequiredHealth::Absent, None) => {}
        (RequiredHealth::Absent, Some(value)) if strict => {
            bail!("service {service} has unexpected health state {value:?}")
        }
        (RequiredHealth::Absent, Some(_)) => {
            return Ok(Attempt::Retry("health_unexpected".into()));
        }
    }
    Ok(Attempt::Ready("container_ready".into()))
}

fn probe_service(
    repo_root: &Path,
    metadata: &StackMetadata,
    container: &Container,
    runner: &mut impl CommandRunner,
    host: &mut impl HostProbe,
) -> Result<Attempt> {
    match service_readiness(&container.service)? {
        ReadinessKind::None => Ok(Attempt::Ready("healthy".into())),
        ReadinessKind::Postgres(database) => postgres(repo_root, container, database, runner),
        ReadinessKind::Vault => vault(metadata, host),
        ReadinessKind::HttpConfig => http_config(metadata, &container.service, host),
        ReadinessKind::HttpAlive => http_alive(metadata, &container.service, host),
        ReadinessKind::Inquisition => inquisition(metadata, host),
    }
}

fn postgres(
    repo_root: &Path,
    container: &Container,
    database: &str,
    runner: &mut impl CommandRunner,
) -> Result<Attempt> {
    let command = ArgvCommand::new("docker", repo_root)
        .arg("exec")
        .arg(&container.id)
        .args([
            "pg_isready",
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
            "--username",
            "postgres",
            "--dbname",
            database,
            "--timeout",
            "1",
        ]);
    let output = runner.run(&command)?;
    let stdout = String::from_utf8(output.stdout).context("pg_isready output is not UTF-8")?;
    let stderr = String::from_utf8(output.stderr).context("pg_isready error is not UTF-8")?;
    if output.success {
        ensure!(
            stdout.trim().ends_with(" - accepting connections") && stderr.trim().is_empty(),
            "pg_isready returned malformed success output"
        );
        return Ok(Attempt::Ready("postgres_accepting".into()));
    }
    let detail = format!("{} {}", stdout.trim(), stderr.trim()).to_ascii_lowercase();
    if matches!(output.code, Some(1 | 2))
        && (detail.contains("rejecting connections") || detail.contains("no response"))
    {
        return Ok(Attempt::Retry("postgres_connection_miss".into()));
    }
    bail!(
        "pg_isready failed non-retryably with status {:?}: {detail}",
        output.code
    )
}

fn vault(metadata: &StackMetadata, host: &mut impl HostProbe) -> Result<Attempt> {
    match host.http_json(metadata.ports().vault, "/v1/sys/health", None, None)? {
        HttpAttempt::ConnectionMiss(_) => Ok(Attempt::Retry("vault_connection_miss".into())),
        HttpAttempt::Response(response) => {
            ensure!(
                response.status == 200,
                "Vault health returned HTTP {}",
                response.status
            );
            ensure!(
                response.body.get("initialized").and_then(Value::as_bool) == Some(true)
                    && response.body.get("sealed").and_then(Value::as_bool) == Some(false),
                "Vault health response is malformed or not ready"
            );
            Ok(Attempt::Ready("vault_initialized_unsealed".into()))
        }
    }
}

fn http_config(
    metadata: &StackMetadata,
    service: &str,
    host: &mut impl HostProbe,
) -> Result<Attempt> {
    let port = service_port(metadata, service)?;
    match host.http_json(port, "/info/config", None, None)? {
        HttpAttempt::ConnectionMiss(_) => Ok(Attempt::Retry("http_connection_miss".into())),
        HttpAttempt::Response(response) => {
            ensure!(
                response.status == 200
                    && response.body == json!({"batchtimeout": 20, "version": "0.2.1"}),
                "service {service} returned malformed /info/config response"
            );
            Ok(Attempt::Ready("http_config_ready".into()))
        }
    }
}

fn http_alive(
    metadata: &StackMetadata,
    service: &str,
    host: &mut impl HostProbe,
) -> Result<Attempt> {
    let port = service_port(metadata, service)?;
    match host.http_json(port, "/", None, None)? {
        HttpAttempt::ConnectionMiss(_) => Ok(Attempt::Retry("http_connection_miss".into())),
        HttpAttempt::Response(response) => {
            ensure!(
                matches!(response.status, 200 | 404)
                    && response
                        .body
                        .as_str()
                        .is_some_and(|body| !body.trim().is_empty()),
                "service {service} returned malformed bounded HTTP readiness response"
            );
            Ok(Attempt::Ready("http_application_ready".into()))
        }
    }
}

fn inquisition(metadata: &StackMetadata, host: &mut impl HostProbe) -> Result<Attempt> {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "1.0",
        "id": "bip448-ready",
        "method": "getblockchaininfo",
        "params": []
    }))?;
    match host.http_json(
        metadata.ports().core_rpc,
        "/",
        Some("Basic bWVyY3VyeTptZXJjdXJ5"),
        Some(&body),
    )? {
        HttpAttempt::ConnectionMiss(_) => Ok(Attempt::Retry("inquisition_connection_miss".into())),
        HttpAttempt::Response(response) => {
            ensure!(
                response.status == 200,
                "Inquisition RPC returned HTTP {}",
                response.status
            );
            ensure!(
                response.body.get("error").is_some_and(Value::is_null),
                "Inquisition RPC returned an error"
            );
            ensure!(
                response
                    .body
                    .pointer("/result/chain")
                    .and_then(Value::as_str)
                    == Some("regtest"),
                "Inquisition RPC readiness response is malformed"
            );
            Ok(Attempt::Ready("inquisition_regtest_ready".into()))
        }
    }
}

pub(super) fn port_observations(
    metadata: &StackMetadata,
    host: &mut impl HostProbe,
) -> Result<BTreeMap<u16, bool>> {
    metadata
        .ports()
        .ordered()
        .into_iter()
        .map(|(_, port)| Ok((port, host.port_is_free(port)?)))
        .collect()
}

fn http_json(
    port: u16,
    path: &str,
    authorization: Option<&str>,
    body: Option<&[u8]>,
) -> Result<HttpAttempt> {
    ensure!(
        path.starts_with('/') && !path.contains(['\r', '\n']),
        "unsafe HTTP path"
    );
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = match TcpStream::connect_timeout(&address.into(), CONNECT_TIMEOUT) {
        Ok(stream) => stream,
        Err(error) if retryable_io(&error) => {
            return Ok(HttpAttempt::ConnectionMiss(error.to_string()));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("connect HTTP readiness port {port}"))
        }
    };
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let method = if body.is_some() { "POST" } else { "GET" };
    let body = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    if let Some(authorization) = authorization {
        ensure!(
            !authorization.contains(['\r', '\n']),
            "unsafe HTTP authorization value"
        );
        request.push_str(&format!("Authorization: {authorization}\r\n"));
    }
    if !body.is_empty() {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    if let Err(error) = stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(body))
    {
        if retryable_io(&error) {
            return Ok(HttpAttempt::ConnectionMiss(error.to_string()));
        }
        return Err(error).context("write bounded HTTP readiness request");
    }
    let mut bytes = Vec::new();
    if let Err(error) = stream.take(MAX_HTTP_BYTES + 1).read_to_end(&mut bytes) {
        if retryable_io(&error) {
            return Ok(HttpAttempt::ConnectionMiss(error.to_string()));
        }
        return Err(error).context("read bounded HTTP readiness response");
    }
    ensure!(
        bytes.len() as u64 <= MAX_HTTP_BYTES,
        "HTTP readiness response exceeds byte limit"
    );
    parse_http(&bytes).map(HttpAttempt::Response)
}

fn parse_http(bytes: &[u8]) -> Result<HttpResponse> {
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("HTTP readiness response has no header boundary")?;
    let headers =
        std::str::from_utf8(&bytes[..boundary]).context("HTTP readiness headers are not UTF-8")?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .context("HTTP readiness status line is absent")?;
    let fields = status.split_ascii_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() >= 2 && fields[0] == "HTTP/1.1",
        "malformed HTTP readiness status line"
    );
    let status = fields[1]
        .parse::<u16>()
        .context("HTTP readiness status is not numeric")?;
    ensure!(
        (100..=599).contains(&status),
        "HTTP readiness status is out of range"
    );
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("malformed HTTP readiness header")?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" {
            ensure!(
                value.eq_ignore_ascii_case("chunked"),
                "unsupported HTTP transfer encoding"
            );
            chunked = true;
        } else if name == "content-length" {
            ensure!(content_length.is_none(), "duplicate HTTP content length");
            content_length = Some(
                value
                    .parse::<usize>()
                    .context("malformed HTTP content length")?,
            );
        }
    }
    ensure!(
        !(chunked && content_length.is_some()),
        "ambiguous HTTP body framing"
    );
    let raw_body = &bytes[boundary + 4..];
    let body = if chunked {
        decode_chunked(raw_body)?
    } else if let Some(length) = content_length {
        ensure!(raw_body.len() == length, "HTTP body length mismatch");
        raw_body.to_vec()
    } else {
        raw_body.to_vec()
    };
    let body = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => Value::String(
            String::from_utf8(body)
                .context("HTTP readiness body is neither JSON nor UTF-8")?
                .trim()
                .to_owned(),
        ),
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut bytes: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .context("malformed HTTP chunk length")?;
        let length =
            std::str::from_utf8(&bytes[..end]).context("HTTP chunk length is not UTF-8")?;
        ensure!(
            !length.contains(';'),
            "HTTP chunk extensions are unsupported"
        );
        let length = usize::from_str_radix(length, 16).context("HTTP chunk length is malformed")?;
        bytes = &bytes[end + 2..];
        if length == 0 {
            ensure!(bytes == b"\r\n", "malformed HTTP chunk terminator");
            break;
        }
        ensure!(
            bytes.len() >= length + 2 && &bytes[length..length + 2] == b"\r\n",
            "truncated HTTP chunk"
        );
        output.extend_from_slice(&bytes[..length]);
        ensure!(
            output.len() as u64 <= MAX_HTTP_BYTES,
            "decoded HTTP response exceeds byte limit"
        );
        bytes = &bytes[length + 2..];
    }
    Ok(output)
}

fn retryable_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
    )
}
