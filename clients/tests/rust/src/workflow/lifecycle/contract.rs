use std::collections::BTreeMap;

use anyhow::{Context, Result};

use super::super::build::VerifiedBuild;
use super::super::model::{ImageMap, PortMap, StackMetadata};

pub(super) const SERVICES: [&str; 8] = [
    "db_server",
    "db_lockbox",
    "vault",
    "vault-init",
    "lockbox",
    "inquisition",
    "token-server-v2",
    "mercury-server",
];

pub(super) const DECLARED_VOLUMES: [(&str, &str, &str); 3] = [
    ("bitcoin_inquisition_data", "inquisition", "/data"),
    (
        "postgres_lockbox_data",
        "db_lockbox",
        "/var/lib/postgresql/data",
    ),
    (
        "postgres_server_data",
        "db_server",
        "/var/lib/postgresql/data",
    ),
];

pub(super) const VAULT_ANONYMOUS_MOUNTS: [&str; 2] = ["/vault/file", "/vault/logs"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadinessKind {
    Postgres(&'static str),
    Vault,
    HttpConfig,
    HttpAlive,
    Inquisition,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequiredHealth {
    Healthy,
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExpectedImage {
    pub(super) tag: String,
    pub(super) image_id: Option<String>,
}

pub(super) type ExpectedImages = BTreeMap<String, ExpectedImage>;

pub(super) fn expected_from_verified(build: &VerifiedBuild) -> ExpectedImages {
    BTreeMap::from([
        ("db_server".into(), unresolved("postgres:16.2")),
        ("db_lockbox".into(), unresolved("postgres:16.2")),
        ("vault".into(), unresolved("hashicorp/vault")),
        ("vault-init".into(), unresolved("curlimages/curl")),
        ("lockbox".into(), resolved(&build.lockbox)),
        ("inquisition".into(), resolved(&build.inquisition)),
        ("token-server-v2".into(), resolved(&build.token)),
        ("mercury-server".into(), resolved(&build.mercury)),
    ])
}

pub(super) fn expected_from_metadata(metadata: &StackMetadata) -> ExpectedImages {
    let mut expected = BTreeMap::from([
        ("db_server".into(), unresolved("postgres:16.2")),
        ("db_lockbox".into(), unresolved("postgres:16.2")),
        ("vault".into(), unresolved("hashicorp/vault")),
        ("vault-init".into(), unresolved("curlimages/curl")),
    ]);
    let Some(build) = metadata.build_resolution() else {
        return expected;
    };
    let images = build.images();
    if let Some(image) = images.mercury() {
        expected.insert("mercury-server".into(), stored(image));
    }
    if let Some(image) = images.token() {
        expected.insert("token-server-v2".into(), stored(image));
    }
    if let Some(images) = images.lockbox() {
        expected.insert("lockbox".into(), stored(images.production()));
    }
    if let Some(image) = images.inquisition() {
        expected.insert("inquisition".into(), stored(image));
    }
    expected
}

fn unresolved(tag: &str) -> ExpectedImage {
    ExpectedImage {
        tag: tag.to_owned(),
        image_id: None,
    }
}

fn resolved(image: &super::super::build::VerifiedImage) -> ExpectedImage {
    ExpectedImage {
        tag: image.tag.clone(),
        image_id: Some(image.image_id.clone()),
    }
}

fn stored(image: &super::super::model::ResolvedImage) -> ExpectedImage {
    ExpectedImage {
        tag: image.tag().to_owned(),
        image_id: Some(image.image_id().to_owned()),
    }
}

pub(super) fn image_map(metadata: &StackMetadata, build: &VerifiedBuild) -> Result<ImageMap> {
    ImageMap::new(
        metadata.project(),
        &build.mercury.tag,
        &build.token.tag,
        &build.lockbox.tag,
        &build.lockbox_rng.tag,
    )
}

pub(super) fn image_map_from_metadata(metadata: &StackMetadata) -> Result<ImageMap> {
    let build = metadata
        .build_resolution()
        .context("complete build metadata is required to address an existing stack")?;
    let images = build.images();
    let lockbox = images
        .lockbox()
        .context("complete lockbox build metadata is absent")?;
    ImageMap::new(
        metadata.project(),
        images
            .mercury()
            .context("complete Mercury build metadata is absent")?
            .tag(),
        images
            .token()
            .context("complete token build metadata is absent")?
            .tag(),
        lockbox.production().tag(),
        lockbox.deterministic_rng().tag(),
    )
}

pub(super) fn service_readiness(service: &str) -> Result<ReadinessKind> {
    Ok(match service {
        "db_server" => ReadinessKind::Postgres("mercury"),
        "db_lockbox" => ReadinessKind::Postgres("enclave"),
        "vault" => ReadinessKind::Vault,
        "vault-init" => ReadinessKind::None,
        "lockbox" | "token-server-v2" => ReadinessKind::HttpAlive,
        "mercury-server" => ReadinessKind::HttpConfig,
        "inquisition" => ReadinessKind::Inquisition,
        _ => anyhow::bail!("unknown lifecycle service {service:?}"),
    })
}

pub(super) fn required_health(service: &str) -> Result<RequiredHealth> {
    Ok(match service {
        "vault-init" | "inquisition" => RequiredHealth::Healthy,
        value if SERVICES.contains(&value) => RequiredHealth::Absent,
        _ => anyhow::bail!("unknown lifecycle service {service:?}"),
    })
}

pub(super) fn expected_ports(
    ports: PortMap,
) -> BTreeMap<&'static str, BTreeMap<&'static str, u16>> {
    BTreeMap::from([
        (
            "db_server",
            BTreeMap::from([("5432/tcp", ports.mercury_database)]),
        ),
        (
            "db_lockbox",
            BTreeMap::from([("5432/tcp", ports.lockbox_database)]),
        ),
        ("vault", BTreeMap::from([("8200/tcp", ports.vault)])),
        ("vault-init", BTreeMap::new()),
        ("lockbox", BTreeMap::from([("18080/tcp", ports.lockbox)])),
        (
            "inquisition",
            BTreeMap::from([("18443/tcp", ports.core_rpc), ("18444/tcp", ports.core_p2p)]),
        ),
        (
            "token-server-v2",
            BTreeMap::from([("8001/tcp", ports.token)]),
        ),
        (
            "mercury-server",
            BTreeMap::from([("8000/tcp", ports.mercury)]),
        ),
    ])
}

pub(super) fn expected_declared_mount(service: &str) -> Option<(&'static str, &'static str)> {
    DECLARED_VOLUMES
        .iter()
        .find(|(_, owner, _)| *owner == service)
        .map(|(volume, _, destination)| (*volume, *destination))
}

pub(super) fn service_port(metadata: &StackMetadata, service: &str) -> Result<u16> {
    let ports = metadata.ports();
    match service {
        "vault" => Ok(ports.vault),
        "lockbox" => Ok(ports.lockbox),
        "token-server-v2" => Ok(ports.token),
        "mercury-server" => Ok(ports.mercury),
        _ => Err(anyhow::anyhow!("service {service:?} has no HTTP endpoint"))
            .context("resolve lifecycle HTTP port"),
    }
}

pub(super) fn network_name(metadata: &StackMetadata) -> String {
    format!("{}_default", metadata.project())
}

pub(super) fn declared_volume_name(metadata: &StackMetadata, key: &str) -> String {
    format!("{}_{key}", metadata.project())
}
