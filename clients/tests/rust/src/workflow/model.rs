use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::stack::ComposeFile;

use super::matrix::{self, MATRIX};

pub const STACK_SCHEMA_VERSION: u32 = 1;
pub const WORKFLOW_NAME: &str = "bip448-test";

pub const MERCURY_IMAGE_PREFIX: &str = "mercurylayer/mercury-server:bip448-test-";
pub const TOKEN_IMAGE_PREFIX: &str = "mercurylayer/token-server:bip448-test-";
pub const LOCKBOX_IMAGE_PREFIX: &str = "mercurylayer/lockbox:bip448-test-";
pub const INQUISITION_IMAGE: &str = "mercurylayer/bitcoin-inquisition:f536586";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Project(String);

impl Project {
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        let bytes = value.as_bytes();
        if !(1..=63).contains(&bytes.len())
            || (!bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit())
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
            })
        {
            return Err(format!(
                "invalid Compose project {value:?}; expected ^[a-z0-9][a-z0-9_-]{{0,62}}$"
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Project {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortRole {
    Mercury,
    Token,
    Lockbox,
    MercuryDatabase,
    LockboxDatabase,
    CoreRpc,
    CoreP2p,
    Vault,
}

impl fmt::Display for PortRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Mercury => "mercury",
            Self::Token => "token",
            Self::Lockbox => "lockbox",
            Self::MercuryDatabase => "mercury_database",
            Self::LockboxDatabase => "lockbox_database",
            Self::CoreRpc => "core_rpc",
            Self::CoreP2p => "core_p2p",
            Self::Vault => "vault",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortMap {
    pub mercury: u16,
    pub token: u16,
    pub lockbox: u16,
    pub mercury_database: u16,
    pub lockbox_database: u16,
    pub core_rpc: u16,
    pub core_p2p: u16,
    pub vault: u16,
}

impl PortMap {
    pub fn from_base(base: u16) -> std::result::Result<Self, String> {
        if base == 0 {
            return Err("--base-port must be at least 1".to_owned());
        }
        let value = |offset: u16| {
            base.checked_add(offset).ok_or_else(|| {
                format!("--base-port {base} cannot provide the required eight-port range")
            })
        };
        Ok(Self {
            mercury: value(0)?,
            token: value(1)?,
            lockbox: value(2)?,
            mercury_database: value(3)?,
            lockbox_database: value(4)?,
            core_rpc: value(5)?,
            core_p2p: value(6)?,
            vault: value(7)?,
        })
    }

    pub fn base(self) -> u16 {
        self.mercury
    }

    pub fn ordered(self) -> [(PortRole, u16); 8] {
        [
            (PortRole::Mercury, self.mercury),
            (PortRole::Token, self.token),
            (PortRole::Lockbox, self.lockbox),
            (PortRole::MercuryDatabase, self.mercury_database),
            (PortRole::LockboxDatabase, self.lockbox_database),
            (PortRole::CoreRpc, self.core_rpc),
            (PortRole::CoreP2p, self.core_p2p),
            (PortRole::Vault, self.vault),
        ]
    }

    fn validate_exact(self) -> Result<()> {
        let expected = Self::from_base(self.base()).map_err(anyhow::Error::msg)?;
        ensure!(
            self == expected,
            "stack metadata contains a non-canonical port map"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointMap {
    pub mercury_url: String,
    pub lockbox_url: String,
    pub core_rpc_url: String,
    pub mercury_database_url: String,
    pub lockbox_database_url: String,
}

impl EndpointMap {
    pub fn from_ports(ports: PortMap) -> Self {
        Self {
            mercury_url: loopback_http(ports.mercury),
            lockbox_url: loopback_http(ports.lockbox),
            core_rpc_url: loopback_http(ports.core_rpc),
            mercury_database_url: loopback_postgres(ports.mercury_database, "mercury"),
            lockbox_database_url: loopback_postgres(ports.lockbox_database, "enclave"),
        }
    }
}

fn loopback_http(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn loopback_postgres(port: u16, database: &str) -> String {
    format!("postgres://postgres:postgres@127.0.0.1:{port}/{database}")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunPaths {
    pub run_directory: PathBuf,
    pub settings_file: PathBuf,
    pub stack_metadata: PathBuf,
    pub wallet_database: PathBuf,
}

impl RunPaths {
    pub fn new(repo_root: &Path, project: &Project) -> Self {
        let run_directory = repo_root.join("target/bip448-runs").join(project.as_str());
        Self {
            settings_file: run_directory.join("Settings.toml"),
            stack_metadata: run_directory.join("stack.json"),
            wallet_database: run_directory.join("wallet.db"),
            run_directory,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageRole {
    Mercury,
    Token,
    Lockbox,
    LockboxRng,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageMap {
    mercury: String,
    token: String,
    lockbox: String,
    lockbox_rng: String,
}

impl ImageMap {
    pub fn new(
        project: &Project,
        mercury: &str,
        token: &str,
        lockbox: &str,
        lockbox_rng: &str,
    ) -> Result<Self> {
        validate_image(mercury, MERCURY_IMAGE_PREFIX)?;
        validate_image(token, TOKEN_IMAGE_PREFIX)?;
        let lockbox_fingerprint = validate_image(lockbox, LOCKBOX_IMAGE_PREFIX)?;
        ensure!(
            lockbox_rng
                == format!("mercurylayer/lockbox:bip448-test-{lockbox_fingerprint}-rng-{project}"),
            "lockbox RNG image must match the lockbox fingerprint and Compose project"
        );
        Ok(Self {
            mercury: mercury.to_owned(),
            token: token.to_owned(),
            lockbox: lockbox.to_owned(),
            lockbox_rng: lockbox_rng.to_owned(),
        })
    }

    pub fn mercury(&self) -> &str {
        &self.mercury
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn lockbox(&self) -> &str {
        &self.lockbox
    }

    pub fn lockbox_rng(&self) -> &str {
        &self.lockbox_rng
    }
}

fn validate_image<'a>(value: &'a str, prefix: &str) -> Result<&'a str> {
    let fingerprint = value
        .strip_prefix(prefix)
        .context("image does not have the required component prefix")?;
    ensure!(
        fingerprint.len() == 16
            && fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "image must end in a 16-character lowercase hex fingerprint"
    );
    Ok(fingerprint)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectSpec {
    project: Project,
    repo_root: PathBuf,
    paths: RunPaths,
    ports: PortMap,
    endpoints: EndpointMap,
    images: ImageMap,
}

impl ProjectSpec {
    fn from_metadata(metadata: &StackMetadata, images: ImageMap) -> Self {
        Self {
            project: metadata.project.clone(),
            repo_root: metadata.repo_root.clone(),
            paths: metadata.paths.clone(),
            ports: metadata.ports,
            endpoints: metadata.endpoints.clone(),
            images,
        }
    }

    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn paths(&self) -> &RunPaths {
        &self.paths
    }

    pub fn ports(&self) -> PortMap {
        self.ports
    }

    pub fn endpoints(&self) -> &EndpointMap {
        &self.endpoints
    }

    pub fn images(&self) -> &ImageMap {
        &self.images
    }

    pub fn managed_environment(&self) -> Result<BTreeMap<String, String>> {
        let wallet_database = self
            .paths
            .wallet_database
            .to_str()
            .context("wallet database path is not UTF-8")?;
        let settings_file = self
            .paths
            .settings_file
            .to_str()
            .context("settings path is not UTF-8")?;

        Ok(BTreeMap::from([
            ("COMPOSE_PROJECT_NAME".into(), self.project.to_string()),
            ("ML_TEST_PROJECT".into(), self.project.to_string()),
            (
                "ML_TEST_MERCURY_URL".into(),
                self.endpoints.mercury_url.clone(),
            ),
            (
                "ML_TEST_LOCKBOX_URL".into(),
                self.endpoints.lockbox_url.clone(),
            ),
            (
                "ML_TEST_CORE_RPC_URL".into(),
                self.endpoints.core_rpc_url.clone(),
            ),
            (
                "ML_TEST_MERCURY_DATABASE_URL".into(),
                self.endpoints.mercury_database_url.clone(),
            ),
            (
                "ML_TEST_LOCKBOX_DATABASE_URL".into(),
                self.endpoints.lockbox_database_url.clone(),
            ),
            ("ML_TEST_WALLET_NAME".into(), "mercury_test".into()),
            ("ML_TEST_WALLET_DB".into(), wallet_database.into()),
            (
                "ML_TEST_CORE_RPC_PORT".into(),
                self.ports.core_rpc.to_string(),
            ),
            (
                "ML_TEST_CORE_P2P_PORT".into(),
                self.ports.core_p2p.to_string(),
            ),
            ("ML_TEST_VAULT_PORT".into(), self.ports.vault.to_string()),
            (
                "ML_TEST_LOCKBOX_PORT".into(),
                self.ports.lockbox.to_string(),
            ),
            ("ML_TEST_TOKEN_PORT".into(), self.ports.token.to_string()),
            (
                "ML_TEST_MERCURY_PORT".into(),
                self.ports.mercury.to_string(),
            ),
            (
                "ML_TEST_LOCKBOX_DB_PORT".into(),
                self.ports.lockbox_database.to_string(),
            ),
            (
                "ML_TEST_MERCURY_DB_PORT".into(),
                self.ports.mercury_database.to_string(),
            ),
            ("ML_TEST_MERCURY_IMAGE".into(), self.images.mercury.clone()),
            ("ML_TEST_TOKEN_IMAGE".into(), self.images.token.clone()),
            ("ML_TEST_LOCKBOX_IMAGE".into(), self.images.lockbox.clone()),
            (
                "ML_TEST_LOCKBOX_RNG_IMAGE".into(),
                self.images.lockbox_rng.clone(),
            ),
            ("ML_SETTINGS_FILE".into(), settings_file.into()),
            ("ML_NETWORK".into(), "regtest".into()),
            ("RUSTUP_TOOLCHAIN".into(), "1.92.0".into()),
        ]))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentConfig {
    pub service: &'static str,
    pub compose_files: &'static [ComposeFile],
    pub ports: &'static [PortRole],
    pub images: &'static [ImageRole],
}

const TOKEN_SERVERS: &[ComposeFile] = &[ComposeFile::TokenServers];
const BOTH_COMPOSE_FILES: &[ComposeFile] = &[ComposeFile::TokenServers, ComposeFile::Lockbox];

pub const COMPONENTS: &[ComponentConfig] = &[
    ComponentConfig {
        service: "db_server",
        compose_files: BOTH_COMPOSE_FILES,
        ports: &[PortRole::MercuryDatabase],
        images: &[],
    },
    ComponentConfig {
        service: "db_lockbox",
        compose_files: BOTH_COMPOSE_FILES,
        ports: &[PortRole::LockboxDatabase],
        images: &[],
    },
    ComponentConfig {
        service: "vault",
        compose_files: BOTH_COMPOSE_FILES,
        ports: &[PortRole::Vault],
        images: &[],
    },
    ComponentConfig {
        service: "vault-init",
        compose_files: BOTH_COMPOSE_FILES,
        ports: &[],
        images: &[],
    },
    ComponentConfig {
        service: "lockbox",
        compose_files: BOTH_COMPOSE_FILES,
        ports: &[PortRole::Lockbox],
        images: &[ImageRole::Lockbox, ImageRole::LockboxRng],
    },
    ComponentConfig {
        service: "inquisition",
        compose_files: TOKEN_SERVERS,
        ports: &[PortRole::CoreRpc, PortRole::CoreP2p],
        images: &[],
    },
    ComponentConfig {
        service: "token-server",
        compose_files: TOKEN_SERVERS,
        ports: &[PortRole::Token],
        images: &[ImageRole::Token],
    },
    ComponentConfig {
        service: "mercury-server",
        compose_files: BOTH_COMPOSE_FILES,
        ports: &[PortRole::Mercury],
        images: &[ImageRole::Mercury],
    },
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ComposeSource {
    TokenServers,
    Lockbox,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredComponentConfig {
    service: String,
    compose_files: Vec<ComposeSource>,
    ports: Vec<PortRole>,
    images: Vec<ImageRole>,
}

impl From<&ComponentConfig> for StoredComponentConfig {
    fn from(component: &ComponentConfig) -> Self {
        Self {
            service: component.service.to_owned(),
            compose_files: component
                .compose_files
                .iter()
                .map(|file| match file {
                    ComposeFile::TokenServers => ComposeSource::TokenServers,
                    ComposeFile::Lockbox => ComposeSource::Lockbox,
                })
                .collect(),
            ports: component.ports.to_vec(),
            images: component.images.to_vec(),
        }
    }
}

fn stored_components() -> Vec<StoredComponentConfig> {
    COMPONENTS.iter().map(StoredComponentConfig::from).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixTargetSummary {
    target: String,
    test_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixSummary {
    target_count: usize,
    test_count: usize,
    targets: Vec<MatrixTargetSummary>,
}

impl MatrixSummary {
    fn current() -> Self {
        Self {
            target_count: MATRIX.len(),
            test_count: matrix::test_count(),
            targets: MATRIX
                .iter()
                .map(|entry| MatrixTargetSummary {
                    target: entry.target.to_owned(),
                    test_count: entry.tests.len(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleSupport {
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleObservation {
    NotObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleState {
    support: LifecycleSupport,
    observation: LifecycleObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeHashes {
    token_servers_sha256: String,
    lockbox_sha256: String,
}

impl ComposeHashes {
    pub(super) fn new(token_servers_sha256: String, lockbox_sha256: String) -> Self {
        Self {
            token_servers_sha256,
            lockbox_sha256,
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        validate_sha256(&self.token_servers_sha256, "token-servers Compose hash")?;
        validate_sha256(&self.lockbox_sha256, "lockbox Compose hash")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSource {
    head: String,
    status_sha256: String,
    compose: ComposeHashes,
}

impl BuildSource {
    pub(super) fn new(head: String, status_sha256: String, compose: ComposeHashes) -> Self {
        Self {
            head,
            status_sha256,
            compose,
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.head.len() == 40 && is_lower_hex(&self.head),
            "build source HEAD must be a 40-character lowercase hexadecimal commit"
        );
        validate_sha256(&self.status_sha256, "build source status digest")?;
        self.compose.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildFingerprints {
    mercury: String,
    token: String,
    lockbox: String,
    inquisition: String,
}

impl BuildFingerprints {
    pub(super) fn new(
        mercury: String,
        token: String,
        lockbox: String,
        inquisition: String,
    ) -> Self {
        Self {
            mercury,
            token,
            lockbox,
            inquisition,
        }
    }

    pub(super) fn mercury(&self) -> &str {
        &self.mercury
    }

    pub(super) fn token(&self) -> &str {
        &self.token
    }

    pub(super) fn lockbox(&self) -> &str {
        &self.lockbox
    }

    pub(super) fn inquisition(&self) -> &str {
        &self.inquisition
    }

    fn validate(&self) -> Result<()> {
        validate_sha256(&self.mercury, "Mercury build fingerprint")?;
        validate_sha256(&self.token, "token build fingerprint")?;
        validate_sha256(&self.lockbox, "lockbox build fingerprint")?;
        validate_sha256(&self.inquisition, "Inquisition build fingerprint")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedImage {
    fingerprint: String,
    tag: String,
    image_id: String,
}

impl ResolvedImage {
    pub(super) fn new(fingerprint: String, tag: String, image_id: String) -> Self {
        Self {
            fingerprint,
            tag,
            image_id,
        }
    }

    pub(super) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(super) fn tag(&self) -> &str {
        &self.tag
    }

    pub(super) fn image_id(&self) -> &str {
        &self.image_id
    }

    fn validate(&self, fingerprint: &str, expected_tag: &str) -> Result<()> {
        ensure!(
            self.fingerprint == fingerprint,
            "resolved image fingerprint does not match build fingerprints"
        );
        ensure!(self.tag == expected_tag, "resolved image tag mismatch");
        validate_image_id(&self.image_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedLockboxImages {
    production: ResolvedImage,
    deterministic_rng: ResolvedImage,
}

impl ResolvedLockboxImages {
    pub(super) fn new(production: ResolvedImage, deterministic_rng: ResolvedImage) -> Self {
        Self {
            production,
            deterministic_rng,
        }
    }

    pub(super) fn production(&self) -> &ResolvedImage {
        &self.production
    }

    pub(super) fn deterministic_rng(&self) -> &ResolvedImage {
        &self.deterministic_rng
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedImages {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mercury: Option<ResolvedImage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<ResolvedImage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lockbox: Option<ResolvedLockboxImages>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquisition: Option<ResolvedImage>,
}

impl ResolvedImages {
    pub(super) fn mercury(&self) -> Option<&ResolvedImage> {
        self.mercury.as_ref()
    }

    pub(super) fn token(&self) -> Option<&ResolvedImage> {
        self.token.as_ref()
    }

    pub(super) fn lockbox(&self) -> Option<&ResolvedLockboxImages> {
        self.lockbox.as_ref()
    }

    pub(super) fn inquisition(&self) -> Option<&ResolvedImage> {
        self.inquisition.as_ref()
    }

    pub(super) fn set_mercury(&mut self, image: ResolvedImage) {
        self.mercury = Some(image);
    }

    pub(super) fn set_token(&mut self, image: ResolvedImage) {
        self.token = Some(image);
    }

    pub(super) fn set_lockbox(&mut self, images: ResolvedLockboxImages) {
        self.lockbox = Some(images);
    }

    pub(super) fn set_inquisition(&mut self, image: ResolvedImage) {
        self.inquisition = Some(image);
    }

    fn is_empty(&self) -> bool {
        self.mercury.is_none()
            && self.token.is_none()
            && self.lockbox.is_none()
            && self.inquisition.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildResolution {
    source: BuildSource,
    fingerprints: BuildFingerprints,
    images: ResolvedImages,
}

impl BuildResolution {
    pub(super) fn new(
        source: BuildSource,
        fingerprints: BuildFingerprints,
        images: ResolvedImages,
    ) -> Self {
        Self {
            source,
            fingerprints,
            images,
        }
    }

    pub(super) fn source(&self) -> &BuildSource {
        &self.source
    }

    pub(super) fn fingerprints(&self) -> &BuildFingerprints {
        &self.fingerprints
    }

    pub(super) fn images(&self) -> &ResolvedImages {
        &self.images
    }

    fn validate(&self, project: &Project) -> Result<()> {
        self.source.validate()?;
        self.fingerprints.validate()?;
        ensure!(
            !self.images.is_empty(),
            "build resolution must contain at least one resolved image"
        );

        if let Some(image) = &self.images.mercury {
            image.validate(
                &self.fingerprints.mercury,
                &fingerprinted_tag(MERCURY_IMAGE_PREFIX, &self.fingerprints.mercury),
            )?;
        }
        if let Some(image) = &self.images.token {
            image.validate(
                &self.fingerprints.token,
                &fingerprinted_tag(TOKEN_IMAGE_PREFIX, &self.fingerprints.token),
            )?;
        }
        if let Some(images) = &self.images.lockbox {
            let tag = fingerprinted_tag(LOCKBOX_IMAGE_PREFIX, &self.fingerprints.lockbox);
            images
                .production
                .validate(&self.fingerprints.lockbox, &tag)?;
            images
                .deterministic_rng
                .validate(&self.fingerprints.lockbox, &format!("{tag}-rng-{project}"))?;
        }
        if let Some(image) = &self.images.inquisition {
            image.validate(&self.fingerprints.inquisition, INQUISITION_IMAGE)?;
        }
        Ok(())
    }
}

fn fingerprinted_tag(prefix: &str, fingerprint: &str) -> String {
    format!("{prefix}{}", &fingerprint[..16])
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && is_lower_hex(value),
        "{label} must be a 64-character lowercase hexadecimal SHA-256 digest"
    );
    Ok(())
}

fn validate_image_id(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("resolved image ID must start with sha256:")?;
    validate_sha256(digest, "resolved image ID")
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl LifecycleState {
    fn foundation() -> Self {
        Self {
            support: LifecycleSupport::Unsupported,
            observation: LifecycleObservation::NotObserved,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackMetadata {
    schema_version: u32,
    workflow: String,
    project: Project,
    repo_root: PathBuf,
    paths: RunPaths,
    ports: PortMap,
    endpoints: EndpointMap,
    components: Vec<StoredComponentConfig>,
    matrix: MatrixSummary,
    lifecycle: LifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    build: Option<BuildResolution>,
}

impl StackMetadata {
    pub fn new(repo_root: &Path, project: Project, ports: PortMap) -> Self {
        Self {
            schema_version: STACK_SCHEMA_VERSION,
            workflow: WORKFLOW_NAME.to_owned(),
            paths: RunPaths::new(repo_root, &project),
            endpoints: EndpointMap::from_ports(ports),
            components: stored_components(),
            matrix: MatrixSummary::current(),
            lifecycle: LifecycleState::foundation(),
            build: None,
            project,
            repo_root: repo_root.to_path_buf(),
            ports,
        }
    }

    pub fn project(&self) -> &Project {
        &self.project
    }

    pub fn paths(&self) -> &RunPaths {
        &self.paths
    }

    pub fn ports(&self) -> PortMap {
        self.ports
    }

    pub fn endpoints(&self) -> &EndpointMap {
        &self.endpoints
    }

    pub(super) fn build_resolution(&self) -> Option<&BuildResolution> {
        self.build.as_ref()
    }

    pub(super) fn set_build_resolution(&mut self, build: BuildResolution) {
        self.build = Some(build);
    }

    pub fn project_spec(&self, images: ImageMap) -> ProjectSpec {
        ProjectSpec::from_metadata(self, images)
    }

    pub fn settings_contents(&self) -> Result<String> {
        let database_file = self
            .paths
            .wallet_database
            .to_str()
            .context("wallet database path is not UTF-8")?;
        Ok(format!(
            concat!(
                "statechain_entity = {}\n",
                "chain_backend = \"core\"\n",
                "core_rpc_url = {}\n",
                "core_rpc_auth = \"userpass\"\n",
                "core_rpc_user = \"mercury\"\n",
                "core_rpc_password = \"mercury\"\n",
                "network = \"regtest\"\n",
                "fee_rate_tolerance = 5\n",
                "database_file = {}\n",
                "confirmation_target = 2\n",
                "max_fee_rate = 1\n"
            ),
            toml_string(&self.endpoints.mercury_url),
            toml_string(&self.endpoints.core_rpc_url),
            toml_string(database_file),
        ))
    }

    pub fn validate(&self, repo_root: &Path, expected_project: &Project) -> Result<()> {
        ensure!(
            self.schema_version == STACK_SCHEMA_VERSION,
            "unsupported stack metadata schema version {}",
            self.schema_version
        );
        ensure!(
            self.workflow == WORKFLOW_NAME,
            "stack metadata workflow mismatch"
        );
        Project::parse(self.project.as_str()).map_err(anyhow::Error::msg)?;
        ensure!(
            &self.project == expected_project,
            "stack metadata project {} does not match requested project {}",
            self.project,
            expected_project
        );
        ensure!(
            self.repo_root == repo_root,
            "stack metadata repository root mismatch"
        );
        ensure!(
            self.paths == RunPaths::new(repo_root, expected_project),
            "stack metadata contains non-controller paths"
        );
        self.ports.validate_exact()?;
        ensure!(
            self.endpoints == EndpointMap::from_ports(self.ports),
            "stack metadata endpoint map does not match its ports"
        );
        ensure!(
            self.components == stored_components(),
            "stack metadata component configuration mismatch"
        );
        ensure!(
            self.matrix == MatrixSummary::current(),
            "stack metadata test matrix summary mismatch"
        );
        ensure!(
            self.lifecycle == LifecycleState::foundation(),
            "stack metadata lifecycle state is not supported by this foundation"
        );
        if let Some(build) = &self.build {
            build.validate(&self.project)?;
        }
        Ok(())
    }
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a UTF-8 string cannot fail")
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    let value = sort_json(serde_json::to_value(value)?);
    let mut output = serde_json::to_string(&value)?;
    output.push('\n');
    Ok(output)
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(values.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

pub fn parse_metadata(bytes: &[u8]) -> Result<StackMetadata> {
    let metadata = serde_json::from_slice(bytes).context("parse stack metadata JSON")?;
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> StackMetadata {
        StackMetadata::new(
            Path::new("/repo"),
            Project::parse("workflow_1").unwrap(),
            PortMap::from_base(23000).unwrap(),
        )
    }

    #[test]
    fn project_validation_matches_the_managed_stack_contract() {
        for valid in [
            "a".to_owned(),
            "0".to_owned(),
            "a-b_2".to_owned(),
            "a".repeat(63),
        ] {
            assert!(Project::parse(&valid).is_ok(), "rejected {valid:?}");
        }
        for invalid in [
            "",
            "UPPER",
            "has.dot",
            "has/slash",
            "has space",
            "has$meta",
            "-leading",
            "_leading",
            &"a".repeat(64),
        ] {
            assert!(Project::parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn explicit_port_map_is_exact_and_bounded() {
        let ports = PortMap::from_base(23000).unwrap();
        assert_eq!(
            ports.ordered(),
            [
                (PortRole::Mercury, 23000),
                (PortRole::Token, 23001),
                (PortRole::Lockbox, 23002),
                (PortRole::MercuryDatabase, 23003),
                (PortRole::LockboxDatabase, 23004),
                (PortRole::CoreRpc, 23005),
                (PortRole::CoreP2p, 23006),
                (PortRole::Vault, 23007),
            ]
        );
        assert!(PortMap::from_base(0).is_err());
        assert!(PortMap::from_base(65528).is_ok());
        assert!(PortMap::from_base(65529).is_err());
    }

    #[test]
    fn endpoints_and_settings_have_one_port_derived_owner() {
        let metadata = metadata();
        assert_eq!(metadata.endpoints.mercury_url, "http://127.0.0.1:23000");
        assert_eq!(metadata.endpoints.lockbox_url, "http://127.0.0.1:23002");
        assert_eq!(metadata.endpoints.core_rpc_url, "http://127.0.0.1:23005");
        assert_eq!(
            metadata.endpoints.mercury_database_url,
            "postgres://postgres:postgres@127.0.0.1:23003/mercury"
        );
        assert_eq!(
            metadata.endpoints.lockbox_database_url,
            "postgres://postgres:postgres@127.0.0.1:23004/enclave"
        );

        let settings = metadata.settings_contents().unwrap();
        assert!(settings.contains("statechain_entity = \"http://127.0.0.1:23000\"\n"));
        assert!(settings.contains("core_rpc_url = \"http://127.0.0.1:23005\"\n"));
        assert!(settings
            .contains("database_file = \"/repo/target/bip448-runs/workflow_1/wallet.db\"\n"));
        assert!(settings.contains("network = \"regtest\"\n"));
    }

    #[test]
    fn metadata_is_versioned_canonical_and_strict() {
        let metadata = metadata();
        metadata
            .validate(Path::new("/repo"), metadata.project())
            .unwrap();
        let encoded = canonical_json(&metadata).unwrap();
        assert!(encoded.ends_with('\n'));
        assert!(encoded.contains("\"observation\":\"not_observed\""));
        assert!(encoded.contains("\"support\":\"unsupported\""));
        assert!(encoded.contains("\"target_count\":8"));
        assert!(encoded.contains("\"test_count\":59"));
        assert!(!encoded.contains("\"build\""));
        assert_eq!(
            canonical_json(&parse_metadata(encoded.as_bytes()).unwrap()).unwrap(),
            encoded
        );

        let with_unknown = encoded.replacen('{', "{\"unknown\":true,", 1);
        assert!(parse_metadata(with_unknown.as_bytes()).is_err());
    }

    #[test]
    fn optional_build_resolution_preserves_schema_v1_and_is_strictly_validated() {
        let mut metadata = metadata();
        let fingerprints = BuildFingerprints::new(
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
        );
        let mut images = ResolvedImages::default();
        images.set_mercury(ResolvedImage::new(
            "a".repeat(64),
            format!("{MERCURY_IMAGE_PREFIX}{}", "a".repeat(16)),
            format!("sha256:{}", "e".repeat(64)),
        ));
        metadata.set_build_resolution(BuildResolution::new(
            BuildSource::new(
                "0".repeat(40),
                "1".repeat(64),
                ComposeHashes::new("2".repeat(64), "3".repeat(64)),
            ),
            fingerprints,
            images,
        ));
        metadata
            .validate(Path::new("/repo"), metadata.project())
            .unwrap();
        let encoded = canonical_json(&metadata).unwrap();
        assert!(encoded.contains("\"schema_version\":1"));
        assert!(encoded.contains("\"build\":"));
        assert_eq!(
            canonical_json(&parse_metadata(encoded.as_bytes()).unwrap()).unwrap(),
            encoded
        );

        let invalid = encoded.replace(&format!("sha256:{}", "e".repeat(64)), "sha256:short");
        let invalid = parse_metadata(invalid.as_bytes()).unwrap();
        assert!(invalid
            .validate(Path::new("/repo"), invalid.project())
            .is_err());
    }

    #[test]
    fn metadata_rejects_paths_endpoints_and_lifecycle_drift() {
        let expected_project = Project::parse("workflow_1").unwrap();

        let mut changed = metadata();
        changed.paths.wallet_database = PathBuf::from("/tmp/wallet.db");
        assert!(changed
            .validate(Path::new("/repo"), &expected_project)
            .is_err());

        let mut changed = metadata();
        changed.endpoints.mercury_url.push_str("/wrong");
        assert!(changed
            .validate(Path::new("/repo"), &expected_project)
            .is_err());

        let mut changed = metadata();
        changed.lifecycle.observation = LifecycleObservation::NotObserved;
        changed.lifecycle.support = LifecycleSupport::Unsupported;
        changed.schema_version += 1;
        assert!(changed
            .validate(Path::new("/repo"), &expected_project)
            .is_err());

        assert!(metadata()
            .validate(Path::new("/different"), &expected_project)
            .is_err());
        assert!(metadata()
            .validate(Path::new("/repo"), &Project::parse("different").unwrap())
            .is_err());
    }

    #[test]
    fn components_cover_c1_services_ports_and_images_once() {
        assert_eq!(COMPONENTS.len(), 8);
        assert_eq!(
            COMPONENTS
                .iter()
                .map(|value| value.service)
                .collect::<Vec<_>>(),
            [
                "db_server",
                "db_lockbox",
                "vault",
                "vault-init",
                "lockbox",
                "inquisition",
                "token-server",
                "mercury-server",
            ]
        );
        let ports = COMPONENTS
            .iter()
            .flat_map(|value| value.ports.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(ports.len(), 8);
        assert_eq!(
            ports
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            8
        );
        let images = COMPONENTS
            .iter()
            .flat_map(|value| value.images.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            images,
            [
                ImageRole::Lockbox,
                ImageRole::LockboxRng,
                ImageRole::Token,
                ImageRole::Mercury,
            ]
        );
    }

    #[test]
    fn explicit_images_and_managed_environment_round_trip_through_stack_config() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let project = Project::parse("workflow_roundtrip").unwrap();
        let metadata = StackMetadata::new(
            &repo_root,
            project.clone(),
            PortMap::from_base(23000).unwrap(),
        );
        let images = ImageMap::new(
            &project,
            "mercurylayer/mercury-server:bip448-test-0123456789abcdef",
            "mercurylayer/token-server:bip448-test-1111111111111111",
            "mercurylayer/lockbox:bip448-test-abcdef0123456789",
            "mercurylayer/lockbox:bip448-test-abcdef0123456789-rng-workflow_roundtrip",
        )
        .unwrap();
        let spec = metadata.project_spec(images);
        let environment = spec.managed_environment().unwrap();

        assert_eq!(environment.len(), 24);
        assert_eq!(environment["COMPOSE_PROJECT_NAME"], "workflow_roundtrip");
        assert_eq!(environment["ML_TEST_MERCURY_PORT"], "23000");
        assert_eq!(environment["ML_TEST_TOKEN_PORT"], "23001");
        assert_eq!(environment["ML_TEST_LOCKBOX_PORT"], "23002");
        assert_eq!(environment["ML_TEST_MERCURY_DB_PORT"], "23003");
        assert_eq!(environment["ML_TEST_LOCKBOX_DB_PORT"], "23004");
        assert_eq!(environment["ML_TEST_CORE_RPC_PORT"], "23005");
        assert_eq!(environment["ML_TEST_CORE_P2P_PORT"], "23006");
        assert_eq!(environment["ML_TEST_VAULT_PORT"], "23007");
        assert_eq!(spec.repo_root(), repo_root);

        let stack = crate::stack::StackConfig::from_env_map(&environment).unwrap();
        assert_eq!(stack.project(), spec.project().as_str());
        assert_eq!(stack.mercury_url(), spec.endpoints().mercury_url);
        assert_eq!(stack.wallet_db(), spec.paths().wallet_database);
        assert_eq!(stack.mercury_image(), spec.images().mercury());
        assert_eq!(stack.token_image(), spec.images().token());
        assert_eq!(stack.lockbox_image(), spec.images().lockbox());
        assert_eq!(stack.lockbox_rng_image(), spec.images().lockbox_rng());

        let command = stack.compose_command(ComposeFile::TokenServers, &["config"]);
        let compose_environment = command
            .get_envs()
            .filter_map(|(key, value)| {
                value.map(|value| {
                    (
                        key.to_str().unwrap().to_owned(),
                        value.to_str().unwrap().to_owned(),
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(compose_environment.len(), 12);
        for key in [
            "ML_TEST_CORE_RPC_PORT",
            "ML_TEST_CORE_P2P_PORT",
            "ML_TEST_VAULT_PORT",
            "ML_TEST_LOCKBOX_PORT",
            "ML_TEST_TOKEN_PORT",
            "ML_TEST_MERCURY_PORT",
            "ML_TEST_LOCKBOX_DB_PORT",
            "ML_TEST_MERCURY_DB_PORT",
            "ML_TEST_MERCURY_IMAGE",
            "ML_TEST_TOKEN_IMAGE",
            "ML_TEST_LOCKBOX_IMAGE",
            "ML_TEST_LOCKBOX_RNG_IMAGE",
        ] {
            assert_eq!(
                compose_environment[key], environment[key],
                "mismatch for {key}"
            );
        }
    }

    #[test]
    fn image_values_are_explicit_and_project_bound() {
        let project = Project::parse("images_1").unwrap();
        let valid = ImageMap::new(
            &project,
            "mercurylayer/mercury-server:bip448-test-0123456789abcdef",
            "mercurylayer/token-server:bip448-test-1111111111111111",
            "mercurylayer/lockbox:bip448-test-abcdef0123456789",
            "mercurylayer/lockbox:bip448-test-abcdef0123456789-rng-images_1",
        )
        .unwrap();
        assert_eq!(
            valid.lockbox_rng(),
            "mercurylayer/lockbox:bip448-test-abcdef0123456789-rng-images_1"
        );

        assert!(ImageMap::new(
            &project,
            "mercurylayer/mercury-server:bip448-test-ABCDEF0123456789",
            valid.token(),
            valid.lockbox(),
            valid.lockbox_rng(),
        )
        .is_err());
        assert!(ImageMap::new(
            &project,
            valid.mercury(),
            valid.token(),
            valid.lockbox(),
            "mercurylayer/lockbox:bip448-test-abcdef0123456789-rng-other",
        )
        .is_err());
    }
}
