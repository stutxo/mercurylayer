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
        service: "token-server-v2",
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
        assert!(encoded.contains("\"test_count\":58"));
        assert_eq!(
            canonical_json(&parse_metadata(encoded.as_bytes()).unwrap()).unwrap(),
            encoded
        );

        let with_unknown = encoded.replacen('{', "{\"unknown\":true,", 1);
        assert!(parse_metadata(with_unknown.as_bytes()).is_err());
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
                "token-server-v2",
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
}
