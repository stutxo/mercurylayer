use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const MANAGED_KEYS: [&str; 20] = [
    "ML_TEST_PROJECT",
    "ML_TEST_MERCURY_URL",
    "ML_TEST_LOCKBOX_URL",
    "ML_TEST_CORE_RPC_URL",
    "ML_TEST_MERCURY_DATABASE_URL",
    "ML_TEST_LOCKBOX_DATABASE_URL",
    "ML_TEST_WALLET_NAME",
    "ML_TEST_WALLET_DB",
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
];

const REQUIRED_NON_TEST_KEYS: [&str; 4] = [
    "COMPOSE_PROJECT_NAME",
    "ML_SETTINGS_FILE",
    "ML_NETWORK",
    "RUSTUP_TOOLCHAIN",
];

const RUSTUP_CANONICAL_TOOLCHAIN_1_92_0: &str = "1.92.0-x86_64-unknown-linux-gnu";

const SERVICES: [&str; 8] = [
    "db_server",
    "db_lockbox",
    "vault",
    "vault-init",
    "lockbox",
    "inquisition",
    "token-server-v2",
    "mercury-server",
];

macro_rules! ref_getters {
    ($( $name:ident: $field:ident => $kind:ty ),+ $(,)?) => {
        $(pub fn $name(&self) -> &$kind { &self.$field })+
    };
}

macro_rules! port_getters {
    ($( $name:ident: $field:ident ),+ $(,)?) => {
        $(pub fn $name(&self) -> u16 { self.$field })+
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackConfig {
    project: String,
    repo_root: PathBuf,
    token_compose_file: PathBuf,
    lockbox_compose_file: PathBuf,
    mercury_url: String,
    lockbox_url: String,
    core_rpc_url: String,
    mercury_database_url: String,
    lockbox_database_url: String,
    wallet_name: String,
    wallet_db: PathBuf,
    mercury_image: String,
    token_image: String,
    lockbox_image: String,
    lockbox_rng_image: String,
    core_rpc_port: u16,
    core_p2p_port: u16,
    vault_port: u16,
    lockbox_port: u16,
    token_port: u16,
    mercury_port: u16,
    lockbox_db_port: u16,
    mercury_db_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeFile {
    TokenServers,
    Lockbox,
}

pub fn current() -> &'static StackConfig {
    static CONFIG: OnceLock<StackConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        StackConfig::from_process_env()
            .unwrap_or_else(|error| panic!("invalid BIP448 test stack configuration: {error:#}"))
    })
}

impl StackConfig {
    fn from_process_env() -> Result<Self> {
        let mut env = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            let Some(name) = relevant_env_name(&name)? else {
                continue;
            };
            let value = value
                .into_string()
                .map_err(|_| anyhow::anyhow!("environment value for {name} is not UTF-8"))?;
            env.insert(name, value);
        }
        Self::from_env_map(&env)
    }

    pub(crate) fn from_env_map(env: &BTreeMap<String, String>) -> Result<Self> {
        for name in env.keys().filter(|name| name.starts_with("ML_TEST_")) {
            if !MANAGED_KEYS.contains(&name.as_str()) {
                bail!("unknown managed stack variable {name}");
            }
        }

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .context("resolve repository root for BIP448 test stack")?;
        let token_compose_file = repo_root.join("docker-compose-token-servers.yml");
        let lockbox_compose_file = repo_root.join("docker-compose-lockbox.yml");

        let Some(project) = env.get("ML_TEST_PROJECT") else {
            if let Some(name) = env.keys().find(|name| name.starts_with("ML_TEST_")) {
                bail!("{name} requires ML_TEST_PROJECT and a complete managed environment");
            }
            let project = env
                .get("COMPOSE_PROJECT_NAME")
                .map(String::as_str)
                .unwrap_or("mercurylayer");
            validate_project(project)?;
            return Ok(Self {
                project: project.to_owned(),
                repo_root: repo_root.clone(),
                token_compose_file,
                lockbox_compose_file,
                mercury_url: "http://127.0.0.1:8000".into(),
                lockbox_url: "http://127.0.0.1:18080".into(),
                core_rpc_url: "http://127.0.0.1:18443".into(),
                mercury_database_url: "postgres://postgres:postgres@127.0.0.1:5432/mercury".into(),
                lockbox_database_url: "postgres://postgres:postgres@127.0.0.1:5433/enclave".into(),
                wallet_name: "mercury_test".into(),
                wallet_db: repo_root.join("clients/tests/rust/wallet.db"),
                mercury_image: "mercurylayer/mercury-server:bip448-test-local".into(),
                token_image: "mercurylayer/token-server-v2:bip448-test-local".into(),
                lockbox_image: "mercurylayer/lockbox:bip448-test-local".into(),
                lockbox_rng_image: "mercurylayer/lockbox:bip448-test-local-rng-mercurylayer".into(),
                core_rpc_port: 18443,
                core_p2p_port: 18444,
                vault_port: 8200,
                lockbox_port: 18080,
                token_port: 8001,
                mercury_port: 8000,
                lockbox_db_port: 5433,
                mercury_db_port: 5432,
            });
        };

        for name in MANAGED_KEYS.into_iter().chain(REQUIRED_NON_TEST_KEYS) {
            if !env.contains_key(name) {
                bail!("managed stack environment is missing {name}");
            }
        }
        validate_project(project)?;
        if env["COMPOSE_PROJECT_NAME"] != *project {
            bail!("COMPOSE_PROJECT_NAME and ML_TEST_PROJECT must be byte-identical");
        }
        require_value(env, "ML_NETWORK", "regtest")?;
        require_value(env, "RUSTUP_TOOLCHAIN", "1.92.0")?;
        require_value(env, "ML_TEST_WALLET_NAME", "mercury_test")?;

        let core_rpc_port = port(env, "ML_TEST_CORE_RPC_PORT")?;
        let core_p2p_port = port(env, "ML_TEST_CORE_P2P_PORT")?;
        let vault_port = port(env, "ML_TEST_VAULT_PORT")?;
        let lockbox_port = port(env, "ML_TEST_LOCKBOX_PORT")?;
        let token_port = port(env, "ML_TEST_TOKEN_PORT")?;
        let mercury_port = port(env, "ML_TEST_MERCURY_PORT")?;
        let lockbox_db_port = port(env, "ML_TEST_LOCKBOX_DB_PORT")?;
        let mercury_db_port = port(env, "ML_TEST_MERCURY_DB_PORT")?;

        require_value(
            env,
            "ML_TEST_MERCURY_URL",
            &format!("http://127.0.0.1:{mercury_port}"),
        )?;
        require_value(
            env,
            "ML_TEST_LOCKBOX_URL",
            &format!("http://127.0.0.1:{lockbox_port}"),
        )?;
        require_value(
            env,
            "ML_TEST_CORE_RPC_URL",
            &format!("http://127.0.0.1:{core_rpc_port}"),
        )?;
        require_value(
            env,
            "ML_TEST_MERCURY_DATABASE_URL",
            &format!("postgres://postgres:postgres@127.0.0.1:{mercury_db_port}/mercury"),
        )?;
        require_value(
            env,
            "ML_TEST_LOCKBOX_DATABASE_URL",
            &format!("postgres://postgres:postgres@127.0.0.1:{lockbox_db_port}/enclave"),
        )?;

        let run_dir = repo_root.join("target/bip448-runs").join(project);
        require_path(env, "ML_TEST_WALLET_DB", &run_dir.join("wallet.db"))?;
        require_path(env, "ML_SETTINGS_FILE", &run_dir.join("Settings.toml"))?;

        validate_image(
            &env["ML_TEST_MERCURY_IMAGE"],
            "mercurylayer/mercury-server:bip448-test-",
        )?;
        validate_image(
            &env["ML_TEST_TOKEN_IMAGE"],
            "mercurylayer/token-server-v2:bip448-test-",
        )?;
        let lockbox_fingerprint = validate_image(
            &env["ML_TEST_LOCKBOX_IMAGE"],
            "mercurylayer/lockbox:bip448-test-",
        )?;
        require_value(
            env,
            "ML_TEST_LOCKBOX_RNG_IMAGE",
            &format!("mercurylayer/lockbox:bip448-test-{lockbox_fingerprint}-rng-{project}"),
        )?;

        Ok(Self {
            project: project.clone(),
            repo_root,
            token_compose_file,
            lockbox_compose_file,
            mercury_url: env["ML_TEST_MERCURY_URL"].clone(),
            lockbox_url: env["ML_TEST_LOCKBOX_URL"].clone(),
            core_rpc_url: env["ML_TEST_CORE_RPC_URL"].clone(),
            mercury_database_url: env["ML_TEST_MERCURY_DATABASE_URL"].clone(),
            lockbox_database_url: env["ML_TEST_LOCKBOX_DATABASE_URL"].clone(),
            wallet_name: env["ML_TEST_WALLET_NAME"].clone(),
            wallet_db: PathBuf::from(&env["ML_TEST_WALLET_DB"]),
            mercury_image: env["ML_TEST_MERCURY_IMAGE"].clone(),
            token_image: env["ML_TEST_TOKEN_IMAGE"].clone(),
            lockbox_image: env["ML_TEST_LOCKBOX_IMAGE"].clone(),
            lockbox_rng_image: env["ML_TEST_LOCKBOX_RNG_IMAGE"].clone(),
            core_rpc_port,
            core_p2p_port,
            vault_port,
            lockbox_port,
            token_port,
            mercury_port,
            lockbox_db_port,
            mercury_db_port,
        })
    }

    ref_getters! {
        project: project => str,
        repo_root: repo_root => Path,
        token_compose_file: token_compose_file => Path,
        lockbox_compose_file: lockbox_compose_file => Path,
        mercury_url: mercury_url => str,
        lockbox_url: lockbox_url => str,
        core_rpc_url: core_rpc_url => str,
        mercury_database_url: mercury_database_url => str,
        lockbox_database_url: lockbox_database_url => str,
        wallet_name: wallet_name => str,
        wallet_db: wallet_db => Path,
        mercury_image: mercury_image => str,
        token_image: token_image => str,
        lockbox_image: lockbox_image => str,
        lockbox_rng_image: lockbox_rng_image => str,
    }
    port_getters! {
        core_rpc_port: core_rpc_port,
        core_p2p_port: core_p2p_port,
        vault_port: vault_port,
        lockbox_port: lockbox_port,
        token_port: token_port,
        mercury_port: mercury_port,
        lockbox_db_port: lockbox_db_port,
        mercury_db_port: mercury_db_port,
    }

    pub fn service_container_id(&self, service: &str) -> Result<String> {
        if !SERVICES.contains(&service) {
            bail!("unknown BIP448 Compose service {service}");
        }
        let project_filter = format!("label=com.docker.compose.project={}", self.project);
        let service_filter = format!("label=com.docker.compose.service={service}");
        let output = Command::new("docker")
            .args([
                "ps",
                "-q",
                "--filter",
                &project_filter,
                "--filter",
                &service_filter,
                "--filter",
                "status=running",
            ])
            .output()
            .context("look up BIP448 Compose service by labels")?;
        if !output.status.success() {
            bail!("Docker service lookup failed with status {}", output.status);
        }
        let stdout = String::from_utf8(output.stdout)
            .context("Docker service lookup returned non-UTF-8 output")?;
        let ids = stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        match ids.as_slice() {
            [id] => Ok((*id).to_owned()),
            [] => bail!(
                "expected one running {service} container for project {}, found zero",
                self.project
            ),
            _ => bail!(
                "expected one running {service} container for project {}, found {}",
                self.project,
                ids.len()
            ),
        }
    }

    pub fn compose_command(&self, file: ComposeFile, args: &[&str]) -> Command {
        let compose_file = match file {
            ComposeFile::TokenServers => &self.token_compose_file,
            ComposeFile::Lockbox => &self.lockbox_compose_file,
        };
        let mut command = Command::new("docker");
        command
            .current_dir(&self.repo_root)
            .arg("compose")
            .arg("-p")
            .arg(&self.project)
            .arg("-f")
            .arg(compose_file)
            .args(args)
            .env("ML_TEST_CORE_RPC_PORT", self.core_rpc_port.to_string())
            .env("ML_TEST_CORE_P2P_PORT", self.core_p2p_port.to_string())
            .env("ML_TEST_VAULT_PORT", self.vault_port.to_string())
            .env("ML_TEST_LOCKBOX_PORT", self.lockbox_port.to_string())
            .env("ML_TEST_TOKEN_PORT", self.token_port.to_string())
            .env("ML_TEST_MERCURY_PORT", self.mercury_port.to_string())
            .env("ML_TEST_LOCKBOX_DB_PORT", self.lockbox_db_port.to_string())
            .env("ML_TEST_MERCURY_DB_PORT", self.mercury_db_port.to_string())
            .env("ML_TEST_MERCURY_IMAGE", &self.mercury_image)
            .env("ML_TEST_TOKEN_IMAGE", &self.token_image)
            .env("ML_TEST_LOCKBOX_IMAGE", &self.lockbox_image)
            .env("ML_TEST_LOCKBOX_RNG_IMAGE", &self.lockbox_rng_image);
        command
    }

    pub fn wallet_artifact_paths(&self) -> [PathBuf; 3] {
        [
            self.wallet_db.clone(),
            append_suffix(&self.wallet_db, "-wal"),
            append_suffix(&self.wallet_db, "-shm"),
        ]
    }
}

fn relevant_env_name(name: &OsStr) -> Result<Option<String>> {
    let Some(name) = name.to_str() else {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let bytes = name.as_bytes();
            if bytes.starts_with(b"ML_TEST_")
                || [
                    b"COMPOSE_PROJECT_NAME".as_slice(),
                    b"ML_SETTINGS_FILE".as_slice(),
                    b"ML_NETWORK".as_slice(),
                    b"RUSTUP_TOOLCHAIN".as_slice(),
                ]
                .contains(&bytes)
            {
                bail!("relevant BIP448 stack environment name is not UTF-8");
            }
        }
        return Ok(None);
    };
    if name.starts_with("ML_TEST_")
        || [
            "COMPOSE_PROJECT_NAME",
            "ML_SETTINGS_FILE",
            "ML_NETWORK",
            "RUSTUP_TOOLCHAIN",
        ]
        .contains(&name)
    {
        Ok(Some(name.to_owned()))
    } else {
        Ok(None)
    }
}

fn validate_project(project: &str) -> Result<()> {
    let bytes = project.as_bytes();
    if !(1..=63).contains(&bytes.len())
        || (!bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
    {
        bail!("invalid Compose project {project:?}; expected ^[a-z0-9][a-z0-9_-]{{0,62}}$");
    }
    Ok(())
}

fn require_value(env: &BTreeMap<String, String>, name: &str, expected: &str) -> Result<()> {
    let actual = env.get(name).map(String::as_str);
    if actual != Some(expected)
        && !(name == "RUSTUP_TOOLCHAIN" && actual == Some(RUSTUP_CANONICAL_TOOLCHAIN_1_92_0))
    {
        bail!("{name} must equal {expected:?}");
    }
    Ok(())
}

fn require_path(env: &BTreeMap<String, String>, name: &str, expected: &Path) -> Result<()> {
    if env.get(name).map(PathBuf::from).as_deref() != Some(expected) {
        bail!(
            "{name} must equal the exact absolute path {}",
            expected.display()
        );
    }
    Ok(())
}

fn port(env: &BTreeMap<String, String>, name: &str) -> Result<u16> {
    env[name]
        .parse::<u16>()
        .with_context(|| format!("{name} must be a valid u16 port"))
}

fn validate_image<'a>(value: &'a str, prefix: &str) -> Result<&'a str> {
    let Some(fingerprint) = value.strip_prefix(prefix) else {
        bail!("image {value:?} must start with {prefix:?}");
    };
    if fingerprint.len() != 16
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("image {value:?} must end in a 16-character lowercase hex fingerprint");
    }
    Ok(fingerprint)
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    value.into()
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;
    fn managed(project: &str) -> BTreeMap<String, String> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
        let run = root.join("target/bip448-runs").join(project);
        BTreeMap::from([
            ("COMPOSE_PROJECT_NAME".into(), project.into()),
            ("ML_TEST_PROJECT".into(), project.into()),
            ("ML_TEST_MERCURY_URL".into(), "http://127.0.0.1:23000".into()),
            ("ML_TEST_LOCKBOX_URL".into(), "http://127.0.0.1:23002".into()),
            ("ML_TEST_CORE_RPC_URL".into(), "http://127.0.0.1:23005".into()),
            ("ML_TEST_MERCURY_DATABASE_URL".into(), "postgres://postgres:postgres@127.0.0.1:23003/mercury".into()),
            ("ML_TEST_LOCKBOX_DATABASE_URL".into(), "postgres://postgres:postgres@127.0.0.1:23004/enclave".into()),
            ("ML_TEST_WALLET_NAME".into(), "mercury_test".into()),
            ("ML_TEST_WALLET_DB".into(), run.join("wallet.db").display().to_string()),
            ("ML_TEST_CORE_RPC_PORT".into(), "23005".into()),
            ("ML_TEST_CORE_P2P_PORT".into(), "23006".into()),
            ("ML_TEST_VAULT_PORT".into(), "23007".into()),
            ("ML_TEST_LOCKBOX_PORT".into(), "23002".into()),
            ("ML_TEST_TOKEN_PORT".into(), "23001".into()),
            ("ML_TEST_MERCURY_PORT".into(), "23000".into()),
            ("ML_TEST_LOCKBOX_DB_PORT".into(), "23004".into()),
            ("ML_TEST_MERCURY_DB_PORT".into(), "23003".into()),
            ("ML_TEST_MERCURY_IMAGE".into(), "mercurylayer/mercury-server:bip448-test-0123456789abcdef".into()),
            ("ML_TEST_TOKEN_IMAGE".into(), "mercurylayer/token-server-v2:bip448-test-1111111111111111".into()),
            ("ML_TEST_LOCKBOX_IMAGE".into(), "mercurylayer/lockbox:bip448-test-abcdef0123456789".into()),
            ("ML_TEST_LOCKBOX_RNG_IMAGE".into(), format!("mercurylayer/lockbox:bip448-test-abcdef0123456789-rng-{project}")),
            ("ML_SETTINGS_FILE".into(), run.join("Settings.toml").display().to_string()),
            ("ML_NETWORK".into(), "regtest".into()),
            ("RUSTUP_TOOLCHAIN".into(), "1.92.0".into()),
        ])
    }
    #[test]
    fn unmanaged_defaults_are_exact() {
        let c = StackConfig::from_env_map(&BTreeMap::new()).unwrap();
        assert_eq!((c.project(), c.mercury_url(), c.lockbox_url(), c.core_rpc_url()), ("mercurylayer", "http://127.0.0.1:8000", "http://127.0.0.1:18080", "http://127.0.0.1:18443"));
        assert_eq!((c.mercury_database_url(), c.lockbox_database_url()), ("postgres://postgres:postgres@127.0.0.1:5432/mercury", "postgres://postgres:postgres@127.0.0.1:5433/enclave"));
        assert_eq!(c.wallet_name(), "mercury_test");
        assert_eq!(c.wallet_db(), c.repo_root().join("clients/tests/rust/wallet.db"));
        assert_eq!((c.mercury_port(), c.token_port(), c.lockbox_port(), c.mercury_db_port(), c.lockbox_db_port()), (8000, 8001, 18080, 5432, 5433));
        assert_eq!((c.core_rpc_port(), c.core_p2p_port(), c.vault_port()), (18443, 18444, 8200));
        assert_eq!((c.mercury_image(), c.token_image(), c.lockbox_image(), c.lockbox_rng_image()), ("mercurylayer/mercury-server:bip448-test-local", "mercurylayer/token-server-v2:bip448-test-local", "mercurylayer/lockbox:bip448-test-local", "mercurylayer/lockbox:bip448-test-local-rng-mercurylayer"));
        assert!(c.token_compose_file().is_absolute() && c.lockbox_compose_file().is_absolute());
    }
    #[test]
    fn unmanaged_project_override_preserves_every_default() {
        let mut expected = StackConfig::from_env_map(&BTreeMap::new()).unwrap();
        expected.project = "manual_1".into();
        let env = BTreeMap::from([("COMPOSE_PROJECT_NAME".into(), "manual_1".into())]);
        assert_eq!(StackConfig::from_env_map(&env).unwrap(), expected);
    }
    #[test]
    fn complete_managed_values_round_trip_to_getters() {
        let env = managed("roundtrip");
        let c = StackConfig::from_env_map(&env).unwrap();
        assert_eq!((c.project(), c.mercury_url(), c.lockbox_url(), c.core_rpc_url()), ("roundtrip", env["ML_TEST_MERCURY_URL"].as_str(), env["ML_TEST_LOCKBOX_URL"].as_str(), env["ML_TEST_CORE_RPC_URL"].as_str()));
        assert_eq!((c.mercury_database_url(), c.lockbox_database_url(), c.wallet_name()), (env["ML_TEST_MERCURY_DATABASE_URL"].as_str(), env["ML_TEST_LOCKBOX_DATABASE_URL"].as_str(), env["ML_TEST_WALLET_NAME"].as_str()));
        assert_eq!(c.wallet_db(), Path::new(&env["ML_TEST_WALLET_DB"]));
        assert_eq!((c.mercury_image(), c.token_image(), c.lockbox_image(), c.lockbox_rng_image()), (env["ML_TEST_MERCURY_IMAGE"].as_str(), env["ML_TEST_TOKEN_IMAGE"].as_str(), env["ML_TEST_LOCKBOX_IMAGE"].as_str(), env["ML_TEST_LOCKBOX_RNG_IMAGE"].as_str()));
        assert_eq!((c.mercury_port(), c.token_port(), c.lockbox_port(), c.mercury_db_port(), c.lockbox_db_port()), (23000, 23001, 23002, 23003, 23004));
        assert_eq!((c.core_rpc_port(), c.core_p2p_port(), c.vault_port()), (23005, 23006, 23007));
        assert_eq!(c.token_compose_file(), c.repo_root().join("docker-compose-token-servers.yml"));
        assert_eq!(c.lockbox_compose_file(), c.repo_root().join("docker-compose-lockbox.yml"));
    }
    #[test]
    fn managed_rustup_toolchain_is_exactly_version_1_92_0() {
        let mut canonical = managed("canonical_toolchain");
        canonical.insert("RUSTUP_TOOLCHAIN".into(), RUSTUP_CANONICAL_TOOLCHAIN_1_92_0.into());
        assert!(StackConfig::from_env_map(&canonical).is_ok());
        for rejected in [
            "stable-x86_64-unknown-linux-gnu",
            "nightly-x86_64-unknown-linux-gnu",
            "1.93.1-x86_64-unknown-linux-gnu",
            "1.92.0-aarch64-unknown-linux-gnu",
        ] {
            let mut env = managed("wrong_toolchain");
            env.insert("RUSTUP_TOOLCHAIN".into(), rejected.into());
            assert!(
                StackConfig::from_env_map(&env).is_err(),
                "accepted {rejected:?}"
            );
        }
    }
    #[test]
    fn project_validation_is_exact() {
        for project in ["a".to_owned(), "a".repeat(63)] {
            assert!(StackConfig::from_env_map(&managed(&project)).is_ok());
        }
        for project in [
            "",
            "UPPER",
            "has.dot",
            "has/slash",
            "has space",
            "has$meta",
            &"a".repeat(64),
        ] {
            let env = BTreeMap::from([("COMPOSE_PROJECT_NAME".into(), project.into())]);
            assert!(StackConfig::from_env_map(&env).is_err(), "accepted {project:?}");
        }
    }
    #[test]
    fn partial_or_mismatched_managed_environment_is_rejected() {
        let partial = BTreeMap::from([("ML_TEST_MERCURY_URL".into(), "http://127.0.0.1:23000".into(),)]);
        assert!(StackConfig::from_env_map(&partial).is_err());
        let unknown = BTreeMap::from([("ML_TEST_UNKNOWN".into(), "value".into())]);
        assert!(StackConfig::from_env_map(&unknown).is_err());
        for missing in MANAGED_KEYS.into_iter().chain(REQUIRED_NON_TEST_KEYS) {
            let mut env = managed("partial");
            env.remove(missing);
            assert!(StackConfig::from_env_map(&env).is_err(), "accepted missing {missing}");
        }
        let mut env = managed("one");
        env.insert("COMPOSE_PROJECT_NAME".into(), "two".into());
        assert!(StackConfig::from_env_map(&env).is_err());
    }
    #[test]
    fn invalid_ports_endpoints_and_database_urls_are_rejected() {
        let mut port = managed("ports");
        port.insert("ML_TEST_MERCURY_PORT".into(), "65536".into());
        assert!(StackConfig::from_env_map(&port).is_err());
        for (key, value) in [
            ("ML_TEST_MERCURY_URL", "http://127.0.0.1:23001"),
            ("ML_TEST_CORE_RPC_URL", "http://localhost:23005"),
            (
                "ML_TEST_MERCURY_DATABASE_URL",
                "postgres://postgres:postgres@127.0.0.1:23004/mercury",
            ),
            (
                "ML_TEST_LOCKBOX_DATABASE_URL",
                "postgres://postgres:postgres@127.0.0.1:23004/wrong",
            ),
        ] {
            let mut env = managed("endpoint");
            env.insert(key.into(), value.into());
            assert!(StackConfig::from_env_map(&env).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn invalid_images_and_run_paths_are_rejected() {
        for (key, value) in [
            (
                "ML_TEST_MERCURY_IMAGE",
                "wrong/mercury:bip448-test-0123456789abcdef",
            ),
            (
                "ML_TEST_TOKEN_IMAGE",
                "mercurylayer/token-server-v2:bip448-test-ABCDEF0123456789",
            ),
            (
                "ML_TEST_LOCKBOX_IMAGE",
                "mercurylayer/lockbox:bip448-test-short",
            ),
            (
                "ML_TEST_LOCKBOX_RNG_IMAGE",
                "mercurylayer/lockbox:bip448-test-1111111111111111-rng-images",
            ),
            (
                "ML_TEST_LOCKBOX_RNG_IMAGE",
                "mercurylayer/lockbox:bip448-test-abcdef0123456789-rng-other",
            ),
        ] {
            let mut env = managed("images");
            env.insert(key.into(), value.into());
            assert!(StackConfig::from_env_map(&env).is_err(), "accepted {key}");
        }
        for key in ["ML_TEST_WALLET_DB", "ML_SETTINGS_FILE"] {
            let mut env = managed("paths");
            env.insert(key.into(), "/tmp/not-the-run-directory".into());
            assert!(StackConfig::from_env_map(&env).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn artifact_paths_are_unambiguous() {
        let c = StackConfig::from_env_map(&managed("artifacts")).unwrap();
        let db = c.repo_root().join("target/bip448-runs/artifacts/wallet.db");
        assert_eq!(
            c.wallet_artifact_paths(),
            [
                db.clone(),
                append_suffix(&db, "-wal"),
                append_suffix(&db, "-shm")
            ]
        );
    }
    #[test]
    fn compose_command_is_explicit_and_ordered() {
        let c = StackConfig::from_env_map(&managed("command")).unwrap();
        let command = c.compose_command(ComposeFile::TokenServers, &["up", "-d", "lockbox"]);
        let args = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "compose",
                "-p",
                "command",
                "-f",
                c.token_compose_file().to_str().unwrap(),
                "up",
                "-d",
                "lockbox"
            ]
        );
        assert_eq!(command.get_program(), "docker");
        assert_eq!(command.get_current_dir(), Some(c.repo_root()));
        let explicit = command
            .get_envs()
            .filter_map(|(key, value)| {
                value.map(|value| (key.to_str().unwrap(), value.to_str().unwrap()))
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(explicit.len(), 12);
        assert_eq!(explicit["ML_TEST_MERCURY_PORT"], "23000");
        assert_eq!(explicit["ML_TEST_LOCKBOX_DB_PORT"], "23004");
        assert_eq!((explicit["ML_TEST_MERCURY_IMAGE"], explicit["ML_TEST_TOKEN_IMAGE"], explicit["ML_TEST_LOCKBOX_IMAGE"]), (c.mercury_image(), c.token_image(), c.lockbox_image()));
        assert_eq!(explicit["ML_TEST_LOCKBOX_RNG_IMAGE"], c.lockbox_rng_image());
    }
    #[test]
    fn unknown_service_is_rejected_before_docker() {
        let c = StackConfig::from_env_map(&BTreeMap::new()).unwrap();
        assert!(c
            .service_container_id("not-a-service")
            .unwrap_err()
            .to_string()
            .contains("unknown BIP448 Compose service"));
    }
}
