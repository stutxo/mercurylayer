use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};

use super::super::model::{BuildFingerprints, BuildSource, ComposeHashes, INQUISITION_IMAGE};
use super::inputs::{
    component_records, directory_metadata, read_regular, regular_metadata, InputComponent,
    InputKind, InputRecord,
};
use super::{run_checked, ArgvCommand, CommandRunner, INQUISITION_BUILD_ARG, INQUISITION_COMMIT};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BuildSnapshot {
    pub(super) source: BuildSource,
    pub(super) fingerprints: BuildFingerprints,
}

pub(super) fn snapshot(repo_root: &Path, runner: &mut impl CommandRunner) -> Result<BuildSnapshot> {
    validate_contract(repo_root)?;
    let mercury = hash_component(repo_root, InputComponent::Mercury)?;
    let token = hash_component(repo_root, InputComponent::Token)?;
    let lockbox = hash_component(repo_root, InputComponent::Lockbox)?;
    let inquisition = hash_component(repo_root, InputComponent::Inquisition)?;
    let token_compose = hash_paths(
        repo_root,
        &[PathBuf::from("docker-compose-token-servers.yml")],
        b"bip448-compose-token-servers-v1",
        &[],
    )?;
    let lockbox_compose = hash_paths(
        repo_root,
        &[PathBuf::from("docker-compose-lockbox.yml")],
        b"bip448-compose-lockbox-v1",
        &[],
    )?;

    let head_output = run_checked(
        runner,
        ArgvCommand::new("git", repo_root).args(["rev-parse", "--verify", "HEAD^{commit}"]),
    )?;
    let head = String::from_utf8(head_output.stdout)
        .context("git rev-parse returned non-UTF-8 output")?
        .trim()
        .to_owned();
    ensure!(
        head.len() == 40
            && head
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "git rev-parse did not return one lowercase full commit ID"
    );
    let status = run_checked(
        runner,
        ArgvCommand::new("git", repo_root).args([
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=no",
        ]),
    )?;
    let status_sha256 = hash_bytes(b"bip448-git-status-v1", &status.stdout);

    Ok(BuildSnapshot {
        source: BuildSource::new(
            head,
            status_sha256,
            ComposeHashes::new(token_compose, lockbox_compose),
        ),
        fingerprints: BuildFingerprints::new(mercury, token, lockbox, inquisition),
    })
}

pub(super) fn validate_contract(repo_root: &Path) -> Result<()> {
    let root_ignore = repo_root.join(".dockerignore");
    match fs::symlink_metadata(&root_ignore) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspect forbidden root Docker ignore {}", root_ignore.display())
            })
        }
        Ok(_) => bail!(
            "repository-root .dockerignore must be absent because Mercury and token use root build contexts"
        ),
    }

    let token_compose = read_regular(repo_root, Path::new("docker-compose-token-servers.yml"))?;
    let token_compose =
        String::from_utf8(token_compose).context("token-servers Compose file is not UTF-8")?;
    ensure!(
        token_compose.contains(&format!("BITCOIN_INQUISITION_COMMIT: {INQUISITION_COMMIT}"))
            && token_compose.contains(&format!("image: {INQUISITION_IMAGE}")),
        "Inquisition Compose build commit or pinned image tag changed"
    );
    let lockbox_compose = read_regular(repo_root, Path::new("docker-compose-lockbox.yml"))?;
    let lockbox_compose =
        String::from_utf8(lockbox_compose).context("lockbox Compose file is not UTF-8")?;
    ensure!(
        lockbox_compose.contains("LOCKBOX_ENABLE_TEST_RNG: ${LOCKBOX_ENABLE_TEST_RNG:-OFF}"),
        "lockbox Compose build-argument contract changed"
    );
    Ok(())
}

pub(super) fn hash_component(repo_root: &Path, component: InputComponent) -> Result<String> {
    let records = component_records(repo_root, component)?;
    let (domain, identities): (&[u8], Vec<(&[u8], &[u8])>) = match component {
        InputComponent::Mercury => (b"bip448-mercury-build-v1", Vec::new()),
        InputComponent::Token => (b"bip448-token-build-v1", Vec::new()),
        InputComponent::Lockbox => (b"bip448-lockbox-build-v1", Vec::new()),
        InputComponent::Inquisition => (
            b"bip448-inquisition-build-v1",
            vec![(
                INQUISITION_BUILD_ARG.as_bytes(),
                INQUISITION_COMMIT.as_bytes(),
            )],
        ),
    };
    hash_records(repo_root, &records, domain, &identities)
}

pub(super) fn hash_paths(
    repo_root: &Path,
    paths: &[PathBuf],
    domain: &[u8],
    identities: &[(&[u8], &[u8])],
) -> Result<String> {
    let records = paths
        .iter()
        .cloned()
        .map(|relative| InputRecord {
            relative,
            kind: InputKind::File,
        })
        .collect::<Vec<_>>();
    hash_records(repo_root, &records, domain, identities)
}

fn hash_records(
    repo_root: &Path,
    records: &[InputRecord],
    domain: &[u8],
    identities: &[(&[u8], &[u8])],
) -> Result<String> {
    let mut ordered = records.to_vec();
    ordered.sort_by(|left, right| {
        left.relative
            .as_os_str()
            .as_bytes()
            .cmp(right.relative.as_os_str().as_bytes())
            .then_with(|| left.kind.cmp(&right.kind))
    });
    ensure!(
        ordered
            .windows(2)
            .all(|pair| pair[0].relative != pair[1].relative),
        "hash input record set contains a duplicate path"
    );
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", domain);
    for record in ordered {
        match record.kind {
            InputKind::File => {
                let before = regular_metadata(repo_root, &record.relative)?;
                let bytes = read_regular(repo_root, &record.relative)?;
                hasher.update(b"file\0");
                hash_field(&mut hasher, b"path", record.relative.as_os_str().as_bytes());
                hash_field(
                    &mut hasher,
                    b"mode",
                    &(before.permissions().mode() & 0o7777).to_be_bytes(),
                );
                hash_field(&mut hasher, b"content", &bytes);
            }
            InputKind::Directory => {
                let metadata = directory_metadata(repo_root, &record.relative)?;
                hasher.update(b"directory\0");
                hash_field(&mut hasher, b"path", record.relative.as_os_str().as_bytes());
                hash_field(
                    &mut hasher,
                    b"mode",
                    &(metadata.permissions().mode() & 0o7777).to_be_bytes(),
                );
            }
        }
    }
    for (name, value) in identities {
        hasher.update(b"identity\0");
        hash_field(&mut hasher, b"name", name);
        hash_field(&mut hasher, b"value", value);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", domain);
    hash_field(&mut hasher, b"content", bytes);
    hex::encode(hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, label: &[u8], value: &[u8]) {
    hasher.update((label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
