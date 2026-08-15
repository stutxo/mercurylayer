use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};

use super::super::argv::{ArgvCommand, CommandOutput, CommandRunner};
use super::super::model::StackMetadata;
use super::contract::ExpectedImages;

pub(super) fn resolve_unrecorded_image_ids(
    repo_root: &Path,
    expected: &mut ExpectedImages,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    let mut resolved: BTreeMap<String, String> = BTreeMap::new();
    for image in expected.values_mut() {
        if image.image_id.is_none() {
            let id = match resolved.get(&image.tag) {
                Some(id) => id.clone(),
                None => {
                    let id = image_id(repo_root, &image.tag, runner)?
                        .with_context(|| format!("required image tag {} is absent", image.tag))?;
                    resolved.insert(image.tag.clone(), id.clone());
                    id
                }
            };
            image.image_id = Some(id);
        }
    }
    Ok(())
}

fn image_id(
    repo_root: &Path,
    tag: &str,
    runner: &mut impl CommandRunner,
) -> Result<Option<String>> {
    let command = docker(repo_root)
        .args(["image", "inspect", "--format", "{{.Id}}"])
        .arg(tag);
    let output = runner.run(&command)?;
    if !output.success {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.code == Some(1) && stderr.to_ascii_lowercase().contains("no such image") {
            return Ok(None);
        }
        return command_failure(&command, &output);
    }
    let value = one_line(&output.stdout, "Docker image inspect")?;
    validate_image_id(&value)?;
    Ok(Some(value))
}

pub(super) fn compose_command(
    repo_root: &Path,
    metadata: &StackMetadata,
    environment: &BTreeMap<String, String>,
    args: &[&str],
) -> Result<ArgvCommand> {
    let mut command = docker(repo_root)
        .arg("compose")
        .arg("-p")
        .arg(metadata.project().as_str())
        .arg("-f")
        .arg(repo_root.join("docker-compose-token-servers.yml"))
        .args(args.iter().copied());
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
        command = command.env(
            key,
            environment
                .get(key)
                .with_context(|| format!("managed Compose environment is missing {key}"))?,
        );
    }
    Ok(command)
}

pub(super) fn run_checked(
    runner: &mut impl CommandRunner,
    command: ArgvCommand,
) -> Result<CommandOutput> {
    let output = runner.run(&command)?;
    if output.success {
        Ok(output)
    } else {
        command_failure(&command, &output)
    }
}

pub(super) fn require_volume_absent(
    repo_root: &Path,
    volume: &str,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    let command = docker(repo_root).args(["volume", "inspect"]).arg(volume);
    let output = runner.run(&command)?;
    if output.success {
        bail!("recorded anonymous Vault volume {volume} still exists after Compose down");
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if output.code == Some(1) && stderr.contains("no such volume") {
        return Ok(());
    }
    super::super::argv::record_failure(&command, &output);
    bail!(
        "Docker volume absence inspection failed with status {:?}: {}",
        output.code,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

pub(super) fn docker(repo_root: &Path) -> ArgvCommand {
    ArgvCommand::new("docker", repo_root)
}

fn one_line(bytes: &[u8], label: &str) -> Result<String> {
    let value =
        String::from_utf8(bytes.to_vec()).with_context(|| format!("{label} is not UTF-8"))?;
    let value = value.trim();
    ensure!(
        !value.is_empty() && !value.contains(char::is_whitespace),
        "{label} returned multiple or malformed values"
    );
    Ok(value.to_owned())
}

fn validate_image_id(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("Docker image ID lacks sha256: prefix")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Docker image ID must be a full lowercase hexadecimal digest"
    );
    Ok(())
}

fn command_failure<T>(command: &ArgvCommand, output: &CommandOutput) -> Result<T> {
    super::super::argv::record_failure(command, output);
    bail!(
        "argv command {command:?} failed with status {:?}: stdout={} stderr={}",
        output.code,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}
