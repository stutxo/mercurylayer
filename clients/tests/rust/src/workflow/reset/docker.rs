use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;

use super::super::argv::{ArgvCommand, CommandOutput, CommandRunner};
use super::super::model::Project;

const PROJECT_LABEL: &str = "com.docker.compose.project";
const SERVICE_LABEL: &str = "com.docker.compose.service";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ResourceSets {
    pub(super) containers: BTreeSet<String>,
    pub(super) networks: BTreeSet<String>,
    pub(super) volumes: BTreeSet<String>,
}

impl ResourceSets {
    pub(super) fn is_empty(&self) -> bool {
        self.containers.is_empty() && self.networks.is_empty() && self.volumes.is_empty()
    }

    fn without(&self, removed: &Self) -> Result<Self> {
        ensure!(
            removed.containers.is_subset(&self.containers)
                && removed.networks.is_subset(&self.networks)
                && removed.volumes.is_subset(&self.volumes),
            "project resources were not a subset of the global Docker snapshot"
        );
        Ok(Self {
            containers: self
                .containers
                .difference(&removed.containers)
                .cloned()
                .collect(),
            networks: self
                .networks
                .difference(&removed.networks)
                .cloned()
                .collect(),
            volumes: self.volumes.difference(&removed.volumes).cloned().collect(),
        })
    }
}

pub(super) struct DockerPlan {
    global_before: ResourceSets,
    project_before: ResourceSets,
}

impl DockerPlan {
    pub(super) fn capture(
        repo_root: &Path,
        project: &Project,
        runner: &mut impl CommandRunner,
    ) -> Result<Self> {
        let global_before = global_resources(repo_root, runner)?;
        let project_before = project_resources(repo_root, project, runner)?;
        Ok(Self {
            global_before,
            project_before,
        })
    }

    pub(super) fn project_resources_exist(&self) -> bool {
        !self.project_before.is_empty()
    }

    pub(super) fn verify_teardown(
        &self,
        repo_root: &Path,
        project: &Project,
        runner: &mut impl CommandRunner,
    ) -> Result<()> {
        let project_after = project_resources(repo_root, project, runner)?;
        ensure!(
            project_after.is_empty(),
            "reset teardown left exact project Docker resources: {project_after:?}"
        );
        let global_after = global_resources(repo_root, runner)?;
        let expected = self.global_before.without(&self.project_before)?;
        ensure!(
            global_after == expected,
            "unrelated global Docker container/network/volume identities changed during reset"
        );
        Ok(())
    }
}

fn global_resources(repo_root: &Path, runner: &mut impl CommandRunner) -> Result<ResourceSets> {
    Ok(ResourceSets {
        containers: listed(
            repo_root,
            runner,
            &["ps", "--all", "--quiet", "--no-trunc"],
            IdentityKind::Digest,
        )?,
        networks: listed(
            repo_root,
            runner,
            &["network", "ls", "--quiet", "--no-trunc"],
            IdentityKind::Digest,
        )?,
        volumes: listed(
            repo_root,
            runner,
            &["volume", "ls", "--quiet"],
            IdentityKind::Name,
        )?,
    })
}

fn project_resources(
    repo_root: &Path,
    project: &Project,
    runner: &mut impl CommandRunner,
) -> Result<ResourceSets> {
    let filter = format!("label={PROJECT_LABEL}={project}");
    let containers = listed_owned(
        repo_root,
        runner,
        &["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter],
        IdentityKind::Digest,
    )?;
    let networks = listed_owned(
        repo_root,
        runner,
        &[
            "network",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            &filter,
        ],
        IdentityKind::Digest,
    )?;
    let declared = listed_owned(
        repo_root,
        runner,
        &["volume", "ls", "--quiet", "--filter", &filter],
        IdentityKind::Name,
    )?;

    let mut anonymous = BTreeSet::new();
    if !containers.is_empty() {
        let values = inspect_many(repo_root, "container", &containers, runner)?;
        for value in values {
            let id = string_field(&value, &["Id"], "container ID")?;
            ensure!(
                containers.contains(id),
                "Docker inspected an unrequested container"
            );
            validate_labels(&value, project, "Config", true)?;
            let service = string_field(
                value
                    .pointer("/Config/Labels")
                    .context("container labels are absent")?,
                &[SERVICE_LABEL],
                "Compose service label",
            )?;
            for mount in value
                .get("Mounts")
                .and_then(Value::as_array)
                .context("container mounts are absent")?
            {
                if service == "vault"
                    && mount.get("Type").and_then(Value::as_str) == Some("volume")
                    && matches!(
                        mount.get("Destination").and_then(Value::as_str),
                        Some("/vault/file" | "/vault/logs")
                    )
                {
                    let name = mount
                        .get("Name")
                        .and_then(Value::as_str)
                        .context("anonymous Vault volume name is absent")?;
                    validate_name(name)?;
                    ensure!(
                        anonymous.insert(name.to_owned()),
                        "duplicate anonymous Vault volume identity"
                    );
                }
            }
        }
    }
    validate_labeled_resources(repo_root, "network", &networks, project, runner)?;
    validate_labeled_resources(repo_root, "volume", &declared, project, runner)?;
    if !anonymous.is_empty() {
        let inspected = inspect_many(repo_root, "volume", &anonymous, runner)?;
        ensure!(
            inspected.len() == anonymous.len(),
            "anonymous Vault volume inspection count mismatch"
        );
        for value in inspected {
            let name = string_field(&value, &["Name"], "volume name")?;
            ensure!(
                anonymous.contains(name),
                "Docker inspected an unrequested anonymous volume"
            );
        }
    }
    let mut volumes = declared;
    volumes.extend(anonymous);
    Ok(ResourceSets {
        containers,
        networks,
        volumes,
    })
}

fn validate_labeled_resources(
    repo_root: &Path,
    kind: &str,
    identities: &BTreeSet<String>,
    project: &Project,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    if identities.is_empty() {
        return Ok(());
    }
    let values = inspect_many(repo_root, kind, identities, runner)?;
    ensure!(
        values.len() == identities.len(),
        "Docker {kind} inspection count mismatch"
    );
    for value in values {
        let field = if kind == "network" { "Id" } else { "Name" };
        let identity = string_field(&value, &[field], "Docker resource identity")?;
        ensure!(
            identities.contains(identity),
            "Docker inspected an unrequested {kind}"
        );
        validate_labels(&value, project, "Labels", false)?;
    }
    Ok(())
}

fn validate_labels(value: &Value, project: &Project, field: &str, nested: bool) -> Result<()> {
    let labels = if nested {
        value.get(field).and_then(|config| config.get("Labels"))
    } else {
        value.get(field)
    }
    .and_then(Value::as_object)
    .context("Docker resource labels are absent")?;
    ensure!(
        labels.get(PROJECT_LABEL).and_then(Value::as_str) == Some(project.as_str()),
        "Docker resource project label mismatch"
    );
    Ok(())
}

fn inspect_many(
    repo_root: &Path,
    kind: &str,
    identities: &BTreeSet<String>,
    runner: &mut impl CommandRunner,
) -> Result<Vec<Value>> {
    if identities.is_empty() {
        return Ok(Vec::new());
    }
    let command = docker(repo_root)
        .arg(kind)
        .arg("inspect")
        .args(identities.iter());
    let output = run_checked(runner, command)?;
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse Docker {kind} inspection JSON"))
}

#[derive(Clone, Copy)]
enum IdentityKind {
    Digest,
    Name,
}

fn listed_owned(
    repo_root: &Path,
    runner: &mut impl CommandRunner,
    args: &[&str],
    kind: IdentityKind,
) -> Result<BTreeSet<String>> {
    listed(repo_root, runner, args, kind)
}

fn listed(
    repo_root: &Path,
    runner: &mut impl CommandRunner,
    args: &[&str],
    kind: IdentityKind,
) -> Result<BTreeSet<String>> {
    let output = run_checked(runner, docker(repo_root).args(args.iter().copied()))?;
    let text = String::from_utf8(output.stdout).context("Docker identity list is not UTF-8")?;
    let mut values = BTreeSet::new();
    for line in text.lines() {
        let value = line.trim();
        ensure!(
            !value.is_empty() && !value.contains(char::is_whitespace),
            "Docker returned a malformed resource identity"
        );
        match kind {
            IdentityKind::Digest => validate_digest(value)?,
            IdentityKind::Name => validate_name(value)?,
        }
        ensure!(
            values.insert(value.to_owned()),
            "Docker returned a duplicate resource identity"
        );
    }
    Ok(values)
}

fn string_field<'a>(value: &'a Value, fields: &[&str], label: &str) -> Result<&'a str> {
    let mut value = value;
    for field in fields {
        value = value
            .get(*field)
            .with_context(|| format!("{label} field {field:?} is absent"))?;
    }
    value
        .as_str()
        .with_context(|| format!("{label} is not a string"))
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(is_lower_hex),
        "Docker identity is not a full lowercase hexadecimal digest"
    );
    Ok(())
}

fn validate_name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.') }),
        "Docker resource name is malformed"
    );
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn docker(repo_root: &Path) -> ArgvCommand {
    ArgvCommand::new("docker", repo_root)
}

fn run_checked(runner: &mut impl CommandRunner, command: ArgvCommand) -> Result<CommandOutput> {
    let output = runner.run(&command)?;
    if output.success {
        Ok(output)
    } else {
        command_failure(&command, &output)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_invariance_subtracts_only_exact_owned_resources() {
        let before = ResourceSets {
            containers: BTreeSet::from(["a".into(), "b".into()]),
            networks: BTreeSet::from(["n".into(), "u".into()]),
            volumes: BTreeSet::from(["v".into(), "x".into()]),
        };
        let owned = ResourceSets {
            containers: BTreeSet::from(["a".into()]),
            networks: BTreeSet::from(["n".into()]),
            volumes: BTreeSet::from(["v".into()]),
        };
        assert_eq!(
            before.without(&owned).unwrap(),
            ResourceSets {
                containers: BTreeSet::from(["b".into()]),
                networks: BTreeSet::from(["u".into()]),
                volumes: BTreeSet::from(["x".into()]),
            }
        );
        assert!(before
            .without(&ResourceSets {
                containers: BTreeSet::from(["alien".into()]),
                ..ResourceSets::default()
            })
            .is_err());
    }
}
