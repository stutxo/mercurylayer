use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::super::argv::{ArgvCommand, CommandRunner};
use super::super::model::StackMetadata;
use super::contract::SERVICES;
use super::docker_command::{docker, run_checked};
use super::inspect_types::{ContainerInspect, NetworkInspect, PortBinding, VolumeInspect};
use anyhow::{ensure, Context, Result};

const PROJECT_LABEL: &str = "com.docker.compose.project";
const SERVICE_LABEL: &str = "com.docker.compose.service";
const NETWORK_LABEL: &str = "com.docker.compose.network";
const VOLUME_LABEL: &str = "com.docker.compose.volume";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Observation {
    pub(super) containers: BTreeMap<String, Container>,
    pub(super) networks: Vec<Network>,
    pub(super) declared_volumes: Vec<Volume>,
    pub(super) anonymous_vault_volumes: Vec<Volume>,
}

impl Observation {
    pub(super) fn resources_absent(&self) -> bool {
        self.containers.is_empty()
            && self.networks.is_empty()
            && self.declared_volumes.is_empty()
            && self.anonymous_vault_volumes.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Container {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) service: String,
    pub(super) configured_image: String,
    pub(super) image_id: String,
    pub(super) state: String,
    pub(super) running: bool,
    pub(super) restarting: bool,
    pub(super) dead: bool,
    pub(super) started_at: String,
    pub(super) health: Option<String>,
    pub(super) networks: BTreeMap<String, String>,
    pub(super) mounts: Vec<Mount>,
    pub(super) listeners: BTreeMap<String, Listener>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mount {
    pub(super) kind: String,
    pub(super) name: String,
    pub(super) destination: String,
    pub(super) read_write: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Listener {
    pub(super) host_addresses: Vec<String>,
    pub(super) host_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Network {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) driver: String,
    pub(super) project_label: Option<String>,
    pub(super) network_label: Option<String>,
    pub(super) container_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Volume {
    pub(super) name: String,
    pub(super) driver: String,
    pub(super) project_label: Option<String>,
    pub(super) volume_label: Option<String>,
    pub(super) destination: Option<String>,
}

pub(super) fn observe(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<Observation> {
    let project_filter = format!("label={PROJECT_LABEL}={}", metadata.project());
    let container_ids = listed(
        runner,
        docker(repo_root).args([
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            &project_filter,
        ]),
        IdentifierKind::Digest,
    )?;
    let network_ids = listed(
        runner,
        docker(repo_root).args([
            "network",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            &project_filter,
        ]),
        IdentifierKind::Digest,
    )?;
    let volume_names = listed(
        runner,
        docker(repo_root).args(["volume", "ls", "--quiet", "--filter", &project_filter]),
        IdentifierKind::Name,
    )?;

    let containers = inspect_containers(repo_root, metadata, &container_ids, runner)?;
    let networks = inspect_networks(repo_root, metadata, &network_ids, runner)?;
    let declared_volumes = inspect_volumes(repo_root, &volume_names, runner)?;

    let anonymous = containers
        .get("vault")
        .into_iter()
        .flat_map(|container| container.mounts.iter())
        .filter(|mount| mount.kind == "volume")
        .filter(|mount| mount.destination == "/vault/file" || mount.destination == "/vault/logs")
        .map(|mount| (mount.name.clone(), mount.destination.clone()))
        .collect::<BTreeMap<_, _>>();
    let names = anonymous.keys().cloned().collect::<Vec<_>>();
    let mut anonymous_vault_volumes = inspect_volumes(repo_root, &names, runner)?;
    for volume in &mut anonymous_vault_volumes {
        volume.destination = anonymous.get(&volume.name).cloned();
    }

    Ok(Observation {
        containers,
        networks,
        declared_volumes,
        anonymous_vault_volumes,
    })
}

fn inspect_containers(
    repo_root: &Path,
    metadata: &StackMetadata,
    ids: &[String],
    runner: &mut impl CommandRunner,
) -> Result<BTreeMap<String, Container>> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let command = docker(repo_root)
        .args(["container", "inspect"])
        .args(ids.iter());
    let output = run_checked(runner, command)?;
    let values: Vec<ContainerInspect> =
        serde_json::from_slice(&output.stdout).context("parse Docker container inspection JSON")?;
    ensure!(
        values.len() == ids.len(),
        "Docker container inspection count mismatch"
    );
    let expected_ids = ids.iter().collect::<BTreeSet<_>>();
    let mut containers = BTreeMap::new();
    for value in values {
        validate_digest(&value.id, "container ID")?;
        ensure!(
            expected_ids.contains(&value.id),
            "Docker inspected an unrequested container"
        );
        let labels = value.config.labels.context("container labels are absent")?;
        ensure!(
            labels.get(PROJECT_LABEL).map(String::as_str) == Some(metadata.project().as_str()),
            "container project label mismatch"
        );
        let service = labels
            .get(SERVICE_LABEL)
            .context("container Compose service label is absent")?
            .clone();
        ensure!(
            SERVICES.contains(&service.as_str()),
            "unexpected Compose service {service:?}"
        );
        ensure!(
            !containers.contains_key(&service),
            "duplicate container for service {service}"
        );
        let networks = value
            .network_settings
            .networks
            .into_iter()
            .map(|(name, attachment)| {
                validate_digest(&attachment.network_id, "attached network ID")?;
                Ok((name, attachment.network_id))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mounts = value
            .mounts
            .into_iter()
            .map(|mount| Mount {
                kind: mount.kind,
                name: mount.name,
                destination: mount.destination,
                read_write: mount.read_write,
            })
            .collect();
        containers.insert(
            service.clone(),
            Container {
                id: value.id,
                name: value
                    .name
                    .strip_prefix('/')
                    .unwrap_or(&value.name)
                    .to_owned(),
                service,
                configured_image: value.config.image,
                image_id: value.image,
                state: value.state.status,
                running: value.state.running,
                restarting: value.state.restarting,
                dead: value.state.dead,
                started_at: value.state.started_at,
                health: value.state.health.map(|health| health.status),
                networks,
                mounts,
                listeners: listeners(value.network_settings.ports)?,
            },
        );
    }
    ensure!(
        containers.len() == ids.len(),
        "duplicate inspected container identity"
    );
    Ok(containers)
}

fn inspect_networks(
    repo_root: &Path,
    metadata: &StackMetadata,
    ids: &[String],
    runner: &mut impl CommandRunner,
) -> Result<Vec<Network>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let command = docker(repo_root)
        .args(["network", "inspect"])
        .args(ids.iter());
    let output = run_checked(runner, command)?;
    let values: Vec<NetworkInspect> =
        serde_json::from_slice(&output.stdout).context("parse Docker network inspection JSON")?;
    ensure!(
        values.len() == ids.len(),
        "Docker network inspection count mismatch"
    );
    let mut networks = Vec::new();
    for value in values {
        validate_digest(&value.id, "network ID")?;
        ensure!(
            ids.contains(&value.id),
            "Docker inspected an unrequested network"
        );
        ensure!(
            value.labels.get(PROJECT_LABEL).map(String::as_str)
                == Some(metadata.project().as_str()),
            "network project label mismatch"
        );
        let mut container_ids = value.containers.into_keys().collect::<Vec<_>>();
        for id in &container_ids {
            validate_digest(id, "network container ID")?;
        }
        container_ids.sort();
        networks.push(Network {
            id: value.id,
            name: value.name,
            driver: value.driver,
            project_label: value.labels.get(PROJECT_LABEL).cloned(),
            network_label: value.labels.get(NETWORK_LABEL).cloned(),
            container_ids,
        });
    }
    networks.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(networks)
}

fn inspect_volumes(
    repo_root: &Path,
    names: &[String],
    runner: &mut impl CommandRunner,
) -> Result<Vec<Volume>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let command = docker(repo_root)
        .args(["volume", "inspect"])
        .args(names.iter());
    let output = run_checked(runner, command)?;
    let values: Vec<VolumeInspect> =
        serde_json::from_slice(&output.stdout).context("parse Docker volume inspection JSON")?;
    ensure!(
        values.len() == names.len(),
        "Docker volume inspection count mismatch"
    );
    let mut seen = BTreeSet::new();
    let mut volumes = Vec::new();
    for value in values {
        ensure!(
            names.contains(&value.name),
            "Docker inspected an unrequested volume"
        );
        ensure!(
            seen.insert(value.name.clone()),
            "duplicate volume inspection"
        );
        volumes.push(Volume {
            name: value.name,
            driver: value.driver,
            project_label: value.labels.get(PROJECT_LABEL).cloned(),
            volume_label: value.labels.get(VOLUME_LABEL).cloned(),
            destination: None,
        });
    }
    volumes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(volumes)
}

fn listeners(
    ports: BTreeMap<String, Option<Vec<PortBinding>>>,
) -> Result<BTreeMap<String, Listener>> {
    let mut listeners = BTreeMap::new();
    for (container_port, bindings) in ports {
        let Some(bindings) = bindings else { continue };
        ensure!(
            !bindings.is_empty(),
            "Docker returned an empty listener binding list"
        );
        let mut addresses = BTreeSet::new();
        let mut host_port = None;
        for binding in bindings {
            let port = binding
                .host_port
                .parse::<u16>()
                .context("Docker listener host port is not a u16")?;
            ensure!(port != 0, "Docker listener host port is zero");
            ensure!(
                host_port.is_none() || host_port == Some(port),
                "one container port maps to multiple host ports"
            );
            host_port = Some(port);
            ensure!(
                addresses.insert(binding.host_ip),
                "duplicate Docker listener address"
            );
        }
        listeners.insert(
            container_port,
            Listener {
                host_addresses: addresses.into_iter().collect(),
                host_port: host_port.context("Docker listener has no host port")?,
            },
        );
    }
    Ok(listeners)
}

#[derive(Clone, Copy)]
enum IdentifierKind {
    Digest,
    Name,
}

fn listed(
    runner: &mut impl CommandRunner,
    command: ArgvCommand,
    kind: IdentifierKind,
) -> Result<Vec<String>> {
    let output = run_checked(runner, command)?;
    let text = String::from_utf8(output.stdout).context("Docker list output is not UTF-8")?;
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let value = line.trim();
        ensure!(!value.is_empty(), "Docker list returned an empty identity");
        ensure!(
            !value.contains(char::is_whitespace),
            "Docker list returned a malformed identity"
        );
        if matches!(kind, IdentifierKind::Digest) {
            validate_digest(value, "Docker list identity")?;
        }
        ensure!(
            seen.insert(value.to_owned()),
            "Docker list returned a duplicate identity"
        );
    }
    Ok(seen.into_iter().collect())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} must be a full lowercase hexadecimal digest"
    );
    Ok(())
}
