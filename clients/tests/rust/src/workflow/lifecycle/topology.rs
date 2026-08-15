use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};

use super::super::model::StackMetadata;
use super::contract::{
    declared_volume_name, expected_declared_mount, expected_ports, network_name, ExpectedImages,
    DECLARED_VOLUMES, SERVICES, VAULT_ANONYMOUS_MOUNTS,
};
use super::docker::{Container, Mount, Observation};
use super::report::{
    AssignedPortReport, ContainerReport, ImageReport, ListenerReport, NetworkReport,
    ReadinessReport, RuntimeReport, VolumeReport, VolumeSetReport,
};

pub(super) fn validate_exact(
    observation: &Observation,
    metadata: &StackMetadata,
    expected: &ExpectedImages,
) -> Result<()> {
    ensure!(
        observation.containers.len() == SERVICES.len()
            && SERVICES
                .iter()
                .all(|service| observation.containers.contains_key(*service)),
        "lifecycle requires exactly one container for each of the eight Compose services"
    );
    ensure!(
        observation.declared_volumes.len() == DECLARED_VOLUMES.len(),
        "lifecycle requires exactly the three declared project volumes"
    );
    ensure!(
        observation.anonymous_vault_volumes.len() == VAULT_ANONYMOUS_MOUNTS.len(),
        "lifecycle requires exactly two anonymous Vault volumes"
    );
    validate_safe(observation, metadata, expected)
}

pub(super) fn validate_safe(
    observation: &Observation,
    metadata: &StackMetadata,
    expected: &ExpectedImages,
) -> Result<()> {
    ensure!(
        observation.networks.len() <= 1,
        "multiple project networks are unsafe"
    );
    let expected_network = network_name(metadata);
    let network = observation.networks.first();
    if let Some(network) = network {
        ensure!(
            network.name == expected_network,
            "unexpected project network name"
        );
        ensure!(
            network.driver == "bridge",
            "project network must use the bridge driver"
        );
        ensure!(
            network.project_label.as_deref() == Some(metadata.project().as_str())
                && network.network_label.as_deref() == Some("default"),
            "project network labels are not exact"
        );
    }

    let expected_ports = expected_ports(metadata.ports());
    let mut host_ports = BTreeMap::new();
    for (service, container) in &observation.containers {
        let image = expected
            .get(service)
            .with_context(|| format!("no configured image contract for {service}"))?;
        ensure!(
            container.configured_image == image.tag,
            "service {service} configured image tag mismatch"
        );
        validate_image_id(&container.image_id)?;
        if let Some(expected_id) = &image.image_id {
            ensure!(
                &container.image_id == expected_id,
                "service {service} image ID does not match the resolved exact ID"
            );
        }
        let network = network.context("a project container exists without its project network")?;
        ensure!(
            container.networks.len() == 1
                && container.networks.get(&expected_network) == Some(&network.id),
            "service {service} is not attached only to the exact project network"
        );
        let observed_listener_ports = container
            .listeners
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let expected_listener_ports = expected_ports[service.as_str()]
            .keys()
            .copied()
            .collect::<Vec<_>>();
        ensure!(
            observed_listener_ports == expected_listener_ports,
            "service {service} listener container-port set mismatch"
        );
        for (container_port, expected_host_port) in &expected_ports[service.as_str()] {
            let listener = container
                .listeners
                .get(*container_port)
                .context("expected listener is absent")?;
            ensure!(
                listener.host_port == *expected_host_port,
                "service {service} listener host port mismatch"
            );
            ensure!(
                listener
                    .host_addresses
                    .iter()
                    .any(|address| address == "0.0.0.0" || address == "127.0.0.1"),
                "service {service} has no IPv4 host listener"
            );
            ensure!(
                listener.host_addresses.iter().all(|address| matches!(
                    address.as_str(),
                    "0.0.0.0" | "127.0.0.1" | "::" | "::1"
                )),
                "service {service} has an unexpected listener address"
            );
            ensure!(
                host_ports.insert(listener.host_port, service).is_none(),
                "multiple service listeners share one assigned host port"
            );
        }
        validate_mounts(metadata, container)?;
    }

    validate_network_membership(observation)?;
    validate_declared_volumes(observation, metadata)?;
    validate_anonymous_volumes(observation)?;
    Ok(())
}

fn validate_network_membership(observation: &Observation) -> Result<()> {
    let Some(network) = observation.networks.first() else {
        ensure!(
            observation.containers.is_empty(),
            "containers exist without a network"
        );
        return Ok(());
    };
    let expected = observation
        .containers
        .values()
        .map(|container| container.id.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        network
            .container_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            == expected,
        "project network membership does not match project containers"
    );
    Ok(())
}

fn validate_declared_volumes(observation: &Observation, metadata: &StackMetadata) -> Result<()> {
    let mut keys = BTreeSet::new();
    for volume in &observation.declared_volumes {
        let key = volume
            .volume_label
            .as_deref()
            .context("declared project volume lacks its Compose volume label")?;
        ensure!(
            DECLARED_VOLUMES
                .iter()
                .any(|(expected, _, _)| *expected == key),
            "unexpected declared Compose volume {key:?}"
        );
        ensure!(keys.insert(key), "duplicate declared Compose volume label");
        ensure!(
            volume.name == declared_volume_name(metadata, key),
            "declared project volume name mismatch"
        );
        ensure!(
            volume.driver == "local",
            "declared project volume driver mismatch"
        );
        ensure!(
            volume.project_label.as_deref() == Some(metadata.project().as_str()),
            "declared project volume project label mismatch"
        );
    }
    Ok(())
}

fn validate_anonymous_volumes(observation: &Observation) -> Result<()> {
    let vault_present = observation.containers.contains_key("vault");
    if !vault_present {
        ensure!(
            observation.anonymous_vault_volumes.is_empty(),
            "anonymous Vault volumes were observed without a Vault container"
        );
        return Ok(());
    }
    ensure!(
        observation.anonymous_vault_volumes.len() == VAULT_ANONYMOUS_MOUNTS.len(),
        "Vault must have exactly two inspectable anonymous volumes"
    );
    let mut destinations = BTreeSet::new();
    for volume in &observation.anonymous_vault_volumes {
        ensure!(
            volume.name.len() == 64
                && volume
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "anonymous Vault volume name is not an exact Docker volume identity"
        );
        ensure!(
            volume.driver == "local",
            "anonymous Vault volume driver mismatch"
        );
        let destination = volume
            .destination
            .as_deref()
            .context("anonymous Vault destination is absent")?;
        ensure!(
            VAULT_ANONYMOUS_MOUNTS.contains(&destination),
            "unexpected anonymous Vault mount destination"
        );
        ensure!(
            destinations.insert(destination),
            "duplicate anonymous Vault mount destination"
        );
    }
    Ok(())
}

fn validate_mounts(metadata: &StackMetadata, container: &Container) -> Result<()> {
    if container.service == "vault" {
        ensure!(
            container.mounts.len() == 2,
            "Vault must have exactly two mounts"
        );
        for mount in &container.mounts {
            validate_volume_mount(mount)?;
            ensure!(
                VAULT_ANONYMOUS_MOUNTS.contains(&mount.destination.as_str()),
                "unexpected Vault mount"
            );
        }
        return Ok(());
    }
    if let Some((key, destination)) = expected_declared_mount(&container.service) {
        ensure!(
            container.mounts.len() == 1,
            "service must have exactly one declared mount"
        );
        let mount = &container.mounts[0];
        validate_volume_mount(mount)?;
        ensure!(
            mount.name == declared_volume_name(metadata, key) && mount.destination == destination,
            "service declared mount identity mismatch"
        );
    } else {
        ensure!(container.mounts.is_empty(), "service has unexpected mounts");
    }
    Ok(())
}

fn validate_volume_mount(mount: &Mount) -> Result<()> {
    ensure!(mount.kind == "volume", "stack mount is not a Docker volume");
    ensure!(!mount.name.is_empty(), "stack volume mount has no identity");
    ensure!(mount.read_write, "stack volume mount is not read-write");
    Ok(())
}

fn validate_image_id(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("container image ID lacks sha256: prefix")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "container image ID is malformed"
    );
    Ok(())
}

pub(super) fn report(
    observation: &Observation,
    metadata: &StackMetadata,
    expected: &ExpectedImages,
    readiness: &BTreeMap<String, ReadinessReport>,
    port_free: &BTreeMap<u16, bool>,
) -> Result<RuntimeReport> {
    let exact = validate_exact(observation, metadata, expected).is_ok();
    let mut containers = BTreeMap::new();
    for service in SERVICES {
        let expected_image = expected.get(service);
        let value = match observation.containers.get(service) {
            Some(container) => ContainerReport {
                id: Some(container.id.clone()),
                name: Some(container.name.clone()),
                state: container.state.clone(),
                running: container.running,
                restarting: container.restarting,
                dead: container.dead,
                health: container.health.clone(),
                image: ImageReport {
                    configured_tag: Some(container.configured_image.clone()),
                    expected_id: expected_image.and_then(|image| image.image_id.clone()),
                    actual_id: Some(container.image_id.clone()),
                    matches_expected: expected_image.is_some_and(|image| {
                        container.configured_image == image.tag
                            && image
                                .image_id
                                .as_ref()
                                .is_none_or(|id| id == &container.image_id)
                    }),
                },
                listeners: container
                    .listeners
                    .iter()
                    .map(|(port, listener)| ListenerReport {
                        container_port: port.clone(),
                        host_addresses: listener.host_addresses.clone(),
                        host_port: listener.host_port,
                    })
                    .collect(),
                readiness: readiness.get(service).cloned().unwrap_or(ReadinessReport {
                    ready: false,
                    detail: "not_checked".into(),
                }),
            },
            None => ContainerReport {
                id: None,
                name: None,
                state: "absent".into(),
                running: false,
                restarting: false,
                dead: false,
                health: None,
                image: ImageReport {
                    configured_tag: expected_image.map(|image| image.tag.clone()),
                    expected_id: expected_image.and_then(|image| image.image_id.clone()),
                    actual_id: None,
                    matches_expected: false,
                },
                listeners: Vec::new(),
                readiness: ReadinessReport {
                    ready: false,
                    detail: "container_absent".into(),
                },
            },
        };
        containers.insert(service.to_owned(), value);
    }

    let mut listener_owners = BTreeMap::new();
    for (service, container) in &observation.containers {
        for listener in container.listeners.values() {
            ensure!(
                listener_owners
                    .insert(listener.host_port, service.clone())
                    .is_none(),
                "duplicate observed host listener port"
            );
        }
    }
    let assigned_ports = metadata
        .ports()
        .ordered()
        .into_iter()
        .map(|(role, port)| AssignedPortReport {
            role: role.to_string(),
            port,
            listener_service: listener_owners.get(&port).cloned(),
            free: port_free.get(&port).copied().unwrap_or(false),
        })
        .collect();
    let all_services_ready = exact
        && SERVICES.iter().all(|service| {
            readiness
                .get(*service)
                .is_some_and(|readiness| readiness.ready)
        });
    Ok(RuntimeReport {
        resources_absent: observation.resources_absent(),
        all_services_ready,
        containers,
        networks: observation
            .networks
            .iter()
            .map(|network| NetworkReport {
                id: network.id.clone(),
                name: network.name.clone(),
                driver: network.driver.clone(),
                project_label: network.project_label.clone(),
                network_label: network.network_label.clone(),
                container_ids: network.container_ids.clone(),
            })
            .collect(),
        volumes: VolumeSetReport {
            declared: observation
                .declared_volumes
                .iter()
                .map(volume_report)
                .collect(),
            anonymous_vault: observation
                .anonymous_vault_volumes
                .iter()
                .map(volume_report)
                .collect(),
        },
        assigned_ports,
    })
}

fn volume_report(volume: &super::docker::Volume) -> VolumeReport {
    VolumeReport {
        id: volume.name.clone(),
        name: volume.name.clone(),
        driver: volume.driver.clone(),
        project_label: volume.project_label.clone(),
        volume_label: volume.volume_label.clone(),
        destination: volume.destination.clone(),
    }
}
