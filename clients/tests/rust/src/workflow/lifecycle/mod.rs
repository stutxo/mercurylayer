mod contract;
mod docker;
mod docker_command;
mod inspect_types;
mod readiness;
mod readiness_http;
mod report;
mod topology;
mod wallet;

#[cfg(test)]
mod controller_tests;
#[cfg(test)]
mod readiness_tests;
#[cfg(test)]
mod test_support;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};

use super::argv::{ArgvCommand, CommandOutput, CommandRunner, SystemCommandRunner};
use super::build::{self, VerifiedBuild};
use super::model::{ProjectSpec, StackMetadata};
use contract::{
    expected_from_metadata, expected_from_verified, image_map, image_map_from_metadata,
};
use docker::{observe, Observation};
use docker_command::{compose_command, resolve_unrecorded_image_ids, run_checked};
use readiness::{port_observations, sample, HostProbe, SystemHostProbe};
use report::ReadinessReport;
pub(super) use report::StatusReport;

const READY_DEADLINE: Duration = Duration::from_secs(120);
const READY_RETRY_INTERVAL: Duration = Duration::from_millis(250);

trait BuildVerifier<R: CommandRunner> {
    fn verify(
        &mut self,
        repo_root: &Path,
        metadata: &StackMetadata,
        runner: &mut R,
    ) -> Result<VerifiedBuild>;
}

struct CurrentBuildVerifier;

impl<R: CommandRunner> BuildVerifier<R> for CurrentBuildVerifier {
    fn verify(
        &mut self,
        repo_root: &Path,
        metadata: &StackMetadata,
        runner: &mut R,
    ) -> Result<VerifiedBuild> {
        build::verify_complete(repo_root, metadata, runner)
    }
}

pub(super) fn up(repo_root: &Path, metadata: &StackMetadata) -> Result<StatusReport> {
    let mut runner = SystemCommandRunner;
    let mut host = SystemHostProbe::new();
    let mut verifier = CurrentBuildVerifier;
    up_with(repo_root, metadata, &mut runner, &mut host, &mut verifier)
}

pub(super) fn ready(repo_root: &Path, metadata: &StackMetadata) -> Result<StatusReport> {
    let mut runner = SystemCommandRunner;
    let mut host = SystemHostProbe::new();
    let mut verifier = CurrentBuildVerifier;
    ready_with(repo_root, metadata, &mut runner, &mut host, &mut verifier)
}

pub(super) fn status(repo_root: &Path, metadata: &StackMetadata) -> Result<StatusReport> {
    let mut runner = SystemCommandRunner;
    let mut host = SystemHostProbe::new();
    status_with(repo_root, metadata, &mut runner, &mut host)
}

pub(super) fn down(repo_root: &Path, metadata: &StackMetadata) -> Result<StatusReport> {
    let mut runner = SystemCommandRunner;
    let mut host = SystemHostProbe::new();
    down_with(repo_root, metadata, &mut runner, &mut host)
}

pub(super) fn compose_logs_with(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<(ArgvCommand, CommandOutput)> {
    let environment = metadata
        .project_spec(image_map_from_metadata(metadata)?)
        .managed_environment()?;
    let command = compose_command(
        repo_root,
        metadata,
        &environment,
        &["logs", "--no-color", "--timestamps", "--tail", "200"],
    )?;
    let output =
        run_checked(runner, command.clone()).context("read bounded literal BIP448 Compose logs")?;
    Ok((command, output))
}

pub(super) fn project_spec(metadata: &StackMetadata) -> Result<ProjectSpec> {
    Ok(metadata.project_spec(image_map_from_metadata(metadata)?))
}

pub(super) fn exact_mercury_config(metadata: &StackMetadata) -> Result<serde_json::Value> {
    let mut host = SystemHostProbe::new();
    readiness::exact_mercury_config(metadata, &mut host)
}

pub(super) fn require_stable_started(report: &StatusReport) -> Result<()> {
    ensure!(
        report.runtime.all_services_ready && report.runtime.containers.len() == 8,
        "control topology is not exactly eight ready services"
    );
    for (service, container) in &report.runtime.containers {
        ensure!(
            container
                .started_at
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty()),
            "control service {service} has no stable StartedAt identity"
        );
    }
    Ok(())
}

pub(super) fn restart_mercury(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    let environment = metadata
        .project_spec(image_map_from_metadata(metadata)?)
        .managed_environment()?;
    let command = compose_command(
        repo_root,
        metadata,
        &environment,
        &["restart", "mercury-server"],
    )?;
    run_checked(runner, command).context("restart exactly the project Mercury service")?;
    Ok(())
}

fn up_with<R, H, V>(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut R,
    host: &mut H,
    verifier: &mut V,
) -> Result<StatusReport>
where
    R: CommandRunner,
    H: HostProbe,
    V: BuildVerifier<R>,
{
    let verified = verifier.verify(repo_root, metadata, runner)?;
    let mut expected = expected_from_verified(&verified);
    resolve_unrecorded_image_ids(repo_root, &mut expected, runner)?;
    let observation = observe(repo_root, metadata, runner)?;

    if !observation.resources_absent() {
        topology::validate_exact(&observation, metadata, &expected)
            .context("refusing to reconcile an existing partial or mismatched topology")?;
        let ports = port_observations(metadata, host)?;
        require_ports_occupied(&ports)?;
        let (readiness, all_ready) =
            sample(repo_root, metadata, &observation, runner, host, false)?;
        ensure!(
            all_ready,
            "refusing to mutate an existing topology that is not exactly ready"
        );
        return make_report(metadata, observation, &expected, readiness, ports);
    }

    let ports = port_observations(metadata, host)?;
    require_ports_free(&ports)?;
    let environment = metadata
        .project_spec(image_map(metadata, &verified)?)
        .managed_environment()?;
    run_checked(
        runner,
        compose_command(
            repo_root,
            metadata,
            &environment,
            &["up", "-d", "--no-build", "--pull", "never"],
        )?,
    )
    .context("start exact BIP448 token-server Compose stack")?;

    let verified_after = verifier.verify(repo_root, metadata, runner)?;
    ensure!(
        verified_after == verified,
        "resolved build changed while Compose was starting"
    );
    let mut expected_after = expected_from_verified(&verified_after);
    resolve_unrecorded_image_ids(repo_root, &mut expected_after, runner)?;
    ensure!(
        expected_after == expected,
        "image tags changed while Compose was starting"
    );

    let observation = observe(repo_root, metadata, runner)?;
    topology::validate_exact(&observation, metadata, &expected)?;
    let ports = port_observations(metadata, host)?;
    require_ports_occupied(&ports)?;
    let (readiness, _) = sample(repo_root, metadata, &observation, runner, host, false)?;
    make_report(metadata, observation, &expected, readiness, ports)
}

fn ready_with<R, H, V>(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut R,
    host: &mut H,
    verifier: &mut V,
) -> Result<StatusReport>
where
    R: CommandRunner,
    H: HostProbe,
    V: BuildVerifier<R>,
{
    let verified = verifier.verify(repo_root, metadata, runner)?;
    let mut expected = expected_from_verified(&verified);
    resolve_unrecorded_image_ids(repo_root, &mut expected, runner)?;
    let deadline = host
        .now_millis()
        .saturating_add(u64::try_from(READY_DEADLINE.as_millis()).unwrap_or(u64::MAX));
    loop {
        let observation = observe(repo_root, metadata, runner)?;
        topology::validate_exact(&observation, metadata, &expected)?;
        let ports = port_observations(metadata, host)?;
        require_ports_occupied(&ports)?;
        let (readiness, all_ready) = sample(repo_root, metadata, &observation, runner, host, true)?;
        if all_ready {
            return make_report(metadata, observation, &expected, readiness, ports);
        }
        if host.now_millis() >= deadline {
            let missing = readiness
                .iter()
                .filter(|(_, value)| !value.ready)
                .map(|(service, value)| format!("{service}:{}", value.detail))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("BIP448 stack readiness deadline expired: {missing}");
        }
        host.sleep(READY_RETRY_INTERVAL);
    }
}

fn status_with<R: CommandRunner, H: HostProbe>(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut R,
    host: &mut H,
) -> Result<StatusReport> {
    let expected = expected_from_metadata(metadata);
    let observation = observe(repo_root, metadata, runner)?;
    let ports = port_observations(metadata, host)?;
    let readiness = if topology::validate_safe(&observation, metadata, &expected).is_ok() {
        sample(repo_root, metadata, &observation, runner, host, false)?.0
    } else {
        observation
            .containers
            .keys()
            .map(|service| {
                (
                    service.clone(),
                    ReadinessReport {
                        ready: false,
                        detail: "topology_mismatch".into(),
                    },
                )
            })
            .collect()
    };
    make_report(metadata, observation, &expected, readiness, ports)
}

#[cfg(test)]
pub(in crate::workflow) fn evidence_test_metadata(repo_root: &Path) -> StackMetadata {
    test_support::metadata(repo_root)
}

#[cfg(test)]
pub(in crate::workflow) fn evidence_test_absent_status(
    repo_root: &Path,
    metadata: &StackMetadata,
) -> Result<StatusReport> {
    let mut docker = test_support::MockDocker::absent();
    let mut host = test_support::MockHost::new(true);
    status_with(repo_root, metadata, &mut docker, &mut host)
}

fn down_with<R: CommandRunner, H: HostProbe>(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut R,
    host: &mut H,
) -> Result<StatusReport> {
    let expected = expected_from_metadata(metadata);
    let before = observe(repo_root, metadata, runner)?;
    if before.resources_absent() {
        let ports = port_observations(metadata, host)?;
        require_ports_free(&ports)?;
        wallet::remove_wallet_artifacts(metadata.paths())?;
        return make_report(metadata, before, &expected, BTreeMap::new(), ports);
    }

    topology::validate_safe(&before, metadata, &expected)
        .context("refusing to remove an unsafe or foreign project topology")?;
    let anonymous = before
        .anonymous_vault_volumes
        .iter()
        .map(|volume| volume.name.clone())
        .collect::<Vec<_>>();
    let environment = metadata
        .project_spec(image_map_from_metadata(metadata)?)
        .managed_environment()?;
    run_checked(
        runner,
        compose_command(repo_root, metadata, &environment, &["down", "-v"])?,
    )
    .context("remove exact BIP448 token-server Compose stack")?;

    let after = observe(repo_root, metadata, runner)?;
    ensure!(
        after.resources_absent(),
        "Compose down left labeled project containers, networks, or declared volumes"
    );
    for volume in &anonymous {
        docker_command::require_volume_absent(repo_root, volume, runner)?;
    }
    let ports = port_observations(metadata, host)?;
    require_ports_free(&ports)?;
    wallet::remove_wallet_artifacts(metadata.paths())?;
    make_report(metadata, after, &expected, BTreeMap::new(), ports)
}

fn make_report(
    metadata: &StackMetadata,
    observation: Observation,
    expected: &contract::ExpectedImages,
    readiness: BTreeMap<String, ReadinessReport>,
    ports: BTreeMap<u16, bool>,
) -> Result<StatusReport> {
    Ok(StatusReport {
        configured: metadata.clone(),
        runtime: topology::report(&observation, metadata, expected, &readiness, &ports)?,
    })
}

fn require_ports_free(ports: &BTreeMap<u16, bool>) -> Result<()> {
    let occupied = ports
        .iter()
        .filter_map(|(port, free)| (!free).then_some(*port))
        .collect::<Vec<_>>();
    ensure!(
        occupied.is_empty(),
        "assigned host ports are occupied: {occupied:?}"
    );
    Ok(())
}

fn require_ports_occupied(ports: &BTreeMap<u16, bool>) -> Result<()> {
    let free = ports
        .iter()
        .filter_map(|(port, free)| free.then_some(*port))
        .collect::<Vec<_>>();
    ensure!(
        free.is_empty(),
        "expected Docker listeners are absent on ports: {free:?}"
    );
    Ok(())
}
