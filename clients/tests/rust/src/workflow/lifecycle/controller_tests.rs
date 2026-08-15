use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::model::{canonical_json, PortMap, Project, StackMetadata};
use super::test_support::{metadata, strings, MockDocker, MockHost, StackShape, StubVerifier};
use super::{down_with, status_with, up_with};

#[test]
fn up_uses_one_exact_compose_argv_and_repeated_up_preserves_container_ids() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::absent();
    let mut host = MockHost::new(false);
    host.push_port_round(true);
    let mut verifier = StubVerifier::new();

    let first = up_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap();
    assert!(first.runtime.all_services_ready);
    assert_eq!(docker.compose_calls("up"), 1);
    assert_eq!(verifier.calls, 2);
    let first_ids = first
        .runtime
        .containers
        .iter()
        .map(|(service, value)| (service.clone(), value.id.clone()))
        .collect::<Vec<_>>();

    let second = up_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap();
    assert!(second.runtime.all_services_ready);
    assert_eq!(docker.compose_calls("up"), 1);
    assert_eq!(
        second
            .runtime
            .containers
            .iter()
            .map(|(service, value)| (service.clone(), value.id.clone()))
            .collect::<Vec<_>>(),
        first_ids
    );

    let compose = docker
        .seen
        .iter()
        .find(|command| strings(&command.args).get(5).map(String::as_str) == Some("up"))
        .unwrap();
    assert_eq!(
        strings(&compose.args),
        [
            "compose",
            "-p",
            "life_test",
            "-f",
            "/repo/docker-compose-token-servers.yml",
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never"
        ]
    );
    assert_eq!(compose.environment.len(), 12);
    assert_eq!(
        compose.environment[OsStr::new("ML_TEST_MERCURY_PORT")],
        "24000"
    );
    assert_eq!(
        compose.environment[OsStr::new("ML_TEST_CORE_RPC_PORT")],
        "24005"
    );
    assert_direct_argv_only(&docker);
}

#[test]
fn up_rejects_partial_topology_without_compose_mutation() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::exact();
    docker.shape = StackShape::Missing("token-server-v2");
    let mut host = MockHost::new(false);
    let mut verifier = StubVerifier::new();

    let error = up_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap_err();
    assert!(format!("{error:#}").contains("partial or mismatched topology"));
    assert_eq!(docker.compose_calls("up"), 0);
}

#[test]
fn status_reports_absent_and_stopped_without_mutation() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut absent = MockDocker::absent();
    let mut host = MockHost::new(true);
    let report = status_with(root, &metadata, &mut absent, &mut host).unwrap();
    assert!(report.runtime.resources_absent);
    assert!(!report.runtime.all_services_ready);
    assert!(report
        .runtime
        .containers
        .values()
        .all(|container| container.state == "absent"));
    let encoded = canonical_json(&report).unwrap();
    assert!(encoded.contains("\"configured\":{\"build\":"));
    assert_eq!(absent.compose_calls("up") + absent.compose_calls("down"), 0);

    let mut stopped = MockDocker::exact();
    stopped.state = "exited".into();
    stopped.running = false;
    let mut host = MockHost::new(true);
    let report = status_with(root, &metadata, &mut stopped, &mut host).unwrap();
    assert!(!report.runtime.resources_absent);
    assert!(!report.runtime.all_services_ready);
    assert!(report
        .runtime
        .containers
        .values()
        .all(|container| container.state == "exited" && !container.readiness.ready));
    assert_eq!(
        stopped.compose_calls("up") + stopped.compose_calls("down"),
        0
    );
}

#[test]
fn down_is_one_exact_compose_call_then_proves_absence_and_repeats_as_noop() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::exact();
    let mut host = MockHost::new(true);

    let first = down_with(root, &metadata, &mut docker, &mut host).unwrap();
    assert!(first.runtime.resources_absent);
    assert_eq!(docker.compose_calls("down"), 1);
    let down_index = docker
        .seen
        .iter()
        .position(|command| strings(&command.args).get(5).map(String::as_str) == Some("down"))
        .unwrap();
    let absence_inspections = docker
        .seen
        .iter()
        .enumerate()
        .filter(|(_, command)| {
            let args = strings(&command.args);
            args.first().map(String::as_str) == Some("volume")
                && args.get(1).map(String::as_str) == Some("inspect")
                && args.len() == 3
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(absence_inspections.len(), 2);
    assert!(absence_inspections.iter().all(|index| *index > down_index));

    let second = down_with(root, &metadata, &mut docker, &mut host).unwrap();
    assert!(second.runtime.resources_absent);
    assert_eq!(docker.compose_calls("down"), 1);
    assert_direct_argv_only(&docker);
}

#[test]
fn down_never_removes_wallet_before_resource_and_volume_proofs() {
    let temp = TempRoot::new();
    let metadata = metadata(&temp.path);
    fs::create_dir_all(&metadata.paths().run_directory).unwrap();
    fs::write(&metadata.paths().wallet_database, b"wallet").unwrap();

    let mut resources_left = MockDocker::exact();
    resources_left.down_leaves_resources = true;
    let mut host = MockHost::new(true);
    assert!(down_with(&temp.path, &metadata, &mut resources_left, &mut host).is_err());
    assert!(metadata.paths().wallet_database.exists());

    let mut daemon_error = MockDocker::exact();
    daemon_error.absence_daemon_error = true;
    let mut host = MockHost::new(true);
    assert!(down_with(&temp.path, &metadata, &mut daemon_error, &mut host).is_err());
    assert!(metadata.paths().wallet_database.exists());
}

#[test]
fn down_rejects_wallet_symlink_after_proving_stack_and_ports_absent() {
    let temp = TempRoot::new();
    let metadata = metadata(&temp.path);
    fs::create_dir_all(&metadata.paths().run_directory).unwrap();
    let target = temp.path.join("outside-wallet");
    fs::write(&target, b"keep").unwrap();
    symlink(&target, &metadata.paths().wallet_database).unwrap();
    let mut docker = MockDocker::absent();
    let mut host = MockHost::new(true);

    let error = down_with(&temp.path, &metadata, &mut docker, &mut host).unwrap_err();
    assert!(format!("{error:#}").contains("regular nonsymlink"));
    assert!(metadata.paths().wallet_database.symlink_metadata().is_ok());
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    assert_eq!(docker.compose_calls("down"), 0);
}

#[test]
fn down_does_not_broadly_clean_an_existing_stack_without_complete_build_metadata() {
    let root = Path::new("/repo");
    let metadata = StackMetadata::new(
        root,
        Project::parse("life_test").unwrap(),
        PortMap::from_base(24000).unwrap(),
    );
    let mut docker = MockDocker::exact();
    let mut host = MockHost::new(true);
    assert!(down_with(root, &metadata, &mut docker, &mut host).is_err());
    assert_eq!(docker.compose_calls("down"), 0);
}

fn assert_direct_argv_only(docker: &MockDocker) {
    for command in &docker.seen {
        assert_eq!(command.program(), "docker");
        let args = command.args_slice();
        assert!(!args.iter().any(|arg| arg == "-c"));
        assert!(!args.iter().any(|arg| arg == "sh" || arg == "bash"));
    }
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bip448-lifecycle-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
