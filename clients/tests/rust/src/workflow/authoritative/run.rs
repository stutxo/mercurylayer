use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::Serialize;

use super::super::bootstrap;
use super::super::build::{self, SystemCommandRunner};
use super::super::cli::BuildService;
use super::super::error::WorkflowError;
use super::super::evidence;
use super::super::lifecycle;
use super::super::model::{canonical_json, RunPaths, StackMetadata};
use super::super::storage;
use super::super::test_runner::{self, RngAdoptionRecord};
use super::super::verifier::{self, VerifyReport};
use super::cleanup::{append_accounting_error, attach_cleanup, combine_checks, ordered_cleanup};
use super::daemon::{self, DaemonAccounting, DaemonSnapshot};
use super::pair::PairSpec;
use super::rng::{require_exact_rng_history, RngHistoryReport};
use super::sequence::{run_matrix, MatrixStep, MatrixTargetRecord};
use super::snapshot::{self, ControlSnapshot, SnapshotDigests};

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BuildIdentityReport {
    pub(super) production_image_ids: BTreeMap<String, String>,
    pub(super) primary_rng_tag: String,
    pub(super) primary_rng_image_id: String,
    pub(super) control_rng_tag: String,
    pub(super) control_rng_image_id: String,
    pub(super) same_source_and_fingerprints: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoritativeReport {
    version: u32,
    status: String,
    primary_project: String,
    primary_base_port: u16,
    control_project: String,
    control_base_port: u16,
    all_sixteen_ports_preflighted: bool,
    mutable_runtime_identities_disjoint: bool,
    build_identity: BuildIdentityReport,
    rng_history: RngHistoryReport,
    control_before_matrix: ControlSnapshot,
    control_before_matrix_digests: SnapshotDigests,
    matrix: Vec<MatrixTargetRecord>,
    matrix_test_count: usize,
    complete_first_invocation_target_records: usize,
    retries: usize,
    primary_direct_verification: VerifyReport,
    control_after_matrix: ControlSnapshot,
    control_after_primary_down: ControlSnapshot,
    control_comparisons_exact: bool,
    mercury_restart_count: u32,
    cleanup_order: Vec<String>,
    both_projects_absent: bool,
    all_sixteen_ports_free: bool,
    both_wallet_sets_absent: bool,
    source_content_identity_unchanged: bool,
    daemon_accounting: DaemonAccounting,
}

struct Orchestrator<'a> {
    repo_root: &'a Path,
    pair: &'a PairSpec,
    primary_operation: &'a str,
    control_operation: &'a str,
    primary: Option<StackMetadata>,
    control: Option<StackMetadata>,
    daemon_before: Option<DaemonSnapshot>,
    rng_adoptions: Vec<RngAdoptionRecord>,
    primary_down: bool,
    control_down: bool,
}

pub(in crate::workflow) fn execute(
    repo_root: &Path,
    pair: &PairSpec,
    primary_operation: &str,
    control_operation: &str,
) -> Result<String, WorkflowError> {
    let mut orchestrator = Orchestrator {
        repo_root,
        pair,
        primary_operation,
        control_operation,
        primary: None,
        control: None,
        daemon_before: None,
        rng_adoptions: Vec::new(),
        primary_down: false,
        control_down: false,
    };
    let result = orchestrator.run();
    match result {
        Ok(report) => {
            let output = canonical_json(&report).map_err(WorkflowError::from)?;
            evidence::capture_test_output(output.as_bytes(), b"");
            Ok(output)
        }
        Err(primary) => {
            let mut cleanup_errors = orchestrator.cleanup_after_failure();
            append_accounting_error(&mut cleanup_errors, orchestrator.account_after_failure());
            Err(attach_cleanup(primary, cleanup_errors))
        }
    }
}

impl Orchestrator<'_> {
    fn run(&mut self) -> Result<AuthoritativeReport, WorkflowError> {
        let reservations = preflight(self.repo_root, self.pair)?;
        self.daemon_before = Some(
            DaemonSnapshot::capture(self.repo_root)
                .context("capture Docker image/cache/global baseline before either configure")?,
        );
        drop(reservations);

        let primary = storage::configure_prepared(
            self.repo_root,
            self.pair.primary().clone(),
            self.pair.primary_ports(),
            self.primary_operation,
        )
        .context("configure authoritative primary project")?;
        self.primary = Some(primary);
        let control = storage::configure_prepared(
            self.repo_root,
            self.pair.control().clone(),
            self.pair.control_ports(),
            self.control_operation,
        )
        .context("configure authoritative control project")?;
        self.control = Some(control);

        let primary = build_all(self.repo_root, self.primary.as_ref().unwrap())
            .context("build authoritative primary images")?;
        self.primary = Some(primary);
        let control = build_all(self.repo_root, self.control.as_ref().unwrap())
            .context("build authoritative control images")?;
        self.control = Some(control);
        let build_identity = compare_builds(self.primary(), self.control())?;
        let control_build_metadata = self.control().clone();

        start_ready(self.repo_root, self.primary()).context("start authoritative primary")?;
        start_ready(self.repo_root, self.control()).context("start verifier-owned control")?;
        bootstrap_fresh(self.repo_root, self.primary())
            .context("fresh-bootstrap authoritative primary")?;
        bootstrap_fresh(self.repo_root, self.control())
            .context("fresh-bootstrap verifier-owned control")?;
        daemon::require_projects_disjoint(
            self.repo_root,
            self.pair.primary(),
            self.pair.control(),
        )?;

        let control_before_matrix = ControlSnapshot::capture(self.repo_root, self.control())?;
        let control_before_matrix_digests = control_before_matrix.digests()?;

        let repo_root = self.repo_root;
        let primary_project = self.pair.primary().clone();
        let mut observed_adoptions = Vec::new();
        let matrix = run_matrix(
            self.primary().clone(),
            |target| {
                evidence::MatrixTargetOperation::start(
                    repo_root,
                    &primary_project,
                    target.target,
                    target.tests,
                )
            },
            |metadata, target, identity| {
                test_runner::execute(repo_root, metadata, target, identity).map(|execution| {
                    if let Some(adoption) = execution.rng_adoption.as_ref() {
                        observed_adoptions.push(adoption.clone());
                    }
                    MatrixStep {
                        metadata: execution.metadata,
                        adoption: execution.rng_adoption,
                    }
                })
            },
            |operation, result| operation.finish(result),
        );
        self.rng_adoptions = observed_adoptions;
        let matrix = matrix?;
        self.primary = Some(matrix.metadata.clone());
        evidence::require_complete_matrix_records(self.repo_root, self.pair.primary())
            .context("validate all eight complete successful first-invocation records")?;
        let rng_history = require_exact_rng_history(
            &build_identity,
            self.primary(),
            &control_build_metadata,
            self.control(),
            &matrix.adoptions,
        )?;
        let primary_direct_verification = verifier::direct(self.repo_root, self.primary())
            .context("run primary direct contract verifier exactly once")?;
        verifier::require_direct_success(&primary_direct_verification, self.primary())?;

        let control_after_matrix = ControlSnapshot::capture(self.repo_root, self.control())?;
        snapshot::compare(&control_before_matrix, &control_after_matrix)
            .context("prove primary MATRIX and direct verification did not mutate control")?;

        lifecycle::down(self.repo_root, self.primary())
            .context("tear down authoritative primary before control")?;
        self.primary_down = true;
        daemon::require_project_absent(self.repo_root, self.pair.primary())?;
        require_wallet_absent(self.primary())?;

        let control_after_primary_down = ControlSnapshot::capture(self.repo_root, self.control())?;
        snapshot::compare(&control_before_matrix, &control_after_primary_down)
            .context("prove primary teardown did not mutate live control")?;

        lifecycle::down(self.repo_root, self.control())
            .context("tear down verifier-owned control after isolation proof")?;
        self.control_down = true;
        final_mutable_absence(self.repo_root, self.pair, self.primary(), self.control())?;
        require_final_build_identity(self.repo_root, self.primary(), self.control())?;
        let daemon_accounting = self
            .daemon_before
            .as_ref()
            .context("authoritative Docker baseline is absent")?
            .account_final(
                self.repo_root,
                self.primary(),
                self.control(),
                &rng_history.adoption_history,
            )?;

        Ok(AuthoritativeReport {
            version: 1,
            status: "authoritative".into(),
            primary_project: self.pair.primary().to_string(),
            primary_base_port: self.pair.primary_ports().base(),
            control_project: self.pair.control().to_string(),
            control_base_port: self.pair.control_ports().base(),
            all_sixteen_ports_preflighted: true,
            mutable_runtime_identities_disjoint: true,
            build_identity,
            rng_history,
            control_before_matrix,
            control_before_matrix_digests,
            matrix_test_count: matrix.records.iter().map(|target| target.tests.len()).sum(),
            complete_first_invocation_target_records: 8,
            matrix: matrix.records,
            retries: 0,
            primary_direct_verification,
            control_after_matrix,
            control_after_primary_down,
            control_comparisons_exact: true,
            mercury_restart_count: 1,
            cleanup_order: vec!["primary".into(), "control".into()],
            both_projects_absent: true,
            all_sixteen_ports_free: true,
            both_wallet_sets_absent: true,
            source_content_identity_unchanged: true,
            daemon_accounting,
        })
    }

    fn primary(&self) -> &StackMetadata {
        self.primary
            .as_ref()
            .expect("primary metadata exists after configure")
    }

    fn control(&self) -> &StackMetadata {
        self.control
            .as_ref()
            .expect("control metadata exists after configure")
    }

    fn cleanup_after_failure(&mut self) -> Vec<String> {
        self.refresh_metadata();
        let primary = (!self.primary_down).then(|| self.primary.clone()).flatten();
        let control = (!self.control_down).then(|| self.control.clone()).flatten();
        let attempts = ordered_cleanup(primary, control, |metadata| {
            lifecycle::down(self.repo_root, metadata).map(|_| ())
        });
        self.primary_down |= attempts.primary_succeeded;
        self.control_down |= attempts.control_succeeded;
        attempts.errors
    }

    fn account_after_failure(&mut self) -> Result<()> {
        self.refresh_metadata();
        let Some(daemon_before) = self.daemon_before.as_ref() else {
            return Ok(());
        };
        let primary = self
            .primary
            .as_ref()
            .context("primary metadata is absent during failure accounting")?;
        let control = self
            .control
            .as_ref()
            .context("control metadata is absent during failure accounting")?;
        let absence = final_mutable_absence(self.repo_root, self.pair, primary, control)
            .context("prove final mutable absence after failure cleanup");
        let accounting = daemon_before
            .account_final(self.repo_root, primary, control, &self.rng_adoptions)
            .context("account Docker state after failure cleanup")
            .map(|_| ());
        combine_checks(absence, accounting)
    }

    fn refresh_metadata(&mut self) {
        if let Some(primary) = self.primary.as_ref() {
            if let Ok(current) = storage::status(self.repo_root, primary.project()) {
                self.primary = Some(current);
            }
        }
        if let Some(control) = self.control.as_ref() {
            if let Ok(current) = storage::status(self.repo_root, control.project()) {
                self.control = Some(current);
            }
        }
    }
}

fn preflight(repo_root: &Path, pair: &PairSpec) -> Result<Vec<TcpListener>> {
    ensure!(
        RunPaths::new(repo_root, pair.primary()).run_directory
            != RunPaths::new(repo_root, pair.control()).run_directory,
        "primary and control run directories must be disjoint"
    );
    for project in [pair.primary(), pair.control()] {
        let paths = RunPaths::new(repo_root, project);
        require_fresh_metadata(&paths)?;
        daemon::require_project_absent(repo_root, project)?;
    }
    reserve_all_ports(&pair.all_ports())
}

fn require_fresh_metadata(paths: &RunPaths) -> Result<()> {
    for path in [
        paths.stack_metadata.clone(),
        paths.settings_file.clone(),
        paths.wallet_database.clone(),
        paths.wallet_database.with_extension("db-wal"),
        paths.wallet_database.with_extension("db-shm"),
    ] {
        ensure!(
            fs::symlink_metadata(&path).is_err_and(|error| error.kind() == ErrorKind::NotFound),
            "fresh authoritative metadata/wallet identity already exists: {}",
            path.display()
        );
    }
    Ok(())
}

fn reserve_all_ports(ports: &[u16]) -> Result<Vec<TcpListener>> {
    ensure!(
        ports.len() == 16 && ports.iter().copied().collect::<BTreeSet<_>>().len() == 16,
        "authoritative pair does not own exactly 16 distinct ports"
    );
    ports
        .iter()
        .map(|port| {
            TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, *port))
                .with_context(|| format!("authoritative preflight port {port} is not free"))
        })
        .collect()
}

fn build_all(repo_root: &Path, metadata: &StackMetadata) -> Result<StackMetadata> {
    let mut runner = SystemCommandRunner;
    let updated = build::execute(repo_root, metadata, BuildService::All, &mut runner)?;
    storage::replace_metadata(repo_root, metadata.project(), metadata, &updated)?;
    Ok(updated)
}

fn compare_builds(primary: &StackMetadata, control: &StackMetadata) -> Result<BuildIdentityReport> {
    let primary_build = primary
        .build_resolution()
        .context("primary build resolution is absent")?;
    let control_build = control
        .build_resolution()
        .context("control build resolution is absent")?;
    ensure!(
        primary_build.source() == control_build.source()
            && primary_build.fingerprints() == control_build.fingerprints(),
        "primary and control were not built from the same authenticated source/fingerprints"
    );
    let primary_images = primary_build.images();
    let control_images = control_build.images();
    let mut production_image_ids = BTreeMap::new();
    for (name, primary_image, control_image) in [
        (
            "mercury",
            primary_images.mercury(),
            control_images.mercury(),
        ),
        ("token", primary_images.token(), control_images.token()),
        (
            "inquisition",
            primary_images.inquisition(),
            control_images.inquisition(),
        ),
    ] {
        let primary_image =
            primary_image.with_context(|| format!("primary {name} image absent"))?;
        let control_image =
            control_image.with_context(|| format!("control {name} image absent"))?;
        ensure!(
            primary_image.tag() == control_image.tag()
                && primary_image.image_id() == control_image.image_id(),
            "primary/control immutable {name} image identity differs"
        );
        production_image_ids.insert(name.into(), primary_image.image_id().into());
    }
    let primary_lockbox = primary_images
        .lockbox()
        .context("primary lockbox images absent")?;
    let control_lockbox = control_images
        .lockbox()
        .context("control lockbox images absent")?;
    ensure!(
        primary_lockbox.production().tag() == control_lockbox.production().tag()
            && primary_lockbox.production().image_id() == control_lockbox.production().image_id(),
        "primary/control immutable lockbox image identity differs"
    );
    production_image_ids.insert(
        "lockbox".into(),
        primary_lockbox.production().image_id().into(),
    );
    let primary_rng = primary_lockbox.deterministic_rng();
    let control_rng = control_lockbox.deterministic_rng();
    ensure!(
        primary_rng.tag() != control_rng.tag() && primary_rng.image_id() != control_rng.image_id(),
        "primary/control deterministic RNG image identities are not disjoint"
    );
    Ok(BuildIdentityReport {
        production_image_ids,
        primary_rng_tag: primary_rng.tag().into(),
        primary_rng_image_id: primary_rng.image_id().into(),
        control_rng_tag: control_rng.tag().into(),
        control_rng_image_id: control_rng.image_id().into(),
        same_source_and_fingerprints: true,
    })
}

fn start_ready(repo_root: &Path, metadata: &StackMetadata) -> Result<()> {
    lifecycle::up(repo_root, metadata)?;
    lifecycle::ready(repo_root, metadata)?;
    Ok(())
}

fn bootstrap_fresh(repo_root: &Path, metadata: &StackMetadata) -> Result<()> {
    bootstrap::execute(repo_root, metadata, true).map_err(anyhow::Error::new)?;
    lifecycle::ready(repo_root, metadata)?;
    Ok(())
}

fn final_mutable_absence(
    repo_root: &Path,
    pair: &PairSpec,
    primary: &StackMetadata,
    control: &StackMetadata,
) -> Result<()> {
    daemon::require_project_absent(repo_root, pair.primary())?;
    daemon::require_project_absent(repo_root, pair.control())?;
    drop(reserve_all_ports(&pair.all_ports())?);
    require_wallet_absent(primary)?;
    require_wallet_absent(control)?;
    Ok(())
}

fn require_final_build_identity(
    repo_root: &Path,
    primary: &StackMetadata,
    control: &StackMetadata,
) -> Result<()> {
    let mut runner = SystemCommandRunner;
    build::verify_complete(repo_root, primary, &mut runner)
        .context("final primary source/content/build identity recheck")?;
    build::verify_complete(repo_root, control, &mut runner)
        .context("final control source/content/build identity recheck")?;
    Ok(())
}

fn require_wallet_absent(metadata: &StackMetadata) -> Result<()> {
    let database = &metadata.paths().wallet_database;
    for path in [
        database.clone(),
        database.with_extension("db-wal"),
        database.with_extension("db-shm"),
    ] {
        ensure!(
            fs::symlink_metadata(&path).is_err_and(|error| error.kind() == ErrorKind::NotFound),
            "wallet artifact remains after project teardown: {}",
            path.display()
        );
    }
    Ok(())
}
