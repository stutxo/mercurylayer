use super::*;
use crate::workflow::matrix::MATRIX;
use crate::workflow::model::{
    BuildFingerprints, BuildResolution, BuildSource, ComposeHashes, PortMap, Project,
    ResolvedImage, ResolvedImages, ResolvedLockboxImages,
};
use crate::workflow::test_runner::{
    RngAdoptionRecord, RNG_RECONCILIATION_TARGET, RNG_RECONCILIATION_TEST,
};

fn matrix_metadata(project: &str) -> StackMetadata {
    StackMetadata::new(
        Path::new("/repo"),
        Project::parse(project).unwrap(),
        PortMap::from_base(24_600).unwrap(),
    )
}

#[test]
fn pair_preflight_rejects_duplicate_ports_and_existing_metadata() {
    assert!(reserve_all_ports(&[25_600; 16]).is_err());

    let root = std::env::temp_dir().join(format!(
        "bip448-authoritative-preflight-{}",
        uuid::Uuid::new_v4()
    ));
    let project = Project::parse("preflight").unwrap();
    let paths = RunPaths::new(&root, &project);
    std::fs::create_dir_all(&paths.run_directory).unwrap();
    assert!(require_fresh_metadata(&paths).is_ok());
    std::fs::write(&paths.stack_metadata, b"collision").unwrap();
    assert!(require_fresh_metadata(&paths).is_err());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn matrix_sequence_is_exactly_eight_targets_and_fifty_nine_one_shots() {
    let mut seen = Vec::new();
    let mut started = Vec::new();
    let mut finished = 0;
    let records = run_matrix(
        matrix_metadata("matrix"),
        |target| {
            started.push(target.target);
            Ok(())
        },
        |metadata, target, test| {
            assert_eq!(metadata.project().as_str(), "matrix");
            seen.push((target.to_owned(), test.to_owned()));
            Ok(MatrixStep {
                metadata: metadata.clone(),
                adoption: None,
            })
        },
        |(), result| {
            finished += 1;
            result
        },
    )
    .unwrap();
    assert_eq!(records.records.len(), 8);
    assert_eq!(
        started,
        MATRIX
            .iter()
            .map(|target| target.target)
            .collect::<Vec<_>>()
    );
    assert_eq!(finished, 8);
    assert_eq!(seen.len(), 59);
    assert_eq!(
        seen,
        MATRIX
            .iter()
            .flat_map(|target| target
                .tests
                .iter()
                .map(move |test| (target.target.to_owned(), (*test).to_owned())))
            .collect::<Vec<_>>()
    );
}

#[test]
fn matrix_stops_at_first_failure_without_retry() {
    let mut calls = 0;
    let mut started = 0;
    let mut finished = 0;
    let error = run_matrix(
        matrix_metadata("matrix"),
        |_| {
            started += 1;
            Ok(())
        },
        |metadata, _, _| {
            calls += 1;
            if calls == 7 {
                Err(WorkflowError::child_exit(19, "first failure"))
            } else {
                Ok(MatrixStep {
                    metadata: metadata.clone(),
                    adoption: None,
                })
            }
        },
        |(), result| {
            finished += 1;
            result
        },
    )
    .unwrap_err();
    assert_eq!(calls, 7);
    assert_eq!(started, 3);
    assert_eq!(finished, 3);
    assert_eq!(error.exit_code(), 19);
}

#[test]
fn next_matrix_identity_uses_the_adopted_metadata() {
    let initial = rng_metadata("matrix", 24_600, &image_id('d'));
    let adopted = rng_metadata("matrix", 24_600, &image_id('f'));
    let mut calls = 0;
    let result = run_matrix(
        initial.clone(),
        |_| Ok(()),
        |metadata, _, _| {
            calls += 1;
            if calls == 1 {
                assert_eq!(metadata, &initial);
                Ok(MatrixStep {
                    metadata: adopted.clone(),
                    adoption: None,
                })
            } else {
                assert_eq!(metadata, &adopted);
                Ok(MatrixStep {
                    metadata: metadata.clone(),
                    adoption: None,
                })
            }
        },
        |(), result| result,
    )
    .unwrap();
    assert_eq!(calls, 59);
    assert_eq!(result.metadata, adopted);
}

fn image_id(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn rng_metadata(project: &str, base: u16, rng_id: &str) -> StackMetadata {
    let root = Path::new("/repo");
    let project = Project::parse(project).unwrap();
    let mut metadata = StackMetadata::new(root, project.clone(), PortMap::from_base(base).unwrap());
    let fingerprint = "6".repeat(64);
    let source = BuildSource::new(
        "a".repeat(40),
        "1".repeat(64),
        ComposeHashes::new("2".repeat(64), "3".repeat(64)),
    );
    let fingerprints = BuildFingerprints::new(
        "4".repeat(64),
        "5".repeat(64),
        fingerprint.clone(),
        "7".repeat(64),
    );
    let tag = "mercurylayer/lockbox:bip448-test-6666666666666666";
    let mut images = ResolvedImages::default();
    images.set_lockbox(ResolvedLockboxImages::new(
        ResolvedImage::new(fingerprint.clone(), tag.into(), image_id('c')),
        ResolvedImage::new(fingerprint, format!("{tag}-rng-{project}"), rng_id.into()),
    ));
    metadata.set_build_resolution(BuildResolution::new(source, fingerprints, images));
    metadata
}

#[test]
fn rng_report_requires_exact_primary_history_and_unchanged_control() {
    let primary_initial = image_id('d');
    let primary_final = image_id('f');
    let control_id = image_id('e');
    let primary = rng_metadata("primary", 24_600, &primary_final);
    let control = rng_metadata("control", 24_608, &control_id);
    let build = BuildIdentityReport {
        production_image_ids: BTreeMap::new(),
        primary_rng_tag: "mercurylayer/lockbox:bip448-test-6666666666666666-rng-primary".into(),
        primary_rng_image_id: primary_initial.clone(),
        control_rng_tag: "mercurylayer/lockbox:bip448-test-6666666666666666-rng-control".into(),
        control_rng_image_id: control_id.clone(),
        same_source_and_fingerprints: true,
    };
    let adoption = RngAdoptionRecord {
        project: "primary".into(),
        target: RNG_RECONCILIATION_TARGET.into(),
        test: RNG_RECONCILIATION_TEST.into(),
        tag: build.primary_rng_tag.clone(),
        previous_image_id: primary_initial,
        adopted_image_id: primary_final.clone(),
    };
    let report = require_exact_rng_history(
        &build,
        &primary,
        &control,
        &control,
        std::slice::from_ref(&adoption),
    )
    .unwrap();
    assert_eq!(report.adoption_count, 1);
    assert_eq!(report.primary_final_image_id, primary_final);
    assert!(report.control_metadata_unchanged);

    let changed_control = rng_metadata("control", 24_608, &image_id('0'));
    assert!(
        require_exact_rng_history(&build, &primary, &control, &changed_control, &[adoption])
            .is_err()
    );
}

#[test]
fn cleanup_error_never_masks_primary_child_status() {
    let mut secondary = vec!["primary down".into(), "control down".into()];
    append_accounting_error(
        &mut secondary,
        Err(anyhow::anyhow!("daemon accounting drift")),
    );
    let error = attach_cleanup(WorkflowError::child_exit(37, "matrix failed"), secondary);
    assert_eq!(error.exit_code(), 37);
    assert!(error.to_string().contains("matrix failed"));
    assert!(error.to_string().contains("primary down; control down"));
    assert!(error.to_string().contains("daemon accounting drift"));
}

#[test]
fn failure_absence_and_global_accounting_are_both_preserved() {
    let error = combine_checks(
        Err(anyhow::anyhow!("mutable absence drift")),
        Err(anyhow::anyhow!("global daemon drift")),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("mutable absence drift"));
    assert!(format!("{error:#}").contains("global daemon drift"));
}

#[test]
fn cleanup_order_is_primary_then_control_and_both_are_attempted() {
    let mut order = Vec::new();
    let attempts = ordered_cleanup(Some("primary"), Some("control"), |role| {
        order.push(*role);
        if *role == "primary" {
            anyhow::bail!("primary cleanup failure")
        }
        Ok(())
    });
    assert_eq!(order, ["primary", "control"]);
    assert!(!attempts.primary_succeeded);
    assert!(attempts.control_succeeded);
    assert_eq!(attempts.errors.len(), 1);
}
