use std::collections::BTreeMap;

use super::super::cli::BuildService;
use super::super::model::{BuildFingerprints, BuildSource, ComposeHashes, Project};
use super::fingerprint::BuildSnapshot;
use super::plan::{plan_build, selected_artifacts, Artifact, PlanAction};
use super::test_support::MockRunner;

const NONCE: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn service_selection_is_exact_and_lockbox_selects_both_variants() {
    assert_eq!(
        selected_artifacts(BuildService::All),
        &[
            Artifact::Mercury,
            Artifact::Token,
            Artifact::Lockbox,
            Artifact::LockboxRng,
            Artifact::Inquisition,
        ]
    );
    assert_eq!(
        selected_artifacts(BuildService::Mercury),
        &[Artifact::Mercury]
    );
    assert_eq!(selected_artifacts(BuildService::Token), &[Artifact::Token]);
    assert_eq!(
        selected_artifacts(BuildService::Lockbox),
        &[Artifact::Lockbox, Artifact::LockboxRng]
    );
    assert_eq!(
        selected_artifacts(BuildService::Inquisition),
        &[Artifact::Inquisition]
    );
}

#[test]
fn planner_distinguishes_cache_hits_and_unique_staging_misses() {
    let snapshot = snapshot();
    let project = Project::parse("planner_1").unwrap();
    let mut observed = BTreeMap::from([
        (Artifact::Lockbox, Some(MockRunner::image_id(1))),
        (Artifact::LockboxRng, None),
    ]);
    let plan = plan_build(BuildService::Lockbox, &project, &snapshot, &observed, NONCE).unwrap();
    assert!(matches!(
        &plan.images[0].action,
        PlanAction::CacheHit { image_id } if image_id == &MockRunner::image_id(1)
    ));
    let PlanAction::Build { staging_tag } = &plan.images[1].action else {
        panic!("RNG miss was not planned as a build")
    };
    assert!(staging_tag.contains("b448-stage-planner_1-"));
    assert!(staging_tag.contains(NONCE));
    assert!(staging_tag.ends_with("-lockbox-rng"));
    assert!(plan.images[1].final_tag.ends_with("-rng-planner_1"));

    observed.remove(&Artifact::LockboxRng);
    assert!(plan_build(BuildService::Lockbox, &project, &snapshot, &observed, NONCE).is_err());
    assert!(plan_build(
        BuildService::Lockbox,
        &project,
        &snapshot,
        &BTreeMap::from([(Artifact::Lockbox, None), (Artifact::LockboxRng, None)]),
        "not-a-uuid"
    )
    .is_err());
}

#[test]
fn inquisition_plans_only_the_pinned_final_tag() {
    let snapshot = snapshot();
    let plan = plan_build(
        BuildService::Inquisition,
        &Project::parse("pinned").unwrap(),
        &snapshot,
        &BTreeMap::from([(Artifact::Inquisition, None)]),
        NONCE,
    )
    .unwrap();
    assert_eq!(
        plan.images[0].final_tag,
        "mercurylayer/bitcoin-inquisition:f536586"
    );
}

fn snapshot() -> BuildSnapshot {
    BuildSnapshot {
        source: BuildSource::new(
            "0".repeat(40),
            "1".repeat(64),
            ComposeHashes::new("2".repeat(64), "3".repeat(64)),
        ),
        fingerprints: BuildFingerprints::new(
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
        ),
    }
}
