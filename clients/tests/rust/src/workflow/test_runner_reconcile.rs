use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use super::super::build::{self, CommandRunner};
use super::super::model::StackMetadata;
use super::super::ready_gate::ReadyGate;
use super::super::storage;

pub(in crate::workflow) const RNG_RECONCILIATION_TARGET: &str = "lockbox_compatibility";
pub(in crate::workflow) const RNG_RECONCILIATION_TEST: &str =
    "deterministic_lockbox_vectors_match_golden_outputs";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::workflow) struct RngAdoptionRecord {
    pub(in crate::workflow) project: String,
    pub(in crate::workflow) target: String,
    pub(in crate::workflow) test: String,
    pub(in crate::workflow) tag: String,
    pub(in crate::workflow) previous_image_id: String,
    pub(in crate::workflow) adopted_image_id: String,
}

#[derive(Debug)]
pub(super) struct BoundaryOutcome {
    pub(super) metadata: StackMetadata,
    pub(super) adoption: Option<RngAdoptionRecord>,
}

pub(super) fn after_success(
    repo_root: &Path,
    metadata: &StackMetadata,
    target: &str,
    test: &str,
    runner: &mut impl CommandRunner,
    gate: &mut impl ReadyGate,
) -> Result<BoundaryOutcome> {
    if !is_rng_reconciliation_identity(target, test) {
        gate.require_ready(repo_root, metadata)
            .context("require exact ready stack after successful BIP448 test")?;
        return Ok(BoundaryOutcome {
            metadata: metadata.clone(),
            adoption: None,
        });
    }

    let replacement = build::inspect_rng_replacement(repo_root, metadata, runner)
        .context("authenticate deterministic RNG image replacement")?;
    commit_and_ready(
        metadata,
        replacement,
        |expected, updated| {
            storage::replace_metadata(repo_root, expected.project(), expected, updated)
                .context("atomically adopt deterministic RNG image metadata")
        },
        |updated| {
            gate.require_ready(repo_root, updated)
                .context("require exact ready stack after deterministic RNG adoption")?;
            Ok(())
        },
    )
}

fn is_rng_reconciliation_identity(target: &str, test: &str) -> bool {
    target == RNG_RECONCILIATION_TARGET && test == RNG_RECONCILIATION_TEST
}

fn commit_and_ready(
    expected: &StackMetadata,
    replacement: build::RngImageReplacement,
    commit: impl FnOnce(&StackMetadata, &StackMetadata) -> Result<()>,
    ready: impl FnOnce(&StackMetadata) -> Result<()>,
) -> Result<BoundaryOutcome> {
    commit(expected, &replacement.metadata)?;
    ready(&replacement.metadata)?;
    Ok(BoundaryOutcome {
        metadata: replacement.metadata,
        adoption: Some(RngAdoptionRecord {
            project: expected.project().to_string(),
            target: RNG_RECONCILIATION_TARGET.into(),
            test: RNG_RECONCILIATION_TEST.into(),
            tag: replacement.tag,
            previous_image_id: replacement.previous_image_id,
            adopted_image_id: replacement.adopted_image_id,
        }),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::workflow::model::{
        BuildFingerprints, BuildResolution, BuildSource, ComposeHashes, PortMap, Project,
        ResolvedImage, ResolvedImages, ResolvedLockboxImages,
    };

    fn metadata(project: &str) -> StackMetadata {
        StackMetadata::new(
            Path::new("/repo"),
            Project::parse(project).unwrap(),
            PortMap::from_base(24_600).unwrap(),
        )
    }

    fn replacement() -> build::RngImageReplacement {
        build::RngImageReplacement {
            metadata: metadata("primary"),
            tag: "rng-tag".into(),
            previous_image_id: format!("sha256:{}", "a".repeat(64)),
            adopted_image_id: format!("sha256:{}", "b".repeat(64)),
        }
    }

    fn image_id(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn built_metadata(root: &Path, project: &str, rng_id: &str) -> StackMetadata {
        let project = Project::parse(project).unwrap();
        let mut metadata =
            StackMetadata::new(root, project.clone(), PortMap::from_base(24_600).unwrap());
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
    fn reconciliation_identity_is_one_exact_matrix_pair() {
        assert!(is_rng_reconciliation_identity(
            RNG_RECONCILIATION_TARGET,
            RNG_RECONCILIATION_TEST
        ));
        for (target, test) in [
            ("functional", RNG_RECONCILIATION_TEST),
            (RNG_RECONCILIATION_TARGET, "substring"),
            ("lockbox_compatibility_extra", RNG_RECONCILIATION_TEST),
        ] {
            assert!(!is_rng_reconciliation_identity(target, test));
        }
    }

    #[test]
    fn cas_race_fails_before_ready_and_never_returns_adopted_metadata() {
        let expected = metadata("primary");
        let ready_called = Cell::new(false);
        let error = commit_and_ready(
            &expected,
            replacement(),
            |observed, _| {
                assert_eq!(observed, &expected);
                anyhow::bail!("simulated metadata CAS race")
            },
            |_| {
                ready_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("CAS race"));
        assert!(!ready_called.get());
    }

    #[test]
    fn real_metadata_cas_rejects_a_racing_exact_rng_update() {
        let root =
            std::env::temp_dir().join(format!("bip448-rng-cas-race-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let expected = built_metadata(&root, "cas-race", &image_id('d'));
        storage::create_run(&expected).unwrap();
        let contender = built_metadata(&root, "cas-race", &image_id('e'));
        storage::replace_metadata(&root, expected.project(), &expected, &contender).unwrap();
        let adopted = built_metadata(&root, "cas-race", &image_id('f'));
        let replacement = build::RngImageReplacement {
            metadata: adopted,
            tag: "mercurylayer/lockbox:bip448-test-6666666666666666-rng-cas-race".into(),
            previous_image_id: image_id('d'),
            adopted_image_id: image_id('f'),
        };
        let ready_called = Cell::new(false);
        let error = commit_and_ready(
            &expected,
            replacement,
            |observed, updated| {
                storage::replace_metadata(&root, observed.project(), observed, updated)
            },
            |_| {
                ready_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("stack metadata changed"));
        assert!(!ready_called.get());
        assert_eq!(
            storage::status(&root, expected.project()).unwrap(),
            contender
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn successful_cas_readies_and_returns_only_adopted_metadata() {
        let expected = metadata("primary");
        let adopted = replacement().metadata.clone();
        let outcome = commit_and_ready(
            &expected,
            replacement(),
            |observed, updated| {
                assert_eq!(observed, &expected);
                assert_eq!(updated, &adopted);
                Ok(())
            },
            |updated| {
                assert_eq!(updated, &adopted);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(outcome.metadata, adopted);
        assert_eq!(outcome.adoption.unwrap().project, "primary");
    }
}
