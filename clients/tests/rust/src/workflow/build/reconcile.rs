use std::path::Path;

use anyhow::{ensure, Context, Result};

use super::super::model::{BuildResolution, ResolvedImage, ResolvedLockboxImages, StackMetadata};
use super::execute::image_id;
use super::fingerprint::{snapshot, BuildSnapshot};
use super::CommandRunner;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::workflow) struct RngImageReplacement {
    pub(in crate::workflow) metadata: StackMetadata,
    pub(in crate::workflow) tag: String,
    pub(in crate::workflow) previous_image_id: String,
    pub(in crate::workflow) adopted_image_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedImages {
    mercury: String,
    token: String,
    lockbox: String,
    lockbox_rng: String,
    inquisition: String,
}

pub(in crate::workflow) fn inspect_rng_replacement(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<RngImageReplacement> {
    let before = snapshot(repo_root, runner)
        .context("reauthenticate source before deterministic RNG reconciliation")?;
    let recorded = complete_images(metadata)?;
    let observed = ObservedImages {
        mercury: required_image_id(repo_root, recorded.mercury().unwrap().tag(), runner)?,
        token: required_image_id(repo_root, recorded.token().unwrap().tag(), runner)?,
        lockbox: required_image_id(
            repo_root,
            recorded.lockbox().unwrap().production().tag(),
            runner,
        )?,
        lockbox_rng: required_image_id(
            repo_root,
            recorded.lockbox().unwrap().deterministic_rng().tag(),
            runner,
        )?,
        inquisition: required_image_id(repo_root, recorded.inquisition().unwrap().tag(), runner)?,
    };
    let after = snapshot(repo_root, runner)
        .context("reauthenticate source after deterministic RNG image inspection")?;
    ensure!(
        before == after,
        "source or build fingerprints changed during deterministic RNG reconciliation"
    );
    plan_replacement(repo_root, metadata, &after, &observed)
}

fn complete_images(metadata: &StackMetadata) -> Result<&super::super::model::ResolvedImages> {
    let images = metadata
        .build_resolution()
        .context("deterministic RNG reconciliation requires complete build metadata")?
        .images();
    ensure!(
        images.mercury().is_some()
            && images.token().is_some()
            && images.lockbox().is_some()
            && images.inquisition().is_some(),
        "deterministic RNG reconciliation requires all five recorded image identities"
    );
    Ok(images)
}

fn required_image_id(
    repo_root: &Path,
    tag: &str,
    runner: &mut impl CommandRunner,
) -> Result<String> {
    image_id(repo_root, tag, runner)?
        .with_context(|| format!("required reconciled image tag is absent: {tag}"))
}

fn plan_replacement(
    repo_root: &Path,
    metadata: &StackMetadata,
    current: &BuildSnapshot,
    observed: &ObservedImages,
) -> Result<RngImageReplacement> {
    metadata.validate(repo_root, metadata.project())?;
    let resolution = metadata
        .build_resolution()
        .context("deterministic RNG reconciliation requires build metadata")?;
    ensure!(
        resolution.source() == &current.source
            && resolution.fingerprints() == &current.fingerprints,
        "source or build fingerprints differ from recorded metadata during RNG reconciliation"
    );
    let images = complete_images(metadata)?;
    let lockbox = images.lockbox().unwrap();
    for (label, actual, expected) in [
        ("Mercury", &observed.mercury, images.mercury().unwrap()),
        ("token", &observed.token, images.token().unwrap()),
        (
            "production lockbox",
            &observed.lockbox,
            lockbox.production(),
        ),
        (
            "Inquisition",
            &observed.inquisition,
            images.inquisition().unwrap(),
        ),
    ] {
        ensure!(
            actual == expected.image_id(),
            "immutable {label} image tag/ID changed during deterministic RNG reconciliation"
        );
    }

    let previous = lockbox.deterministic_rng();
    ensure!(
        observed.lockbox_rng != previous.image_id(),
        "deterministic vector test did not replace its exact project RNG image identity"
    );
    let replacement = ResolvedImage::new(
        previous.fingerprint().to_owned(),
        previous.tag().to_owned(),
        observed.lockbox_rng.clone(),
    );
    let mut updated_images = images.clone();
    updated_images.set_lockbox(ResolvedLockboxImages::new(
        lockbox.production().clone(),
        replacement,
    ));
    let mut updated = metadata.clone();
    updated.set_build_resolution(BuildResolution::new(
        resolution.source().clone(),
        resolution.fingerprints().clone(),
        updated_images,
    ));
    updated.validate(repo_root, metadata.project())?;
    require_exact_one_field_change(metadata, &updated)?;

    Ok(RngImageReplacement {
        metadata: updated,
        tag: previous.tag().to_owned(),
        previous_image_id: previous.image_id().to_owned(),
        adopted_image_id: observed.lockbox_rng.clone(),
    })
}

fn require_exact_one_field_change(before: &StackMetadata, after: &StackMetadata) -> Result<()> {
    let mut expected = serde_json::to_value(before)?;
    let actual = serde_json::to_value(after)?;
    let adopted = actual
        .pointer("/build/images/lockbox/deterministic_rng/image_id")
        .cloned()
        .context("updated metadata has no deterministic RNG image ID")?;
    let expected_id = expected
        .pointer_mut("/build/images/lockbox/deterministic_rng/image_id")
        .context("recorded metadata has no deterministic RNG image ID")?;
    *expected_id = adopted;
    ensure!(
        expected == actual,
        "RNG reconciliation changed metadata beyond deterministic_rng.image_id"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::model::{
        BuildFingerprints, BuildSource, ComposeHashes, PortMap, Project, ResolvedImages,
    };

    fn id(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn source(head: char) -> BuildSource {
        BuildSource::new(
            head.to_string().repeat(40),
            "1".repeat(64),
            ComposeHashes::new("2".repeat(64), "3".repeat(64)),
        )
    }

    fn fingerprints(lockbox: char) -> BuildFingerprints {
        BuildFingerprints::new(
            "4".repeat(64),
            "5".repeat(64),
            lockbox.to_string().repeat(64),
            "7".repeat(64),
        )
    }

    fn fixture() -> (StackMetadata, BuildSnapshot, ObservedImages) {
        let root = Path::new("/repo");
        let project = Project::parse("reconcile").unwrap();
        let mut metadata =
            StackMetadata::new(root, project.clone(), PortMap::from_base(24600).unwrap());
        let source = source('a');
        let fingerprints = fingerprints('6');
        let mut images = ResolvedImages::default();
        images.set_mercury(ResolvedImage::new(
            fingerprints.mercury().into(),
            "mercurylayer/mercury-server:bip448-test-4444444444444444".into(),
            id('a'),
        ));
        images.set_token(ResolvedImage::new(
            fingerprints.token().into(),
            "mercurylayer/token-server-v2:bip448-test-5555555555555555".into(),
            id('b'),
        ));
        images.set_lockbox(ResolvedLockboxImages::new(
            ResolvedImage::new(
                fingerprints.lockbox().into(),
                "mercurylayer/lockbox:bip448-test-6666666666666666".into(),
                id('c'),
            ),
            ResolvedImage::new(
                fingerprints.lockbox().into(),
                format!("mercurylayer/lockbox:bip448-test-6666666666666666-rng-{project}"),
                id('d'),
            ),
        ));
        images.set_inquisition(ResolvedImage::new(
            fingerprints.inquisition().into(),
            crate::workflow::model::INQUISITION_IMAGE.into(),
            id('e'),
        ));
        metadata.set_build_resolution(BuildResolution::new(
            source.clone(),
            fingerprints.clone(),
            images,
        ));
        let snapshot = BuildSnapshot {
            source,
            fingerprints,
        };
        let observed = ObservedImages {
            mercury: id('a'),
            token: id('b'),
            lockbox: id('c'),
            lockbox_rng: id('f'),
            inquisition: id('e'),
        };
        (metadata, snapshot, observed)
    }

    #[test]
    fn replacement_changes_exactly_one_metadata_field() {
        let (metadata, snapshot, observed) = fixture();
        let replacement =
            plan_replacement(Path::new("/repo"), &metadata, &snapshot, &observed).unwrap();
        require_exact_one_field_change(&metadata, &replacement.metadata).unwrap();
        assert_eq!(replacement.previous_image_id, id('d'));
        assert_eq!(replacement.adopted_image_id, id('f'));
    }

    #[test]
    fn source_fingerprint_and_every_immutable_image_drift_are_rejected() {
        let (metadata, snapshot, observed) = fixture();
        let mut source_drift = snapshot.clone();
        source_drift.source = source('b');
        assert!(plan_replacement(Path::new("/repo"), &metadata, &source_drift, &observed).is_err());

        let mut fingerprint_drift = snapshot.clone();
        fingerprint_drift.fingerprints = fingerprints('8');
        assert!(
            plan_replacement(Path::new("/repo"), &metadata, &fingerprint_drift, &observed).is_err()
        );

        for field in 0..4 {
            let mut drift = observed.clone();
            match field {
                0 => drift.mercury = id('0'),
                1 => drift.token = id('0'),
                2 => drift.lockbox = id('0'),
                _ => drift.inquisition = id('0'),
            }
            assert!(plan_replacement(Path::new("/repo"), &metadata, &snapshot, &drift).is_err());
        }
    }
}
