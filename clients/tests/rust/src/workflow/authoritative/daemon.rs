use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;

use super::super::argv::{record_failure, ArgvCommand, CommandRunner, SystemCommandRunner};
use super::super::model::{Project, StackMetadata};
use super::super::reset::{docker, images};
use super::super::test_runner::{
    RngAdoptionRecord, RNG_RECONCILIATION_TARGET, RNG_RECONCILIATION_TEST,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DaemonSnapshot {
    resources: docker::ResourceSets,
    image_ids: BTreeSet<String>,
    image_tags: BTreeMap<String, String>,
    cache_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DaemonAccounting {
    pub(super) global_resources_unchanged: bool,
    pub(super) image_ids_before: usize,
    pub(super) image_ids_after: usize,
    pub(super) added_image_ids: Vec<String>,
    pub(super) image_tags_before: usize,
    pub(super) image_tags_after: usize,
    pub(super) added_image_tags: BTreeMap<String, String>,
    pub(super) cache_records_before: usize,
    pub(super) cache_records_after: usize,
    pub(super) added_cache_records: Vec<String>,
    pub(super) prune_used: bool,
}

impl DaemonSnapshot {
    pub(super) fn capture(repo_root: &Path) -> Result<Self> {
        let mut runner = SystemCommandRunner;
        Ok(Self {
            resources: docker::global_resources(repo_root, &mut runner)?,
            image_ids: image_ids(repo_root, &mut runner)?,
            image_tags: images::image_tags(repo_root, &mut runner)?,
            cache_ids: cache_ids(repo_root, &mut runner)?,
        })
    }

    pub(super) fn account_final(
        &self,
        repo_root: &Path,
        primary: &StackMetadata,
        control: &StackMetadata,
        rng_adoptions: &[RngAdoptionRecord],
    ) -> Result<DaemonAccounting> {
        let after = Self::capture(repo_root)?;
        ensure!(
            after.resources == self.resources,
            "unrelated global Docker container/network/volume identities changed"
        );
        ensure!(
            self.image_ids.is_subset(&after.image_ids),
            "a pre-existing Docker image identity disappeared"
        );
        ensure!(
            self.cache_ids.is_subset(&after.cache_ids),
            "a pre-existing BuildKit cache record disappeared; prune or foreign mutation detected"
        );
        for (tag, id) in &self.image_tags {
            ensure!(
                after.image_tags.get(tag) == Some(id),
                "pre-existing Docker image tag changed or disappeared: {tag}"
            );
        }

        let expected = expected_tags(primary)?
            .into_iter()
            .chain(expected_tags(control)?)
            .collect::<BTreeMap<_, _>>();
        let added_image_tags = after
            .image_tags
            .iter()
            .filter(|(tag, _)| !self.image_tags.contains_key(*tag))
            .map(|(tag, id)| (tag.clone(), id.clone()))
            .collect::<BTreeMap<_, _>>();
        for (tag, id) in &added_image_tags {
            ensure!(
                expected.get(tag) == Some(id),
                "unaccounted Docker image tag/ID appeared: {tag} -> {id}"
            );
        }
        for (tag, id) in &expected {
            ensure!(
                after.image_tags.get(tag) == Some(id),
                "recorded build image tag/ID is absent at final accounting: {tag}"
            );
        }
        for project in [primary.project(), control.project()] {
            let staging = format!("b448-stage-{project}-");
            ensure!(
                after.image_tags.keys().all(|tag| !tag.contains(&staging)),
                "project staging image tag survived authoritative build: {project}"
            );
        }

        let expected_ids = expected.values().cloned().collect::<BTreeSet<_>>();
        let authorized_superseded_ids =
            authorized_superseded_rng_ids(primary, control, rng_adoptions)?;
        let added_image_ids = after
            .image_ids
            .difference(&self.image_ids)
            .cloned()
            .collect::<Vec<_>>();
        require_allowed_added_image_ids(
            &added_image_ids,
            &expected_ids,
            &authorized_superseded_ids,
        )?;
        let added_cache_records = after
            .cache_ids
            .difference(&self.cache_ids)
            .cloned()
            .collect::<Vec<_>>();
        Ok(DaemonAccounting {
            global_resources_unchanged: true,
            image_ids_before: self.image_ids.len(),
            image_ids_after: after.image_ids.len(),
            added_image_ids,
            image_tags_before: self.image_tags.len(),
            image_tags_after: after.image_tags.len(),
            added_image_tags,
            cache_records_before: self.cache_ids.len(),
            cache_records_after: after.cache_ids.len(),
            added_cache_records,
            prune_used: false,
        })
    }
}

fn authorized_superseded_rng_ids(
    primary: &StackMetadata,
    control: &StackMetadata,
    adoptions: &[RngAdoptionRecord],
) -> Result<BTreeSet<String>> {
    let mut superseded = BTreeSet::new();
    for adoption in adoptions {
        ensure!(
            adoption.target == RNG_RECONCILIATION_TARGET
                && adoption.test == RNG_RECONCILIATION_TEST,
            "image accounting received an unauthorized RNG adoption identity"
        );
        let metadata = if adoption.project == primary.project().as_str() {
            primary
        } else if adoption.project == control.project().as_str() {
            control
        } else {
            bail!(
                "image accounting RNG adoption names an unknown project: {}",
                adoption.project
            )
        };
        let final_rng = metadata
            .build_resolution()
            .and_then(|build| build.images().lockbox())
            .context("final deterministic RNG build metadata is absent")?
            .deterministic_rng();
        ensure!(
            adoption.tag == final_rng.tag()
                && adoption.adopted_image_id == final_rng.image_id()
                && adoption.previous_image_id != adoption.adopted_image_id,
            "RNG adoption history does not terminate at the exact recorded project image"
        );
        validate_image_id(&adoption.previous_image_id)?;
        validate_image_id(&adoption.adopted_image_id)?;
        ensure!(
            superseded.insert(adoption.previous_image_id.clone()),
            "duplicate superseded deterministic RNG image identity"
        );
    }
    Ok(superseded)
}

fn require_allowed_added_image_ids(
    added: &[String],
    final_ids: &BTreeSet<String>,
    authorized_superseded_ids: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        added
            .iter()
            .all(|id| final_ids.contains(id) || authorized_superseded_ids.contains(id)),
        "Docker image identities changed beyond final builds and exact authorized superseded RNG history"
    );
    Ok(())
}

pub(super) fn require_project_absent(repo_root: &Path, project: &Project) -> Result<()> {
    let mut runner = SystemCommandRunner;
    let resources = docker::project_resources(repo_root, project, &mut runner)?;
    ensure!(
        resources.is_empty(),
        "Compose project {project} already has Docker resources: {resources:?}"
    );
    Ok(())
}

pub(super) fn require_projects_disjoint(
    repo_root: &Path,
    primary: &Project,
    control: &Project,
) -> Result<()> {
    let mut runner = SystemCommandRunner;
    let primary = docker::project_resources(repo_root, primary, &mut runner)?;
    let control = docker::project_resources(repo_root, control, &mut runner)?;
    ensure!(
        !primary.is_empty() && !control.is_empty() && primary.is_disjoint(&control),
        "primary/control container, network, declared-volume, or anonymous-volume identities are not complete and disjoint"
    );
    Ok(())
}

fn expected_tags(metadata: &StackMetadata) -> Result<BTreeMap<String, String>> {
    let build = metadata
        .build_resolution()
        .context("authoritative image accounting requires complete build metadata")?;
    let images = build.images();
    let mut tags = BTreeMap::new();
    for image in [images.mercury(), images.token(), images.inquisition()]
        .into_iter()
        .flatten()
    {
        tags.insert(image.tag().to_owned(), image.image_id().to_owned());
    }
    let lockbox = images
        .lockbox()
        .context("authoritative image accounting requires lockbox images")?;
    for image in [lockbox.production(), lockbox.deterministic_rng()] {
        tags.insert(image.tag().to_owned(), image.image_id().to_owned());
    }
    ensure!(
        tags.len() == 5,
        "build metadata does not contain five exact image tags"
    );
    Ok(tags)
}

fn image_ids(repo_root: &Path, runner: &mut impl CommandRunner) -> Result<BTreeSet<String>> {
    let output = checked(
        runner,
        ArgvCommand::new("docker", repo_root).args([
            "image",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
        ]),
    )?;
    let text = String::from_utf8(output).context("Docker image identity list is not UTF-8")?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|id| {
            validate_image_id(id)?;
            Ok(id.to_owned())
        })
        .collect()
}

fn cache_ids(repo_root: &Path, runner: &mut impl CommandRunner) -> Result<BTreeSet<String>> {
    let output = checked(
        runner,
        ArgvCommand::new("docker", repo_root).args(["buildx", "du", "--format", "{{json .}}"]),
    )?;
    let text = String::from_utf8(output).context("BuildKit cache list is not UTF-8")?;
    let mut ids = BTreeSet::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: serde_json::Value =
            serde_json::from_str(line).context("parse BuildKit cache JSON row")?;
        let id = value
            .get("ID")
            .and_then(serde_json::Value::as_str)
            .context("BuildKit cache row has no string ID")?;
        ensure!(
            (1..=128).contains(&id.len())
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
            "BuildKit cache identity is malformed"
        );
        ensure!(
            ids.insert(id.to_owned()),
            "duplicate BuildKit cache identity"
        );
    }
    Ok(ids)
}

fn checked(runner: &mut impl CommandRunner, command: ArgvCommand) -> Result<Vec<u8>> {
    let output = runner.run(&command)?;
    if !output.success {
        record_failure(&command, &output);
        bail!(
            "Docker inventory command failed with status {:?}: {}",
            output.code,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    ensure!(
        output.code == Some(0) && output.signal.is_none() && output.stderr.is_empty(),
        "Docker inventory command returned a non-canonical success"
    );
    Ok(output.stdout)
}

fn validate_image_id(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("Docker image ID lacks sha256 prefix")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Docker image ID is malformed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::model::{
        BuildFingerprints, BuildResolution, BuildSource, ComposeHashes, PortMap, ResolvedImage,
        ResolvedImages, ResolvedLockboxImages,
    };

    fn id(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn rng_metadata(project: &str, base: u16, rng_id: &str) -> StackMetadata {
        let root = Path::new("/repo");
        let project = Project::parse(project).unwrap();
        let mut metadata =
            StackMetadata::new(root, project.clone(), PortMap::from_base(base).unwrap());
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
            ResolvedImage::new(fingerprint.clone(), tag.into(), id('c')),
            ResolvedImage::new(fingerprint, format!("{tag}-rng-{project}"), rng_id.into()),
        ));
        metadata.set_build_resolution(BuildResolution::new(source, fingerprints, images));
        metadata
    }

    fn adoption(project: &str, tag: &str, previous: &str, adopted: &str) -> RngAdoptionRecord {
        RngAdoptionRecord {
            project: project.into(),
            target: RNG_RECONCILIATION_TARGET.into(),
            test: RNG_RECONCILIATION_TEST.into(),
            tag: tag.into(),
            previous_image_id: previous.into(),
            adopted_image_id: adopted.into(),
        }
    }

    #[test]
    fn daemon_accepts_only_final_or_authorized_superseded_image_ids() {
        let primary = rng_metadata("primary", 24_600, &id('b'));
        let control = rng_metadata("control", 24_608, &id('e'));
        let tag = primary
            .build_resolution()
            .unwrap()
            .images()
            .lockbox()
            .unwrap()
            .deterministic_rng()
            .tag();
        let history = [adoption("primary", tag, &id('a'), &id('b'))];
        let superseded = authorized_superseded_rng_ids(&primary, &control, &history).unwrap();
        assert_eq!(superseded, BTreeSet::from([id('a')]));

        let final_ids = BTreeSet::from([id('b'), id('e')]);
        require_allowed_added_image_ids(&[id('a'), id('b'), id('e')], &final_ids, &superseded)
            .unwrap();
        assert!(require_allowed_added_image_ids(
            &[id('a'), id('b'), id('e'), id('d')],
            &final_ids,
            &superseded,
        )
        .is_err());

        let unknown = [adoption("unknown", tag, &id('a'), &id('b'))];
        assert!(authorized_superseded_rng_ids(&primary, &control, &unknown).is_err());
        let mut wrong_identity = history[0].clone();
        wrong_identity.test = "not-the-authorized-test".into();
        assert!(authorized_superseded_rng_ids(&primary, &control, &[wrong_identity]).is_err());
    }
}
