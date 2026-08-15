use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use uuid::Uuid;

use super::super::cli::BuildService;
use super::super::model::{
    BuildResolution, Project, ResolvedImage, ResolvedImages, ResolvedLockboxImages, StackMetadata,
};
use super::fingerprint::{snapshot, BuildSnapshot};
use super::plan::{plan_build, selected_artifacts, Artifact, PlanAction};
use super::{
    run_checked, ArgvCommand, CommandRunner, VerifiedBuild, VerifiedImage, INQUISITION_BUILD_ARG,
    INQUISITION_COMMIT, LOCKBOX_BUILD_ARG,
};

pub(super) fn execute(
    repo_root: &Path,
    metadata: &StackMetadata,
    service: BuildService,
    runner: &mut impl CommandRunner,
) -> Result<StackMetadata> {
    ensure_no_project_containers(repo_root, metadata.project(), runner)?;
    let initial = snapshot(repo_root, runner)?;

    let mut images = match metadata.build_resolution() {
        Some(previous) => {
            ensure!(
                previous.source() == &initial.source
                    && previous.fingerprints() == &initial.fingerprints,
                "current source does not match the source recorded in stack metadata"
            );
            validate_recorded_images(repo_root, previous.images(), runner)?;
            previous.images().clone()
        }
        None => ResolvedImages::default(),
    };

    let mut observed = BTreeMap::new();
    for artifact in selected_artifacts(service) {
        let tag = artifact.final_tag(metadata.project(), &initial);
        observed.insert(*artifact, image_id(repo_root, &tag, runner)?);
    }

    validate_selected_recorded_images(&images, service, metadata.project(), &initial, &observed)?;

    let nonce = Uuid::new_v4().simple().to_string();
    let plan = plan_build(service, metadata.project(), &initial, &observed, &nonce)?;
    let mut staging_tags = Vec::new();
    let operation = (|| {
        let mut staged_ids = BTreeMap::new();
        for image in &plan.images {
            let PlanAction::Build { staging_tag } = &image.action else {
                continue;
            };
            ensure!(
                image_id(repo_root, staging_tag, runner)?.is_none(),
                "unique staging image tag unexpectedly already exists: {staging_tag}"
            );
            staging_tags.push(staging_tag.clone());
            run_checked(
                runner,
                build_command(repo_root, image.artifact, staging_tag),
            )
            .with_context(|| format!("build {} image", image.artifact.label()))?;
            let id = image_id(repo_root, staging_tag, runner)?.with_context(|| {
                format!("build did not create exact staging image tag {staging_tag}")
            })?;
            staged_ids.insert(image.artifact, id);
        }

        if !staged_ids.is_empty() {
            let after_build = snapshot(repo_root, runner)?;
            ensure!(
                after_build == initial,
                "build inputs or source state changed while images were building"
            );
        }

        let mut resolved = BTreeMap::new();
        for image in &plan.images {
            let id = match &image.action {
                PlanAction::CacheHit { image_id } => image_id.clone(),
                PlanAction::Build { staging_tag } => {
                    let staging_id = staged_ids
                        .get(&image.artifact)
                        .context("staged image ID is missing")?;
                    match image_id(repo_root, &image.final_tag, runner)? {
                        None => {
                            run_checked(
                                runner,
                                docker_command(repo_root)
                                    .args(["image", "tag"])
                                    .arg(staging_tag)
                                    .arg(&image.final_tag),
                            )
                            .with_context(|| {
                                format!(
                                    "promote staging image {staging_tag} to {}",
                                    image.final_tag
                                )
                            })?;
                        }
                        Some(final_id) if final_id == *staging_id => {}
                        Some(final_id) => bail!(
                            "refusing to overwrite colliding final image tag {}: staged ID {}, present ID {}",
                            image.final_tag,
                            staging_id,
                            final_id
                        ),
                    }
                    let promoted = image_id(repo_root, &image.final_tag, runner)?
                        .context("promoted final image tag is absent")?;
                    ensure!(
                        promoted == *staging_id,
                        "promoted final image tag {} has unexpected ID {promoted}",
                        image.final_tag
                    );
                    promoted
                }
            };
            resolved.insert(image.artifact, id);
        }

        for image in &plan.images {
            let expected = resolved
                .get(&image.artifact)
                .context("resolved image ID is missing")?;
            let actual = image_id(repo_root, &image.final_tag, runner)?
                .with_context(|| format!("final image tag {} disappeared", image.final_tag))?;
            ensure!(
                actual == *expected,
                "final image tag {} changed IDs during build resolution",
                image.final_tag
            );
        }
        Ok::<_, anyhow::Error>(resolved)
    })();

    let cleanup = cleanup_staging_tags(repo_root, &staging_tags, runner);
    let resolved = match (operation, cleanup) {
        (Ok(resolved), Ok(())) => resolved,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(cleanup)) => return Err(cleanup.context("clean staging image tags")),
        (Err(error), Err(cleanup)) => {
            bail!("{error:#}; cleanup of exact staging tags also failed: {cleanup:#}")
        }
    };

    let final_snapshot = snapshot(repo_root, runner)?;
    ensure!(
        final_snapshot == initial,
        "build inputs or source state changed before metadata resolution"
    );

    record_selected_images(
        &mut images,
        service,
        metadata.project(),
        &initial,
        &resolved,
    )?;
    validate_recorded_images(repo_root, &images, runner)?;
    let mut updated = metadata.clone();
    updated.set_build_resolution(BuildResolution::new(
        initial.source,
        initial.fingerprints,
        images,
    ));
    updated.validate(repo_root, metadata.project())?;
    Ok(updated)
}

pub(super) fn verify_complete(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<VerifiedBuild> {
    let current = snapshot(repo_root, runner)?;
    let resolution = metadata
        .build_resolution()
        .context("all BIP448 stack images must be resolved before lifecycle operations")?;
    ensure!(
        resolution.source() == &current.source
            && resolution.fingerprints() == &current.fingerprints,
        "current source does not match the complete build recorded in stack metadata"
    );
    validate_recorded_images(repo_root, resolution.images(), runner)?;

    let resolved = resolution.images();
    let image = |value: &ResolvedImage| VerifiedImage {
        tag: value.tag().to_owned(),
        image_id: value.image_id().to_owned(),
    };
    let lockbox = resolved
        .lockbox()
        .context("lockbox and deterministic RNG images are not resolved")?;
    Ok(VerifiedBuild {
        mercury: image(
            resolved
                .mercury()
                .context("Mercury image is not resolved")?,
        ),
        token: image(resolved.token().context("token image is not resolved")?),
        lockbox: image(lockbox.production()),
        lockbox_rng: image(lockbox.deterministic_rng()),
        inquisition: image(
            resolved
                .inquisition()
                .context("Inquisition image is not resolved")?,
        ),
    })
}

fn validate_selected_recorded_images(
    recorded: &ResolvedImages,
    service: BuildService,
    project: &Project,
    snapshot: &BuildSnapshot,
    observed: &BTreeMap<Artifact, Option<String>>,
) -> Result<()> {
    for artifact in selected_artifacts(service) {
        let Some(expected) = recorded_image(recorded, *artifact) else {
            continue;
        };
        ensure!(
            expected.fingerprint() == artifact.fingerprint(snapshot)
                && expected.tag() == artifact.final_tag(project, snapshot),
            "selected image does not match its recorded source fingerprint and tag"
        );
        let present = observed
            .get(artifact)
            .context("selected image observation is missing")?
            .as_deref();
        ensure!(
            present == Some(expected.image_id()),
            "selected image tag {} is absent or has changed from recorded ID {}",
            expected.tag(),
            expected.image_id()
        );
    }
    Ok(())
}

fn validate_recorded_images(
    repo_root: &Path,
    recorded: &ResolvedImages,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    for artifact in [
        Artifact::Mercury,
        Artifact::Token,
        Artifact::Lockbox,
        Artifact::LockboxRng,
        Artifact::Inquisition,
    ] {
        let Some(expected) = recorded_image(recorded, artifact) else {
            continue;
        };
        let actual = image_id(repo_root, expected.tag(), runner)?;
        ensure!(
            actual.as_deref() == Some(expected.image_id()),
            "recorded image tag {} is absent or has changed from exact ID {}",
            expected.tag(),
            expected.image_id()
        );
    }
    Ok(())
}

fn recorded_image(images: &ResolvedImages, artifact: Artifact) -> Option<&ResolvedImage> {
    match artifact {
        Artifact::Mercury => images.mercury(),
        Artifact::Token => images.token(),
        Artifact::Lockbox => images.lockbox().map(ResolvedLockboxImages::production),
        Artifact::LockboxRng => images
            .lockbox()
            .map(ResolvedLockboxImages::deterministic_rng),
        Artifact::Inquisition => images.inquisition(),
    }
}

fn record_selected_images(
    images: &mut ResolvedImages,
    service: BuildService,
    project: &Project,
    snapshot: &BuildSnapshot,
    resolved: &BTreeMap<Artifact, String>,
) -> Result<()> {
    let resolved_image = |artifact: Artifact| -> Result<ResolvedImage> {
        Ok(ResolvedImage::new(
            artifact.fingerprint(snapshot).to_owned(),
            artifact.final_tag(project, snapshot),
            resolved
                .get(&artifact)
                .with_context(|| format!("missing resolved {} image", artifact.label()))?
                .clone(),
        ))
    };
    match service {
        BuildService::All => {
            images.set_mercury(resolved_image(Artifact::Mercury)?);
            images.set_token(resolved_image(Artifact::Token)?);
            images.set_lockbox(ResolvedLockboxImages::new(
                resolved_image(Artifact::Lockbox)?,
                resolved_image(Artifact::LockboxRng)?,
            ));
            images.set_inquisition(resolved_image(Artifact::Inquisition)?);
        }
        BuildService::Mercury => images.set_mercury(resolved_image(Artifact::Mercury)?),
        BuildService::Token => images.set_token(resolved_image(Artifact::Token)?),
        BuildService::Lockbox => images.set_lockbox(ResolvedLockboxImages::new(
            resolved_image(Artifact::Lockbox)?,
            resolved_image(Artifact::LockboxRng)?,
        )),
        BuildService::Inquisition => images.set_inquisition(resolved_image(Artifact::Inquisition)?),
    }
    Ok(())
}

fn ensure_no_project_containers(
    repo_root: &Path,
    project: &Project,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    let output = run_checked(
        runner,
        docker_command(repo_root).args([
            "ps",
            "--all",
            "--quiet",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
        ]),
    )?;
    ensure!(
        output.stdout.iter().all(u8::is_ascii_whitespace),
        "refusing to build while Compose project {project} has containers"
    );
    Ok(())
}

fn build_command(repo_root: &Path, artifact: Artifact, staging_tag: &str) -> ArgvCommand {
    let command = docker_command(repo_root).arg("build");
    match artifact {
        Artifact::Mercury => command
            .arg("--file")
            .arg(repo_root.join("server/Dockerfile"))
            .arg("--tag")
            .arg(staging_tag)
            .arg(repo_root),
        Artifact::Token => command
            .arg("--file")
            .arg(repo_root.join("token-server-v2/Dockerfile"))
            .arg("--tag")
            .arg(staging_tag)
            .arg(repo_root),
        Artifact::Lockbox => command
            .arg("--build-arg")
            .arg(format!("{LOCKBOX_BUILD_ARG}=OFF"))
            .arg("--file")
            .arg(repo_root.join("lockbox/Dockerfile"))
            .arg("--tag")
            .arg(staging_tag)
            .arg(repo_root.join("lockbox")),
        Artifact::LockboxRng => command
            .arg("--build-arg")
            .arg(format!("{LOCKBOX_BUILD_ARG}=ON"))
            .arg("--file")
            .arg(repo_root.join("lockbox/Dockerfile"))
            .arg("--tag")
            .arg(staging_tag)
            .arg(repo_root.join("lockbox")),
        Artifact::Inquisition => command
            .arg("--build-arg")
            .arg(format!("{INQUISITION_BUILD_ARG}={INQUISITION_COMMIT}"))
            .arg("--file")
            .arg(repo_root.join("docker/bitcoin-inquisition/Dockerfile"))
            .arg("--tag")
            .arg(staging_tag)
            .arg(repo_root.join("docker/bitcoin-inquisition")),
    }
}

fn cleanup_staging_tags(
    repo_root: &Path,
    tags: &[String],
    runner: &mut impl CommandRunner,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for tag in tags.iter().rev() {
        if !seen.insert(tag) {
            continue;
        }
        if image_id(repo_root, tag, runner)?.is_none() {
            continue;
        }
        run_checked(
            runner,
            docker_command(repo_root).args(["image", "rm"]).arg(tag),
        )
        .with_context(|| format!("untag exact staging image {tag}"))?;
        ensure!(
            image_id(repo_root, tag, runner)?.is_none(),
            "staging image tag still exists after untagging: {tag}"
        );
    }
    Ok(())
}

fn image_id(
    repo_root: &Path,
    tag: &str,
    runner: &mut impl CommandRunner,
) -> Result<Option<String>> {
    let command = docker_command(repo_root)
        .args(["image", "inspect", "--format", "{{.Id}}"])
        .arg(tag);
    let output = runner.run(&command)?;
    if !output.success {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.to_ascii_lowercase().contains("no such image") {
            return Ok(None);
        }
        super::super::argv::record_failure(&command, &output);
        bail!(
            "argv command {command:?} failed with status {:?}: stdout={} stderr={}",
            output.code,
            String::from_utf8_lossy(&output.stdout).trim(),
            stderr.trim()
        );
    }
    let value = String::from_utf8(output.stdout)
        .context("docker image inspect returned non-UTF-8 output")?;
    let value = value.trim();
    ensure!(
        !value.contains(char::is_whitespace),
        "docker image inspect returned multiple or malformed image IDs"
    );
    validate_image_id(value)?;
    Ok(Some(value.to_owned()))
}

fn validate_image_id(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("Docker image ID does not start with sha256:")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Docker image ID is not a full lowercase SHA-256 digest"
    );
    Ok(())
}

fn docker_command(repo_root: &Path) -> ArgvCommand {
    ArgvCommand::new("docker", repo_root)
}
