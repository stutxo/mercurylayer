use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;

use super::super::argv::{ArgvCommand, CommandOutput, CommandRunner};
use super::super::model::{Project, StackMetadata};

pub(super) struct ImagePlan {
    tags_before: BTreeMap<String, String>,
    owned_tags: BTreeSet<String>,
}

impl ImagePlan {
    pub(super) fn capture(
        repo_root: &Path,
        project: &Project,
        metadata: Option<&StackMetadata>,
        runner: &mut impl CommandRunner,
    ) -> Result<Self> {
        let tags_before = image_tags(repo_root, runner)?;
        let owned_tags = owned_tags(project, metadata, &tags_before)?;
        for tag in &owned_tags {
            inspect_owned_tag(repo_root, tag, &tags_before, runner)?;
        }
        Ok(Self {
            tags_before,
            owned_tags,
        })
    }

    pub(super) fn remove_owned_tags(
        &self,
        repo_root: &Path,
        runner: &mut impl CommandRunner,
    ) -> Result<Vec<String>> {
        ensure!(
            image_tags(repo_root, runner)? == self.tags_before,
            "Docker image tags changed after reset preflight"
        );
        for tag in &self.owned_tags {
            inspect_owned_tag(repo_root, tag, &self.tags_before, runner)?;
        }

        for tag in &self.owned_tags {
            let expected_id = self
                .tags_before
                .get(tag)
                .context("owned image tag vanished from preflight snapshot")?;
            let inspected = inspect_image(repo_root, tag, runner)?
                .with_context(|| format!("owned reset image tag disappeared: {tag}"))?;
            ensure!(
                inspected.id == *expected_id && inspected.repo_tags.contains(tag),
                "owned image tag changed identity before untag: {tag}"
            );
            let preserved = inspected
                .repo_tags
                .difference(&self.owned_tags)
                .cloned()
                .collect::<BTreeSet<_>>();
            run_checked(
                runner,
                docker(repo_root)
                    .args(["image", "rm", "--no-prune"])
                    .arg(tag),
            )
            .with_context(|| format!("untag exact project-owned reset image {tag}"))?;
            ensure!(
                inspect_image(repo_root, tag, runner)?.is_none(),
                "project-owned image tag remains after untag: {tag}"
            );
            for shared in preserved {
                let actual = inspect_image(repo_root, &shared, runner)?
                    .with_context(|| format!("shared image tag disappeared: {shared}"))?;
                ensure!(
                    actual.id == *expected_id,
                    "shared image tag changed ID while removing {tag}: {shared}"
                );
            }
        }

        let tags_after = image_tags(repo_root, runner)?;
        let expected_after = self
            .tags_before
            .iter()
            .filter(|(tag, _)| !self.owned_tags.contains(*tag))
            .map(|(tag, id)| (tag.clone(), id.clone()))
            .collect::<BTreeMap<_, _>>();
        ensure!(
            tags_after == expected_after,
            "Docker image tag changes exceeded the exact reset-owned allowlist"
        );
        Ok(self.owned_tags.iter().cloned().collect())
    }
}

fn owned_tags(
    project: &Project,
    metadata: Option<&StackMetadata>,
    tags: &BTreeMap<String, String>,
) -> Result<BTreeSet<String>> {
    let recorded_rng = metadata
        .and_then(StackMetadata::build_resolution)
        .and_then(|build| build.images().lockbox())
        .map(|images| images.deterministic_rng().tag().to_owned());
    if let Some(tag) = &recorded_rng {
        ensure!(
            valid_rng_tag(tag, project),
            "recorded deterministic RNG tag is not owned by the exact reset project"
        );
    }
    let mut owned = BTreeSet::new();
    for tag in tags.keys() {
        if valid_rng_tag(tag, project) || valid_staging_tag(tag, project) {
            owned.insert(tag.clone());
        }
    }
    if let Some(tag) = recorded_rng {
        if tags.contains_key(&tag) {
            owned.insert(tag);
        }
    }
    Ok(owned)
}

fn valid_rng_tag(tag: &str, project: &Project) -> bool {
    let Some(value) = tag.strip_prefix("mercurylayer/lockbox:bip448-test-") else {
        return false;
    };
    let Some(fingerprint) = value.strip_suffix(&format!("-rng-{project}")) else {
        return false;
    };
    fingerprint.len() == 16 && fingerprint.bytes().all(is_lower_hex)
}

fn valid_staging_tag(tag: &str, project: &Project) -> bool {
    let Some((repository, value)) = tag.rsplit_once(':') else {
        return false;
    };
    let Some(value) = value.strip_prefix(&format!("b448-stage-{project}-")) else {
        return false;
    };
    let Some((nonce, artifact)) = value.split_once('-') else {
        return false;
    };
    if nonce.len() != 32 || !nonce.bytes().all(is_lower_hex) {
        return false;
    }
    matches!(
        (repository, artifact),
        ("mercurylayer/mercury-server", "mercury")
            | ("mercurylayer/token-server-v2", "token")
            | ("mercurylayer/lockbox", "lockbox")
            | ("mercurylayer/lockbox", "lockbox-rng")
            | ("mercurylayer/bitcoin-inquisition", "inquisition")
    )
}

#[derive(Debug)]
struct ImageInspect {
    id: String,
    repo_tags: BTreeSet<String>,
}

fn inspect_owned_tag(
    repo_root: &Path,
    tag: &str,
    tags: &BTreeMap<String, String>,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    let expected = tags
        .get(tag)
        .with_context(|| format!("owned image tag is absent from exact tag snapshot: {tag}"))?;
    let image = inspect_image(repo_root, tag, runner)?
        .with_context(|| format!("owned image tag is absent during inspection: {tag}"))?;
    ensure!(
        image.id == *expected && image.repo_tags.contains(tag),
        "owned image tag/ID/RepoTags proof failed: {tag}"
    );
    for repo_tag in &image.repo_tags {
        ensure!(
            tags.get(repo_tag) == Some(expected),
            "image inspection contains an unaccounted RepoTag {repo_tag}"
        );
    }
    Ok(())
}

fn inspect_image(
    repo_root: &Path,
    tag: &str,
    runner: &mut impl CommandRunner,
) -> Result<Option<ImageInspect>> {
    let command = docker(repo_root).args(["image", "inspect"]).arg(tag);
    let output = runner.run(&command)?;
    if !output.success {
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if output.code == Some(1) && stderr.contains("no such image") {
            return Ok(None);
        }
        return command_failure(&command, &output);
    }
    let values: Vec<Value> =
        serde_json::from_slice(&output.stdout).context("parse Docker image inspection JSON")?;
    ensure!(values.len() == 1, "Docker image inspection count mismatch");
    let value = &values[0];
    let id = value
        .get("Id")
        .and_then(Value::as_str)
        .context("Docker image inspection has no ID")?
        .to_owned();
    validate_image_id(&id)?;
    let repo_tags = value
        .get("RepoTags")
        .and_then(Value::as_array)
        .context("Docker image inspection has no RepoTags")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("Docker RepoTag is not a string")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(!repo_tags.is_empty(), "Docker image has no repository tags");
    Ok(Some(ImageInspect { id, repo_tags }))
}

fn image_tags(
    repo_root: &Path,
    runner: &mut impl CommandRunner,
) -> Result<BTreeMap<String, String>> {
    let command = docker(repo_root).args([
        "image",
        "ls",
        "--all",
        "--no-trunc",
        "--format",
        "{{.Repository}}:{{.Tag}}\\t{{.ID}}",
    ]);
    let output = run_checked(runner, command)?;
    let text = String::from_utf8(output.stdout).context("Docker image tag list is not UTF-8")?;
    let mut tags = BTreeMap::new();
    for line in text.lines() {
        let (tag, id) = line
            .split_once('\t')
            .context("Docker image tag list row has no tab separator")?;
        if tag == "<none>:<none>" {
            continue;
        }
        ensure!(
            !tag.is_empty() && !tag.contains(char::is_whitespace),
            "Docker image tag is malformed"
        );
        validate_image_id(id)?;
        ensure!(
            tags.insert(tag.to_owned(), id.to_owned()).is_none(),
            "Docker image tag list contains a duplicate tag"
        );
    }
    Ok(tags)
}

fn validate_image_id(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("Docker image ID lacks sha256: prefix")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(is_lower_hex),
        "Docker image ID is not a full lowercase hexadecimal digest"
    );
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn docker(repo_root: &Path) -> ArgvCommand {
    ArgvCommand::new("docker", repo_root)
}

fn run_checked(runner: &mut impl CommandRunner, command: ArgvCommand) -> Result<CommandOutput> {
    let output = runner.run(&command)?;
    if output.success {
        Ok(output)
    } else {
        command_failure(&command, &output)
    }
}

fn command_failure<T>(command: &ArgvCommand, output: &CommandOutput) -> Result<T> {
    super::super::argv::record_failure(command, output);
    bail!(
        "argv command {command:?} failed with status {:?}: stdout={} stderr={}",
        output.code,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    const SHARED_ID: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_ID: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct MockImages {
        tags: BTreeMap<String, String>,
        removed: Vec<String>,
    }

    impl MockImages {
        fn new() -> Self {
            Self {
                tags: BTreeMap::from([
                    (
                        "mercurylayer/lockbox:bip448-test-0123456789abcdef".into(),
                        SHARED_ID.into(),
                    ),
                    (
                        "mercurylayer/lockbox:bip448-test-0123456789abcdef-rng-project".into(),
                        SHARED_ID.into(),
                    ),
                    ("unrelated/image:keep".into(), OTHER_ID.into()),
                ]),
                removed: Vec::new(),
            }
        }

        fn argv(command: &ArgvCommand) -> Vec<String> {
            command
                .args_slice()
                .iter()
                .map(|value| value.to_str().unwrap().to_owned())
                .collect()
        }
    }

    impl CommandRunner for MockImages {
        fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
            assert_eq!(command.program(), OsStr::new("docker"));
            let args = Self::argv(command);
            match args.as_slice() {
                [image, list, rest @ ..] if image == "image" && list == "ls" => {
                    assert!(rest.contains(&"--no-trunc".to_owned()));
                    let output = self
                        .tags
                        .iter()
                        .map(|(tag, id)| format!("{tag}\t{id}\n"))
                        .collect::<String>();
                    Ok(CommandOutput::success(output))
                }
                [image, inspect, tag] if image == "image" && inspect == "inspect" => {
                    let Some(id) = self.tags.get(tag) else {
                        return Ok(CommandOutput::failure(1, "No such image"));
                    };
                    let repo_tags = self
                        .tags
                        .iter()
                        .filter_map(|(candidate, candidate_id)| {
                            (candidate_id == id).then_some(candidate)
                        })
                        .collect::<Vec<_>>();
                    Ok(CommandOutput::success(
                        serde_json::to_vec(&serde_json::json!([{
                            "Id": id,
                            "RepoTags": repo_tags,
                            "Config": { "Labels": null }
                        }]))
                        .unwrap(),
                    ))
                }
                [image, remove, no_prune, tag]
                    if image == "image" && remove == "rm" && no_prune == "--no-prune" =>
                {
                    ensure!(self.tags.remove(tag).is_some(), "mock removed absent tag");
                    self.removed.push(tag.clone());
                    Ok(CommandOutput::success(Vec::new()))
                }
                _ => panic!("unexpected mock image argv: {args:?}"),
            }
        }
    }

    #[test]
    fn only_exact_project_rng_and_staging_tags_are_owned() {
        let project = Project::parse("reset_project_with_a_long_suffix").unwrap();
        assert!(valid_rng_tag(
            "mercurylayer/lockbox:bip448-test-0123456789abcdef-rng-reset_project_with_a_long_suffix",
            &project
        ));
        assert!(!valid_rng_tag(
            "mercurylayer/lockbox:bip448-test-0123456789abcdef-rng-reset_project_with_a_long_suffix2",
            &project
        ));
        assert!(valid_staging_tag(
            "mercurylayer/lockbox:b448-stage-reset_project_with_a_long_suffix-0123456789abcdef0123456789abcdef-lockbox-rng",
            &project
        ));
        assert!(!valid_staging_tag(
            "mercurylayer/lockbox:b448-stage-reset_project_with_a_long_suffix-0123456789abcdef0123456789abcdef-mercury",
            &project
        ));
        assert!(!valid_staging_tag(
            "mercurylayer/lockbox:b448-stage-reset_project_with_a_lon-0123456789abcdef0123456789abcdef-lockbox-rng",
            &project
        ));
        assert!(!valid_staging_tag(
            "mercurylayer/lockbox:b448-stage-reset_project_with_a_long_suffix-0123456789ABCDEF0123456789ABCDEF-lockbox-rng",
            &project
        ));
        assert!(!valid_staging_tag(
            "mercurylayer/lockbox:b448-stage-reset_project_with_a_long_suffix-0123456789abcdef0123456789abcdeg-lockbox-rng",
            &project
        ));
    }

    #[test]
    fn full_long_project_ownership_never_claims_a_shared_prefix_peer() {
        let prefix = "a".repeat(24);
        let first = Project::parse(&format!("{prefix}-first")).unwrap();
        let second = Project::parse(&format!("{prefix}-second")).unwrap();
        let first_tag = format!(
            "mercurylayer/lockbox:b448-stage-{first}-0123456789abcdef0123456789abcdef-lockbox-rng"
        );
        let second_tag = format!(
            "mercurylayer/lockbox:b448-stage-{second}-0123456789abcdef0123456789abcdef-lockbox-rng"
        );
        assert!(valid_staging_tag(&first_tag, &first));
        assert!(!valid_staging_tag(&second_tag, &first));

        let mut docker = MockImages::new();
        docker.tags.insert(first_tag.clone(), OTHER_ID.into());
        docker.tags.insert(second_tag.clone(), OTHER_ID.into());
        let plan = ImagePlan::capture(Path::new("/repo"), &first, None, &mut docker).unwrap();
        assert_eq!(
            plan.remove_owned_tags(Path::new("/repo"), &mut docker)
                .unwrap(),
            [first_tag.clone()]
        );
        assert!(!docker.tags.contains_key(&first_tag));
        assert_eq!(
            docker.tags.get(&second_tag).map(String::as_str),
            Some(OTHER_ID)
        );
    }

    #[test]
    fn maximum_project_staging_tag_is_accepted_within_docker_limit() {
        let project = Project::parse(&"a".repeat(63)).unwrap();
        let tag = format!(
            "mercurylayer/lockbox:b448-stage-{project}-0123456789abcdef0123456789abcdef-lockbox-rng"
        );
        assert!(valid_staging_tag(&tag, &project));
        assert!(tag.rsplit_once(':').unwrap().1.len() <= 128);
    }

    #[test]
    fn removal_is_by_exact_tag_and_preserves_every_shared_id_tag() {
        let root = Path::new("/repo");
        let project = Project::parse("project").unwrap();
        let mut docker = MockImages::new();
        let plan = ImagePlan::capture(root, &project, None, &mut docker).unwrap();
        let removed = plan.remove_owned_tags(root, &mut docker).unwrap();
        assert_eq!(
            removed,
            ["mercurylayer/lockbox:bip448-test-0123456789abcdef-rng-project"]
        );
        assert_eq!(docker.removed, removed);
        assert_eq!(
            docker
                .tags
                .get("mercurylayer/lockbox:bip448-test-0123456789abcdef")
                .map(String::as_str),
            Some(SHARED_ID)
        );
        assert_eq!(
            docker.tags.get("unrelated/image:keep").map(String::as_str),
            Some(OTHER_ID)
        );
    }

    #[test]
    fn tag_drift_fails_before_any_untag() {
        let root = Path::new("/repo");
        let project = Project::parse("project").unwrap();
        let mut docker = MockImages::new();
        let plan = ImagePlan::capture(root, &project, None, &mut docker).unwrap();
        docker
            .tags
            .insert("unrelated/new:tag".into(), OTHER_ID.into());
        assert!(plan.remove_owned_tags(root, &mut docker).is_err());
        assert!(docker.removed.is_empty());
    }
}
