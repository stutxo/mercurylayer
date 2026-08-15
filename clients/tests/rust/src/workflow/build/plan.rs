use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};

use super::super::cli::BuildService;
use super::super::model::{
    Project, INQUISITION_IMAGE, LOCKBOX_IMAGE_PREFIX, MERCURY_IMAGE_PREFIX, TOKEN_IMAGE_PREFIX,
};
use super::fingerprint::BuildSnapshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Artifact {
    Mercury,
    Token,
    Lockbox,
    LockboxRng,
    Inquisition,
}

impl Artifact {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Mercury => "mercury",
            Self::Token => "token",
            Self::Lockbox => "lockbox",
            Self::LockboxRng => "lockbox-rng",
            Self::Inquisition => "inquisition",
        }
    }

    pub(super) fn fingerprint<'a>(self, snapshot: &'a BuildSnapshot) -> &'a str {
        match self {
            Self::Mercury => snapshot.fingerprints.mercury(),
            Self::Token => snapshot.fingerprints.token(),
            Self::Lockbox | Self::LockboxRng => snapshot.fingerprints.lockbox(),
            Self::Inquisition => snapshot.fingerprints.inquisition(),
        }
    }

    pub(super) fn final_tag(self, project: &Project, snapshot: &BuildSnapshot) -> String {
        let short = &self.fingerprint(snapshot)[..16];
        match self {
            Self::Mercury => format!("{MERCURY_IMAGE_PREFIX}{short}"),
            Self::Token => format!("{TOKEN_IMAGE_PREFIX}{short}"),
            Self::Lockbox => format!("{LOCKBOX_IMAGE_PREFIX}{short}"),
            Self::LockboxRng => format!("{LOCKBOX_IMAGE_PREFIX}{short}-rng-{project}"),
            Self::Inquisition => INQUISITION_IMAGE.to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PlanAction {
    CacheHit { image_id: String },
    Build { staging_tag: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PlannedImage {
    pub(super) artifact: Artifact,
    pub(super) final_tag: String,
    pub(super) action: PlanAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BuildPlan {
    pub(super) images: Vec<PlannedImage>,
}

pub(super) fn selected_artifacts(service: BuildService) -> &'static [Artifact] {
    match service {
        BuildService::All => &[
            Artifact::Mercury,
            Artifact::Token,
            Artifact::Lockbox,
            Artifact::LockboxRng,
            Artifact::Inquisition,
        ],
        BuildService::Mercury => &[Artifact::Mercury],
        BuildService::Token => &[Artifact::Token],
        BuildService::Lockbox => &[Artifact::Lockbox, Artifact::LockboxRng],
        BuildService::Inquisition => &[Artifact::Inquisition],
    }
}

pub(super) fn plan_build(
    service: BuildService,
    project: &Project,
    snapshot: &BuildSnapshot,
    observed: &BTreeMap<Artifact, Option<String>>,
    nonce: &str,
) -> Result<BuildPlan> {
    ensure!(
        nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "staging nonce must be 32 hexadecimal characters"
    );
    let project_fragment = project.as_str().chars().take(24).collect::<String>();
    let mut images = Vec::new();
    for artifact in selected_artifacts(service) {
        let final_tag = artifact.final_tag(project, snapshot);
        let existing = observed
            .get(artifact)
            .context("planner is missing an observed image state")?;
        let action = match existing {
            Some(image_id) => PlanAction::CacheHit {
                image_id: image_id.clone(),
            },
            None => {
                let repository = final_tag
                    .rsplit_once(':')
                    .map(|(repository, _)| repository)
                    .context("final image tag has no tag separator")?;
                PlanAction::Build {
                    staging_tag: format!(
                        "{repository}:b448-stage-{project_fragment}-{nonce}-{}",
                        artifact.label()
                    ),
                }
            }
        };
        images.push(PlannedImage {
            artifact: *artifact,
            final_tag,
            action,
        });
    }
    Ok(BuildPlan { images })
}
