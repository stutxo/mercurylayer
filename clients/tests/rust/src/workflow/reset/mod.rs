mod deletion;
pub(super) mod docker;
mod filesystem;
pub(super) mod images;

#[cfg(test)]
mod tests;

use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::Serialize;

use super::argv::SystemCommandRunner;
use super::lifecycle;
use super::model::{canonical_json, Project, RunPaths};
use super::storage;
use docker::DockerPlan;
use filesystem::TreePlan;
use images::ImagePlan;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResetReport {
    version: u32,
    project: String,
    run_tree_removed: bool,
    removed_image_tags: Vec<String>,
}

pub(super) fn execute(repo_root: &Path, project: &Project) -> Result<String> {
    let paths = RunPaths::new(repo_root, project);
    let tree = TreePlan::capture(paths).context("validate and pin exact reset run tree")?;
    let metadata = if tree.stack_exists() {
        Some(
            storage::status(repo_root, project)
                .context("validate stack metadata before destructive reset")?,
        )
    } else {
        None
    };
    let mut runner = SystemCommandRunner;
    let docker = DockerPlan::capture(repo_root, project, &mut runner)
        .context("capture exact reset Docker and image preflight")?;
    let images = ImagePlan::capture(repo_root, project, metadata.as_ref(), &mut runner)
        .context("capture exact reset-owned image tags")?;
    let run_tree_removed = tree.run_exists();

    ensure!(
        metadata.is_some() || !docker.project_resources_exist(),
        "Compose project resources exist but exact stack metadata is absent; refusing reset"
    );
    if let Some(metadata) = &metadata {
        lifecycle::down(repo_root, metadata)
            .context("run exact lifecycle down before reset deletion")?;
    }
    docker.verify_teardown(repo_root, project, &mut runner)?;
    tree.validate_after_down()?;
    let removed_image_tags = images.remove_owned_tags(repo_root, &mut runner)?;
    // Image operations do not authorize any concurrent C/N/V change.
    docker.verify_teardown(repo_root, project, &mut runner)?;
    tree.delete()?;
    canonical_json(&ResetReport {
        version: 1,
        project: project.to_string(),
        run_tree_removed,
        removed_image_tags,
    })
}

#[cfg(test)]
fn sequence<D, V, F, I, X>(
    metadata_exists: bool,
    project_resources_exist: bool,
    down: D,
    mut verify_docker: V,
    validate_tree: F,
    remove_images: I,
    delete_tree: X,
) -> Result<Vec<String>>
where
    D: FnOnce() -> Result<()>,
    V: FnMut() -> Result<()>,
    F: FnOnce() -> Result<()>,
    I: FnOnce() -> Result<Vec<String>>,
    X: FnOnce() -> Result<()>,
{
    ensure!(
        metadata_exists || !project_resources_exist,
        "Compose project resources exist but exact stack metadata is absent; refusing reset"
    );
    down()?;
    verify_docker()?;
    validate_tree()?;
    let removed = remove_images()?;
    // Image operations do not authorize any concurrent C/N/V change.
    verify_docker()?;
    delete_tree()?;
    Ok(removed)
}
