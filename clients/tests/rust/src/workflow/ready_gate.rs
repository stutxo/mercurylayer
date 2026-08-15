use std::path::Path;

use anyhow::Result;

use super::lifecycle;
use super::model::{ProjectSpec, StackMetadata};

pub(super) trait ReadyGate {
    fn require_ready(&mut self, repo_root: &Path, metadata: &StackMetadata) -> Result<ProjectSpec>;
}

pub(super) struct LiveReadyGate;

impl ReadyGate for LiveReadyGate {
    fn require_ready(&mut self, repo_root: &Path, metadata: &StackMetadata) -> Result<ProjectSpec> {
        let _ = lifecycle::ready(repo_root, metadata)?;
        lifecycle::project_spec(metadata)
    }
}
