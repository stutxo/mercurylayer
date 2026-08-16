use std::fs;
use std::io::ErrorKind;

use anyhow::{ensure, Context, Result};

use super::filesystem::{
    fd_child, file_name, metadata_at, validate_identity_at, EntryKind, FileKind, PinnedDirectory,
    TreePlan,
};

impl TreePlan {
    pub(super) fn delete(self) -> Result<()> {
        self.validate_after_down()?;
        let Some(run) = self.run.as_ref() else {
            self.prove_absent()?;
            return Ok(());
        };
        let runs = self
            .runs
            .as_ref()
            .context("captured run directory has no pinned runs root")?;
        run.delete_contents(self.owner, true)?;
        let name = file_name(&self.paths.run_directory)?;
        validate_identity_at(runs, name, &run.identity, EntryKind::Directory, self.owner)?;
        fs::remove_dir(fd_child(runs, name)).with_context(|| {
            format!(
                "remove exact empty run directory {}",
                self.paths.run_directory.display()
            )
        })?;
        ensure!(
            metadata_at(runs, name).is_err_and(|error| error.kind() == ErrorKind::NotFound),
            "run directory still exists after exact removal"
        );
        self.prove_absent()
    }
}

impl PinnedDirectory {
    fn delete_contents(&self, owner: u32, allow_wallet_absent: bool) -> Result<()> {
        self.validate(owner, allow_wallet_absent)?;
        for file in &self.files {
            if allow_wallet_absent && file.kind == FileKind::Wallet && !file.exists(&self.anchor) {
                continue;
            }
            file.validate(&self.anchor, owner)?;
            let path = fd_child(&self.anchor, &file.name);
            fs::remove_file(&path).with_context(|| {
                format!(
                    "remove exact validated file {}",
                    self.anchor.path.join(&file.name).display()
                )
            })?;
            ensure!(
                fs::symlink_metadata(&path).is_err_and(|error| error.kind() == ErrorKind::NotFound),
                "validated file remains after removal: {}",
                self.anchor.path.join(&file.name).display()
            );
        }
        for directory in self.directories.iter().rev() {
            directory.delete_contents(owner, allow_wallet_absent)?;
            let name = file_name(&directory.anchor.path)?;
            validate_identity_at(
                &self.anchor,
                name,
                &directory.identity,
                EntryKind::Directory,
                owner,
            )?;
            fs::remove_dir(fd_child(&self.anchor, name)).with_context(|| {
                format!(
                    "remove exact empty directory {}",
                    directory.anchor.path.display()
                )
            })?;
        }
        ensure!(
            super::filesystem::directory_names(&self.anchor)?.is_empty(),
            "validated directory is not empty after exact cleanup: {}",
            self.anchor.path.display()
        );
        Ok(())
    }
}
