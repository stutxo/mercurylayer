use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

use super::{client_artifacts, real_uid};

pub(super) struct ArtifactGuard {
    paths: Vec<PathBuf>,
    handles: Vec<Option<File>>,
    cleanup_attempted: bool,
}

impl ArtifactGuard {
    pub(super) fn new(directory: &Path) -> Result<Self> {
        validate_directory(directory)?;
        let paths = client_artifacts(directory);
        require_absent(&paths)?;
        Ok(Self {
            handles: (0..paths.len()).map(|_| None).collect(),
            paths,
            cleanup_attempted: false,
        })
    }

    #[cfg(test)]
    pub(super) fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    pub(super) fn write_settings(&mut self, contents: &[u8]) -> Result<()> {
        let mut file = self.create(0)?;
        file.write_all(contents)
            .context("write disposable verifier Settings.toml")?;
        file.sync_all()
            .context("sync disposable verifier Settings.toml")?;
        self.validate_index(0)
    }

    pub(super) fn create_database(&mut self) -> Result<()> {
        let file = self.create(1)?;
        file.sync_all()
            .context("sync empty disposable verifier database")?;
        drop(file);
        self.validate_index(1)
    }

    pub(super) fn capture_helper_artifacts(&mut self) -> Result<()> {
        for index in 0..self.paths.len() {
            match fs::symlink_metadata(&self.paths[index]) {
                Err(error) if error.kind() == ErrorKind::NotFound && index >= 2 => continue,
                Err(error) => return Err(error).with_context(|| self.label(index, "inspect")),
                Ok(_) if self.handles[index].is_some() => self.validate_index(index)?,
                Ok(_) => self.capture_index(index)?,
            }
        }
        Ok(())
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        self.cleanup_attempted = true;
        for index in (0..self.paths.len()).rev() {
            match fs::symlink_metadata(&self.paths[index]) {
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => return Err(error).with_context(|| self.label(index, "inspect")),
                Ok(_) => self.validate_index(index)?,
            }
            fs::remove_file(&self.paths[index])
                .with_context(|| self.label(index, "remove exact"))?;
            self.handles[index].take();
        }
        require_absent(&self.paths)
    }

    fn create(&mut self, index: usize) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.paths[index])
            .with_context(|| self.label(index, "create"))?;
        self.handles[index] = Some(file);
        self.validate_index(index)?;
        self.handles[index]
            .as_ref()
            .expect("newly created artifact handle is installed")
            .try_clone()
            .with_context(|| self.label(index, "clone created handle"))
    }

    fn capture_index(&mut self, index: usize) -> Result<()> {
        let path_metadata = validate_file(&self.paths[index])?;
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.paths[index])?;
        let open_metadata = handle.metadata()?;
        ensure!(
            path_metadata.dev() == open_metadata.dev()
                && path_metadata.ino() == open_metadata.ino(),
            "disposable verifier artifact changed while it was captured"
        );
        self.handles[index] = Some(handle);
        Ok(())
    }

    fn validate_index(&self, index: usize) -> Result<()> {
        let handle = self.handles[index]
            .as_ref()
            .context("refuse to remove an untracked verifier artifact")?;
        let metadata = validate_file(&self.paths[index])?;
        let expected = handle.metadata()?;
        ensure!(
            metadata.dev() == expected.dev() && metadata.ino() == expected.ino(),
            "disposable verifier artifact identity was substituted: {}",
            self.paths[index].display()
        );
        Ok(())
    }

    fn label(&self, index: usize, action: &str) -> String {
        format!(
            "{action} disposable verifier artifact {}",
            self.paths[index].display()
        )
    }
}

impl Drop for ArtifactGuard {
    fn drop(&mut self) {
        if !self.cleanup_attempted {
            if let Err(error) = self.cleanup() {
                eprintln!("bip448-test: verifier artifact cleanup failed: {error:#}");
            }
        }
    }
}

fn validate_directory(path: &Path) -> Result<()> {
    ensure!(
        path.canonicalize()? == path,
        "verifier run directory is not canonical"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == real_uid()?
            && metadata.permissions().mode() & 0o7777 == 0o700,
        "verifier run directory must be a real UID-owned mode-0700 directory"
    );
    Ok(())
}

fn validate_file(path: &Path) -> Result<fs::Metadata> {
    ensure!(
        path.canonicalize()? == path,
        "verifier artifact path is not canonical"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.uid() == real_uid()?
            && metadata.permissions().mode() & 0o7777 == 0o600,
        "verifier artifact must be one real UID-owned mode-0600 regular file"
    );
    Ok(metadata)
}

fn require_absent(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        ensure!(
            fs::symlink_metadata(path).is_err_and(|error| error.kind() == ErrorKind::NotFound),
            "disposable verifier artifact already exists: {}",
            path.display()
        );
    }
    Ok(())
}
