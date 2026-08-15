use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

const LOCK_MODE: u32 = 0o600;

pub(super) struct MetadataLock {
    path: PathBuf,
    file: File,
    release_attempted: bool,
}

impl MetadataLock {
    pub(super) fn acquire(metadata_path: &Path) -> Result<Self> {
        let path = lock_path(metadata_path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(LOCK_MODE)
            .open(&path)
            .with_context(|| {
                format!(
                    "exclusively create metadata update lock {}; a residue or concurrent writer is unsafe",
                    path.display()
                )
            })?;
        let mut lock = Self {
            path,
            file,
            release_attempted: false,
        };
        lock.initialize()?;
        Ok(lock)
    }

    fn initialize(&mut self) -> Result<()> {
        self.file
            .set_permissions(fs::Permissions::from_mode(LOCK_MODE))
            .with_context(|| format!("set metadata lock mode on {}", self.path.display()))?;
        self.file
            .sync_all()
            .with_context(|| format!("sync metadata lock {}", self.path.display()))?;
        let linked = self.ensure_owned()?;
        ensure!(
            linked.permissions().mode() & 0o7777 == LOCK_MODE,
            "metadata update lock {} must have mode {LOCK_MODE:o}",
            self.path.display()
        );
        sync_directory(self.parent()?)
    }

    pub(super) fn release(&mut self) -> Result<()> {
        self.release_once()
    }

    fn release_once(&mut self) -> Result<()> {
        ensure!(
            !self.release_attempted,
            "metadata lock release was already attempted"
        );
        self.release_attempted = true;
        self.ensure_owned()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove metadata update lock {}", self.path.display()))?;
        sync_directory(self.parent()?)
    }

    fn ensure_owned(&self) -> Result<fs::Metadata> {
        let opened = self
            .file
            .metadata()
            .with_context(|| format!("inspect opened metadata lock {}", self.path.display()))?;
        let linked = fs::symlink_metadata(&self.path)
            .with_context(|| format!("inspect metadata update lock {}", self.path.display()))?;
        ensure!(
            linked.is_file()
                && !linked.file_type().is_symlink()
                && linked.dev() == opened.dev()
                && linked.ino() == opened.ino(),
            "metadata update lock {} is no longer the exact owned lock",
            self.path.display()
        );
        Ok(linked)
    }

    fn parent(&self) -> Result<&Path> {
        self.path
            .parent()
            .context("metadata update lock has no parent")
    }
}

impl Drop for MetadataLock {
    fn drop(&mut self) {
        if !self.release_attempted {
            let _ = self.release_once();
        }
    }
}

pub(super) fn lock_path(metadata_path: &Path) -> Result<PathBuf> {
    let name = metadata_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("stack metadata filename is not UTF-8")?;
    Ok(metadata_path.with_file_name(format!(".{name}.lock")))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bip448-metadata-lock-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn lock_is_owner_only_exclusive_and_removed_on_release() {
        let temp = TempDirectory::new();
        let metadata = temp.0.join("stack.json");
        let path = lock_path(&metadata).unwrap();
        let mut lock = MetadataLock::acquire(&metadata).unwrap();

        let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, LOCK_MODE);
        assert!(MetadataLock::acquire(&metadata).is_err());

        lock.release().unwrap();
        assert!(matches!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            ErrorKind::NotFound
        ));
    }

    #[test]
    fn drop_never_removes_a_replacement_lock() {
        let temp = TempDirectory::new();
        let metadata = temp.0.join("stack.json");
        let path = lock_path(&metadata).unwrap();
        let lock = MetadataLock::acquire(&metadata).unwrap();

        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(LOCK_MODE)).unwrap();
        drop(lock);

        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }
}
