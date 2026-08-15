use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

const ROOT_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "docker-compose-token-servers.yml",
    "docker-compose-lockbox.yml",
    "clients/tests/rust/Cargo.toml",
    "clients/tests/rust/src/stack.rs",
];

pub fn active_root() -> Result<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .context("resolve BIP448 repository root")?;
    validate_repo_root(&root)?;
    let current = std::env::current_dir().context("read current working directory")?;
    validate_working_directory(&root, &current)?;
    Ok(root)
}

pub fn validate_repo_root(root: &Path) -> Result<()> {
    ensure!(root.is_absolute(), "repository root must be absolute");
    let canonical = root
        .canonicalize()
        .with_context(|| format!("canonicalize repository root {}", root.display()))?;
    ensure!(canonical == root, "repository root must be canonical");

    let git = fs::symlink_metadata(root.join(".git"))
        .context("repository root is missing its .git marker")?;
    ensure!(
        !git.file_type().is_symlink() && (git.is_file() || git.is_dir()),
        "repository .git marker has an unsupported type"
    );

    for relative in ROOT_FILES {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("repository root is missing {relative}"))?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "repository root entry {relative} must be a regular file"
        );
    }
    Ok(())
}

pub fn validate_working_directory(root: &Path, current: &Path) -> Result<()> {
    let current = current
        .canonicalize()
        .with_context(|| format!("canonicalize working directory {}", current.display()))?;
    ensure!(
        current == root,
        "run bip448-test from repository root {}",
        root.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bip448-repository-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }

        fn make_repo(&self) {
            fs::write(self.0.join(".git"), b"gitdir: controlled\n").unwrap();
            for relative in ROOT_FILES {
                let path = self.0.join(relative);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"controlled\n").unwrap();
            }
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn exact_repository_shape_and_working_directory_are_required() {
        let temp = TempDirectory::new();
        assert!(validate_repo_root(&temp.0).is_err());
        temp.make_repo();
        validate_repo_root(&temp.0).unwrap();
        validate_working_directory(&temp.0, &temp.0).unwrap();

        let nested = temp.0.join("nested");
        fs::create_dir(&nested).unwrap();
        assert!(validate_working_directory(&temp.0, &nested).is_err());
    }

    #[test]
    fn symlinked_sentinel_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TempDirectory::new();
        temp.make_repo();
        fs::remove_file(temp.0.join("Cargo.lock")).unwrap();
        symlink("Cargo.toml", temp.0.join("Cargo.lock")).unwrap();
        assert!(validate_repo_root(&temp.0).is_err());
    }
}
