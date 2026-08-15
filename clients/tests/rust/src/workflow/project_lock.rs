use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};

use super::model::Project;

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

pub(super) struct ProjectLock {
    file: File,
    path: PathBuf,
}

impl ProjectLock {
    pub(super) fn acquire(repo_root: &Path, project: &Project) -> Result<Self> {
        let owner = effective_uid()?;
        validate_owned_directory(&repo_root.join("target"), owner)?;
        let directory = repo_root.join("target/bip448-controller-locks");
        ensure_private_directory(&directory, owner)?;
        let path = directory.join(format!("{}.lock", project.as_str()));
        let file = open_private_file(&path, owner)?;
        file.lock()
            .with_context(|| format!("acquire project workflow lock {}", path.display()))?;
        validate_open_file(&path, &file, owner)?;
        Ok(Self { file, path })
    }
}

impl Drop for ProjectLock {
    fn drop(&mut self) {
        if let Err(error) = self.file.unlock() {
            eprintln!(
                "bip448-test: release project workflow lock {}: {error}",
                self.path.display()
            );
        }
    }
}

fn ensure_private_directory(path: &Path, owner: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            match DirBuilder::new().mode(DIRECTORY_MODE).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("create project lock directory {}", path.display())
                    })
                }
            }
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect lock directory {}", path.display()))
        }
        Ok(_) => {}
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect project lock directory {}", path.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "project lock directory {} must be a real directory",
        path.display()
    );
    ensure!(
        metadata.uid() == owner,
        "project lock directory {} is not owned by the effective UID",
        path.display()
    );
    ensure!(
        metadata.permissions().mode() & 0o7777 == DIRECTORY_MODE,
        "project lock directory {} must have mode 700",
        path.display()
    );
    Ok(())
}

pub(super) fn validate_owned_directory(path: &Path, owner: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect owned directory {}", path.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "{} must be a real directory",
        path.display()
    );
    ensure!(
        metadata.uid() == owner,
        "{} is not owned by the effective UID",
        path.display()
    );
    Ok(())
}

fn open_private_file(path: &Path, owner: u32) -> Result<File> {
    let file = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => open_existing(path)?,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create project lock {}", path.display()))
            }
        },
        Err(error) => {
            return Err(error).with_context(|| format!("inspect project lock {}", path.display()))
        }
        Ok(_) => open_existing(path)?,
    };
    validate_open_file(path, &file, owner)?;
    Ok(file)
}

fn open_existing(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open project lock {}", path.display()))
}

fn validate_open_file(path: &Path, file: &File, owner: u32) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect project lock {}", path.display()))?;
    let open_metadata = file
        .metadata()
        .with_context(|| format!("inspect open project lock {}", path.display()))?;
    ensure!(
        path_metadata.is_file()
            && !path_metadata.file_type().is_symlink()
            && open_metadata.is_file()
            && path_metadata.dev() == open_metadata.dev()
            && path_metadata.ino() == open_metadata.ino()
            && path_metadata.nlink() == 1,
        "project lock {} must be one stable regular non-symlink file",
        path.display()
    );
    ensure!(
        path_metadata.uid() == owner && open_metadata.uid() == owner,
        "project lock {} is not owned by the effective UID",
        path.display()
    );
    ensure!(
        path_metadata.permissions().mode() & 0o7777 == FILE_MODE
            && open_metadata.permissions().mode() & 0o7777 == FILE_MODE,
        "project lock {} must have mode 600",
        path.display()
    );
    Ok(())
}

pub(super) fn effective_uid() -> Result<u32> {
    let mut status = String::new();
    File::open("/proc/self/status")
        .context("open /proc/self/status for effective UID")?
        .read_to_string(&mut status)
        .context("read /proc/self/status for effective UID")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .context("/proc/self/status has no Uid field")?;
    let values = line.split_ascii_whitespace().skip(1).collect::<Vec<_>>();
    if values.len() != 4 {
        bail!("/proc/self/status has a malformed Uid field");
    }
    values[1]
        .parse()
        .context("parse effective UID from /proc/self/status")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use uuid::Uuid;

    use super::*;

    struct Temp(PathBuf);

    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("bip448-project-lock-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            fs::create_dir(path.join("target")).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn same_project_serializes_and_disjoint_project_does_not() {
        let root = Temp::new();
        let one = Project::parse("one").unwrap();
        let two = Project::parse("two").unwrap();
        let held = ProjectLock::acquire(&root.0, &one).unwrap();
        let (tx, rx) = mpsc::channel();
        let path = root.0.clone();
        let handle = thread::spawn(move || {
            tx.send("waiting").unwrap();
            let _lock = ProjectLock::acquire(&path, &one).unwrap();
            tx.send("acquired").unwrap();
        });
        assert_eq!(rx.recv().unwrap(), "waiting");
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());
        let _independent = ProjectLock::acquire(&root.0, &two).unwrap();
        drop(held);
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), "acquired");
        handle.join().unwrap();
    }

    #[test]
    fn modes_and_links_fail_closed() {
        let root = Temp::new();
        let project = Project::parse("mode").unwrap();
        drop(ProjectLock::acquire(&root.0, &project).unwrap());
        let directory = root.0.join("target/bip448-controller-locks");
        let lock = directory.join("mode.lock");
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(&lock).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ProjectLock::acquire(&root.0, &project).is_err());
        fs::remove_file(&lock).unwrap();
        symlink("/etc/passwd", &lock).unwrap();
        assert!(ProjectLock::acquire(&root.0, &project).is_err());
    }
}
