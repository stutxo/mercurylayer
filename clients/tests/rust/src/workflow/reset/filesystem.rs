use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use uuid::Uuid;

use super::super::model::RunPaths;
use super::super::project_lock::effective_uid;

const DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const SQLITE_FILE_MODE: u32 = 0o644;

pub(super) struct TreePlan {
    pub(super) target: Anchor,
    pub(super) runs: Option<Anchor>,
    pub(super) run: Option<PinnedDirectory>,
    pub(super) paths: RunPaths,
    pub(super) owner: u32,
}

impl TreePlan {
    pub(super) fn capture(paths: RunPaths) -> Result<Self> {
        let owner = effective_uid()?;
        let target_path = paths
            .run_directory
            .parent()
            .and_then(Path::parent)
            .context("run directory has no target ancestor")?;
        let target = Anchor::open(target_path, owner, None)?;
        let runs_path = paths
            .run_directory
            .parent()
            .context("run directory has no runs root")?;
        let runs = match fs::symlink_metadata(runs_path) {
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect runs root {}", runs_path.display()))
            }
            Ok(_) => Some(Anchor::open(runs_path, owner, Some(DIRECTORY_MODE))?),
        };
        let run = match &runs {
            None => {
                ensure!(
                    fs::symlink_metadata(&paths.run_directory)
                        .is_err_and(|error| error.kind() == ErrorKind::NotFound),
                    "run directory exists without its runs root"
                );
                None
            }
            Some(runs) => match metadata_at(runs, file_name(&paths.run_directory)?) {
                Err(error) if error.kind() == ErrorKind::NotFound => None,
                Err(error) => return Err(error).context("inspect exact project run directory"),
                Ok(_) => Some(PinnedDirectory::capture(
                    &paths.run_directory,
                    DirectoryKind::Run,
                    owner,
                )?),
            },
        };
        let plan = Self {
            target,
            runs,
            run,
            paths,
            owner,
        };
        plan.validate(false)?;
        Ok(plan)
    }

    pub(super) fn run_exists(&self) -> bool {
        self.run.is_some()
    }

    pub(super) fn stack_exists(&self) -> bool {
        self.run
            .as_ref()
            .is_some_and(|run| run.files.iter().any(|file| file.name == "stack.json"))
    }

    pub(super) fn validate_after_down(&self) -> Result<()> {
        self.validate(true)
    }

    fn validate(&self, allow_wallet_absent: bool) -> Result<()> {
        self.target.validate(self.owner, None)?;
        match &self.runs {
            Some(runs) => {
                runs.validate(self.owner, Some(DIRECTORY_MODE))?;
                let target_name = file_name(&runs.path)?;
                validate_identity_at(
                    &self.target,
                    target_name,
                    &runs.identity,
                    EntryKind::Directory,
                    self.owner,
                )?;
            }
            None => ensure!(
                metadata_at(&self.target, "bip448-runs")
                    .is_err_and(|error| error.kind() == ErrorKind::NotFound),
                "runs root appeared after reset preflight"
            ),
        }
        match (&self.runs, &self.run) {
            (Some(runs), Some(run)) => {
                let name = file_name(&self.paths.run_directory)?;
                validate_identity_at(runs, name, &run.identity, EntryKind::Directory, self.owner)?;
                run.validate(self.owner, allow_wallet_absent)?;
            }
            (Some(runs), None) => ensure!(
                metadata_at(runs, file_name(&self.paths.run_directory)?)
                    .is_err_and(|error| error.kind() == ErrorKind::NotFound),
                "run directory appeared after reset preflight"
            ),
            (None, None) => {}
            (None, Some(_)) => bail!("captured run directory has no runs root"),
        }
        Ok(())
    }

    pub(super) fn prove_absent(&self) -> Result<()> {
        self.target.validate(self.owner, None)?;
        if let Some(runs) = &self.runs {
            runs.validate(self.owner, Some(DIRECTORY_MODE))?;
            ensure!(
                metadata_at(runs, file_name(&self.paths.run_directory)?)
                    .is_err_and(|error| error.kind() == ErrorKind::NotFound),
                "run directory remains after reset"
            );
        } else {
            ensure!(
                metadata_at(&self.target, "bip448-runs")
                    .is_err_and(|error| error.kind() == ErrorKind::NotFound),
                "runs root appeared during absent reset"
            );
        }
        Ok(())
    }
}

pub(super) struct Anchor {
    pub(super) path: PathBuf,
    file: File,
    pub(super) identity: Identity,
}

impl Anchor {
    fn open(path: &Path, owner: u32, mode: Option<u32>) -> Result<Self> {
        let metadata = validate_metadata(path, EntryKind::Directory, owner, mode)?;
        let file = File::open(path)
            .with_context(|| format!("pin cleanup directory {}", path.display()))?;
        let opened = file.metadata()?;
        let identity = Identity::from(&metadata);
        ensure!(
            identity == Identity::from(&opened),
            "cleanup directory changed while being pinned: {}",
            path.display()
        );
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
        })
    }

    fn validate(&self, owner: u32, mode: Option<u32>) -> Result<()> {
        let metadata = validate_metadata(&self.path, EntryKind::Directory, owner, mode)?;
        ensure!(
            Identity::from(&metadata) == self.identity
                && Identity::from(&self.file.metadata()?) == self.identity,
            "pinned cleanup directory was replaced: {}",
            self.path.display()
        );
        Ok(())
    }
}

pub(super) struct PinnedDirectory {
    pub(super) anchor: Anchor,
    pub(super) identity: Identity,
    pub(super) files: Vec<PinnedFile>,
    pub(super) directories: Vec<PinnedDirectory>,
}

impl PinnedDirectory {
    fn capture(path: &Path, kind: DirectoryKind, owner: u32) -> Result<Self> {
        let anchor = Anchor::open(path, owner, Some(DIRECTORY_MODE))?;
        let identity = anchor.identity;
        let mut files = Vec::new();
        let mut directories = Vec::new();
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("read cleanup directory {}", path.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("cleanup entry name is not UTF-8"))?;
            let entry_path = path.join(&name);
            match kind.classify(&name)? {
                AllowedEntry::Directory(child_kind) => {
                    directories.push(Self::capture(&entry_path, child_kind, owner)?)
                }
                AllowedEntry::File(file_kind) => {
                    let observed_mode = metadata_mode(&entry_path)?;
                    file_kind.validate_mode(observed_mode)?;
                    let metadata = validate_metadata(
                        &entry_path,
                        EntryKind::File,
                        owner,
                        Some(file_kind.mode(&observed_mode)),
                    )?;
                    ensure!(
                        metadata.nlink() == 1,
                        "cleanup file has more than one hard link: {}",
                        entry_path.display()
                    );
                    files.push(PinnedFile {
                        name,
                        identity: Identity::from(&metadata),
                        kind: file_kind,
                    });
                }
            }
        }
        Ok(Self {
            anchor,
            identity,
            files,
            directories,
        })
    }

    pub(super) fn validate(&self, owner: u32, allow_wallet_absent: bool) -> Result<()> {
        self.anchor.validate(owner, Some(DIRECTORY_MODE))?;
        let actual = directory_names(&self.anchor)?;
        let expected = self
            .files
            .iter()
            .filter(|file| {
                !(allow_wallet_absent
                    && file.kind == FileKind::Wallet
                    && !file.exists(&self.anchor))
            })
            .map(|file| file.name.clone())
            .chain(self.directories.iter().map(|directory| {
                directory
                    .anchor
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("")
                    .to_owned()
            }))
            .collect::<BTreeSet<_>>();
        ensure!(
            actual == expected,
            "cleanup directory contents changed or contain unexpected entries: {}",
            self.anchor.path.display()
        );
        for file in &self.files {
            if allow_wallet_absent && file.kind == FileKind::Wallet && !file.exists(&self.anchor) {
                continue;
            }
            file.validate(&self.anchor, owner)?;
        }
        for directory in &self.directories {
            let name = file_name(&directory.anchor.path)?;
            validate_identity_at(
                &self.anchor,
                name,
                &directory.identity,
                EntryKind::Directory,
                owner,
            )?;
            directory.validate(owner, allow_wallet_absent)?;
        }
        Ok(())
    }
}

pub(super) struct PinnedFile {
    pub(super) name: String,
    identity: Identity,
    pub(super) kind: FileKind,
}

impl PinnedFile {
    pub(super) fn exists(&self, parent: &Anchor) -> bool {
        metadata_at(parent, &self.name).is_ok()
    }

    pub(super) fn validate(&self, parent: &Anchor, owner: u32) -> Result<()> {
        let metadata =
            validate_identity_at(parent, &self.name, &self.identity, EntryKind::File, owner)?;
        ensure!(metadata.nlink() == 1, "cleanup file gained a hard link");
        self.kind
            .validate_mode(metadata.permissions().mode() & 0o7777)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryKind {
    Run,
    Operations,
    Operation,
}

impl DirectoryKind {
    fn classify(self, name: &str) -> Result<AllowedEntry> {
        match self {
            Self::Run => match name {
                "operations" => Ok(AllowedEntry::Directory(Self::Operations)),
                "Settings.toml" | "stack.json" => Ok(AllowedEntry::File(FileKind::Private)),
                "wallet.db" | "wallet.db-wal" | "wallet.db-shm" => {
                    Ok(AllowedEntry::File(FileKind::Wallet))
                }
                value if valid_run_temporary(value) => Ok(AllowedEntry::File(FileKind::Private)),
                _ => bail!("unexpected run-tree entry {name:?}"),
            },
            Self::Operations => {
                ensure!(
                    Uuid::parse_str(name).is_ok_and(|id| id.to_string() == name),
                    "operation directory name is not a canonical UUID: {name:?}"
                );
                Ok(AllowedEntry::Directory(Self::Operation))
            }
            Self::Operation => {
                ensure!(
                    matches!(
                        name,
                        "started.json" | "result.json" | "test.stdout" | "test.stderr"
                    ) || valid_evidence_temporary(name),
                    "unexpected operation entry {name:?}"
                );
                Ok(AllowedEntry::File(FileKind::Private))
            }
        }
    }
}

enum AllowedEntry {
    Directory(DirectoryKind),
    File(FileKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileKind {
    Private,
    Wallet,
}

impl FileKind {
    fn mode(self, observed: &u32) -> u32 {
        match self {
            Self::Private => PRIVATE_FILE_MODE,
            Self::Wallet => *observed,
        }
    }

    fn validate_mode(self, mode: u32) -> Result<()> {
        let valid = match self {
            Self::Private => mode == PRIVATE_FILE_MODE,
            // SQLite creates the disposable wallet with the process umask
            // (normally 0644); controller-created sidecars are 0600. No
            // writable group/other mode is accepted.
            Self::Wallet => matches!(mode, PRIVATE_FILE_MODE | SQLITE_FILE_MODE),
        };
        ensure!(valid, "cleanup file has a disallowed mode {mode:o}");
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    device: u64,
    inode: u64,
}

impl From<&fs::Metadata> for Identity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn validate_metadata(
    path: &Path,
    kind: EntryKind,
    owner: u32,
    mode: Option<u32>,
) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect cleanup path {}", path.display()))?;
    let expected_kind = match kind {
        EntryKind::Directory => metadata.is_dir(),
        EntryKind::File => metadata.is_file(),
    };
    ensure!(
        expected_kind && !metadata.file_type().is_symlink(),
        "cleanup path has an unsupported type: {}",
        path.display()
    );
    ensure!(
        metadata.uid() == owner,
        "cleanup path is not owned by the effective UID: {}",
        path.display()
    );
    if let Some(mode) = mode {
        ensure!(
            metadata.permissions().mode() & 0o7777 == mode,
            "cleanup path has wrong mode: {}",
            path.display()
        );
    }
    Ok(metadata)
}

pub(super) fn validate_identity_at(
    parent: &Anchor,
    name: &str,
    expected: &Identity,
    kind: EntryKind,
    owner: u32,
) -> Result<fs::Metadata> {
    let path = fd_child(parent, name);
    let metadata = validate_metadata(&path, kind, owner, None)?;
    ensure!(
        Identity::from(&metadata) == *expected,
        "validated cleanup entry was replaced: {}",
        parent.path.join(name).display()
    );
    Ok(metadata)
}

pub(super) fn directory_names(directory: &Anchor) -> Result<BTreeSet<String>> {
    fs::read_dir(fd_path(directory))?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "non-UTF-8 filename"))
        })
        .collect::<std::io::Result<_>>()
        .context("read pinned cleanup directory")
}

pub(super) fn metadata_at(parent: &Anchor, name: &str) -> std::io::Result<fs::Metadata> {
    fs::symlink_metadata(fd_child(parent, name))
}

fn fd_path(directory: &Anchor) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.file.as_raw_fd()))
}

pub(super) fn fd_child(directory: &Anchor, name: &str) -> PathBuf {
    fd_path(directory).join(name)
}

pub(super) fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .context("cleanup path name is not UTF-8")
}

fn metadata_mode(path: &Path) -> Result<u32> {
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o7777)
}

fn valid_run_temporary(name: &str) -> bool {
    matches!(name, ".Settings.toml.tmp" | ".stack.json.tmp")
        || name
            .strip_prefix(".stack.json.")
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(|nonce| {
                nonce.len() == 32
                    && nonce
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn valid_evidence_temporary(name: &str) -> bool {
    [
        ".started.json.",
        ".result.json.",
        ".test.stdout.",
        ".test.stderr.",
    ]
    .iter()
    .find_map(|prefix| name.strip_prefix(prefix))
    .and_then(|rest| rest.strip_suffix(".tmp"))
    .is_some_and(|id| Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id))
}

#[cfg(test)]
mod tests {
    use std::fs::{DirBuilder, OpenOptions};
    use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt};

    use super::*;
    use crate::workflow::model::Project;
    use crate::workflow::project_lock::ProjectLock;

    struct Fixture {
        root: PathBuf,
        paths: RunPaths,
    }

    impl Fixture {
        fn new(project_name: &str, run: bool) -> Self {
            let root = std::env::temp_dir().join(format!("bip448-reset-{}", Uuid::new_v4()));
            directory(&root, 0o700);
            directory(&root.join("target"), 0o700);
            directory(&root.join("target/bip448-runs"), DIRECTORY_MODE);
            let project = Project::parse(project_name).unwrap();
            let paths = RunPaths::new(&root, &project);
            if run {
                directory(&paths.run_directory, DIRECTORY_MODE);
            }
            Self { root, paths }
        }

        fn private(&self, name: &str) -> PathBuf {
            let path = self.paths.run_directory.join(name);
            regular(&path, PRIVATE_FILE_MODE);
            path
        }

        fn wallet(&self, name: &str, mode: u32) -> PathBuf {
            let path = self.paths.run_directory.join(name);
            regular(&path, mode);
            path
        }

        fn operation(&self, id: &str) -> PathBuf {
            let operations = self.paths.run_directory.join("operations");
            if !operations.exists() {
                directory(&operations, DIRECTORY_MODE);
            }
            let operation = operations.join(id);
            directory(&operation, DIRECTORY_MODE);
            operation
        }

        fn cleanup_anchors(self) {
            fs::remove_dir(self.root.join("target/bip448-runs")).unwrap();
            fs::remove_dir(self.root.join("target")).unwrap();
            fs::remove_dir(self.root).unwrap();
        }
    }

    fn directory(path: &Path, mode: u32) {
        DirBuilder::new().mode(mode).create(path).unwrap();
    }

    fn regular(path: &Path, mode: u32) {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .unwrap();
    }

    fn complete_tree() -> Fixture {
        let fixture = Fixture::new("tree", true);
        fixture.private("Settings.toml");
        fixture.private("stack.json");
        fixture.private(".Settings.toml.tmp");
        fixture.private(".stack.json.tmp");
        fixture.private(".stack.json.0123456789abcdef0123456789abcdef.tmp");
        fixture.wallet("wallet.db", 0o644);
        fixture.wallet("wallet.db-wal", PRIVATE_FILE_MODE);
        fixture.wallet("wallet.db-shm", 0o644);

        let complete = fixture.operation("00000000-0000-4000-8000-000000000001");
        for name in ["started.json", "result.json", "test.stdout", "test.stderr"] {
            regular(&complete.join(name), PRIVATE_FILE_MODE);
        }
        regular(
            &complete.join(".result.json.00000000-0000-4000-8000-000000000011.tmp"),
            PRIVATE_FILE_MODE,
        );
        let incomplete = fixture.operation("00000000-0000-4000-8000-000000000002");
        regular(&incomplete.join("started.json"), PRIVATE_FILE_MODE);
        fixture
    }

    #[test]
    fn exact_complete_incomplete_and_atomic_temp_tree_is_removed_bottom_up() {
        let fixture = complete_tree();
        let plan = TreePlan::capture(fixture.paths.clone()).unwrap();
        assert!(plan.stack_exists());
        plan.delete().unwrap();
        assert!(fixture
            .paths
            .run_directory
            .symlink_metadata()
            .is_err_and(|error| error.kind() == ErrorKind::NotFound));
        fixture.cleanup_anchors();
    }

    #[test]
    fn absent_project_is_an_exact_repeatable_noop() {
        let fixture = Fixture::new("absent", false);
        TreePlan::capture(fixture.paths.clone())
            .unwrap()
            .delete()
            .unwrap();
        TreePlan::capture(fixture.paths.clone())
            .unwrap()
            .delete()
            .unwrap();
        fixture.cleanup_anchors();
    }

    #[test]
    fn unexpected_name_symlink_type_mode_hardlink_and_alien_owner_fail_closed() {
        let fixture = Fixture::new("reject", true);
        let settings = fixture.private("Settings.toml");

        let alien = fixture.paths.run_directory.join("alien");
        regular(&alien, PRIVATE_FILE_MODE);
        assert!(TreePlan::capture(fixture.paths.clone()).is_err());
        fs::remove_file(&alien).unwrap();

        let outside = fixture.root.join("outside");
        regular(&outside, PRIVATE_FILE_MODE);
        let stack = fixture.paths.run_directory.join("stack.json");
        symlink(&outside, &stack).unwrap();
        assert!(TreePlan::capture(fixture.paths.clone()).is_err());
        fs::remove_file(&stack).unwrap();
        regular(&stack, PRIVATE_FILE_MODE);

        let wallet = fixture.wallet("wallet.db", 0o666);
        assert!(TreePlan::capture(fixture.paths.clone()).is_err());
        fs::set_permissions(&wallet, fs::Permissions::from_mode(0o644)).unwrap();

        let hardlink = fixture.root.join("settings-hardlink");
        fs::hard_link(&settings, &hardlink).unwrap();
        assert!(TreePlan::capture(fixture.paths.clone()).is_err());
        fs::remove_file(&hardlink).unwrap();

        let metadata = fs::symlink_metadata(&settings).unwrap();
        assert!(validate_metadata(
            &settings,
            EntryKind::File,
            metadata.uid().wrapping_add(1),
            Some(PRIVATE_FILE_MODE)
        )
        .is_err());

        TreePlan::capture(fixture.paths.clone())
            .unwrap()
            .delete()
            .unwrap();
        fs::remove_file(outside).unwrap();
        fixture.cleanup_anchors();
    }

    #[test]
    fn parent_substitution_and_post_capture_entries_are_detected_before_delete() {
        let fixture = Fixture::new("replace", true);
        fixture.private("Settings.toml");
        let plan = TreePlan::capture(fixture.paths.clone()).unwrap();
        let saved = fixture.paths.run_directory.with_file_name("replace.saved");
        fs::rename(&fixture.paths.run_directory, &saved).unwrap();
        directory(&fixture.paths.run_directory, DIRECTORY_MODE);
        assert!(plan.validate_after_down().is_err());
        fs::remove_dir(&fixture.paths.run_directory).unwrap();
        fs::rename(&saved, &fixture.paths.run_directory).unwrap();

        let unexpected = fixture.paths.run_directory.join("new-after-preflight");
        regular(&unexpected, PRIVATE_FILE_MODE);
        assert!(plan.validate_after_down().is_err());
        fs::remove_file(unexpected).unwrap();
        plan.delete().unwrap();
        fixture.cleanup_anchors();
    }

    #[test]
    fn lifecycle_wallet_removal_is_the_only_allowed_predelete_disappearance() {
        let fixture = Fixture::new("wallet_gone", true);
        fixture.private("Settings.toml");
        let wallet = fixture.wallet("wallet.db", 0o644);
        let plan = TreePlan::capture(fixture.paths.clone()).unwrap();
        fs::remove_file(wallet).unwrap();
        plan.validate_after_down().unwrap();
        plan.delete().unwrap();
        fixture.cleanup_anchors();
    }

    #[test]
    fn stable_project_lock_inode_is_retained_and_reusable() {
        let fixture = Fixture::new("lock_reuse", true);
        fixture.private("Settings.toml");
        let project = Project::parse("lock_reuse").unwrap();
        drop(ProjectLock::acquire(&fixture.root, &project).unwrap());
        let lock = fixture
            .root
            .join("target/bip448-controller-locks/lock_reuse.lock");
        let inode = fs::symlink_metadata(&lock).unwrap().ino();

        TreePlan::capture(fixture.paths.clone())
            .unwrap()
            .delete()
            .unwrap();
        drop(ProjectLock::acquire(&fixture.root, &project).unwrap());
        assert_eq!(fs::symlink_metadata(&lock).unwrap().ino(), inode);

        fs::remove_file(lock).unwrap();
        fs::remove_dir(fixture.root.join("target/bip448-controller-locks")).unwrap();
        fixture.cleanup_anchors();
    }
}
