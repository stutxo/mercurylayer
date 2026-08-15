use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use uuid::Uuid;

use super::metadata_lock::MetadataLock;
use super::model::{canonical_json, parse_metadata, PortMap, Project, RunPaths, StackMetadata};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_METADATA_BYTES: u64 = 1_048_576;

pub fn configure(repo_root: &Path, project: Project, ports: PortMap) -> Result<StackMetadata> {
    let metadata = StackMetadata::new(repo_root, project, ports);
    metadata.validate(repo_root, metadata.project())?;
    ensure_run_absent(metadata.paths())?;
    let _reservations = reserve_ports(ports)?;
    create_run(&metadata)?;
    Ok(metadata)
}

pub fn status(repo_root: &Path, project: &Project) -> Result<StackMetadata> {
    let paths = RunPaths::new(repo_root, project);
    require_mode(
        &paths.run_directory,
        FileKind::Directory,
        PRIVATE_DIRECTORY_MODE,
    )?;
    require_mode(&paths.settings_file, FileKind::Regular, PRIVATE_FILE_MODE)?;
    let metadata_file = require_mode(&paths.stack_metadata, FileKind::Regular, PRIVATE_FILE_MODE)?;
    ensure!(
        metadata_file.len() <= MAX_METADATA_BYTES,
        "stack metadata is larger than {MAX_METADATA_BYTES} bytes"
    );

    let bytes = fs::read(&paths.stack_metadata)
        .with_context(|| format!("read stack metadata {}", paths.stack_metadata.display()))?;
    let metadata = parse_metadata(&bytes)?;
    metadata.validate(repo_root, project)?;

    let canonical = canonical_json(&metadata)?;
    ensure!(
        bytes == canonical.as_bytes(),
        "stack metadata is not in canonical JSON form"
    );
    let settings = fs::read_to_string(&paths.settings_file)
        .with_context(|| format!("read settings file {}", paths.settings_file.display()))?;
    ensure!(
        settings == metadata.settings_contents()?,
        "Settings.toml does not match stack metadata"
    );
    Ok(metadata)
}

pub fn replace_metadata(
    repo_root: &Path,
    project: &Project,
    expected: &StackMetadata,
    updated: &StackMetadata,
) -> Result<()> {
    expected.validate(repo_root, project)?;
    updated.validate(repo_root, project)?;
    ensure!(
        expected.paths() == updated.paths()
            && expected.ports() == updated.ports()
            && expected.endpoints() == updated.endpoints(),
        "build metadata update changed configured stack identity"
    );

    let mut lock = MetadataLock::acquire(&expected.paths().stack_metadata)?;
    let update = replace_metadata_locked(repo_root, project, expected, updated);
    let unlock = lock.release();
    match (update, unlock) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(unlock)) => Err(unlock),
        (Err(error), Err(unlock)) => {
            bail!("{error:#}; metadata update lock release also failed: {unlock:#}")
        }
    }
}

fn replace_metadata_locked(
    repo_root: &Path,
    project: &Project,
    expected: &StackMetadata,
    updated: &StackMetadata,
) -> Result<()> {
    ensure!(
        status(repo_root, project)? == *expected,
        "stack metadata changed after build began"
    );

    let path = &expected.paths().stack_metadata;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("stack metadata filename is not UTF-8")?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", Uuid::new_v4().simple()));
    let bytes = canonical_json(updated)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&temporary)
        .with_context(|| format!("create metadata update file {}", temporary.display()))?;
    let result = (|| {
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        drop(file);
        ensure!(
            status(repo_root, project)? == *expected,
            "stack metadata changed while build metadata was being committed"
        );
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "atomically replace stack metadata {} with {}",
                path.display(),
                temporary.display()
            )
        })?;
        sync_directory(path.parent().context("stack metadata has no parent")?)?;
        ensure!(
            status(repo_root, project)? == *updated,
            "stored build metadata did not round trip exactly"
        );
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = result {
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(cleanup) if cleanup.kind() == ErrorKind::NotFound => {}
            Err(cleanup) => {
                bail!(
                    "{error:#}; cleanup of metadata update file {} also failed: {cleanup}",
                    temporary.display()
                )
            }
        }
        return Err(error);
    }
    Ok(())
}

fn reserve_ports(ports: PortMap) -> Result<Vec<TcpListener>> {
    let mut reservations = Vec::with_capacity(8);
    for (role, port) in ports.ordered() {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        let listener = TcpListener::bind(address)
            .with_context(|| format!("required {role} port {port} is not free on 127.0.0.1"))?;
        reservations.push(listener);
    }
    Ok(reservations)
}

fn create_run(metadata: &StackMetadata) -> Result<()> {
    let paths = metadata.paths();
    prepare_runs_root(&paths.run_directory)?;
    ensure_run_absent(paths)?;
    DirBuilder::new()
        .mode(PRIVATE_DIRECTORY_MODE)
        .create(&paths.run_directory)
        .with_context(|| format!("create run directory {}", paths.run_directory.display()))?;

    let result = (|| {
        atomic_write(
            &paths.settings_file,
            metadata.settings_contents()?.as_bytes(),
        )?;
        atomic_write(&paths.stack_metadata, canonical_json(metadata)?.as_bytes())?;
        sync_directory(&paths.run_directory)?;
        sync_directory(
            paths
                .run_directory
                .parent()
                .context("run directory has no parent")?,
        )?;
        Ok(())
    })();

    if let Err(error) = result {
        if let Err(cleanup) = cleanup_created_run(paths) {
            bail!("{error:#}; cleanup of the new run directory also failed: {cleanup:#}");
        }
        return Err(error);
    }
    Ok(())
}

fn prepare_runs_root(run_directory: &Path) -> Result<()> {
    let runs_root = run_directory
        .parent()
        .context("run directory has no runs root")?;
    let target = runs_root
        .parent()
        .context("runs root has no target parent")?;
    ensure_directory(target, None)?;
    ensure_directory(runs_root, Some(PRIVATE_DIRECTORY_MODE))?;
    Ok(())
}

fn ensure_directory(path: &Path, required_mode: Option<u32>) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "{} must be a real directory",
                path.display()
            );
            if let Some(mode) = required_mode {
                ensure!(
                    metadata.permissions().mode() & 0o7777 == mode,
                    "{} must have mode {mode:o}",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(required_mode.unwrap_or(PRIVATE_DIRECTORY_MODE))
                .create(path)
                .with_context(|| format!("create directory {}", path.display()))?;
            sync_directory(path.parent().context("new directory has no parent")?)?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect directory {}", path.display()))
        }
    }
    Ok(())
}

fn ensure_run_absent(paths: &RunPaths) -> Result<()> {
    match fs::symlink_metadata(&paths.run_directory) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect run directory {}", paths.run_directory.display())),
        Ok(_) => bail!(
            "refusing to overwrite existing run directory {}",
            paths.run_directory.display()
        ),
    }
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect output file {}", path.display()))
        }
        Ok(_) => bail!("refusing to overwrite output file {}", path.display()),
    }

    let temporary = temporary_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&temporary)
        .with_context(|| format!("create temporary file {}", temporary.display()))?;
    if let Err(error) = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_directory(path.parent().context("output file has no parent")?)?;
        Ok::<_, anyhow::Error>(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("atomically write {}", path.display()));
    }
    Ok(())
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("output filename is not UTF-8")?;
    Ok(path.with_file_name(format!(".{name}.tmp")))
}

fn cleanup_created_run(paths: &RunPaths) -> Result<()> {
    for path in [
        temporary_path(&paths.settings_file)?,
        temporary_path(&paths.stack_metadata)?,
        paths.settings_file.clone(),
        paths.stack_metadata.clone(),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("remove {}", path.display())),
        }
    }
    fs::remove_dir(&paths.run_directory)
        .with_context(|| format!("remove run directory {}", paths.run_directory.display()))?;
    Ok(())
}

#[derive(Clone, Copy)]
enum FileKind {
    Directory,
    Regular,
}

fn require_mode(path: &Path, kind: FileKind, mode: u32) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect configured path {}", path.display()))?;
    let right_kind = match kind {
        FileKind::Directory => metadata.is_dir(),
        FileKind::Regular => metadata.is_file(),
    };
    ensure!(
        right_kind && !metadata.file_type().is_symlink(),
        "configured path {} has an unsupported type",
        path.display()
    );
    ensure!(
        metadata.permissions().mode() & 0o7777 == mode,
        "configured path {} must have mode {mode:o}",
        path.display()
    );
    Ok(metadata)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::workflow::metadata_lock::lock_path;
    use crate::workflow::model::{
        BuildFingerprints, BuildResolution, BuildSource, ComposeHashes, ResolvedImage,
        ResolvedImages, MERCURY_IMAGE_PREFIX,
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bip448-storage-test-{}-{}",
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

    fn metadata(root: &Path) -> StackMetadata {
        StackMetadata::new(
            root,
            Project::parse("storage_1").unwrap(),
            PortMap::from_base(23000).unwrap(),
        )
    }

    fn with_mercury_build(original: &StackMetadata, fingerprint_byte: char) -> StackMetadata {
        let fingerprint = fingerprint_byte.to_string().repeat(64);
        let mut images = ResolvedImages::default();
        images.set_mercury(ResolvedImage::new(
            fingerprint.clone(),
            format!("{MERCURY_IMAGE_PREFIX}{}", &fingerprint[..16]),
            format!("sha256:{fingerprint}"),
        ));
        let mut updated = original.clone();
        updated.set_build_resolution(BuildResolution::new(
            BuildSource::new(
                "0".repeat(40),
                "1".repeat(64),
                ComposeHashes::new("2".repeat(64), "3".repeat(64)),
            ),
            BuildFingerprints::new(fingerprint, "b".repeat(64), "c".repeat(64), "d".repeat(64)),
            images,
        ));
        updated
    }

    #[test]
    fn creation_is_private_atomic_and_round_trips_through_status() {
        let temp = TempDirectory::new();
        let metadata = metadata(&temp.0);
        create_run(&metadata).unwrap();

        let paths = metadata.paths();
        assert_eq!(
            fs::symlink_metadata(&paths.run_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        for path in [&paths.settings_file, &paths.stack_metadata] {
            assert_eq!(
                fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
        assert!(!paths.wallet_database.exists());
        assert!(!temporary_path(&paths.settings_file).unwrap().exists());
        assert!(!temporary_path(&paths.stack_metadata).unwrap().exists());
        assert_eq!(status(&temp.0, metadata.project()).unwrap(), metadata);
    }

    #[test]
    fn existing_run_and_metadata_mismatch_are_rejected() {
        let temp = TempDirectory::new();
        let metadata = metadata(&temp.0);
        create_run(&metadata).unwrap();
        assert!(create_run(&metadata).is_err());

        fs::write(
            &metadata.paths().settings_file,
            b"statechain_entity = \"wrong\"\n",
        )
        .unwrap();
        assert!(status(&temp.0, metadata.project()).is_err());
    }

    #[test]
    fn build_metadata_replacement_is_atomic_exact_and_rejects_stale_writers() {
        let temp = TempDirectory::new();
        let original = metadata(&temp.0);
        create_run(&original).unwrap();
        let settings_before = fs::read(&original.paths().settings_file).unwrap();

        let updated = with_mercury_build(&original, 'a');

        replace_metadata(&temp.0, original.project(), &original, &updated).unwrap();
        assert_eq!(status(&temp.0, original.project()).unwrap(), updated);
        assert_eq!(
            fs::read(&original.paths().settings_file).unwrap(),
            settings_before
        );
        assert!(fs::read_dir(&original.paths().run_directory)
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));

        assert!(replace_metadata(&temp.0, original.project(), &original, &updated).is_err());
        assert_eq!(status(&temp.0, original.project()).unwrap(), updated);
        assert!(!lock_path(&original.paths().stack_metadata)
            .unwrap()
            .exists());
    }

    #[test]
    fn crash_lock_residue_fails_closed_without_changing_metadata() {
        let temp = TempDirectory::new();
        let original = metadata(&temp.0);
        create_run(&original).unwrap();
        let updated = with_mercury_build(&original, 'a');
        let path = lock_path(&original.paths().stack_metadata).unwrap();
        let mut residue = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .open(&path)
            .unwrap();
        residue.write_all(b"crash residue").unwrap();
        residue.sync_all().unwrap();
        drop(residue);

        assert!(replace_metadata(&temp.0, original.project(), &original, &updated).is_err());
        assert_eq!(status(&temp.0, original.project()).unwrap(), original);
        assert_eq!(fs::read(path).unwrap(), b"crash residue");
    }

    #[test]
    fn concurrent_divergent_metadata_writers_have_one_exact_winner() {
        let temp = TempDirectory::new();
        let original = metadata(&temp.0);
        create_run(&original).unwrap();
        let left = with_mercury_build(&original, 'a');
        let right = with_mercury_build(&original, 'e');
        let barrier = Arc::new(Barrier::new(3));

        let spawn_writer = |updated: StackMetadata| {
            let root = temp.0.clone();
            let expected = original.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                replace_metadata(&root, expected.project(), &expected, &updated)
            })
        };
        let left_writer = spawn_writer(left.clone());
        let right_writer = spawn_writer(right.clone());
        barrier.wait();
        let left_result = left_writer.join().unwrap();
        let right_result = right_writer.join().unwrap();

        assert_eq!(
            usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()),
            1
        );
        let stored = status(&temp.0, original.project()).unwrap();
        if left_result.is_ok() {
            assert_eq!(stored, left);
        } else {
            assert_eq!(stored, right);
        }
        assert!(!lock_path(&original.paths().stack_metadata)
            .unwrap()
            .exists());
    }

    #[test]
    fn occupied_port_is_reported_before_any_run_is_created() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        if port > 65528 {
            return;
        }
        let ports = PortMap::from_base(port).unwrap();
        assert!(reserve_ports(ports).is_err());
    }
}
