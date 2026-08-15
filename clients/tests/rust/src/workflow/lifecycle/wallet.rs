use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

use super::super::model::RunPaths;

pub(super) fn remove_wallet_artifacts(paths: &RunPaths) -> Result<()> {
    let uid = effective_uid()?;
    let candidates = wallet_artifacts(paths);
    let mut existing = Vec::new();
    for path in &candidates {
        ensure!(
            path.parent() == Some(paths.run_directory.as_path()),
            "wallet artifact is outside the exact run directory"
        );
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_candidate(path, &metadata, uid)?;
                existing.push(path.clone());
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect wallet artifact {}", path.display()));
            }
        }
    }
    for path in &existing {
        fs::remove_file(path)
            .with_context(|| format!("remove exact wallet artifact {}", path.display()))?;
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Ok(_) => anyhow::bail!(
                "wallet artifact still exists after removal: {}",
                path.display()
            ),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("prove wallet artifact absent {}", path.display()));
            }
        }
    }
    Ok(())
}

pub(super) fn wallet_artifacts(paths: &RunPaths) -> [PathBuf; 3] {
    [
        paths.wallet_database.clone(),
        append_suffix(&paths.wallet_database, "-wal"),
        append_suffix(&paths.wallet_database, "-shm"),
    ]
}

fn validate_candidate(path: &Path, metadata: &fs::Metadata, uid: u32) -> Result<()> {
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "wallet artifact must be a regular nonsymlink file: {}",
        path.display()
    );
    ensure!(
        metadata.uid() == uid,
        "wallet artifact is not owned by the current effective UID: {}",
        path.display()
    );
    Ok(())
}

fn effective_uid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status").context("read current effective UID")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .context("process status has no Uid field")?;
    let values = line
        .split_ascii_whitespace()
        .skip(1)
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("process Uid field is malformed")?;
    ensure!(values.len() == 4, "process Uid field has the wrong arity");
    Ok(values[1])
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    value.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_requires_a_regular_current_uid_file() {
        let metadata = fs::metadata("/proc/self/status").unwrap();
        assert!(
            validate_candidate(Path::new("/proc/self/status"), &metadata, metadata.uid()).is_ok()
        );
        assert!(validate_candidate(
            Path::new("/proc/self/status"),
            &metadata,
            metadata.uid() + 1
        )
        .is_err());
        let directory = fs::metadata("/proc/self").unwrap();
        assert!(validate_candidate(Path::new("/proc/self"), &directory, directory.uid()).is_err());
    }
}
