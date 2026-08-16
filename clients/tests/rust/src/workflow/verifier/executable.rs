#[cfg(test)]
#[path = "executable_tests.rs"]
mod tests;

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::argv::ArgvCommand;

const PROC_SELF_EXE: &str = "/proc/self/exe";
const HIDDEN_HELPER: &str = "__bip448-verify-helper";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    sha256: String,
}

pub(super) fn helper_command(repo_root: &Path) -> Result<ArgvCommand> {
    command(repo_root, [HIDDEN_HELPER])
}

fn command<I, S>(repo_root: &Path, arguments: I) -> Result<ArgvCommand>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    inspect(PROC_SELF_EXE, super::real_uid()?)
        .context("authenticate kernel-pinned workflow executable")?;
    Ok(ArgvCommand::new(PROC_SELF_EXE, repo_root)
        .clear_environment()
        .args(arguments))
}

fn inspect(path: impl AsRef<Path>, expected_uid: u32) -> Result<ExecutableIdentity> {
    let path = path.as_ref();
    let mut file =
        File::open(path).with_context(|| format!("open pinned executable {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("fstat pinned executable {}", path.display()))?;
    validate_metadata(&before, expected_uid)?;

    let mut hasher = Sha256::new();
    let mut prefix = Vec::with_capacity(4);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read pinned executable {}", path.display()))?;
        if count == 0 {
            break;
        }
        if prefix.len() < 4 {
            let needed = 4 - prefix.len();
            prefix.extend_from_slice(&buffer[..count.min(needed)]);
        }
        hasher.update(&buffer[..count]);
    }
    ensure!(
        prefix == b"\x7fELF",
        "pinned executable is not an ELF image"
    );

    let after = file
        .metadata()
        .with_context(|| format!("refstat pinned executable {}", path.display()))?;
    let linked = fs::metadata(path)
        .with_context(|| format!("restat pinned executable target {}", path.display()))?;
    require_same_content_identity(&before, &after)?;
    require_same_content_identity(&before, &linked)?;

    Ok(ExecutableIdentity {
        device: before.dev(),
        inode: before.ino(),
        uid: before.uid(),
        mode: before.permissions().mode() & 0o7777,
        bytes: before.len(),
        modified_seconds: before.mtime(),
        modified_nanoseconds: before.mtime_nsec(),
        sha256: hex::encode(hasher.finalize()),
    })
}

fn validate_metadata(metadata: &Metadata, expected_uid: u32) -> Result<()> {
    let mode = metadata.permissions().mode() & 0o7777;
    ensure!(
        metadata.is_file(),
        "pinned executable is not a regular file"
    );
    ensure!(
        metadata.uid() == expected_uid,
        "pinned executable is not owned by the current UID"
    );
    ensure!(
        mode & 0o500 == 0o500 && mode & 0o002 == 0 && mode & 0o7000 == 0,
        "pinned executable lacks safe owner read/execute mode"
    );
    ensure!(metadata.len() > 4, "pinned executable is empty");
    Ok(())
}

fn require_same_content_identity(expected: &Metadata, actual: &Metadata) -> Result<()> {
    ensure!(
        expected.dev() == actual.dev()
            && expected.ino() == actual.ino()
            && expected.uid() == actual.uid()
            && (expected.permissions().mode() & 0o7777) == (actual.permissions().mode() & 0o7777)
            && expected.len() == actual.len()
            && expected.mtime() == actual.mtime()
            && expected.mtime_nsec() == actual.mtime_nsec(),
        "pinned executable inode or content identity changed during validation"
    );
    Ok(())
}
