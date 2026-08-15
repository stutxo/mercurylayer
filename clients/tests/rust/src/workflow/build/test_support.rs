use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use uuid::Uuid;

use super::super::model::{PortMap, Project, StackMetadata};
use super::{ArgvCommand, CommandOutput, CommandRunner, INQUISITION_COMMIT};

pub(super) struct TempRepository(PathBuf);

impl TempRepository {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bip448-build-test-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).unwrap();
        let root = path.canonicalize().unwrap();
        let fixture = Self(root);
        fixture.populate();
        fixture
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    pub(super) fn write(&self, relative: &str, contents: &[u8]) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    pub(super) fn metadata(&self) -> StackMetadata {
        StackMetadata::new(
            &self.0,
            Project::parse("mock_build").unwrap(),
            PortMap::from_base(24000).unwrap(),
        )
    }

    fn populate(&self) {
        self.write("Cargo.lock", b"lock\n");
        self.write("Rocket.toml", b"[default]\n");
        self.write("server/Dockerfile", b"FROM scratch\nCOPY server /server\n");
        self.write("server/src/main.rs", b"fn main() {}\n");
        self.write("server/.dockerignore", b"Settings.toml\n");
        self.write("lib/Cargo.toml", b"[package]\nname='fixture'\n");
        self.write("lib/src/lib.rs", b"pub fn fixture() {}\n");
        self.write(
            "token-server-v2/Dockerfile",
            b"FROM scratch\nCOPY token-server-v2 /token\n",
        );
        self.write("token-server-v2/src/main.rs", b"fn main() {}\n");
        self.write("token-server-v2/.dockerignore", b"Settings.toml\n");
        self.write("lockbox/.dockerignore", b"Settings.toml\nbuild/**\n");
        self.write(
            "lockbox/Dockerfile",
            b"FROM scratch\nARG LOCKBOX_ENABLE_TEST_RNG=OFF\nCOPY . .\n",
        );
        self.write("lockbox/src/main.cpp", b"int main() { return 0; }\n");
        self.write("lockbox/Settings.toml", b"ignored=true\n");
        self.write("lockbox/build/generated", b"ignored\n");
        self.write(
            "docker/bitcoin-inquisition/Dockerfile",
            format!("FROM scratch\nARG BITCOIN_INQUISITION_COMMIT={INQUISITION_COMMIT}\n")
                .as_bytes(),
        );
        self.write("docker/bitcoin-inquisition/context.txt", b"context\n");
        self.write(
            "docker-compose-token-servers.yml",
            format!(
                "BITCOIN_INQUISITION_COMMIT: {INQUISITION_COMMIT}\nimage: mercurylayer/bitcoin-inquisition:f536586\n"
            )
            .as_bytes(),
        );
        self.write(
            "docker-compose-lockbox.yml",
            b"LOCKBOX_ENABLE_TEST_RNG: ${LOCKBOX_ENABLE_TEST_RNG:-OFF}\n",
        );
    }
}

impl Drop for TempRepository {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[derive(Default)]
pub(super) struct MockRunner {
    pub(super) commands: Vec<ArgvCommand>,
    pub(super) images: BTreeMap<String, String>,
    pub(super) build_count: usize,
    pub(super) fail_build: bool,
    pub(super) fail_tag: bool,
    pub(super) failed_build_leaves_tag: bool,
    pub(super) drift_after_build: bool,
    pub(super) containers: bool,
    pub(super) collision_after_build: Option<(String, String)>,
    pub(super) next_id: u64,
}

impl MockRunner {
    pub(super) fn image_id(number: u64) -> String {
        format!("sha256:{number:064x}")
    }

    fn success(stdout: impl Into<Vec<u8>>) -> CommandOutput {
        CommandOutput {
            success: true,
            code: Some(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    fn failure(stderr: impl Into<Vec<u8>>) -> CommandOutput {
        CommandOutput {
            success: false,
            code: Some(1),
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }
}

impl CommandRunner for MockRunner {
    fn run(&mut self, command: &ArgvCommand) -> Result<CommandOutput> {
        self.commands.push(command.clone());
        let program = command.program.to_str().unwrap_or_default();
        let args = command
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        match (program, args.first().map(String::as_str)) {
            ("git", Some("rev-parse")) => Ok(Self::success(
                b"0123456789abcdef0123456789abcdef01234567\n".to_vec(),
            )),
            ("git", Some("status")) => {
                if self.drift_after_build && self.build_count > 0 {
                    Ok(Self::success(b" M server/src/main.rs\0".to_vec()))
                } else {
                    Ok(Self::success(Vec::new()))
                }
            }
            ("docker", Some("ps")) => {
                if self.containers {
                    Ok(Self::success(b"container-id\n".to_vec()))
                } else {
                    Ok(Self::success(Vec::new()))
                }
            }
            ("docker", Some("build")) => {
                let tag = option_value(&args, "--tag")?;
                self.build_count += 1;
                self.next_id += 1;
                let id = Self::image_id(self.next_id);
                if !self.fail_build || self.failed_build_leaves_tag {
                    self.images.insert(tag.to_owned(), id);
                }
                if self.fail_build {
                    Ok(Self::failure(b"controlled build failure\n".to_vec()))
                } else {
                    Ok(Self::success(Vec::new()))
                }
            }
            ("docker", Some("image")) if args.get(1).map(String::as_str) == Some("inspect") => {
                let tag = args.last().expect("inspect tag");
                if self.build_count > 0 {
                    if let Some((collision_tag, collision_id)) = &self.collision_after_build {
                        if tag == collision_tag {
                            return Ok(Self::success(format!("{collision_id}\n").into_bytes()));
                        }
                    }
                }
                match self.images.get(tag) {
                    Some(id) => Ok(Self::success(format!("{id}\n").into_bytes())),
                    None => Ok(Self::failure(b"Error: No such image\n".to_vec())),
                }
            }
            ("docker", Some("image")) if args.get(1).map(String::as_str) == Some("tag") => {
                if self.fail_tag {
                    return Ok(Self::failure(b"controlled tag failure\n".to_vec()));
                }
                let source = args.get(2).expect("source tag");
                let destination = args.get(3).expect("destination tag");
                let id = self
                    .images
                    .get(source)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("mock source image is absent"))?;
                self.images.insert(destination.clone(), id);
                Ok(Self::success(Vec::new()))
            }
            ("docker", Some("image")) if args.get(1).map(String::as_str) == Some("rm") => {
                let tag = args.get(2).expect("remove tag");
                self.images.remove(tag);
                Ok(Self::success(Vec::new()))
            }
            _ => bail!("unexpected mock argv command: {command:?}"),
        }
    }
}

fn option_value<'a>(args: &'a [String], option: &str) -> Result<&'a str> {
    let index = args
        .iter()
        .position(|arg| arg == option)
        .ok_or_else(|| anyhow::anyhow!("mock command is missing {option}"))?;
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("mock command has no value for {option}"))
}

pub(super) fn command_has_arg(command: &ArgvCommand, value: &OsStr) -> bool {
    command.args.iter().any(|arg| arg == value)
}
