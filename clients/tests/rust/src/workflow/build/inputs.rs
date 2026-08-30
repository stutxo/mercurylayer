use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component as PathComponent, Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InputComponent {
    Mercury,
    Token,
    Lockbox,
    Inquisition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum InputKind {
    Directory,
    File,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct InputRecord {
    pub(super) relative: PathBuf,
    pub(super) kind: InputKind,
}

pub(super) fn component_records(
    repo_root: &Path,
    component: InputComponent,
) -> Result<Vec<InputRecord>> {
    let mut records = Vec::new();
    match component {
        InputComponent::Mercury => {
            let ignore = root_dockerignore(repo_root)?;
            add_regular(repo_root, Path::new(".dockerignore"), &mut records)?;
            add_regular(repo_root, Path::new("Cargo.lock"), &mut records)?;
            add_regular(repo_root, Path::new("Rocket.toml"), &mut records)?;
            walk_tree(
                repo_root,
                Path::new("server"),
                Some((&ignore, Path::new(""))),
                true,
                &mut records,
            )?;
            walk_tree(
                repo_root,
                Path::new("lib"),
                Some((&ignore, Path::new(""))),
                true,
                &mut records,
            )?;
        }
        InputComponent::Token => {
            let ignore = root_dockerignore(repo_root)?;
            add_regular(repo_root, Path::new(".dockerignore"), &mut records)?;
            add_regular(repo_root, Path::new("Cargo.lock"), &mut records)?;
            walk_tree(
                repo_root,
                Path::new("token-server"),
                Some((&ignore, Path::new(""))),
                true,
                &mut records,
            )?;
        }
        InputComponent::Lockbox => {
            let ignore_path = Path::new("lockbox/.dockerignore");
            let ignore = DockerIgnore::parse(&read_regular(repo_root, ignore_path)?)?;
            walk_tree(
                repo_root,
                Path::new("lockbox"),
                Some((&ignore, Path::new("lockbox"))),
                true,
                &mut records,
            )?;
        }
        InputComponent::Inquisition => {
            walk_tree(
                repo_root,
                Path::new("docker/bitcoin-inquisition"),
                None,
                true,
                &mut records,
            )?;
        }
    }
    records.sort_by(|left, right| {
        left.relative
            .as_os_str()
            .as_bytes()
            .cmp(right.relative.as_os_str().as_bytes())
            .then_with(|| left.kind.cmp(&right.kind))
    });
    ensure!(
        records
            .windows(2)
            .all(|pair| pair[0].relative != pair[1].relative),
        "build input record set contains a duplicate path"
    );
    Ok(records)
}

#[cfg(test)]
pub(super) fn component_paths(repo_root: &Path, component: InputComponent) -> Result<Vec<PathBuf>> {
    Ok(component_records(repo_root, component)?
        .into_iter()
        .filter(|record| record.kind == InputKind::File)
        .map(|record| record.relative)
        .collect())
}

pub(super) fn root_dockerignore(repo_root: &Path) -> Result<DockerIgnore> {
    DockerIgnore::parse(&read_regular(repo_root, Path::new(".dockerignore"))?)
        .context("parse repository-root .dockerignore")
}

fn walk_tree(
    repo_root: &Path,
    relative_directory: &Path,
    dockerignore: Option<(&DockerIgnore, &Path)>,
    include_directory: bool,
    output: &mut Vec<InputRecord>,
) -> Result<bool> {
    let _ = directory_metadata(repo_root, relative_directory)?;
    let directory = repo_root.join(relative_directory);
    let mut children = Vec::new();
    let mut entries = fs::read_dir(&directory)
        .with_context(|| format!("read build input directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });

    for entry in entries {
        let relative = relative_directory.join(entry.file_name());
        validate_relative(&relative)?;
        let metadata = fs::symlink_metadata(entry.path())
            .with_context(|| format!("inspect build input {}", relative.display()))?;
        let context_relative = dockerignore
            .map(|(_, context)| {
                relative
                    .strip_prefix(context)
                    .context("build input escaped its Docker context")
            })
            .transpose()?;
        let ignored = match (dockerignore, context_relative) {
            (Some((ignore, _)), Some(path)) => {
                let always_sent =
                    path == Path::new("Dockerfile") || path == Path::new(".dockerignore");
                !always_sent && ignore.is_ignored(path)
            }
            _ => false,
        };

        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if ignored && dockerignore.is_some_and(|(ignore, _)| !ignore.has_negations()) {
                continue;
            }
            walk_tree(repo_root, &relative, dockerignore, !ignored, &mut children)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            if !ignored {
                children.push(InputRecord {
                    relative,
                    kind: InputKind::File,
                });
            }
        } else if !ignored {
            bail!(
                "build input {} is a link or special file",
                entry.path().display()
            );
        }
    }

    if include_directory || !children.is_empty() {
        output.push(InputRecord {
            relative: relative_directory.to_path_buf(),
            kind: InputKind::Directory,
        });
        output.append(&mut children);
        Ok(true)
    } else {
        Ok(false)
    }
}

fn add_regular(repo_root: &Path, relative: &Path, output: &mut Vec<InputRecord>) -> Result<()> {
    let _ = regular_metadata(repo_root, relative)?;
    output.push(InputRecord {
        relative: relative.to_path_buf(),
        kind: InputKind::File,
    });
    Ok(())
}

pub(super) fn read_regular(repo_root: &Path, relative: &Path) -> Result<Vec<u8>> {
    let before = regular_metadata(repo_root, relative)?;
    let path = repo_root.join(relative);
    let mut file = File::open(&path)
        .with_context(|| format!("open regular build input {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened build input {}", path.display()))?;
    ensure!(
        opened.is_file() && opened.dev() == before.dev() && opened.ino() == before.ino(),
        "build input {} changed type or identity while opening",
        path.display()
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read build input {}", path.display()))?;
    let after = fs::symlink_metadata(&path)
        .with_context(|| format!("reinspect build input {}", path.display()))?;
    ensure!(
        after.is_file()
            && !after.file_type().is_symlink()
            && after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.len() == bytes.len() as u64
            && (after.permissions().mode() & 0o7777) == (before.permissions().mode() & 0o7777),
        "build input {} changed while reading",
        path.display()
    );
    Ok(bytes)
}

pub(super) fn regular_metadata(repo_root: &Path, relative: &Path) -> Result<fs::Metadata> {
    typed_metadata(repo_root, relative, InputKind::File)
}

pub(super) fn directory_metadata(repo_root: &Path, relative: &Path) -> Result<fs::Metadata> {
    typed_metadata(repo_root, relative, InputKind::Directory)
}

fn typed_metadata(repo_root: &Path, relative: &Path, kind: InputKind) -> Result<fs::Metadata> {
    validate_relative(relative)?;
    ensure!(repo_root.is_absolute(), "repository root must be absolute");
    let path = repo_root.join(relative);
    ensure!(
        path.starts_with(repo_root),
        "build input path escaped repository root"
    );
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect build input {}", path.display()))?;
    let expected_type = match kind {
        InputKind::Directory => metadata.is_dir(),
        InputKind::File => metadata.is_file(),
    };
    ensure!(
        expected_type && !metadata.file_type().is_symlink(),
        "build input {} has an unexpected type",
        path.display()
    );
    Ok(metadata)
}

fn validate_relative(path: &Path) -> Result<()> {
    ensure!(!path.as_os_str().is_empty(), "build input path is empty");
    ensure!(!path.is_absolute(), "build input path must be relative");
    ensure!(
        path.components()
            .all(|component| matches!(component, PathComponent::Normal(_))),
        "build input path contains a non-normal component: {}",
        path.display()
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IgnorePattern {
    pattern: Vec<u8>,
    negated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DockerIgnore {
    patterns: Vec<IgnorePattern>,
}

impl DockerIgnore {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self> {
        let contents = std::str::from_utf8(bytes).context(".dockerignore is not UTF-8")?;
        let mut patterns = Vec::new();
        for raw in contents.lines() {
            let mut line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let negated = line.starts_with('!');
            if negated {
                line = line[1..].trim();
                ensure!(!line.is_empty(), "invalid empty .dockerignore negation");
            }
            while let Some(stripped) = line.strip_prefix("./") {
                line = stripped;
            }
            line = line.trim_matches('/');
            ensure!(
                !line.is_empty() && line != "." && !line.split('/').any(|part| part == ".."),
                "invalid .dockerignore pattern {raw:?}"
            );
            patterns.push(IgnorePattern {
                pattern: line.as_bytes().to_vec(),
                negated,
            });
        }
        Ok(Self { patterns })
    }

    fn has_negations(&self) -> bool {
        self.patterns.iter().any(|pattern| pattern.negated)
    }

    pub(super) fn is_ignored(&self, relative: &Path) -> bool {
        let path = relative.as_os_str().as_bytes();
        let mut ignored = false;
        for pattern in &self.patterns {
            if matches_path_or_parent(&pattern.pattern, path) {
                ignored = !pattern.negated;
            }
        }
        ignored
    }
}

fn matches_path_or_parent(pattern: &[u8], path: &[u8]) -> bool {
    if pattern_matches(pattern, path) {
        return true;
    }
    path.iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .any(|(index, _)| pattern_matches(pattern, &path[..index]))
}

fn pattern_matches(pattern: &[u8], path: &[u8]) -> bool {
    if glob_matches(pattern, path) {
        return true;
    }
    if pattern.contains(&b'/') {
        return false;
    }
    path.split(|byte| *byte == b'/')
        .any(|name| glob_matches(pattern, name))
}

fn glob_matches(pattern: &[u8], value: &[u8]) -> bool {
    fn matches(
        pattern: &[u8],
        value: &[u8],
        p: usize,
        v: usize,
        memo: &mut BTreeMap<(usize, usize), bool>,
    ) -> bool {
        if let Some(result) = memo.get(&(p, v)) {
            return *result;
        }
        let result = if p == pattern.len() {
            v == value.len()
        } else if pattern[p] == b'*' {
            if p + 1 < pattern.len() && pattern[p + 1] == b'*' {
                let mut next = p + 2;
                while next < pattern.len() && pattern[next] == b'*' {
                    next += 1;
                }
                matches(pattern, value, next, v, memo)
                    || (pattern.get(next) == Some(&b'/')
                        && matches(pattern, value, next + 1, v, memo))
                    || (v < value.len() && matches(pattern, value, p, v + 1, memo))
            } else {
                matches(pattern, value, p + 1, v, memo)
                    || (v < value.len()
                        && value[v] != b'/'
                        && matches(pattern, value, p, v + 1, memo))
            }
        } else if pattern[p] == b'?' {
            v < value.len() && value[v] != b'/' && matches(pattern, value, p + 1, v + 1, memo)
        } else if pattern[p] == b'[' {
            let (class_matches, next) = match_character_class(pattern, p, value.get(v).copied());
            class_matches && matches(pattern, value, next, v + 1, memo)
        } else {
            v < value.len() && pattern[p] == value[v] && matches(pattern, value, p + 1, v + 1, memo)
        };
        memo.insert((p, v), result);
        result
    }
    matches(pattern, value, 0, 0, &mut BTreeMap::new())
}

fn match_character_class(pattern: &[u8], start: usize, value: Option<u8>) -> (bool, usize) {
    let Some(value) = value.filter(|value| *value != b'/') else {
        return (false, start + 1);
    };
    let mut index = start + 1;
    let negated = pattern
        .get(index)
        .is_some_and(|byte| *byte == b'!' || *byte == b'^');
    if negated {
        index += 1;
    }
    let mut matched = false;
    let mut found_end = false;
    while index < pattern.len() {
        if pattern[index] == b']' {
            found_end = true;
            index += 1;
            break;
        }
        if index + 2 < pattern.len() && pattern[index + 1] == b'-' && pattern[index + 2] != b']' {
            matched |= (pattern[index]..=pattern[index + 2]).contains(&value);
            index += 3;
        } else {
            matched |= pattern[index] == value;
            index += 1;
        }
    }
    if !found_end {
        return (value == b'[', start + 1);
    }
    (if negated { !matched } else { matched }, index)
}
