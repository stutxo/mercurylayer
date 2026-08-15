use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use super::fingerprint::{hash_component, hash_paths, validate_contract};
use super::inputs::{component_paths, DockerIgnore, InputComponent};
use super::test_support::TempRepository;

#[test]
fn repository_root_dockerignore_must_be_absent_for_root_contexts() {
    let absent = TempRepository::new();
    validate_contract(absent.path()).unwrap();

    let regular = TempRepository::new();
    regular.write(".dockerignore", b"target\n");
    assert!(validate_contract(regular.path()).is_err());

    let directory = TempRepository::new();
    fs::create_dir(directory.path().join(".dockerignore")).unwrap();
    assert!(validate_contract(directory.path()).is_err());

    let linked = TempRepository::new();
    symlink("Cargo.lock", linked.path().join(".dockerignore")).unwrap();
    assert!(validate_contract(linked.path()).is_err());

    let special = TempRepository::new();
    let _socket = UnixListener::bind(special.path().join(".dockerignore")).unwrap();
    assert!(validate_contract(special.path()).is_err());
}

#[test]
fn component_path_sets_match_the_four_build_contracts() {
    let repo = TempRepository::new();
    let paths = |component| component_paths(repo.path(), component).unwrap();

    assert_eq!(
        paths(InputComponent::Mercury),
        path_list(&[
            "Cargo.lock",
            "Rocket.toml",
            "lib/Cargo.toml",
            "lib/src/lib.rs",
            "server/.dockerignore",
            "server/Dockerfile",
            "server/src/main.rs",
        ])
    );
    assert_eq!(
        paths(InputComponent::Token),
        path_list(&[
            "Cargo.lock",
            "token-server-v2/.dockerignore",
            "token-server-v2/Dockerfile",
            "token-server-v2/src/main.rs",
        ])
    );
    assert_eq!(
        paths(InputComponent::Lockbox),
        path_list(&[
            "lockbox/.dockerignore",
            "lockbox/Dockerfile",
            "lockbox/src/main.cpp",
        ])
    );
    assert_eq!(
        paths(InputComponent::Inquisition),
        path_list(&[
            "docker/bitcoin-inquisition/Dockerfile",
            "docker/bitcoin-inquisition/context.txt",
        ])
    );
}

#[test]
fn fingerprints_include_content_mode_path_and_untracked_files() {
    let repo = TempRepository::new();
    let baseline = hash_component(repo.path(), InputComponent::Token).unwrap();

    repo.write("token-server-v2/src/main.rs", b"fn main() { changed(); }\n");
    let content_changed = hash_component(repo.path(), InputComponent::Token).unwrap();
    assert_ne!(baseline, content_changed);

    let source = repo.path().join("token-server-v2/src/main.rs");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let mode_changed = hash_component(repo.path(), InputComponent::Token).unwrap();
    assert_ne!(content_changed, mode_changed);

    fs::rename(&source, repo.path().join("token-server-v2/src/renamed.rs")).unwrap();
    let path_changed = hash_component(repo.path(), InputComponent::Token).unwrap();
    assert_ne!(mode_changed, path_changed);

    repo.write("token-server-v2/untracked.input", b"untracked bytes\n");
    let untracked_changed = hash_component(repo.path(), InputComponent::Token).unwrap();
    assert_ne!(path_changed, untracked_changed);
}

#[test]
fn fingerprints_include_empty_directories_without_changing_file_hashes() {
    let repo = TempRepository::new();
    let paths = component_paths(repo.path(), InputComponent::Token).unwrap();
    let component_before = hash_component(repo.path(), InputComponent::Token).unwrap();
    let files_before = hash_paths(repo.path(), &paths, b"file-semantics", &[]).unwrap();

    fs::create_dir(repo.path().join("token-server-v2/empty-input")).unwrap();

    assert_ne!(
        component_before,
        hash_component(repo.path(), InputComponent::Token).unwrap()
    );
    assert_eq!(
        paths,
        component_paths(repo.path(), InputComponent::Token).unwrap()
    );
    assert_eq!(
        files_before,
        hash_paths(repo.path(), &paths, b"file-semantics", &[]).unwrap()
    );
}

#[test]
fn fingerprints_include_directory_modes_without_changing_file_hashes() {
    let repo = TempRepository::new();
    let paths = component_paths(repo.path(), InputComponent::Token).unwrap();
    let component_before = hash_component(repo.path(), InputComponent::Token).unwrap();
    let files_before = hash_paths(repo.path(), &paths, b"file-semantics", &[]).unwrap();

    let directory = repo.path().join("token-server-v2/src");
    let original_mode = fs::symlink_metadata(&directory)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    fs::set_permissions(
        &directory,
        fs::Permissions::from_mode(original_mode ^ 0o040),
    )
    .unwrap();

    assert_ne!(
        component_before,
        hash_component(repo.path(), InputComponent::Token).unwrap()
    );
    assert_eq!(
        paths,
        component_paths(repo.path(), InputComponent::Token).unwrap()
    );
    assert_eq!(
        files_before,
        hash_paths(repo.path(), &paths, b"file-semantics", &[]).unwrap()
    );
}

#[test]
fn lockbox_dockerignore_excludes_only_context_exclusions() {
    let repo = TempRepository::new();
    let baseline = hash_component(repo.path(), InputComponent::Lockbox).unwrap();

    repo.write("lockbox/Settings.toml", b"changed ignored settings\n");
    repo.write("lockbox/build/new-generated", b"changed ignored build\n");
    assert_eq!(
        baseline,
        hash_component(repo.path(), InputComponent::Lockbox).unwrap()
    );

    repo.write("lockbox/src/untracked.cpp", b"int relevant = 1;\n");
    assert_ne!(
        baseline,
        hash_component(repo.path(), InputComponent::Lockbox).unwrap()
    );
}

#[test]
fn dockerignore_patterns_apply_in_order_with_globs_and_negation() {
    let ignore =
        DockerIgnore::parse(b"# comment\n*.tmp\ncache/**\n!cache/keep.tmp\n**/*.log\n").unwrap();
    assert!(ignore.is_ignored(Path::new("root.tmp")));
    assert!(ignore.is_ignored(Path::new("nested/root.tmp")));
    assert!(ignore.is_ignored(Path::new("cache/drop.bin")));
    assert!(!ignore.is_ignored(Path::new("cache/keep.tmp")));
    assert!(ignore.is_ignored(Path::new("one.log")));
    assert!(ignore.is_ignored(Path::new("nested/one.log")));
    assert!(!ignore.is_ignored(Path::new("nested/one.txt")));
}

#[test]
fn relevant_links_and_out_of_root_paths_are_rejected() {
    let repo = TempRepository::new();
    symlink(
        repo.path().join("Cargo.lock"),
        repo.path().join("server/linked-input"),
    )
    .unwrap();
    assert!(hash_component(repo.path(), InputComponent::Mercury).is_err());

    assert!(hash_paths(
        repo.path(),
        &[PathBuf::from("../outside")],
        b"test-domain",
        &[]
    )
    .is_err());
}

#[test]
fn hashing_is_order_independent_but_dockerignore_bytes_are_inputs() {
    let repo = TempRepository::new();
    let left = PathBuf::from("Cargo.lock");
    let right = PathBuf::from("Rocket.toml");
    assert_eq!(
        hash_paths(repo.path(), &[left.clone(), right.clone()], b"ordered", &[]).unwrap(),
        hash_paths(repo.path(), &[right, left], b"ordered", &[]).unwrap()
    );

    let baseline = hash_component(repo.path(), InputComponent::Lockbox).unwrap();
    repo.write(
        "lockbox/.dockerignore",
        b"# semantic comment\nSettings.toml\nbuild/**\n",
    );
    assert_ne!(
        baseline,
        hash_component(repo.path(), InputComponent::Lockbox).unwrap()
    );
}

fn path_list(values: &[&str]) -> Vec<PathBuf> {
    values.iter().map(PathBuf::from).collect()
}
