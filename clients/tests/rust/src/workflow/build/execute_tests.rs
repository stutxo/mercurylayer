use std::ffi::OsStr;
use std::fs;

use super::super::cli::BuildService;
use super::execute;
use super::fingerprint::snapshot;
use super::plan::Artifact;
use super::test_support::{command_has_arg, MockRunner, TempRepository};

#[test]
fn cache_hit_records_exact_id_without_build_or_tag_mutation() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner::default();
    let final_tag = tag(&repo, &mut runner, Artifact::Mercury);
    let id = MockRunner::image_id(41);
    runner.images.insert(final_tag.clone(), id.clone());
    let before = runner.images.clone();

    let updated = execute(repo.path(), &metadata, BuildService::Mercury, &mut runner).unwrap();

    assert_eq!(runner.images, before);
    assert_eq!(runner.build_count, 0);
    assert!(!has_image_action(&runner, "tag"));
    assert!(!has_image_action(&runner, "rm"));
    let image = updated
        .build_resolution()
        .unwrap()
        .images()
        .mercury()
        .unwrap();
    assert_eq!(image.tag(), final_tag);
    assert_eq!(image.image_id(), id);
}

#[test]
fn miss_builds_staging_promotes_verifies_and_untags_only_staging() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner::default();
    let final_tag = tag(&repo, &mut runner, Artifact::Mercury);

    let updated = execute(repo.path(), &metadata, BuildService::Mercury, &mut runner).unwrap();

    assert_eq!(runner.build_count, 1);
    assert_eq!(
        runner.images.get(&final_tag),
        Some(&MockRunner::image_id(1))
    );
    assert!(runner
        .images
        .keys()
        .all(|tag| !tag.contains(":b448-stage-")));
    assert!(has_image_action(&runner, "tag"));
    assert!(has_image_action(&runner, "rm"));
    assert_eq!(
        updated
            .build_resolution()
            .unwrap()
            .images()
            .mercury()
            .unwrap()
            .image_id(),
        MockRunner::image_id(1)
    );
    assert!(metadata.build_resolution().is_none());
}

#[test]
fn lockbox_build_is_two_isolated_variants_with_no_seed_build_input() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner::default();

    let updated = execute(repo.path(), &metadata, BuildService::Lockbox, &mut runner).unwrap();

    assert_eq!(runner.build_count, 2);
    let builds = runner
        .commands
        .iter()
        .filter(|command| command.args.first().and_then(|arg| arg.to_str()) == Some("build"))
        .collect::<Vec<_>>();
    assert_eq!(builds.len(), 2);
    assert!(command_has_arg(
        builds[0],
        OsStr::new("LOCKBOX_ENABLE_TEST_RNG=OFF")
    ));
    assert!(command_has_arg(
        builds[1],
        OsStr::new("LOCKBOX_ENABLE_TEST_RNG=ON")
    ));
    assert!(builds
        .iter()
        .flat_map(|command| &command.args)
        .all(|arg| !arg.to_string_lossy().contains("LOCKBOX_TEST_RNG_SEED")));

    let lockbox = updated
        .build_resolution()
        .unwrap()
        .images()
        .lockbox()
        .unwrap();
    assert_ne!(
        lockbox.production().image_id(),
        lockbox.deterministic_rng().image_id()
    );
    assert!(lockbox
        .deterministic_rng()
        .tag()
        .ends_with("-rng-mock_build"));
}

#[test]
fn inquisition_is_cache_only_when_pinned_tag_exists_and_pinned_when_built() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut cached = MockRunner::default();
    cached.images.insert(
        "mercurylayer/bitcoin-inquisition:f536586".into(),
        MockRunner::image_id(9),
    );
    execute(
        repo.path(),
        &metadata,
        BuildService::Inquisition,
        &mut cached,
    )
    .unwrap();
    assert_eq!(cached.build_count, 0);

    let mut missing = MockRunner::default();
    execute(
        repo.path(),
        &metadata,
        BuildService::Inquisition,
        &mut missing,
    )
    .unwrap();
    let build = missing
        .commands
        .iter()
        .find(|command| command.args.first().and_then(|arg| arg.to_str()) == Some("build"))
        .unwrap();
    assert!(command_has_arg(
        build,
        OsStr::new("BITCOIN_INQUISITION_COMMIT=f5365867662091c2dbf1b2d438b8bb477a3dcb6f")
    ));
    assert!(missing
        .images
        .contains_key("mercurylayer/bitcoin-inquisition:f536586"));
}

#[test]
fn source_drift_aborts_before_promotion_and_cleans_staging() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner {
        drift_after_build: true,
        ..MockRunner::default()
    };
    let final_tag = tag(&repo, &mut runner, Artifact::Token);

    let error = execute(repo.path(), &metadata, BuildService::Token, &mut runner).unwrap_err();
    assert!(format!("{error:#}").contains("changed while images were building"));
    assert!(!runner.images.contains_key(&final_tag));
    assert!(runner
        .images
        .keys()
        .all(|tag| !tag.contains(":b448-stage-")));
}

#[test]
fn final_tag_collision_never_overwrites_and_cleans_staging() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner::default();
    let final_tag = tag(&repo, &mut runner, Artifact::Mercury);
    runner.collision_after_build = Some((final_tag.clone(), MockRunner::image_id(99)));

    let error = execute(repo.path(), &metadata, BuildService::Mercury, &mut runner).unwrap_err();
    assert!(format!("{error:#}").contains("colliding final image tag"));
    assert!(!has_image_action(&runner, "tag"));
    assert!(runner
        .images
        .keys()
        .all(|tag| !tag.contains(":b448-stage-")));
}

#[test]
fn identical_racing_promotion_is_accepted_without_tag_mutation() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner::default();
    let final_tag = tag(&repo, &mut runner, Artifact::Mercury);
    runner.collision_after_build = Some((final_tag, MockRunner::image_id(1)));

    execute(repo.path(), &metadata, BuildService::Mercury, &mut runner).unwrap();
    assert!(!has_image_action(&runner, "tag"));
    assert!(has_image_action(&runner, "rm"));
}

#[test]
fn build_and_promotion_failures_leave_metadata_and_final_tags_untouched() {
    for promotion_failure in [false, true] {
        let repo = TempRepository::new();
        let metadata = repo.metadata();
        fs::create_dir_all(&metadata.paths().run_directory).unwrap();
        fs::write(&metadata.paths().stack_metadata, b"metadata-before\n").unwrap();
        let mut runner = MockRunner {
            fail_build: !promotion_failure,
            failed_build_leaves_tag: !promotion_failure,
            fail_tag: promotion_failure,
            ..MockRunner::default()
        };
        let final_tag = tag(&repo, &mut runner, Artifact::Mercury);

        assert!(execute(repo.path(), &metadata, BuildService::Mercury, &mut runner).is_err());
        assert_eq!(
            fs::read(&metadata.paths().stack_metadata).unwrap(),
            b"metadata-before\n"
        );
        assert!(!runner.images.contains_key(&final_tag));
        assert!(runner
            .images
            .keys()
            .all(|tag| !tag.contains(":b448-stage-")));
    }
}

#[test]
fn recorded_source_or_image_drift_is_refused_without_mutation() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner::default();
    let final_tag = tag(&repo, &mut runner, Artifact::Mercury);
    runner
        .images
        .insert(final_tag.clone(), MockRunner::image_id(7));
    let built = execute(repo.path(), &metadata, BuildService::Mercury, &mut runner).unwrap();

    repo.write("server/src/main.rs", b"fn changed() {}\n");
    runner.commands.clear();
    assert!(execute(repo.path(), &built, BuildService::Mercury, &mut runner).is_err());
    assert_eq!(runner.build_count, 0);

    repo.write("server/src/main.rs", b"fn main() {}\n");
    runner.images.remove(&final_tag);
    assert!(execute(repo.path(), &built, BuildService::Mercury, &mut runner).is_err());
    assert_eq!(runner.build_count, 0);
}

#[test]
fn project_containers_are_refused_before_git_or_image_inspection() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner {
        containers: true,
        ..MockRunner::default()
    };
    assert!(execute(repo.path(), &metadata, BuildService::All, &mut runner).is_err());
    assert_eq!(runner.commands.len(), 1);
    assert_eq!(runner.commands[0].program, OsStr::new("docker"));
}

#[test]
fn every_external_command_is_direct_argv_without_a_shell() {
    let repo = TempRepository::new();
    let metadata = repo.metadata();
    let mut runner = MockRunner::default();
    execute(repo.path(), &metadata, BuildService::Token, &mut runner).unwrap();
    assert!(runner.commands.iter().all(|command| {
        command.program == OsStr::new("docker") || command.program == OsStr::new("git")
    }));
    assert!(runner.commands.iter().all(|command| {
        !command_has_arg(command, OsStr::new("-c"))
            && !command_has_arg(command, OsStr::new("sh"))
            && !command_has_arg(command, OsStr::new("bash"))
    }));
}

fn tag(repo: &TempRepository, runner: &mut MockRunner, artifact: Artifact) -> String {
    let snapshot = snapshot(repo.path(), runner).unwrap();
    runner.commands.clear();
    artifact.final_tag(repo.metadata().project(), &snapshot)
}

fn has_image_action(runner: &MockRunner, action: &str) -> bool {
    runner.commands.iter().any(|command| {
        command.args.first().and_then(|arg| arg.to_str()) == Some("image")
            && command.args.get(1).and_then(|arg| arg.to_str()) == Some(action)
    })
}
