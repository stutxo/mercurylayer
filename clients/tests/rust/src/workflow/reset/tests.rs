use std::cell::RefCell;
use std::ffi::OsString;

use anyhow::bail;

use super::*;
use crate::workflow::cli::{self, Command};

#[test]
fn reset_usage_names_the_evidence_preservation_step() {
    assert!(super::super::USAGE.contains("Run checkpoint and logs first"));
}

#[test]
fn reset_parses_but_is_not_a_normal_evidence_mutation() {
    let command = cli::parse(
        ["reset", "--project", "reset_1"]
            .into_iter()
            .map(OsString::from),
    )
    .unwrap();
    assert_eq!(
        command,
        Command::Reset {
            project: Project::parse("reset_1").unwrap()
        }
    );
    assert_eq!(command.mutation(), None);
}

#[test]
fn sequence_is_down_verify_tree_images_verify_delete() {
    let calls = RefCell::new(Vec::new());
    let removed = sequence(
        true,
        true,
        || {
            calls.borrow_mut().push("down");
            Ok(())
        },
        || {
            calls.borrow_mut().push("verify");
            Ok(())
        },
        || {
            calls.borrow_mut().push("tree");
            Ok(())
        },
        || {
            calls.borrow_mut().push("images");
            Ok(vec!["owned".into()])
        },
        || {
            calls.borrow_mut().push("delete");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(removed, ["owned"]);
    assert_eq!(
        calls.into_inner(),
        ["down", "verify", "tree", "images", "verify", "delete"]
    );
}

#[test]
fn missing_metadata_resources_and_every_predelete_failure_fail_closed() {
    let called = RefCell::new(false);
    assert!(sequence(
        false,
        true,
        || {
            *called.borrow_mut() = true;
            Ok(())
        },
        || Ok(()),
        || Ok(()),
        || Ok(Vec::new()),
        || Ok(())
    )
    .is_err());
    assert!(!called.into_inner());

    let deleted = RefCell::new(false);
    assert!(sequence(
        true,
        true,
        || bail!("down failed"),
        || Ok(()),
        || Ok(()),
        || Ok(Vec::new()),
        || {
            *deleted.borrow_mut() = true;
            Ok(())
        }
    )
    .is_err());
    assert!(!deleted.into_inner());

    let deleted = RefCell::new(false);
    assert!(sequence(
        true,
        false,
        || Ok(()),
        || Ok(()),
        || Ok(()),
        || bail!("unsafe tag"),
        || {
            *deleted.borrow_mut() = true;
            Ok(())
        }
    )
    .is_err());
    assert!(!deleted.into_inner());
}
