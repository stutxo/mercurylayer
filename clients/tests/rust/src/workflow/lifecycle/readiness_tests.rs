use std::path::Path;

use serde_json::{json, Value};

use super::readiness::HttpResponse;
use super::ready_with;
use super::test_support::{metadata, MockDocker, MockHost, StubVerifier};

#[test]
fn ready_retries_only_bounded_connection_misses_then_returns_exact_status() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::exact();
    docker.postgres_misses = 1;
    let mut host = MockHost::new(false);
    host.http_misses.insert(metadata.ports().mercury, 1);
    let mut verifier = StubVerifier::new();

    let report = ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap();
    assert!(report.runtime.all_services_ready);
    assert_eq!(host.sleeps, 1);
    assert_eq!(verifier.calls, 1);
    assert_eq!(docker.compose_calls("up") + docker.compose_calls("down"), 0);
    assert!(host
        .requests
        .iter()
        .all(|(port, path)| (*port == metadata.ports().mercury) == (path == "/info/config")));
    for port in [metadata.ports().lockbox, metadata.ports().token] {
        assert!(host.requests.contains(&(port, "/".into())));
    }
}

#[test]
fn ready_connection_deadline_is_bounded_and_does_not_mutate() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::exact();
    let mut host = MockHost::new(false);
    host.http_misses.insert(metadata.ports().mercury, 10);
    host.sleep_advance = 120_000;
    let mut verifier = StubVerifier::new();

    let error = ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap_err();
    assert!(format!("{error:#}").contains("readiness deadline expired"));
    assert_eq!(host.sleeps, 1);
    assert_eq!(docker.compose_calls("up") + docker.compose_calls("down"), 0);
}

#[test]
fn malformed_http_is_fatal_without_retry() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::exact();
    let mut host = MockHost::new(false);
    host.malformed_port = Some(metadata.ports().mercury);
    let mut verifier = StubVerifier::new();

    let error = ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap_err();
    assert!(format!("{error:#}").contains("malformed /info/config"));
    assert_eq!(host.sleeps, 0);
}

#[test]
fn mercury_config_accepts_the_exact_reviewed_response() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::exact();
    let mut host = MockHost::new(false);
    host.mercury_response = HttpResponse {
        status: 200,
        body: json!({"batchtimeout": 20, "version": "0.2.1"}),
    };
    let mut verifier = StubVerifier::new();

    let report = ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap();
    assert!(report.runtime.all_services_ready);
    assert!(host
        .requests
        .contains(&(metadata.ports().mercury, "/info/config".into())));
}

#[test]
fn mercury_config_rejects_status_shape_types_values_and_fields() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let exact = json!({"batchtimeout": 20, "version": "0.2.1"});
    let rejected = [
        ("other 2xx", 204, exact.clone()),
        ("missing field", 200, json!({"batchtimeout": 20})),
        (
            "extra field",
            200,
            json!({"batchtimeout": 20, "version": "0.2.1", "extra": true}),
        ),
        (
            "batchtimeout type",
            200,
            json!({"batchtimeout": "20", "version": "0.2.1"}),
        ),
        (
            "batchtimeout value",
            200,
            json!({"batchtimeout": 21, "version": "0.2.1"}),
        ),
        (
            "version type",
            200,
            json!({"batchtimeout": 20, "version": 201}),
        ),
        (
            "version value",
            200,
            json!({"batchtimeout": 20, "version": "0.2.2"}),
        ),
        ("malformed JSON", 200, Value::String("{bad-json".into())),
        ("nonobject JSON", 200, json!([20, "0.2.1"])),
    ];

    for (case, status, body) in rejected {
        let mut docker = MockDocker::exact();
        let mut host = MockHost::new(false);
        host.mercury_response = HttpResponse { status, body };
        let mut verifier = StubVerifier::new();

        let error =
            ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).expect_err(case);
        assert!(
            format!("{error:#}").contains("malformed /info/config"),
            "{case}"
        );
        assert_eq!(host.sleeps, 0, "{case}");
        assert_eq!(
            docker.compose_calls("up") + docker.compose_calls("down"),
            0,
            "{case}"
        );
    }
}

#[test]
fn dead_unhealthy_duplicate_and_image_mismatch_are_immediate_failures() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    for mut docker in [
        {
            let mut value = MockDocker::exact();
            value.dead = true;
            value
        },
        {
            let mut value = MockDocker::exact();
            value.health = "unhealthy".into();
            value
        },
        {
            let mut value = MockDocker::exact();
            value.duplicate_list_id = true;
            value
        },
        {
            let mut value = MockDocker::exact();
            value.wrong_image_service = Some("mercury-server");
            value
        },
    ] {
        let mut host = MockHost::new(false);
        let mut verifier = StubVerifier::new();
        assert!(ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).is_err());
        assert_eq!(host.sleeps, 0);
        assert_eq!(docker.compose_calls("up") + docker.compose_calls("down"), 0);
    }
}
