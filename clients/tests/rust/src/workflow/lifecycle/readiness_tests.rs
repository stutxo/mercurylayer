use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

use serde_json::{json, Value};

use super::super::argv::{begin_failure_capture, finish_failure_capture};
use super::readiness::{http_json, HttpAttempt, HttpResponse};
use super::readiness_http::{parse_http, parse_http_stream, ParseState};
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
    assert!(host.requests.iter().all(|(port, path, _)| {
        (*port == metadata.ports().mercury) == (path == "/info/config")
    }));
    assert!(host.requests.contains(&(
        metadata.ports().lockbox,
        "/health/ready".into(),
        Some(super::LOCKBOX_TEST_AUTHORIZATION.into()),
    )));
    assert!(host
        .requests
        .contains(&(metadata.ports().token, "/".into(), None)));
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
        body: json!({"batchtimeout": 20, "version": "0.1.0"}),
    };
    let mut verifier = StubVerifier::new();

    let report = ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap();
    assert!(report.runtime.all_services_ready);
    assert!(host
        .requests
        .contains(&(metadata.ports().mercury, "/info/config".into(), None,)));
}

#[test]
fn lockbox_readiness_rejects_an_unauthenticated_or_malformed_health_response() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let mut docker = MockDocker::exact();
    let mut host = MockHost::new(false);
    host.lockbox_response = HttpResponse {
        status: 401,
        body: json!({"message": "Unauthorized"}),
    };
    let mut verifier = StubVerifier::new();

    let error = ready_with(root, &metadata, &mut docker, &mut host, &mut verifier).unwrap_err();
    assert!(format!("{error:#}").contains("malformed /health/ready"));
    assert_eq!(host.sleeps, 0);
}

#[test]
fn mercury_config_rejects_status_shape_types_values_and_fields() {
    let root = Path::new("/repo");
    let metadata = metadata(root);
    let exact = json!({"batchtimeout": 20, "version": "0.1.0"});
    let rejected = [
        ("other 2xx", 204, exact.clone()),
        ("missing field", 200, json!({"batchtimeout": 20})),
        (
            "extra field",
            200,
            json!({"batchtimeout": 20, "version": "0.1.0", "extra": true}),
        ),
        (
            "batchtimeout type",
            200,
            json!({"batchtimeout": "20", "version": "0.1.0"}),
        ),
        (
            "batchtimeout value",
            200,
            json!({"batchtimeout": 21, "version": "0.1.0"}),
        ),
        (
            "version type",
            200,
            json!({"batchtimeout": 20, "version": 201}),
        ),
        (
            "version value",
            200,
            json!({"batchtimeout": 20, "version": "0.1.1"}),
        ),
        ("malformed JSON", 200, Value::String("{bad-json".into())),
        ("nonobject JSON", 200, json!([20, "0.1.0"])),
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

#[test]
fn structurally_incomplete_http_frames_are_retryable_but_complete_malformed_frames_are_fatal() {
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let incomplete = [
        Vec::new(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}".to_vec(),
        [chunked.as_slice(), b"2"].concat(),
        [chunked.as_slice(), b"2\r\n{"].concat(),
        [chunked.as_slice(), b"2\r\n{}\r"].concat(),
        [chunked.as_slice(), b"2\r\n{}\r\n0\r\nX-Test: yes\r\n"].concat(),
    ];
    for response in incomplete {
        assert!(matches!(
            parse_http(&response).unwrap(),
            ParseState::Incomplete(_)
        ));
    }

    let malformed = [
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nBad-Header\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}".to_vec(),
        [chunked.as_slice(), b"Z\r\n"].concat(),
        [chunked.as_slice(), b"2\r\n{}xx"].concat(),
        [chunked.as_slice(), b"0\r\nBad-Trailer\r\n\r\n"].concat(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n\xff".to_vec(),
    ];
    for response in malformed {
        assert!(parse_http(&response).is_err());
    }

    let complete = [chunked.as_slice(), b"2\r\n{}\r\n0\r\n\r\n"].concat();
    assert!(matches!(
        parse_http(&complete).unwrap(),
        ParseState::Complete(HttpResponse { status: 200, .. })
    ));
    assert!(matches!(
        parse_http_stream(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", false).unwrap(),
        ParseState::Complete(_)
    ));
    assert!(matches!(
        parse_http_stream(b"HTTP/1.1 200 OK\r\n\r\n{}", false).unwrap(),
        ParseState::Incomplete("incomplete_close_delimited_body")
    ));
}

#[test]
fn incomplete_http_retry_context_is_bounded_and_never_includes_response_body() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nsecret-body".to_vec();
    let received = response.len();
    let server = std::thread::spawn(move || serve_http_once(listener, &response));

    let attempt = http_json("mercury-server", port, "/info/config", None, None).unwrap();
    server.join().unwrap();
    let HttpAttempt::ConnectionMiss(detail) = attempt else {
        panic!("truncated response was not retryable");
    };
    assert!(detail.contains("service=mercury-server"));
    assert!(detail.contains(&format!("port={port}")));
    assert!(detail.contains("path=/info/config"));
    assert!(detail.contains(&format!("received_bytes={received}")));
    assert!(!detail.contains("secret-body"));
    assert!(detail.len() < 512);

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let response = b"HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\nsecret-body".to_vec();
    let received = response.len();
    let server = std::thread::spawn(move || serve_http_once(listener, &response));
    let error = http_json("mercury-server", port, "/info/config", None, None).unwrap_err();
    server.join().unwrap();
    let error = format!("{error:#}");
    assert!(error.contains("service=mercury-server"));
    assert!(error.contains(&format!("port={port}")));
    assert!(error.contains("path=/info/config"));
    assert!(error.contains(&format!("received_bytes={received}")));
    assert!(!error.contains("secret-body"));
    assert!(error.len() < 512);
}

#[test]
fn pg_isready_capture_excludes_retryable_misses_and_records_unexpected_failure() {
    let root = Path::new("/repo");
    let metadata = metadata(root);

    let mut retry = MockDocker::exact();
    retry.postgres_misses = 1;
    let mut host = MockHost::new(false);
    let mut verifier = StubVerifier::new();
    begin_failure_capture().unwrap();
    let result = ready_with(root, &metadata, &mut retry, &mut host, &mut verifier);
    let captured = finish_failure_capture();
    assert!(result.is_ok());
    assert!(captured.is_none());

    let mut failed = MockDocker::exact();
    failed.postgres_failure = true;
    let mut host = MockHost::new(false);
    let mut verifier = StubVerifier::new();
    begin_failure_capture().unwrap();
    let result = ready_with(root, &metadata, &mut failed, &mut host, &mut verifier);
    let captured = finish_failure_capture().unwrap();
    assert!(result.is_err());
    assert_eq!(captured.exit_code, Some(3));
    assert_eq!(captured.signal, None);
    assert_eq!(captured.argv.first().map(String::as_str), Some("docker"));
    assert!(captured.argv.iter().any(|arg| arg == "pg_isready"));
}

fn serve_http_once(listener: TcpListener, response: &[u8]) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut request = Vec::new();
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 512];
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0 && request.len() + count <= 4096);
        request.extend_from_slice(&chunk[..count]);
    }
    stream.write_all(response).unwrap();
}
