use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Deserializer, Serialize};

use crate::workflow::argv::ChildFailure;

pub(super) const EVIDENCE_VERSION: u32 = 1;
pub(super) const MAX_CONTROLLER_ERROR_BYTES: usize = 2_048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceIdentity {
    pub(super) head: String,
    pub(super) status_sha256: String,
    pub(super) clean: bool,
}

impl SourceIdentity {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.head.len() == 40 && self.head.bytes().all(is_lower_hex),
            "operation source HEAD is malformed"
        );
        ensure!(
            self.status_sha256.len() == 64 && self.status_sha256.bytes().all(is_lower_hex),
            "operation source status digest is malformed"
        );
        ensure!(self.clean, "operation source was not clean");
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StartedRecord {
    pub(super) version: u32,
    pub(super) operation_id: String,
    pub(super) project: String,
    pub(super) command: String,
    pub(super) arguments: Vec<String>,
    pub(super) source: SourceIdentity,
    pub(super) started_at: String,
}

impl StartedRecord {
    pub(super) fn validate(&self, operation_id: &str, project: &str) -> Result<()> {
        ensure!(
            self.version == EVIDENCE_VERSION,
            "unsupported started record version"
        );
        ensure!(
            self.operation_id == operation_id,
            "started record operation ID mismatch"
        );
        ensure!(self.project == project, "started record project mismatch");
        ensure!(
            matches!(
                self.command.as_str(),
                "configure" | "build" | "up" | "bootstrap" | "test" | "down"
            ),
            "started record command is unsupported"
        );
        self.source.validate()?;
        validate_timestamp(&self.started_at)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OutcomeKind {
    Success,
    ExitCode,
    Signal,
    OperationalError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Outcome {
    pub(super) kind: OutcomeKind,
    pub(super) exit_code: Option<i32>,
    pub(super) signal: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredLog {
    pub(super) file: String,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

impl StoredLog {
    pub(super) fn validate(&self, expected_file: &str) -> Result<()> {
        ensure!(self.file == expected_file, "stored log filename mismatch");
        ensure!(
            self.sha256.len() == 64 && self.sha256.bytes().all(is_lower_hex),
            "stored log digest is malformed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestLogs {
    pub(super) stdout: StoredLog,
    pub(super) stderr: StoredLog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResultRecord {
    pub(super) version: u32,
    pub(super) operation_id: String,
    pub(super) project: String,
    pub(super) command: String,
    pub(super) finished_at: String,
    pub(super) outcome: Outcome,
    pub(super) first_failing_child: Option<ChildFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) controller_error: Option<String>,
    pub(super) test_logs: Option<TestLogs>,
}

impl ResultRecord {
    pub(super) fn validate(&self, started: &StartedRecord) -> Result<()> {
        ensure!(
            self.version == EVIDENCE_VERSION,
            "unsupported result record version"
        );
        ensure!(
            self.operation_id == started.operation_id,
            "result operation ID mismatch"
        );
        ensure!(self.project == started.project, "result project mismatch");
        ensure!(self.command == started.command, "result command mismatch");
        validate_timestamp(&self.finished_at)?;
        self.validate_intrinsic()?;
        if let Some(logs) = &self.test_logs {
            logs.stdout.validate("test.stdout")?;
            logs.stderr.validate("test.stderr")?;
        }
        Ok(())
    }

    fn validate_intrinsic(&self) -> Result<()> {
        if let Some(child) = &self.first_failing_child {
            ensure!(!child.argv.is_empty(), "failing child argv is empty");
            let valid_status = match (child.exit_code, child.signal) {
                (Some(code), None) => (1..=255).contains(&code),
                (None, Some(signal)) => (1..=127).contains(&signal),
                _ => false,
            };
            ensure!(valid_status, "failing child status is malformed");
        }

        match self.outcome.kind {
            OutcomeKind::Success => {
                ensure!(
                    self.outcome.exit_code == Some(0) && self.outcome.signal.is_none(),
                    "successful outcome has malformed status"
                );
                ensure!(
                    self.first_failing_child.is_none(),
                    "successful outcome has a failing child"
                );
                ensure!(
                    self.controller_error.is_none(),
                    "successful outcome has a controller error"
                );
            }
            OutcomeKind::ExitCode => {
                ensure!(
                    self.outcome
                        .exit_code
                        .is_some_and(|code| (1..=255).contains(&code))
                        && self.outcome.signal.is_none(),
                    "exit-code outcome has malformed status"
                );
                ensure!(
                    self.controller_error.is_none(),
                    "exit-code outcome has a controller error"
                );
            }
            OutcomeKind::Signal => {
                let signal = self
                    .outcome
                    .signal
                    .context("signal outcome lacks a signal")?;
                ensure!(
                    (1..=127).contains(&signal) && self.outcome.exit_code == Some(128 + signal),
                    "signal outcome has malformed status"
                );
                let child = self
                    .first_failing_child
                    .as_ref()
                    .context("signal outcome lacks a failing child")?;
                ensure!(
                    child.signal == Some(signal),
                    "signal outcome does not match its failing child"
                );
                ensure!(
                    self.controller_error.is_none(),
                    "signal outcome has a controller error"
                );
            }
            OutcomeKind::OperationalError => {
                ensure!(
                    self.outcome.exit_code == Some(1) && self.outcome.signal.is_none(),
                    "operational outcome has malformed status"
                );
                let error = self
                    .controller_error
                    .as_ref()
                    .context("operational outcome lacks a controller error")?;
                ensure!(
                    !error.trim().is_empty() && error.len() <= MAX_CONTROLLER_ERROR_BYTES,
                    "operational controller error is blank or exceeds its byte limit"
                );
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultRecordWire {
    version: u32,
    operation_id: String,
    project: String,
    command: String,
    finished_at: String,
    outcome: Outcome,
    first_failing_child: Option<ChildFailure>,
    #[serde(default)]
    controller_error: Option<String>,
    test_logs: Option<TestLogs>,
}

impl<'de> Deserialize<'de> for ResultRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ResultRecordWire::deserialize(deserializer)?;
        let record = Self {
            version: wire.version,
            operation_id: wire.operation_id,
            project: wire.project,
            command: wire.command,
            finished_at: wire.finished_at,
            outcome: wire.outcome,
            first_failing_child: wire.first_failing_child,
            controller_error: wire.controller_error,
            test_logs: wire.test_logs,
        };
        record
            .validate_intrinsic()
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

pub(super) trait Clock {
    fn now_utc(&mut self) -> Result<String>;
}

pub(super) struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&mut self) -> Result<String> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?;
        Ok(format_utc(duration.as_secs()))
    }
}

fn format_utc(seconds: u64) -> String {
    let days = seconds / 86_400;
    let within = seconds % 86_400;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(i64::MAX));
    let hour = within / 3_600;
    let minute = (within % 3_600) / 60;
    let second = within % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn validate_timestamp(value: &str) -> Result<()> {
    ensure!(
        value.len() == 20
            && value.as_bytes()[4] == b'-'
            && value.as_bytes()[7] == b'-'
            && value.as_bytes()[10] == b'T'
            && value.as_bytes()[13] == b':'
            && value.as_bytes()[16] == b':'
            && value.ends_with('Z')
            && value
                .bytes()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16 | 19)
                    || byte.is_ascii_digit()),
        "operation timestamp is not canonical UTC"
    );
    let number = |range: std::ops::Range<usize>| -> Result<u32> {
        value[range]
            .parse()
            .context("parse operation timestamp field")
    };
    let year = number(0..4)?;
    let month = number(5..7)?;
    let day = number(8..10)?;
    let hour = number(11..13)?;
    let minute = number(14..16)?;
    let second = number(17..19)?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    ensure!(
        max_day != 0 && (1..=max_day).contains(&day) && hour < 24 && minute < 60 && second < 60,
        "operation timestamp contains an out-of-range UTC field"
    );
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_format_has_stable_epoch_and_leap_day_values() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn intrinsic_matrix_validates_and_round_trips() {
        let started = started_record();
        let cases = vec![
            ("success", success()),
            ("exit without child", exited()),
            (
                "exit with exit child",
                with_child(exited(), child(Some(23), None)),
            ),
            (
                "exit with signal child",
                with_child(exited(), child(None, Some(15))),
            ),
            ("signal", signaled()),
            ("operational without child", operational()),
            (
                "operational with exit child",
                with_child(operational(), child(Some(1), None)),
            ),
            (
                "operational with signal child",
                with_child(operational(), child(None, Some(9))),
            ),
        ];
        for (name, record) in cases {
            record
                .validate(&started)
                .unwrap_or_else(|error| panic!("{name}: {error:#}"));
            let decoded: ResultRecord =
                serde_json::from_value(serde_json::to_value(&record).unwrap())
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(decoded, record, "{name}");
        }
    }

    #[test]
    fn intrinsic_matrix_rejects_malformed_cross_fields() {
        let started = started_record();
        let cases = vec![
            (
                "success missing exit",
                changed(success(), |r| r.outcome.exit_code = None),
            ),
            (
                "success signal",
                changed(success(), |r| r.outcome.signal = Some(1)),
            ),
            ("success child", with_child(success(), child(Some(1), None))),
            ("success cause", with_error(success(), "cause")),
            (
                "exit missing",
                changed(exited(), |r| r.outcome.exit_code = None),
            ),
            (
                "exit zero",
                changed(exited(), |r| r.outcome.exit_code = Some(0)),
            ),
            (
                "exit out of range",
                changed(exited(), |r| r.outcome.exit_code = Some(256)),
            ),
            (
                "exit signal field",
                changed(exited(), |r| r.outcome.signal = Some(1)),
            ),
            ("exit cause", with_error(exited(), "cause")),
            (
                "signal missing field",
                changed(signaled(), |r| r.outcome.signal = None),
            ),
            (
                "signal wrong exit",
                changed(signaled(), |r| r.outcome.exit_code = Some(142)),
            ),
            (
                "signal out of range",
                changed(signaled(), |r| {
                    r.outcome.exit_code = Some(256);
                    r.outcome.signal = Some(128);
                    r.first_failing_child = Some(child(None, Some(128)));
                }),
            ),
            (
                "signal missing child",
                changed(signaled(), |r| r.first_failing_child = None),
            ),
            (
                "signal exit child",
                with_child(signaled(), child(Some(143), None)),
            ),
            (
                "signal mismatch child",
                with_child(signaled(), child(None, Some(9))),
            ),
            ("signal cause", with_error(signaled(), "cause")),
            (
                "operational wrong exit",
                changed(operational(), |r| r.outcome.exit_code = Some(2)),
            ),
            (
                "operational signal",
                changed(operational(), |r| r.outcome.signal = Some(1)),
            ),
            (
                "operational missing cause",
                changed(operational(), |r| r.controller_error = None),
            ),
            ("operational blank cause", with_error(operational(), " \t")),
            (
                "operational oversized cause",
                changed(operational(), |r| {
                    r.controller_error = Some("x".repeat(MAX_CONTROLLER_ERROR_BYTES + 1));
                }),
            ),
            (
                "child empty argv",
                with_child(exited(), empty_child(Some(1), None)),
            ),
            ("child zero", with_child(exited(), child(Some(0), None))),
            (
                "child exit out of range",
                with_child(exited(), child(Some(256), None)),
            ),
            (
                "child signal out of range",
                with_child(exited(), child(None, Some(128))),
            ),
            (
                "child both statuses",
                with_child(exited(), child(Some(1), Some(1))),
            ),
            (
                "child neither status",
                with_child(exited(), child(None, None)),
            ),
        ];
        for (name, record) in cases {
            assert!(
                record.validate(&started).is_err(),
                "validate accepted {name}"
            );
            assert!(
                serde_json::from_value::<ResultRecord>(serde_json::to_value(&record).unwrap())
                    .is_err(),
                "deserialize accepted {name}"
            );
        }
    }

    fn started_record() -> StartedRecord {
        StartedRecord {
            version: EVIDENCE_VERSION,
            operation_id: "99999999-9999-4999-8999-999999999999".into(),
            project: "record_1".into(),
            command: "test".into(),
            arguments: Vec::new(),
            source: SourceIdentity {
                head: "a".repeat(40),
                status_sha256: "b".repeat(64),
                clean: true,
            },
            started_at: "2026-08-15T01:02:03Z".into(),
        }
    }

    fn base(kind: OutcomeKind, exit_code: Option<i32>, signal: Option<i32>) -> ResultRecord {
        ResultRecord {
            version: EVIDENCE_VERSION,
            operation_id: "99999999-9999-4999-8999-999999999999".into(),
            project: "record_1".into(),
            command: "test".into(),
            finished_at: "2026-08-15T01:02:04Z".into(),
            outcome: Outcome {
                kind,
                exit_code,
                signal,
            },
            first_failing_child: None,
            controller_error: None,
            test_logs: None,
        }
    }

    fn success() -> ResultRecord {
        base(OutcomeKind::Success, Some(0), None)
    }

    fn exited() -> ResultRecord {
        base(OutcomeKind::ExitCode, Some(23), None)
    }

    fn signaled() -> ResultRecord {
        with_child(
            base(OutcomeKind::Signal, Some(143), Some(15)),
            child(None, Some(15)),
        )
    }

    fn operational() -> ResultRecord {
        with_error(
            base(OutcomeKind::OperationalError, Some(1), None),
            "controller failure",
        )
    }

    fn changed(mut record: ResultRecord, change: impl FnOnce(&mut ResultRecord)) -> ResultRecord {
        change(&mut record);
        record
    }

    fn with_child(mut record: ResultRecord, child: ChildFailure) -> ResultRecord {
        record.first_failing_child = Some(child);
        record
    }

    fn with_error(mut record: ResultRecord, error: &str) -> ResultRecord {
        record.controller_error = Some(error.to_owned());
        record
    }

    fn child(exit_code: Option<i32>, signal: Option<i32>) -> ChildFailure {
        child_with_argv(vec!["child".into()], exit_code, signal)
    }

    fn empty_child(exit_code: Option<i32>, signal: Option<i32>) -> ChildFailure {
        child_with_argv(Vec::new(), exit_code, signal)
    }

    fn child_with_argv(
        argv: Vec<String>,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> ChildFailure {
        ChildFailure {
            argv,
            exit_code,
            signal,
        }
    }
}
