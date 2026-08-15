use std::collections::BTreeMap;
use std::ffi::OsString;

use super::error::WorkflowError;
use super::matrix;
use super::model::{PortMap, Project};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Doctor,
    Configure {
        project: Project,
        ports: PortMap,
    },
    Build {
        project: Project,
        service: BuildService,
    },
    Up {
        project: Project,
    },
    Ready {
        project: Project,
    },
    Status {
        project: Project,
    },
    Checkpoint {
        project: Project,
    },
    Logs {
        project: Project,
    },
    Down {
        project: Project,
    },
    Bootstrap {
        project: Project,
        require_zero: bool,
    },
    Test {
        project: Project,
        target: String,
        test: String,
    },
}

impl Command {
    pub(super) fn mutation(&self) -> Option<(&Project, &'static str)> {
        match self {
            Self::Configure { project, .. } => Some((project, "configure")),
            Self::Build { project, .. } => Some((project, "build")),
            Self::Up { project } => Some((project, "up")),
            Self::Bootstrap { project, .. } => Some((project, "bootstrap")),
            Self::Test { project, .. } => Some((project, "test")),
            Self::Down { project } => Some((project, "down")),
            Self::Help
            | Self::Doctor
            | Self::Ready { .. }
            | Self::Status { .. }
            | Self::Checkpoint { .. }
            | Self::Logs { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildService {
    All,
    Mercury,
    Token,
    Lockbox,
    Inquisition,
}

impl BuildService {
    fn parse(value: &str) -> Result<Self, WorkflowError> {
        match value {
            "all" => Ok(Self::All),
            "mercury" => Ok(Self::Mercury),
            "token" => Ok(Self::Token),
            "lockbox" => Ok(Self::Lockbox),
            "inquisition" => Ok(Self::Inquisition),
            _ => Err(WorkflowError::usage(
                "--service must be one of all, mercury, token, lockbox, or inquisition",
            )),
        }
    }
}

pub fn parse<I>(args: I) -> Result<Command, WorkflowError>
where
    I: IntoIterator<Item = OsString>,
{
    let args = args
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| WorkflowError::usage("arguments must be valid UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let Some(command) = args.first().map(String::as_str) else {
        return Err(WorkflowError::usage("a command is required"));
    };

    match command {
        "--help" | "-h" if args.len() == 1 => Ok(Command::Help),
        "doctor" if args.len() == 1 => Ok(Command::Doctor),
        "doctor" if args.get(1).map(String::as_str) == Some("--help") && args.len() == 2 => {
            Ok(Command::Help)
        }
        "configure" => parse_configure(&args[1..]),
        "build" => parse_build(&args[1..]),
        "up" => parse_project_command(&args[1..], |project| Command::Up { project }),
        "ready" => parse_project_command(&args[1..], |project| Command::Ready { project }),
        "status" => parse_project_command(&args[1..], |project| Command::Status { project }),
        "checkpoint" => {
            parse_project_command(&args[1..], |project| Command::Checkpoint { project })
        }
        "logs" => parse_project_command(&args[1..], |project| Command::Logs { project }),
        "down" => parse_project_command(&args[1..], |project| Command::Down { project }),
        "bootstrap" => parse_bootstrap(&args[1..]),
        "test" => parse_test(&args[1..]),
        other => Err(WorkflowError::usage(format!(
            "unknown or malformed command {other:?}"
        ))),
    }
}

fn parse_bootstrap(args: &[String]) -> Result<Command, WorkflowError> {
    if args == ["--help"] {
        return Ok(Command::Help);
    }
    let mut project = None;
    let mut require_zero = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--project" => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| WorkflowError::usage("--project requires a value"))?;
                if project.replace(value.clone()).is_some() {
                    return Err(WorkflowError::usage("--project may be specified only once"));
                }
                index += 2;
            }
            "--require-zero" => {
                if require_zero {
                    return Err(WorkflowError::usage(
                        "--require-zero may be specified only once",
                    ));
                }
                require_zero = true;
                index += 1;
            }
            name => {
                return Err(WorkflowError::usage(format!(
                    "unknown bootstrap option {name:?}"
                )));
            }
        }
    }
    let project =
        project.ok_or_else(|| WorkflowError::usage("required option --project is missing"))?;
    Ok(Command::Bootstrap {
        project: Project::parse(&project).map_err(WorkflowError::usage)?,
        require_zero,
    })
}

fn parse_test(args: &[String]) -> Result<Command, WorkflowError> {
    if args == ["--help"] {
        return Ok(Command::Help);
    }
    let options = parse_options(args, &["--project", "--target", "--test"])?;
    let target = options["--target"].clone();
    let test = options["--test"].clone();
    matrix::select(&target, &test).map_err(WorkflowError::usage)?;
    Ok(Command::Test {
        project: required_project(&options)?,
        target,
        test,
    })
}

fn parse_build(args: &[String]) -> Result<Command, WorkflowError> {
    if args == ["--help"] {
        return Ok(Command::Help);
    }
    let options = parse_options(args, &["--project", "--service"])?;
    Ok(Command::Build {
        project: required_project(&options)?,
        service: BuildService::parse(&options["--service"])?,
    })
}

fn parse_configure(args: &[String]) -> Result<Command, WorkflowError> {
    if args == ["--help"] {
        return Ok(Command::Help);
    }
    let options = parse_options(args, &["--project", "--base-port"])?;
    let project = required_project(&options)?;
    let base = options["--base-port"].parse::<u16>().map_err(|_| {
        WorkflowError::usage("--base-port must be an integer in the u16 port range")
    })?;
    let ports = PortMap::from_base(base).map_err(WorkflowError::usage)?;
    Ok(Command::Configure { project, ports })
}

fn parse_project_command(
    args: &[String],
    command: impl FnOnce(Project) -> Command,
) -> Result<Command, WorkflowError> {
    if args == ["--help"] {
        return Ok(Command::Help);
    }
    let options = parse_options(args, &["--project"])?;
    Ok(command(required_project(&options)?))
}

fn required_project(options: &BTreeMap<String, String>) -> Result<Project, WorkflowError> {
    Project::parse(&options["--project"]).map_err(WorkflowError::usage)
}

fn parse_options(
    args: &[String],
    required: &[&str],
) -> Result<BTreeMap<String, String>, WorkflowError> {
    if args.len() != required.len() * 2 {
        return Err(WorkflowError::usage(format!(
            "expected exactly {} required option(s)",
            required.len()
        )));
    }

    let mut parsed = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        let name = pair[0].as_str();
        if !required.contains(&name) {
            return Err(WorkflowError::usage(format!("unknown option {name:?}")));
        }
        if pair[1].starts_with("--") {
            return Err(WorkflowError::usage(format!(
                "option {name} requires a value"
            )));
        }
        if parsed.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(WorkflowError::usage(format!(
                "option {name} may be specified only once"
            )));
        }
    }

    for name in required {
        if !parsed.contains_key(*name) {
            return Err(WorkflowError::usage(format!(
                "required option {name} is missing"
            )));
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn fixed_commands_parse() {
        assert_eq!(parse(args(&["--help"])).unwrap(), Command::Help);
        assert_eq!(parse(args(&["doctor"])).unwrap(), Command::Doctor);

        let configured = parse(args(&[
            "configure",
            "--base-port",
            "23000",
            "--project",
            "matrix_1",
        ]))
        .unwrap();
        assert_eq!(
            configured,
            Command::Configure {
                project: Project::parse("matrix_1").unwrap(),
                ports: PortMap::from_base(23000).unwrap(),
            }
        );
        assert_eq!(
            parse(args(&[
                "bootstrap",
                "--require-zero",
                "--project",
                "matrix_1",
            ]))
            .unwrap(),
            Command::Bootstrap {
                project: Project::parse("matrix_1").unwrap(),
                require_zero: true,
            }
        );
        assert_eq!(
            parse(args(&[
                "test",
                "--test",
                "bip448_template_signature_rebinds_prevout_on_inquisition",
                "--project",
                "matrix_1",
                "--target",
                "bip448_primitive_spike",
            ]))
            .unwrap(),
            Command::Test {
                project: Project::parse("matrix_1").unwrap(),
                target: "bip448_primitive_spike".into(),
                test: "bip448_template_signature_rebinds_prevout_on_inquisition".into(),
            }
        );
        assert_eq!(
            parse(args(&["status", "--project", "matrix_1"])).unwrap(),
            Command::Status {
                project: Project::parse("matrix_1").unwrap()
            }
        );
        assert_eq!(
            parse(args(&["checkpoint", "--project", "matrix_1"])).unwrap(),
            Command::Checkpoint {
                project: Project::parse("matrix_1").unwrap()
            }
        );
        assert_eq!(
            parse(args(&["logs", "--project", "matrix_1"])).unwrap(),
            Command::Logs {
                project: Project::parse("matrix_1").unwrap()
            }
        );
        assert_eq!(
            parse(args(&["up", "--project", "matrix_1"])).unwrap(),
            Command::Up {
                project: Project::parse("matrix_1").unwrap()
            }
        );
        assert_eq!(
            parse(args(&["ready", "--project", "matrix_1"])).unwrap(),
            Command::Ready {
                project: Project::parse("matrix_1").unwrap()
            }
        );
        assert_eq!(
            parse(args(&["down", "--project", "matrix_1"])).unwrap(),
            Command::Down {
                project: Project::parse("matrix_1").unwrap()
            }
        );
        assert_eq!(
            parse(args(&[
                "build",
                "--service",
                "lockbox",
                "--project",
                "matrix_1",
            ]))
            .unwrap(),
            Command::Build {
                project: Project::parse("matrix_1").unwrap(),
                service: BuildService::Lockbox,
            }
        );
        for (value, service) in [
            ("all", BuildService::All),
            ("mercury", BuildService::Mercury),
            ("token", BuildService::Token),
            ("lockbox", BuildService::Lockbox),
            ("inquisition", BuildService::Inquisition),
        ] {
            assert_eq!(
                parse(args(&[
                    "build",
                    "--project",
                    "matrix_1",
                    "--service",
                    value,
                ]))
                .unwrap(),
                Command::Build {
                    project: Project::parse("matrix_1").unwrap(),
                    service,
                }
            );
        }
    }

    #[test]
    fn malformed_commands_are_usage_errors() {
        for values in [
            vec![],
            vec!["unknown"],
            vec!["doctor", "extra"],
            vec!["configure", "--project", "ok"],
            vec!["configure", "--project", "ok", "--project", "again"],
            vec!["configure", "--project", "UPPER", "--base-port", "23000"],
            vec!["configure", "--project", "ok", "--base-port", "65530"],
            vec!["status", "--project", "has.dot"],
            vec!["build", "--project", "ok", "--service", "unknown"],
            vec!["build", "--project", "ok"],
            vec![
                "bootstrap",
                "--project",
                "ok",
                "--require-zero",
                "--require-zero",
            ],
            vec!["bootstrap", "--project", "ok", "unexpected"],
            vec!["bootstrap", "--project", "--require-zero", "ok"],
            vec![
                "test",
                "--project",
                "ok",
                "--target",
                "unknown",
                "--test",
                "nope",
            ],
            vec![
                "test",
                "--project",
                "ok",
                "--target",
                "bip448_primitive_spike",
                "--test",
                "nope",
            ],
        ] {
            let error = parse(args(&values)).unwrap_err();
            assert!(error.is_usage(), "accepted or misclassified {values:?}");
            assert_eq!(error.exit_code(), 2);
        }
    }
}
