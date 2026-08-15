use std::collections::BTreeMap;
use std::ffi::OsString;

use super::error::WorkflowError;
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
    Status {
        project: Project,
    },
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
        "status" => parse_status(&args[1..]),
        other => Err(WorkflowError::usage(format!(
            "unknown or malformed command {other:?}"
        ))),
    }
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

fn parse_status(args: &[String]) -> Result<Command, WorkflowError> {
    if args == ["--help"] {
        return Ok(Command::Help);
    }
    let options = parse_options(args, &["--project"])?;
    Ok(Command::Status {
        project: required_project(&options)?,
    })
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
            parse(args(&["status", "--project", "matrix_1"])).unwrap(),
            Command::Status {
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
        ] {
            let error = parse(args(&values)).unwrap_err();
            assert!(error.is_usage(), "accepted or misclassified {values:?}");
            assert_eq!(error.exit_code(), 2);
        }
    }
}
