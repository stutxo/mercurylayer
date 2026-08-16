mod argv;
mod authoritative;
mod bootstrap;
mod build;
mod cli;
mod command;
mod doctor;
mod error;
mod evidence;
mod lifecycle;
mod matrix;
mod metadata_lock;
mod model;
mod project_lock;
mod ready_gate;
mod repository;
mod reset;
mod storage;
mod supervision;
mod test_runner;
mod verifier;

use std::ffi::OsString;
use std::io::{self, Write};

pub use cli::BuildService;
pub use error::{WorkflowError, EXIT_FAILURE, EXIT_SUCCESS, EXIT_USAGE};
pub use matrix::{MatrixTarget, MATRIX};
pub use model::{
    ComponentConfig, EndpointMap, ImageMap, ImageRole, LifecycleState, PortMap, PortRole, Project,
    ProjectSpec, RunPaths, StackMetadata, COMPONENTS,
};

pub const USAGE: &str = "Usage:\n  bip448-test --help\n  bip448-test doctor\n  bip448-test configure --project <PROJECT> --base-port <PORT>\n  bip448-test build --project <PROJECT> --service <all|mercury|token|lockbox|inquisition>\n  bip448-test up --project <PROJECT>\n  bip448-test ready --project <PROJECT>\n  bip448-test status --project <PROJECT>\n  bip448-test checkpoint --project <PROJECT>\n  bip448-test logs --project <PROJECT>\n  bip448-test down --project <PROJECT>\n  bip448-test bootstrap --project <PROJECT> [--require-zero]\n  bip448-test test --project <PROJECT> --target <MATRIX_BINARY> --test <EXACT_IDENTITY>\n  bip448-test verify --project <PROJECT> --base-port <PORT> [--control-project <PROJECT>] [--control-base-port <PORT>]\n  bip448-test reset --project <PROJECT>\n\nverify is the authoritative fresh paired-project 58-test workflow. It configures, runs, directly inspects, compares, and tears down both projects without retry.\nreset permanently removes the selected project's run and operation-evidence tree. Run checkpoint and logs first when evidence must be retained.";

pub async fn run_hidden_verify_helper<I>(args: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    match verifier::helper::run(args).await {
        Ok(output) => match write_output(io::stdout().lock(), &output) {
            Ok(()) => EXIT_SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "bip448-test helper: {error}");
                EXIT_FAILURE
            }
        },
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "bip448-test helper: {error:#}");
            EXIT_FAILURE
        }
    }
}

pub async fn run<I>(args: I) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let _signals = match supervision::SignalWatch::install() {
        Ok(signals) => signals,
        Err(error) => {
            let _ = writeln!(
                io::stderr().lock(),
                "bip448-test: initialize signal-safe child supervision: {error:#}"
            );
            return EXIT_FAILURE;
        }
    };
    let result = _signals.scope_workflow(run_inner(args)).await;
    match result {
        Ok(output) => match write_output(io::stdout().lock(), &output) {
            Ok(()) => EXIT_SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "bip448-test: {error}");
                EXIT_FAILURE
            }
        },
        Err(error) => {
            let code = error.exit_code();
            let _ = writeln!(io::stderr().lock(), "bip448-test: {error}");
            if error.is_usage() {
                let _ = writeln!(io::stderr().lock(), "\n{USAGE}");
            }
            code
        }
    }
}

async fn run_inner<I>(args: I) -> Result<String, WorkflowError>
where
    I: IntoIterator<Item = OsString>,
{
    let raw = args.into_iter().collect::<Vec<_>>();
    let command = cli::parse(raw.clone())?;
    let raw = raw
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| WorkflowError::usage("arguments must be valid UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    command::execute(command, &raw).await
}

fn write_output(mut writer: impl Write, output: &str) -> io::Result<()> {
    writer.write_all(output.as_bytes())?;
    if !output.ends_with('\n') {
        writer.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_gets_exactly_one_trailing_newline() {
        let mut output = Vec::new();
        write_output(&mut output, "ok").unwrap();
        assert_eq!(output, b"ok\n");

        output.clear();
        write_output(&mut output, "ok\n").unwrap();
        assert_eq!(output, b"ok\n");
    }
}
