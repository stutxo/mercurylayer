mod execute;
mod fingerprint;
mod inputs;
mod plan;
mod reconcile;

#[cfg(test)]
mod execute_tests;
#[cfg(test)]
mod fingerprint_tests;
#[cfg(test)]
mod plan_tests;
#[cfg(test)]
mod test_support;

use std::path::Path;

use anyhow::{bail, Result};

pub(super) use super::argv::{ArgvCommand, CommandOutput, CommandRunner, SystemCommandRunner};
use super::cli::BuildService;
use super::model::StackMetadata;
pub(super) use reconcile::{inspect_rng_replacement, RngImageReplacement};

const INQUISITION_COMMIT: &str = "f5365867662091c2dbf1b2d438b8bb477a3dcb6f";
const INQUISITION_BUILD_ARG: &str = "BITCOIN_INQUISITION_COMMIT";
const LOCKBOX_BUILD_ARG: &str = "LOCKBOX_ENABLE_TEST_RNG";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifiedImage {
    pub(super) tag: String,
    pub(super) image_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifiedBuild {
    pub(super) mercury: VerifiedImage,
    pub(super) token: VerifiedImage,
    pub(super) lockbox: VerifiedImage,
    pub(super) lockbox_rng: VerifiedImage,
    pub(super) inquisition: VerifiedImage,
}

pub(super) fn execute(
    repo_root: &Path,
    metadata: &StackMetadata,
    service: BuildService,
    runner: &mut impl CommandRunner,
) -> Result<StackMetadata> {
    execute::execute(repo_root, metadata, service, runner)
}

pub(super) fn verify_complete(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<VerifiedBuild> {
    execute::verify_complete(repo_root, metadata, runner)
}

fn run_checked(runner: &mut impl CommandRunner, command: ArgvCommand) -> Result<CommandOutput> {
    let output = runner.run(&command)?;
    if !output.success {
        super::argv::record_failure(&command, &output);
        bail!(
            "argv command {command:?} failed with status {:?}: stdout={} stderr={}",
            output.code,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}
