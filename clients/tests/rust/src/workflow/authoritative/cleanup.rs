use anyhow::Result;

use super::super::error::WorkflowError;

pub(super) struct CleanupAttempts {
    pub(super) primary_succeeded: bool,
    pub(super) control_succeeded: bool,
    pub(super) errors: Vec<String>,
}

pub(super) fn ordered_cleanup<T>(
    primary: Option<T>,
    control: Option<T>,
    mut down: impl FnMut(&T) -> Result<()>,
) -> CleanupAttempts {
    let mut attempts = CleanupAttempts {
        primary_succeeded: primary.is_none(),
        control_succeeded: control.is_none(),
        errors: Vec::new(),
    };
    if let Some(primary) = primary.as_ref() {
        match down(primary) {
            Ok(()) => attempts.primary_succeeded = true,
            Err(error) => attempts.errors.push(format!("primary down: {error:#}")),
        }
    }
    if let Some(control) = control.as_ref() {
        match down(control) {
            Ok(()) => attempts.control_succeeded = true,
            Err(error) => attempts.errors.push(format!("control down: {error:#}")),
        }
    }
    attempts
}

pub(super) fn attach_cleanup(primary: WorkflowError, cleanup_errors: Vec<String>) -> WorkflowError {
    if cleanup_errors.is_empty() {
        return primary;
    }
    let code = primary.exit_code();
    let message = format!(
        "{primary}; ordered cleanup also failed: {}",
        cleanup_errors.join("; ")
    );
    match primary {
        WorkflowError::ChildExit { .. } => WorkflowError::child_exit(code, message),
        WorkflowError::Usage(_) | WorkflowError::Operational(_) => {
            WorkflowError::from(anyhow::anyhow!(message))
        }
    }
}

pub(super) fn append_accounting_error(errors: &mut Vec<String>, accounting: Result<()>) {
    if let Err(error) = accounting {
        errors.push(format!("failure final accounting: {error:#}"));
    }
}

pub(super) fn combine_checks(absence: Result<()>, accounting: Result<()>) -> Result<()> {
    match (absence, accounting) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(absence), Err(accounting)) => {
            anyhow::bail!("{absence:#}; Docker accounting also failed: {accounting:#}")
        }
    }
}
