use std::fmt;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

#[derive(Debug)]
pub enum WorkflowError {
    Usage(String),
    Operational(anyhow::Error),
}

impl WorkflowError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => EXIT_USAGE,
            Self::Operational(_) => EXIT_FAILURE,
        }
    }

    pub fn is_usage(&self) -> bool {
        matches!(self, Self::Usage(_))
    }
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::Operational(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for WorkflowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Usage(_) => None,
            Self::Operational(error) => error.source(),
        }
    }
}

impl From<anyhow::Error> for WorkflowError {
    fn from(error: anyhow::Error) -> Self {
        Self::Operational(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_mapping_is_stable() {
        let usage = WorkflowError::usage("bad arguments");
        assert_eq!(usage.exit_code(), EXIT_USAGE);
        assert!(usage.is_usage());

        let operational = WorkflowError::from(anyhow::anyhow!("failed"));
        assert_eq!(operational.exit_code(), EXIT_FAILURE);
        assert!(!operational.is_usage());
        assert_eq!(EXIT_SUCCESS, 0);
    }
}
