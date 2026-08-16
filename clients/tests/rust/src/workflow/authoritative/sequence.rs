use serde::Serialize;

use super::super::error::WorkflowError;
use super::super::matrix::{MatrixTarget, MATRIX};
use super::super::model::StackMetadata;
use super::super::test_runner::RngAdoptionRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MatrixTargetRecord {
    pub(super) ordinal: usize,
    pub(super) target: String,
    pub(super) tests: Vec<String>,
    pub(super) status: String,
    pub(super) first_invocation: bool,
}

pub(super) struct MatrixStep {
    pub(super) metadata: StackMetadata,
    pub(super) adoption: Option<RngAdoptionRecord>,
}

#[derive(Debug)]
pub(super) struct MatrixExecution {
    pub(super) records: Vec<MatrixTargetRecord>,
    pub(super) metadata: StackMetadata,
    pub(super) adoptions: Vec<RngAdoptionRecord>,
}

pub(super) fn run_matrix<S>(
    mut metadata: StackMetadata,
    mut start: impl FnMut(&'static MatrixTarget) -> Result<S, WorkflowError>,
    mut invoke: impl FnMut(&StackMetadata, &str, &str) -> Result<MatrixStep, WorkflowError>,
    mut finish: impl FnMut(
        S,
        Result<MatrixTargetRecord, WorkflowError>,
    ) -> Result<MatrixTargetRecord, WorkflowError>,
) -> Result<MatrixExecution, WorkflowError> {
    let mut records = Vec::with_capacity(MATRIX.len());
    let mut adoptions = Vec::new();
    for (ordinal, target) in MATRIX.iter().enumerate() {
        let target_evidence = start(target)?;
        let mut tests = Vec::with_capacity(target.tests.len());
        let target_result = (|| {
            for identity in target.tests {
                let step = invoke(&metadata, target.target, identity)?;
                metadata = step.metadata;
                if let Some(adoption) = step.adoption {
                    adoptions.push(adoption);
                }
                tests.push((*identity).to_owned());
            }
            Ok(MatrixTargetRecord {
                ordinal,
                target: target.target.into(),
                tests,
                status: "successful".into(),
                first_invocation: true,
            })
        })();
        records.push(finish(target_evidence, target_result)?);
    }
    Ok(MatrixExecution {
        records,
        metadata,
        adoptions,
    })
}
