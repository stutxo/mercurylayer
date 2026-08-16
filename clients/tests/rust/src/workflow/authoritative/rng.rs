use anyhow::{ensure, Context, Result};
use serde::Serialize;

use super::super::model::StackMetadata;
use super::super::test_runner::{
    RngAdoptionRecord, RNG_RECONCILIATION_TARGET, RNG_RECONCILIATION_TEST,
};
use super::run::BuildIdentityReport;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RngHistoryReport {
    pub(super) primary_initial_image_id: String,
    pub(super) primary_final_image_id: String,
    pub(super) control_initial_image_id: String,
    pub(super) control_final_image_id: String,
    pub(super) adoption_count: usize,
    pub(super) adoption_history: Vec<RngAdoptionRecord>,
    pub(super) control_metadata_unchanged: bool,
}

pub(super) fn require_exact_rng_history(
    initial: &BuildIdentityReport,
    primary: &StackMetadata,
    control_initial: &StackMetadata,
    control_final: &StackMetadata,
    adoptions: &[RngAdoptionRecord],
) -> Result<RngHistoryReport> {
    ensure!(
        adoptions.len() == 1,
        "authoritative run requires one exact deterministic RNG adoption, found {}",
        adoptions.len()
    );
    let adoption = &adoptions[0];
    let primary_rng = primary
        .build_resolution()
        .and_then(|build| build.images().lockbox())
        .context("final primary deterministic RNG metadata is absent")?
        .deterministic_rng();
    let control_rng = control_final
        .build_resolution()
        .and_then(|build| build.images().lockbox())
        .context("final control deterministic RNG metadata is absent")?
        .deterministic_rng();
    ensure!(
        adoption.project == primary.project().as_str()
            && adoption.target == RNG_RECONCILIATION_TARGET
            && adoption.test == RNG_RECONCILIATION_TEST
            && adoption.tag == initial.primary_rng_tag
            && adoption.previous_image_id == initial.primary_rng_image_id
            && adoption.adopted_image_id == primary_rng.image_id()
            && adoption.previous_image_id != adoption.adopted_image_id,
        "primary deterministic RNG adoption history is not the one exact authorized transition"
    );
    ensure!(
        primary_rng.tag() == initial.primary_rng_tag,
        "primary deterministic RNG tag changed during adoption"
    );
    ensure!(
        control_initial == control_final
            && control_rng.tag() == initial.control_rng_tag
            && control_rng.image_id() == initial.control_rng_image_id,
        "control metadata or deterministic RNG identity changed during primary adoption"
    );
    Ok(RngHistoryReport {
        primary_initial_image_id: initial.primary_rng_image_id.clone(),
        primary_final_image_id: primary_rng.image_id().into(),
        control_initial_image_id: initial.control_rng_image_id.clone(),
        control_final_image_id: control_rng.image_id().into(),
        adoption_count: 1,
        adoption_history: adoptions.to_vec(),
        control_metadata_unchanged: true,
    })
}
