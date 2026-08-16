use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::super::bootstrap::{self, ChainWalletSnapshot};
use super::super::lifecycle::{self, StatusReport};
use super::super::model::{canonical_json, StackMetadata};
use super::super::verifier::{self, StableContractSnapshot};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlSnapshot {
    pub(super) lifecycle: StatusReport,
    pub(super) chain_wallet: ChainWalletSnapshot,
    pub(super) contracts: StableContractSnapshot,
}

impl ControlSnapshot {
    pub(super) fn capture(repo_root: &Path, metadata: &StackMetadata) -> Result<Self> {
        let lifecycle = lifecycle::ready(repo_root, metadata)
            .context("capture exact ready control topology")?;
        lifecycle::require_stable_started(&lifecycle)?;
        let chain_wallet = bootstrap::snapshot(repo_root, metadata)
            .context("capture exact control chain and wallet")?;
        ensure!(
            chain_wallet.height == 101,
            "fresh control chain height must remain exactly 101"
        );
        let contracts = verifier::stable_snapshot(repo_root, metadata)
            .context("capture exact control config and catalogs")?;
        Ok(Self {
            lifecycle,
            chain_wallet,
            contracts,
        })
    }

    pub(super) fn digests(&self) -> Result<SnapshotDigests> {
        Ok(SnapshotDigests {
            topology: digest(&self.lifecycle)?,
            chain_wallet: digest(&self.chain_wallet)?,
            settings: digest(&self.contracts.settings)?,
            config: digest(&self.contracts.mercury_config)?,
            client_catalog: digest(&(
                &self.contracts.client_migration_sha256,
                &self.contracts.client_database,
            ))?,
            postgres_catalogs: digest(&self.contracts.postgres)?,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotDigests {
    pub(super) topology: String,
    pub(super) chain_wallet: String,
    pub(super) settings: String,
    pub(super) config: String,
    pub(super) client_catalog: String,
    pub(super) postgres_catalogs: String,
}

pub(super) fn compare(expected: &ControlSnapshot, actual: &ControlSnapshot) -> Result<()> {
    compare_digests(&expected.digests()?, &actual.digests()?)?;
    ensure!(
        expected == actual,
        "control snapshot digest equality did not imply exact value equality"
    );
    Ok(())
}

fn compare_digests(expected: &SnapshotDigests, actual: &SnapshotDigests) -> Result<()> {
    let changed = [
        ("topology", &expected.topology, &actual.topology),
        ("chain_wallet", &expected.chain_wallet, &actual.chain_wallet),
        ("settings", &expected.settings, &actual.settings),
        ("config", &expected.config, &actual.config),
        (
            "client_catalog",
            &expected.client_catalog,
            &actual.client_catalog,
        ),
        (
            "postgres_catalogs",
            &expected.postgres_catalogs,
            &actual.postgres_catalogs,
        ),
    ]
    .into_iter()
    .filter_map(|(name, before, after)| (before != after).then_some(name))
    .collect::<Vec<_>>();
    ensure!(
        changed.is_empty(),
        "control stable snapshot drifted in dimensions: {}",
        changed.join(", ")
    );
    Ok(())
}

fn digest(value: &impl Serialize) -> Result<String> {
    let bytes = canonical_json(value)?;
    let mut hash = Sha256::new();
    hash.update(b"bip448-control-stable-snapshot-v1\0");
    hash.update(bytes.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_names_every_independent_drift_dimension() {
        let baseline = SnapshotDigests {
            topology: "a".into(),
            chain_wallet: "b".into(),
            settings: "c".into(),
            config: "d".into(),
            client_catalog: "e".into(),
            postgres_catalogs: "f".into(),
        };
        assert!(compare_digests(&baseline, &baseline).is_ok());
        for (name, mutate) in [
            ("topology", 0),
            ("chain_wallet", 1),
            ("settings", 2),
            ("config", 3),
            ("client_catalog", 4),
            ("postgres_catalogs", 5),
        ] {
            let mut changed = baseline.clone();
            match mutate {
                0 => changed.topology = "x".into(),
                1 => changed.chain_wallet = "x".into(),
                2 => changed.settings = "x".into(),
                3 => changed.config = "x".into(),
                4 => changed.client_catalog = "x".into(),
                _ => changed.postgres_catalogs = "x".into(),
            }
            let error = compare_digests(&baseline, &changed).unwrap_err();
            assert!(format!("{error:#}").contains(name));
        }
    }
}
