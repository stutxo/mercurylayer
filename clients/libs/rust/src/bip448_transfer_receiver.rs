use std::fmt;

use anyhow::Result;
use mercurylib::{
    transfer::bip448::{Bip448TransferChainFacts, Bip448TransferMsg},
    wallet::{Activity, Coin},
};
use secp256k1::PublicKey;

use crate::client_config::ClientConfig;

use super::Bip448ReceiveOutcome;

#[path = "bip448_transfer_receiver/driver.rs"]
mod driver;
#[path = "bip448_transfer_receiver/persist.rs"]
mod persist;
#[path = "bip448_transfer_receiver/verify.rs"]
mod verify;

pub(crate) use persist::Bip448AcceptedTransferState;
pub(crate) use verify::{expected_server_pubkey, transfer_chain_facts};

#[derive(Debug)]
pub struct Bip448PostAcceptanceSyncError {
    accepted_statechain_ids: Vec<String>,
    source: anyhow::Error,
}

impl Bip448PostAcceptanceSyncError {
    pub(crate) fn new(mut accepted_statechain_ids: Vec<String>, source: anyhow::Error) -> Self {
        accepted_statechain_ids.sort();
        accepted_statechain_ids.dedup();
        Self {
            accepted_statechain_ids,
            source,
        }
    }

    pub fn accepted_statechain_ids(&self) -> &[String] {
        &self.accepted_statechain_ids
    }
}

impl fmt::Display for Bip448PostAcceptanceSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "BIP448 transfer/key update already accepted for {}; duplicate rescan pending and the next update/list will retry: {}",
            self.accepted_statechain_ids.join(","),
            self.source
        )
    }
}

impl std::error::Error for Bip448PostAcceptanceSyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

struct Bip448VerifiedTransfer {
    msg: Bip448TransferMsg,
    chain_facts: Bip448TransferChainFacts,
    x1_generation: PublicKey,
}

struct Bip448CompletedKeyUpdate {
    server_pubkey: PublicKey,
}

pub(super) async fn try_transfer_bip448_receiver(
    client_config: &ClientConfig,
    coin: &mut Coin,
    enc_message: &str,
    wallet_network: &str,
    wallet_name: &str,
    activities: &mut Vec<Activity>,
) -> Result<Bip448ReceiveOutcome> {
    driver::try_transfer_bip448_receiver(
        client_config,
        coin,
        enc_message,
        wallet_network,
        wallet_name,
        activities,
    )
    .await
}

#[cfg(test)]
pub(in crate::transfer_receiver) use driver::test_support;
