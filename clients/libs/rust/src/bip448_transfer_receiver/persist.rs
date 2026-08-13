use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{absolute, Address, Network};
use chrono::Utc;
use mercurylib::{
    bip448_statechain::{
        deposit::BIP448_COIN_PROTOCOL,
        storage::{
            build_funding_latest_state, build_funding_recovery_artifacts, Bip448StatechainRecord,
        },
    },
    wallet::{Activity, Coin, CoinStatus},
};
use secp256k1::{PublicKey, Secp256k1};

use crate::sqlite_manager::{
    insert_bip448_state_history_entry, insert_or_update_bip448_statechain_from_transfer,
};

use super::super::{Bip448ReceiveOutcome, TransferReceiveRequestResult};
use super::{verify::expected_server_pubkey, Bip448CompletedKeyUpdate, Bip448VerifiedTransfer};

pub(crate) struct Bip448AcceptedTransferState {
    record: Bip448StatechainRecord,
}

impl Bip448AcceptedTransferState {
    fn new(
        wallet_name: &str,
        verified: &Bip448VerifiedTransfer,
        completed_key_update: &Bip448CompletedKeyUpdate,
    ) -> Result<Self> {
        let expected_server =
            expected_server_pubkey(&verified.msg, &verified.chain_facts.receiver_user_pubkey)?;
        if completed_key_update.server_pubkey != expected_server {
            return Err(anyhow!(
                "BIP448 accepted transfer does not have the expected server share"
            ));
        }
        let record = build_transfer_record(wallet_name, verified)?;
        Ok(Self { record })
    }

    pub(crate) fn record(&self) -> &Bip448StatechainRecord {
        &self.record
    }
}

pub(super) async fn persist_accepted_transfer(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet_name: &str,
    coin: &mut Coin,
    activities: &mut Vec<Activity>,
    verified: Bip448VerifiedTransfer,
    response: TransferReceiveRequestResult,
) -> Result<Bip448ReceiveOutcome> {
    if response.is_batch_locked {
        return Ok(Bip448ReceiveOutcome::BatchLocked);
    }

    let completed = Bip448CompletedKeyUpdate::new(
        &verified,
        response
            .server_pubkey
            .as_deref()
            .ok_or_else(|| anyhow!("BIP448 transfer response has no server public key"))?,
    )?;
    let accepted = Bip448AcceptedTransferState::new(wallet_name, &verified, &completed)?;
    let (updated_coin, activity) = accepted_coin(coin, &accepted, &completed)?;

    insert_or_update_bip448_statechain_from_transfer(pool, &accepted).await?;
    for entry in &verified.msg.state_history {
        insert_bip448_state_history_entry(pool, wallet_name, &verified.msg.statechain_id, entry)
            .await?;
    }
    *coin = updated_coin;
    activities.push(activity);

    Ok(Bip448ReceiveOutcome::Processed(verified.msg.statechain_id))
}

fn build_transfer_record(
    wallet_name: &str,
    verified: &Bip448VerifiedTransfer,
) -> Result<Bip448StatechainRecord> {
    let secp = Secp256k1::new();
    let aggregate_pubkey = PublicKey::from_str(&verified.msg.aggregate_pubkey)?;
    let recovery_script = Address::p2tr(
        &secp,
        verified
            .chain_facts
            .receiver_user_pubkey
            .x_only_public_key()
            .0,
        None,
        verified.chain_facts.expected_network,
    )
    .script_pubkey();
    let artifacts = build_funding_recovery_artifacts(
        &secp,
        &aggregate_pubkey,
        verified.chain_facts.funding_outpoint,
        verified.chain_facts.funding_output.value,
        recovery_script,
        verified.msg.latest_state_number,
        absolute::LockTime::from_consensus(verified.msg.latest_state.state_locktime),
        verified.msg.challenge_delay,
        verified.msg.latest_state.fee_bump_policy,
    )?;
    if artifacts.funding_output_script_pubkey != verified.chain_facts.funding_output.script_pubkey {
        return Err(anyhow!("BIP448 transfer funding script does not match Tx0"));
    }
    let latest_state = build_funding_latest_state(
        &secp,
        &aggregate_pubkey,
        &artifacts,
        verified.msg.latest_state.signing_metadata.clone(),
        Vec::new(),
    )?;
    if latest_state != verified.msg.latest_state {
        return Err(anyhow!("BIP448 transfer latest state is not canonical"));
    }

    let mut funding_outpoint = verified.msg.funding_outpoint.clone();
    funding_outpoint.txid = verified.chain_facts.funding_outpoint.txid.to_string();
    funding_outpoint.vout = verified.chain_facts.funding_outpoint.vout;
    funding_outpoint.value_sats = verified.chain_facts.funding_output.value;
    Ok(Bip448StatechainRecord {
        wallet_name: wallet_name.to_string(),
        statechain_id: verified.msg.statechain_id.clone(),
        aggregate_pubkey: aggregate_pubkey.to_string(),
        funding_outpoint,
        latest_state_number: latest_state.state_number,
        challenge_delay: latest_state.challenge_delay,
        amount_sats: verified.chain_facts.funding_output.value,
        network: verified.chain_facts.expected_network.to_string(),
        latest_state,
    })
}

fn accepted_coin(
    coin: &Coin,
    accepted: &Bip448AcceptedTransferState,
    completed: &Bip448CompletedKeyUpdate,
) -> Result<(Coin, Activity)> {
    let record = accepted.record();
    let mut coin = coin.clone();
    let network = Network::from_str(&record.network)?;
    let aggregate = PublicKey::from_str(&record.aggregate_pubkey)?;
    let funding_spend_info = mercurylib::bip448_statechain::script::funding_spend_info(
        &Secp256k1::new(),
        aggregate.x_only_public_key().0,
    )?;
    let funding_script =
        mercurylib::bip448_statechain::script::output_script_pubkey(&funding_spend_info);
    let aggregated_address = Address::from_script(&funding_script, network)?;
    let amount = u32::try_from(record.amount_sats)
        .map_err(|_| anyhow!("BIP448 transfer amount does not fit the wallet coin format"))?;

    coin.server_pubkey = Some(completed.server_pubkey.to_string());
    coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
    coin.aggregated_address = Some(aggregated_address.to_string());
    coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
    coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
    coin.utxo_vout = Some(record.funding_outpoint.vout);
    coin.amount = Some(amount);
    coin.statechain_id = Some(record.statechain_id.clone());
    coin.signed_statechain_id = Some(mercurylib::transfer::receiver::sign_message(
        &record.statechain_id,
        &coin,
    )?);
    coin.locktime = Some(record.latest_state.state_locktime);
    coin.public_nonce = Some(
        record
            .latest_state
            .signing_metadata
            .client_public_nonce
            .clone(),
    );
    coin.server_public_nonce = Some(
        record
            .latest_state
            .signing_metadata
            .server_public_nonce
            .clone(),
    );
    coin.blinding_factor = Some(record.latest_state.signing_metadata.blinding_factor.clone());
    coin.status = CoinStatus::CONFIRMED;

    Ok((
        coin,
        Activity {
            utxo: record.funding_outpoint.txid.clone(),
            amount,
            action: "Receive".to_string(),
            date: Utc::now().to_rfc3339(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_receiver::{
        bip448_transfer_receiver::{test_support::*, Bip448VerifiedTransfer},
        Bip448ReceiveOutcome, TransferReceiveRequestResult,
    };
    use mercurylib::transfer::receiver::StatechainInfoResponsePayload;

    #[tokio::test]
    #[rustfmt::skip]
    async fn locked_batch_response_returns_without_mutating_client_state() {
        let fixture = fixture();
        let mut coin = fixture.coin.clone();
        let coin_before = serde_json::to_string(&coin).unwrap();
        let mut activities = Vec::new();
        let pool = pool().await;
        let info: StatechainInfoResponsePayload = serde_json::from_str(INFO).unwrap();
        let verified = Bip448VerifiedTransfer::new(fixture.msg.clone(), &info, fixture.facts.clone()).unwrap();

        let outcome = persist_accepted_transfer(
            &pool, "wallet", &mut coin, &mut activities, verified,
            TransferReceiveRequestResult { is_batch_locked: true, server_pubkey: None },
        ).await.unwrap();

        assert!(matches!(outcome, Bip448ReceiveOutcome::BatchLocked));
        assert_eq!(serde_json::to_string(&coin).unwrap(), coin_before);
        assert!(activities.is_empty());
        assert!(crate::sqlite_manager::get_bip448_statechain_optional(&pool, "wallet", "statechain").await.unwrap().is_none());
        assert!(crate::sqlite_manager::get_bip448_state_history(&pool, "wallet", "statechain").await.unwrap().is_empty());
    }
}
