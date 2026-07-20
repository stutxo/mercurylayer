use std::{future::Future, str::FromStr};

use anyhow::{anyhow, Result};
use bitcoin::{
    absolute,
    consensus::deserialize,
    hashes::{sha256, Hash},
    Address, Network, OutPoint, PrivateKey, Transaction, Txid,
};
use chrono::Utc;
use mercurylib::{
    bip448_statechain::{
        deposit::BIP448_COIN_PROTOCOL,
        storage::{
            build_funding_latest_state, build_funding_recovery_artifacts, Bip448StatechainRecord,
        },
    },
    transfer::{
        bip448::{
            decrypt_bip448_transfer_msg, verify_bip448_transfer_msg, Bip448TransferChainFacts,
            Bip448TransferMsg,
        },
        receiver::{StatechainInfoResponsePayload, TransferReceiverRequestPayload},
        TxOutpoint,
    },
    wallet::{Activity, Coin, CoinStatus},
};
use secp256k1::{schnorr, KeyPair, PublicKey, Scalar, Secp256k1};

use crate::{
    client_config::ClientConfig,
    sqlite_manager::{
        get_bip448_statechain_optional, get_wallet,
        insert_or_update_bip448_statechain_from_transfer,
    },
    utils,
};

use super::{Bip448ReceiveOutcome, MessageResult};

const ALREADY_UPDATED_ERROR: &str = "key update already completed; manual completion required";

enum ReceiverPostError {
    LostResponse(anyhow::Error),
    Definite(anyhow::Error),
}

impl ReceiverPostError {
    fn classify(error: anyhow::Error) -> Self {
        let lost_response = error.downcast_ref::<reqwest::Error>().is_some_and(|error| {
            !error.is_builder()
                && !error.is_redirect()
                && !error.is_status()
                && !error.is_decode()
                && (error.is_timeout()
                    || error.is_connect()
                    || error.is_request()
                    || error.is_body())
        });
        if lost_response {
            Self::LostResponse(error)
        } else {
            Self::Definite(error)
        }
    }

    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::LostResponse(error) | Self::Definite(error) => error,
        }
    }
}

struct Bip448VerifiedTransfer {
    msg: Bip448TransferMsg,
    chain_facts: Bip448TransferChainFacts,
}

impl Bip448VerifiedTransfer {
    fn new(
        msg: Bip448TransferMsg,
        statechain_info: &StatechainInfoResponsePayload,
        chain_facts: Bip448TransferChainFacts,
    ) -> Result<Self> {
        verify_bip448_transfer_msg(&msg, statechain_info, &chain_facts)?;
        Ok(Self { msg, chain_facts })
    }
}

struct Bip448CompletedKeyUpdate {
    server_pubkey: PublicKey,
}

impl Bip448CompletedKeyUpdate {
    fn new(verified: &Bip448VerifiedTransfer, server_pubkey: &str) -> Result<Self> {
        let server_pubkey = PublicKey::from_str(server_pubkey)?;
        if server_pubkey
            != expected_server_pubkey(&verified.msg, &verified.chain_facts.receiver_user_pubkey)?
        {
            return Err(anyhow!(
                "BIP448 key update returned an unexpected server public key"
            ));
        }
        Ok(Self { server_pubkey })
    }
}

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

pub(super) async fn try_transfer_bip448_receiver(
    client_config: &ClientConfig,
    coin: &mut Coin,
    enc_message: &str,
    wallet_network: &str,
    wallet_name: &str,
    activities: &mut Vec<Activity>,
) -> Result<Bip448ReceiveOutcome> {
    let Some(msg) = decrypt_transfer_message(enc_message, &coin.auth_privkey)? else {
        return Ok(Bip448ReceiveOutcome::Legacy);
    };
    transfer_bip448_receiver(
        client_config,
        coin,
        msg,
        wallet_network,
        wallet_name,
        activities,
    )
    .await
}

fn decrypt_transfer_message(
    enc_message: &str,
    auth_privkey: &str,
) -> Result<Option<Bip448TransferMsg>> {
    Ok(decrypt_bip448_transfer_msg(enc_message, auth_privkey).ok())
}

async fn transfer_bip448_receiver(
    client_config: &ClientConfig,
    coin: &mut Coin,
    msg: Bip448TransferMsg,
    wallet_network: &str,
    wallet_name: &str,
    activities: &mut Vec<Activity>,
) -> Result<Bip448ReceiveOutcome> {
    let statechain_info = utils::get_statechain_info(&msg.statechain_id, client_config)
        .await?
        .ok_or_else(|| anyhow!("Statechain info not found"))?;
    let current_server = PublicKey::from_str(&statechain_info.enclave_public_key)?;
    if has_persisted_bip448_receipt(
        &client_config.pool,
        wallet_name,
        coin,
        &msg,
        &current_server,
    )
    .await?
    {
        return Ok(Bip448ReceiveOutcome::AlreadyProcessed);
    }

    let chain_facts = transfer_chain_facts(client_config, &msg, coin, wallet_network).await?;
    let verified =
        match Bip448VerifiedTransfer::new(msg.clone(), &statechain_info, chain_facts.clone()) {
            Ok(verified) => verified,
            Err(error) => {
                if !expected_server_pubkey(&msg, &chain_facts.receiver_user_pubkey)
                    .is_ok_and(|expected| current_server == expected)
                {
                    return Err(error);
                }
                return resolve_already_updated(
                    &client_config.pool,
                    wallet_name,
                    coin,
                    &msg,
                    &current_server,
                )
                .await;
            }
        };
    let unlock_signature =
        mercurylib::transfer::receiver::sign_message(&verified.msg.statechain_id, coin)?;
    let unlock_statechain_id = verified.msg.statechain_id.clone();
    let auth_pubkey = coin.auth_pubkey.clone();
    let receiver_request = create_receiver_request(&verified.msg, coin)?;

    execute_receiver_attempt(
        || std::future::ready(Ok(verified)),
        || Ok(()),
        || {
            super::unlock_statecoin(
                client_config,
                &unlock_statechain_id,
                &unlock_signature,
                &auth_pubkey,
            )
        },
        || async {
            super::send_transfer_receiver_request_payload(client_config, &receiver_request)
                .await
                .map_err(ReceiverPostError::classify)
        },
        |verified, response| {
            persist_accepted_transfer(
                &client_config.pool,
                wallet_name,
                coin,
                activities,
                verified,
                response,
            )
        },
    )
    .await
    .map(Bip448ReceiveOutcome::Processed)
}

async fn resolve_already_updated(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet_name: &str,
    receiver_coin: &Coin,
    msg: &Bip448TransferMsg,
    current_server: &PublicKey,
) -> Result<Bip448ReceiveOutcome> {
    if has_persisted_bip448_receipt(pool, wallet_name, receiver_coin, msg, current_server).await? {
        return Ok(Bip448ReceiveOutcome::AlreadyProcessed);
    }

    Err(anyhow!(ALREADY_UPDATED_ERROR))
}

async fn has_persisted_bip448_receipt(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet_name: &str,
    receiver_coin: &Coin,
    msg: &Bip448TransferMsg,
    current_server: &PublicKey,
) -> Result<bool> {
    let Some(record) =
        get_bip448_statechain_optional(pool, wallet_name, &msg.statechain_id).await?
    else {
        return Ok(false);
    };

    if record.wallet_name != wallet_name
        || record.statechain_id != msg.statechain_id
        || record.aggregate_pubkey != msg.aggregate_pubkey
        || record.funding_outpoint != msg.funding_outpoint
        || record.challenge_delay != msg.challenge_delay
        || record.amount_sats != msg.amount_sats
        || record.network != msg.network
        || record.latest_state_number < msg.latest_state_number
        || (record.latest_state_number == msg.latest_state_number
            && record.latest_state != msg.latest_state)
    {
        return Ok(false);
    }

    let server_pubkey = current_server.to_string();
    let wallet = get_wallet(pool, wallet_name).await?;
    Ok(wallet.coins.iter().any(|coin| {
        coin.status != CoinStatus::INITIALISED
            && coin.statechain_protocol.as_deref() == Some(BIP448_COIN_PROTOCOL)
            && coin.statechain_id.as_deref() == Some(msg.statechain_id.as_str())
            && coin.auth_pubkey == receiver_coin.auth_pubkey
            && coin.user_pubkey == msg.receiver_user_public_key
            && coin.server_pubkey.as_deref() == Some(server_pubkey.as_str())
            && coin.aggregated_pubkey.as_deref() == Some(record.aggregate_pubkey.as_str())
            && coin.utxo_txid.as_deref() == Some(record.funding_outpoint.txid.as_str())
            && coin.utxo_vout == Some(record.funding_outpoint.vout)
            && coin.amount.map(u64::from) == Some(record.amount_sats)
            && coin
                .signed_statechain_id
                .as_ref()
                .is_some_and(|value| !value.is_empty())
    }))
}

async fn persist_accepted_transfer(
    pool: &sqlx::Pool<sqlx::Sqlite>,
    wallet_name: &str,
    coin: &mut Coin,
    activities: &mut Vec<Activity>,
    verified: Bip448VerifiedTransfer,
    response: super::TransferReceiveRequestResult,
) -> Result<MessageResult> {
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
    *coin = updated_coin;
    activities.push(activity);

    Ok(MessageResult {
        is_batch_locked: false,
        statechain_id: Some(verified.msg.statechain_id),
        duplicated_coins: Vec::new(),
    })
}

async fn transfer_chain_facts(
    client_config: &ClientConfig,
    msg: &Bip448TransferMsg,
    coin: &Coin,
    wallet_network: &str,
) -> Result<Bip448TransferChainFacts> {
    let funding_outpoint = OutPoint {
        txid: Txid::from_str(&msg.funding_outpoint.txid)?,
        vout: msg.funding_outpoint.vout,
    };
    let tx0_hex = super::get_tx0(&client_config.chain_client, &msg.funding_outpoint.txid).await?;
    let tx0: Transaction = deserialize(&hex::decode(&tx0_hex)?)?;
    let funding_output = tx0
        .output
        .get(funding_outpoint.vout as usize)
        .cloned()
        .ok_or_else(|| anyhow!("BIP448 funding output is missing from Tx0"))?;
    let (tx0_unspent, status) = super::verify_tx0_output_is_unspent_and_confirmed(
        &client_config.chain_client,
        &TxOutpoint {
            txid: funding_outpoint.txid.to_string(),
            vout: funding_outpoint.vout,
        },
        &tx0_hex,
        wallet_network,
        client_config.confirmation_target,
    )
    .await?;

    Ok(Bip448TransferChainFacts {
        expected_network: Network::from_str(wallet_network)?,
        median_time_past: client_config.chain_client.median_time_past()?,
        funding_outpoint,
        funding_output,
        tx0_confirmed: status == CoinStatus::CONFIRMED,
        tx0_unspent,
        receiver_user_pubkey: PublicKey::from_str(&coin.user_pubkey)?,
    })
}

fn expected_server_pubkey(msg: &Bip448TransferMsg, receiver: &PublicKey) -> Result<PublicKey> {
    Ok(PublicKey::from_str(&msg.aggregate_pubkey)?.combine(&receiver.negate())?)
}

fn create_receiver_request(
    msg: &Bip448TransferMsg,
    coin: &Coin,
) -> Result<TransferReceiverRequestPayload> {
    let receiver_secret = PrivateKey::from_wif(&coin.user_privkey)?.inner;
    let t1 = Scalar::from_be_bytes(msg.t1)?;
    let t2 = receiver_secret.negate().add_tweak(&t1)?;
    let t2 = hex::encode(t2.to_secret_bytes());
    let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let secp = Secp256k1::new();
    let auth_keypair = KeyPair::from_secret_key(&secp, &auth_secret);
    let auth_message = sha256::Hash::hash(t2.as_bytes()).to_byte_array();
    let auth_sig = schnorr::sign(&auth_message, &auth_keypair);

    Ok(TransferReceiverRequestPayload {
        statechain_id: msg.statechain_id.clone(),
        batch_data: None,
        t2,
        auth_sig: auth_sig.to_string(),
    })
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
        2,
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

    Ok(Bip448StatechainRecord {
        wallet_name: wallet_name.to_string(),
        statechain_id: verified.msg.statechain_id.clone(),
        aggregate_pubkey: aggregate_pubkey.to_string(),
        funding_outpoint: verified.msg.funding_outpoint.clone(),
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

async fn execute_receiver_attempt<Verified, Response, Output, V, VF, C, U, UF, K, KF, P, PF>(
    verify: V,
    before_receiver_post: C,
    unlock: U,
    mut key_update: K,
    persist: P,
) -> Result<Output>
where
    V: FnOnce() -> VF,
    VF: Future<Output = Result<Verified>>,
    C: FnOnce() -> Result<()>,
    U: FnOnce() -> UF,
    UF: Future<Output = Result<()>>,
    K: FnMut() -> KF,
    KF: Future<Output = std::result::Result<Response, ReceiverPostError>>,
    P: FnOnce(Verified, Response) -> PF,
    PF: Future<Output = Result<Output>>,
{
    let verified = verify().await?;
    unlock().await?;
    before_receiver_post()?;
    let response = match key_update().await {
        Ok(response) => response,
        Err(ReceiverPostError::LostResponse(_)) => {
            key_update().await.map_err(ReceiverPostError::into_inner)?
        }
        Err(error) => return Err(error.into_inner()),
    };
    persist(verified, response).await
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    #[derive(Default)]
    struct MockTransport {
        updated: bool,
        persisted: bool,
        crash_before_post: bool,
        lose_response: bool,
        crash_after_update: bool,
        verify_calls: u32,
        post_calls: u32,
        events: Vec<&'static str>,
    }

    async fn mock_attempt(mock: Rc<RefCell<MockTransport>>) -> Result<()> {
        {
            let mut mock = mock.borrow_mut();
            mock.verify_calls += 1;
            mock.events.push("verify");
            if mock.updated {
                return Err(anyhow!(ALREADY_UPDATED_ERROR));
            }
        }
        let checkpoint_mock = Rc::clone(&mock);
        let unlock_mock = Rc::clone(&mock);
        let update_mock = Rc::clone(&mock);
        let persist_mock = Rc::clone(&mock);

        execute_receiver_attempt(
            || std::future::ready(Ok(())),
            move || {
                let mut mock = checkpoint_mock.borrow_mut();
                mock.events.push("before_post");
                if std::mem::take(&mut mock.crash_before_post) {
                    return Err(anyhow!("crash before transfer/receiver"));
                }
                Ok(())
            },
            move || {
                unlock_mock.borrow_mut().events.push("unlock");
                std::future::ready(Ok(()))
            },
            move || {
                let mut mock = update_mock.borrow_mut();
                mock.events.push("post");
                mock.post_calls += 1;
                mock.updated = true;
                if std::mem::take(&mut mock.lose_response) {
                    std::future::ready(Err(anyhow!("lost response")))
                } else {
                    std::future::ready(Ok("server-share-2"))
                }
            },
            move |(), response| {
                let mut mock = persist_mock.borrow_mut();
                mock.events.push("persist");
                let result = if std::mem::take(&mut mock.crash_after_update) {
                    Err(anyhow!("crash after key update"))
                } else {
                    assert_eq!(response, "server-share-2");
                    mock.persisted = true;
                    Ok(())
                };
                std::future::ready(result)
            },
        )
        .await
    }

    #[tokio::test]
    async fn full_happy_path_uses_the_mock_transport_once() {
        let mock = Rc::new(RefCell::new(MockTransport::default()));
        mock_attempt(Rc::clone(&mock)).await.unwrap();

        let mock = mock.borrow();
        assert!(mock.updated && mock.persisted);
        assert_eq!(mock.verify_calls, 1);
        assert_eq!(mock.post_calls, 1);
        assert_eq!(
            mock.events,
            ["verify", "unlock", "before_post", "post", "persist"]
        );
    }

    #[tokio::test]
    async fn crash_before_receiver_post_reruns_verification_and_completes() {
        let mock = Rc::new(RefCell::new(MockTransport {
            crash_before_post: true,
            ..Default::default()
        }));
        assert!(mock_attempt(Rc::clone(&mock)).await.is_err());
        assert!(!mock.borrow().updated);

        mock_attempt(Rc::clone(&mock)).await.unwrap();
        let mock = mock.borrow();
        assert_eq!(mock.verify_calls, 2);
        assert_eq!(mock.post_calls, 1);
        assert!(mock.persisted);
    }

    #[tokio::test]
    async fn lost_response_reposts_without_reverification() {
        let mock = Rc::new(RefCell::new(MockTransport {
            lose_response: true,
            ..Default::default()
        }));
        mock_attempt(Rc::clone(&mock)).await.unwrap();

        let mock = mock.borrow();
        assert_eq!(mock.verify_calls, 1);
        assert_eq!(mock.post_calls, 2);
        assert!(mock.updated && mock.persisted);
    }

    #[tokio::test]
    async fn crash_after_key_update_requires_manual_completion_on_rerun() {
        let mock = Rc::new(RefCell::new(MockTransport {
            crash_after_update: true,
            ..Default::default()
        }));
        assert!(mock_attempt(Rc::clone(&mock)).await.is_err());
        assert!(mock.borrow().updated);
        assert!(!mock.borrow().persisted);

        let error = mock_attempt(Rc::clone(&mock)).await.unwrap_err();
        assert_eq!(error.to_string(), ALREADY_UPDATED_ERROR);
        assert_eq!(mock.borrow().verify_calls, 2);
        assert!(!mock.borrow().persisted);
    }

}
