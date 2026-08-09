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
        get_bip448_statechain_optional, get_wallet, insert_bip448_state_history_entry,
        insert_or_update_bip448_statechain_from_transfer,
    },
    utils,
};

use super::Bip448ReceiveOutcome;

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
    let msg = decrypt_transfer_message(enc_message, &coin.auth_privkey)?;
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

fn decrypt_transfer_message(enc_message: &str, auth_privkey: &str) -> Result<Bip448TransferMsg> {
    Ok(decrypt_bip448_transfer_msg(enc_message, auth_privkey)?)
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

    let chain_facts = transfer_chain_facts(
        client_config,
        &msg,
        PublicKey::from_str(&coin.user_pubkey)?,
        wallet_network,
    )
    .await?;
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
    let mut funding_outpoint = msg.funding_outpoint.clone();
    funding_outpoint.txid = Txid::from_str(&funding_outpoint.txid)?.to_string();

    if record.wallet_name != wallet_name
        || record.statechain_id != msg.statechain_id
        || record.aggregate_pubkey != msg.aggregate_pubkey
        || record.funding_outpoint != funding_outpoint
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

pub(crate) async fn transfer_chain_facts(
    client_config: &ClientConfig,
    msg: &Bip448TransferMsg,
    receiver_user_pubkey: PublicKey,
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
        receiver_user_pubkey,
    })
}

pub(crate) fn expected_server_pubkey(
    msg: &Bip448TransferMsg,
    receiver: &PublicKey,
) -> Result<PublicKey> {
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
    use crate::chain::{ChainClient, CoreRpcAuth, CoreRpcConfig};
    use bitcoin::TxOut;
    use mercurylib::{
        bip448_statechain::script,
        encode_sc_address,
        wallet::{Settings, Wallet},
    };
    use secp256k1::SecretKey;
    use sqlx::sqlite::SqlitePoolOptions;

    // Cryptographically valid two-state transfer vector with deterministic keys and nonces.
    const MSG: &str = r#"{"msg_version":2,"statechain_id":"statechain","transfer_signature":"bf5840f84f3ac32690da6c53ebec7f99fab14ddf5a6318476ff072971e82ab558dd4e81145cec932de46230fea378bdf431efbfec70335337f457c17c075a8fe","sender_user_public_key":"02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","receiver_user_public_key":"0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7","server_public_key":"03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b","aggregate_pubkey":"02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f","funding_outpoint":{"txid":"4242424242424242424242424242424242424242424242424242424242424242","vout":0,"value_sats":100000},"latest_state_number":2,"challenge_delay":144,"amount_sats":100000,"network":"regtest","value_schedule":{"funding_value_sats":100000,"update_input_value_sats":100000,"update_state_output_value_sats":100000,"settlement_input_value_sats":100000,"settlement_recovery_output_value_sats":100000},"latest_state":{"state_number":2,"state_locktime":1000000005,"challenge_delay":144,"update_tx":"03000000000101424242424242424242424242424242424242424242424242424242424242424200000000000000000002a086010000000000225120f99f4d961c7c21602831c6d649a4ea38201af79c05d0991d16d90829fdadb45400000000000000000451024e73034065baa3ef9d33105e31878e408fa9ffd32f2545ca635720a86abecc6edffae0310f6d946e034e65b1b58c1a51e98f49aa553920437775a1aab26422538579297f03cecbcc21c1989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f05ca9a3b","settlement_tx":"0300000000010123c27b49882b8977be9f7bf669f513351fdd151d241c9f7749db49bc2a9ae40300000000009000000002a0860100000000002251209a09f771892f1be2e77ac302ff88d53afdc94e3ad79f66a6065bcf343378a14d00000000000000000451024e730223201345b09228120c17a2e1e0690f9dfb9b15b59b1f7debd52a0acac6b4dcb66c72ce8741c0989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f017f96e5b2074130b4d846e4bbf1c794346f38b6c90f6b2d7bcf85ac4b2d13e005ca9a3b","update_template_hash":"70e2849f02b3e921cda139949d9f68771e007317387e7ef60515231440fd1e52","settlement_template_hash":"1345b09228120c17a2e1e0690f9dfb9b15b59b1f7debd52a0acac6b4dcb66c72","state_output_script_pubkey":"5120f99f4d961c7c21602831c6d649a4ea38201af79c05d0991d16d90829fdadb454","funding_update_script":"cecbcc","funding_update_control_block":"c1989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f","state_update_script":"0406ca9a3bb175cecbcc","state_update_control_block":"c0989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fd8d16b3760c57c7267b789d8a1cd2ffe9c5978025537629273b460aba53ab90c","state_settlement_script":"201345b09228120c17a2e1e0690f9dfb9b15b59b1f7debd52a0acac6b4dcb66c72ce87","state_settlement_control_block":"c0989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f017f96e5b2074130b4d846e4bbf1c794346f38b6c90f6b2d7bcf85ac4b2d13e0","csfs_key_metadata":{"aggregate_pubkey_parity_odd":false,"negate_seckey":false},"signing_metadata":{"role":"funding_update","signing_id":"0202020202020202020202020202020202020202020202020202020202020202","client_public_nonce":"03bc02445e1111ebf1f103c6ff2cf62c214fec48d0084a65c482e99ce73ba198de03d28c76d8f858a659d37f4abd1505f8931c45077ba71a5274adde79bc8aae06f3","server_public_nonce":"035f10ef76a0174cdb766a68b3439e22bcf24dc277497b37205bab3766e32a6899038f6a8fc25318cc9887a6e8cadbe7cac425174b884599058ce8b2f78c6e8fbd70","blinding_factor":"1616161616161616161616161616161616161616161616161616161616161616","update_template_hash":"70e2849f02b3e921cda139949d9f68771e007317387e7ef60515231440fd1e52","update_signature":"65baa3ef9d33105e31878e408fa9ffd32f2545ca635720a86abecc6edffae0310f6d946e034e65b1b58c1a51e98f49aa553920437775a1aab26422538579297f","server_signature_count":2},"fee_bump_policy":"zero_fee_ephemeral_anchor","value_schedule":{"funding_value_sats":100000,"update_input_value_sats":100000,"update_state_output_value_sats":100000,"settlement_input_value_sats":100000,"settlement_recovery_output_value_sats":100000},"anchors":[{"tx_role":"funding_update","output_index":1,"value_sats":0,"script_pubkey":"51024e73"},{"tx_role":"settlement","output_index":1,"value_sats":0,"script_pubkey":"51024e73"}],"cpfp_child_templates":[]},"server_signature_count":2,"t1":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"state_history":[{"state_number":1,"state_locktime":999999995,"owner_public_key":"02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337","update_template_hash":"381f652c451fde1f0eef1f979592ba5a418376e2316b738614b28c69e9400490","settlement_template_hash":"0e81168589cdd3d3e91d4e9e8f6d0fccd95bb0825393626e74164e23f5220126","update_signature":"f5fe9372be09b258db29877d816469c1a921b8dcb778ef23af00e969459d8416ce63f43466445e8958cc66b1ed431d934675738cf66da4a33ef8d48a6b58fcae","client_public_nonce":"0303d4415fc74e49a480db2ee554566f625b2d4b1af82b6e262c433374859e9efb033eee3c4e3493e97110f0a4c0a4d4d4d5f272f980782234a46dc5a7f01b019ee0","server_public_nonce":"039f31d027e17b6be6aace5fd20d1119f131f226777884bc423fb262dc037b38e302b2890303451ceffd050fcb0ee9db960c4b05755f5b533ef9535cbe25b6a4b533","blinding_factor":"1515151515151515151515151515151515151515151515151515151515151515"},{"state_number":2,"state_locktime":1000000005,"owner_public_key":"0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7","update_template_hash":"70e2849f02b3e921cda139949d9f68771e007317387e7ef60515231440fd1e52","settlement_template_hash":"1345b09228120c17a2e1e0690f9dfb9b15b59b1f7debd52a0acac6b4dcb66c72","update_signature":"65baa3ef9d33105e31878e408fa9ffd32f2545ca635720a86abecc6edffae0310f6d946e034e65b1b58c1a51e98f49aa553920437775a1aab26422538579297f","client_public_nonce":"03bc02445e1111ebf1f103c6ff2cf62c214fec48d0084a65c482e99ce73ba198de03d28c76d8f858a659d37f4abd1505f8931c45077ba71a5274adde79bc8aae06f3","server_public_nonce":"035f10ef76a0174cdb766a68b3439e22bcf24dc277497b37205bab3766e32a6899038f6a8fc25318cc9887a6e8cadbe7cac425174b884599058ce8b2f78c6e8fbd70","blinding_factor":"1616161616161616161616161616161616161616161616161616161616161616"}]}"#;
    const INFO: &str = r#"{"enclave_public_key":"03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b","num_sigs":2,"statechain_info":[{"statechain_id":"statechain","server_pubnonce":"039f31d027e17b6be6aace5fd20d1119f131f226777884bc423fb262dc037b38e302b2890303451ceffd050fcb0ee9db960c4b05755f5b533ef9535cbe25b6a4b533","challenge":"c92315f66e51c7fe79055243762996a9e250782ddd53adf6c6c958dc928a6d7b","tx_n":1},{"statechain_id":"statechain","server_pubnonce":"035f10ef76a0174cdb766a68b3439e22bcf24dc277497b37205bab3766e32a6899038f6a8fc25318cc9887a6e8cadbe7cac425174b884599058ce8b2f78c6e8fbd70","challenge":"ac31ec275e2e9d4e9fc62ed0f9d9f558800def734bd267fb2e260a283d606b93","tx_n":2}],"x1_pub":"03f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a"}"#;
    // ECIES plaintext is {"msg_version":1,"statechain_id":"statechain"} under auth key [8; 32].
    const MISSING_SIGNATURE: &str = "0450bfa93d1d7eccf21e821b47555b35717c7581539a802dbce4e2681e947f9ed1265b32fb0f3168723723f59ac9acda6a5e3aa93ae3da95b2f6c466abac1f9c02d4a0b843668195f2fc903b94f884316ecbe86fd73a02a26c8202c2f98e3189b6a065c5444ba47420e7c54e8f68986f32ca7a456ba17f5ba14ce0ded13d738e391ba33a2afe2ad28f8f61c0e9c96f";
    #[rustfmt::skip]
    struct Fixture { msg: Bip448TransferMsg, mailbox: String, facts: Bip448TransferChainFacts, coin: Coin }
    #[rustfmt::skip]
    fn test_coin(user_seed: u8, auth_seed: u8) -> Coin {
        let secp = Secp256k1::new();
        let user = SecretKey::from_secret_bytes([user_seed; 32]).unwrap();
        let auth = SecretKey::from_secret_bytes([auth_seed; 32]).unwrap();
        let mut coin = test_wallet(Vec::new()).get_new_coin().unwrap();
        coin.user_privkey = PrivateKey::new(user, Network::Regtest).to_wif();
        coin.user_pubkey = user.public_key(&secp).to_string();
        coin.auth_privkey = PrivateKey::new(auth, Network::Regtest).to_wif();
        coin.auth_pubkey = auth.public_key(&secp).to_string();
        coin.address = encode_sc_address(&user.public_key(&secp), &auth.public_key(&secp), Network::Regtest).unwrap();
        coin.backup_address = Address::p2tr(&secp, user.public_key(&secp).x_only_public_key().0, None, Network::Regtest).to_string();
        coin
    }

    #[rustfmt::skip]
    fn test_wallet(coins: Vec<Coin>) -> Wallet {
        Wallet {
            name: "wallet".to_string(), mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(), state_entity_endpoint: "http://127.0.0.1:1".to_string(), chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:1".to_string(), network: "regtest".to_string(), blockheight: 0,
            activities: Vec::new(), coins,
            settings: Settings { network: "regtest".to_string(), block_explorerURL: None, torProxyHost: None, torProxyPort: None, torProxyControlPassword: None, torProxyControlPort: None, statechainEntityApi: "http://127.0.0.1:1".to_string(), torStatechainEntityApi: None, chainBackend: "core".to_string(), chainUrl: "http://127.0.0.1:1".to_string(), chainType: None, notifications: false, tutorials: false },
        }
    }

    #[rustfmt::skip]
    fn fixture() -> Fixture {
        let mut msg: Bip448TransferMsg = serde_json::from_str(MSG).unwrap();
        for entry in &mut msg.state_history { entry.owner_public_key = PublicKey::from_str(&entry.owner_public_key).unwrap().x_only_public_key().0.to_string(); }
        let coin = test_coin(5, 8);
        let aggregate = PublicKey::from_str(&msg.aggregate_pubkey).unwrap();
        let secp = Secp256k1::new();
        let funding_outpoint = OutPoint { txid: Txid::from_str(&msg.funding_outpoint.txid).unwrap(), vout: msg.funding_outpoint.vout };
        let funding_output = TxOut { value: msg.amount_sats, script_pubkey: script::output_script_pubkey(&script::funding_spend_info(&secp, aggregate.x_only_public_key().0).unwrap()) };
        let facts = Bip448TransferChainFacts { expected_network: Network::Regtest, median_time_past: 1_900_000_000, funding_outpoint, funding_output, tx0_confirmed: true, tx0_unspent: true, receiver_user_pubkey: PublicKey::from_str(&coin.user_pubkey).unwrap() };
        let mailbox = msg.encrypt(&PublicKey::from_str(&coin.auth_pubkey).unwrap()).unwrap();
        Fixture { msg, mailbox, facts, coin }
    }

    #[test]
    fn mirrored_t2_satisfies_continuity_equation() {
        let secp = Secp256k1::new();
        let msg: Bip448TransferMsg = serde_json::from_str(MSG).unwrap();
        let coin = test_coin(5, 8);
        let request = create_receiver_request(&msg, &coin).unwrap();
        let t2_bytes: [u8; 32] = hex::decode(request.t2).unwrap().try_into().unwrap();
        let t2_g = SecretKey::from_secret_bytes(t2_bytes)
            .unwrap()
            .public_key(&secp);
        let t1_g = SecretKey::from_secret_bytes(msg.t1)
            .unwrap()
            .public_key(&secp);
        let receiver = PublicKey::from_str(&coin.user_pubkey).unwrap();

        assert_eq!(t2_g, t1_g.combine(&receiver.negate()).unwrap());
    }

    #[rustfmt::skip]
    async fn pool() -> sqlx::Pool<sqlx::Sqlite> {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[rustfmt::skip]
    fn test_client_config(endpoint: String, pool: sqlx::Pool<sqlx::Sqlite>) -> ClientConfig {
        ClientConfig { statechain_entity: endpoint.clone(), chain_backend: "core".to_string(), chain_client: ChainClient::new(CoreRpcConfig { url: endpoint.clone(), auth: CoreRpcAuth::None }).unwrap(), core_rpc_url: Some(endpoint), core_rpc_auth: Some("none".to_string()), core_rpc_user: None, core_rpc_password: None, core_rpc_cookie_file: None, network: Network::Regtest, fee_rate_tolerance: 0.05, confirmation_target: 1, pool, tor_proxy: None, max_fee_rate: 100.0 }
    }

    #[derive(Default)]
    #[rustfmt::skip]
    struct Transport { server: String, crash_before: bool, lose_response: bool, crash_after: bool, verifies: u32, unlocks: u32, posts: u32 }
    #[rustfmt::skip]
    fn transport() -> Rc<RefCell<Transport>> {
        let info: StatechainInfoResponsePayload = serde_json::from_str(INFO).unwrap();
        Rc::new(RefCell::new(Transport { server: info.enclave_public_key, ..Default::default() }))
    }

    #[rustfmt::skip]
    async fn attempt(
        fixture: &Fixture, pool: &sqlx::Pool<sqlx::Sqlite>, coin: &mut Coin,
        activities: &mut Vec<Activity>, transport: Rc<RefCell<Transport>>,
    ) -> Result<Bip448ReceiveOutcome> {
        let msg = decrypt_transfer_message(&fixture.mailbox, &coin.auth_privkey)?;
        let mut info: StatechainInfoResponsePayload = serde_json::from_str(INFO)?;
        info.enclave_public_key = transport.borrow().server.clone();
        if info.enclave_public_key != serde_json::from_str::<StatechainInfoResponsePayload>(INFO)?.enclave_public_key { info.statechain_info.clear(); }
        let current_server = PublicKey::from_str(&info.enclave_public_key)?;
        let expected = expected_server_pubkey(&msg, &fixture.facts.receiver_user_pubkey)?;
        transport.borrow_mut().verifies += 1;
        let verified = match Bip448VerifiedTransfer::new(msg, &info, fixture.facts.clone()) {
            Ok(verified) => verified,
            Err(_) if current_server == expected => return Err(anyhow!(ALREADY_UPDATED_ERROR)),
            Err(error) => return Err(error),
        };
        let request = create_receiver_request(&verified.msg, coin)?;
        assert_eq!(request.t2, hex::encode([4u8; 32]));
        let digest = sha256::Hash::hash(request.t2.as_bytes()).to_byte_array();
        schnorr::verify(&schnorr::Signature::from_str(&request.auth_sig)?, &digest, &PublicKey::from_str(&coin.auth_pubkey)?.x_only_public_key().0)?;
        assert!(!mercurylib::transfer::receiver::sign_message(&verified.msg.statechain_id, coin)?.is_empty());
        let checkpoint_transport = Rc::clone(&transport);
        let unlock_transport = Rc::clone(&transport);
        let update_transport = Rc::clone(&transport);
        let persist_transport = Rc::clone(&transport);
        let expected_text = expected.to_string();
        execute_receiver_attempt(
            || std::future::ready(Ok(verified)),
            move || if std::mem::take(&mut checkpoint_transport.borrow_mut().crash_before) { Err(anyhow!("crash before transfer/receiver")) } else { Ok(()) },
            move || { unlock_transport.borrow_mut().unlocks += 1; std::future::ready(Ok(())) },
            move || {
                let mut transport = update_transport.borrow_mut();
                transport.posts += 1;
                transport.server = expected_text.clone();
                let result = if std::mem::take(&mut transport.lose_response) { Err(ReceiverPostError::LostResponse(anyhow!("lost response"))) } else { Ok(super::super::TransferReceiveRequestResult { is_batch_locked: false, server_pubkey: Some(expected_text.clone()) }) };
                std::future::ready(result)
            },
            move |verified, response| {
                let crash = std::mem::take(&mut persist_transport.borrow_mut().crash_after);
                async move { if crash { Err(anyhow!("crash after key update")) } else { persist_accepted_transfer(pool, "wallet", coin, activities, verified, response).await } }
            },
        ).await
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn full_happy_path_verifies_requests_persists_and_updates_coin() {
        let fixture = fixture(); let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        let outcome = attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.unwrap();
        let result = match outcome { Bip448ReceiveOutcome::Processed(result) => result, _ => panic!("happy path did not process the transfer") };
        let record = crate::sqlite_manager::get_bip448_statechain(&pool, "wallet", "statechain").await.unwrap();
        let history = crate::sqlite_manager::get_bip448_state_history(&pool, "wallet", "statechain").await.unwrap();
        assert_eq!(result, "statechain");
        assert_eq!(record.latest_state_number, 2);
        assert_eq!(history, fixture.msg.state_history);
        assert_eq!(coin.statechain_protocol.as_deref(), Some("bip448"));
        assert_eq!(coin.utxo_txid.as_deref(), Some("4242424242424242424242424242424242424242424242424242424242424242"));
        assert_eq!(coin.amount, Some(100_000));
        assert_eq!(coin.status, CoinStatus::CONFIRMED);
        assert_eq!(activities.len(), 1);
        assert_eq!((transport.borrow().verifies, transport.borrow().unlocks, transport.borrow().posts), (1, 1, 1));
    }

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
            super::super::TransferReceiveRequestResult { is_batch_locked: true, server_pubkey: None },
        ).await.unwrap();

        assert!(matches!(outcome, Bip448ReceiveOutcome::BatchLocked));
        assert_eq!(serde_json::to_string(&coin).unwrap(), coin_before);
        assert!(activities.is_empty());
        assert!(crate::sqlite_manager::get_bip448_statechain_optional(&pool, "wallet", "statechain").await.unwrap().is_none());
        assert!(crate::sqlite_manager::get_bip448_state_history(&pool, "wallet", "statechain").await.unwrap().is_empty());
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn completed_receipt_is_recognized_as_an_idempotent_replay() {
        let fixture = fixture(); let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.unwrap();
        crate::sqlite_manager::insert_wallet(&pool, &test_wallet(vec![coin.clone()])).await.unwrap();
        let current_server = PublicKey::from_str(coin.server_pubkey.as_deref().unwrap()).unwrap();
        let mut replay = fixture.msg.clone();
        replay.funding_outpoint.txid.make_ascii_uppercase();
        let outcome = resolve_already_updated(&pool, "wallet", &coin, &replay, &current_server).await.unwrap();
        assert!(matches!(outcome, Bip448ReceiveOutcome::AlreadyProcessed));
        assert_eq!(activities.len(), 1);
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn accepted_transfer_canonicalizes_an_uppercase_funding_txid() {
        let mut fixture = fixture();
        fixture.msg.funding_outpoint.txid.make_ascii_uppercase();
        fixture.mailbox = fixture.msg.encrypt(&PublicKey::from_str(&fixture.coin.auth_pubkey).unwrap()).unwrap();
        let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        attempt(&fixture, &pool, &mut coin, &mut activities, transport).await.unwrap();
        let record = crate::sqlite_manager::get_bip448_statechain(&pool, "wallet", "statechain").await.unwrap();
        assert_eq!(record.funding_outpoint.txid, "42".repeat(32));
        assert_eq!(coin.utxo_txid.as_deref(), Some("4242424242424242424242424242424242424242424242424242424242424242"));
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn record_without_persisted_accepted_coin_still_requires_manual_completion() {
        let fixture = fixture(); let original_coin = fixture.coin.clone(); let mut accepted_coin = original_coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        attempt(&fixture, &pool, &mut accepted_coin, &mut activities, Rc::clone(&transport)).await.unwrap();
        crate::sqlite_manager::insert_wallet(&pool, &test_wallet(vec![original_coin.clone()])).await.unwrap();
        let current_server = PublicKey::from_str(accepted_coin.server_pubkey.as_deref().unwrap()).unwrap();
        let result = resolve_already_updated(&pool, "wallet", &original_coin, &fixture.msg, &current_server).await;
        let error = match result { Err(error) => error, Ok(_) => panic!("incomplete receipt was accepted as a replay") };
        assert_eq!(error.to_string(), ALREADY_UPDATED_ERROR);
        assert!(crate::sqlite_manager::get_bip448_statechain_optional(&pool, "wallet", "statechain").await.unwrap().is_some());
        assert_eq!(crate::sqlite_manager::get_wallet(&pool, "wallet").await.unwrap().coins[0].status, CoinStatus::INITIALISED);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rustfmt::skip]
    async fn completed_receipt_replays_through_execute_without_duplicate_wallet_state() {
        let fixture = fixture(); let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.unwrap();
        let mut wallet = test_wallet(vec![coin.clone()]); wallet.activities = activities;
        crate::sqlite_manager::insert_wallet(&pool, &wallet).await.unwrap();
        let mut statechain_info: StatechainInfoResponsePayload = serde_json::from_str(INFO).unwrap();
        statechain_info.enclave_public_key = coin.server_pubkey.clone().unwrap();
        let (endpoint, server) = mock_execute_endpoints(vec![fixture.mailbox], Some(serde_json::to_string(&statechain_info).unwrap())).await;
        let config = test_client_config(endpoint, pool.clone());
        let result = super::super::execute(&config, "wallet").await;
        server.abort();
        let result = result.unwrap();
        assert!(result.received_statechain_ids.is_empty());
        assert!(!result.is_there_batch_locked);
        let wallet = crate::sqlite_manager::get_wallet(&pool, "wallet").await.unwrap();
        assert_eq!(wallet.coins.len(), 1);
        assert_eq!(wallet.activities.len(), 1);
        assert_eq!(wallet.coins[0].statechain_id.as_deref(), Some("statechain"));
        assert_eq!(wallet.coins[0].status, CoinStatus::CONFIRMED);
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn crash_before_receiver_post_rereads_mailbox_and_reverifies() {
        let fixture = fixture(); let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        transport.borrow_mut().crash_before = true;
        assert!(attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.is_err());
        attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.unwrap();
        assert_eq!((transport.borrow().verifies, transport.borrow().posts), (2, 1));
        assert!(crate::sqlite_manager::get_bip448_statechain_optional(&pool, "wallet", "statechain").await.unwrap().is_some());
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn lost_response_reposts_without_reverification() {
        let fixture = fixture(); let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        transport.borrow_mut().lose_response = true;
        attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.unwrap();
        assert_eq!((transport.borrow().verifies, transport.borrow().posts), (1, 2));
        assert!(crate::sqlite_manager::get_bip448_statechain_optional(&pool, "wallet", "statechain").await.unwrap().is_some());
    }

    #[tokio::test]
    #[rustfmt::skip]
    async fn crash_after_key_update_detects_p_minus_o2_and_persists_nothing() {
        let fixture = fixture(); let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        transport.borrow_mut().crash_after = true;
        assert!(attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.is_err());
        let error = match attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await { Err(error) => error, Ok(_) => panic!("rerun unexpectedly succeeded") };
        assert_eq!(error.to_string(), ALREADY_UPDATED_ERROR);
        assert_eq!(transport.borrow().verifies, 2);
        assert!(crate::sqlite_manager::get_bip448_statechain_optional(&pool, "wallet", "statechain").await.unwrap().is_none());
    }

    #[test]
    #[rustfmt::skip]
    fn version_one_plaintext_missing_transfer_signature_is_rejected_without_panic() {
        let coin = test_coin(5, 8);
        let result = std::panic::catch_unwind(|| decrypt_transfer_message(MISSING_SIGNATURE, &coin.auth_privkey));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }

    #[rustfmt::skip]
    async fn mock_execute_endpoints(mailbox: Vec<String>, statechain_info: Option<String>) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mailbox = serde_json::json!({"list_enc_transfer_msg": mailbox}).to_string();
            let mut rpc_calls = 0;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = [0u8; 8192];
                let size = socket.read(&mut bytes).await.unwrap();
                let request = String::from_utf8_lossy(&bytes[..size]);
                let body = if request.starts_with("GET /transfer/get_msg_addr/") { mailbox.clone() } else {
                    if request.starts_with("GET /info/statechain/") && statechain_info.is_some() { statechain_info.clone().unwrap() } else {
                    rpc_calls += 1;
                    if rpc_calls % 2 == 1 { r#"{"result":{"feerate":0.00001},"error":null,"id":"mercury-client"}"#.to_string() }
                    else { r#"{"result":42,"error":null,"id":"mercury-client"}"#.to_string() }
                    }
                };
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (endpoint, task)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rustfmt::skip]
    async fn bip448_error_does_not_append_reused_address_coin_or_abort_receive_loop() {
        use crate::sqlite_manager::insert_wallet;
        let mut receiver = test_coin(9, 10); receiver.status = CoinStatus::CONFIRMED;
        let (endpoint, server) = mock_execute_endpoints(vec!["invalid transfer message".to_string()], None).await;
        let pool = pool().await;
        let config = test_client_config(endpoint, pool.clone());
        let wallet = test_wallet(vec![receiver]);
        insert_wallet(&pool, &wallet).await.unwrap();
        let result = super::super::execute(&config, "wallet").await;
        server.abort();
        assert!(result.is_ok());
        let wallet = crate::sqlite_manager::get_wallet(&pool, "wallet").await.unwrap();
        assert_eq!(wallet.coins.len(), 1);
        assert_eq!(wallet.coins[0].status, CoinStatus::CONFIRMED);
    }
}
