use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin::{OutPoint, Txid};
use chrono::Utc;
use mercurylib::{
    bip448_statechain::{
        deposit::is_bip448_coin,
        signing_api::{Bip448PartialSignatureRequestPayload, Bip448SignFirstRequestPayload},
    },
    transaction::{
        create_and_commit_nonces, create_signature, get_bip448_withdrawal_partial_sig_request,
        new_backup_transaction,
    },
    wallet::{Activity, CoinStatus},
};
use secp256k1::{rand, SecretKey};

use crate::{
    client_config::ClientConfig,
    deposit::{bip448_sign_first, bip448_sign_second},
    sqlite_manager::{
        get_bip448_pending_transfer_signing, get_bip448_statechain, get_wallet, update_wallet,
    },
    utils::info_config,
};

const UNEXPECTED_COMPLETION_RESPONSE: &str =
    "BIP448 withdraw completion returned an unexpected response";

fn require_statechain_deleted(body: &str) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| anyhow!("{UNEXPECTED_COMPLETION_RESPONSE}"))?;
    if value.get("message").and_then(serde_json::Value::as_str) != Some("Statechain deleted.") {
        return Err(anyhow!("{UNEXPECTED_COMPLETION_RESPONSE}"));
    }
    Ok(())
}

pub async fn execute(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    to_address: &str,
    fee_rate: Option<f64>,
) -> Result<()> {
    let mut wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let coin_index = wallet
        .coins
        .iter()
        .position(|coin| coin.statechain_id.as_deref() == Some(statechain_id))
        .ok_or_else(|| anyhow!("No coins associated with this statechain ID were found"))?;
    if !is_bip448_coin(&wallet.coins[coin_index]) {
        return Err(anyhow!(
            "statechain {statechain_id} is not a BIP448 coin; BIP448 withdrawal requires an accepted BIP448 coin"
        ));
    }
    if get_bip448_pending_transfer_signing(&client_config.pool, wallet_name, statechain_id)
        .await?
        .is_some()
    {
        return Err(anyhow!(
            "cancel or complete the in-flight transfer before withdrawing"
        ));
    }
    if !mercurylib::validate_address(to_address, &wallet.network)? {
        return Err(anyhow!("Invalid address"));
    }

    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let coin = &mut wallet.coins[coin_index];
    if coin.status != CoinStatus::CONFIRMED && coin.status != CoinStatus::IN_TRANSFER {
        return Err(anyhow!(
            "Coin status must be CONFIRMED or IN_TRANSFER to withdraw it. The current status is {}",
            coin.status
        ));
    }
    if coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
        || record.network != wallet.network
        || record.amount_sats != record.funding_outpoint.value_sats
        || coin.amount.map(u64::from) != Some(record.amount_sats)
    {
        return Err(anyhow!(
            "BIP448 coin does not match its accepted funding record"
        ));
    }

    let server_info = info_config(client_config).await?;
    let fee_rate = fee_rate.unwrap_or(
        server_info
            .fee_rate_sats_per_byte
            .min(client_config.max_fee_rate),
    );
    let nonce = create_and_commit_nonces(coin)?;
    coin.secret_nonce = Some(nonce.secret_nonce);
    coin.public_nonce = Some(nonce.public_nonce);
    coin.blinding_factor = Some(nonce.blinding_factor);
    let signing_id = hex::encode(SecretKey::new(&mut rand::rng()).to_secret_bytes());
    let signed_statechain_id = coin
        .signed_statechain_id
        .clone()
        .ok_or_else(|| anyhow!("BIP448 withdraw coin missing signed_statechain_id"))?;
    let server_pubnonce = bip448_sign_first(
        client_config,
        &Bip448SignFirstRequestPayload {
            statechain_id: statechain_id.to_string(),
            signed_statechain_id: signed_statechain_id.clone(),
            signing_id: signing_id.clone(),
        },
    )
    .await?;
    coin.server_public_nonce = Some(server_pubnonce);

    let funding_outpoint = OutPoint {
        txid: Txid::from_str(&record.funding_outpoint.txid)?,
        vout: record.funding_outpoint.vout,
    };
    let msg1 = get_bip448_withdrawal_partial_sig_request(
        coin,
        funding_outpoint,
        record.funding_outpoint.value_sats,
        client_config.chain_client.tip_height()?,
        fee_rate,
        to_address,
        client_config.network,
    )?;
    let request = &msg1.partial_signature_request_payload;
    let server_partial = bip448_sign_second(
        client_config,
        &Bip448PartialSignatureRequestPayload {
            statechain_id: request.statechain_id.clone(),
            signed_statechain_id: request.signed_statechain_id.clone(),
            signing_id,
            negate_seckey: request.negate_seckey,
            session: request.session.clone(),
            server_pub_nonce: request.server_pub_nonce.clone(),
        },
    )
    .await?;
    // This signature permanently commits the coin to exit: it advances the shared count,
    // making every later transfer ineligible. Retries re-sign; there is no count compensation.
    let signature = create_signature(
        msg1.msg,
        msg1.client_partial_sig,
        hex::encode(server_partial.serialize()),
        msg1.encoded_session,
        msg1.output_pubkey,
    )?;
    let signed_tx = new_backup_transaction(msg1.encoded_unsigned_tx, signature)?;
    #[cfg(feature = "test-hooks")]
    if std::env::var("ML_BIP448_WITHDRAW_STOP_AFTER_SIGNATURE").as_deref() == Ok("1") {
        return Err(anyhow!("BIP448 withdraw stopped after signature for test"));
    }

    let txid = client_config
        .chain_client
        .broadcast_tx(&hex::decode(signed_tx)?)?;
    coin.tx_withdraw = Some(txid.to_string());
    coin.withdrawal_address = Some(to_address.to_string());
    coin.status = CoinStatus::WITHDRAWING;
    wallet.activities.push(Activity {
        utxo: txid.to_string(),
        amount: coin.amount.ok_or_else(|| anyhow!("coin.amount is None"))?,
        action: "Withdraw".to_string(),
        date: Utc::now().to_rfc3339(),
    });
    update_wallet(&client_config.pool, &wallet).await?;
    let completion =
        crate::utils::complete_withdraw(statechain_id, &signed_statechain_id, client_config).await?;
    // Diagnostic only: the transaction is broadcast and the statechain is already deleted;
    // confirmation still promotes the persisted coin from WITHDRAWING to WITHDRAWN.
    require_statechain_deleted(&completion)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use mercurylib::wallet::{Settings, Wallet};
    use sqlx::sqlite::SqlitePoolOptions;

    use crate::{
        chain::{ChainClient, CoreRpcAuth, CoreRpcConfig},
        sqlite_manager::{insert_wallet, update_wallet},
    };

    fn wallet(protocol: Option<&str>) -> Wallet {
        let mut wallet = Wallet {
            name: "wallet".into(), mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(), version: "0.1.0".into(),
            state_entity_endpoint: "http://127.0.0.1:1".into(), chain_backend: "core".into(), chain_endpoint: "http://127.0.0.1:1".into(), network: "regtest".into(),
            blockheight: 0, initlock: 1_000, interval: 10, activities: Vec::new(), coins: Vec::new(),
            settings: Settings { network: "regtest".into(), block_explorerURL: None, torProxyHost: None, torProxyPort: None, torProxyControlPassword: None, torProxyControlPort: None, statechainEntityApi: "http://127.0.0.1:1".into(), torStatechainEntityApi: None, chainBackend: "core".into(), chainUrl: "http://127.0.0.1:1".into(), chainType: None, notifications: false, tutorials: false },
        };
        let mut coin = wallet.get_new_coin().unwrap();
        coin.statechain_id = Some("statechain".into());
        coin.statechain_protocol = protocol.map(str::to_owned);
        coin.status = CoinStatus::CONFIRMED;
        wallet.coins.push(coin);
        wallet
    }

    async fn config() -> Result<ClientConfig> {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let url = "http://127.0.0.1:1";
        Ok(ClientConfig { statechain_entity: url.into(), chain_backend: "core".into(), chain_client: ChainClient::new(CoreRpcConfig { url: url.into(), auth: CoreRpcAuth::None })?, core_rpc_url: Some(url.into()), core_rpc_auth: Some("none".into()), core_rpc_user: None, core_rpc_password: None, core_rpc_cookie_file: None, network: Network::Regtest, fee_rate_tolerance: 0.0, confirmation_target: 1, pool, tor_proxy: None, max_fee_rate: 10.0 })
    }

    #[test]
    fn require_statechain_deleted_accepts_exact_envelope() {
        assert!(require_statechain_deleted(r#"{"message":"Statechain deleted."}"#).is_ok());
    }

    #[test]
    fn require_statechain_deleted_rejects_plain_text_counterexample() {
        let error = require_statechain_deleted("Statechain deleted.").unwrap_err();
        assert_eq!(error.to_string(), UNEXPECTED_COMPLETION_RESPONSE);
    }

    #[test]
    fn require_statechain_deleted_rejects_json_without_string_message() {
        let error = require_statechain_deleted(r#"{"status":"deleted"}"#).unwrap_err();
        assert_eq!(error.to_string(), UNEXPECTED_COMPLETION_RESPONSE);
    }

    #[test]
    fn require_statechain_deleted_rejects_different_message() {
        let error = require_statechain_deleted(r#"{"message":"Statechain retained."}"#).unwrap_err();
        assert_eq!(error.to_string(), UNEXPECTED_COMPLETION_RESPONSE);
    }

    #[tokio::test]
    async fn protocol_and_pending_transfer_guards_precede_signing() -> Result<()> {
        let config = config().await?;
        let mut wallet = wallet(None);
        insert_wallet(&config.pool, &wallet).await?;
        let error = execute(&config, "wallet", "statechain", "unused", None).await.unwrap_err();
        assert_eq!(error.to_string(), "statechain statechain is not a BIP448 coin; BIP448 withdrawal requires an accepted BIP448 coin");

        wallet.coins[0].statechain_protocol = Some("bip448".into());
        update_wallet(&config.pool, &wallet).await?;

        sqlx::query("INSERT INTO bip448_pending_transfer_signings (wallet_name,statechain_id,funding_txid,funding_vout,funding_value_sats,update_template_hash,settlement_template_hash,state_locktime,signing_id,client_secret_nonce,client_public_nonce,blinding_factor) VALUES ('wallet','statechain','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',0,50000,'aa','bb',700000000,'cc','dd','ee','ff')").execute(&config.pool).await?;
        let error = execute(&config, "wallet", "statechain", "unused", None).await.unwrap_err();
        assert_eq!(error.to_string(), "cancel or complete the in-flight transfer before withdrawing");
        Ok(())
    }
}
