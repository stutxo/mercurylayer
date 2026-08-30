use std::{str::FromStr, time::Duration};

use anyhow::{anyhow, Result};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use mercurylib::{
    bip448_statechain::{
        deposit::is_bip448_coin,
        signing_api::Bip448SignFirstRequestPayload,
        storage::Bip448StatechainRecord,
        withdraw::{
            create_bip448_keypath_nonces, prepare_bip448_keypath_spend,
            sample_bip448_keypath_spend_lock_time, Bip448KeypathSpendSource,
        },
    },
    wallet::{Coin, Wallet},
};
use secp256k1::{rand, PublicKey, SecretKey};

use crate::{
    bip448_funding::{
        Bip448BroadcastStatus, Bip448CloseGate, Bip448CompletionStatus, Bip448WithdrawalAttempt,
        Bip448WithdrawalAttemptKind, Bip448WithdrawalPhase,
    },
    bip448_owner::{get_bip448_statechain_presence, Bip448StatechainPresence},
    client_config::ClientConfig,
    coin_status::sync_bip448_funding_bindings_from_height_zero,
    deposit::bip448_signature_count,
    sqlite_manager::{
        begin_bip448_mutation_guard, classify_bip448_close_gate, get_bip448_funding_binding,
        get_bip448_pending_transfer_signing, get_bip448_statechain, get_bip448_withdrawal_attempt,
        get_wallet, has_bip448_transfer_msg_for_statechain, list_bip448_transfer_intents,
        list_bip448_transfer_msg_raw_rows, persist_bip448_canonical_withdrawal_wallet,
        reconcile_bip448_accepted_local_outgoing_messages,
        transition_bip448_withdrawal_completion_status, with_bip448_canonical_completion_fence,
    },
    utils::{complete_withdraw, estimate_fee_rate_sats_per_byte},
};

use super::{
    driver::{
        bip448_process_checkpoint, broadcast_signed_attempt, drive_withdrawal_attempt,
        reconcile_and_validate_frozen_snapshot, refresh_withdrawal_attempt,
    },
    policy::{
        ensure_withdraw_status, prove_attempt_owner, require_exact_confirmed_source,
        require_statechain_deleted, validate_attempt_identity, validate_attempt_invocation,
    },
};

const BIP448_CANONICAL_COMPLETION_TIMEOUT: Duration = Duration::from_secs(20);

fn require_canonical_coin_record_identity(
    wallet: &Wallet,
    coin: &Coin,
    record: &Bip448StatechainRecord,
) -> Result<()> {
    if record.wallet_name != wallet.name
        || record.network != wallet.network
        || record.amount_sats != record.funding_outpoint.value_sats
        || coin.statechain_id.as_deref() != Some(record.statechain_id.as_str())
        || coin.aggregated_pubkey.as_deref() != Some(record.aggregate_pubkey.as_str())
        || coin.utxo_txid.as_deref() != Some(record.funding_outpoint.txid.as_str())
        || coin.utxo_vout != Some(record.funding_outpoint.vout)
        || coin.amount.map(u64::from) != Some(record.amount_sats)
    {
        return Err(anyhow!(
            "BIP448 canonical Coin does not match its accepted funding record"
        ));
    }
    Ok(())
}

fn require_ready_close_gate(gate: Bip448CloseGate) -> Result<String> {
    match gate {
        Bip448CloseGate::Ready {
            closing_bindings_json,
            ..
        } => Ok(closing_bindings_json),
        Bip448CloseGate::Blocked { reasons } => Err(anyhow!(
            "BIP448 canonical withdrawal is blocked by unresolved close facts: {reasons:?}"
        )),
    }
}

async fn refresh_accepted_canonical_attempt(
    client_config: &ClientConfig,
    to_address: &str,
    fee_rate: Option<f64>,
    expected: &Bip448WithdrawalAttempt,
) -> Result<Bip448WithdrawalAttempt> {
    let (_, _, _, live, _, _) =
        refresh_withdrawal_attempt(client_config, to_address, fee_rate, expected).await?;
    if live.attempt_kind != Bip448WithdrawalAttemptKind::Canonical
        || live.binding_index != 0
        || live.phase != Bip448WithdrawalPhase::Signed
    {
        return Err(anyhow!(
            "canonical BIP448 close journal is not durably Signed"
        ));
    }
    let live = broadcast_signed_attempt(client_config, live).await?;
    if !matches!(
        live.broadcast_status,
        Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
    ) {
        return Err(anyhow!(
            "canonical BIP448 close bytes are {}, not accepted",
            live.broadcast_status
        ));
    }
    Ok(live)
}

async fn mark_canonical_closed(
    client_config: &ClientConfig,
    attempt: &Bip448WithdrawalAttempt,
) -> Result<()> {
    transition_bip448_withdrawal_completion_status(
        &client_config.pool,
        &attempt.wallet_name,
        &attempt.statechain_id,
        &attempt.signing_id,
        Bip448CompletionStatus::CloseArmed,
        Bip448CompletionStatus::Closed,
    )
    .await?;
    Ok(())
}

async fn reconcile_canonical_completion_result(
    client_config: &ClientConfig,
    attempt: &Bip448WithdrawalAttempt,
    completion: Result<String>,
) -> Result<()> {
    let completion_error = match completion {
        Ok(body) => {
            bip448_process_checkpoint("canonical_completion_returned");
            match require_statechain_deleted(&body) {
                Ok(()) => return mark_canonical_closed(client_config, attempt).await,
                Err(error) => error,
            }
        }
        Err(error) => error,
    };
    match get_bip448_statechain_presence(client_config, &attempt.statechain_id).await {
        Ok(Bip448StatechainPresence::Missing) => {
            mark_canonical_closed(client_config, attempt).await
        }
        Ok(Bip448StatechainPresence::Present(_)) => Err(completion_error.context(
            "BIP448 canonical completion is indeterminate while Mercury state remains present",
        )),
        Err(presence_error) => Err(completion_error.context(format!(
            "BIP448 canonical completion reconciliation was indeterminate: {presence_error}"
        ))),
    }
}

async fn complete_canonical_under_mutation_fence(
    client_config: &ClientConfig,
    expected: &Bip448WithdrawalAttempt,
) -> Result<(Bip448WithdrawalAttempt, Result<String>)> {
    // This short request is the irreversible boundary. Keep BEGIN IMMEDIATE
    // alive from the final frozen-snapshot reload until the response returns,
    // so no passive scan or other local mutation can commit in between.
    with_bip448_canonical_completion_fence(
        &client_config.pool,
        &expected.wallet_name,
        &expected.statechain_id,
        &expected.signing_id,
        BIP448_CANONICAL_COMPLETION_TIMEOUT,
        |canonical| async move {
            complete_withdraw(
                &canonical.statechain_id,
                &canonical.signed_statechain_id,
                client_config,
            )
            .await
        },
    )
    .await
}

async fn drive_canonical_attempt(
    client_config: &ClientConfig,
    to_address: &str,
    fee_rate: Option<f64>,
    attempt: Bip448WithdrawalAttempt,
) -> Result<()> {
    if attempt.attempt_kind != Bip448WithdrawalAttemptKind::Canonical || attempt.binding_index != 0
    {
        return Err(anyhow!("duplicate BIP448 attempt reached canonical driver"));
    }
    let signed = drive_withdrawal_attempt(client_config, to_address, fee_rate, attempt).await?;
    if !matches!(
        signed.broadcast_status,
        Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
    ) {
        return Err(anyhow!(
            "canonical BIP448 transaction is {}, so completion remains blocked",
            signed.broadcast_status
        ));
    }
    persist_bip448_canonical_withdrawal_wallet(
        &client_config.pool,
        &signed.wallet_name,
        &signed.statechain_id,
        &signed.signing_id,
    )
    .await?;
    bip448_process_checkpoint("canonical_wallet_persisted");

    let mut canonical =
        refresh_accepted_canonical_attempt(client_config, to_address, fee_rate, &signed).await?;
    if canonical.completion_status == Bip448CompletionStatus::Closed {
        return Ok(());
    }
    if canonical.completion_status == Bip448CompletionStatus::Open {
        reconcile_and_validate_frozen_snapshot(client_config, &canonical).await?;
        canonical = transition_bip448_withdrawal_completion_status(
            &client_config.pool,
            &canonical.wallet_name,
            &canonical.statechain_id,
            &canonical.signing_id,
            Bip448CompletionStatus::Open,
            Bip448CompletionStatus::CloseArmed,
        )
        .await?;
        bip448_process_checkpoint("canonical_close_armed");
    }
    if canonical.completion_status != Bip448CompletionStatus::CloseArmed {
        return Err(anyhow!("canonical BIP448 completion journal is invalid"));
    }

    // Journal identity and exact broadcast acceptance are established before
    // consulting Mercury. A definitive row-absent 404 is then terminal proof
    // of a previously completed request and must never return to signing.
    match get_bip448_statechain_presence(client_config, &canonical.statechain_id).await? {
        Bip448StatechainPresence::Missing => {
            return mark_canonical_closed(client_config, &canonical).await;
        }
        Bip448StatechainPresence::Present(_) => {}
    }

    // Refresh all exact chain facts after /info and immediately before the one
    // completion request permitted in this invocation.
    canonical =
        refresh_accepted_canonical_attempt(client_config, to_address, fee_rate, &canonical).await?;
    reconcile_and_validate_frozen_snapshot(client_config, &canonical).await?;
    let (canonical, completion) =
        complete_canonical_under_mutation_fence(client_config, &canonical).await?;
    reconcile_canonical_completion_result(client_config, &canonical, completion).await
}

pub async fn execute(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    to_address: &str,
    fee_rate: Option<f64>,
) -> Result<()> {
    // Canonical replay is journal-first. In particular, Signed/CloseArmed/Closed
    // rows remain actionable after valid Mercury deletion and never regenerate.
    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let has_statechain_coin = wallet
        .coins
        .iter()
        .any(|coin| coin.statechain_id.as_deref() == Some(statechain_id));
    if !has_statechain_coin {
        return Err(anyhow!(
            "No coins associated with this statechain ID were found"
        ));
    }
    if !wallet
        .coins
        .iter()
        .any(|coin| coin.statechain_id.as_deref() == Some(statechain_id) && is_bip448_coin(coin))
    {
        return Err(anyhow!(
            "statechain {statechain_id} is not a BIP448 coin; BIP448 withdrawal requires an accepted BIP448 coin"
        ));
    }
    if let Some(attempt) =
        get_bip448_withdrawal_attempt(&client_config.pool, wallet_name, statechain_id, 0).await?
    {
        let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
        let binding =
            get_bip448_funding_binding(&client_config.pool, wallet_name, statechain_id, 0)
                .await?
                .ok_or_else(|| anyhow!("accepted BIP448 canonical funding binding is missing"))?;
        validate_attempt_invocation(&attempt, to_address, fee_rate)?;
        validate_attempt_identity(client_config, &wallet, &record, &binding, &attempt).await?;
        return drive_canonical_attempt(client_config, to_address, fee_rate, attempt).await;
    }

    // No-row preflight deliberately precedes every signing, wallet/activity,
    // broadcast, and completion side effect.
    let local_candidates = wallet
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(statechain_id) && is_bip448_coin(coin))
        .collect::<Vec<_>>();
    if let [only_candidate] = local_candidates.as_slice() {
        ensure_withdraw_status(&only_candidate.status)?;
    }

    let transfer_intents =
        list_bip448_transfer_intents(&client_config.pool, wallet_name, statechain_id).await?;
    if !transfer_intents.is_empty() {
        let gate =
            classify_bip448_close_gate(&client_config.pool, wallet_name, statechain_id).await?;
        return Err(anyhow!(
            "BIP448 canonical withdrawal is blocked by transfer intent state: {gate:?}"
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
    // Load before synchronization, but accepted-prefix cleanup is permitted
    // only after that synchronization succeeds.
    let _outgoing_messages =
        list_bip448_transfer_msg_raw_rows(&client_config.pool, wallet_name, statechain_id).await?;

    let sync = sync_bip448_funding_bindings_from_height_zero(client_config, wallet_name).await?;
    reconcile_bip448_accepted_local_outgoing_messages(
        &client_config.pool,
        wallet_name,
        statechain_id,
    )
    .await?;
    if has_bip448_transfer_msg_for_statechain(&client_config.pool, wallet_name, statechain_id)
        .await?
    {
        return Err(anyhow!(
            "outgoing BIP448 transfer message blocks canonical withdrawal"
        ));
    }

    let wallet = get_wallet(&client_config.pool, wallet_name).await?;
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id).await?;
    let binding = get_bip448_funding_binding(&client_config.pool, wallet_name, statechain_id, 0)
        .await?
        .ok_or_else(|| anyhow!("accepted BIP448 canonical binding disappeared after rescan"))?;
    if let Some(attempt) =
        get_bip448_withdrawal_attempt(&client_config.pool, wallet_name, statechain_id, 0).await?
    {
        validate_attempt_invocation(&attempt, to_address, fee_rate)?;
        validate_attempt_identity(client_config, &wallet, &record, &binding, &attempt).await?;
        return drive_canonical_attempt(client_config, to_address, fee_rate, attempt).await;
    }
    let owner_coin = prove_attempt_owner(
        client_config,
        &wallet,
        &record,
        &binding,
        Bip448WithdrawalAttemptKind::Canonical,
        None,
    )
    .await?;
    ensure_withdraw_status(&owner_coin.status)?;
    require_canonical_coin_record_identity(&wallet, &owner_coin, &record)?;
    require_exact_confirmed_source(client_config, &binding)?;
    let closing_bindings_json = require_ready_close_gate(
        classify_bip448_close_gate(&client_config.pool, wallet_name, statechain_id).await?,
    )?;

    let fee_rate_sat_per_vbyte = match fee_rate {
        Some(fee_rate) => fee_rate,
        None => estimate_fee_rate_sats_per_byte(client_config)?.min(client_config.max_fee_rate),
    };
    let source = Bip448KeypathSpendSource {
        outpoint: OutPoint {
            txid: Txid::from_str(&binding.txid)?,
            vout: binding.vout,
        },
        value_sats: binding.value_sats,
        script_pubkey: ScriptBuf::from_bytes(hex::decode(&binding.script_pubkey)?),
    };
    let prepared = prepare_bip448_keypath_spend(
        &record.aggregate_pubkey,
        &source,
        to_address,
        client_config.network,
        fee_rate_sat_per_vbyte,
        sample_bip448_keypath_spend_lock_time(sync.tip_height),
    )?;
    let nonce = create_bip448_keypath_nonces(&owner_coin)?;
    let signing_id = hex::encode(SecretKey::new(&mut rand::rng()).to_secret_bytes());
    let signed_statechain_id = owner_coin
        .signed_statechain_id
        .clone()
        .ok_or_else(|| anyhow!("BIP448 canonical owner is missing signed_statechain_id"))?;
    let sign_first = Bip448SignFirstRequestPayload {
        statechain_id: statechain_id.to_owned(),
        signed_statechain_id: signed_statechain_id.clone(),
        signing_id: signing_id.clone(),
    };
    let owner_user_pubkey = PublicKey::from_str(&owner_coin.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();
    let attempt = Bip448WithdrawalAttempt {
        wallet_name: wallet_name.to_owned(),
        statechain_id: statechain_id.to_owned(),
        binding_index: 0,
        attempt_kind: Bip448WithdrawalAttemptKind::Canonical,
        owner_user_pubkey,
        owner_state_number: record.latest_state_number,
        source_txid: binding.txid.clone(),
        source_vout: binding.vout,
        source_value_sats: binding.value_sats,
        source_script_pubkey: binding.script_pubkey.clone(),
        destination_address: to_address.to_owned(),
        destination_script_pubkey: hex::encode(prepared.destination_script_pubkey.as_bytes()),
        fee_rate_sat_per_vbyte,
        fee_sats: prepared.fee_sats,
        lock_time: prepared.lock_time,
        unsigned_tx_hex: hex::encode(&prepared.unsigned_tx),
        signing_id,
        signed_statechain_id,
        sign_first_payload_json: serde_json::to_string(&sign_first)?,
        client_secret_nonce: nonce.secret_nonce,
        client_public_nonce: nonce.public_nonce,
        blinding_factor: nonce.blinding_factor,
        server_public_nonce: None,
        message_hex: None,
        output_pubkey: None,
        client_partial_sig: None,
        encoded_session: None,
        sign_second_payload_json: None,
        server_partial_sig: None,
        aggregate_signature: None,
        signed_tx_hex: None,
        txid: None,
        phase: Bip448WithdrawalPhase::Prepared,
        broadcast_status: Bip448BroadcastStatus::NotBroadcast,
        completion_status: Bip448CompletionStatus::Open,
        closing_tip_height: Some(sync.tip_height),
        closing_tip_hash: Some(sync.tip_hash.clone()),
        closing_bindings_json: Some(closing_bindings_json),
        created_at: String::new(),
        updated_at: String::new(),
    };

    let mut guard = begin_bip448_mutation_guard(&client_config.pool).await?;
    require_exact_confirmed_source(client_config, &binding)?;
    let live_tip_height = client_config.chain_client.tip_height()?;
    let live_tip_hash = client_config
        .chain_client
        .get_block_hash(live_tip_height)?
        .to_string();
    if live_tip_height != sync.tip_height || live_tip_hash != sync.tip_hash {
        return Err(anyhow!(
            "BIP448 canonical close chain tip changed before Prepared persistence"
        ));
    }
    let expected = guard
        .withdrawal_signature_count_expectation(wallet_name, statechain_id)
        .await?;
    let actual = bip448_signature_count(client_config, statechain_id).await?;
    if actual != expected.settled_count || expected.second_armed_landed_count.is_some() {
        return Err(anyhow!(
            "BIP448 lockbox signature count is {actual}, expected {} before canonical close",
            expected.settled_count
        ));
    }
    let persisted = guard.insert_withdrawal_attempt_if_absent(&attempt).await?;
    guard.commit().await?;
    bip448_process_checkpoint("attempt_prepared");
    drive_canonical_attempt(client_config, to_address, fee_rate, persisted).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use mercurylib::wallet::{CoinStatus, Settings, Wallet};
    use sqlx::sqlite::SqlitePoolOptions;

    use crate::{
        chain::{ChainClient, CoreRpcAuth, CoreRpcConfig},
        sqlite_manager::{insert_wallet, update_wallet},
    };

    fn wallet(protocol: Option<&str>) -> Wallet {
        let mut wallet = Wallet {
            name: "wallet".into(), mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(), version: "0.1.0".into(),
            state_entity_endpoint: "http://127.0.0.1:1".into(), chain_backend: "core".into(), chain_endpoint: "http://127.0.0.1:1".into(), network: "regtest".into(),
            blockheight: 0, activities: Vec::new(), coins: Vec::new(),
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
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        let url = "http://127.0.0.1:1";
        Ok(ClientConfig {
            statechain_entity: url.into(),
            chain_backend: "core".into(),
            chain_client: ChainClient::new(CoreRpcConfig {
                url: url.into(),
                auth: CoreRpcAuth::None,
            })?,
            chain_endpoint: Some(url.into()),
            core_rpc_auth: Some("none".into()),
            core_rpc_user: None,
            core_rpc_password: None,
            core_rpc_cookie_file: None,
            network: Network::Regtest,
            fee_rate_tolerance: 0.0,
            confirmation_target: 1,
            pool,
            tor_proxy: None,
            max_fee_rate: 10.0,
        })
    }

    #[test]
    fn selected_owner_status_gate_remains_operation_specific() {
        assert!(ensure_withdraw_status(&CoinStatus::CONFIRMED).is_ok());
        assert!(ensure_withdraw_status(&CoinStatus::IN_TRANSFER).is_err());
        assert!(ensure_withdraw_status(&CoinStatus::INITIALISED).is_err());
    }

    #[tokio::test]
    async fn protocol_and_pending_transfer_guards_precede_signing() -> Result<()> {
        let config = config().await?;
        let mut wallet = wallet(None);
        insert_wallet(&config.pool, &wallet).await?;
        let error = execute(&config, "wallet", "statechain", "unused", None)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "statechain statechain is not a BIP448 coin; BIP448 withdrawal requires an accepted BIP448 coin");

        wallet.coins[0].statechain_protocol = Some("bip448".into());
        update_wallet(&config.pool, &wallet).await?;

        sqlx::query("INSERT INTO bip448_pending_transfer_signings (wallet_name,statechain_id,funding_txid,funding_vout,funding_value_sats,update_template_hash,settlement_template_hash,state_locktime,signing_id,client_secret_nonce,client_public_nonce,blinding_factor) VALUES ('wallet','statechain','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',0,50000,'aa','bb',700000000,'cc','dd','ee','ff')").execute(&config.pool).await?;
        let error = execute(&config, "wallet", "statechain", "unused", None)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cancel or complete the in-flight transfer before withdrawing"
        );
        Ok(())
    }
}
