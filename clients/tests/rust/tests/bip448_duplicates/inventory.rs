use super::support::*;
use super::*;

#[derive(Debug, PartialEq, Eq)]
struct PassiveInvariant {
    wallet_json: String,
    accepted: (String, Vec<(i64, String)>),
    canonical_amount: Option<u32>,
    canonical_outpoint: (Option<String>, Option<u32>),
    signature_count: u32,
}

async fn passive_invariant(
    config: &ClientConfig,
    lockbox_client: &Client,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<PassiveInvariant> {
    let wallet_json = sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
        .bind(wallet_name)
        .fetch_one(&config.pool)
        .await?;
    let wallet = mercuryrustlib::sqlite_manager::get_wallet(&config.pool, wallet_name).await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(statechain_id))
        .context("BIP448 passive invariant lost its logical Coin")?;
    Ok(PassiveInvariant {
        wallet_json,
        accepted: accepted_state_bytes(&config.pool, wallet_name, statechain_id).await?,
        canonical_amount: coin.amount,
        canonical_outpoint: (coin.utxo_txid.clone(), coin.utxo_vout),
        signature_count: common::lockbox::get_signature_count(lockbox_client, statechain_id)
            .await?,
    })
}

async fn passive_sync_preserving_state(
    config: &ClientConfig,
    lockbox_client: &Client,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Bip448SyncReport> {
    let before = passive_invariant(config, lockbox_client, wallet_name, statechain_id).await?;
    let report =
        mercuryrustlib::coin_status::sync_bip448_funding_bindings(config, wallet_name).await?;
    let after = passive_invariant(config, lockbox_client, wallet_name, statechain_id).await?;
    assert_eq!(
        after, before,
        "passive synchronization mutated canonical state"
    );
    Ok(report)
}

fn observation(
    binding: &Bip448FundingBinding,
    status: Bip448ObservationStatus,
    last_scanned_height: u32,
    spend_txid: Option<Txid>,
    spend_height: Option<u32>,
) -> Bip448BindingObservation {
    let funding_height = match status {
        Bip448ObservationStatus::Mempool | Bip448ObservationStatus::Absent => None,
        _ => binding.funding_height.or(Some(1)),
    };
    Bip448BindingObservation {
        txid: binding.txid.clone(),
        vout: binding.vout,
        value_sats: binding.value_sats,
        script_pubkey: binding.script_pubkey.clone(),
        observation_status: status,
        funding_height,
        spend_txid: spend_txid.map(|txid| txid.to_string()),
        spend_height,
        last_scanned_height,
    }
}

fn fresh_observation(
    funding: &FundingOutput,
    script_pubkey: &str,
    status: Bip448ObservationStatus,
    last_scanned_height: u32,
) -> Bip448BindingObservation {
    Bip448BindingObservation {
        txid: funding.outpoint.txid.to_string(),
        vout: funding.outpoint.vout,
        value_sats: funding.value_sats,
        script_pubkey: script_pubkey.to_owned(),
        observation_status: status,
        funding_height: None,
        spend_txid: None,
        spend_height: None,
        last_scanned_height,
    }
}

fn attempt_for(
    binding: &Bip448FundingBinding,
    binding_index: u32,
    kind: Bip448WithdrawalAttemptKind,
    phase: Bip448WithdrawalPhase,
) -> Bip448WithdrawalAttempt {
    Bip448WithdrawalAttempt {
        wallet_name: binding.wallet_name.clone(),
        statechain_id: binding.statechain_id.clone(),
        binding_index,
        attempt_kind: kind,
        owner_user_pubkey: binding.owner_user_pubkey.clone(),
        owner_state_number: binding.owner_state_number,
        source_txid: binding.txid.clone(),
        source_vout: binding.vout,
        source_value_sats: binding.value_sats,
        source_script_pubkey: binding.script_pubkey.clone(),
        destination_address: "test-destination".into(),
        destination_script_pubkey: "51".into(),
        fee_rate_sat_per_vbyte: 1.0,
        fee_sats: 100,
        lock_time: 1,
        unsigned_tx_hex: "00".into(),
        signing_id: "11".repeat(32),
        signed_statechain_id: "12".repeat(64),
        sign_first_payload_json: "{}".into(),
        client_secret_nonce: "13".repeat(132),
        client_public_nonce: "14".repeat(66),
        blinding_factor: "15".repeat(32),
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
        phase,
        broadcast_status: Bip448BroadcastStatus::NotBroadcast,
        completion_status: Bip448CompletionStatus::NotApplicable,
        closing_tip_height: None,
        closing_tip_hash: None,
        closing_bindings_json: None,
        created_at: "test".into(),
        updated_at: "test".into(),
    }
}

async fn sign_and_broadcast_duplicate(
    config: &ClientConfig,
    canonical_coin: &Coin,
    duplicate: &Bip448FundingBinding,
) -> Result<Txid> {
    let mut signing_coin = canonical_coin.clone();
    signing_coin.utxo_txid = Some(duplicate.txid.clone());
    signing_coin.utxo_vout = Some(duplicate.vout);
    signing_coin.amount = Some(u32::try_from(duplicate.value_sats)?);
    let nonce = create_bip448_keypath_nonces(&signing_coin)?;
    signing_coin.secret_nonce = Some(nonce.secret_nonce);
    signing_coin.public_nonce = Some(nonce.public_nonce);
    signing_coin.blinding_factor = Some(nonce.blinding_factor);
    let signing_id = sha256::Hash::hash(uuid::Uuid::new_v4().as_bytes()).to_string();
    let statechain_id = signing_coin
        .statechain_id
        .clone()
        .context("duplicate signing Coin has no statechain ID")?;
    let signed_statechain_id = signing_coin
        .signed_statechain_id
        .clone()
        .context("duplicate signing Coin has no signed statechain ID")?;
    signing_coin.server_public_nonce = Some(
        mercuryrustlib::deposit::bip448_sign_first(
            config,
            &Bip448SignFirstRequestPayload {
                statechain_id: statechain_id.clone(),
                signed_statechain_id: signed_statechain_id.clone(),
                signing_id: signing_id.clone(),
            },
        )
        .await?,
    );
    let destination = common::bitcoin_core::getnewaddress()?;
    let signing = build_bip448_withdrawal_signing_data(
        &signing_coin,
        OutPoint {
            txid: Txid::from_str(&duplicate.txid)?,
            vout: duplicate.vout,
        },
        duplicate.value_sats,
        config.chain_client.tip_height()?,
        1.0,
        &destination,
        config.network,
    )?;
    let request = signing.partial_signature_request_payload;
    let server_partial = mercuryrustlib::deposit::bip448_sign_second(
        config,
        &Bip448PartialSignatureRequestPayload {
            statechain_id: request.statechain_id,
            signed_statechain_id: request.signed_statechain_id,
            signing_id,
            negate_seckey: request.negate_seckey,
            session: request.session,
            server_pub_nonce: request.server_pub_nonce,
        },
    )
    .await?;
    let signature = aggregate_bip448_keypath_signature(
        signing.msg,
        signing.client_partial_sig,
        hex::encode(server_partial.serialize()),
        signing.encoded_session,
        signing.output_pubkey,
    )?;
    let signed_tx = finalize_bip448_keypath_transaction(signing.encoded_unsigned_tx, signature)?;
    Ok(config.chain_client.broadcast_tx(&hex::decode(signed_tx)?)?)
}

pub(super) async fn bip448_duplicate_inventory_is_stable_across_restart_reorg_and_spend(
) -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    assert!(
        client_config.confirmation_target > 1,
        "the inventory transition test requires an unconfirmed interval"
    );
    let wallet_name = format!("bip448-inventory-{}", uuid::Uuid::new_v4());
    let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
    let token = mercuryrustlib::deposit::get_token(&client_config).await?;
    let token_id = common::utils::handle_token_response(&client_config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        &client_config,
        &wallet_name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    let aggregate_address =
        Address::from_str(&deposit.address)?.require_network(client_config.network)?;
    let script_pubkey = hex::encode(aggregate_address.script_pubkey().as_bytes());

    // A standard 400-sat P2TR output is relayable, but its eventual one-input
    // sweep output is dust after fees. It arrives before the canonical output.
    let dust = fund_address_output(&aggregate_address, DUST_DUPLICATE_AMOUNT_SATS)?;
    let pre_accept_report =
        mercuryrustlib::coin_status::sync_bip448_funding_bindings(&client_config, &wallet_name)
            .await?;
    assert!(pre_accept_report.bindings.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_funding_bindings WHERE wallet_name = $1",
        )
        .bind(&wallet_name)
        .fetch_one(&client_config.pool)
        .await?,
        0
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        0
    );
    common::bitcoin_core::mine_blocks(1)?;

    // Pending-journal insert/update/delete and the raw-wallet birth-height
    // change each invalidate a pre-RPC full SyncBase snapshot.
    let pending_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let pending_statechain_id = format!("pending-race-{}", uuid::Uuid::new_v4());
    sqlx::query(
        "INSERT INTO bip448_pending_deposit_signings (wallet_name,statechain_id,\
         update_template_hash,signing_id,client_secret_nonce,client_public_nonce,\
         blinding_factor) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&wallet_name)
    .bind(&pending_statechain_id)
    .bind("21".repeat(32))
    .bind("22".repeat(32))
    .bind("23".repeat(132))
    .bind("24".repeat(66))
    .bind("25".repeat(32))
    .execute(&client_config.pool)
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &pending_base,
        )
        .await
        .is_err()
    );
    let inserted_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    sqlx::query(
        "UPDATE bip448_pending_deposit_signings SET server_public_nonce=$1 \
         WHERE wallet_name=$2 AND statechain_id=$3",
    )
    .bind("26".repeat(66))
    .bind(&wallet_name)
    .bind(&pending_statechain_id)
    .execute(&client_config.pool)
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &inserted_base,
        )
        .await
        .is_err()
    );
    let updated_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    sqlx::query(
        "DELETE FROM bip448_pending_deposit_signings \
         WHERE wallet_name=$1 AND statechain_id=$2",
    )
    .bind(&wallet_name)
    .bind(&pending_statechain_id)
    .execute(&client_config.pool)
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &updated_base,
        )
        .await
        .is_err()
    );

    let wallet_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let mut receiver_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let simulated_receiver_birth = client_config
        .chain_client
        .tip_height()?
        .checked_add(1)
        .context("simulated receiver birth height overflow")?;
    receiver_wallet.blockheight = simulated_receiver_birth;
    mercuryrustlib::sqlite_manager::update_wallet(&client_config.pool, &receiver_wallet).await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &wallet_base,
        )
        .await
        .is_err()
    );

    let canonical = fund_address_output(&aggregate_address, FUNDING_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &client_config,
        &deposit.address,
        canonical.outpoint,
        canonical.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(client_config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;

    let accepted_before =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    let accepted_record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        accepted_record.funding_outpoint.txid,
        canonical.outpoint.txid.to_string()
    );
    assert_eq!(
        accepted_record.funding_outpoint.vout,
        canonical.outpoint.vout
    );
    assert_eq!(accepted_record.amount_sats, u64::from(FUNDING_AMOUNT_SATS));
    assert_eq!(accepted_before.1.len(), 1);
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        1
    );

    let accepted_sync = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let mut bindings = accepted_sync
        .bindings
        .into_iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .collect::<Vec<_>>();
    bindings.sort_by_key(|binding| binding.binding_index);
    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0].binding_index, 0);
    assert_eq!(bindings[0].role, Bip448BindingRole::Canonical);
    assert_eq!(bindings[0].txid, canonical.outpoint.txid.to_string());
    assert_eq!(bindings[1].binding_index, 1);
    assert_eq!(bindings[1].role, Bip448BindingRole::Duplicate);
    assert_eq!(bindings[1].txid, dust.outpoint.txid.to_string());
    assert_eq!(
        bindings[1].value_sats,
        u64::from(DUST_DUPLICATE_AMOUNT_SATS)
    );
    assert!(bindings[1].funding_height.context("dust funding height")? < simulated_receiver_birth);
    let owner_user_pubkey = bindings[0].owner_user_pubkey.clone();
    let owner_state_number = bindings[0].owner_state_number;

    // Two later values arrive together. Feed their real mempool observations
    // in reverse order through the public reconciliation helper; production's
    // internal sort, not callback order, determines their durable indices.
    let small = fund_address_output(&aggregate_address, SMALL_DUPLICATE_AMOUNT_SATS)?;
    let large = fund_address_output(&aggregate_address, DUPLICATE_AMOUNT_SATS)?;
    let tip_height = client_config.chain_client.tip_height()?;
    let mut reversed_observations = bindings
        .iter()
        .map(|binding| {
            observation(
                binding,
                binding.observation_status,
                tip_height,
                binding
                    .spend_txid
                    .as_deref()
                    .map(Txid::from_str)
                    .transpose()
                    .expect("stored spend txid must parse"),
                binding.spend_height,
            )
        })
        .collect::<Vec<_>>();
    reversed_observations.push(fresh_observation(
        &small,
        &script_pubkey,
        Bip448ObservationStatus::Mempool,
        tip_height,
    ));
    reversed_observations.push(fresh_observation(
        &large,
        &script_pubkey,
        Bip448ObservationStatus::Mempool,
        tip_height,
    ));
    reversed_observations.reverse();
    let count_before_order_injection =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    let reverse_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &reversed_observations,
    )
    .await?;
    let mut forward_observations = reversed_observations;
    forward_observations.reverse();
    let forward_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &forward_observations,
    )
    .await?;
    assert_eq!(
        reverse_rows
            .iter()
            .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
            .collect::<std::collections::BTreeMap<_, _>>(),
        forward_rows
            .iter()
            .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
            .collect::<std::collections::BTreeMap<_, _>>()
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        count_before_order_injection
    );
    let post_funding_indices = forward_rows
        .iter()
        .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut new_outpoints = [small.outpoint, large.outpoint];
    new_outpoints.sort_by_key(|outpoint| (outpoint.txid.to_string(), outpoint.vout));
    assert_eq!(
        post_funding_indices[&(new_outpoints[0].txid.to_string(), new_outpoints[0].vout)],
        2
    );
    assert_eq!(
        post_funding_indices[&(new_outpoints[1].txid.to_string(), new_outpoints[1].vout)],
        3
    );

    let mempool = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for outpoint in [small.outpoint, large.outpoint] {
        assert_eq!(
            mempool
                .bindings
                .iter()
                .find(|binding| binding.txid == outpoint.txid.to_string()
                    && binding.vout == outpoint.vout)
                .context("mempool duplicate binding")?
                .observation_status,
            Bip448ObservationStatus::Mempool
        );
    }
    common::bitcoin_core::mine_blocks(1)?;
    let duplicate_funding_block_hash = client_config
        .chain_client
        .get_block_hash(client_config.chain_client.tip_height()?)?
        .to_string();
    let unconfirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for outpoint in [small.outpoint, large.outpoint] {
        assert_eq!(
            unconfirmed
                .bindings
                .iter()
                .find(|binding| binding.txid == outpoint.txid.to_string()
                    && binding.vout == outpoint.vout)
                .context("unconfirmed duplicate binding")?
                .observation_status,
            Bip448ObservationStatus::Unconfirmed
        );
    }
    common::bitcoin_core::mine_blocks(client_config.confirmation_target - 1)?;
    let confirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for outpoint in [small.outpoint, large.outpoint] {
        assert_eq!(
            confirmed
                .bindings
                .iter()
                .find(|binding| binding.txid == outpoint.txid.to_string()
                    && binding.vout == outpoint.vout)
                .context("confirmed duplicate binding")?
                .observation_status,
            Bip448ObservationStatus::Confirmed
        );
    }

    // Close and reopen every client connection: the next inventory is rebuilt
    // from Bitcoin and keeps the exact outpoint-to-index assignment.
    let durable_indices = confirmed
        .bindings
        .iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
        .collect::<std::collections::BTreeMap<_, _>>();
    client_config.pool.close().await;
    drop(client_config);
    let client_config = ClientConfig::load().await;
    let restarted = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let restarted_indices = restarted
        .bindings
        .iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(restarted_indices, durable_indices);

    let restarted_bindings = restarted
        .bindings
        .iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .cloned()
        .collect::<Vec<_>>();
    let current_tip = client_config.chain_client.tip_height()?;
    let current_observations = restarted_bindings
        .iter()
        .map(|binding| observation(binding, binding.observation_status, current_tip, None, None))
        .collect::<Vec<_>>();
    let fake_observation = Bip448BindingObservation {
        txid: "fe".repeat(32),
        vout: 7,
        value_sats: 9_999,
        script_pubkey: script_pubkey.clone(),
        observation_status: Bip448ObservationStatus::Confirmed,
        funding_height: Some(1),
        spend_txid: None,
        spend_height: None,
        last_scanned_height: current_tip,
    };
    let binding_count_before_integrity = restarted_bindings.len() as i64;
    let count_before_integrity =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;

    // Record-only storage is not acceptance: without its exact history, a
    // novel observation cannot create a binding.
    let saved_history = sqlx::query_as::<_, (i64, String)>(
        "SELECT state_number,entry_json FROM bip448_state_history \
         WHERE wallet_name=$1 AND statechain_id=$2 ORDER BY state_number",
    )
    .bind(&wallet_name)
    .bind(&deposit.statechain_id)
    .fetch_all(&client_config.pool)
    .await?;
    sqlx::query("DELETE FROM bip448_state_history WHERE wallet_name=$1 AND statechain_id=$2")
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .execute(&client_config.pool)
        .await?;
    let mut observations_with_fake = current_observations.clone();
    observations_with_fake.push(fake_observation.clone());
    assert!(
        mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
            &client_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            &owner_user_pubkey,
            owner_state_number,
            &observations_with_fake,
        )
        .await
        .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_funding_bindings \
             WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .fetch_one(&client_config.pool)
        .await?,
        binding_count_before_integrity
    );
    for (state_number, entry_json) in &saved_history {
        sqlx::query(
            "INSERT INTO bip448_state_history \
             (wallet_name,statechain_id,state_number,entry_json) VALUES ($1,$2,$3,$4)",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .bind(*state_number)
        .bind(entry_json)
        .execute(&client_config.pool)
        .await?;
    }

    // History-only storage is equally insufficient. Preserve and restore the
    // accepted row byte-for-byte around the deliberately failed reconcile.
    type StoredRecord = (
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
        String,
        String,
    );
    let saved_record = sqlx::query_as::<_, StoredRecord>(
        "SELECT wallet_name,statechain_id,aggregate_pubkey,funding_txid,funding_vout,\
         funding_value_sats,latest_state_number,challenge_delay,amount_sats,network,\
         record_json,created_at,updated_at FROM bip448_statechains \
         WHERE wallet_name=$1 AND statechain_id=$2",
    )
    .bind(&wallet_name)
    .bind(&deposit.statechain_id)
    .fetch_one(&client_config.pool)
    .await?;
    sqlx::query("DELETE FROM bip448_statechains WHERE wallet_name=$1 AND statechain_id=$2")
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .execute(&client_config.pool)
        .await?;
    assert!(
        mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
            &client_config.pool,
            &wallet_name,
            &deposit.statechain_id,
            &owner_user_pubkey,
            owner_state_number,
            &observations_with_fake,
        )
        .await
        .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_funding_bindings \
             WHERE wallet_name=$1 AND statechain_id=$2",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .fetch_one(&client_config.pool)
        .await?,
        binding_count_before_integrity
    );
    sqlx::query(
        "INSERT INTO bip448_statechains (wallet_name,statechain_id,aggregate_pubkey,\
         funding_txid,funding_vout,funding_value_sats,latest_state_number,challenge_delay,\
         amount_sats,network,record_json,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(&saved_record.0)
    .bind(&saved_record.1)
    .bind(&saved_record.2)
    .bind(&saved_record.3)
    .bind(saved_record.4)
    .bind(saved_record.5)
    .bind(saved_record.6)
    .bind(saved_record.7)
    .bind(saved_record.8)
    .bind(&saved_record.9)
    .bind(&saved_record.10)
    .bind(&saved_record.11)
    .bind(&saved_record.12)
    .execute(&client_config.pool)
    .await?;
    assert_eq!(
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?,
        accepted_before
    );
    let idempotent_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &current_observations,
    )
    .await?;
    assert_eq!(idempotent_rows.len() as i64, binding_count_before_integrity);
    assert_eq!(
        idempotent_rows
            .iter()
            .map(|binding| ((binding.txid.clone(), binding.vout), binding.binding_index))
            .collect::<std::collections::BTreeMap<_, _>>(),
        durable_indices
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        count_before_integrity
    );

    // Stage both a new observation and a cursor/cache revision under one
    // guard, then simulate a process crash by dropping it before commit.
    let cursor_before = sqlx::query_as::<_, (i64, i64, i64, String)>(
        "SELECT coverage_start_height,scan_revision,last_scanned_height,last_scanned_block_hash \
         FROM bip448_scan_cursors WHERE wallet_name=$1 AND script_pubkey=$2",
    )
    .bind(&wallet_name)
    .bind(&script_pubkey)
    .fetch_one(&client_config.pool)
    .await?;
    let bindings_before_crash = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let crash_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let mut crash_guard = mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
        &client_config.pool,
        &crash_base,
    )
    .await?;
    crash_guard
        .reconcile_funding_bindings(
            &wallet_name,
            &deposit.statechain_id,
            &owner_user_pubkey,
            owner_state_number,
            &observations_with_fake,
        )
        .await?;
    crash_guard
        .apply_scan_cache_and_cursor(
            &wallet_name,
            &script_pubkey,
            &Bip448ScanCursor {
                coverage_start_height: u32::try_from(cursor_before.0)?,
                scan_revision: u64::try_from(cursor_before.1)?,
                last_scanned_height: u32::try_from(cursor_before.2)?
                    .checked_add(1)
                    .context("test cursor height overflow")?,
                last_scanned_block_hash: client_config
                    .chain_client
                    .get_block_hash(client_config.chain_client.tip_height()?)?
                    .to_string(),
            },
            &[],
        )
        .await?;
    drop(crash_guard);
    tokio::task::yield_now().await;
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64, String)>(
            "SELECT coverage_start_height,scan_revision,last_scanned_height,last_scanned_block_hash \
             FROM bip448_scan_cursors WHERE wallet_name=$1 AND script_pubkey=$2",
        )
        .bind(&wallet_name)
        .bind(&script_pubkey)
        .fetch_one(&client_config.pool)
        .await?,
        cursor_before
    );
    assert_eq!(
        mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
            &client_config.pool,
            &wallet_name,
            &deposit.statechain_id,
        )
        .await?,
        bindings_before_crash
    );

    // A newer scan commits first. The older pre-RPC snapshot cannot follow it,
    // even though both began from the same accepted wallet and chain tip.
    let reversed_commit_base = mercuryrustlib::sqlite_manager::capture_bip448_sync_base(
        &client_config.pool,
        &wallet_name,
        &script_pubkey,
    )
    .await?;
    let newer_scan = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert!(
        mercuryrustlib::sqlite_manager::begin_bip448_sync_base_guard(
            &client_config.pool,
            &reversed_commit_base,
        )
        .await
        .is_err(),
        "an older candidate committed after the newer full SyncBase winner"
    );

    // A second same-tip no-op scan advances only the durable revision. A final
    // wallet CAS holding the first scan's token must still lose.
    let stale_wallet_json: String =
        sqlx::query_scalar("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
            .bind(&wallet_name)
            .fetch_one(&client_config.pool)
            .await?;
    let stale_tokens = newer_scan.applied_scan_revisions.clone();
    assert!(!stale_tokens.is_empty());
    let same_tip_winner = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for stale in &stale_tokens {
        let winner = same_tip_winner
            .applied_scan_revisions
            .iter()
            .find(|token| token.script_pubkey == stale.script_pubkey)
            .context("same-tip winner omitted a script revision")?;
        assert!(winner.scan_revision > stale.scan_revision);
    }
    let mut stale_replacement =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    stale_replacement.blockheight = stale_replacement
        .blockheight
        .checked_add(1)
        .context("stale replacement height overflow")?;
    assert!(
        !mercuryrustlib::sqlite_manager::compare_and_set_wallet_after_bip448_scan(
            &client_config.pool,
            &wallet_name,
            &stale_wallet_json,
            &stale_replacement,
            &stale_tokens,
        )
        .await?
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1",)
            .bind(&wallet_name)
            .fetch_one(&client_config.pool)
            .await?,
        stale_wallet_json
    );

    // The interim old canonical withdrawal gate must fail before any signing,
    // broadcast, completion, activity, or server mutation.
    let withdrawal_wallet_before = stale_wallet_json.clone();
    let withdrawal_accepted_before =
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?;
    let withdrawal_mercury_before = mercury_state_bytes(&deposit.statechain_id).await?;
    let withdrawal_count_before =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    let withdrawal_rows_before = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT \
         (SELECT COUNT(*) FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_pending_transfer_signings WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2)",
    )
    .bind(&wallet_name)
    .bind(&deposit.statechain_id)
    .fetch_one(&client_config.pool)
    .await?;
    let withdrawal_destination = common::bitcoin_core::getnewaddress()?;
    let withdrawal_error = mercuryrustlib::bip448_withdraw::execute(
        &client_config,
        &wallet_name,
        &deposit.statechain_id,
        &withdrawal_destination,
        Some(1.0),
    )
    .await
    .expect_err("old canonical withdrawal must reject every duplicate binding");
    let withdrawal_error = withdrawal_error.to_string();
    assert!(
        withdrawal_error
            .contains("BIP448 canonical withdrawal is blocked by unresolved close facts"),
        "unexpected canonical close-gate error: {withdrawal_error}"
    );
    assert!(
        withdrawal_error.contains("BindingObservation"),
        "canonical close did not report its unresolved duplicate binding: {withdrawal_error}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1",)
            .bind(&wallet_name)
            .fetch_one(&client_config.pool)
            .await?,
        withdrawal_wallet_before
    );
    assert_eq!(
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?,
        withdrawal_accepted_before
    );
    assert_eq!(
        mercury_state_bytes(&deposit.statechain_id).await?,
        withdrawal_mercury_before
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        withdrawal_count_before
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT \
             (SELECT COUNT(*) FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2),\
             (SELECT COUNT(*) FROM bip448_pending_transfer_signings WHERE wallet_name=$1 AND statechain_id=$2),\
             (SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2)",
        )
        .bind(&wallet_name)
        .bind(&deposit.statechain_id)
        .fetch_one(&client_config.pool)
        .await?,
        withdrawal_rows_before
    );

    // A real mempool eviction must force one authoritative height-zero replay.
    // The public sync path observes Absent, then the exact transactions
    // reappear with their original stable indices and no canonical mutation.
    let inventory = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let canonical_binding = inventory
        .iter()
        .find(|binding| binding.binding_index == 0)
        .context("canonical inventory binding")?
        .clone();
    let small_binding = inventory
        .iter()
        .find(|binding| binding.txid == small.outpoint.txid.to_string())
        .context("small duplicate inventory binding")?
        .clone();
    let stable_small_index = small_binding.binding_index;
    let large_binding_before_eviction = inventory
        .iter()
        .find(|binding| binding.txid == large.outpoint.txid.to_string())
        .context("large duplicate inventory binding before eviction")?
        .clone();
    let stable_large_index = large_binding_before_eviction.binding_index;
    let small_transaction = common::bitcoin_core::wallet_transaction(&small.outpoint.txid)?;
    let large_transaction = common::bitcoin_core::wallet_transaction(&large.outpoint.txid)?;
    assert!(
        common::bitcoin_core::raw_mempool()?.is_empty(),
        "the eviction fixture requires an empty persisted mempool baseline"
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury savemempool",
    )?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {duplicate_funding_block_hash}"
    ))?;
    let reorged_receives = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for (outpoint, stable_index) in [
        (small.outpoint, stable_small_index),
        (large.outpoint, stable_large_index),
    ] {
        let row = reorged_receives
            .bindings
            .iter()
            .find(|binding| binding.txid == outpoint.txid.to_string())
            .context("reorged mempool receive binding")?;
        assert_eq!(row.binding_index, stable_index);
        assert_eq!(row.observation_status, Bip448ObservationStatus::Mempool);
    }

    let eviction_tip_height = client_config.chain_client.tip_height()?;
    let flushed_chainstate: serde_json::Value =
        serde_json::from_str(&common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury gettxoutsetinfo none",
        )?)?;
    assert_eq!(
        flushed_chainstate
            .get("height")
            .and_then(serde_json::Value::as_u64),
        Some(u64::from(eviction_tip_height)),
        "the eviction fixture must flush the exact post-invalidation chain tip"
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury unloadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury unloadwallet mercury_tokens",
    )?;
    let bitcoin_container = common::bitcoin_core::get_container_id()?;
    restart_bitcoin_core_after_unclean_stop(&bitcoin_container)?;
    assert_eq!(
        client_config.chain_client.tip_height()?,
        eviction_tip_height,
        "the force-flushed post-invalidation tip must survive the unclean restart"
    );
    common::bitcoin_core::assert_not_in_mempool(&small.outpoint.txid)?;
    common::bitcoin_core::assert_not_in_mempool(&large.outpoint.txid)?;
    let absent_receives = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for (outpoint, stable_index) in [
        (small.outpoint, stable_small_index),
        (large.outpoint, stable_large_index),
    ] {
        let row = absent_receives
            .bindings
            .iter()
            .find(|binding| binding.txid == outpoint.txid.to_string())
            .context("authoritatively absent receive binding")?;
        assert_eq!(row.binding_index, stable_index);
        assert_eq!(row.observation_status, Bip448ObservationStatus::Absent);
    }
    assert_eq!(absent_receives.bindings.len(), inventory.len());

    assert_eq!(
        common::bitcoin_core::broadcast_raw_transaction(&small_transaction)?,
        small.outpoint.txid
    );
    assert_eq!(
        common::bitcoin_core::broadcast_raw_transaction(&large_transaction)?,
        large.outpoint.txid
    );
    let reappeared_receives = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    for (outpoint, stable_index) in [
        (small.outpoint, stable_small_index),
        (large.outpoint, stable_large_index),
    ] {
        let row = reappeared_receives
            .bindings
            .iter()
            .find(|binding| binding.txid == outpoint.txid.to_string())
            .context("reappeared mempool receive binding")?;
        assert_eq!(row.binding_index, stable_index);
        assert_eq!(row.observation_status, Bip448ObservationStatus::Mempool);
    }
    assert_eq!(reappeared_receives.bindings.len(), inventory.len());

    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
    )?;
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
    )?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury reconsiderblock {duplicate_funding_block_hash}"
    ))?;
    common::bitcoin_core::ensure_wallet_loaded()?;
    let restored_receive = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        restored_receive
            .bindings
            .iter()
            .find(|binding| binding.txid == small_binding.txid)
            .context("restored receive binding")?
            .observation_status,
        Bip448ObservationStatus::Confirmed
    );
    assert_eq!(
        restored_receive
            .bindings
            .iter()
            .find(|binding| binding.txid == large_binding_before_eviction.txid)
            .context("restored large receive binding")?
            .binding_index,
        stable_large_index
    );

    // Use the retained key-path primitive only to manufacture a real external
    // spend. Every subsequent observation is passive and must leave the new
    // signature count fixed.
    let wallet_for_spend =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let canonical_coin = wallet_for_spend
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str()))
        .context("canonical Coin for duplicate test spend")?
        .clone();
    let large_binding = restored_receive
        .bindings
        .iter()
        .find(|binding| binding.txid == large.outpoint.txid.to_string())
        .context("large duplicate inventory binding")?
        .clone();
    assert_eq!(large_binding.binding_index, stable_large_index);
    let spend_txid =
        sign_and_broadcast_duplicate(&client_config, &canonical_coin, &large_binding).await?;
    let signed_count =
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?;
    assert_eq!(signed_count, withdrawal_count_before + 1);
    let spent_mempool = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let spent_row = spent_mempool
        .bindings
        .iter()
        .find(|binding| binding.binding_index == stable_large_index)
        .context("mempool-spent duplicate")?;
    assert_eq!(
        spent_row.observation_status,
        Bip448ObservationStatus::SpentMempool
    );
    assert_eq!(
        spent_row.spend_txid.as_deref(),
        Some(spend_txid.to_string().as_str())
    );

    common::bitcoin_core::mine_block_with_transactions(&[spend_txid])?;
    let spend_block_height = client_config.chain_client.tip_height()?;
    let spend_block_hash = client_config
        .chain_client
        .get_block_hash(spend_block_height)?
        .to_string();
    let spent_unconfirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        spent_unconfirmed
            .bindings
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("unconfirmed-spent duplicate")?
            .observation_status,
        Bip448ObservationStatus::SpentUnconfirmed
    );
    common::bitcoin_core::mine_blocks(client_config.confirmation_target - 1)?;
    let spent_confirmed = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        spent_confirmed
            .bindings
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("confirmed-spent duplicate")?
            .observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );

    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {spend_block_hash}"
    ))?;
    let reorged = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    let reorged_spend = reorged
        .bindings
        .iter()
        .find(|binding| binding.binding_index == stable_large_index)
        .context("reorged duplicate spend")?;
    assert_eq!(reorged_spend.binding_index, stable_large_index);
    assert_eq!(
        reorged_spend.observation_status,
        Bip448ObservationStatus::SpentMempool
    );
    assert!(reorged.bindings.iter().all(|binding| {
        binding.txid == large_binding.txid
            || binding.observation_status != Bip448ObservationStatus::Absent
    }));
    let cursor_coverage: i64 = sqlx::query_scalar(
        "SELECT coverage_start_height FROM bip448_scan_cursors \
         WHERE wallet_name=$1 AND script_pubkey=$2",
    )
    .bind(&wallet_name)
    .bind(&script_pubkey)
    .fetch_one(&client_config.pool)
    .await?;
    assert_eq!(cursor_coverage, 0);

    // Inject the authoritative result of mempool-spend eviction, then restore
    // the original block. Neither transition removes or renumbers the row.
    let reorg_tip = client_config.chain_client.tip_height()?;
    let eviction_rows = mercuryrustlib::sqlite_manager::reconcile_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
        &owner_user_pubkey,
        owner_state_number,
        &[
            observation(
                &canonical_binding,
                canonical_binding.observation_status,
                reorg_tip,
                None,
                None,
            ),
            observation(
                &large_binding,
                Bip448ObservationStatus::Confirmed,
                reorg_tip,
                None,
                None,
            ),
        ],
    )
    .await?;
    assert_eq!(
        eviction_rows
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("mempool-spend eviction row")?
            .observation_status,
        Bip448ObservationStatus::Confirmed
    );
    assert_eq!(eviction_rows.len(), inventory.len());
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury reconsiderblock {spend_block_hash}"
    ))?;
    let reconsidered = passive_sync_preserving_state(
        &client_config,
        &lockbox_client,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?;
    assert_eq!(
        reconsidered
            .bindings
            .iter()
            .find(|binding| binding.binding_index == stable_large_index)
            .context("reconsidered duplicate spend")?
            .observation_status,
        Bip448ObservationStatus::SpentConfirmed
    );
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        signed_count
    );

    // The real list path keeps one logical Coin, preserves the seven legacy
    // fields, and nests all duplicate inventory in stable-index order.
    let final_wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name).await?;
    let logical_coins = final_wallet
        .coins
        .iter()
        .filter(|coin| coin.statechain_id.as_deref() == Some(deposit.statechain_id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(logical_coins.len(), 1, "duplicate discovery cloned a Coin");
    let list =
        mercuryrustlib::coin_status::statecoin_list_json(&client_config, &final_wallet).await?;
    let listed = list
        .iter()
        .find(|entry| {
            entry
                .get("coin.statechain_id")
                .and_then(serde_json::Value::as_str)
                == Some(deposit.statechain_id.as_str())
        })
        .context("nested duplicate list entry")?;
    let expected_outer_keys = [
        "coin.address",
        "coin.address_retired",
        "coin.aggregated_address",
        "coin.amount",
        "coin.close_tip_hash",
        "coin.close_tip_height",
        "coin.duplicates",
        "coin.exit_only",
        "coin.locktime",
        "coin.statechain_id",
        "coin.statechain_protocol",
        "coin.status",
        "coin.user_pubkey",
        "coin.utxo_txid",
        "coin.utxo_vout",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        listed
            .as_object()
            .context("statecoin list entry object")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected_outer_keys
    );
    assert_eq!(
        listed["coin.amount"].as_u64(),
        Some(u64::from(FUNDING_AMOUNT_SATS))
    );
    assert!(listed["coin.close_tip_height"].is_null());
    assert!(listed["coin.close_tip_hash"].is_null());
    let duplicate_json = listed["coin.duplicates"]
        .as_array()
        .context("nested duplicate array")?;
    assert_eq!(duplicate_json.len(), 3);
    assert_eq!(
        duplicate_json
            .iter()
            .map(|row| row["duplicate_index"].as_u64())
            .collect::<Vec<_>>(),
        vec![Some(1), Some(2), Some(3)]
    );
    let expected_duplicate_keys = [
        "amount_sats",
        "broadcast_status",
        "cooperative_only",
        "duplicate_index",
        "observation_status",
        "ownership_status",
        "server_dependent",
        "spend_txid",
        "sweep_phase",
        "txid",
        "vout",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for row in duplicate_json {
        assert_eq!(
            row.as_object()
                .context("nested duplicate object")?
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected_duplicate_keys
        );
        assert!(row["amount_sats"].as_u64().is_some());
        assert!(row["vout"].as_u64().is_some());
    }
    assert_eq!(
        duplicate_json
            .iter()
            .map(|row| row["amount_sats"].as_u64().expect("u64 duplicate amount"))
            .collect::<BTreeSet<_>>(),
        [
            u64::from(DUST_DUPLICATE_AMOUNT_SATS),
            u64::from(SMALL_DUPLICATE_AMOUNT_SATS),
            u64::from(DUPLICATE_AMOUNT_SATS),
        ]
        .into_iter()
        .collect()
    );

    // Full attachment identity prevents rows from another statechain, wallet,
    // or owner generation on a reused aggregate script from leaking in.
    let truth_binding = reconsidered
        .bindings
        .iter()
        .find(|binding| binding.txid == small_binding.txid)
        .context("truth-table duplicate")?
        .clone();
    let mut foreign_statechain = truth_binding.clone();
    foreign_statechain.statechain_id = format!("foreign-{}", uuid::Uuid::new_v4());
    let mut foreign_wallet = truth_binding.clone();
    foreign_wallet.wallet_name = format!("foreign-{}", uuid::Uuid::new_v4());
    let mut foreign_owner = truth_binding.clone();
    foreign_owner.owner_user_pubkey = "02".repeat(32);
    let isolated = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &wallet_name,
        logical_coins[0],
        &[
            truth_binding.clone(),
            foreign_statechain,
            foreign_wallet,
            foreign_owner,
        ],
        &[],
    )?;
    assert_eq!(
        isolated["coin.duplicates"]
            .as_array()
            .context("isolated duplicates")?
            .len(),
        1
    );

    let flags = |entry: &serde_json::Value| -> Result<(bool, bool)> {
        let row = entry["coin.duplicates"]
            .as_array()
            .and_then(|rows| rows.first())
            .context("truth-table duplicate row")?;
        Ok((
            row["cooperative_only"]
                .as_bool()
                .context("cooperative_only bool")?,
            row["server_dependent"]
                .as_bool()
                .context("server_dependent bool")?,
        ))
    };
    let mut current_live = truth_binding.clone();
    current_live.observation_status = Bip448ObservationStatus::Confirmed;
    current_live.spend_txid = None;
    current_live.spend_height = None;
    current_live.ownership_status = Bip448OwnershipStatus::Current;
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[current_live.clone()],
            &[],
        )?)?,
        (true, true)
    );
    for phase in [
        Bip448WithdrawalPhase::Prepared,
        Bip448WithdrawalPhase::FirstArmed,
        Bip448WithdrawalPhase::NonceStored,
        Bip448WithdrawalPhase::SecondArmed,
    ] {
        let attempt = attempt_for(
            &current_live,
            current_live.binding_index,
            Bip448WithdrawalAttemptKind::Duplicate,
            phase,
        );
        assert_eq!(
            flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
                &wallet_name,
                logical_coins[0],
                &[current_live.clone()],
                &[attempt],
            )?)?,
            (true, true),
            "non-durable phase {phase} changed cooperative truth"
        );
    }
    let signed_attempt = attempt_for(
        &current_live,
        current_live.binding_index,
        Bip448WithdrawalAttemptKind::Duplicate,
        Bip448WithdrawalPhase::Signed,
    );
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[current_live.clone()],
            &[signed_attempt],
        )?)?,
        (false, false)
    );
    let mut independently_spent = current_live.clone();
    independently_spent.observation_status = Bip448ObservationStatus::SpentConfirmed;
    independently_spent.spend_txid = Some("ab".repeat(32));
    independently_spent.spend_height = Some(1);
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[independently_spent],
            &[],
        )?)?,
        (false, false)
    );
    let mut previous_unresolved = current_live.clone();
    previous_unresolved.ownership_status = Bip448OwnershipStatus::Previous;
    assert_eq!(
        flags(&mercuryrustlib::coin_status::statecoin_list_entry_json(
            &wallet_name,
            logical_coins[0],
            &[previous_unresolved],
            &[],
        )?)?,
        (true, false)
    );
    let canonical_attempt = attempt_for(
        &canonical_binding,
        0,
        Bip448WithdrawalAttemptKind::Canonical,
        Bip448WithdrawalPhase::Prepared,
    );
    let retired = mercuryrustlib::coin_status::statecoin_list_entry_json(
        &wallet_name,
        logical_coins[0],
        &[current_live],
        &[canonical_attempt],
    )?;
    assert_eq!(flags(&retired)?, (true, false));
    assert_eq!(retired["coin.address_retired"].as_bool(), Some(true));

    let final_indices = mercuryrustlib::sqlite_manager::list_bip448_funding_bindings(
        &client_config.pool,
        &wallet_name,
        &deposit.statechain_id,
    )
    .await?
    .into_iter()
    .map(|binding| ((binding.txid, binding.vout), binding.binding_index))
    .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(final_indices, durable_indices);
    assert_eq!(
        accepted_state_bytes(&client_config.pool, &wallet_name, &deposit.statechain_id).await?,
        accepted_before
    );
    assert_eq!(logical_coins[0].amount, Some(FUNDING_AMOUNT_SATS));
    assert_eq!(
        logical_coins[0].utxo_txid.as_deref(),
        Some(canonical.outpoint.txid.to_string().as_str())
    );
    assert_eq!(logical_coins[0].utxo_vout, Some(canonical.outpoint.vout));
    assert_eq!(
        common::lockbox::get_signature_count(&lockbox_client, &deposit.statechain_id).await?,
        signed_count
    );

    println!(
        "BIP448 duplicate inventory stable: statechain_id={} canonical={} dust={} small={} large={} spend={} indices={:?}",
        deposit.statechain_id,
        canonical.outpoint,
        dust.outpoint,
        small.outpoint,
        large.outpoint,
        spend_txid,
        final_indices,
    );

    Ok(())
}
