use super::*;

pub(super) const DUPLICATE_AMOUNT_SATS: u32 = 73_421;
pub(super) const SMALL_DUPLICATE_AMOUNT_SATS: u32 = 12_345;
pub(super) const DUST_DUPLICATE_AMOUNT_SATS: u32 = 400;
pub(super) const MERCURY_DATABASE_URL: &str = "postgres://postgres:postgres@127.0.0.1:5432/mercury";

pub(super) async fn run_commit10_child_if_requested() -> Result<bool> {
    let Ok(operation) = std::env::var("ML_BIP448_COMMIT10_CHILD") else {
        return Ok(false);
    };
    std::env::set_var("ML_NETWORK", "regtest");
    let config = mercuryrustlib::client_config::load().await;
    let wallet_name = std::env::var("ML_BIP448_RESTART_WALLET")?;
    let statechain_id = std::env::var("ML_BIP448_RESTART_STATECHAIN_ID")?;
    let result = match operation.as_str() {
        "force-transfer" => {
            mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
                &config,
                &std::env::var("ML_BIP448_RESTART_RECIPIENT")?,
                &wallet_name,
                &statechain_id,
                None,
                mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
                    acknowledge_cooperative_duplicates: true,
                    intent: Bip448TransferIntentKind::UserTransfer,
                },
            )
            .await
        }
        "cancel" => mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
            &config,
            &wallet_name,
            &statechain_id,
        )
        .await
        .map(|_| ()),
        _ => anyhow::bail!("unknown Commit 10 child operation {operation}"),
    };
    config.pool.close().await;
    result?;
    Ok(true)
}

pub(super) fn spawn_commit10_barrier_child(
    test_name: &str,
    operation: &str,
    wallet_name: &str,
    statechain_id: &str,
    recipient: Option<&str>,
    barrier: &str,
) -> Result<(Child, PathBuf, PathBuf)> {
    let id = uuid::Uuid::new_v4();
    let reached = std::env::temp_dir().join(format!("bip448-commit10-{id}-reached"));
    let release = std::env::temp_dir().join(format!("bip448-commit10-{id}-release"));
    if reached.try_exists()? || release.try_exists()? {
        anyhow::bail!("unique Commit 10 barrier path already exists");
    }
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            test_name,
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_COMMIT10_CHILD", operation)
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env("ML_BIP448_TEST_BARRIER", barrier)
        .env("ML_BIP448_TEST_BARRIER_REACHED", &reached)
        .env("ML_BIP448_TEST_BARRIER_RELEASE", &release)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT")
        .env_remove("ML_BIP448_DUPLICATE_SWEEP_CHILD")
        .env_remove("ML_BIP448_CANONICAL_CLOSE_CHILD_MODE")
        .env_remove("ML_BIP448_RECEIVER_RESCAN_CHILD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(recipient) = recipient {
        command.env("ML_BIP448_RESTART_RECIPIENT", recipient);
    } else {
        command.env_remove("ML_BIP448_RESTART_RECIPIENT");
    }
    Ok((command.spawn()?, reached, release))
}

pub(super) fn wait_for_commit10_barrier(
    child: &mut Child,
    reached: &Path,
    barrier: &str,
) -> Result<()> {
    for _ in 0..6_000 {
        if reached.try_exists()? {
            let observed = std::fs::read_to_string(reached)?;
            if observed != barrier {
                anyhow::bail!("Commit 10 child reached {observed}, expected {barrier}");
            }
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("Commit 10 barrier child exited with {status} before reaching {barrier}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    anyhow::bail!("timed out waiting for Commit 10 child barrier {barrier}")
}

pub(super) fn release_commit10_barrier(
    child: Child,
    reached: &Path,
    release: &Path,
) -> Result<Output> {
    std::fs::write(release, b"release")?;
    let output = child.wait_with_output();
    for path in [reached, release] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(output?)
}

pub(super) async fn mercury_transfer_side_effect_counts(statechain_id: &str) -> Result<(i64, i64)> {
    let pool = sqlx::PgPool::connect(MERCURY_DATABASE_URL).await?;
    Ok(sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE encrypted_transfer_msg IS NOT NULL) \
         FROM statechain_transfer WHERE statechain_id=$1",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?)
}

pub(super) async fn mercury_state_bytes(statechain_id: &str) -> Result<(String, String, String)> {
    let pool = sqlx::PgPool::connect(MERCURY_DATABASE_URL).await?;
    let statechain_data = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(row_data)), '[]'::jsonb)::text FROM (\
         SELECT * FROM statechain_data WHERE statechain_id = $1 ORDER BY statechain_id\
         ) AS row_data",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?;
    let signatures = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(row_data)), '[]'::jsonb)::text FROM (\
         SELECT * FROM bip448_signature_data WHERE statechain_id = $1 ORDER BY signing_id\
         ) AS row_data",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?;
    let transfer = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(row_data)), '[]'::jsonb)::text FROM (\
         SELECT * FROM statechain_transfer WHERE statechain_id = $1 ORDER BY statechain_id\
         ) AS row_data",
    )
    .bind(statechain_id)
    .fetch_one(&pool)
    .await?;
    Ok((statechain_data, signatures, transfer))
}

pub(super) async fn accepted_state_bytes(
    pool: &sqlx::SqlitePool,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<(String, Vec<(i64, String)>)> {
    let record_json = sqlx::query_scalar(
        "SELECT record_json FROM bip448_statechains \
         WHERE wallet_name = $1 AND statechain_id = $2",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_one(pool)
    .await?;
    let history_rows = sqlx::query_as(
        "SELECT state_number, entry_json FROM bip448_state_history \
         WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY state_number",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_all(pool)
    .await?;

    Ok((record_json, history_rows))
}

pub(super) fn restart_bitcoin_core_after_unclean_stop(container_id: &str) -> Result<()> {
    if container_id.is_empty() {
        anyhow::bail!("cannot restart an empty Bitcoin Core container ID");
    }
    for action in ["kill", "start"] {
        let output = Command::new("docker")
            .args([action, container_id])
            .output()
            .with_context(|| format!("failed to execute docker {action}"))?;
        if !output.status.success() {
            anyhow::bail!(
                "docker {action} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    for _ in 0..120 {
        if common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury getblockchaininfo",
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    anyhow::bail!("Bitcoin Core did not become ready after its unclean restart")
}

pub(super) struct DuplicateSweepFixture {
    pub(super) config: ClientConfig,
    pub(super) wallet_name: String,
    pub(super) statechain_id: String,
    pub(super) bindings: Vec<Bip448FundingBinding>,
}

pub(super) async fn duplicate_sweep_fixture(
    duplicate_amounts: &[u32],
) -> Result<DuplicateSweepFixture> {
    let config = common::prepare_test_env().await?;
    let wallet_name = format!("bip448-sweep-{}", uuid::Uuid::new_v4());
    let wallet = mercuryrustlib::wallet::create_wallet(&wallet_name, &config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&config.pool, &wallet).await?;
    let token = mercuryrustlib::deposit::get_token(&config).await?;
    let token_id = common::utils::handle_token_response(&config, &token).await?;
    let deposit = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        &config,
        &wallet_name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    let aggregate_address = Address::from_str(&deposit.address)?.require_network(config.network)?;
    let canonical = fund_address_output(&aggregate_address, FUNDING_AMOUNT_SATS)?;
    common::chain::wait_for_address_outpoint(
        &config,
        &deposit.address,
        canonical.outpoint,
        canonical.value_sats,
    )
    .await?;
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    mercuryrustlib::coin_status::update_coins(&config, &wallet_name).await?;
    for amount in duplicate_amounts {
        fund_address_output(&aggregate_address, *amount)?;
    }
    common::bitcoin_core::mine_blocks(config.confirmation_target)?;
    let report =
        mercuryrustlib::coin_status::sync_bip448_funding_bindings(&config, &wallet_name).await?;
    let mut bindings = report
        .bindings
        .into_iter()
        .filter(|binding| binding.statechain_id == deposit.statechain_id)
        .collect::<Vec<_>>();
    bindings.sort_by_key(|binding| binding.binding_index);
    assert_eq!(bindings.len(), duplicate_amounts.len() + 1);
    assert_eq!(bindings[0].role, Bip448BindingRole::Canonical);
    for binding in bindings.iter().skip(1) {
        assert_eq!(binding.role, Bip448BindingRole::Duplicate);
        assert_eq!(
            binding.observation_status,
            Bip448ObservationStatus::Confirmed
        );
        assert_eq!(binding.ownership_status, Bip448OwnershipStatus::Current);
    }
    Ok(DuplicateSweepFixture {
        config,
        wallet_name,
        statechain_id: deposit.statechain_id,
        bindings,
    })
}

pub(super) async fn retained_update_conflict_package(
    fixture: &DuplicateSweepFixture,
    duplicate: &Bip448FundingBinding,
) -> Result<Bip448RecoveryPackage> {
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &fixture.config.pool,
        &fixture.wallet_name,
        &fixture.statechain_id,
    )
    .await?;
    assert_eq!(
        duplicate.value_sats, record.funding_outpoint.value_sats,
        "retained U may only be rebound to an exact-value duplicate"
    );
    assert_eq!(
        duplicate.script_pubkey, fixture.bindings[0].script_pubkey,
        "competing-spend target is not the accepted aggregate script"
    );
    let retained_update_bytes = hex::decode(&record.latest_state.update_tx)?;
    let retained_update: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&retained_update_bytes)?;
    assert_eq!(
        bitcoin::consensus::serialize(&retained_update),
        retained_update_bytes
    );
    let retained_hash = transaction::update_template_hash(&retained_update)?;
    let retained_witness = retained_update.input[0].witness.clone();
    let rebound = transaction::rebind_update_tx(
        &retained_update,
        OutPoint {
            txid: Txid::from_str(&duplicate.txid)?,
            vout: duplicate.vout,
        },
        duplicate.value_sats,
        FeePolicy::ZeroFeeEphemeralAnchor,
    )?;
    assert_eq!(
        transaction::update_template_hash(&rebound)?,
        retained_hash,
        "retained U template hash changed during exact rebinding"
    );
    assert_eq!(
        rebound.input[0].witness, retained_witness,
        "retained U signature witness changed during rebinding"
    );
    let anchor = record
        .latest_state
        .anchors
        .iter()
        .find(|anchor| anchor.tx_role == Bip448RecoveryTemplateRole::FundingUpdate)
        .context("retained U has no FundingUpdate anchor metadata")?;
    let fee_funding = fund_p2a_fee_input()?;
    common::bitcoin_core::mine_block()?;
    let fee_input = Bip448CpfpFeeInput::keyless(fee_funding.outpoint, fee_funding.value_sats);
    let change_script =
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey();
    Ok(build_anchor_cpfp_package(
        &rebound,
        duplicate.value_sats,
        anchor.output_index,
        &[fee_input],
        change_script,
        2.0,
    )?)
}

pub(super) fn save_empty_mempool_baseline() -> Result<()> {
    assert!(
        common::bitcoin_core::raw_mempool()?.is_empty(),
        "mempool baseline must be empty before the unclean-restart eviction"
    );
    common::bitcoin_core::execute_bitcoin_command(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury savemempool",
    )?;
    Ok(())
}

pub(super) fn restart_core_dropping_unpersisted_mempool(
    config: &ClientConfig,
    expected_tip_height: u32,
    reload_wallets: bool,
) -> Result<()> {
    let flushed: serde_json::Value =
        serde_json::from_str(&common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury gettxoutsetinfo none",
        )?)?;
    assert_eq!(
        flushed.get("height").and_then(serde_json::Value::as_u64),
        Some(u64::from(expected_tip_height))
    );
    let loaded_wallets: Vec<String> =
        serde_json::from_str(&common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury listwallets",
        )?)?;
    for wallet_name in ["mercury_test", "mercury_tokens"] {
        if loaded_wallets.iter().any(|loaded| loaded == wallet_name) {
            common::bitcoin_core::execute_bitcoin_command(&format!(
                "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury unloadwallet {wallet_name}"
            ))?;
        }
    }
    let container = common::bitcoin_core::get_container_id()?;
    restart_bitcoin_core_after_unclean_stop(&container)?;
    assert_eq!(config.chain_client.tip_height()?, expected_tip_height);
    if reload_wallets {
        common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_test",
        )?;
        common::bitcoin_core::execute_bitcoin_command(
            "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury loadwallet mercury_tokens",
        )?;
    }
    Ok(())
}

pub(super) fn submit_conflict_package(package: &Bip448RecoveryPackage) -> Result<()> {
    common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])?;
    common::bitcoin_core::assert_in_mempool(&package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&package.cpfp_child_tx.txid())?;
    Ok(())
}

pub(super) fn confirm_conflict_package(
    config: &ClientConfig,
    package: &Bip448RecoveryPackage,
) -> Result<String> {
    submit_conflict_package(package)?;
    common::bitcoin_core::mine_block_with_transactions(&[
        package.parent_tx.txid(),
        package.cpfp_child_tx.txid(),
    ])?;
    let conflict_block_height = config.chain_client.tip_height()?;
    let conflict_block_hash = config
        .chain_client
        .get_block_hash(conflict_block_height)?
        .to_string();
    common::bitcoin_core::mine_blocks(config.confirmation_target.saturating_sub(1))?;
    Ok(conflict_block_hash)
}

pub(super) fn invalidate_conflict_and_evict(
    config: &ClientConfig,
    conflict_block_hash: &str,
    conflict_txid: Txid,
    reload_wallets: bool,
) -> Result<()> {
    save_empty_mempool_baseline()?;
    common::bitcoin_core::execute_bitcoin_command(&format!(
        "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury invalidateblock {conflict_block_hash}"
    ))?;
    common::bitcoin_core::assert_in_mempool(&conflict_txid)?;
    let reorg_tip = config.chain_client.tip_height()?;
    restart_core_dropping_unpersisted_mempool(config, reorg_tip, reload_wallets)?;
    common::bitcoin_core::assert_not_in_mempool(&conflict_txid)?;
    Ok(())
}

pub(super) fn duplicate_attempt_immutable_json(
    attempt: &Bip448WithdrawalAttempt,
) -> serde_json::Value {
    serde_json::json!({
        "wallet_name": attempt.wallet_name,
        "statechain_id": attempt.statechain_id,
        "binding_index": attempt.binding_index,
        "attempt_kind": attempt.attempt_kind.to_string(),
        "owner_user_pubkey": attempt.owner_user_pubkey,
        "owner_state_number": attempt.owner_state_number,
        "source_txid": attempt.source_txid,
        "source_vout": attempt.source_vout,
        "source_value_sats": attempt.source_value_sats,
        "source_script_pubkey": attempt.source_script_pubkey,
        "destination_address": attempt.destination_address,
        "destination_script_pubkey": attempt.destination_script_pubkey,
        "fee_rate_bits": attempt.fee_rate_sat_per_vbyte.to_bits(),
        "fee_sats": attempt.fee_sats,
        "lock_time": attempt.lock_time,
        "unsigned_tx_hex": attempt.unsigned_tx_hex,
        "signing_id": attempt.signing_id,
        "signed_statechain_id": attempt.signed_statechain_id,
        "sign_first_payload_json": attempt.sign_first_payload_json,
        "client_secret_nonce": attempt.client_secret_nonce,
        "client_public_nonce": attempt.client_public_nonce,
        "blinding_factor": attempt.blinding_factor,
    })
}

pub(super) async fn raw_withdrawal_attempt_journal_snapshot(
    config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
) -> Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT json_array(wallet_name,statechain_id,binding_index,attempt_kind,\
            owner_user_pubkey,owner_state_number,source_txid,source_vout,source_value_sats,\
            source_script_pubkey,destination_address,destination_script_pubkey,\
            fee_rate_sat_per_vbyte,fee_sats,lock_time,unsigned_tx_hex,signing_id,\
            signed_statechain_id,sign_first_payload_json,client_secret_nonce,\
            client_public_nonce,blinding_factor,server_public_nonce,message_hex,output_pubkey,\
            client_partial_sig,encoded_session,sign_second_payload_json,server_partial_sig,\
            aggregate_signature,signed_tx_hex,txid,phase,broadcast_status,completion_status,\
            closing_tip_height,closing_tip_hash,closing_bindings_json,created_at,updated_at) \
         FROM bip448_withdrawal_attempts WHERE wallet_name=$1 AND statechain_id=$2 \
           AND binding_index=$3",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(binding_index))
    .fetch_one(&config.pool)
    .await?)
}

pub(super) fn run_duplicate_sweep_child(
    wallet_name: &str,
    statechain_id: &str,
    duplicate_index: u32,
    destination: &str,
    checkpoint: Option<&str>,
    fail_post_sign_count: bool,
) -> Result<Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "--ignored",
            "--exact",
            "bip448_duplicate_sweep_replays_every_signing_and_broadcast_boundary",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ML_BIP448_RESTART_CHILD", "1")
        .env("ML_BIP448_DUPLICATE_SWEEP_CHILD", "1")
        .env("ML_BIP448_RESTART_WALLET", wallet_name)
        .env("ML_BIP448_RESTART_STATECHAIN_ID", statechain_id)
        .env(
            "ML_BIP448_RESTART_DUPLICATE_INDEX",
            duplicate_index.to_string(),
        )
        .env("ML_BIP448_RESTART_DESTINATION", destination)
        .env("ML_NETWORK", "regtest")
        .env_remove("ML_BIP448_TEST_CHECKPOINT")
        .env_remove("ML_BIP448_FAIL_POST_SIGN_COUNT");
    if let Some(checkpoint) = checkpoint {
        command.env("ML_BIP448_TEST_CHECKPOINT", checkpoint);
    }
    if fail_post_sign_count {
        command.env("ML_BIP448_FAIL_POST_SIGN_COUNT", "1");
    }
    Ok(command.output()?)
}

pub(super) fn require_child_exit(output: &Output, expected: i32, checkpoint: &str) -> Result<()> {
    if output.status.code() == Some(expected) {
        return Ok(());
    }
    anyhow::bail!(
        "duplicate sweep child at {checkpoint} exited {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub(super) fn json_has_duplicate_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(key, value)| {
            key.to_ascii_lowercase().contains("duplicate") || json_has_duplicate_key(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(json_has_duplicate_key),
        _ => false,
    }
}

pub(super) fn require_v2_message_without_duplicate_field(raw: &str) -> Result<Bip448TransferMsg> {
    let json: serde_json::Value = serde_json::from_str(raw)?;
    assert!(
        !json_has_duplicate_key(&json),
        "BIP448 transfer wire message unexpectedly contains duplicate metadata"
    );
    let message: Bip448TransferMsg = serde_json::from_value(json)?;
    assert_eq!(message.msg_version, 2);
    assert_eq!(serde_json::to_string(&message)?, raw);
    Ok(message)
}

pub(super) async fn bip448_transfer_artifact_counts(
    config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT \
         (SELECT COUNT(*) FROM bip448_transfer_messages WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_transfer_intents WHERE wallet_name=$1 AND statechain_id=$2),\
         (SELECT COUNT(*) FROM bip448_pending_transfer_signings WHERE wallet_name=$1 AND statechain_id=$2)",
    )
    .bind(wallet_name)
    .bind(statechain_id)
    .fetch_one(&config.pool)
    .await?)
}
