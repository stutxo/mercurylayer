mod common;

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{consensus::encode, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use common::bip448_regtest::{fund_p2a_fee_input, FUNDING_AMOUNT_SATS};
use mercurylib::bip448_statechain::{
    package::{
        build_anchor_cpfp_package, build_latest_state_recovery_package, Bip448CpfpFeeInput,
        Bip448RecoveryPackage,
    },
    storage::{Bip448RecoveryTemplateRole, Bip448StatechainRecord},
    transaction::pay_to_anchor_script,
};
use mercuryrustlib::{client_config::ClientConfig, CoinStatus, Wallet};
use serde_json::Value;

const PACKAGE_FEERATE_SAT_PER_VBYTE: f64 = 2.0;
const FEE_INPUT_COUNT: usize = 8;

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_deposit_recovers_through_update_and_settlement_packages() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet = mercuryrustlib::wallet::create_wallet("bip448-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    let record = mercuryrustlib::sqlite_manager::get_bip448_statechain(
        &client_config.pool,
        &wallet.name,
        &deposit.statechain_id,
    )
    .await?;
    let wallet =
        mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet.name).await?;
    let coin = wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some(&deposit.statechain_id))
        .context("BIP448 deposit coin not found after status update")?;
    assert_eq!(coin.statechain_protocol.as_deref(), Some("bip448"));
    assert!(matches!(
        coin.status,
        CoinStatus::UNCONFIRMED | CoinStatus::CONFIRMED
    ));

    let fee_inputs = confirmed_p2a_fee_inputs(FEE_INPUT_COUNT)?;
    let change_script = wallet_change_script()?;
    let update_tx = tx_from_hex(&record.latest_state.update_tx)?;
    let settlement_tx = tx_from_hex(&record.latest_state.settlement_tx)?;

    assert_eq!(update_tx.output[1].script_pubkey, pay_to_anchor_script());
    assert_eq!(
        settlement_tx.output[1].script_pubkey,
        pay_to_anchor_script()
    );
    assert_eq!(settlement_tx.input[0].witness.len(), 2);
    assert_ne!(settlement_tx.input[0].witness.nth(0).unwrap().len(), 64);

    assert_parent_only_rejected(&update_tx, "zero-fee BIP448 update parent")?;
    assert_committed_update_mutation_rejected(&record, &fee_inputs[0], change_script.clone())?;
    assert_anchor_mutation_rejected(
        &update_tx,
        record.funding_outpoint.value_sats,
        &fee_inputs[1],
        change_script.clone(),
    )?;

    let update_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::FundingUpdate,
        &[fee_inputs[2].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&update_package)?;
    common::bitcoin_core::assert_in_mempool(&update_package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&update_package.cpfp_child_tx.txid())?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&update_package.parent_tx.txid())?;

    let early_settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &[fee_inputs[3].clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    assert_package_rejected(&early_settlement_package, "early BIP68 settlement package")?;

    common::bitcoin_core::mine_blocks(record.challenge_delay as u32)?;

    assert_committed_settlement_mutation_rejected(&record, &fee_inputs[4], change_script.clone())?;
    assert_anchor_mutation_rejected(
        &settlement_tx,
        record
            .latest_state
            .value_schedule
            .settlement_input_value_sats,
        &fee_inputs[5],
        change_script.clone(),
    )?;

    let settlement_package = build_latest_state_recovery_package(
        &record,
        Bip448RecoveryTemplateRole::Settlement,
        &[fee_inputs[6].clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    submit_package_success(&settlement_package)?;
    common::bitcoin_core::assert_in_mempool(&settlement_package.parent_tx.txid())?;
    common::bitcoin_core::assert_in_mempool(&settlement_package.cpfp_child_tx.txid())?;
    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&settlement_package.parent_tx.txid())?;

    common::chain::wait_for_address_outpoint(
        &client_config,
        &coin.backup_address,
        OutPoint {
            txid: settlement_package.parent_tx.txid(),
            vout: 0,
        },
        u64::from(FUNDING_AMOUNT_SATS),
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[ignore = "requires docker regtest stack with Mercury server, lockbox, and active BIP448 Inquisition deployments"]
async fn bip448_client_submitter_broadcasts_recovery_package() -> Result<()> {
    let _guard = common::test_guard();

    common::bitcoin_core::ensure_wallet_loaded()?;
    common::bip448_activation::ensure_bip448_deployments_active()?;
    common::bitcoin_core::ensure_wallet_ready()?;
    let mercury_client = common::mercury::http_client();
    common::mercury::wait_until_ready(&mercury_client).await?;
    let lockbox_client = common::lockbox::http_client();
    common::lockbox::wait_until_ready(&lockbox_client).await?;

    let client_config = common::prepare_test_env().await?;
    let wallet =
        mercuryrustlib::wallet::create_wallet("bip448-submitter-wallet", &client_config).await?;
    mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;

    let deposit = create_confirmed_bip448_deposit(&client_config, &wallet).await?;
    let fee_inputs = confirmed_p2a_fee_inputs(1)?;
    let change_address = common::bitcoin_core::getnewaddress()?;

    // Exercise the client submitter end-to-end, including both mempool deduplication
    // and Bitcoin Core's response when the parent is already confirmed.
    let submit_funding_update = || {
        mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
            &client_config,
            &wallet.name,
            &deposit.statechain_id,
            Bip448RecoveryTemplateRole::FundingUpdate,
            &fee_inputs,
            &change_address,
            Some(PACKAGE_FEERATE_SAT_PER_VBYTE),
        )
    };
    let submission = submit_funding_update().await?;
    let mempool_replay = submit_funding_update().await?;

    assert_eq!(submission.role, "funding_update");
    assert_eq!(mempool_replay.parent_txid, submission.parent_txid);
    assert_eq!(mempool_replay.cpfp_child_txid, submission.cpfp_child_txid);
    let parent_txid = Txid::from_str(&submission.parent_txid)?;
    let child_txid = Txid::from_str(&submission.cpfp_child_txid)?;
    common::bitcoin_core::assert_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;

    // Mine only the parent so the fee input remains available and Core can
    // evaluate every transaction in the replayed package. Once the child is
    // also confirmed, Core instead returns an ambiguous package-level error
    // with no transaction results, which the client intentionally rejects.
    common::bitcoin_core::mine_block_with_transactions(&[parent_txid])?;
    common::bitcoin_core::assert_confirmed(&parent_txid)?;
    common::bitcoin_core::assert_not_in_mempool(&parent_txid)?;
    common::bitcoin_core::assert_in_mempool(&child_txid)?;

    let confirmed_parent_replay = submit_funding_update().await?;
    assert_eq!(confirmed_parent_replay.parent_txid, submission.parent_txid);
    assert_eq!(
        confirmed_parent_replay.cpfp_child_txid,
        submission.cpfp_child_txid
    );
    assert_ne!(
        confirmed_parent_replay
            .submitpackage_response
            .get("package_msg")
            .and_then(Value::as_str),
        Some("success")
    );
    let tx_results = confirmed_parent_replay
        .submitpackage_response
        .get("tx-results")
        .and_then(Value::as_object)
        .context("confirmed-parent replay did not include transaction results")?;
    assert_eq!(tx_results.len(), 2);
    let parent_result = tx_results
        .values()
        .find(|result| result.get("txid").and_then(Value::as_str) == Some(&submission.parent_txid))
        .context("confirmed-parent replay did not include the parent result")?;
    assert_eq!(
        parent_result.get("error").and_then(Value::as_str),
        Some("txn-already-known")
    );
    let child_result = tx_results
        .values()
        .find(|result| {
            result.get("txid").and_then(Value::as_str) == Some(&submission.cpfp_child_txid)
        })
        .context("confirmed-parent replay did not include the CPFP child result")?;
    assert!(child_result.get("error").is_none());

    common::bitcoin_core::mine_block()?;
    common::bitcoin_core::assert_confirmed(&child_txid)?;

    Ok(())
}

struct Bip448DepositFixture {
    statechain_id: String,
}

async fn create_confirmed_bip448_deposit(
    client_config: &ClientConfig,
    wallet: &Wallet,
) -> Result<Bip448DepositFixture> {
    let token_response = mercuryrustlib::deposit::get_token(client_config).await?;
    let token_id = common::utils::handle_token_response(client_config, &token_response).await?;
    let deposit_address = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
        client_config,
        &wallet.name,
        &token_id,
        FUNDING_AMOUNT_SATS,
    )
    .await?;

    let _ = common::bitcoin_core::sendtoaddress(FUNDING_AMOUNT_SATS, &deposit_address.address)?;
    common::chain::wait_for_address_utxo(
        client_config,
        &deposit_address.address,
        FUNDING_AMOUNT_SATS,
    )
    .await?;
    common::bitcoin_core::mine_block()?;
    mercuryrustlib::coin_status::update_coins(client_config, &wallet.name).await?;

    Ok(Bip448DepositFixture {
        statechain_id: deposit_address.statechain_id,
    })
}

fn confirmed_p2a_fee_inputs(count: usize) -> Result<Vec<Bip448CpfpFeeInput>> {
    let funded = (0..count)
        .map(|_| fund_p2a_fee_input())
        .collect::<Result<Vec<_>>>()?;
    common::bitcoin_core::mine_block()?;

    Ok(funded
        .into_iter()
        .map(|funding| Bip448CpfpFeeInput::keyless(funding.outpoint, funding.value_sats))
        .collect())
}

fn wallet_change_script() -> Result<ScriptBuf> {
    Ok(
        common::bitcoin_core::regtest_address(&common::bitcoin_core::getnewaddress()?)?
            .script_pubkey(),
    )
}

fn tx_from_hex(tx_hex: &str) -> Result<Transaction> {
    Ok(encode::deserialize(&hex::decode(tx_hex)?)?)
}

fn submit_package_success(package: &Bip448RecoveryPackage) -> Result<Value> {
    let response = common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])?;

    if !package_response_is_success(&response) {
        return Err(anyhow!("submitpackage did not accept package: {response}"));
    }

    Ok(response)
}

fn assert_package_rejected(package: &Bip448RecoveryPackage, context: &str) -> Result<()> {
    let response = common::bitcoin_core::submit_package(&[
        package.parent_tx.clone(),
        package.cpfp_child_tx.clone(),
    ])
    .with_context(|| format!("{context}: submitpackage invocation failed"))?;
    let package_msg = response
        .get("package_msg")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{context}: submitpackage omitted package_msg: {response}"))?;
    if package_msg == "success" {
        return Err(anyhow!(
            "{context} unexpectedly accepted by submitpackage: {response}"
        ));
    }

    common::bitcoin_core::assert_not_in_mempool(&package.parent_tx.txid())?;
    common::bitcoin_core::assert_not_in_mempool(&package.cpfp_child_tx.txid())?;

    Ok(())
}

fn assert_parent_only_rejected(parent_tx: &Transaction, context: &str) -> Result<()> {
    match common::bitcoin_core::broadcast_raw_transaction(parent_tx) {
        Ok(txid) => Err(anyhow!("{context} unexpectedly broadcast alone: {txid}")),
        Err(error) => {
            let error = error.to_string();
            if !error.contains("error code: -26") || !error.contains("min relay fee not met") {
                return Err(anyhow!(
                    "{context} broadcast failed for an unexpected reason: {error}"
                ));
            }
            common::bitcoin_core::assert_not_in_mempool(&parent_tx.txid())?;
            Ok(())
        }
    }
}

fn assert_committed_update_mutation_rejected(
    record: &Bip448StatechainRecord,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut mutated = tx_from_hex(&record.latest_state.update_tx)?;
    mutated.output[0].value -= 1;
    let package = build_anchor_cpfp_package(
        &mutated,
        record.funding_outpoint.value_sats,
        1,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;

    assert_package_rejected(&package, "mutated BIP448 update package")
}

fn assert_committed_settlement_mutation_rejected(
    record: &Bip448StatechainRecord,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut mutated = tx_from_hex(&record.latest_state.settlement_tx)?;
    mutated.output[0].value -= 1;
    let package = build_anchor_cpfp_package(
        &mutated,
        record
            .latest_state
            .value_schedule
            .settlement_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;

    assert_package_rejected(&package, "mutated BIP448 settlement package")
}

fn assert_anchor_mutation_rejected(
    parent_tx: &Transaction,
    parent_input_value_sats: u64,
    fee_input: &Bip448CpfpFeeInput,
    change_script: ScriptBuf,
) -> Result<()> {
    let mut missing_anchor = parent_tx.clone();
    missing_anchor.output.pop();
    assert!(build_anchor_cpfp_package(
        &missing_anchor,
        parent_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )
    .is_err());

    let mut mutated_anchor = parent_tx.clone();
    mutated_anchor.output[1].script_pubkey = change_script.clone();
    assert!(build_anchor_cpfp_package(
        &mutated_anchor,
        parent_input_value_sats,
        1,
        &[fee_input.clone()],
        change_script.clone(),
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )
    .is_err());

    let mut moved_anchor = parent_tx.clone();
    let replacement_anchor = moved_anchor.output[1].clone();
    moved_anchor.output[1] = TxOut {
        value: 0,
        script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
    };
    moved_anchor.output.push(replacement_anchor);
    let replacement_anchor_package = build_anchor_cpfp_package(
        &moved_anchor,
        parent_input_value_sats,
        2,
        &[fee_input.clone()],
        change_script,
        PACKAGE_FEERATE_SAT_PER_VBYTE,
    )?;
    assert_package_rejected(
        &replacement_anchor_package,
        "BIP448 parent with its committed anchor replaced and moved",
    )?;

    Ok(())
}

fn package_response_is_success(response: &Value) -> bool {
    response.get("package_msg").and_then(Value::as_str) == Some("success")
}
