use crate::utils::create_activity;
use std::str::FromStr;

use anyhow::{anyhow, Ok, Result};
use bitcoin::Address;
use mercurylib::{
    bip448_statechain::{deposit as bip448_deposit, storage::Bip448StatechainRecord},
    utils::is_enclave_pubkey_part_of_coin,
    wallet::{Activity, BackupTx, Coin, CoinStatus},
};

use crate::{
    chain::ChainUtxo,
    client_config::ClientConfig,
    deposit::{create_bip448_deposit_state, create_tx1},
    sqlite_manager::{
        delete_bip448_pending_deposit_signing, get_bip448_statechain_optional, get_wallet,
        insert_backup_txs, update_wallet,
    },
};

struct DepositResult {
    activity: Activity,
    backup_tx: BackupTx,
}

struct Bip448DepositResult {
    activity: Activity,
}

async fn check_deposit(
    client_config: &ClientConfig,
    coin: &mut Coin,
    wallet_netwotk: &str,
) -> Result<Option<DepositResult>> {
    if coin.statechain_id.is_none() && coin.utxo_txid.is_none() && coin.utxo_vout.is_none() {
        if coin.status != CoinStatus::INITIALISED {
            return Err(anyhow!(
                "Coin does not have a statechain ID, a UTXO and the status is not INITIALISED"
            ));
        } else {
            return Ok(None);
        }
    }

    let mut utxo: Option<ChainUtxo> = None;

    let address = Address::from_str(&coin.aggregated_address.as_ref().unwrap())?
        .require_network(client_config.network)?;

    let utxo_list = client_config
        .chain_client
        .list_unspent(address.script_pubkey().as_script())?;

    for unspent in utxo_list {
        if unspent.value == coin.amount.unwrap() as u64 {
            utxo = Some(unspent);
            break;
        }
    }

    // No deposit found. No change in the coin status
    if utxo.is_none() {
        return Ok(None);
        // return Err(anyhow!("There is no UTXO with the address {} and the amount {}", coin.aggregated_address.as_ref().unwrap(), coin.amount.unwrap()));
    }

    let utxo = utxo.unwrap();

    // IN_MEMPOOL. there is nothing to do
    if utxo.height == 0 && coin.status == CoinStatus::IN_MEMPOOL {
        return Ok(None);
    }

    let blockheight = client_config.chain_client.tip_height()?;

    let mut deposit_result: Option<DepositResult> = None;

    if coin.status == CoinStatus::INITIALISED {
        let utxo_txid = utxo.txid.clone();
        let utxo_vout = utxo.vout;

        if coin.status != CoinStatus::INITIALISED {
            return Err(anyhow!(
                "The coin with the public key {} is not in the INITIALISED state",
                coin.user_pubkey.to_string()
            ));
        }

        coin.utxo_txid = Some(utxo_txid.to_string());
        coin.utxo_vout = Some(utxo_vout);

        coin.status = CoinStatus::IN_MEMPOOL;

        let backup_tx = create_tx1(client_config, coin, wallet_netwotk, 1u32).await?;

        let activity_utxo = format!("{}:{}", utxo.txid, utxo.vout);

        let activity = Some(create_activity(
            &activity_utxo,
            utxo.value as u32,
            "deposit",
        ));

        deposit_result = Some(DepositResult {
            activity: activity.unwrap(),
            backup_tx,
        });
    }

    if utxo.height > 0 {
        let confirmations = blockheight - utxo.height + 1;

        coin.status = CoinStatus::UNCONFIRMED;

        if confirmations as u32 >= client_config.confirmation_target {
            coin.status = CoinStatus::CONFIRMED;
        }
    }

    Ok(deposit_result)
}

async fn check_bip448_deposit(
    client_config: &ClientConfig,
    wallet_name: &str,
    coin: &mut Coin,
    wallet_network: &str,
) -> Result<Option<Bip448DepositResult>> {
    if coin.statechain_id.is_none() && coin.utxo_txid.is_none() && coin.utxo_vout.is_none() {
        if coin.status != CoinStatus::INITIALISED {
            return Err(anyhow!(
                "BIP448 coin does not have a statechain ID, a UTXO and the status is not INITIALISED"
            ));
        }

        return Ok(None);
    }

    let address = Address::from_str(
        coin.aggregated_address
            .as_ref()
            .ok_or_else(|| anyhow!("BIP448 coin missing aggregated_address"))?,
    )?
    .require_network(client_config.network)?;
    let utxo_list = client_config
        .chain_client
        .list_unspent(address.script_pubkey().as_script())?;
    let utxo = match (coin.utxo_txid.as_ref(), coin.utxo_vout) {
        // Once the funding outpoint is known, match on it deterministically
        // rather than by value (list_unspent order is not stable, and equal
        // value UTXOs at the same address would otherwise be ambiguous).
        (Some(txid), Some(vout)) => utxo_list
            .into_iter()
            .find(|unspent| &unspent.txid == txid && unspent.vout == vout),
        // Initial detection: match the expected funding amount at this address.
        _ => {
            let expected_value = match coin.amount {
                Some(amount) => amount as u64,
                None => return Ok(None),
            };
            utxo_list
                .into_iter()
                .find(|unspent| unspent.value == expected_value)
        }
    };

    if utxo.is_none() {
        return Ok(None);
    }

    let utxo = utxo.unwrap();
    let blockheight = client_config.chain_client.tip_height()?;
    let mut deposit_result = None;

    if coin.utxo_txid.is_none() || coin.utxo_vout.is_none() {
        if coin.status != CoinStatus::INITIALISED {
            return Err(anyhow!(
                "The BIP448 coin with public key {} is not in the INITIALISED state",
                coin.user_pubkey
            ));
        }

        coin.utxo_txid = Some(utxo.txid.clone());
        coin.utxo_vout = Some(utxo.vout);
        coin.status = CoinStatus::IN_MEMPOOL;
    }

    if utxo.height == 0 {
        return Ok(None);
    }

    let confirmations = blockheight.saturating_sub(utxo.height).saturating_add(1);
    coin.status = CoinStatus::UNCONFIRMED;

    if coin.public_nonce.is_none() {
        let statechain_id = coin
            .statechain_id
            .as_ref()
            .ok_or_else(|| anyhow!("BIP448 coin missing statechain_id"))?
            .clone();

        if let Some(record) =
            get_bip448_statechain_optional(&client_config.pool, wallet_name, &statechain_id).await?
        {
            restore_bip448_deposit_state_from_record(
                coin, &record, &utxo.txid, utxo.vout, utxo.value,
            )?;
            delete_bip448_pending_deposit_signing(&client_config.pool, wallet_name, &statechain_id)
                .await?;
        } else {
            create_bip448_deposit_state(
                client_config,
                wallet_name,
                coin,
                wallet_network,
                &utxo.txid,
                utxo.vout,
                utxo.value,
            )
            .await?;
        }

        let activity_utxo = format!("{}:{}", utxo.txid, utxo.vout);
        deposit_result = Some(Bip448DepositResult {
            activity: create_activity(&activity_utxo, utxo.value as u32, "bip448_deposit"),
        });
    }

    if confirmations as u32 >= client_config.confirmation_target {
        coin.status = CoinStatus::CONFIRMED;
    }

    Ok(deposit_result)
}

fn restore_bip448_deposit_state_from_record(
    coin: &mut Coin,
    record: &Bip448StatechainRecord,
    funding_txid: &str,
    funding_vout: u32,
    funding_value_sats: u64,
) -> Result<()> {
    let statechain_id = coin
        .statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("BIP448 coin missing statechain_id"))?;

    if record.statechain_id != *statechain_id {
        return Err(anyhow!(
            "persisted BIP448 deposit statechain_id does not match wallet coin"
        ));
    }

    if record.funding_outpoint.txid != funding_txid
        || record.funding_outpoint.vout != funding_vout
        || record.funding_outpoint.value_sats != funding_value_sats
    {
        return Err(anyhow!(
            "persisted BIP448 deposit funding outpoint does not match wallet coin"
        ));
    }

    let signing_metadata = &record.latest_state.signing_metadata;
    coin.public_nonce = Some(signing_metadata.client_public_nonce.clone());
    coin.server_public_nonce = Some(signing_metadata.server_public_nonce.clone());
    coin.blinding_factor = Some(signing_metadata.blinding_factor.clone());

    Ok(())
}

async fn check_transfer(client_config: &ClientConfig, coin: &Coin) -> Result<bool> {
    if coin.statechain_id.is_none() {
        return Err(anyhow!("Coin does not have a statechain ID"));
    }

    let statechain_id = coin.statechain_id.as_ref().unwrap();

    let statechain_info = crate::utils::get_statechain_info(statechain_id, &client_config).await?;

    // if the statechain info is not found, we assume the coin has been transferred
    if statechain_info.is_none() {
        return Ok(true);
    }

    let statechain_info = statechain_info.unwrap();

    let enclave_public_key = statechain_info.enclave_public_key;

    // if the enclave's public key is no longer part of the coin, the coin has been transferred
    let is_transferred = !is_enclave_pubkey_part_of_coin(&coin, &enclave_public_key)?;

    return Ok(is_transferred);
}

async fn check_withdrawal(client_config: &ClientConfig, coin: &mut Coin) -> Result<()> {
    let mut txid: Option<String> = None;

    if coin.tx_withdraw.is_some() {
        txid = Some(coin.tx_withdraw.as_ref().unwrap().to_string());
    }

    if coin.tx_cpfp.is_some() {
        if txid.is_some() {
            return Err(anyhow!("Coin has both tx_withdraw and tx_cpfp"));
        }
        txid = Some(coin.tx_cpfp.as_ref().unwrap().to_string());
    }

    if txid.is_none() {
        return Err(anyhow!("Coin does not have tx_withdraw or tx_cpfp"));
    }

    let txid = txid.unwrap();

    if coin.withdrawal_address.is_none() {
        return Err(anyhow!("Coin does not have withdrawal_address"));
    }

    let address = Address::from_str(&coin.withdrawal_address.as_ref().unwrap())?
        .require_network(client_config.network)?;

    let utxo_list = client_config
        .chain_client
        .list_unspent(address.script_pubkey().as_script())?;

    let mut utxo: Option<ChainUtxo> = None;

    for unspent in utxo_list {
        if unspent.txid == txid {
            utxo = Some(unspent);
            break;
        }
    }

    if utxo.is_none() {
        // Sometimes the configured chain backend has not observed the transaction yet.
        // return Err(anyhow!("There is no UTXO with the address {} and the txid {}", coin.withdrawal_address.as_ref().unwrap(), txid));
        return Ok(());
    }

    let utxo = utxo.unwrap();

    if utxo.height > 0 {
        let blockheight = client_config.chain_client.tip_height()?;

        let confirmations = blockheight - utxo.height + 1;

        if confirmations as u32 >= client_config.confirmation_target {
            coin.status = CoinStatus::WITHDRAWN;
        }
    }

    Ok(())
}

async fn check_for_duplicated(
    client_config: &ClientConfig,
    existing_coins: &Vec<Coin>,
) -> Result<Vec<Coin>> {
    let mut duplicated_coin_list: Vec<Coin> = Vec::new();

    for coin in existing_coins.iter() {
        if coin.status != CoinStatus::IN_MEMPOOL
            && coin.status != CoinStatus::UNCONFIRMED
            && coin.status != CoinStatus::CONFIRMED
        {
            continue;
        }

        if bip448_deposit::is_bip448_coin(coin) {
            continue;
        }

        let address = Address::from_str(&coin.aggregated_address.as_ref().unwrap())?
            .require_network(client_config.network)?;

        let utxo_list = client_config
            .chain_client
            .list_unspent(address.script_pubkey().as_script())?;

        let mut max_duplicated_index = existing_coins
            .iter()
            .filter(|c| c.statechain_id == coin.statechain_id)
            .map(|coin| coin.duplicate_index)
            .max()
            .unwrap();

        for unspent in utxo_list {
            let utxo_exists = existing_coins.iter().any(|coin| {
                coin.utxo_txid == Some(unspent.txid.clone()) && coin.utxo_vout == Some(unspent.vout)
            });

            if utxo_exists {
                continue;
            }

            max_duplicated_index = max_duplicated_index + 1;

            let mut duplicated_coin = coin.clone();
            duplicated_coin.status = CoinStatus::DUPLICATED;
            duplicated_coin.utxo_txid = Some(unspent.txid);
            duplicated_coin.utxo_vout = Some(unspent.vout);
            duplicated_coin.amount = Some(unspent.value as u32);
            duplicated_coin.duplicate_index = max_duplicated_index;
            duplicated_coin_list.push(duplicated_coin);
        }
    }

    Ok(duplicated_coin_list)
}

pub async fn update_coins(client_config: &ClientConfig, wallet_name: &str) -> Result<()> {
    let mut wallet: mercurylib::wallet::Wallet =
        get_wallet(&client_config.pool, &wallet_name).await?;

    let network = wallet.network.clone();

    for coin in wallet.coins.iter_mut() {
        if coin.status == CoinStatus::INITIALISED
            || coin.status == CoinStatus::IN_MEMPOOL
            || coin.status == CoinStatus::UNCONFIRMED
        {
            if bip448_deposit::is_bip448_coin(coin) {
                let deposit_result =
                    check_bip448_deposit(client_config, &wallet.name, coin, &network).await?;

                if let Some(deposit_result) = deposit_result {
                    wallet.activities.push(deposit_result.activity);
                }

                continue;
            }

            let deposit_result = check_deposit(client_config, coin, &network).await?;

            if deposit_result.is_some() {
                let deposit_result = deposit_result.unwrap();
                let activity = deposit_result.activity;
                let backup_tx = deposit_result.backup_tx;

                wallet.activities.push(activity);
                insert_backup_txs(
                    &client_config.pool,
                    &wallet.name,
                    &coin.statechain_id.as_ref().unwrap(),
                    &[backup_tx].to_vec(),
                )
                .await?;
            }
        } else if coin.status == CoinStatus::IN_TRANSFER {
            let is_transferred = check_transfer(client_config, coin).await?;

            if is_transferred {
                coin.status = CoinStatus::TRANSFERRED;
            }
        } else if coin.status == CoinStatus::WITHDRAWING {
            check_withdrawal(client_config, coin).await?;
        }
    }

    let duplicated_coins = check_for_duplicated(client_config, &wallet.coins).await?;

    wallet.coins.extend(duplicated_coins);

    // invalidate duplicated coins that were not transferred
    for i in 0..wallet.coins.len() {
        if wallet.coins[i].status == CoinStatus::DUPLICATED {
            let is_transferred = (0..wallet.coins.len()).any(|j| {
                i != j && // Skip comparing with self
                wallet.coins[j].statechain_id == wallet.coins[i].statechain_id &&
                wallet.coins[j].locktime == wallet.coins[i].locktime &&
                wallet.coins[j].status == CoinStatus::TRANSFERRED
            });
            if is_transferred {
                wallet.coins[i].status = CoinStatus::INVALIDATED;
            }
        }
    }

    update_wallet(&client_config.pool, &wallet).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercurylib::bip448_statechain::storage::{
        Bip448AnchorOutput, Bip448CpfpChildTemplate, Bip448CsfsKeyMetadata, Bip448FeeBumpPolicy,
        Bip448FundingOutpoint, Bip448LatestState, Bip448RecoveryTemplateRole,
        Bip448SigningMetadata, Bip448ValueSchedule,
    };

    fn sample_coin() -> Coin {
        Coin {
            index: 0,
            user_privkey: "user-privkey".to_string(),
            user_pubkey: "user-pubkey".to_string(),
            auth_privkey: "auth-privkey".to_string(),
            auth_pubkey: "auth-pubkey".to_string(),
            derivation_path: "m/86h/0h/0h/0/0".to_string(),
            fingerprint: "deadbeef".to_string(),
            address: "address".to_string(),
            backup_address: "backup".to_string(),
            server_pubkey: None,
            aggregated_pubkey: None,
            aggregated_address: None,
            statechain_protocol: Some(bip448_deposit::BIP448_COIN_PROTOCOL.to_string()),
            utxo_txid: Some("aa".repeat(32)),
            utxo_vout: Some(1),
            amount: Some(50_000),
            statechain_id: Some("statechain".to_string()),
            signed_statechain_id: None,
            locktime: None,
            secret_nonce: None,
            public_nonce: None,
            blinding_factor: None,
            server_public_nonce: None,
            tx_cpfp: None,
            tx_withdraw: None,
            withdrawal_address: None,
            status: CoinStatus::UNCONFIRMED,
            duplicate_index: 0,
        }
    }

    fn sample_record(
        funding_txid: &str,
        funding_vout: u32,
        funding_value_sats: u64,
    ) -> Bip448StatechainRecord {
        let latest_state = Bip448LatestState {
            state_number: 1,
            challenge_delay: 144,
            update_tx: "02000000".to_string(),
            settlement_tx: "03000000".to_string(),
            update_template_hash: "11".repeat(32),
            settlement_template_hash: "22".repeat(32),
            state_output_script_pubkey: "5120".to_string() + &"33".repeat(32),
            funding_update_script: "51cecbcc".to_string(),
            funding_update_control_block: "c0".to_string() + &"44".repeat(32),
            state_update_script: "b175cecbcc".to_string(),
            state_update_control_block: "c0".to_string() + &"55".repeat(32),
            state_settlement_script: "20".to_string() + &"22".repeat(32) + "ce87",
            state_settlement_control_block: "c0".to_string() + &"66".repeat(32),
            csfs_key_metadata: Bip448CsfsKeyMetadata {
                aggregate_pubkey_parity_odd: true,
                negate_seckey: true,
            },
            signing_metadata: Bip448SigningMetadata {
                role: Bip448RecoveryTemplateRole::FundingUpdate,
                signing_id: "77".repeat(32),
                client_public_nonce: "88".repeat(66),
                server_public_nonce: "99".repeat(66),
                blinding_factor: "aa".repeat(32),
                update_template_hash: "11".repeat(32),
                update_signature: "bb".repeat(64),
                server_signature_count: 1,
            },
            fee_bump_policy: Bip448FeeBumpPolicy::ZeroFeeEphemeralAnchor,
            value_schedule: Bip448ValueSchedule {
                funding_value_sats,
                update_input_value_sats: funding_value_sats,
                update_state_output_value_sats: funding_value_sats,
                settlement_input_value_sats: funding_value_sats,
                settlement_recovery_output_value_sats: funding_value_sats,
            },
            anchors: vec![Bip448AnchorOutput {
                tx_role: Bip448RecoveryTemplateRole::FundingUpdate,
                output_index: 1,
                value_sats: 0,
                script_pubkey: "51024e73".to_string(),
            }],
            cpfp_child_templates: vec![Bip448CpfpChildTemplate {
                parent_role: Bip448RecoveryTemplateRole::FundingUpdate,
                anchor_output_index: 1,
                tx_hex: "03000000".to_string(),
                fee_sats: 1_000,
                target_feerate_sat_per_vbyte: Some(10),
            }],
        };

        Bip448StatechainRecord {
            wallet_name: "wallet".to_string(),
            statechain_id: "statechain".to_string(),
            aggregate_pubkey: "02".to_string() + &"12".repeat(32),
            funding_outpoint: Bip448FundingOutpoint {
                txid: funding_txid.to_string(),
                vout: funding_vout,
                value_sats: funding_value_sats,
            },
            latest_state_number: latest_state.state_number,
            challenge_delay: latest_state.challenge_delay,
            amount_sats: funding_value_sats,
            network: "regtest".to_string(),
            latest_state,
        }
    }

    #[test]
    fn bip448_deposit_recovery_restores_wallet_signing_metadata() -> Result<()> {
        let mut coin = sample_coin();
        let record = sample_record(&"aa".repeat(32), 1, 50_000);

        restore_bip448_deposit_state_from_record(&mut coin, &record, &"aa".repeat(32), 1, 50_000)?;

        assert_eq!(coin.public_nonce, Some("88".repeat(66)));
        assert_eq!(coin.server_public_nonce, Some("99".repeat(66)));
        assert_eq!(coin.blinding_factor, Some("aa".repeat(32)));

        Ok(())
    }

    #[test]
    fn bip448_deposit_recovery_rejects_mismatched_funding_outpoint() {
        let mut coin = sample_coin();
        let record = sample_record(&"bb".repeat(32), 1, 50_000);

        assert!(restore_bip448_deposit_state_from_record(
            &mut coin,
            &record,
            &"aa".repeat(32),
            1,
            50_000,
        )
        .is_err());
        assert_eq!(coin.public_nonce, None);
    }
}
