use crate::{
    bip448_owner::get_current_bip448_owner,
    client_config::ClientConfig,
    sqlite_manager::{begin_bip448_mutation_guard, get_wallet},
};
use anyhow::{anyhow, Result};
use bitcoin::PrivateKey;
use mercurylib::{
    transfer::sender::{
        PaymentHashRequestPayload, PaymentHashResponsePayload, TransferPreimageRequestPayload,
        TransferPreimageResponsePayload,
    },
    wallet::CoinStatus,
};
use secp256k1::{schnorr, KeyPair, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
pub struct CreatePreImageResponse {
    pub hash: String,
    pub batch_id: String,
}

pub async fn create_pre_image(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<CreatePreImageResponse> {
    let wallet: mercurylib::wallet::Wallet = get_wallet(&client_config.pool, &wallet_name).await?;
    let current_owner =
        get_current_bip448_owner(client_config, &wallet, wallet_name, statechain_id).await?;
    let coin = wallet
        .coins
        .get(current_owner.coin_index)
        .ok_or_else(|| anyhow!("current BIP448 owner index is no longer present in the wallet"))?;
    let owner_user_pubkey = PublicKey::from_str(&coin.user_pubkey)?
        .x_only_public_key()
        .0
        .to_string();
    let expected_signed_statechain_id = coin
        .signed_statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("coin.signed_statechain_id is None"))?
        .clone();

    // The guard is deliberately held across this short creation call. There
    // is no latch journal, so the transaction is the local linearization point
    // against attempt and transfer-intent creation.
    let mut guard = begin_bip448_mutation_guard(&client_config.pool).await?;
    let coin = guard
        .latch_creation_coin(
            wallet_name,
            statechain_id,
            &owner_user_pubkey,
            &expected_signed_statechain_id,
        )
        .await?;
    if coin.amount.is_none() {
        return Err(anyhow::anyhow!("coin.amount is None"));
    }
    ensure_create_pre_image_status(&coin.status)?;
    if coin.locktime.is_none() {
        return Err(anyhow::anyhow!("coin.locktime is None"));
    }
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("coin.signed_statechain_id is None"))?;
    let batch_id = uuid::Uuid::new_v4().to_string();

    let payment_hash_payload = PaymentHashRequestPayload {
        statechain_id: statechain_id.to_string(),
        auth_sig: signed_statechain_id.to_string(),
        batch_id: batch_id.clone(),
    };

    let endpoint = client_config.statechain_entity.clone();
    let path = "transfer/paymenthash";

    let client = client_config.get_reqwest_client()?;
    let request = client.post(&format!("{}/{}", endpoint, path));

    let response = request.json(&payment_hash_payload).send().await?;

    if response.status() != 200 {
        let response_body = response.text().await?;
        return Err(anyhow!(response_body));
    }

    let value = response.text().await?;

    let payment_hash_response_payload: PaymentHashResponsePayload =
        serde_json::from_str(value.as_str())?;

    guard.commit().await?;

    Ok(CreatePreImageResponse {
        hash: payment_hash_response_payload.hash,
        batch_id,
    })
}

pub async fn confirm_pending_invoice(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<()> {
    let wallet: mercurylib::wallet::Wallet = get_wallet(&client_config.pool, &wallet_name).await?;
    let current_owner =
        get_current_bip448_owner(client_config, &wallet, wallet_name, statechain_id).await?;
    let coin = wallet
        .coins
        .get(current_owner.coin_index)
        .ok_or_else(|| anyhow!("current BIP448 owner index is no longer present in the wallet"))?;
    let generation_text = current_owner
        .statechain_info
        .x1_pub
        .as_deref()
        .ok_or_else(|| anyhow!("current BIP448 transfer generation is missing"))?;
    let generation = PublicKey::from_str(generation_text)?;
    if generation.to_string() != generation_text {
        return Err(anyhow!(
            "current BIP448 transfer generation is noncanonical"
        ));
    }
    let digest = mercurylib::transfer::receiver::bip448_transfer_unlock_auth_digest(
        mercurylib::transfer::receiver::Bip448TransferUnlockRole::CurrentOwner,
        statechain_id,
        &generation,
    )?;
    let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)?.inner;
    let auth_keypair = KeyPair::from_secret_key(&Secp256k1::new(), &auth_secret);
    let auth_sig = schnorr::sign(&digest, &auth_keypair).to_string();

    let path = "transfer/unlock";

    let client = client_config.get_reqwest_client()?;
    let request = client.post(&format!("{}/{}", client_config.statechain_entity, path));

    let transfer_unlock_request_payload =
        mercurylib::transfer::receiver::TransferUnlockRequestPayload {
            statechain_id: statechain_id.to_string(),
            auth_sig,
            auth_pub_key: Some(generation.to_string()),
        };

    let status = request
        .json(&transfer_unlock_request_payload)
        .send()
        .await?
        .status();

    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to update transfer message".to_string()
        ));
    }

    Ok(())
}

pub async fn retrieve_pre_image(
    client_config: &ClientConfig,
    wallet_name: &str,
    statechain_id: &str,
    batch_id: &str,
) -> Result<String> {
    let wallet: mercurylib::wallet::Wallet = get_wallet(&client_config.pool, &wallet_name).await?;
    let coin = wallet
        .coins
        .get(historical_latch_creator_coin_index(&wallet, statechain_id)?)
        .ok_or_else(|| anyhow!("historical latch creator is no longer present in the wallet"))?;
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_ref()
        .ok_or_else(|| anyhow!("coin.signed_statechain_id is None"))?;

    let path = "transfer/transfer_preimage";

    let client = client_config.get_reqwest_client()?;
    let request = client.post(&format!("{}/{}", client_config.statechain_entity, path));

    let transfer_preimage_request_payload = TransferPreimageRequestPayload {
        statechain_id: statechain_id.to_string(),
        auth_sig: signed_statechain_id.to_string(),
        previous_user_auth_key: coin.auth_pubkey.to_string(),
        batch_id: batch_id.to_string(),
    };

    let value = request
        .json(&transfer_preimage_request_payload)
        .send()
        .await?
        .text()
        .await?;

    let transfer_preimage_response_payload: TransferPreimageResponsePayload =
        serde_json::from_str(value.as_str())?;

    Ok(transfer_preimage_response_payload.preimage)
}

pub async fn get_payment_hash(
    client_config: &ClientConfig,
    batch_id: &str,
) -> Result<Option<String>> {
    let path = format!("transfer/paymenthash/{}", batch_id);

    let client = client_config.get_reqwest_client()?;
    let request = client.get(&format!("{}/{}", client_config.statechain_entity, path));

    let response = request.send().await?;

    if response.status() == 401 {
        return Ok(None);
    } else if response.status() != 200 {
        let response_body = response.text().await?;
        return Err(anyhow!(response_body));
    }

    let value = response.text().await?;

    let payment_hash_response_payload: PaymentHashResponsePayload =
        serde_json::from_str(value.as_str())?;

    Ok(Some(payment_hash_response_payload.hash))
}

fn ensure_create_pre_image_status(status: &CoinStatus) -> Result<()> {
    if !matches!(status, CoinStatus::CONFIRMED | CoinStatus::IN_TRANSFER) {
        return Err(anyhow!(
            "Coin status must be CONFIRMED or IN_TRANSFER to transfer it. The current status is {}",
            status
        ));
    }
    Ok(())
}

// Preimage retrieval authenticates the wallet generation that created the
// latch. It is intentionally historical cleanup after ownership may rotate,
// unlike latch creation and confirmation, which require the current owner.
fn historical_latch_creator_coin_index(
    wallet: &mercurylib::wallet::Wallet,
    statechain_id: &str,
) -> Result<usize> {
    wallet
        .coins
        .iter()
        .enumerate()
        .filter(|(_, coin)| coin.statechain_id.as_deref() == Some(statechain_id))
        .min_by_key(|(_, coin)| coin.locktime.unwrap_or(u32::MAX))
        .map(|(coin_index, _)| coin_index)
        .ok_or_else(|| anyhow!("No coins associated with this statechain ID were found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercurylib::wallet::{Settings, Wallet};

    fn wallet() -> Wallet {
        Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://127.0.0.1:1".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:1".to_string(),
            network: "regtest".to_string(),
            blockheight: 0,
            activities: Vec::new(),
            coins: Vec::new(),
            settings: Settings {
                network: "regtest".to_string(),
                block_explorerURL: None,
                torProxyHost: None,
                torProxyPort: None,
                torProxyControlPassword: None,
                torProxyControlPort: None,
                statechainEntityApi: "http://127.0.0.1:1".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:1".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        }
    }

    #[test]
    fn selected_owner_create_status_gate_is_preserved() {
        assert!(ensure_create_pre_image_status(&CoinStatus::CONFIRMED).is_ok());
        assert!(ensure_create_pre_image_status(&CoinStatus::IN_TRANSFER).is_ok());
        assert!(ensure_create_pre_image_status(&CoinStatus::INITIALISED).is_err());
    }

    #[test]
    fn retrieval_uses_the_historical_latch_creator_after_owner_rotation() {
        let mut wallet = wallet();
        let mut current_owner = wallet.get_new_coin().unwrap();
        current_owner.statechain_id = Some("statechain".to_string());
        current_owner.locktime = Some(200);
        let mut latch_creator = wallet.get_new_coin().unwrap();
        latch_creator.statechain_id = Some("statechain".to_string());
        latch_creator.locktime = Some(100);
        wallet.coins = vec![current_owner, latch_creator];

        assert_eq!(
            historical_latch_creator_coin_index(&wallet, "statechain").unwrap(),
            1
        );
    }
}
