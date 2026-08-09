use crate::client_config::ClientConfig;
use anyhow::{anyhow, Ok, Result};
use chrono::Utc;
use mercurylib::{
    transfer::receiver::StatechainInfoResponsePayload, wallet::Activity,
    withdraw::WithdrawCompletePayload,
};
use reqwest::StatusCode;

pub fn estimate_fee_rate_sats_per_byte(client_config: &ClientConfig) -> Result<f64> {
    client_config.chain_client.estimate_fee_sat_per_vbyte(3)
}

pub fn create_activity(utxo: &str, amount: u32, action: &str) -> Activity {
    let date = Utc::now(); // This will get the current date and time in UTC
    let iso_string = date.to_rfc3339(); // Converts the date to an ISO 8601 string

    let activity = Activity {
        utxo: utxo.to_string(),
        amount,
        action: action.to_string(),
        date: iso_string,
    };

    activity
}

pub async fn get_statechain_info(
    statechain_id: &str,
    client_config: &ClientConfig,
) -> Result<Option<StatechainInfoResponsePayload>> {
    let path = format!("info/statechain/{}", statechain_id.to_string());

    let client = client_config.get_reqwest_client()?;
    let request = client.get(&format!("{}/{}", client_config.statechain_entity, path));

    let response = request.send().await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let value = response.text().await?;

    let response: StatechainInfoResponsePayload = serde_json::from_str(value.as_str())?;

    Ok(Some(response))
}

pub async fn complete_withdraw(
    statechain_id: &str,
    signed_statechain_id: &str,
    client_config: &ClientConfig,
) -> Result<String> {
    let endpoint = client_config.statechain_entity.clone();
    let path = "withdraw/complete";

    let client = client_config.get_reqwest_client()?;
    let request = client.post(&format!("{}/{}", endpoint, path));

    let delete_statechain_payload = WithdrawCompletePayload {
        statechain_id: statechain_id.to_string(),
        signed_statechain_id: signed_statechain_id.to_string(),
    };

    let response = request.json(&delete_statechain_payload).send().await?;

    if response.status() != 200 {
        let response_body = response.text().await?;
        return Err(anyhow!(response_body));
    }

    Ok(response.text().await?)
}
