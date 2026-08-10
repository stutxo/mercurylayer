use crate::client_config::ClientConfig;
use anyhow::{anyhow, Context, Ok, Result};
use chrono::Utc;
use mercurylib::{
    transfer::receiver::StatechainInfoResponsePayload, wallet::Activity,
    withdraw::WithdrawCompletePayload,
};
use reqwest::StatusCode;

const BIP448_STATECHAIN_MISSING_BODY: &str = r#"{"message":"Statechain Id key not found."}"#;

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

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to fetch BIP448 statechain info for {statechain_id}"))?;
    let status = response.status();
    let body = response.text().await.with_context(|| {
        format!("failed to read BIP448 statechain info response for {statechain_id}")
    })?;

    parse_statechain_info_response(status, &body)
        .with_context(|| format!("invalid BIP448 statechain info response for {statechain_id}"))
}

fn parse_statechain_info_response(
    status: StatusCode,
    body: &str,
) -> Result<Option<StatechainInfoResponsePayload>> {
    if status == StatusCode::NOT_FOUND && body == BIP448_STATECHAIN_MISSING_BODY {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(anyhow!(
            "BIP448 statechain info returned HTTP {status} with body {body:?}"
        ));
    }
    let response = serde_json::from_str(body)
        .with_context(|| format!("BIP448 statechain info returned malformed JSON: {body:?}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_mercury_absence_envelope_is_missing() {
        assert!(parse_statechain_info_response(
            StatusCode::NOT_FOUND,
            BIP448_STATECHAIN_MISSING_BODY,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn different_404_body_is_not_authoritative_absence() {
        let error = parse_statechain_info_response(
            StatusCode::NOT_FOUND,
            r#"{"message":"Lockbox state not found."}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("HTTP 404"));
    }

    #[test]
    fn server_error_is_not_authoritative_absence() {
        let error = parse_statechain_info_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"message":"Internal server error"}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("HTTP 500"));
        assert!(error.to_string().contains("Internal server error"));
    }

    #[test]
    fn invalid_success_json_is_an_error() {
        let error = parse_statechain_info_response(StatusCode::OK, "not-json").unwrap_err();
        assert!(error.to_string().contains("malformed JSON"));
    }
}
