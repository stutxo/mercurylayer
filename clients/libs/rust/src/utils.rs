use crate::client_config::ClientConfig;
use anyhow::{anyhow, Context, Ok, Result};
use chrono::Utc;
use mercurylib::{
    bip448_statechain::signing_api::Bip448StatechainInfoResponsePayloadV1,
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
    let (status, body) = fetch_statechain_info(statechain_id, client_config).await?;

    parse_statechain_info_response(status, &body)
        .with_context(|| format!("invalid BIP448 statechain info response for {statechain_id}"))
}

pub(crate) async fn get_bip448_statechain_info_v1(
    statechain_id: &str,
    client_config: &ClientConfig,
) -> Result<Option<Bip448StatechainInfoResponsePayloadV1>> {
    let (status, body) = fetch_statechain_info(statechain_id, client_config).await?;

    parse_bip448_statechain_info_v1_response(status, &body)
        .with_context(|| format!("invalid BIP448 v1 state response for {statechain_id}"))
}

async fn fetch_statechain_info(
    statechain_id: &str,
    client_config: &ClientConfig,
) -> Result<(StatusCode, String)> {
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

    Ok((status, body))
}

fn parse_statechain_info_response(
    status: StatusCode,
    body: &str,
) -> Result<Option<StatechainInfoResponsePayload>> {
    if status == StatusCode::NOT_FOUND && body == BIP448_STATECHAIN_MISSING_BODY {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(anyhow!("BIP448 statechain info returned HTTP {status}"));
    }
    let response =
        serde_json::from_str(body).context("BIP448 statechain info returned malformed JSON")?;
    Ok(Some(response))
}

fn parse_bip448_statechain_info_v1_response(
    status: StatusCode,
    body: &str,
) -> Result<Option<Bip448StatechainInfoResponsePayloadV1>> {
    if status == StatusCode::NOT_FOUND && body == BIP448_STATECHAIN_MISSING_BODY {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(anyhow!("BIP448 v1 state returned HTTP {status}"));
    }
    let response = serde_json::from_str(body).context("BIP448 v1 state returned malformed JSON")?;
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
        let private_body = r#"{"message":"Internal server error","transaction":"redacted"}"#;
        let error = parse_statechain_info_response(StatusCode::INTERNAL_SERVER_ERROR, private_body)
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 500"));
        assert!(!error.to_string().contains(private_body));
        assert!(!error.to_string().contains("transaction"));
    }

    #[test]
    fn invalid_success_json_is_an_error() {
        let error = parse_statechain_info_response(StatusCode::OK, "not-json").unwrap_err();
        assert!(error.to_string().contains("malformed JSON"));
        assert!(!error.to_string().contains("not-json"));
    }

    #[test]
    fn exact_v1_state_observation_parses_live_n_g_and_s() {
        let body = r#"{"protocol_version":1,"enclave_public_key":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","num_sigs":2,"lockbox_key_generation":4,"statechain_info":[],"x1_pub":"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"}"#;
        let observed = parse_bip448_statechain_info_v1_response(StatusCode::OK, body)
            .unwrap()
            .unwrap();

        assert_eq!(observed.num_sigs.get(), 2);
        assert_eq!(observed.lockbox_key_generation.get(), 4);
        assert_eq!(
            hex::encode(observed.enclave_public_key.as_bytes()),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn v1_state_errors_do_not_echo_response_bodies() {
        let private_body = r#"{"transaction":"never-log-this"}"#;
        let status_error = parse_bip448_statechain_info_v1_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            private_body,
        )
        .unwrap_err();
        let parse_error =
            parse_bip448_statechain_info_v1_response(StatusCode::OK, private_body).unwrap_err();

        assert!(!status_error.to_string().contains(private_body));
        assert!(!parse_error.to_string().contains(private_body));
        assert!(!status_error.to_string().contains("transaction"));
        assert!(!parse_error.to_string().contains("transaction"));
    }
}
