use anyhow::{Ok, Result};
use mercuryrustlib::{client_config::ClientConfig, TokenResponse};

use crate::common::{bitcoin_core, chain};

pub async fn handle_token_response(
    client_config: &ClientConfig,
    token_response: &TokenResponse,
) -> Result<String> {
    let token_id = token_response.token_id.clone();

    if token_response.payment_method == "onchain" {
        let remaining_blocks = token_response.confirmation_target;
        let deposit_address = token_response.deposit_address.clone().unwrap();

        let amount = token_response.fee as u32;

        let _ = bitcoin_core::sendtoaddress(amount, &deposit_address)?;

        let core_wallet_address = bitcoin_core::getnewaddress()?;
        let _ = bitcoin_core::generatetoaddress(remaining_blocks as u32, &core_wallet_address)?;

        chain::wait_for_address_utxo(client_config, &deposit_address, amount).await?;
    }

    return Ok(token_id);
}
