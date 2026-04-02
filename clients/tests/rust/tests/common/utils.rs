use std::{thread, time::Duration};

use anyhow::{Ok, Result};
use mercuryrustlib::{client_config::ClientConfig, TokenResponse};

use crate::common::{bitcoin_core, electrs};

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

        let mut is_tx_indexed = false;
        while !is_tx_indexed {
            is_tx_indexed = electrs::check_address(client_config, &deposit_address, amount).await?;
            thread::sleep(Duration::from_secs(1));
        }
    }

    return Ok(token_id);
}
