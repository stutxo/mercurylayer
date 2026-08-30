#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

mod api;
mod client;
mod model;
mod transfer;
mod withdraw;

#[cfg(test)]
mod test_support;

#[cfg(target_arch = "wasm32")]
mod browser;

#[cfg(target_arch = "wasm32")]
use browser::BrowserBackend;
#[cfg(target_arch = "wasm32")]
use client::WalletClient;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct MercuryWallet {
    inner: WalletClient<BrowserBackend>,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl MercuryWallet {
    #[wasm_bindgen(js_name = create)]
    pub async fn create() -> Result<MercuryWallet, JsValue> {
        let inner = WalletClient::create(BrowserBackend::new())
            .await
            .map_err(js_error)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = fromSeedPhrase)]
    pub async fn from_seed_phrase(seed_phrase: String) -> Result<MercuryWallet, JsValue> {
        let inner = WalletClient::create_from_mnemonic(BrowserBackend::new(), seed_phrase)
            .await
            .map_err(js_error)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = fromSnapshot)]
    pub fn from_snapshot(snapshot: &str) -> Result<MercuryWallet, JsValue> {
        let inner =
            WalletClient::from_snapshot(snapshot, BrowserBackend::new()).map_err(js_error)?;
        Ok(Self { inner })
    }

    pub fn view(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.inner.view().map_err(js_error)?)
            .map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = exportSnapshot)]
    pub fn export_snapshot(&self) -> Result<String, JsValue> {
        self.inner.export_snapshot().map_err(js_error)
    }

    pub fn mnemonic(&self) -> String {
        self.inner.mnemonic().to_string()
    }

    #[wasm_bindgen(js_name = createDepositWithToken)]
    pub async fn create_deposit_with_token(
        &mut self,
        amount: u32,
        token_id: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .create_deposit_with_token(amount, token_id)
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = syncWallet)]
    pub async fn sync_wallet(&mut self) -> Result<JsValue, JsValue> {
        let result = self.inner.sync().await.map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = syncTransfers)]
    pub async fn sync_transfers(&mut self) -> Result<JsValue, JsValue> {
        let result = self.inner.sync_transfers().await.map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }
    #[wasm_bindgen(js_name = createTransferAddressWithBatch)]
    pub fn create_transfer_address_with_batch(
        &mut self,
        generate_batch_id: bool,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .create_transfer_address_with_batch(generate_batch_id)
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = sendStatecoinWithOptions)]
    pub async fn send_statecoin_with_options(
        &mut self,
        statechain_id: &str,
        recipient_address: &str,
        batch_id: Option<String>,
        acknowledge_cooperative_duplicates: bool,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .send_statecoin_with_options(
                statechain_id,
                recipient_address,
                batch_id,
                acknowledge_cooperative_duplicates,
            )
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = cancelStatecoinTransfer)]
    pub async fn cancel_statecoin_transfer(
        &mut self,
        statechain_id: &str,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .cancel_statecoin_transfer(statechain_id)
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = withdrawStatecoin)]
    pub async fn withdraw_statecoin(
        &mut self,
        statechain_id: &str,
        destination_address: &str,
        fee_rate: f64,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .withdraw_statecoin(statechain_id, destination_address, fee_rate)
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = sweepDuplicate)]
    pub async fn sweep_duplicate(
        &mut self,
        statechain_id: &str,
        duplicate_index: u32,
        destination_address: &str,
        fee_rate: f64,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .sweep_duplicate(
                statechain_id,
                duplicate_index,
                destination_address,
                fee_rate,
            )
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = receiveStatecoins)]
    pub async fn receive_statecoins(&mut self) -> Result<JsValue, JsValue> {
        let result = self.inner.receive_statecoins().await.map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = submitUnilateralExit)]
    pub async fn submit_unilateral_exit(
        &mut self,
        statechain_id: &str,
        role: &str,
        fee_rate: f64,
    ) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .submit_unilateral_exit(statechain_id, role, fee_rate)
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }

    #[wasm_bindgen(js_name = verifyEnclave)]
    pub async fn verify_enclave(&mut self, statechain_id: &str) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .verify_enclave(statechain_id)
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }
    #[wasm_bindgen(js_name = verifyEnclaveRuntime)]
    pub async fn verify_enclave_runtime(&mut self) -> Result<JsValue, JsValue> {
        let result = self
            .inner
            .verify_enclave_runtime()
            .await
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&result).map_err(|error| js_error(error.to_string()))
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[cfg(target_arch = "wasm32")]
fn js_error(error: impl Into<String>) -> JsValue {
    JsValue::from_str(&error.into())
}
