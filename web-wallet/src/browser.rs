use js_sys::Date;
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortController, Request, RequestCache, RequestInit, Response};

use crate::{
    api::{ApiResponse, Backend},
    model::STORAGE_KEY,
};

const REQUEST_TIMEOUT_MS: i32 = 65_000;

struct AbortTimeout {
    window: web_sys::Window,
    timeout_id: i32,
    _callback: Closure<dyn FnMut()>,
}

impl Drop for AbortTimeout {
    fn drop(&mut self) {
        self.window.clear_timeout_with_handle(self.timeout_id);
    }
}

#[derive(Clone, Copy)]
pub struct BrowserBackend;

impl BrowserBackend {
    pub fn new() -> Self {
        Self
    }

    fn storage() -> Result<web_sys::Storage, String> {
        let window =
            web_sys::window().ok_or_else(|| "browser window is unavailable".to_string())?;
        window
            .local_storage()
            .map_err(js_error)?
            .ok_or_else(|| "browser local storage is unavailable".to_string())
    }

    async fn fetch(
        &self,
        base_url: &str,
        path: &str,
        method: &str,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<ApiResponse, String> {
        let options = RequestInit::new();
        options.set_method(method);
        options.set_cache(RequestCache::NoStore);
        let abort_controller = AbortController::new().map_err(js_error)?;
        options.set_signal(Some(&abort_controller.signal()));
        let body_value = body.map(JsValue::from_str);
        if let Some(value) = body_value.as_ref() {
            options.set_body(value);
        }

        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let request = Request::new_with_str_and_init(&url, &options).map_err(js_error)?;
        request
            .headers()
            .set("Accept", "application/json, text/plain")
            .map_err(js_error)?;
        if let Some(content_type) = content_type {
            request
                .headers()
                .set("Content-Type", content_type)
                .map_err(js_error)?;
        }

        let window =
            web_sys::window().ok_or_else(|| "browser window is unavailable".to_string())?;
        let timeout_controller = abort_controller.clone();
        let callback = Closure::<dyn FnMut()>::new(move || timeout_controller.abort());
        let timeout_id = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                REQUEST_TIMEOUT_MS,
            )
            .map_err(js_error)?;
        let _timeout = AbortTimeout {
            window: window.clone(),
            timeout_id,
            _callback: callback,
        };

        let response = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(js_error)?
            .dyn_into::<Response>()
            .map_err(js_error)?;
        let status = response.status();
        let body = JsFuture::from(response.text().map_err(js_error)?)
            .await
            .map_err(js_error)?
            .as_string()
            .ok_or_else(|| "HTTP response was not text".to_string())?;

        Ok(ApiResponse { status, body })
    }

    #[cfg(not(feature = "e2e-harness"))]
    async fn connect_enclave(
        endpoint: &str,
        pcrs: [&str; 3],
        debug: bool,
    ) -> Result<enclavia::Client, String> {
        let endpoint = endpoint.replacen("https://", "wss://", 1);
        let pcrs = enclavia::Pcrs::from_hex(pcrs[0], pcrs[1], pcrs[2])
            .map_err(|error| error.to_string())?;
        enclavia::Client::builder(&endpoint)
            .pcrs(pcrs)
            .debug_mode(debug)
            .build()
            .await
            .map_err(|error| format!("direct enclave attestation failed: {error}"))
    }
}

impl Backend for BrowserBackend {
    async fn get(&self, base_url: &str, path: &str) -> Result<ApiResponse, String> {
        self.fetch(base_url, path, "GET", None, None).await
    }

    async fn post_json(
        &self,
        base_url: &str,
        path: &str,
        body: &str,
    ) -> Result<ApiResponse, String> {
        self.fetch(base_url, path, "POST", Some(body), Some("application/json"))
            .await
    }

    async fn post_text(
        &self,
        base_url: &str,
        path: &str,
        body: &str,
    ) -> Result<ApiResponse, String> {
        self.fetch(base_url, path, "POST", Some(body), Some("text/plain"))
            .await
    }

    #[cfg(not(feature = "e2e-harness"))]
    async fn attest_enclave(
        &self,
        endpoint: &str,
        pcrs: [&str; 3],
        debug: bool,
    ) -> Result<(), String> {
        Self::connect_enclave(endpoint, pcrs, debug).await?;
        Ok(())
    }

    /// e2e-harness builds reach the Playwright-hosted enclave stand-in over
    /// plain HTTP; the attested Noise channel itself is covered by the Rust
    /// integration suites against a real lockbox.
    #[cfg(feature = "e2e-harness")]
    async fn attest_enclave(
        &self,
        endpoint: &str,
        _pcrs: [&str; 3],
        _debug: bool,
    ) -> Result<(), String> {
        let response = self.post_json(endpoint, "attest", "{}").await?;
        if response.is_success() {
            Ok(())
        } else {
            Err(format!(
                "enclave attestation failed with {}: {}",
                response.status, response.body
            ))
        }
    }

    #[cfg(not(feature = "e2e-harness"))]
    async fn verify_enclave_statechain(
        &self,
        endpoint: &str,
        pcrs: [&str; 3],
        debug: bool,
        statechain_id: &str,
        challenge: &str,
    ) -> Result<ApiResponse, String> {
        let client = Self::connect_enclave(endpoint, pcrs, debug).await?;
        let body = serde_json::to_vec(&serde_json::json!({
            "statechain_id": statechain_id,
            "challenge": challenge,
        }))
        .map_err(|error| error.to_string())?;
        let response = client
            .post("/verify_statechain")
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| format!("direct Lockbox statechain proof failed: {error}"))?;
        Ok(ApiResponse {
            status: response.status(),
            body: response
                .text()
                .map_err(|error| error.to_string())?
                .to_string(),
        })
    }

    #[cfg(feature = "e2e-harness")]
    async fn verify_enclave_statechain(
        &self,
        endpoint: &str,
        _pcrs: [&str; 3],
        _debug: bool,
        statechain_id: &str,
        challenge: &str,
    ) -> Result<ApiResponse, String> {
        let body = serde_json::json!({
            "statechain_id": statechain_id,
            "challenge": challenge,
        });
        self.post_json(endpoint, "verify_statechain", &body.to_string())
            .await
    }

    fn checkpoint(&self, snapshot: &str) -> Result<(), String> {
        let storage = Self::storage()?;
        if storage.get_item(STORAGE_KEY).map_err(js_error)?.as_deref() != Some(snapshot) {
            storage.set_item(STORAGE_KEY, snapshot).map_err(js_error)?;
        }
        if storage.get_item(STORAGE_KEY).map_err(js_error)?.as_deref() != Some(snapshot) {
            return Err("browser storage did not retain the wallet checkpoint".to_string());
        }
        Ok(())
    }

    fn now_iso(&self) -> String {
        Date::new_0()
            .to_iso_string()
            .as_string()
            .unwrap_or_else(|| "unknown".to_string())
    }
}

fn js_error(value: JsValue) -> String {
    value
        .as_string()
        .unwrap_or_else(|| format!("browser API error: {value:?}"))
}
