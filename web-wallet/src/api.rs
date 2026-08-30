#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
}

impl ApiResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub trait Backend {
    async fn get(&self, base_url: &str, path: &str) -> Result<ApiResponse, String>;
    async fn post_json(
        &self,
        base_url: &str,
        path: &str,
        body: &str,
    ) -> Result<ApiResponse, String>;
    async fn post_text(
        &self,
        _base_url: &str,
        _path: &str,
        _body: &str,
    ) -> Result<ApiResponse, String> {
        Err("backend does not support text requests".to_string())
    }
    async fn attest_enclave(
        &self,
        endpoint: &str,
        pcrs: [&str; 3],
        debug: bool,
    ) -> Result<(), String> {
        let _ = (endpoint, pcrs, debug);
        Err("backend does not support direct enclave attestation".to_string())
    }
    async fn verify_enclave_statechain(
        &self,
        endpoint: &str,
        pcrs: [&str; 3],
        debug: bool,
        statechain_id: &str,
        challenge: &str,
    ) -> Result<ApiResponse, String> {
        let _ = (endpoint, pcrs, debug, statechain_id, challenge);
        Err("backend does not support direct enclave statechain verification".to_string())
    }
    fn checkpoint(&self, snapshot: &str) -> Result<(), String>;
    fn now_iso(&self) -> String;
}
