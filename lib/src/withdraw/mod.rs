use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WithdrawCompletePayload {
    pub statechain_id: String,
    pub signed_statechain_id: String,
}