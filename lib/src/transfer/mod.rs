use serde::{Deserialize, Serialize};

pub mod bip448;
pub mod receiver;
pub mod sender;

#[derive(Debug, Serialize, Deserialize)]
pub struct TxOutpoint {
    pub txid: String,
    pub vout: u32,
}
