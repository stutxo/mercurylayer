use std::{cell::RefCell, collections::VecDeque, rc::Rc, str::FromStr};

use bitcoin::{
    absolute, hashes::Hash, Address, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};

use crate::{
    api::{ApiResponse, Backend},
    client::WalletClient,
    model::WalletSnapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    PostJson,
    PostText,
}

#[derive(Debug, Clone)]
pub struct Step {
    pub method: Method,
    pub path: String,
    pub response: ApiResponse,
}

impl Step {
    pub fn json(method: Method, path: impl Into<String>, body: serde_json::Value) -> Self {
        Self {
            method,
            path: path.into(),
            response: ApiResponse {
                status: 200,
                body: body.to_string(),
            },
        }
    }

    pub fn text(method: Method, path: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            response: ApiResponse {
                status: 200,
                body: body.into(),
            },
        }
    }

    pub fn status(
        method: Method,
        path: impl Into<String>,
        status: u16,
        body: impl Into<String>,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            response: ApiResponse {
                status,
                body: body.into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRequest {
    pub method: Method,
    pub base_url: String,
    pub path: String,
    pub body: Option<String>,
}

#[derive(Clone, Default)]
pub struct ScriptedBackend {
    steps: Rc<RefCell<VecDeque<Step>>>,
    requests: Rc<RefCell<Vec<ObservedRequest>>>,
    checkpoints: Rc<RefCell<Vec<String>>>,
}

impl ScriptedBackend {
    pub fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: Rc::new(RefCell::new(steps.into_iter().collect())),
            requests: Rc::new(RefCell::new(Vec::new())),
            checkpoints: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn requests(&self) -> Vec<ObservedRequest> {
        self.requests.borrow().clone()
    }

    pub fn checkpoints(&self) -> Vec<String> {
        self.checkpoints.borrow().clone()
    }

    pub fn assert_exhausted(&self) {
        assert!(
            self.steps.borrow().is_empty(),
            "unconsumed scripted requests: {:?}",
            self.steps.borrow()
        );
    }

    fn respond(
        &self,
        method: Method,
        base_url: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<ApiResponse, String> {
        self.requests.borrow_mut().push(ObservedRequest {
            method,
            base_url: base_url.to_string(),
            path: path.to_string(),
            body: body.map(str::to_string),
        });
        let step = self
            .steps
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| format!("unexpected {method:?} {path}"))?;
        if step.method != method || step.path != path {
            return Err(format!(
                "expected {:?} {}, observed {method:?} {path}",
                step.method, step.path
            ));
        }
        Ok(step.response)
    }
}

impl Backend for ScriptedBackend {
    async fn get(&self, base_url: &str, path: &str) -> Result<ApiResponse, String> {
        self.respond(Method::Get, base_url, path, None)
    }

    async fn post_json(
        &self,
        base_url: &str,
        path: &str,
        body: &str,
    ) -> Result<ApiResponse, String> {
        self.respond(Method::PostJson, base_url, path, Some(body))
    }

    async fn post_text(
        &self,
        base_url: &str,
        path: &str,
        body: &str,
    ) -> Result<ApiResponse, String> {
        self.respond(Method::PostText, base_url, path, Some(body))
    }

    fn checkpoint(&self, snapshot: &str) -> Result<(), String> {
        self.checkpoints.borrow_mut().push(snapshot.to_string());
        Ok(())
    }

    fn now_iso(&self) -> String {
        "2026-01-01T00:00:00.000Z".to_string()
    }
}

pub fn funding_transaction(snapshot: &WalletSnapshot) -> Transaction {
    let coin = snapshot
        .wallet
        .coins
        .iter()
        .find(|coin| coin.statechain_id.as_deref() == Some("statechain"))
        .unwrap();
    let script_pubkey = Address::from_str(coin.aggregated_address.as_deref().unwrap())
        .unwrap()
        .require_network(Network::Signet)
        .unwrap()
        .script_pubkey();
    Transaction {
        version: 2,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_slice(&[42; 32]).unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: 50_000,
            script_pubkey,
        }],
    }
}

pub fn recovery_snapshot() -> WalletSnapshot {
    serde_json::from_str(include_str!("../tests/fixtures/recovery-ready.json")).unwrap()
}

pub fn recovery_client(backend: ScriptedBackend) -> WalletClient<ScriptedBackend> {
    WalletClient::from_snapshot(
        include_str!("../tests/fixtures/recovery-ready.json"),
        backend,
    )
    .unwrap()
}
