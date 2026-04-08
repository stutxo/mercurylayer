use anyhow::Result;
use mercurylib::wallet::{generate_mnemonic, Settings, Wallet};

use crate::{client_config::ClientConfig, utils::info_config};

pub async fn create_wallet(name: &str, client_config: &ClientConfig) -> Result<Wallet> {
    let mnemonic = generate_mnemonic()?;

    let server_info = info_config(&client_config).await?;

    let blockheight = client_config.chain_client.tip_height()?;

    let chain_backend = client_config.chain_backend.to_string();
    let chain_endpoint = match chain_backend.as_str() {
        "electrum" => client_config.electrum_server_url.to_string(),
        "core" => client_config
            .core_rpc_url
            .clone()
            .expect("Bitcoin Core backend selected without core_rpc_url"),
        other => panic!("Unsupported chain backend: {}", other),
    };
    let chain_type = match chain_backend.as_str() {
        "electrum" => Some(client_config.electrum_type.to_string()),
        _ => None,
    };

    let notifications = false;
    let tutorials = false;

    let settings = Settings {
        network: client_config.network.to_string(),
        block_explorerURL: None,
        torProxyHost: None,
        torProxyPort: None,
        torProxyControlPassword: None,
        torProxyControlPort: None,
        statechainEntityApi: client_config.statechain_entity.to_string(),
        torStatechainEntityApi: None,
        chainBackend: chain_backend.clone(),
        chainUrl: chain_endpoint.clone(),
        chainType: chain_type,
        notifications,
        tutorials,
    };

    let wallet = Wallet {
        name: name.to_string(),
        mnemonic,
        version: String::from("0.1.0"),
        state_entity_endpoint: client_config.statechain_entity.to_string(),
        chain_backend,
        chain_endpoint,
        network: client_config.network.to_string(),
        blockheight,
        initlock: server_info.initlock,
        interval: server_info.interval,
        tokens: Vec::new(),
        activities: Vec::new(),
        coins: Vec::new(),
        settings,
    };

    // save wallet to database

    Ok(wallet)
}
