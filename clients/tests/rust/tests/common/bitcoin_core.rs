use anyhow::{anyhow, Result};
use bitcoin::{
    consensus::encode::{deserialize, serialize},
    Address, Network, Transaction, Txid,
};
use serde_json::Value;
use std::{process::Command, str::FromStr, thread};

const BITCOIN_CONTAINER_NAME: &str = "mercurylayer-inquisition-1";
const BITCOIN_WALLET_NAME: &str = "mercury_test";
const BITCOIN_CLI: &str = "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury";

pub fn get_container_id() -> Result<String> {
    // First, get the container ID by running the docker ps command
    let output = Command::new("docker")
        .arg("ps")
        .arg("-qf")
        .arg(format!("name={}", BITCOIN_CONTAINER_NAME))
        .output()
        .expect("Failed to execute docker ps command");

    // Convert the output to a string and trim whitespace
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if container_id.is_empty() {
        return Err(anyhow!(
            "No container found with the name {}",
            BITCOIN_CONTAINER_NAME
        ));
    }

    Ok(container_id)
}

pub fn execute_bitcoin_command(bitcoin_command: &str) -> Result<String> {
    let container_id = get_container_id()?;

    let output = Command::new("docker")
        .arg("exec")
        .arg(&container_id)
        .arg("sh")
        .arg("-c")
        .arg(bitcoin_command)
        .output()
        .expect("Failed to execute docker exec command");

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout)
            .to_string()
            .trim()
            .to_string());
    } else {
        return Err(anyhow!(
            "Command execution failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
}

pub fn sendtoaddress(amount_in_sats: u32, address: &str) -> Result<String> {
    let amount = amount_in_sats as f64 / 100_000_000.0;

    let bitcoin_command = format!(
        "{} -rpcwallet={} sendtoaddress {} {}",
        BITCOIN_CLI, BITCOIN_WALLET_NAME, address, amount
    );

    execute_bitcoin_command(&bitcoin_command)
}

pub fn ensure_wallet_loaded() -> Result<()> {
    execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} createwallet {BITCOIN_WALLET_NAME} >/dev/null 2>&1 || \
         {BITCOIN_CLI} loadwallet {BITCOIN_WALLET_NAME} >/dev/null 2>&1 || true"
    ))?;

    Ok(())
}

pub fn ensure_wallet_ready() -> Result<()> {
    ensure_wallet_loaded()?;
    mine_blocks(101)
}

pub fn mine_block() -> Result<()> {
    mine_blocks(1)
}

pub fn mine_blocks(num_blocks: u32) -> Result<()> {
    let address = getnewaddress()?;
    generatetoaddress(num_blocks, &address)?;

    Ok(())
}

pub fn generatetoaddress(num_blocks: u32, address: &str) -> Result<String> {
    let bitcoin_command = format!(
        "{} generatetoaddress {} {}",
        BITCOIN_CLI, num_blocks, address
    );

    let res = execute_bitcoin_command(&bitcoin_command);

    // The command may take some time to execute
    thread::sleep(std::time::Duration::from_secs(1));

    res
}

pub fn getnewaddress() -> Result<String> {
    let bitcoin_command = format!(
        "{} -rpcwallet={} getnewaddress",
        BITCOIN_CLI, BITCOIN_WALLET_NAME
    );

    execute_bitcoin_command(&bitcoin_command)
}

pub fn regtest_address(address: &str) -> Result<Address> {
    Ok(Address::from_str(address)?.require_network(Network::Regtest)?)
}

pub fn wallet_transaction(txid: &Txid) -> Result<Transaction> {
    let tx_json = execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} -rpcwallet={BITCOIN_WALLET_NAME} gettransaction {txid}"
    ))?;
    let tx_json: Value = serde_json::from_str(&tx_json)?;
    let tx_hex = tx_json
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("wallet transaction {txid} did not include raw hex"))?;
    let tx_bytes = hex::decode(tx_hex)?;

    Ok(deserialize(&tx_bytes)?)
}

pub fn broadcast_raw_transaction(tx: &Transaction) -> Result<Txid> {
    let tx_hex = hex::encode(serialize(tx));
    let txid = execute_bitcoin_command(&format!("{BITCOIN_CLI} sendrawtransaction {tx_hex}"))?;

    Ok(Txid::from_str(&txid)?)
}

pub fn submit_package(txs: &[Transaction]) -> Result<Value> {
    let tx_hexes = txs
        .iter()
        .map(|tx| hex::encode(serialize(tx)))
        .collect::<Vec<_>>();
    let package_json = serde_json::to_string(&tx_hexes)?;
    let response =
        execute_bitcoin_command(&format!("{BITCOIN_CLI} submitpackage '{}'", package_json))?;

    Ok(serde_json::from_str(&response)?)
}

pub fn raw_mempool() -> Result<Vec<Txid>> {
    let response = execute_bitcoin_command(&format!("{BITCOIN_CLI} getrawmempool"))?;
    let txids = serde_json::from_str::<Vec<String>>(&response)?
        .into_iter()
        .map(|txid| Txid::from_str(&txid))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(txids)
}

pub fn assert_in_mempool(txid: &Txid) -> Result<()> {
    if !raw_mempool()?.contains(txid) {
        return Err(anyhow!("transaction {txid} was not accepted into mempool"));
    }

    Ok(())
}

pub fn assert_not_in_mempool(txid: &Txid) -> Result<()> {
    if raw_mempool()?.contains(txid) {
        return Err(anyhow!("transaction {txid} unexpectedly entered mempool"));
    }

    Ok(())
}

pub fn assert_confirmed(txid: &Txid) -> Result<()> {
    let tx_json = execute_bitcoin_command(&format!("{BITCOIN_CLI} getrawtransaction {txid} true"))?;
    let tx_json: Value = serde_json::from_str(&tx_json)?;
    let confirmations = tx_json
        .get("confirmations")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    if confirmations == 0 {
        return Err(anyhow!("transaction {txid} was not mined"));
    }

    Ok(())
}
