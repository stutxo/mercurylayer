use anyhow::{anyhow, Result};
use bitcoin::{
    consensus::encode::{deserialize, serialize},
    Address, Network, OutPoint, Transaction, Txid,
};
use serde_json::Value;
use std::{process::Command, str::FromStr, thread};

use super::stack;

const BITCOIN_CLI: &str = "bitcoin-cli -regtest -rpcuser=mercury -rpcpassword=mercury";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletReadinessBalanceDecision {
    NeedsBootstrap,
    Ready,
}

fn wallet_readiness_balance_decision(output: &str) -> Result<WalletReadinessBalanceDecision> {
    let value = output.trim_matches(|character: char| character.is_ascii_whitespace());
    if value.is_empty() {
        return Err(anyhow!(
            "Bitcoin Core returned an empty confirmed spendable wallet balance"
        ));
    }
    let balance = value.parse::<f64>().map_err(|error| {
        anyhow!(
            "Bitcoin Core returned invalid confirmed spendable wallet balance {value:?}: {error}"
        )
    })?;
    if !balance.is_finite() || balance.is_sign_negative() {
        return Err(anyhow!(
            "Bitcoin Core returned invalid confirmed spendable wallet balance {value:?}"
        ));
    }
    if balance == 0.0 {
        Ok(WalletReadinessBalanceDecision::NeedsBootstrap)
    } else {
        Ok(WalletReadinessBalanceDecision::Ready)
    }
}

fn confirmed_spendable_wallet_balance() -> Result<WalletReadinessBalanceDecision> {
    let wallet_name = stack::current().wallet_name();
    let output = execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} -rpcwallet={wallet_name} getbalance \"*\" 1 false"
    ))?;
    wallet_readiness_balance_decision(&output)
}

pub fn get_container_id() -> Result<String> {
    stack::current().service_container_id("inquisition")
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
    let wallet_name = stack::current().wallet_name();

    let bitcoin_command = format!(
        "{} -rpcwallet={} sendtoaddress {} {}",
        BITCOIN_CLI, wallet_name, address, amount
    );

    execute_bitcoin_command(&bitcoin_command)
}

pub fn ensure_wallet_loaded() -> Result<()> {
    let wallet_name = stack::current().wallet_name();
    execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} createwallet {wallet_name} >/dev/null 2>&1 || \
         {BITCOIN_CLI} loadwallet {wallet_name} >/dev/null 2>&1 || true"
    ))?;

    Ok(())
}

pub fn ensure_wallet_ready() -> Result<()> {
    ensure_wallet_loaded()?;
    if confirmed_spendable_wallet_balance()? == WalletReadinessBalanceDecision::Ready {
        return Ok(());
    }

    mine_blocks(101)?;
    if confirmed_spendable_wallet_balance()? != WalletReadinessBalanceDecision::Ready {
        return Err(anyhow!(
            "Bitcoin Core wallet has no positive confirmed spendable balance after mining 101 blocks"
        ));
    }

    Ok(())
}

pub fn mine_block() -> Result<()> {
    mine_blocks(1)
}

pub fn mine_blocks(num_blocks: u32) -> Result<()> {
    let address = getnewaddress()?;
    generatetoaddress(num_blocks, &address)?;

    Ok(())
}

pub fn mine_block_with_transactions(txids: &[Txid]) -> Result<()> {
    let address = getnewaddress()?;
    let txids = txids.iter().map(ToString::to_string).collect::<Vec<_>>();
    let transactions = serde_json::to_string(&txids)?;
    execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} generateblock {address} '{transactions}'"
    ))?;

    thread::sleep(std::time::Duration::from_secs(1));

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
    let wallet_name = stack::current().wallet_name();
    let bitcoin_command = format!("{} -rpcwallet={} getnewaddress", BITCOIN_CLI, wallet_name);

    execute_bitcoin_command(&bitcoin_command)
}

pub fn regtest_address(address: &str) -> Result<Address> {
    Ok(Address::from_str(address)?.require_network(Network::Regtest)?)
}

pub fn wallet_transaction(txid: &Txid) -> Result<Transaction> {
    let wallet_name = stack::current().wallet_name();
    let tx_json = execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} -rpcwallet={wallet_name} gettransaction {txid}"
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

pub fn spend_wallet_outpoint(outpoint: OutPoint, value_sats: u64) -> Result<Txid> {
    const FEE_SATS: u64 = 500;
    let output_sats = value_sats
        .checked_sub(FEE_SATS)
        .ok_or_else(|| anyhow!("wallet outpoint is too small to pay the test fee"))?;
    let destination = getnewaddress()?;
    let amount = format!(
        "{}.{:08}",
        output_sats / 100_000_000,
        output_sats % 100_000_000
    );
    let unsigned = execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} createrawtransaction \
         '[{{\"txid\":\"{}\",\"vout\":{}}}]' \
         '{{\"{}\":{}}}'",
        outpoint.txid, outpoint.vout, destination, amount
    ))?;
    let wallet_name = stack::current().wallet_name();
    let signed = execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} -rpcwallet={wallet_name} \
         signrawtransactionwithwallet {unsigned}"
    ))?;
    let signed: Value = serde_json::from_str(&signed)?;
    if signed.get("complete").and_then(Value::as_bool) != Some(true) {
        return Err(anyhow!(
            "Bitcoin Core wallet did not fully sign the test spend"
        ));
    }
    let signed_hex = signed
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("signed test spend did not include transaction hex"))?;
    let txid = execute_bitcoin_command(&format!("{BITCOIN_CLI} sendrawtransaction {signed_hex}"))?;

    Ok(Txid::from_str(&txid)?)
}

pub fn set_wallet_outpoint_locked(outpoint: OutPoint, locked: bool) -> Result<()> {
    let wallet_name = stack::current().wallet_name();
    execute_bitcoin_command(&format!(
        "{BITCOIN_CLI} -rpcwallet={wallet_name} lockunspent {} \
         '[{{\"txid\":\"{}\",\"vout\":{}}}]'",
        !locked, outpoint.txid, outpoint.vout
    ))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_readiness_balance_decision_is_exact() {
        for value in ["0", "0.0", " \t0.00000000\r\n"] {
            assert_eq!(
                wallet_readiness_balance_decision(value).unwrap(),
                WalletReadinessBalanceDecision::NeedsBootstrap,
                "zero balance {value:?} must require bootstrap"
            );
        }
        for value in ["1", "0.00000001", " \t1.25000000\r\n"] {
            assert_eq!(
                wallet_readiness_balance_decision(value).unwrap(),
                WalletReadinessBalanceDecision::Ready,
                "positive balance {value:?} must be ready"
            );
        }
        for value in ["", " \t\r\n", "-1", "-0", "alphabetic", "NaN", "inf"] {
            assert!(
                wallet_readiness_balance_decision(value).is_err(),
                "invalid balance {value:?} must fail"
            );
        }
    }
}
