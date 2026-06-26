use anyhow::{anyhow, Ok, Result};
use std::{process::Command, thread};

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
