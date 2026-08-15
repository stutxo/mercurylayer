#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;

use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;
use serde_json::Value;

use super::argv::{ArgvCommand, CommandOutput, CommandRunner, SystemCommandRunner};
use super::error::WorkflowError;
use super::model::{canonical_json, StackMetadata};
use super::ready_gate::{LiveReadyGate, ReadyGate};

const WALLET: &str = "mercury_test";
const BOOTSTRAP_BLOCKS: u64 = 101;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapReport {
    project: String,
    wallet: String,
    require_zero: bool,
    initial_confirmed_spendable_balance: String,
    final_confirmed_spendable_balance: String,
    initial_height: Option<u64>,
    final_height: Option<u64>,
    blocks_mined: u64,
}

#[derive(Clone, Debug, PartialEq)]
struct Balance {
    text: String,
    value: f64,
}

pub(super) fn execute(
    repo_root: &Path,
    metadata: &StackMetadata,
    require_zero: bool,
) -> Result<String, WorkflowError> {
    let mut runner = SystemCommandRunner;
    let mut gate = LiveReadyGate;
    let report = execute_with(repo_root, metadata, require_zero, &mut runner, &mut gate)?;
    canonical_json(&report).map_err(WorkflowError::from)
}

fn execute_with<R: CommandRunner, G: ReadyGate>(
    repo_root: &Path,
    metadata: &StackMetadata,
    require_zero: bool,
    runner: &mut R,
    gate: &mut G,
) -> Result<BootstrapReport> {
    gate.require_ready(repo_root, metadata)
        .context("require exact ready stack before wallet bootstrap")?;
    let container = inquisition_container(repo_root, metadata, runner)?;
    ensure_wallet_loaded(repo_root, &container, runner)?;
    let initial = confirmed_spendable_balance(repo_root, &container, runner)?;

    if initial.value > 0.0 {
        ensure!(
            !require_zero,
            "--require-zero rejected pre-funded wallet {WALLET} with confirmed spendable balance {}",
            initial.text
        );
        gate.require_ready(repo_root, metadata)
            .context("require exact ready stack after wallet bootstrap")?;
        return Ok(BootstrapReport {
            project: metadata.project().to_string(),
            wallet: WALLET.into(),
            require_zero,
            initial_confirmed_spendable_balance: initial.text.clone(),
            final_confirmed_spendable_balance: initial.text,
            initial_height: None,
            final_height: None,
            blocks_mined: 0,
        });
    }

    let initial_height = block_height(repo_root, &container, runner)?;
    if require_zero {
        ensure!(
            initial_height == 0,
            "--require-zero requires an exact fresh chain height of 0, found {initial_height}"
        );
    }
    let address = new_address(repo_root, &container, runner)?;
    generate_blocks(repo_root, &container, &address, runner)?;
    let final_height = block_height(repo_root, &container, runner)?;
    let expected_height = initial_height
        .checked_add(BOOTSTRAP_BLOCKS)
        .context("wallet bootstrap height overflow")?;
    ensure!(
        final_height == expected_height,
        "wallet bootstrap height transition was not exactly {initial_height} -> {expected_height}: found {final_height}"
    );
    if require_zero {
        ensure!(
            final_height == BOOTSTRAP_BLOCKS,
            "--require-zero did not produce the exact 0 -> {BOOTSTRAP_BLOCKS} height transition"
        );
    }
    let final_balance = confirmed_spendable_balance(repo_root, &container, runner)?;
    ensure!(
        final_balance.value > 0.0,
        "wallet {WALLET} has no positive confirmed spendable balance after mining {BOOTSTRAP_BLOCKS} blocks"
    );
    gate.require_ready(repo_root, metadata)
        .context("require exact ready stack after wallet bootstrap")?;

    Ok(BootstrapReport {
        project: metadata.project().to_string(),
        wallet: WALLET.into(),
        require_zero,
        initial_confirmed_spendable_balance: initial.text,
        final_confirmed_spendable_balance: final_balance.text,
        initial_height: Some(initial_height),
        final_height: Some(final_height),
        blocks_mined: BOOTSTRAP_BLOCKS,
    })
}

fn inquisition_container(
    repo_root: &Path,
    metadata: &StackMetadata,
    runner: &mut impl CommandRunner,
) -> Result<String> {
    let project = format!("label=com.docker.compose.project={}", metadata.project());
    let service = "label=com.docker.compose.service=inquisition";
    let output = checked(
        runner,
        &ArgvCommand::new("docker", repo_root).args([
            "ps",
            "--no-trunc",
            "--quiet",
            "--filter",
            &project,
            "--filter",
            service,
            "--filter",
            "status=running",
        ]),
        "resolve exact running Inquisition container",
    )?;
    let stdout = utf8(&output.stdout, "docker ps output")?;
    let ids = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        ids.len() == 1,
        "expected exactly one running Inquisition container for project {}, found {}",
        metadata.project(),
        ids.len()
    );
    ensure!(
        ids[0].len() == 64
            && ids[0]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Docker returned a malformed Inquisition container ID"
    );
    Ok(ids[0].to_owned())
}

fn ensure_wallet_loaded(
    repo_root: &Path,
    container: &str,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    if loaded_wallets(repo_root, container, runner)?
        .iter()
        .any(|name| name == WALLET)
    {
        return Ok(());
    }
    let wallets = bitcoin_json(repo_root, container, &["listwalletdir"], runner)?;
    let present = wallets
        .get("wallets")
        .and_then(Value::as_array)
        .context("listwalletdir response has no wallets array")?
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .context("listwalletdir wallet entry has no string name")
        })
        .collect::<Result<Vec<_>>>()?
        .contains(&WALLET);
    let action = if present {
        "loadwallet"
    } else {
        "createwallet"
    };
    let _ = bitcoin_checked(repo_root, container, &[action, WALLET], runner)?;
    ensure!(
        loaded_wallets(repo_root, container, runner)?
            .iter()
            .any(|name| name == WALLET),
        "wallet {WALLET} is not loaded after {action}"
    );
    Ok(())
}

fn loaded_wallets(
    repo_root: &Path,
    container: &str,
    runner: &mut impl CommandRunner,
) -> Result<Vec<String>> {
    let value = bitcoin_json(repo_root, container, &["listwallets"], runner)?;
    value
        .as_array()
        .context("listwallets response is not an array")?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .context("listwallets response contains a non-string entry")
        })
        .collect()
}

fn confirmed_spendable_balance(
    repo_root: &Path,
    container: &str,
    runner: &mut impl CommandRunner,
) -> Result<Balance> {
    let output = bitcoin_checked(
        repo_root,
        container,
        &["-rpcwallet=mercury_test", "getbalance", "*", "1", "false"],
        runner,
    )?;
    parse_balance(utf8(&output.stdout, "getbalance output")?)
}

fn parse_balance(output: &str) -> Result<Balance> {
    let text = output.trim_matches(|character: char| character.is_ascii_whitespace());
    ensure!(
        !text.is_empty(),
        "Bitcoin Core returned an empty confirmed spendable wallet balance"
    );
    let value = text.parse::<f64>().with_context(|| {
        format!("Bitcoin Core returned invalid confirmed spendable wallet balance {text:?}")
    })?;
    ensure!(
        value.is_finite() && !value.is_sign_negative(),
        "Bitcoin Core returned invalid confirmed spendable wallet balance {text:?}"
    );
    Ok(Balance {
        text: text.into(),
        value,
    })
}

fn block_height(repo_root: &Path, container: &str, runner: &mut impl CommandRunner) -> Result<u64> {
    let output = bitcoin_checked(repo_root, container, &["getblockcount"], runner)?;
    utf8(&output.stdout, "getblockcount output")?
        .trim()
        .parse()
        .context("Bitcoin Core returned a malformed nonnegative block height")
}

fn new_address(
    repo_root: &Path,
    container: &str,
    runner: &mut impl CommandRunner,
) -> Result<String> {
    let output = bitcoin_checked(
        repo_root,
        container,
        &["-rpcwallet=mercury_test", "getnewaddress"],
        runner,
    )?;
    let address = utf8(&output.stdout, "getnewaddress output")?.trim();
    ensure!(
        !address.is_empty()
            && address.len() <= 128
            && address.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "Bitcoin Core returned a malformed regtest mining address"
    );
    Ok(address.into())
}

fn generate_blocks(
    repo_root: &Path,
    container: &str,
    address: &str,
    runner: &mut impl CommandRunner,
) -> Result<()> {
    let output = bitcoin_checked(
        repo_root,
        container,
        &["generatetoaddress", "101", address],
        runner,
    )?;
    let hashes: Vec<String> = serde_json::from_slice(&output.stdout)
        .context("parse generatetoaddress response as a block-hash array")?;
    ensure!(
        hashes.len() == BOOTSTRAP_BLOCKS as usize,
        "generatetoaddress returned {} hashes instead of {BOOTSTRAP_BLOCKS}",
        hashes.len()
    );
    ensure!(
        hashes.iter().all(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        "generatetoaddress returned a malformed block hash"
    );
    Ok(())
}

fn bitcoin_json(
    repo_root: &Path,
    container: &str,
    args: &[&str],
    runner: &mut impl CommandRunner,
) -> Result<Value> {
    let output = bitcoin_checked(repo_root, container, args, runner)?;
    serde_json::from_slice(&output.stdout).context("parse Bitcoin Core JSON response")
}

fn bitcoin_checked(
    repo_root: &Path,
    container: &str,
    args: &[&str],
    runner: &mut impl CommandRunner,
) -> Result<CommandOutput> {
    checked(
        runner,
        &ArgvCommand::new("docker", repo_root)
            .args(["exec", container, "bitcoin-cli", "-regtest"])
            .args(["-rpcuser=mercury", "-rpcpassword=mercury"])
            .args(args.iter().copied()),
        "execute Bitcoin Core wallet bootstrap argv",
    )
}

fn checked(
    runner: &mut impl CommandRunner,
    command: &ArgvCommand,
    context: &str,
) -> Result<CommandOutput> {
    let output = runner.run(command)?;
    if !output.success {
        super::argv::record_failure(command, &output);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{context} failed with status {:?} signal {:?}: {}",
            output.code,
            output.signal,
            stderr.trim()
        );
    }
    ensure!(
        output.code == Some(0) && output.signal.is_none(),
        "{context} returned an inconsistent success status"
    );
    Ok(output)
}

fn utf8<'a>(bytes: &'a [u8], context: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).with_context(|| format!("{context} is not UTF-8"))
}
