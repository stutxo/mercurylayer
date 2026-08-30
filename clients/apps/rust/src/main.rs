use std::{thread, time::Duration};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a wallet
    CreateWallet {
        /// The name of the wallet to create
        name: String,
    },
    /// Get new token.
    NewToken {},
    /// Get a BIP448 deposit address. Used to fund a prototype BIP448 statecoin.
    NewBip448DepositAddress {
        wallet_name: String,
        token_id: String,
        amount: u32,
    },
    /// Print the wallet-derived BIP448 recovery fee address
    Bip448RecoveryFeeAddress { wallet_name: String },
    /// Submit a BIP448 recovery parent and anchor CPFP child through the configured chain backend
    BroadcastBip448RecoveryPackage {
        wallet_name: String,
        statechain_id: String,
        /// Recovery role: funding_update or settlement
        role: String,
        /// Address that receives CPFP fee-input change
        change_address: Option<String>,
        /// Keyless P2A fee input descriptor: txid:vout:value_sats
        #[arg(
            long = "fee-input",
            required_unless_present = "fund_from_wallet",
            conflicts_with = "fund_from_wallet"
        )]
        fee_inputs: Vec<String>,
        /// Discover and sign confirmed fee inputs from the wallet-derived fee address
        #[arg(long, conflicts_with = "fee_inputs")]
        fund_from_wallet: bool,
        /// Package fee rate in sats per vbyte
        #[arg(long)]
        fee_rate: Option<f64>,
    },
    /// List wallet statecoins
    ListStatecoins { wallet_name: String },
    /// Withdraw a BIP448 statechain coin cooperatively to a bitcoin address
    Bip448Withdraw {
        wallet_name: String,
        statechain_id: String,
        to_address: String,
        /// Transaction fee rate in sats per byte
        fee_rate: Option<f64>,
    },
    /// Sweep one stable-index BIP448 duplicate without closing the statechain
    Bip448SweepDuplicate {
        wallet_name: String,
        statechain_id: String,
        #[arg(value_parser = parse_decimal_u32)]
        duplicate_index: u32,
        to_address: String,
        /// Transaction fee rate in sats per byte
        fee_rate: Option<f64>,
    },
    /// Generate a transfer address to receive funds
    NewTransferAddress {
        wallet_name: String,
        /// Generate batch id for atomic transfers
        #[arg(short = 'b', long)]
        generate_batch_id: bool,
    },
    /// Send a BIP448 statechain coin to a transfer address
    Bip448TransferSend {
        wallet_name: String,
        statechain_id: String,
        to_address: String,
        /// Batch id for atomic transfers
        batch_id: Option<String>,
        /// Acknowledge that duplicate values need independent cooperative sweeps
        #[arg(long)]
        force_send_with_duplicates: bool,
    },
    /// Cancel an in-flight BIP448 transfer by transferring back to this wallet
    Bip448TransferCancel {
        wallet_name: String,
        statechain_id: String,
    },
    /// Send a statechain coin to a transfer address
    TransferReceive { wallet_name: String },
    /// Create a payment hash for a lightning latch
    PaymentHash {
        wallet_name: String,
        statechain_id: String,
    },
    /// Confirm pending invoice
    ConfirmPendingInvoice {
        wallet_name: String,
        statechain_id: String,
    },
    /// Retrieve a payment pre-image for a lightning latch
    RetrievePreImage {
        wallet_name: String,
        statechain_id: String,
        batch_id: String,
    },
    /// Get the payment hash by batch id
    GetPaymentHash { batch_id: String },
}

fn parse_decimal_u32(value: &str) -> std::result::Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("duplicate_index must be a base-10 u32".to_owned());
    }
    value
        .parse::<u32>()
        .map_err(|_| "duplicate_index must be a base-10 u32".to_owned())
}

fn validate_command_before_io(command: &Commands) -> Result<()> {
    if let Commands::Bip448SweepDuplicate {
        duplicate_index: 0, ..
    } = command
    {
        return Err(anyhow!(
            "duplicate_index 0 is canonical and cannot be swept as a duplicate"
        ));
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // This check intentionally precedes configuration loading, which opens the
    // wallet database. The typed library entry point repeats the invariant.
    validate_command_before_io(&cli.command)?;

    let client_config = mercuryrustlib::client_config::load().await;

    match cli.command {
        Commands::CreateWallet { name } => {
            let wallet = mercuryrustlib::wallet::create_wallet(&name, &client_config).await?;

            mercuryrustlib::sqlite_manager::insert_wallet(&client_config.pool, &wallet).await?;
            println!("Wallet created: {:?}", wallet);
        }
        Commands::NewToken {} => {
            let token_response = mercuryrustlib::deposit::get_token(&client_config).await?;

            let obj = json!(token_response);

            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::NewBip448DepositAddress {
            wallet_name,
            token_id,
            amount,
        } => {
            let result = mercuryrustlib::deposit::get_bip448_deposit_bitcoin_address(
                &client_config,
                &wallet_name,
                &token_id,
                amount,
            )
            .await?;

            let obj = json!(result);

            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::Bip448RecoveryFeeAddress { wallet_name } => {
            let wallet =
                mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name)
                    .await?;
            let obj = json!({"address": wallet.bip448_recovery_fee_key()?.address});
            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::BroadcastBip448RecoveryPackage {
            wallet_name,
            statechain_id,
            role,
            change_address,
            fee_inputs,
            fund_from_wallet,
            fee_rate,
        } => {
            let role = mercuryrustlib::bip448_recovery::parse_recovery_template_role(&role)?;
            let result = if fund_from_wallet {
                mercuryrustlib::bip448_recovery::submit_wallet_funded_latest_state_recovery_package(
                    &client_config,
                    &wallet_name,
                    &statechain_id,
                    role,
                    change_address.as_deref(),
                    fee_rate,
                )
                .await?
            } else {
                let fee_inputs = fee_inputs
                    .iter()
                    .map(|input| {
                        mercuryrustlib::bip448_recovery::parse_keyless_p2a_fee_input(input)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let change_address = match change_address {
                    Some(change_address) => change_address,
                    None => mercuryrustlib::sqlite_manager::get_wallet(
                        &client_config.pool,
                        &wallet_name,
                    )
                    .await?
                    .bip448_recovery_fee_key()?
                    .address
                    .to_string(),
                };
                mercuryrustlib::bip448_recovery::submit_latest_state_recovery_package(
                    &client_config,
                    &wallet_name,
                    &statechain_id,
                    role,
                    &fee_inputs,
                    &change_address,
                    fee_rate,
                )
                .await?
            };

            let obj = json!(result);
            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::ListStatecoins { wallet_name } => {
            mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
            let wallet =
                mercuryrustlib::sqlite_manager::get_wallet(&client_config.pool, &wallet_name)
                    .await?;

            let coins_json =
                mercuryrustlib::coin_status::statecoin_list_json(&client_config, &wallet).await?;

            let coins_json_string = serde_json::to_string_pretty(&coins_json).unwrap();
            println!("{}", coins_json_string);
        }
        Commands::Bip448Withdraw {
            wallet_name,
            statechain_id,
            to_address,
            fee_rate,
        } => {
            mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
            mercuryrustlib::bip448_withdraw::execute(
                &client_config,
                &wallet_name,
                &statechain_id,
                &to_address,
                fee_rate,
            )
            .await?;
        }
        Commands::Bip448SweepDuplicate {
            wallet_name,
            statechain_id,
            duplicate_index,
            to_address,
            fee_rate,
        } => {
            let result = mercuryrustlib::bip448_withdraw::execute_duplicate_sweep(
                &client_config,
                &wallet_name,
                &statechain_id,
                duplicate_index,
                &to_address,
                fee_rate,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::NewTransferAddress {
            wallet_name,
            generate_batch_id,
        } => {
            let address = mercuryrustlib::transfer_receiver::new_transfer_address(
                &client_config,
                &wallet_name,
            )
            .await?;

            let mut obj = json!({"new_transfer_address:": address});

            if generate_batch_id {
                // Generate a random batch_id
                let batch_id = Some(uuid::Uuid::new_v4().to_string()).unwrap();

                obj["batch_id"] = json!(batch_id);
            }

            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::Bip448TransferSend {
            wallet_name,
            statechain_id,
            to_address,
            batch_id,
            force_send_with_duplicates,
        } => {
            mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
            mercuryrustlib::bip448_transfer_sender::transfer_bip448_sender_with_options(
                &client_config,
                &to_address,
                &wallet_name,
                &statechain_id,
                batch_id,
                mercuryrustlib::bip448_transfer_sender::Bip448TransferOptions {
                    acknowledge_cooperative_duplicates: force_send_with_duplicates,
                    intent: mercuryrustlib::bip448_funding::Bip448TransferIntentKind::UserTransfer,
                },
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"Transfer": "sent"})).unwrap()
            );
        }
        Commands::Bip448TransferCancel {
            wallet_name,
            statechain_id,
        } => {
            mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;
            let state_number = mercuryrustlib::bip448_transfer_sender::cancel_bip448_transfer(
                &client_config,
                &wallet_name,
                &statechain_id,
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"state_number": state_number})).unwrap()
            );
        }
        Commands::TransferReceive { wallet_name } => {
            mercuryrustlib::coin_status::update_coins(&client_config, &wallet_name).await?;

            let mut received_statechain_ids = Vec::<String>::new();

            loop {
                let transfer_receive_result =
                    mercuryrustlib::transfer_receiver::execute(&client_config, &wallet_name)
                        .await?;
                received_statechain_ids.extend(transfer_receive_result.received_statechain_ids);

                if transfer_receive_result.is_there_batch_locked {
                    println!("Statecoin batch still locked. Waiting until expiration or unlock.");
                    thread::sleep(Duration::from_secs(5));
                } else {
                    break;
                }
            }

            let obj = json!(received_statechain_ids);

            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::PaymentHash {
            wallet_name,
            statechain_id,
        } => {
            let response = mercuryrustlib::lightning_latch::create_pre_image(
                &client_config,
                &wallet_name,
                &statechain_id,
            )
            .await?;

            let obj = json!(response);

            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::ConfirmPendingInvoice {
            wallet_name,
            statechain_id,
        } => {
            mercuryrustlib::lightning_latch::confirm_pending_invoice(
                &client_config,
                &wallet_name,
                &statechain_id,
            )
            .await?;
        }
        Commands::RetrievePreImage {
            wallet_name,
            statechain_id,
            batch_id,
        } => {
            let pre_image = mercuryrustlib::lightning_latch::retrieve_pre_image(
                &client_config,
                &wallet_name,
                &statechain_id,
                &batch_id,
            )
            .await?;

            let obj = json!({"pre_image": pre_image});

            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
        Commands::GetPaymentHash { batch_id } => {
            let payment_hash =
                mercuryrustlib::lightning_latch::get_payment_hash(&client_config, &batch_id)
                    .await?;

            let obj = json!({"payment_hash": payment_hash});

            println!("{}", serde_json::to_string_pretty(&obj).unwrap());
        }
    }

    client_config.pool.close().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercuryrustlib::{
        bip448_funding::{
            Bip448BindingRole, Bip448FundingBinding, Bip448ObservationStatus, Bip448OwnershipStatus,
        },
        Coin, CoinStatus,
    };

    fn list_coin() -> Coin {
        Coin {
            index: 0,
            user_privkey: String::new(),
            user_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
            auth_privkey: String::new(),
            auth_pubkey: String::new(),
            derivation_path: String::new(),
            fingerprint: String::new(),
            address: "transfer-address".into(),
            backup_address: "recovery-address".into(),
            server_pubkey: None,
            aggregated_pubkey: None,
            aggregated_address: Some("aggregate-address".into()),
            statechain_protocol: Some("bip448".into()),
            utxo_txid: None,
            utxo_vout: None,
            amount: Some(100_000),
            statechain_id: Some("statechain".into()),
            signed_statechain_id: None,
            locktime: None,
            secret_nonce: None,
            public_nonce: None,
            blinding_factor: None,
            server_public_nonce: None,
            tx_withdraw: None,
            withdrawal_address: None,
            status: CoinStatus::CONFIRMED,
        }
    }

    fn list_binding(
        index: u32,
        value_sats: u64,
        observation_status: Bip448ObservationStatus,
        ownership_status: Bip448OwnershipStatus,
    ) -> Bip448FundingBinding {
        Bip448FundingBinding {
            wallet_name: "wallet".into(),
            statechain_id: "statechain".into(),
            binding_index: index,
            txid: format!("{:02x}", index + 1).repeat(32),
            vout: index,
            value_sats,
            script_pubkey: "51".into(),
            role: if index == 0 {
                Bip448BindingRole::Canonical
            } else {
                Bip448BindingRole::Duplicate
            },
            observation_status,
            funding_height: Some(1),
            spend_txid: (observation_status == Bip448ObservationStatus::SpentConfirmed)
                .then(|| "44".repeat(32)),
            spend_height: (observation_status == Bip448ObservationStatus::SpentConfirmed)
                .then_some(2),
            last_scanned_height: 3,
            owner_user_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
            owner_state_number: 1,
            ownership_status,
            first_seen_at: "first".into(),
            last_seen_at: "last".into(),
        }
    }

    #[test]
    fn bip448_recovery_requires_exactly_one_fee_source() {
        let base = [
            "client-rust",
            "broadcast-bip448-recovery-package",
            "wallet",
            "statechain",
            "update",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        assert!(Cli::try_parse_from(base.into_iter().chain(["--fund-from-wallet"])).is_ok());
        assert!(Cli::try_parse_from(
            base.into_iter()
                .chain(["--fee-input", &format!("{}:0:20000", "11".repeat(32))])
        )
        .is_ok());
        assert!(Cli::try_parse_from(base.into_iter().chain([
            "--fund-from-wallet",
            "--fee-input",
            &format!("{}:0:20000", "11".repeat(32)),
        ]))
        .is_err());
    }

    #[test]
    fn bip448_duplicate_index_cli_domain_and_zero_handler_are_exact() {
        let invocation = |index: &str| {
            Cli::try_parse_from([
                "client-rust",
                "bip448-sweep-duplicate",
                "wallet",
                "statechain",
                index,
                "bcrt1pdestination",
            ])
        };
        let max = invocation("4294967295").expect("u32::MAX must parse");
        match max.command {
            Commands::Bip448SweepDuplicate {
                duplicate_index, ..
            } => assert_eq!(duplicate_index, u32::MAX),
            _ => panic!("parsed the wrong command"),
        }
        for invalid in ["4294967296", "-1", "1.0", "one", "+1", "0x1"] {
            assert!(
                invocation(invalid).is_err(),
                "unexpectedly parsed {invalid}"
            );
        }
        let zero = invocation("0").expect("zero belongs to the Clap u32 domain");
        assert!(validate_command_before_io(&zero.command).is_err());
    }

    #[test]
    fn legacy_commands_are_rejected_and_bip448_commands_remain_valid() {
        for invocation in [
            vec![
                "client-rust",
                "new-deposit-address",
                "wallet",
                "token",
                "1000",
            ],
            vec![
                "client-rust",
                "broadcast-backup-transaction",
                "wallet",
                "statechain",
            ],
            vec![
                "client-rust",
                "withdraw",
                "wallet",
                "statechain",
                "bcrt1qdestination",
            ],
            vec![
                "client-rust",
                "transfer-send",
                "wallet",
                "statechain",
                "transfer-address",
            ],
        ] {
            let error = Cli::try_parse_from(invocation.clone())
                .err()
                .unwrap_or_else(|| panic!("removed command parsed successfully: {invocation:?}"));
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "unexpected parse error for removed command {invocation:?}: {error}"
            );
        }

        for invocation in [
            vec![
                "client-rust",
                "new-bip448-deposit-address",
                "wallet",
                "token",
                "1000",
            ],
            vec![
                "client-rust",
                "bip448-withdraw",
                "wallet",
                "statechain",
                "bcrt1qdestination",
            ],
            vec![
                "client-rust",
                "bip448-transfer-send",
                "wallet",
                "statechain",
                "transfer-address",
            ],
            vec!["client-rust", "transfer-receive", "wallet"],
        ] {
            assert!(Cli::try_parse_from(invocation).is_ok());
        }
    }

    #[test]
    fn duplicate_transfer_acknowledgement_flag_is_exactly_scoped() {
        let base = [
            "client-rust",
            "bip448-transfer-send",
            "wallet",
            "statechain",
            "transfer-address",
        ];
        let omitted = Cli::try_parse_from(base).expect("safe default transfer must parse");
        match omitted.command {
            Commands::Bip448TransferSend {
                force_send_with_duplicates,
                ..
            } => assert!(!force_send_with_duplicates),
            _ => panic!("parsed the wrong command"),
        }
        let forced = Cli::try_parse_from(base.into_iter().chain(["--force-send-with-duplicates"]))
            .expect("exact duplicate acknowledgement flag must parse");
        match forced.command {
            Commands::Bip448TransferSend {
                force_send_with_duplicates,
                ..
            } => assert!(force_send_with_duplicates),
            _ => panic!("parsed the wrong command"),
        }
        for misspelling in [
            "--force_send_with_duplicates",
            "--force-send",
            "--force_send",
            "--force-send-duplicates",
        ] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain([misspelling])).is_err(),
                "legacy or misspelled flag unexpectedly parsed: {misspelling}"
            );
        }
        for mut invocation in [
            vec!["client-rust", "create-wallet", "wallet"],
            vec!["client-rust", "new-token"],
            vec![
                "client-rust",
                "new-bip448-deposit-address",
                "wallet",
                "token",
                "1000",
            ],
            vec!["client-rust", "bip448-recovery-fee-address", "wallet"],
            vec![
                "client-rust",
                "broadcast-bip448-recovery-package",
                "wallet",
                "statechain",
                "funding_update",
                "--fund-from-wallet",
            ],
            vec!["client-rust", "list-statecoins", "wallet"],
            vec![
                "client-rust",
                "bip448-withdraw",
                "wallet",
                "statechain",
                "bcrt1qdestination",
            ],
            vec![
                "client-rust",
                "bip448-sweep-duplicate",
                "wallet",
                "statechain",
                "1",
                "bcrt1qdestination",
            ],
            vec!["client-rust", "new-transfer-address", "wallet"],
            vec![
                "client-rust",
                "bip448-transfer-cancel",
                "wallet",
                "statechain",
            ],
            vec!["client-rust", "transfer-receive", "wallet"],
            vec!["client-rust", "payment-hash", "wallet", "statechain"],
            vec![
                "client-rust",
                "confirm-pending-invoice",
                "wallet",
                "statechain",
            ],
            vec![
                "client-rust",
                "retrieve-pre-image",
                "wallet",
                "statechain",
                "batch",
            ],
            vec!["client-rust", "get-payment-hash", "batch"],
        ] {
            invocation.push("--force-send-with-duplicates");
            assert!(
                Cli::try_parse_from(invocation.clone()).is_err(),
                "force flag escaped transfer-send scope: {invocation:?}"
            );
        }
    }

    #[test]
    fn list_statecoins_has_exact_nested_duplicate_shape_and_identity() -> Result<()> {
        let coin = list_coin();
        let bindings = vec![
            list_binding(
                2,
                u64::from(u32::MAX) + 9,
                Bip448ObservationStatus::Confirmed,
                Bip448OwnershipStatus::Previous,
            ),
            list_binding(
                0,
                100_000,
                Bip448ObservationStatus::Confirmed,
                Bip448OwnershipStatus::Current,
            ),
            list_binding(
                3,
                7,
                Bip448ObservationStatus::SpentConfirmed,
                Bip448OwnershipStatus::Current,
            ),
            list_binding(
                1,
                546,
                Bip448ObservationStatus::Mempool,
                Bip448OwnershipStatus::Current,
            ),
        ];
        let value = mercuryrustlib::coin_status::statecoin_list_entry_json(
            "wallet",
            &coin,
            &bindings,
            &[],
        )?;
        let keys = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("list entry is not an object"))?
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            [
                "coin.address",
                "coin.address_retired",
                "coin.aggregated_address",
                "coin.amount",
                "coin.close_tip_hash",
                "coin.close_tip_height",
                "coin.duplicates",
                "coin.exit_only",
                "coin.locktime",
                "coin.statechain_id",
                "coin.statechain_protocol",
                "coin.status",
                "coin.user_pubkey",
                "coin.utxo_txid",
                "coin.utxo_vout",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_eq!(value["coin.amount"], 100_000);
        assert!(value["coin.utxo_txid"].is_null());
        assert!(value["coin.utxo_vout"].is_null());
        assert!(value["coin.close_tip_height"].is_null());
        assert!(value["coin.close_tip_hash"].is_null());
        let duplicates = value["coin.duplicates"].as_array().unwrap();
        assert_eq!(
            duplicates
                .iter()
                .map(|duplicate| duplicate["duplicate_index"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(duplicates[0]["amount_sats"], 546_u64);
        assert!(duplicates[0]["sweep_phase"].is_null());
        assert!(duplicates[0]["broadcast_status"].is_null());
        assert_eq!(duplicates[0]["cooperative_only"], true);
        assert_eq!(duplicates[0]["server_dependent"], true);
        assert_eq!(duplicates[1]["amount_sats"], u64::from(u32::MAX) + 9);
        assert_eq!(duplicates[1]["server_dependent"], false);
        assert_eq!(duplicates[2]["cooperative_only"], false);
        assert_eq!(duplicates[2]["server_dependent"], false);
        let duplicate_keys = duplicates[0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(duplicate_keys.len(), 11);
        assert_eq!(
            duplicate_keys,
            [
                "amount_sats",
                "broadcast_status",
                "cooperative_only",
                "duplicate_index",
                "observation_status",
                "ownership_status",
                "server_dependent",
                "spend_txid",
                "sweep_phase",
                "txid",
                "vout",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        Ok(())
    }
}
