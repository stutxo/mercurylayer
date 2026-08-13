use std::collections::{HashMap, HashSet};

#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use mercurylib::wallet::{Coin, CoinStatus};

use crate::{
    client_config::ClientConfig,
    sqlite_manager::{
        get_active_bip448_transfer_intent, get_wallet, mark_bip448_cancellation_receiver_accepted,
        update_wallet,
    },
};

use super::{Bip448PostAcceptanceSyncError, Bip448ReceiveOutcome, TransferReceiveResult};

#[cfg(feature = "test-hooks")]
static BIP448_POST_ACCEPTANCE_SYNC_FAILURES: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "test-hooks")]
pub fn inject_bip448_post_acceptance_sync_failures_for_test(count: usize) {
    BIP448_POST_ACCEPTANCE_SYNC_FAILURES.store(count, Ordering::SeqCst);
}

#[cfg(feature = "test-hooks")]
fn take_bip448_post_acceptance_sync_failure() -> bool {
    BIP448_POST_ACCEPTANCE_SYNC_FAILURES
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
}

#[cfg(not(feature = "test-hooks"))]
fn take_bip448_post_acceptance_sync_failure() -> bool {
    false
}

#[cfg(feature = "test-hooks")]
fn bip448_post_acceptance_checkpoint() {
    if std::env::var("ML_BIP448_RESTART_CHILD").as_deref() == Ok("1")
        && std::env::var("ML_BIP448_TEST_CHECKPOINT").as_deref() == Ok("transfer_receiver_accepted")
    {
        std::process::exit(86);
    }
}

#[cfg(not(feature = "test-hooks"))]
fn bip448_post_acceptance_checkpoint() {}

enum Bip448MessageDisposition {
    Processed,
    BatchLocked,
    AlreadyProcessed,
    Rejected,
}

const EXPIRED_BATCH_TIME_ERROR: &str = "Batch time has expired";

fn handle_bip448_message_result(
    result: Result<Bip448ReceiveOutcome>,
    received_statechain_ids: &mut Vec<String>,
) -> Result<Bip448MessageDisposition> {
    match result {
        std::result::Result::Ok(Bip448ReceiveOutcome::Processed(statechain_id)) => {
            received_statechain_ids.push(statechain_id);
            Ok(Bip448MessageDisposition::Processed)
        }
        std::result::Result::Ok(Bip448ReceiveOutcome::BatchLocked) => {
            Ok(Bip448MessageDisposition::BatchLocked)
        }
        std::result::Result::Ok(Bip448ReceiveOutcome::AlreadyProcessed) => {
            Ok(Bip448MessageDisposition::AlreadyProcessed)
        }
        std::result::Result::Err(error) if error.to_string() == EXPIRED_BATCH_TIME_ERROR => {
            Err(error)
        }
        std::result::Result::Err(error) => {
            println!("BIP448 processing error: {error}");
            Ok(Bip448MessageDisposition::Rejected)
        }
    }
}

pub(super) async fn execute(
    client_config: &ClientConfig,
    wallet_name: &str,
) -> Result<TransferReceiveResult> {
    let mut wallet = get_wallet(&client_config.pool, &wallet_name).await?;

    let mut unique_auth_pubkeys: HashSet<String> = HashSet::new();

    for coin in wallet.coins.iter() {
        unique_auth_pubkeys.insert(coin.auth_pubkey.clone());
    }

    let mut enc_msgs_per_auth_pubkey: HashMap<String, Vec<String>> = HashMap::new();

    for auth_pubkey in unique_auth_pubkeys {
        let enc_messages = super::get_msg_addr(&auth_pubkey, &client_config).await?;
        if enc_messages.len() == 0 {
            continue;
        }

        enc_msgs_per_auth_pubkey.insert(auth_pubkey.clone(), enc_messages);
    }

    let mut is_there_batch_locked = false;

    let mut received_statechain_ids = Vec::<String>::new();

    let mut temp_coins = wallet.coins.clone();
    let mut temp_activities = wallet.activities.clone();

    for (key, values) in &enc_msgs_per_auth_pubkey {
        let auth_pubkey = key.clone();

        for enc_message in values {
            let coin: Option<&mut Coin> = temp_coins.iter_mut().find(|coin| {
                coin.auth_pubkey == auth_pubkey && coin.status == CoinStatus::INITIALISED
            });

            if coin.is_some() {
                let coin = coin.unwrap();

                let bip448_result = super::bip448_transfer_receiver::try_transfer_bip448_receiver(
                    client_config,
                    coin,
                    enc_message,
                    &wallet.network,
                    &wallet.name,
                    &mut temp_activities,
                )
                .await;
                match handle_bip448_message_result(bip448_result, &mut received_statechain_ids)? {
                    Bip448MessageDisposition::BatchLocked => {
                        is_there_batch_locked = true;
                        continue;
                    }
                    Bip448MessageDisposition::Processed
                    | Bip448MessageDisposition::AlreadyProcessed
                    | Bip448MessageDisposition::Rejected => {
                        continue;
                    }
                }
            } else {
                let new_coin =
                    mercurylib::transfer::receiver::clone_transfer_address_coin_to_initialized_state(
                        &wallet,
                        &auth_pubkey,
                    );

                if new_coin.is_err() {
                    println!("Error: {}", new_coin.err().unwrap().to_string());
                    continue;
                }

                let mut new_coin = new_coin.unwrap();

                let bip448_result = super::bip448_transfer_receiver::try_transfer_bip448_receiver(
                    client_config,
                    &mut new_coin,
                    enc_message,
                    &wallet.network,
                    &wallet.name,
                    &mut temp_activities,
                )
                .await;
                match handle_bip448_message_result(bip448_result, &mut received_statechain_ids)? {
                    Bip448MessageDisposition::BatchLocked => {
                        is_there_batch_locked = true;
                        continue;
                    }
                    Bip448MessageDisposition::Processed => {
                        temp_coins.push(new_coin.clone());
                        continue;
                    }
                    Bip448MessageDisposition::AlreadyProcessed
                    | Bip448MessageDisposition::Rejected => continue,
                }
            }
        }
    }

    wallet.coins = temp_coins.clone();
    wallet.activities = temp_activities.clone();

    update_wallet(&client_config.pool, &wallet).await?;

    received_statechain_ids.sort();
    received_statechain_ids.dedup();

    for statechain_id in &received_statechain_ids {
        if let Some(intent) =
            get_active_bip448_transfer_intent(&client_config.pool, wallet_name, statechain_id)
                .await?
        {
            if intent.intent_kind != crate::bip448_funding::Bip448TransferIntentKind::Cancellation {
                return Err(anyhow::anyhow!(
                    "accepted BIP448 receive conflicts with an active local UserTransfer intent"
                ));
            }
            mark_bip448_cancellation_receiver_accepted(
                &client_config.pool,
                wallet_name,
                statechain_id,
                &intent.intent_id,
            )
            .await?;
        }
    }

    if !received_statechain_ids.is_empty() {
        bip448_post_acceptance_checkpoint();
    }

    for statechain_id in &received_statechain_ids {
        let sync_result = if take_bip448_post_acceptance_sync_failure() {
            Err(anyhow::anyhow!(
                "injected BIP448 post-acceptance synchronization failure"
            ))
        } else {
            crate::coin_status::sync_bip448_funding_bindings_for_statechain_from_height_zero(
                client_config,
                wallet_name,
                statechain_id,
            )
            .await
            .map(|_| ())
        };
        if let Err(source) = sync_result {
            return Err(Bip448PostAcceptanceSyncError::new(
                received_statechain_ids.clone(),
                source,
            )
            .into());
        }
    }

    crate::coin_status::reconcile_bip448_post_sync_transfer_artifacts(
        &client_config.pool,
        wallet_name,
        &received_statechain_ids,
    )
    .await?;

    Ok(TransferReceiveResult {
        is_there_batch_locked,
        received_statechain_ids,
    })
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::transfer_receiver::bip448_transfer_receiver::test_support::*;
    use anyhow::anyhow;
    use mercurylib::{transfer::receiver::StatechainInfoResponsePayload, wallet::CoinStatus};

    #[test]
    fn bip448_message_error_does_not_discard_prior_success() {
        let mut received_statechain_ids = Vec::new();

        let success = handle_bip448_message_result(
            Ok(Bip448ReceiveOutcome::Processed(
                "accepted-statechain".to_string(),
            )),
            &mut received_statechain_ids,
        )
        .unwrap();
        let failure = handle_bip448_message_result(
            Err(anyhow!("invalid later message")),
            &mut received_statechain_ids,
        )
        .unwrap();

        assert!(matches!(success, Bip448MessageDisposition::Processed));
        assert!(matches!(failure, Bip448MessageDisposition::Rejected));
        assert_eq!(received_statechain_ids, vec!["accepted-statechain"]);
    }

    #[test]
    fn bip448_post_acceptance_sync_error_is_typed_and_sorts_accepted_ids() {
        let error: anyhow::Error = Bip448PostAcceptanceSyncError::new(
            vec![
                "statechain-b".to_string(),
                "statechain-a".to_string(),
                "statechain-b".to_string(),
            ],
            anyhow!("Bitcoin RPC unavailable"),
        )
        .into();
        let typed = error
            .downcast_ref::<Bip448PostAcceptanceSyncError>()
            .expect("post-acceptance error must remain downcastable");

        assert_eq!(
            typed.accepted_statechain_ids(),
            &["statechain-a".to_string(), "statechain-b".to_string()]
        );
        assert!(typed.to_string().contains("already accepted"));
        assert!(typed.to_string().contains("next update/list will retry"));
        assert!(std::error::Error::source(typed)
            .expect("typed error must retain its synchronization source")
            .to_string()
            .contains("Bitcoin RPC unavailable"));
    }

    #[test]
    fn bip448_expired_batch_error_propagates_exactly() {
        let mut received_statechain_ids = Vec::new();

        let result = handle_bip448_message_result(
            Err(anyhow!(EXPIRED_BATCH_TIME_ERROR)),
            &mut received_statechain_ids,
        );

        assert_eq!(result.err().unwrap().to_string(), EXPIRED_BATCH_TIME_ERROR);
        assert!(received_statechain_ids.is_empty());
    }

    #[test]
    fn completed_bip448_replay_does_not_report_or_mutate_a_new_result() {
        let mut received_statechain_ids = vec!["previously-accepted".to_string()];

        let disposition = handle_bip448_message_result(
            Ok(Bip448ReceiveOutcome::AlreadyProcessed),
            &mut received_statechain_ids,
        )
        .unwrap();

        assert!(matches!(
            disposition,
            Bip448MessageDisposition::AlreadyProcessed
        ));
        assert_eq!(received_statechain_ids, vec!["previously-accepted"]);
    }

    #[test]
    fn invalid_non_bip448_ciphertext_is_rejected_without_panic_or_id_mutation() {
        let mut received_statechain_ids = vec!["previously-accepted".to_string()];

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_bip448_message_result(
                Err(anyhow!("invalid/non-BIP448 ciphertext")),
                &mut received_statechain_ids,
            )
        }));

        let disposition = result.expect("invalid ciphertext must not panic").unwrap();
        assert!(matches!(disposition, Bip448MessageDisposition::Rejected));
        assert_eq!(received_statechain_ids, vec!["previously-accepted"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rustfmt::skip]
    async fn completed_receipt_replays_through_execute_without_duplicate_wallet_state() {
        let fixture = fixture(); let mut coin = fixture.coin.clone(); let mut activities = Vec::new();
        let pool = pool().await; let transport = transport();
        attempt(&fixture, &pool, &mut coin, &mut activities, Rc::clone(&transport)).await.unwrap();
        let mut wallet = test_wallet(vec![coin.clone()]); wallet.activities = activities;
        crate::sqlite_manager::insert_wallet(&pool, &wallet).await.unwrap();
        let mut statechain_info: StatechainInfoResponsePayload = serde_json::from_str(INFO).unwrap();
        statechain_info.enclave_public_key = coin.server_pubkey.clone().unwrap();
        let (endpoint, server) = mock_execute_endpoints(vec![fixture.mailbox], Some(serde_json::to_string(&statechain_info).unwrap())).await;
        let config = test_client_config(endpoint, pool.clone());
        let result = execute(&config, "wallet").await;
        server.abort();
        let result = result.unwrap();
        assert!(result.received_statechain_ids.is_empty());
        assert!(!result.is_there_batch_locked);
        let wallet = crate::sqlite_manager::get_wallet(&pool, "wallet").await.unwrap();
        assert_eq!(wallet.coins.len(), 1);
        assert_eq!(wallet.activities.len(), 1);
        assert_eq!(wallet.coins[0].statechain_id.as_deref(), Some("statechain"));
        assert_eq!(wallet.coins[0].status, CoinStatus::CONFIRMED);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rustfmt::skip]
    async fn bip448_error_does_not_append_reused_address_coin_or_abort_receive_loop() {
        use crate::sqlite_manager::insert_wallet;
        let mut receiver = test_coin(9, 10); receiver.status = CoinStatus::CONFIRMED;
        let (endpoint, server) = mock_execute_endpoints(vec!["invalid transfer message".to_string()], None).await;
        let pool = pool().await;
        let config = test_client_config(endpoint, pool.clone());
        let wallet = test_wallet(vec![receiver]);
        insert_wallet(&pool, &wallet).await.unwrap();
        let result = execute(&config, "wallet").await;
        server.abort();
        assert!(result.is_ok());
        let wallet = crate::sqlite_manager::get_wallet(&pool, "wallet").await.unwrap();
        assert_eq!(wallet.coins.len(), 1);
        assert_eq!(wallet.coins[0].status, CoinStatus::CONFIRMED);
    }
}
