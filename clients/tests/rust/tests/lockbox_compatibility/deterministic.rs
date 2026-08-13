use super::*;

const DETERMINISTIC_RNG_SEED: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DETERMINISTIC_STATECHAIN_ID: &str = "deterministic-vector";
const DETERMINISTIC_SIGNING_ID: &str =
    "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";

#[derive(Debug, PartialEq, Eq)]
struct DeterministicVector {
    server_pubkey: String,
    server_pubnonce: String,
    partial_sig: String,
    updated_server_pubkey: String,
}

struct ProductionRngRestoreGuard {
    active: bool,
}

impl ProductionRngRestoreGuard {
    fn armed() -> Self {
        Self { active: true }
    }

    async fn restore_now(&mut self, client: &reqwest::Client) -> Result<()> {
        lockbox::recreate_lockbox_service_with_rng_seed(client, None).await?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ProductionRngRestoreGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        if let Err(err) = lockbox::recreate_lockbox_service_with_production_rng() {
            eprintln!("failed to restore lockbox production RNG after deterministic test: {err:#}");
        }
    }
}

fn deterministic_partial_signature_payload() -> Bip448LockboxPartialSignatureRequestPayload {
    Bip448LockboxPartialSignatureRequestPayload {
        statechain_id: DETERMINISTIC_STATECHAIN_ID.to_string(),
        signing_id: DETERMINISTIC_SIGNING_ID.to_string(),
        negate_seckey: 0,
        session: "9dede917000000000000000000000000000000000000000000000000000000000000000000b59faf7e0a44057b41d273e70cc0a59194347b286c8108fef3519bb52fe64b0729641b33afc4d71464ccde0ca4b0471ed2fda81a39056745ed7b1f4f90790dfd3ee2e8c6c5937a7f4dd30e9e78ec2096433ff32ea89ffca29a40b02b03b4e7eb".to_string(),
        server_pub_nonce: "032f7d30ca4641d314418be9e8e11ef28e079ce684f7271bceab6e9f835adea05303b1b76528c43918e991aa847abb7b6df753dc116de95a9d811bc9b35a7f020dfb".to_string(),
    }
}

pub(super) async fn deterministic_lockbox_vectors_match_golden_outputs() -> Result<()> {
    let _guard = common::test_guard();
    let client = lockbox::http_client();
    let statechain_id = DETERMINISTIC_STATECHAIN_ID;
    let partial_signature_payload = deterministic_partial_signature_payload();
    let mut production_rng_restore = ProductionRngRestoreGuard::armed();

    lockbox::recreate_lockbox_service_with_rng_seed(&client, Some(DETERMINISTIC_RNG_SEED)).await?;

    let first_created = lockbox::create_statechain(&client, statechain_id).await?;
    let nonce_payload = Bip448LockboxSignFirstRequestPayload {
        statechain_id: statechain_id.to_string(),
        signing_id: DETERMINISTIC_SIGNING_ID.to_string(),
    };
    let first_server_pubnonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    assert_eq!(
        first_server_pubnonce.server_pubnonce,
        partial_signature_payload.server_pub_nonce
    );
    let first_partial_sig =
        lockbox::bip448_request_partial_signature(&client, &partial_signature_payload).await?;
    let first_updated_server_pubkey =
        lockbox::keyupdate(&client, statechain_id, [9u8; 32], [10u8; 32])
            .await?
            .server_pubkey;
    lockbox::delete_statechain(&client, statechain_id).await?;

    let first = DeterministicVector {
        server_pubkey: first_created.server_pubkey,
        server_pubnonce: first_server_pubnonce.server_pubnonce,
        partial_sig: first_partial_sig,
        updated_server_pubkey: first_updated_server_pubkey,
    };

    lockbox::recreate_lockbox_service_with_rng_seed(&client, Some(DETERMINISTIC_RNG_SEED)).await?;

    let second_created = lockbox::create_statechain(&client, statechain_id).await?;
    let second_server_pubnonce = lockbox::bip448_get_public_nonce(&client, &nonce_payload).await?;
    assert_eq!(
        second_server_pubnonce.server_pubnonce,
        partial_signature_payload.server_pub_nonce
    );
    let second_partial_sig =
        lockbox::bip448_request_partial_signature(&client, &partial_signature_payload).await?;
    let second_updated_server_pubkey =
        lockbox::keyupdate(&client, statechain_id, [9u8; 32], [10u8; 32])
            .await?
            .server_pubkey;
    lockbox::delete_statechain(&client, statechain_id).await?;

    let second = DeterministicVector {
        server_pubkey: second_created.server_pubkey,
        server_pubnonce: second_server_pubnonce.server_pubnonce,
        partial_sig: second_partial_sig,
        updated_server_pubkey: second_updated_server_pubkey,
    };

    assert_eq!(first, second);
    assert_eq!(
        first.server_pubkey,
        "03aefcb771d0ab2d82e1cf7b745c9e70cd8464d052b548b53fcca97dfcc9dcfcb0"
    );
    assert_eq!(
        first.server_pubnonce,
        "032f7d30ca4641d314418be9e8e11ef28e079ce684f7271bceab6e9f835adea05303b1b76528c43918e991aa847abb7b6df753dc116de95a9d811bc9b35a7f020dfb"
    );
    assert_eq!(
        first.partial_sig,
        "3ce98d8436bc256e5be176626d3de965a933ab302851ce575a98390a7ec25c21"
    );
    assert_eq!(
        first.updated_server_pubkey,
        "03b0e0d6db0474284547015b23f8e08a2fd9fe9e353688439624880af2b8444cea"
    );

    production_rng_restore.restore_now(&client).await?;

    Ok(())
}
