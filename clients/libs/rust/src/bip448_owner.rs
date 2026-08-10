use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use bitcoin::{
    hashes::{sha256, Hash},
    PrivateKey,
};
use mercurylib::{
    bip448_statechain::deposit::is_bip448_coin,
    transfer::receiver::StatechainInfoResponsePayload,
    wallet::{Coin, Wallet},
};
use secp256k1::{schnorr, PublicKey, Secp256k1};

use crate::{client_config::ClientConfig, sqlite_manager::get_bip448_statechain, utils};

#[derive(Debug)]
pub enum Bip448StatechainPresence {
    Present(StatechainInfoResponsePayload),
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bip448OwnerRelation {
    Current,
    Rotated,
    Missing,
}

#[derive(Debug)]
pub struct CurrentBip448Owner {
    pub coin_index: usize,
    pub statechain_info: StatechainInfoResponsePayload,
}

pub async fn get_bip448_statechain_presence(
    client_config: &ClientConfig,
    statechain_id: &str,
) -> Result<Bip448StatechainPresence> {
    Ok(
        match utils::get_statechain_info(statechain_id, client_config).await? {
            Some(statechain_info) => Bip448StatechainPresence::Present(statechain_info),
            None => Bip448StatechainPresence::Missing,
        },
    )
}

pub async fn get_current_bip448_owner(
    client_config: &ClientConfig,
    wallet: &Wallet,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<CurrentBip448Owner> {
    if wallet.name != wallet_name {
        return Err(anyhow!(
            "BIP448 owner proof wallet does not match the requested wallet name"
        ));
    }
    let record = get_bip448_statechain(&client_config.pool, wallet_name, statechain_id)
        .await
        .with_context(|| {
            format!("failed to load accepted BIP448 statechain {statechain_id} for owner proof")
        })?;
    if record.wallet_name != wallet_name || record.statechain_id != statechain_id {
        return Err(anyhow!(
            "accepted BIP448 statechain identity does not match the requested wallet and statechain"
        ));
    }
    let presence = get_bip448_statechain_presence(client_config, statechain_id).await?;
    select_current_bip448_owner(wallet, statechain_id, &record.aggregate_pubkey, presence)
}

pub fn classify_bip448_owner_relation(
    presence: &Bip448StatechainPresence,
    owner_user_pubkey: &str,
    owner_server_pubkey: &str,
    accepted_aggregate_pubkey: &str,
) -> Result<Bip448OwnerRelation> {
    let Bip448StatechainPresence::Present(statechain_info) = presence else {
        return Ok(Bip448OwnerRelation::Missing);
    };
    let current_server = current_server_public_key(statechain_info)?;
    let owner_user = parse_canonical_public_key(owner_user_pubkey, "owner user public key")?;
    let owner_server =
        parse_canonical_public_key(owner_server_pubkey, "owner stored server public key")?;
    let aggregate =
        parse_canonical_public_key(accepted_aggregate_pubkey, "accepted aggregate public key")?;

    let stored_aggregate = owner_user
        .combine(&owner_server)
        .context("failed to combine BIP448 owner and stored server public keys")?;
    if stored_aggregate != aggregate {
        return Err(anyhow!(
            "stored BIP448 owner generation does not reproduce the accepted aggregate public key"
        ));
    }

    if current_server == owner_server {
        return Ok(Bip448OwnerRelation::Current);
    }

    let current_aggregate = owner_user
        .combine(&current_server)
        .context("failed to combine BIP448 owner and reported server public keys")?;
    if current_aggregate == aggregate {
        return Err(anyhow!(
            "different reported BIP448 server share unexpectedly reproduces the accepted aggregate public key"
        ));
    }

    Ok(Bip448OwnerRelation::Rotated)
}

pub(crate) fn select_current_bip448_owner(
    wallet: &Wallet,
    statechain_id: &str,
    accepted_aggregate_pubkey: &str,
    presence: Bip448StatechainPresence,
) -> Result<CurrentBip448Owner> {
    let Bip448StatechainPresence::Present(statechain_info) = presence else {
        return Err(anyhow!(
            "BIP448 statechain {statechain_id} is missing; current ownership cannot be proven"
        ));
    };
    let current_server = current_server_public_key(&statechain_info)?;
    let current_server_text = current_server.to_string();
    let aggregate =
        parse_canonical_public_key(accepted_aggregate_pubkey, "accepted aggregate public key")?;

    let mut matches = Vec::new();
    for (coin_index, coin) in wallet.coins.iter().enumerate().filter(|(_, coin)| {
        coin.statechain_id.as_deref() == Some(statechain_id) && is_bip448_coin(coin)
    }) {
        if coin.server_pubkey.as_deref() != Some(current_server_text.as_str()) {
            continue;
        }
        let user_pubkey = parse_canonical_public_key(
            &coin.user_pubkey,
            &format!("BIP448 coin {coin_index} user public key"),
        )?;
        let recomputed = user_pubkey
            .combine(&current_server)
            .with_context(|| format!("failed to combine BIP448 coin {coin_index} key shares"))?;
        if recomputed == aggregate {
            validate_bip448_coin_local_auth(coin, statechain_id)
                .with_context(|| format!("BIP448 coin {coin_index} local authentication"))?;
            matches.push(coin_index);
        }
    }

    match matches.as_slice() {
        [coin_index] => Ok(CurrentBip448Owner {
            coin_index: *coin_index,
            statechain_info,
        }),
        [] => Err(anyhow!(
            "no BIP448 wallet coin has the reported server key and reproduces the accepted aggregate key for statechain {statechain_id}"
        )),
        _ => Err(anyhow!(
            "multiple BIP448 wallet coins reproduce the current owner generation for statechain {statechain_id}"
        )),
    }
}

pub(crate) fn current_server_public_key(
    statechain_info: &StatechainInfoResponsePayload,
) -> Result<PublicKey> {
    parse_canonical_public_key(
        &statechain_info.enclave_public_key,
        "current BIP448 server public key",
    )
}

pub(crate) fn validate_bip448_coin_local_auth(coin: &Coin, statechain_id: &str) -> Result<()> {
    let signed_statechain_id = coin
        .signed_statechain_id
        .as_deref()
        .filter(|signature| !signature.is_empty())
        .ok_or_else(|| anyhow!("coin is missing signed_statechain_id"))?;
    let signature = schnorr::Signature::from_str(signed_statechain_id)
        .context("coin signed_statechain_id is invalid")?;
    let auth_pubkey = parse_canonical_public_key(&coin.auth_pubkey, "coin auth public key")?;
    let auth_private =
        PrivateKey::from_wif(&coin.auth_privkey).context("coin auth private key is invalid")?;
    let secp = Secp256k1::new();
    if auth_private.inner.public_key(&secp) != auth_pubkey {
        return Err(anyhow!(
            "coin auth private key does not match its auth public key"
        ));
    }
    let digest = sha256::Hash::hash(statechain_id.as_bytes()).to_byte_array();
    schnorr::verify(&signature, &digest, &auth_pubkey.x_only_public_key().0)
        .context("coin signed_statechain_id does not authenticate this statechain")?;
    Ok(())
}

fn parse_canonical_public_key(value: &str, field: &str) -> Result<PublicKey> {
    let key = PublicKey::from_str(value).with_context(|| format!("invalid {field}"))?;
    if key.to_string() != value {
        return Err(anyhow!("non-canonical {field}"));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercurylib::{
        transfer::receiver::sign_message,
        wallet::{CoinStatus, Settings},
    };
    use secp256k1::SecretKey;

    const STATECHAIN_ID: &str = "statechain";

    fn wallet() -> Wallet {
        Wallet {
            name: "wallet".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "0.1.0".to_string(),
            state_entity_endpoint: "http://127.0.0.1:1".to_string(),
            chain_backend: "core".to_string(),
            chain_endpoint: "http://127.0.0.1:1".to_string(),
            network: "regtest".to_string(),
            blockheight: 0,
            activities: Vec::new(),
            coins: Vec::new(),
            settings: Settings {
                network: "regtest".to_string(),
                block_explorerURL: None,
                torProxyHost: None,
                torProxyPort: None,
                torProxyControlPassword: None,
                torProxyControlPort: None,
                statechainEntityApi: "http://127.0.0.1:1".to_string(),
                torStatechainEntityApi: None,
                chainBackend: "core".to_string(),
                chainUrl: "http://127.0.0.1:1".to_string(),
                chainType: None,
                notifications: false,
                tutorials: false,
            },
        }
    }

    fn public_key(byte: u8) -> PublicKey {
        SecretKey::from_secret_bytes([byte; 32])
            .unwrap()
            .public_key(&Secp256k1::new())
    }

    fn owner_coin(
        wallet: &Wallet,
        user_pubkey: PublicKey,
        server_pubkey: PublicKey,
        aggregate_pubkey: PublicKey,
        locktime: u32,
    ) -> Coin {
        let mut coin = wallet.get_new_coin().unwrap();
        coin.user_pubkey = user_pubkey.to_string();
        coin.server_pubkey = Some(server_pubkey.to_string());
        coin.aggregated_pubkey = Some(aggregate_pubkey.to_string());
        coin.statechain_protocol = Some("bip448".to_string());
        coin.statechain_id = Some(STATECHAIN_ID.to_string());
        coin.locktime = Some(locktime);
        coin.status = CoinStatus::CONFIRMED;
        coin.signed_statechain_id = Some(sign_message(STATECHAIN_ID, &coin).unwrap());
        coin
    }

    fn generations() -> (Wallet, PublicKey, PublicKey) {
        let current_user = public_key(3);
        let current_server = public_key(5);
        let aggregate = current_user.combine(&current_server).unwrap();
        let old_user = public_key(7);
        let old_server = aggregate.combine(&old_user.negate()).unwrap();
        let mut wallet = wallet();
        let old = owner_coin(&wallet, old_user, old_server, aggregate, 10);
        wallet.coins.push(old);
        let current = owner_coin(&wallet, current_user, current_server, aggregate, 20);
        wallet.coins.push(current);
        (wallet, current_server, aggregate)
    }

    fn present(server_pubkey: impl ToString) -> Bip448StatechainPresence {
        Bip448StatechainPresence::Present(StatechainInfoResponsePayload {
            enclave_public_key: server_pubkey.to_string(),
            num_sigs: 2,
            statechain_info: Vec::new(),
            x1_pub: None,
        })
    }

    #[test]
    fn exact_current_generation_is_selected_against_each_immutable_wallet_snapshot() {
        let (wallet, current_server, aggregate) = generations();
        let selected = select_current_bip448_owner(
            &wallet,
            STATECHAIN_ID,
            &aggregate.to_string(),
            present(current_server),
        )
        .unwrap();
        assert_eq!(
            wallet
                .coins
                .get(selected.coin_index)
                .expect("selected index must belong to this wallet snapshot")
                .server_pubkey
                .as_deref(),
            Some(current_server.to_string().as_str())
        );

        let original_index = selected.coin_index;
        let mut reordered = wallet.clone();
        reordered.coins.swap(0, 1);
        reordered
            .coins
            .get_mut(0)
            .expect("reordered wallet has a first coin")
            .locktime = Some(1);
        reordered
            .coins
            .get_mut(1)
            .expect("reordered wallet has a second coin")
            .locktime = Some(u32::MAX);
        assert_ne!(
            reordered
                .coins
                .get(original_index)
                .expect("the old index is in bounds but belongs to another generation")
                .server_pubkey
                .as_deref(),
            Some(current_server.to_string().as_str()),
            "an index from another wallet snapshot must not be applied blindly"
        );

        let reordered_selected = select_current_bip448_owner(
            &reordered,
            STATECHAIN_ID,
            &aggregate.to_string(),
            present(current_server),
        )
        .unwrap();
        assert_ne!(original_index, reordered_selected.coin_index);
        assert_eq!(
            reordered
                .coins
                .get(reordered_selected.coin_index)
                .expect("selected index must belong to the reordered snapshot")
                .server_pubkey
                .as_deref(),
            Some(current_server.to_string().as_str())
        );
    }

    #[test]
    fn stored_server_key_mismatch_fails_closed() {
        let (mut wallet, current_server, aggregate) = generations();
        wallet.coins.remove(0);
        wallet
            .coins
            .get_mut(0)
            .expect("one current-generation coin")
            .server_pubkey = Some(public_key(9).to_string());
        let error = select_current_bip448_owner(
            &wallet,
            STATECHAIN_ID,
            &aggregate.to_string(),
            present(current_server),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no BIP448 wallet coin"));
    }

    #[test]
    fn zero_current_generation_matches_fail_closed() {
        let (_, current_server, aggregate) = generations();
        let error = select_current_bip448_owner(
            &wallet(),
            STATECHAIN_ID,
            &aggregate.to_string(),
            present(current_server),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no BIP448 wallet coin"));
    }

    #[test]
    fn two_current_generation_matches_fail_closed() {
        let (mut wallet, current_server, aggregate) = generations();
        let mut duplicate = wallet
            .coins
            .get(1)
            .expect("current-generation coin")
            .clone();
        duplicate.index = 99;
        duplicate.locktime = Some(0);
        wallet.coins.push(duplicate);
        let error = select_current_bip448_owner(
            &wallet,
            STATECHAIN_ID,
            &aggregate.to_string(),
            present(current_server),
        )
        .unwrap_err();
        assert!(error.to_string().contains("multiple BIP448 wallet coins"));
    }

    #[test]
    fn invalid_current_server_key_is_an_error() {
        let (wallet, _, aggregate) = generations();
        let error = select_current_bip448_owner(
            &wallet,
            STATECHAIN_ID,
            &aggregate.to_string(),
            present("not-a-public-key"),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid current BIP448 server public key"));
    }

    fn relation_keys() -> (PublicKey, PublicKey, PublicKey, PublicKey) {
        let owner_user = public_key(3);
        let stored_server = public_key(5);
        let aggregate = owner_user.combine(&stored_server).unwrap();
        let reported_rotated_server = public_key(7);
        (
            owner_user,
            stored_server,
            aggregate,
            reported_rotated_server,
        )
    }

    #[test]
    fn owner_relation_accepts_a_valid_current_generation() {
        let (owner_user, stored_server, aggregate, _) = relation_keys();
        assert_eq!(
            classify_bip448_owner_relation(
                &present(stored_server),
                &owner_user.to_string(),
                &stored_server.to_string(),
                &aggregate.to_string(),
            )
            .unwrap(),
            Bip448OwnerRelation::Current
        );
    }

    #[test]
    fn owner_relation_accepts_only_a_genuinely_different_reported_server_as_rotated() {
        let (owner_user, stored_server, aggregate, reported_rotated_server) = relation_keys();
        assert_eq!(
            classify_bip448_owner_relation(
                &present(reported_rotated_server),
                &owner_user.to_string(),
                &stored_server.to_string(),
                &aggregate.to_string(),
            )
            .unwrap(),
            Bip448OwnerRelation::Rotated
        );
    }

    #[test]
    fn owner_relation_equal_reported_and_stored_share_with_corrupt_aggregate_is_an_error() {
        let (owner_user, stored_server, _, _) = relation_keys();
        let corrupt_aggregate = public_key(11);
        let error = classify_bip448_owner_relation(
            &present(stored_server),
            &owner_user.to_string(),
            &stored_server.to_string(),
            &corrupt_aggregate.to_string(),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("stored BIP448 owner generation does not reproduce"));
    }

    #[test]
    fn owner_relation_corrupt_stored_tuple_with_different_report_is_an_error() {
        let (owner_user, _, aggregate, reported_rotated_server) = relation_keys();
        let corrupt_stored_server = public_key(9);
        let error = classify_bip448_owner_relation(
            &present(reported_rotated_server),
            &owner_user.to_string(),
            &corrupt_stored_server.to_string(),
            &aggregate.to_string(),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("stored BIP448 owner generation does not reproduce"));
    }

    #[test]
    fn owner_relation_rejects_every_invalid_present_public_key() {
        let (owner_user, stored_server, aggregate, reported_rotated_server) = relation_keys();
        let valid_user = owner_user.to_string();
        let valid_stored = stored_server.to_string();
        let valid_aggregate = aggregate.to_string();
        let valid_reported = reported_rotated_server.to_string();
        for (user, stored, accepted, reported) in [
            (
                "invalid".to_string(),
                valid_stored.clone(),
                valid_aggregate.clone(),
                valid_reported.clone(),
            ),
            (
                valid_user.clone(),
                "invalid".to_string(),
                valid_aggregate.clone(),
                valid_reported.clone(),
            ),
            (
                valid_user.clone(),
                valid_stored.clone(),
                "invalid".to_string(),
                valid_reported.clone(),
            ),
            (
                valid_user.clone(),
                valid_stored.clone(),
                valid_aggregate.clone(),
                "invalid".to_string(),
            ),
        ] {
            assert!(
                classify_bip448_owner_relation(&present(reported), &user, &stored, &accepted,)
                    .is_err()
            );
        }
    }

    #[test]
    fn owner_relation_missing_remains_distinct_from_rotation() {
        assert_eq!(
            classify_bip448_owner_relation(
                &Bip448StatechainPresence::Missing,
                "invalid",
                "invalid",
                "invalid",
            )
            .unwrap(),
            Bip448OwnerRelation::Missing
        );
    }
}
