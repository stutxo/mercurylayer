use std::str::FromStr;

use bitcoin::{
    consensus::{deserialize, serialize},
    Address, Network, OutPoint, ScriptBuf, Transaction, Txid,
};
use mercurylib::{
    bip448_statechain::{
        signing_api::{
            Bip448PartialSignatureRequestPayload, Bip448PartialSignatureResponsePayload,
            Bip448SignFirstRequestPayload, Bip448SignFirstResponsePayload,
            Bip448SignatureCountResponsePayload,
        },
        withdraw::{
            aggregate_bip448_keypath_signature, build_bip448_keypath_spend_signing_data,
            create_bip448_keypath_nonces, finalize_bip448_keypath_transaction,
            prepare_bip448_keypath_spend, sample_bip448_keypath_spend_lock_time,
            Bip448KeypathSpendSource, Bip448PreparedKeypathSpend,
        },
    },
    wallet::{Activity, Coin, CoinStatus},
    withdraw::WithdrawCompletePayload,
};
use secp256k1::{rand, PublicKey, SecretKey};

use crate::{
    api::Backend,
    client::{chain_tip, get_json, normalize_hex, post_json, WalletClient},
    model::{
        WithdrawalAttempt, WithdrawalBroadcastStatus, WithdrawalCompletionStatus, WithdrawalKind,
        WithdrawalPhase, WithdrawalResult, MAX_FEE_RATE, MIN_FEE_RATE, NETWORK,
    },
};

impl<B: Backend> WalletClient<B> {
    pub async fn withdraw_statecoin(
        &mut self,
        statechain_id: &str,
        destination_address: &str,
        fee_rate: f64,
    ) -> Result<WithdrawalResult, String> {
        self.execute_withdrawal(
            statechain_id,
            0,
            WithdrawalKind::Canonical,
            destination_address,
            fee_rate,
        )
        .await
    }

    pub async fn sweep_duplicate(
        &mut self,
        statechain_id: &str,
        duplicate_index: u32,
        destination_address: &str,
        fee_rate: f64,
    ) -> Result<WithdrawalResult, String> {
        if duplicate_index == 0 {
            return Err(
                "duplicate index 0 is canonical and cannot be swept as a duplicate".to_string(),
            );
        }
        self.execute_withdrawal(
            statechain_id,
            duplicate_index,
            WithdrawalKind::Duplicate,
            destination_address,
            fee_rate,
        )
        .await
    }

    async fn execute_withdrawal(
        &mut self,
        statechain_id: &str,
        binding_index: u32,
        kind: WithdrawalKind,
        destination_address: &str,
        fee_rate: f64,
    ) -> Result<WithdrawalResult, String> {
        if !fee_rate.is_finite() || !(MIN_FEE_RATE..=MAX_FEE_RATE).contains(&fee_rate) {
            return Err(format!(
                "fee rate must be between {MIN_FEE_RATE} and {MAX_FEE_RATE} sat/vB"
            ));
        }
        if destination_address.trim() != destination_address || destination_address.is_empty() {
            return Err(
                "destination address is required without surrounding whitespace".to_string(),
            );
        }

        if let Some(existing) = self
            .snapshot
            .withdrawal_attempts
            .iter()
            .find(|attempt| {
                attempt.statechain_id == statechain_id && attempt.binding_index == binding_index
            })
            .cloned()
        {
            validate_invocation(&existing, kind, destination_address, fee_rate)?;
            return self.drive_withdrawal(existing.signing_id).await;
        }

        if self
            .snapshot
            .recovery_attempts
            .iter()
            .any(|attempt| attempt.statechain_id == statechain_id)
        {
            return Err("unilateral recovery has started for this statecoin".to_string());
        }
        if self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .is_some_and(|pending| pending.statechain_id == statechain_id)
        {
            return Err("cancel or complete the in-flight transfer before withdrawing".to_string());
        }
        if self.snapshot.withdrawal_attempts.iter().any(|attempt| {
            attempt.statechain_id == statechain_id
                && attempt.phase != WithdrawalPhase::Signed
                && attempt.binding_index != binding_index
        }) {
            return Err("finish the existing withdrawal signing attempt first".to_string());
        }

        let tip = chain_tip(&self.backend, &self.snapshot.deployment.chain_url).await?;
        self.sync_funding_bindings(tip).await?;
        let record = self
            .snapshot
            .statechain(statechain_id)
            .cloned()
            .ok_or_else(|| format!("statechain {statechain_id} is not in this wallet"))?;
        let coin = withdrawal_coin(&self.snapshot.wallet.coins, statechain_id)?.clone();
        if kind == WithdrawalKind::Canonical && coin.status != CoinStatus::CONFIRMED {
            return Err(format!(
                "canonical withdrawal requires a confirmed statecoin; current status is {}",
                coin.status
            ));
        }
        let binding = self
            .snapshot
            .funding_bindings
            .iter()
            .find(|binding| {
                binding.statechain_id == statechain_id && binding.binding_index == binding_index
            })
            .cloned()
            .ok_or_else(|| format!("funding binding {binding_index} is unknown"))?;
        if binding.observation_status != "Confirmed" {
            return Err(format!(
                "funding binding {binding_index} is {}, not Confirmed",
                binding.observation_status
            ));
        }
        let owner_user_pubkey = PublicKey::from_str(&coin.user_pubkey)
            .map_err(|error| error.to_string())?
            .x_only_public_key()
            .0
            .to_string();
        if binding.owner_state_number != record.latest_state_number
            || binding.owner_user_pubkey != owner_user_pubkey
        {
            return Err(
                "funding binding is not assigned to the current owner generation".to_string(),
            );
        }
        if kind == WithdrawalKind::Canonical {
            let unresolved = self.snapshot.funding_bindings.iter().any(|candidate| {
                candidate.statechain_id == statechain_id
                    && candidate.binding_index != 0
                    && candidate.owner_state_number == record.latest_state_number
                    && !duplicate_is_resolved(&self.snapshot.withdrawal_attempts, candidate)
            });
            if unresolved {
                return Err(
                    "sweep or independently confirm every current-owner duplicate before closing the canonical statecoin"
                        .to_string(),
                );
            }
        }

        let network = Network::from_str(NETWORK).map_err(|error| error.to_string())?;
        let funding_address = Address::from_str(
            coin.aggregated_address
                .as_deref()
                .ok_or_else(|| "statecoin funding address is missing".to_string())?,
        )
        .map_err(|error| error.to_string())?
        .require_network(network)
        .map_err(|error| error.to_string())?;
        let source = Bip448KeypathSpendSource {
            outpoint: OutPoint {
                txid: Txid::from_str(&binding.txid).map_err(|error| error.to_string())?,
                vout: binding.vout,
            },
            value_sats: binding.value_sats,
            script_pubkey: funding_address.script_pubkey(),
        };
        let prepared = prepare_bip448_keypath_spend(
            &record.aggregate_pubkey,
            &source,
            destination_address,
            network,
            fee_rate,
            sample_bip448_keypath_spend_lock_time(tip),
        )
        .map_err(|error| error.to_string())?;
        let nonce = create_bip448_keypath_nonces(&coin).map_err(|error| error.to_string())?;
        let signing_id = hex::encode(SecretKey::new(&mut rand::rng()).to_secret_bytes());
        let attempt = WithdrawalAttempt {
            statechain_id: statechain_id.to_string(),
            binding_index,
            kind,
            owner_user_pubkey,
            owner_state_number: record.latest_state_number,
            source_txid: binding.txid,
            source_vout: binding.vout,
            source_value_sats: binding.value_sats,
            source_script_pubkey: hex::encode(source.script_pubkey.as_bytes()),
            destination_address: destination_address.to_string(),
            destination_script_pubkey: hex::encode(prepared.destination_script_pubkey.as_bytes()),
            fee_rate_sat_per_vbyte: fee_rate,
            fee_sats: prepared.fee_sats,
            lock_time: prepared.lock_time,
            unsigned_tx_hex: hex::encode(&prepared.unsigned_tx),
            signing_id: signing_id.clone(),
            signed_statechain_id: coin
                .signed_statechain_id
                .clone()
                .ok_or_else(|| "statechain authorization is missing".to_string())?,
            client_secret_nonce: nonce.secret_nonce,
            client_public_nonce: nonce.public_nonce,
            blinding_factor: nonce.blinding_factor,
            server_public_nonce: None,
            message_hex: None,
            output_pubkey: None,
            client_partial_sig: None,
            encoded_session: None,
            sign_second_payload: None,
            server_partial_sig: None,
            aggregate_signature: None,
            signed_tx_hex: None,
            txid: None,
            phase: WithdrawalPhase::Prepared,
            broadcast_status: WithdrawalBroadcastStatus::NotBroadcast,
            completion_status: if kind == WithdrawalKind::Canonical {
                WithdrawalCompletionStatus::Open
            } else {
                WithdrawalCompletionStatus::NotApplicable
            },
        };
        self.snapshot.withdrawal_attempts.push(attempt);
        self.checkpoint()?;
        self.drive_withdrawal(signing_id).await
    }

    async fn drive_withdrawal(&mut self, signing_id: String) -> Result<WithdrawalResult, String> {
        for _ in 0..8 {
            let attempt_index = self
                .snapshot
                .withdrawal_attempts
                .iter()
                .position(|attempt| attempt.signing_id == signing_id)
                .ok_or_else(|| "withdrawal attempt disappeared".to_string())?;
            let attempt = self.snapshot.withdrawal_attempts[attempt_index].clone();
            let record = self
                .snapshot
                .statechain(&attempt.statechain_id)
                .cloned()
                .ok_or_else(|| "withdrawal statechain record disappeared".to_string())?;
            let mut coin =
                withdrawal_coin(&self.snapshot.wallet.coins, &attempt.statechain_id)?.clone();
            let expected_count = self.expected_withdrawal_signature_count(&attempt)?;
            match attempt.phase {
                WithdrawalPhase::Prepared => {
                    require_signature_count(self, &attempt.statechain_id, expected_count).await?;
                    self.snapshot.withdrawal_attempts[attempt_index].phase =
                        WithdrawalPhase::FirstArmed;
                    self.checkpoint()?;
                }
                WithdrawalPhase::FirstArmed => {
                    require_signature_count(self, &attempt.statechain_id, expected_count).await?;
                    let first: Bip448SignFirstResponsePayload = post_json(
                        &self.backend,
                        &self.snapshot.deployment.mercury_url,
                        "bip448-statechain/sign/first",
                        &Bip448SignFirstRequestPayload {
                            statechain_id: attempt.statechain_id.clone(),
                            signed_statechain_id: attempt.signed_statechain_id.clone(),
                            signing_id: attempt.signing_id.clone(),
                        },
                        "withdrawal sign/first",
                    )
                    .await?;
                    let server_public_nonce = normalize_hex(&first.server_pubnonce);
                    coin.secret_nonce = Some(attempt.client_secret_nonce.clone());
                    coin.public_nonce = Some(attempt.client_public_nonce.clone());
                    coin.blinding_factor = Some(attempt.blinding_factor.clone());
                    coin.server_public_nonce = Some(server_public_nonce.clone());
                    let source = attempt_source(&attempt)?;
                    let prepared = attempt_prepared(&attempt)?;
                    let signing = build_bip448_keypath_spend_signing_data(
                        &coin,
                        &record.aggregate_pubkey,
                        &source,
                        &prepared,
                    )
                    .map_err(|error| error.to_string())?;
                    if signing.encoded_unsigned_tx != attempt.unsigned_tx_hex {
                        return Err("withdrawal signing regenerated different transaction bytes"
                            .to_string());
                    }
                    let request = Bip448PartialSignatureRequestPayload {
                        statechain_id: signing.partial_signature_request_payload.statechain_id,
                        signed_statechain_id: signing
                            .partial_signature_request_payload
                            .signed_statechain_id,
                        signing_id: attempt.signing_id.clone(),
                        negate_seckey: signing.partial_signature_request_payload.negate_seckey,
                        session: signing.partial_signature_request_payload.session,
                        server_pub_nonce: signing
                            .partial_signature_request_payload
                            .server_pub_nonce,
                    };
                    let stored = &mut self.snapshot.withdrawal_attempts[attempt_index];
                    stored.server_public_nonce = Some(server_public_nonce);
                    stored.message_hex = Some(signing.msg);
                    stored.output_pubkey = Some(signing.output_pubkey);
                    stored.client_partial_sig = Some(signing.client_partial_sig);
                    stored.encoded_session = Some(signing.encoded_session);
                    stored.sign_second_payload = Some(request);
                    stored.phase = WithdrawalPhase::NonceStored;
                    self.checkpoint()?;
                }
                WithdrawalPhase::NonceStored => {
                    require_signature_count(self, &attempt.statechain_id, expected_count).await?;
                    self.snapshot.withdrawal_attempts[attempt_index].phase =
                        WithdrawalPhase::SecondArmed;
                    self.checkpoint()?;
                }
                WithdrawalPhase::SecondArmed => {
                    let before = signature_count(self, &attempt.statechain_id).await?;
                    if before != expected_count && before != expected_count + 1 {
                        return Err(format!(
                            "Lockbox signature count is {before}, expected {expected_count} or {} while resuming sign/second",
                            expected_count + 1
                        ));
                    }
                    let request = attempt
                        .sign_second_payload
                        .clone()
                        .ok_or_else(|| "withdrawal sign/second request is missing".to_string())?;
                    let second: Bip448PartialSignatureResponsePayload = post_json(
                        &self.backend,
                        &self.snapshot.deployment.mercury_url,
                        "bip448-statechain/sign/second",
                        &request,
                        "withdrawal sign/second",
                    )
                    .await?;
                    let server_partial_sig = normalize_hex(&second.partial_sig);
                    let aggregate_signature = aggregate_bip448_keypath_signature(
                        attempt
                            .message_hex
                            .clone()
                            .ok_or_else(|| "withdrawal message is missing".to_string())?,
                        attempt.client_partial_sig.clone().ok_or_else(|| {
                            "withdrawal client partial signature is missing".to_string()
                        })?,
                        server_partial_sig.clone(),
                        attempt
                            .encoded_session
                            .clone()
                            .ok_or_else(|| "withdrawal MuSig session is missing".to_string())?,
                        attempt
                            .output_pubkey
                            .clone()
                            .ok_or_else(|| "withdrawal output key is missing".to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                    let signed_tx_hex = finalize_bip448_keypath_transaction(
                        attempt.unsigned_tx_hex.clone(),
                        aggregate_signature.clone(),
                    )
                    .map_err(|error| error.to_string())?;
                    let transaction: Transaction = deserialize(
                        &hex::decode(&signed_tx_hex).map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                    if hex::encode(serialize(&transaction)) != signed_tx_hex {
                        return Err("withdrawal final transaction is noncanonical".to_string());
                    }
                    require_signature_count(self, &attempt.statechain_id, expected_count + 1)
                        .await?;
                    let stored = &mut self.snapshot.withdrawal_attempts[attempt_index];
                    stored.server_partial_sig = Some(server_partial_sig);
                    stored.aggregate_signature = Some(aggregate_signature);
                    stored.signed_tx_hex = Some(signed_tx_hex);
                    stored.txid = Some(transaction.txid().to_string());
                    stored.phase = WithdrawalPhase::Signed;
                    self.checkpoint()?;
                }
                WithdrawalPhase::Signed => {
                    self.broadcast_withdrawal(attempt_index).await?;
                    if attempt.kind == WithdrawalKind::Canonical {
                        self.complete_canonical_withdrawal(attempt_index).await?;
                    }
                    return self.withdrawal_result(attempt_index);
                }
            }
        }
        Err("withdrawal attempt exceeded its bounded phase driver".to_string())
    }

    fn expected_withdrawal_signature_count(
        &self,
        current: &WithdrawalAttempt,
    ) -> Result<u64, String> {
        let base = u64::from(
            self.snapshot
                .statechain(&current.statechain_id)
                .ok_or_else(|| "withdrawal statechain record disappeared".to_string())?
                .latest_state_number,
        );
        let prior = self
            .snapshot
            .withdrawal_attempts
            .iter()
            .filter(|attempt| {
                attempt.statechain_id == current.statechain_id
                    && attempt.signing_id != current.signing_id
                    && attempt.phase == WithdrawalPhase::Signed
            })
            .count();
        base.checked_add(u64::try_from(prior).map_err(|error| error.to_string())?)
            .ok_or_else(|| "withdrawal signature count overflowed".to_string())
    }

    async fn broadcast_withdrawal(&mut self, attempt_index: usize) -> Result<(), String> {
        let attempt = self.snapshot.withdrawal_attempts[attempt_index].clone();
        if matches!(
            attempt.broadcast_status,
            WithdrawalBroadcastStatus::Accepted | WithdrawalBroadcastStatus::Confirmed
        ) {
            return Ok(());
        }
        let txid = attempt
            .txid
            .clone()
            .ok_or_else(|| "signed withdrawal txid is missing".to_string())?;
        let response = self
            .backend
            .post_text(
                &self.snapshot.deployment.chain_url,
                "tx",
                attempt
                    .signed_tx_hex
                    .as_deref()
                    .ok_or_else(|| "signed withdrawal bytes are missing".to_string())?,
            )
            .await?;
        let response_text = response.body.to_ascii_lowercase();
        let already_known = response_text.contains("txn-already")
            || response_text.contains("already known")
            || response_text.contains("already in mempool")
            || response_text.contains("already in block chain");
        if !response.is_success() && !already_known {
            self.snapshot.withdrawal_attempts[attempt_index].broadcast_status =
                WithdrawalBroadcastStatus::NeedsRebroadcast;
            self.checkpoint()?;
            return Err(format!(
                "Mutinynet transaction broadcast returned {}: {}",
                response.status, response.body
            ));
        }
        let returned = response.body.trim().trim_matches('"');
        if response.is_success() && !returned.is_empty() && returned != txid {
            return Err(format!(
                "Mutinynet returned transaction id {returned}, expected {txid}"
            ));
        }
        self.snapshot.withdrawal_attempts[attempt_index].broadcast_status =
            WithdrawalBroadcastStatus::Accepted;
        let activity_action = if attempt.kind == WithdrawalKind::Canonical {
            "Cooperative withdrawal".to_string()
        } else {
            format!("Cooperative duplicate sweep #{}", attempt.binding_index)
        };
        if !self
            .snapshot
            .wallet
            .activities
            .iter()
            .any(|activity| activity.utxo == txid && activity.action == activity_action)
        {
            self.snapshot.wallet.activities.push(Activity {
                utxo: txid,
                amount: u32::try_from(attempt.source_value_sats)
                    .map_err(|_| "withdrawal amount does not fit wallet activity".to_string())?,
                action: activity_action,
                date: self.backend.now_iso(),
            });
        }
        self.checkpoint()
    }

    async fn complete_canonical_withdrawal(&mut self, attempt_index: usize) -> Result<(), String> {
        let attempt = self.snapshot.withdrawal_attempts[attempt_index].clone();
        if attempt.completion_status == WithdrawalCompletionStatus::Closed {
            return Ok(());
        }
        if attempt.completion_status == WithdrawalCompletionStatus::Open {
            self.snapshot.withdrawal_attempts[attempt_index].completion_status =
                WithdrawalCompletionStatus::CloseArmed;
            self.persist_canonical_wallet(&attempt)?;
            self.checkpoint()?;
        }
        let body = serde_json::to_string(&WithdrawCompletePayload {
            statechain_id: attempt.statechain_id.clone(),
            signed_statechain_id: attempt.signed_statechain_id.clone(),
        })
        .map_err(|error| error.to_string())?;
        let response = self
            .backend
            .post_json(
                &self.snapshot.deployment.mercury_url,
                "withdraw/complete",
                &body,
            )
            .await?;
        if !response.is_success() {
            let presence = self
                .backend
                .get(
                    &self.snapshot.deployment.mercury_url,
                    &format!("info/statechain/{}", attempt.statechain_id),
                )
                .await?;
            if presence.status != 404 {
                return Err(format!(
                    "Mercury withdrawal completion returned {}: {}",
                    response.status, response.body
                ));
            }
        }
        self.snapshot.withdrawal_attempts[attempt_index].completion_status =
            WithdrawalCompletionStatus::Closed;
        let completed = self.snapshot.withdrawal_attempts[attempt_index].clone();
        self.persist_canonical_wallet(&completed)?;
        self.checkpoint()
    }

    fn persist_canonical_wallet(&mut self, attempt: &WithdrawalAttempt) -> Result<(), String> {
        let coin = self
            .snapshot
            .wallet
            .coins
            .iter_mut()
            .filter(|coin| {
                coin.statechain_id.as_deref() == Some(attempt.statechain_id.as_str())
                    && coin.status != CoinStatus::TRANSFERRED
            })
            .max_by_key(|coin| coin.locktime.unwrap_or_default())
            .ok_or_else(|| "canonical withdrawal coin disappeared".to_string())?;
        coin.tx_withdraw = attempt.signed_tx_hex.clone();
        coin.withdrawal_address = Some(attempt.destination_address.clone());
        coin.status = if attempt.completion_status == WithdrawalCompletionStatus::Closed {
            CoinStatus::WITHDRAWN
        } else {
            CoinStatus::WITHDRAWING
        };
        Ok(())
    }

    fn withdrawal_result(&self, attempt_index: usize) -> Result<WithdrawalResult, String> {
        let attempt = self
            .snapshot
            .withdrawal_attempts
            .get(attempt_index)
            .ok_or_else(|| "withdrawal attempt disappeared".to_string())?;
        Ok(WithdrawalResult {
            statechain_id: attempt.statechain_id.clone(),
            duplicate_index: attempt.binding_index,
            source_outpoint: format!("{}:{}", attempt.source_txid, attempt.source_vout),
            amount_sats: attempt.source_value_sats,
            destination_address: attempt.destination_address.clone(),
            txid: attempt
                .txid
                .clone()
                .ok_or_else(|| "withdrawal txid is missing".to_string())?,
            broadcast_status: attempt.broadcast_status,
            exit_only: true,
            statechain_closed: attempt.completion_status == WithdrawalCompletionStatus::Closed,
        })
    }
}

async fn signature_count<B: Backend>(
    client: &WalletClient<B>,
    statechain_id: &str,
) -> Result<u64, String> {
    let response: Bip448SignatureCountResponsePayload = get_json(
        &client.backend,
        &client.snapshot.deployment.mercury_url,
        &format!("bip448-statechain/signature-count/{statechain_id}"),
        "withdrawal signature count",
    )
    .await?;
    Ok(response.sig_count)
}

async fn require_signature_count<B: Backend>(
    client: &WalletClient<B>,
    statechain_id: &str,
    expected: u64,
) -> Result<(), String> {
    let actual = signature_count(client, statechain_id).await?;
    if actual != expected {
        return Err(format!(
            "Lockbox signature count is {actual}, expected {expected}"
        ));
    }
    Ok(())
}

fn withdrawal_coin<'a>(coins: &'a [Coin], statechain_id: &str) -> Result<&'a Coin, String> {
    coins
        .iter()
        .filter(|coin| {
            coin.statechain_id.as_deref() == Some(statechain_id)
                && coin.status != CoinStatus::TRANSFERRED
        })
        .max_by_key(|coin| coin.locktime.unwrap_or_default())
        .ok_or_else(|| format!("wallet coin {statechain_id} is missing"))
}

fn duplicate_is_resolved(
    attempts: &[WithdrawalAttempt],
    binding: &crate::model::FundingBinding,
) -> bool {
    if binding.observation_status == "SpentConfirmed" {
        return true;
    }
    attempts.iter().any(|attempt| {
        attempt.statechain_id == binding.statechain_id
            && attempt.binding_index == binding.binding_index
            && attempt.kind == WithdrawalKind::Duplicate
            && attempt.phase == WithdrawalPhase::Signed
            && matches!(
                attempt.broadcast_status,
                WithdrawalBroadcastStatus::Accepted | WithdrawalBroadcastStatus::Confirmed
            )
    })
}

fn validate_invocation(
    attempt: &WithdrawalAttempt,
    kind: WithdrawalKind,
    destination_address: &str,
    fee_rate: f64,
) -> Result<(), String> {
    if attempt.kind != kind
        || attempt.destination_address != destination_address
        || attempt.fee_rate_sat_per_vbyte.to_bits() != fee_rate.to_bits()
    {
        return Err(
            "retry the saved withdrawal with the exact destination and fee rate".to_string(),
        );
    }
    Ok(())
}

fn attempt_source(attempt: &WithdrawalAttempt) -> Result<Bip448KeypathSpendSource, String> {
    Ok(Bip448KeypathSpendSource {
        outpoint: OutPoint {
            txid: Txid::from_str(&attempt.source_txid).map_err(|error| error.to_string())?,
            vout: attempt.source_vout,
        },
        value_sats: attempt.source_value_sats,
        script_pubkey: ScriptBuf::from_bytes(
            hex::decode(&attempt.source_script_pubkey).map_err(|error| error.to_string())?,
        ),
    })
}

fn attempt_prepared(attempt: &WithdrawalAttempt) -> Result<Bip448PreparedKeypathSpend, String> {
    Ok(Bip448PreparedKeypathSpend {
        unsigned_tx: hex::decode(&attempt.unsigned_tx_hex).map_err(|error| error.to_string())?,
        fee_sats: attempt.fee_sats,
        destination_script_pubkey: ScriptBuf::from_bytes(
            hex::decode(&attempt.destination_script_pubkey).map_err(|error| error.to_string())?,
        ),
        output_value_sats: attempt
            .source_value_sats
            .checked_sub(attempt.fee_sats)
            .ok_or_else(|| "withdrawal fee exceeds source value".to_string())?,
        lock_time: attempt.lock_time,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        rc::Rc,
    };

    use bitcoin::hashes::Hash;

    use secp256k1::{
        musig::{
            new_musig_nonce_pair, MusigSessionId, SecretNonce as MusigSecretNonce,
            Session as MusigSession,
        },
        KeyPair, Secp256k1,
    };

    use super::*;
    use crate::api::ApiResponse;

    struct ServerNonce {
        secret: Option<MusigSecretNonce>,
        public: String,
    }

    #[derive(Clone)]
    struct WithdrawalBackend {
        signature_count: Rc<Cell<u64>>,
        nonces: Rc<RefCell<BTreeMap<String, ServerNonce>>>,
        partials: Rc<RefCell<BTreeMap<String, String>>>,
        canonical_txid: String,
        broadcasts: Rc<RefCell<Vec<String>>>,
        completions: Rc<Cell<u32>>,
        checkpoints: Rc<RefCell<Vec<String>>>,
    }

    impl Default for WithdrawalBackend {
        fn default() -> Self {
            let canonical_txid = crate::test_support::recovery_snapshot().statechains[0]
                .funding_outpoint
                .txid
                .clone();
            Self {
                signature_count: Rc::new(Cell::new(1)),
                nonces: Rc::new(RefCell::new(BTreeMap::new())),
                partials: Rc::new(RefCell::new(BTreeMap::new())),
                canonical_txid,
                broadcasts: Rc::new(RefCell::new(Vec::new())),
                completions: Rc::new(Cell::new(0)),
                checkpoints: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl Backend for WithdrawalBackend {
        async fn get(&self, _base_url: &str, path: &str) -> Result<ApiResponse, String> {
            let body = if path == "blocks/tip/height" {
                "105".to_string()
            } else if path.starts_with("address/") && path.ends_with("/utxo") {
                serde_json::json!([
                    {
                        "txid": self.canonical_txid.clone(),
                        "vout": 0,
                        "value": 50_000,
                        "status": {"confirmed": true, "block_height": 100}
                    },
                    {
                        "txid": Txid::from_slice(&[14; 32]).unwrap().to_string(),
                        "vout": 1,
                        "value": 30_000,
                        "status": {"confirmed": true, "block_height": 100}
                    }
                ])
                .to_string()
            } else if path == "bip448-statechain/signature-count/statechain" {
                serde_json::json!({"sig_count": self.signature_count.get()}).to_string()
            } else {
                return Err(format!("unexpected withdrawal GET {path}"));
            };
            Ok(ApiResponse { status: 200, body })
        }

        async fn post_json(
            &self,
            _base_url: &str,
            path: &str,
            body: &str,
        ) -> Result<ApiResponse, String> {
            let body = match path {
                "bip448-statechain/sign/first" => {
                    let request: Bip448SignFirstRequestPayload =
                        serde_json::from_str(body).map_err(|error| error.to_string())?;
                    if !self.nonces.borrow().contains_key(&request.signing_id) {
                        let server_secret = SecretKey::from_secret_bytes([7; 32])
                            .map_err(|error| error.to_string())?;
                        let server_keypair =
                            KeyPair::from_secret_key(&Secp256k1::new(), &server_secret);
                        let session_id: [u8; 32] = hex::decode(&request.signing_id)
                            .map_err(|error| error.to_string())?
                            .try_into()
                            .map_err(|_| "signing id is not 32 bytes".to_string())?;
                        let (secret, public) = new_musig_nonce_pair(
                            &Secp256k1::new(),
                            MusigSessionId::assume_unique_per_nonce_gen(session_id),
                            None,
                            Some(server_secret),
                            server_keypair.public_key(),
                            None,
                            None,
                        )
                        .map_err(|error| error.to_string())?;
                        self.nonces.borrow_mut().insert(
                            request.signing_id.clone(),
                            ServerNonce {
                                secret: Some(secret),
                                public: hex::encode(public.serialize()),
                            },
                        );
                    }
                    let public = self
                        .nonces
                        .borrow()
                        .get(&request.signing_id)
                        .ok_or_else(|| "server nonce disappeared".to_string())?
                        .public
                        .clone();
                    serde_json::json!({"server_pubnonce": public}).to_string()
                }
                "bip448-statechain/sign/second" => {
                    let request: Bip448PartialSignatureRequestPayload =
                        serde_json::from_str(body).map_err(|error| error.to_string())?;
                    let cached = { self.partials.borrow().get(&request.signing_id).cloned() };
                    if let Some(partial) = cached {
                        serde_json::json!({"partial_sig": partial}).to_string()
                    } else {
                        let server_secret = SecretKey::from_secret_bytes([7; 32])
                            .map_err(|error| error.to_string())?;
                        let server_keypair =
                            KeyPair::from_secret_key(&Secp256k1::new(), &server_secret);
                        let secret_nonce = self
                            .nonces
                            .borrow_mut()
                            .get_mut(&request.signing_id)
                            .and_then(|round| round.secret.take())
                            .ok_or_else(|| "server secret nonce is missing".to_string())?;
                        let encoded_session: [u8; 133] = hex::decode(&request.session)
                            .map_err(|error| error.to_string())?
                            .try_into()
                            .map_err(|_| "blinded session is not 133 bytes".to_string())?;
                        let partial = MusigSession::from_slice(encoded_session)
                            .blinded_partial_sign_without_keyaggcoeff(
                                &Secp256k1::new(),
                                secret_nonce,
                                &server_keypair,
                                request.negate_seckey == 1,
                            )
                            .map_err(|error| error.to_string())?;
                        let partial = hex::encode(partial.serialize());
                        self.partials
                            .borrow_mut()
                            .insert(request.signing_id, partial.clone());
                        self.signature_count
                            .set(self.signature_count.get().checked_add(1).unwrap());
                        serde_json::json!({"partial_sig": partial}).to_string()
                    }
                }
                "withdraw/complete" => {
                    let payload: WithdrawCompletePayload =
                        serde_json::from_str(body).map_err(|error| error.to_string())?;
                    if payload.statechain_id != "statechain"
                        || payload.signed_statechain_id != "signed"
                    {
                        return Err("withdrawal completion authorization changed".to_string());
                    }
                    self.completions.set(self.completions.get() + 1);
                    serde_json::json!({"message": "withdrawn"}).to_string()
                }
                _ => return Err(format!("unexpected withdrawal POST {path}")),
            };
            Ok(ApiResponse { status: 200, body })
        }

        async fn post_text(
            &self,
            _base_url: &str,
            path: &str,
            body: &str,
        ) -> Result<ApiResponse, String> {
            if path != "tx" {
                return Err(format!("unexpected withdrawal text POST {path}"));
            }
            let transaction: Transaction =
                deserialize(&hex::decode(body).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            let txid = transaction.txid().to_string();
            self.broadcasts.borrow_mut().push(body.to_string());
            Ok(ApiResponse {
                status: 200,
                body: txid,
            })
        }

        fn checkpoint(&self, snapshot: &str) -> Result<(), String> {
            self.checkpoints.borrow_mut().push(snapshot.to_string());
            Ok(())
        }

        fn now_iso(&self) -> String {
            "2026-01-01T00:00:00.000Z".to_string()
        }
    }

    #[tokio::test]
    async fn duplicate_then_canonical_withdrawal_runs_every_durable_phase() {
        let backend = WithdrawalBackend::default();
        let observed = backend.clone();
        let mut client = WalletClient::from_snapshot(
            include_str!("../tests/fixtures/recovery-ready.json"),
            backend,
        )
        .unwrap();
        let destination = client.snapshot.wallet.coins[0].backup_address.clone();
        let below_minimum = client
            .withdraw_statecoin("statechain", &destination, 0.09)
            .await
            .unwrap_err();
        assert_eq!(below_minimum, "fee rate must be between 0.1 and 10 sat/vB");

        let duplicate = client
            .sweep_duplicate("statechain", 1, &destination, 0.1)
            .await
            .unwrap();
        assert_eq!(duplicate.duplicate_index, 1);
        assert!(!duplicate.statechain_closed);
        assert_eq!(
            duplicate.broadcast_status,
            WithdrawalBroadcastStatus::Accepted
        );

        let canonical = client
            .withdraw_statecoin("statechain", &destination, 0.1)
            .await
            .unwrap();
        assert_eq!(canonical.duplicate_index, 0);
        assert!(canonical.statechain_closed);
        assert_eq!(
            canonical.broadcast_status,
            WithdrawalBroadcastStatus::Accepted
        );
        assert_eq!(observed.signature_count.get(), 3);
        assert_eq!(observed.broadcasts.borrow().len(), 2);
        assert_eq!(observed.completions.get(), 1);
        assert_eq!(
            client.snapshot.wallet.coins[0].status,
            CoinStatus::WITHDRAWN
        );
        let view = client.view().unwrap();
        assert!(!view.coins[0].exit_only);
        assert_eq!(view.coins[0].withdrawal_status.as_deref(), Some("complete"));

        for snapshot in observed.checkpoints.borrow().iter() {
            WalletClient::from_snapshot(snapshot, observed.clone())
                .expect("every withdrawal checkpoint must restore");
        }

        let replay = client
            .withdraw_statecoin("statechain", &destination, 0.1)
            .await
            .unwrap();
        assert_eq!(replay.txid, canonical.txid);
        assert_eq!(observed.broadcasts.borrow().len(), 2);
        assert_eq!(observed.completions.get(), 1);
    }
}
