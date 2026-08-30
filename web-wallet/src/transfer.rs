use std::str::FromStr;

use bitcoin::{
    absolute, consensus::deserialize, hashes::Hash, Address, Network, OutPoint, PrivateKey,
    Transaction, Txid,
};
use mercurylib::{
    bip448_statechain::{
        deposit::BIP448_COIN_PROTOCOL,
        script::{
            checked_next_state_locktime, funding_spend_info, output_script_pubkey,
            sample_future_state_stride,
        },
        signing::{CsfsSigningParticipant, CsfsSigningRole, CsfsSigningSession},
        signing_api::{
            Bip448CompressedPublicKey, Bip448KeyUpdateAppliedReceiptPayloadV1, Bip448OperationId,
            Bip448PartialSignatureRequestPayload, Bip448PartialSignatureResponsePayload,
            Bip448ProtocolVersionV1, Bip448SchnorrSignature, Bip448SecretScalar,
            Bip448SignFirstRequestPayload, Bip448SignFirstResponsePayload,
            Bip448SignatureCountResponsePayload, Bip448StatechainId,
            Bip448StatechainInfoResponsePayloadV1,
        },
        storage::{
            build_funding_latest_state, build_funding_recovery_artifacts, Bip448RecoveryArtifacts,
            Bip448RecoveryTemplateRole, Bip448SigningMetadata, Bip448StatechainRecord,
        },
    },
    decode_transfer_address,
    transfer::{
        bip448::{
            decrypt_bip448_transfer_msg, verify_bip448_transfer_msg, Bip448StateHistoryEntry,
            Bip448TransferChainFacts, Bip448TransferMsg, BIP448_TRANSFER_MESSAGE_VERSION,
        },
        receiver::{
            bip448_transfer_unlock_auth_digest, sign_message, Bip448TransferUnlockRole,
            GetMsgAddrResponsePayload, StatechainInfo, StatechainInfoResponsePayload,
            TransferReceiverRequestPayloadV1, TransferUnlockRequestPayload,
        },
        sender::{
            bip448_transfer_update_msg_auth_digest, create_transfer_signature,
            TransferSenderRequestPayload, TransferSenderResponsePayload,
            TransferUpdateMsgRequestPayload,
        },
    },
    validate_address,
    wallet::{Activity, Coin, CoinStatus},
};
use secp256k1::{
    musig::{new_musig_nonce_pair, BlindingFactor, MusigSessionId, PartialSignature, PublicNonce},
    rand, schnorr, KeyPair, Message, PublicKey, Scalar, Secp256k1, SecretKey,
};
use serde::Deserialize;

use crate::{
    api::Backend,
    client::{
        chain_tip, checked_response, get_json, median_time_past, normalize_hex, post_json,
        required, secret_nonce_from_hex, WalletClient,
    },
    model::{
        PendingBip448Signing, PendingIncomingTransfer, PendingOutgoingTransfer,
        StatecoinReceiveResult, StatecoinSendResult, TransferAddressResult,
        TransferCancellationResult, WithdrawalBroadcastStatus, CONFIRMATION_TARGET,
    },
};

#[derive(Debug, Deserialize)]
struct EsploraTransferStatus {
    confirmed: bool,
    block_height: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct EsploraTransferUtxo {
    txid: String,
    vout: u32,
    status: EsploraTransferStatus,
}

fn random_batch_id() -> String {
    let mut bytes = SecretKey::new(&mut rand::rng()).to_secret_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(&bytes[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

impl<B: Backend> WalletClient<B> {
    pub fn create_transfer_address(&mut self) -> Result<TransferAddressResult, String> {
        self.create_transfer_address_with_batch(false)
    }

    pub fn create_transfer_address_with_batch(
        &mut self,
        generate_batch_id: bool,
    ) -> Result<TransferAddressResult, String> {
        let coin = self.get_new_unreserved_coin()?;
        let address = coin.address.clone();
        self.snapshot.wallet.coins.push(coin);
        self.checkpoint()?;
        Ok(TransferAddressResult {
            address,
            batch_id: generate_batch_id.then(random_batch_id),
        })
    }

    pub async fn send_statecoin(
        &mut self,
        statechain_id: &str,
        recipient_address: &str,
    ) -> Result<StatecoinSendResult, String> {
        self.send_statecoin_with_options(statechain_id, recipient_address, None, false)
            .await
    }

    pub async fn send_statecoin_with_options(
        &mut self,
        statechain_id: &str,
        recipient_address: &str,
        batch_id: Option<String>,
        acknowledge_cooperative_duplicates: bool,
    ) -> Result<StatecoinSendResult, String> {
        let batch_id = batch_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if !validate_address(recipient_address, &self.snapshot.wallet.network)
            .map_err(error_string)?
        {
            return Err("recipient is not a valid Mutinynet statecoin address".to_string());
        }
        if self
            .snapshot
            .recovery_attempts
            .iter()
            .any(|attempt| attempt.statechain_id == statechain_id)
        {
            return Err(
                "a unilateral exit has started; this statecoin can no longer be sent offchain"
                    .to_string(),
            );
        }
        if self
            .snapshot
            .withdrawal_attempts
            .iter()
            .any(|attempt| attempt.statechain_id == statechain_id)
        {
            return Err(
                "a cooperative withdrawal attempt has started; this statecoin is exit-only"
                    .to_string(),
            );
        }

        let record = self
            .snapshot
            .statechain(statechain_id)
            .cloned()
            .ok_or_else(|| format!("statechain {statechain_id} is not in this wallet"))?;
        let coin = owned_coin(&self.snapshot.wallet.coins, statechain_id)?.clone();
        if coin.status != CoinStatus::CONFIRMED && coin.status != CoinStatus::IN_TRANSFER {
            return Err("statecoin must be confirmed before an offchain send".to_string());
        }
        let unresolved_duplicates = self
            .snapshot
            .funding_bindings
            .iter()
            .filter(|binding| {
                binding.statechain_id == statechain_id
                    && binding.binding_index != 0
                    && binding.owner_state_number == record.latest_state_number
                    && matches!(
                        binding.observation_status.as_str(),
                        "Mempool" | "Unconfirmed" | "Confirmed"
                    )
                    && !self.snapshot.withdrawal_attempts.iter().any(|attempt| {
                        attempt.statechain_id == statechain_id
                            && attempt.binding_index == binding.binding_index
                            && matches!(
                                attempt.broadcast_status,
                                WithdrawalBroadcastStatus::Accepted
                                    | WithdrawalBroadcastStatus::Confirmed
                                    | WithdrawalBroadcastStatus::Conflicted
                            )
                    })
            })
            .count();
        if unresolved_duplicates != 0
            && !acknowledge_cooperative_duplicates
            && self.snapshot.pending_outgoing_transfer.is_none()
        {
            return Err(format!(
                "{unresolved_duplicates} cooperative duplicate value(s) require explicit acknowledgement before transfer"
            ));
        }
        let (_, receiver_user_pubkey, recipient_auth_pubkey) =
            decode_transfer_address(recipient_address).map_err(error_string)?;

        match self.snapshot.pending_outgoing_transfer.as_ref() {
            Some(pending)
                if pending.statechain_id == statechain_id
                    && pending.recipient_address == recipient_address
                    && pending.batch_id == batch_id
                    && pending.acknowledge_cooperative_duplicates
                        == acknowledge_cooperative_duplicates => {}
            Some(_) => {
                return Err("finish the existing offchain send before starting another".to_string())
            }
            None => {
                self.snapshot.pending_outgoing_transfer = Some(PendingOutgoingTransfer {
                    statechain_id: statechain_id.to_string(),
                    recipient_address: recipient_address.to_string(),
                    receiver_user_pubkey: receiver_user_pubkey.to_string(),
                    recipient_auth_pubkey: recipient_auth_pubkey.to_string(),
                    x1: None,
                    signing: None,
                    update_signature: None,
                    message: None,
                    encrypted_message: None,
                    batch_id,
                    acknowledge_cooperative_duplicates,
                    intent_kind: "user_transfer".to_string(),
                    predecessor_message: None,
                    delivered: false,
                });
                self.checkpoint()?;
            }
        }

        if self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .is_some_and(|pending| pending.delivered)
        {
            return Ok(StatecoinSendResult {
                statechain_id: statechain_id.to_string(),
                recipient_address: recipient_address.to_string(),
                status: "sent; completes when recipient wallet syncs".to_string(),
            });
        }

        self.ensure_transfer_x1(&coin).await?;
        self.ensure_transfer_signing(&coin, &record, &receiver_user_pubkey)
            .await?;
        self.ensure_transfer_message(&coin, &record, &receiver_user_pubkey)
            .await?;
        self.deliver_transfer_message(&coin, &recipient_auth_pubkey)
            .await?;

        if let Some(wallet_coin) = self
            .snapshot
            .wallet
            .coins
            .iter_mut()
            .filter(|candidate| {
                candidate.statechain_id.as_deref() == Some(statechain_id)
                    && candidate.status != CoinStatus::TRANSFERRED
            })
            .max_by_key(|candidate| candidate.locktime.unwrap_or_default())
        {
            wallet_coin.status = CoinStatus::IN_TRANSFER;
        }
        let pending = self
            .snapshot
            .pending_outgoing_transfer
            .as_mut()
            .ok_or_else(|| "offchain send state disappeared".to_string())?;
        pending.delivered = true;
        let action = if pending.intent_kind == "cancellation" {
            "Transfer cancellation awaiting acceptance"
        } else {
            "Offchain send delivered; recipient sync pending"
        };
        self.snapshot.wallet.activities.push(Activity {
            utxo: format!(
                "{}:{}",
                record.funding_outpoint.txid, record.funding_outpoint.vout
            ),
            amount: u32::try_from(record.amount_sats)
                .map_err(|_| "statecoin amount does not fit wallet format".to_string())?,
            action: action.to_string(),
            date: self.backend.now_iso(),
        });
        self.checkpoint()?;

        Ok(StatecoinSendResult {
            statechain_id: statechain_id.to_string(),
            recipient_address: recipient_address.to_string(),
            status: "sent; completes when recipient wallet syncs".to_string(),
        })
    }

    pub async fn cancel_statecoin_transfer(
        &mut self,
        statechain_id: &str,
    ) -> Result<TransferCancellationResult, String> {
        let initial = self
            .snapshot
            .pending_outgoing_transfer
            .clone()
            .filter(|pending| pending.statechain_id == statechain_id)
            .ok_or_else(|| "statechain has no in-flight transfer to cancel".to_string())?;
        if initial.intent_kind != "user_transfer" && initial.intent_kind != "cancellation" {
            return Err("saved transfer intent cannot be cancelled".to_string());
        }
        if initial.intent_kind == "user_transfer" && initial.batch_id.is_some() {
            return Err(
                "a batched transfer cannot be cancelled; wait for its unlock or expiry".to_string(),
            );
        }

        if initial.intent_kind == "user_transfer" {
            self.send_statecoin_with_options(
                statechain_id,
                &initial.recipient_address,
                initial.batch_id.clone(),
                initial.acknowledge_cooperative_duplicates,
            )
            .await?;
            let delivered_state_number = self
                .snapshot
                .pending_outgoing_transfer
                .as_ref()
                .and_then(|pending| pending.message.as_ref())
                .map_or(0, |message| message.latest_state_number);
            if self.reconcile_outgoing_transfer().await?.is_some() {
                return Ok(TransferCancellationResult {
                    statechain_id: statechain_id.to_string(),
                    state_number: delivered_state_number,
                    status: "recipient already accepted the transfer".to_string(),
                });
            }
            let predecessor = self
                .snapshot
                .pending_outgoing_transfer
                .as_ref()
                .and_then(|pending| pending.message.clone())
                .ok_or_else(|| {
                    "completed transfer message is unavailable for cancellation".to_string()
                })?;
            let generated = self.snapshot.wallet.get_new_coin().map_err(error_string)?;
            let recipient_address = generated.address.clone();
            let (_, receiver_user_pubkey, recipient_auth_pubkey) =
                decode_transfer_address(&recipient_address).map_err(error_string)?;
            self.snapshot.wallet.coins.push(generated);
            let record = self
                .snapshot
                .statechains
                .iter_mut()
                .find(|record| record.statechain_id == statechain_id)
                .ok_or_else(|| "statechain record disappeared during cancellation".to_string())?;
            record.latest_state_number = predecessor.latest_state_number;
            record.latest_state = predecessor.latest_state.clone();
            self.snapshot
                .state_histories
                .insert(statechain_id.to_string(), predecessor.state_history.clone());
            self.snapshot.pending_outgoing_transfer = Some(PendingOutgoingTransfer {
                statechain_id: statechain_id.to_string(),
                recipient_address,
                receiver_user_pubkey: receiver_user_pubkey.to_string(),
                recipient_auth_pubkey: recipient_auth_pubkey.to_string(),
                x1: None,
                signing: None,
                update_signature: None,
                message: None,
                encrypted_message: None,
                batch_id: None,
                acknowledge_cooperative_duplicates: true,
                intent_kind: "cancellation".to_string(),
                predecessor_message: Some(predecessor),
                delivered: false,
            });
            self.checkpoint()?;
        }

        let cancellation = self
            .snapshot
            .pending_outgoing_transfer
            .clone()
            .filter(|pending| {
                pending.statechain_id == statechain_id && pending.intent_kind == "cancellation"
            })
            .ok_or_else(|| "cancellation intent disappeared".to_string())?;
        self.send_statecoin_with_options(
            statechain_id,
            &cancellation.recipient_address,
            None,
            true,
        )
        .await?;
        let received = self.receive_statecoins().await?;
        if !received
            .received_statechain_ids
            .iter()
            .any(|received_id| received_id == statechain_id)
            && self.snapshot.pending_outgoing_transfer.is_some()
        {
            return Err(
                "cancellation message is waiting for local receiver acceptance".to_string(),
            );
        }
        let state_number = self
            .snapshot
            .statechain(statechain_id)
            .ok_or_else(|| "cancelled statechain record is missing".to_string())?
            .latest_state_number;
        Ok(TransferCancellationResult {
            statechain_id: statechain_id.to_string(),
            state_number,
            status: "cancelled back to this wallet".to_string(),
        })
    }

    pub async fn receive_statecoins(&mut self) -> Result<StatecoinReceiveResult, String> {
        let checked_addresses = self
            .snapshot
            .wallet
            .coins
            .iter()
            .filter(|coin| coin.status == CoinStatus::INITIALISED)
            .count();
        let mut received = Vec::new();

        if self.snapshot.pending_incoming_transfer.is_some() {
            received.push(self.resume_incoming_transfer().await?);
        }

        let addresses = self
            .snapshot
            .wallet
            .coins
            .iter()
            .filter(|coin| coin.status == CoinStatus::INITIALISED)
            .map(|coin| coin.auth_pubkey.clone())
            .collect::<Vec<_>>();
        for auth_pubkey in addresses {
            let mailbox: GetMsgAddrResponsePayload = get_json(
                &self.backend,
                &self.snapshot.deployment.mercury_url,
                &format!("transfer/get_msg_addr/{auth_pubkey}"),
                "statecoin receive mailbox",
            )
            .await?;
            for encrypted_message in mailbox.list_enc_transfer_msg {
                let coin = self
                    .snapshot
                    .wallet
                    .coins
                    .iter()
                    .find(|coin| {
                        coin.status == CoinStatus::INITIALISED && coin.auth_pubkey == auth_pubkey
                    })
                    .ok_or_else(|| "receive address disappeared".to_string())?;
                let message = decrypt_bip448_transfer_msg(&encrypted_message, &coin.auth_privkey)
                    .map_err(error_string)?;
                let is_cancellation = self
                    .snapshot
                    .pending_outgoing_transfer
                    .as_ref()
                    .is_some_and(|pending| {
                        pending.intent_kind == "cancellation"
                            && pending.statechain_id == message.statechain_id
                            && pending.recipient_auth_pubkey == auth_pubkey
                    });
                if self.snapshot.statechain(&message.statechain_id).is_some() && !is_cancellation {
                    continue;
                }
                let mut rng = rand::rng();
                self.snapshot.pending_incoming_transfer = Some(PendingIncomingTransfer {
                    receiver_auth_pubkey: auth_pubkey.clone(),
                    encrypted_message,
                    operation_id: hex::encode(SecretKey::new(&mut rng).to_secret_bytes()),
                    receiver_request: None,
                    expected_server_pubkey: None,
                });
                self.checkpoint()?;
                received.push(self.resume_incoming_transfer().await?);
                break;
            }
        }

        Ok(StatecoinReceiveResult {
            checked_addresses,
            received_statechain_ids: received,
        })
    }

    pub(crate) async fn reconcile_outgoing_transfer(&mut self) -> Result<Option<String>, String> {
        let Some(pending) = self.snapshot.pending_outgoing_transfer.clone() else {
            return Ok(None);
        };
        if !pending.delivered {
            return Ok(None);
        }
        // H1: the deletion below destroys the sender's unilateral-exit and
        // recovery material, so the ownership observation must come from the
        // attested enclave channel; a Mercury-proxied info/statechain response
        // could claim the receiver's share before the enclave applied it.
        let (attested_server, _) = self
            .prove_enclave_server_share(&pending.statechain_id)
            .await
            .map_err(|error| {
                format!("outgoing statecoin ownership enclave proof failed: {error}")
            })?;
        let current_server = PublicKey::from_str(&attested_server).map_err(error_string)?;
        let message = pending
            .message
            .as_ref()
            .ok_or_else(|| "delivered transfer has no saved message".to_string())?;
        let receiver = PublicKey::from_str(&pending.receiver_user_pubkey).map_err(error_string)?;
        let expected_receiver = expected_receiver_server(message, &receiver)?;
        let sender_server =
            PublicKey::from_str(&message.server_public_key).map_err(error_string)?;
        if current_server == sender_server {
            return Ok(None);
        }
        if current_server != expected_receiver {
            return Err("statecoin rotated to an unrelated owner generation".to_string());
        }
        if pending.intent_kind == "cancellation" {
            return Ok(None);
        }

        self.snapshot
            .wallet
            .coins
            .retain(|coin| coin.statechain_id.as_deref() != Some(pending.statechain_id.as_str()));
        self.snapshot
            .statechains
            .retain(|record| record.statechain_id != pending.statechain_id);
        self.snapshot.state_histories.remove(&pending.statechain_id);
        self.snapshot
            .recovery_attempts
            .retain(|attempt| attempt.statechain_id != pending.statechain_id);
        self.snapshot
            .funding_bindings
            .retain(|binding| binding.statechain_id != pending.statechain_id);
        self.snapshot
            .enclave_verifications
            .retain(|proof| proof.statechain_id != pending.statechain_id);
        self.snapshot.pending_outgoing_transfer = None;
        self.snapshot.wallet.activities.push(Activity {
            utxo: pending.statechain_id.clone(),
            amount: u32::try_from(message.amount_sats)
                .map_err(|_| "statecoin amount does not fit wallet format".to_string())?,
            action: "Offchain send completed".to_string(),
            date: self.backend.now_iso(),
        });
        self.checkpoint()?;
        Ok(Some(pending.statechain_id))
    }

    async fn ensure_transfer_x1(&mut self, coin: &Coin) -> Result<(), String> {
        if self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .and_then(|pending| pending.x1.as_ref())
            .is_some()
        {
            return Ok(());
        }
        let pending = self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .ok_or_else(|| "offchain send state disappeared".to_string())?;
        let response: TransferSenderResponsePayload = post_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            "transfer/sender",
            &TransferSenderRequestPayload {
                statechain_id: pending.statechain_id.clone(),
                auth_sig: required(&coin.signed_statechain_id, "statechain authorization")?,
                new_user_auth_key: pending.recipient_auth_pubkey.clone(),
                batch_id: pending.batch_id.clone(),
            },
            "offchain send initialization",
        )
        .await?;
        let x1 = scalar_hex(&response.x1, "transfer x1")?;
        self.snapshot
            .pending_outgoing_transfer
            .as_mut()
            .ok_or_else(|| "offchain send state disappeared".to_string())?
            .x1 = Some(x1);
        self.checkpoint()
    }

    async fn ensure_transfer_signing(
        &mut self,
        coin: &Coin,
        record: &Bip448StatechainRecord,
        receiver: &PublicKey,
    ) -> Result<(), String> {
        if self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .and_then(|pending| pending.signing.as_ref())
            .is_none()
        {
            let next_state = record
                .latest_state_number
                .checked_add(1)
                .ok_or_else(|| "state number overflowed".to_string())?;
            let state_locktime = checked_next_state_locktime(
                absolute::LockTime::from_consensus(record.latest_state.state_locktime),
                sample_future_state_stride(),
            )
            .map_err(error_string)?
            .to_consensus_u32();
            let artifacts = transfer_artifacts(record, receiver, next_state, state_locktime)?;
            let secp = Secp256k1::new();
            let client_secret = PrivateKey::from_wif(&coin.user_privkey)
                .map_err(error_string)?
                .inner;
            let client_pubkey = PublicKey::from_str(&coin.user_pubkey).map_err(error_string)?;
            let mut rng = rand::rng();
            let (secret_nonce, public_nonce) = new_musig_nonce_pair(
                &secp,
                MusigSessionId::new(&mut rng),
                None,
                Some(client_secret),
                client_pubkey,
                Some(Message::from(artifacts.update_template_hash)),
                None,
            )
            .map_err(error_string)?;
            let blinding = BlindingFactor::from_slice(&SecretKey::new(&mut rng).to_secret_bytes())
                .map_err(error_string)?;
            let signing = PendingBip448Signing {
                funding_txid: record.funding_outpoint.txid.clone(),
                funding_vout: record.funding_outpoint.vout,
                funding_value_sats: record.funding_outpoint.value_sats,
                state_locktime,
                update_template_hash: hex::encode(artifacts.update_template_hash.to_byte_array()),
                settlement_template_hash: hex::encode(
                    artifacts.settlement_template_hash.to_byte_array(),
                ),
                signing_id: hex::encode(SecretKey::new(&mut rng).to_secret_bytes()),
                client_secret_nonce: hex::encode(secret_nonce.serialize()),
                client_public_nonce: hex::encode(public_nonce.serialize()),
                blinding_factor: hex::encode(blinding.as_bytes()),
                server_public_nonce: None,
                second_armed: false,
            };
            self.snapshot
                .pending_outgoing_transfer
                .as_mut()
                .ok_or_else(|| "offchain send state disappeared".to_string())?
                .signing = Some(signing);
            self.checkpoint()?;
        }

        let mut signing = self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .and_then(|pending| pending.signing.clone())
            .ok_or_else(|| "offchain signing state disappeared".to_string())?;
        let expected_count = u64::from(record.latest_state_number);
        let count = self.signature_count(&record.statechain_id).await?;
        if count != expected_count && count != expected_count + 1 {
            return Err("Lockbox signature count changed during offchain send".to_string());
        }
        if signing.server_public_nonce.is_none() {
            if count != expected_count {
                return Err("offchain sign/first response was not saved before the signature count advanced"
                    .to_string());
            }
            let first: Bip448SignFirstResponsePayload = post_json(
                &self.backend,
                &self.snapshot.deployment.mercury_url,
                "bip448-statechain/sign/first",
                &Bip448SignFirstRequestPayload {
                    statechain_id: record.statechain_id.clone(),
                    signed_statechain_id: required(
                        &coin.signed_statechain_id,
                        "statechain authorization",
                    )?,
                    signing_id: signing.signing_id.clone(),
                },
                "offchain state sign/first",
            )
            .await?;
            signing.server_public_nonce = Some(normalize_hex(&first.server_pubnonce));
            self.snapshot
                .pending_outgoing_transfer
                .as_mut()
                .ok_or_else(|| "offchain send state disappeared".to_string())?
                .signing = Some(signing.clone());
            self.checkpoint()?;
        }

        if self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .and_then(|pending| pending.update_signature.as_ref())
            .is_some()
        {
            if self.signature_count(&record.statechain_id).await? != expected_count + 1 {
                return Err(
                    "saved offchain signature does not match the Lockbox counter".to_string(),
                );
            }
            return Ok(());
        }

        let next_state = record.latest_state_number + 1;
        let artifacts = transfer_artifacts(record, receiver, next_state, signing.state_locktime)?;
        validate_signing(&signing, record, &artifacts)?;
        let secp = Secp256k1::new();
        let client_secret = PrivateKey::from_wif(&coin.user_privkey)
            .map_err(error_string)?
            .inner;
        let client_keypair = KeyPair::from_secret_key(&secp, &client_secret);
        let client_public_nonce = PublicNonce::from_slice(
            &hex::decode(&signing.client_public_nonce).map_err(error_string)?,
        )
        .map_err(error_string)?;
        let server_nonce_text = signing
            .server_public_nonce
            .clone()
            .ok_or_else(|| "offchain server nonce is missing".to_string())?;
        let server_nonce =
            PublicNonce::from_slice(&hex::decode(&server_nonce_text).map_err(error_string)?)
                .map_err(error_string)?;
        let blinding = BlindingFactor::from_slice(
            &hex::decode(&signing.blinding_factor).map_err(error_string)?,
        )
        .map_err(error_string)?;
        let aggregate = PublicKey::from_str(&record.aggregate_pubkey).map_err(error_string)?;
        let session = CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::FundingUpdate,
            aggregate,
            &client_public_nonce,
            &server_nonce,
            artifacts.update_template_hash,
            &blinding,
        )
        .map_err(error_string)?;
        let client_partial = session
            .partial_sign_verified(
                &secp,
                CsfsSigningParticipant::Client,
                secret_nonce_from_hex(&signing.client_secret_nonce)?,
                &client_public_nonce,
                &client_keypair,
            )
            .map_err(error_string)?;
        if !signing.second_armed {
            signing.second_armed = true;
            self.snapshot
                .pending_outgoing_transfer
                .as_mut()
                .ok_or_else(|| "offchain send state disappeared".to_string())?
                .signing = Some(signing.clone());
            self.checkpoint()?;
        }
        let second: Bip448PartialSignatureResponsePayload = post_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            "bip448-statechain/sign/second",
            &Bip448PartialSignatureRequestPayload {
                statechain_id: record.statechain_id.clone(),
                signed_statechain_id: required(
                    &coin.signed_statechain_id,
                    "statechain authorization",
                )?,
                signing_id: signing.signing_id.clone(),
                negate_seckey: u8::from(session.negate_seckey()),
                session: hex::encode(session.blinded_server_session().serialize()),
                server_pub_nonce: server_nonce_text,
            },
            "offchain state sign/second",
        )
        .await?;
        let server_partial = PartialSignature::from_slice(
            &hex::decode(normalize_hex(&second.partial_sig)).map_err(error_string)?,
        )
        .map_err(error_string)?;
        let server_pubkey = PublicKey::from_str(&required(&coin.server_pubkey, "server key")?)
            .map_err(error_string)?;
        session
            .verify_partial(
                &secp,
                CsfsSigningParticipant::Server,
                &server_partial,
                &server_nonce,
                &server_pubkey,
            )
            .map_err(error_string)?;
        let signature = session
            .aggregate_and_verify(&[&client_partial, &server_partial])
            .map_err(error_string)?;
        if self.signature_count(&record.statechain_id).await? != expected_count + 1 {
            return Err("Lockbox did not advance to the next offchain state".to_string());
        }
        self.snapshot
            .pending_outgoing_transfer
            .as_mut()
            .ok_or_else(|| "offchain send state disappeared".to_string())?
            .update_signature = Some(signature.to_string());
        self.checkpoint()
    }

    async fn ensure_transfer_message(
        &mut self,
        coin: &Coin,
        record: &Bip448StatechainRecord,
        receiver: &PublicKey,
    ) -> Result<(), String> {
        if self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .and_then(|pending| pending.message.as_ref())
            .is_some()
        {
            return Ok(());
        }
        let pending = self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .ok_or_else(|| "offchain send state disappeared".to_string())?;
        let x1 = pending
            .x1
            .as_deref()
            .ok_or_else(|| "transfer x1 is missing".to_string())?;
        let signing = pending
            .signing
            .as_ref()
            .ok_or_else(|| "offchain signing state is missing".to_string())?;
        let update_signature = pending
            .update_signature
            .as_deref()
            .ok_or_else(|| "offchain update signature is missing".to_string())?;
        let next_state = record.latest_state_number + 1;
        let artifacts = transfer_artifacts(record, receiver, next_state, signing.state_locktime)?;
        validate_signing(signing, record, &artifacts)?;
        let metadata = Bip448SigningMetadata {
            role: Bip448RecoveryTemplateRole::FundingUpdate,
            signing_id: signing.signing_id.clone(),
            client_public_nonce: signing.client_public_nonce.clone(),
            server_public_nonce: signing
                .server_public_nonce
                .clone()
                .ok_or_else(|| "offchain server nonce is missing".to_string())?,
            blinding_factor: signing.blinding_factor.clone(),
            update_template_hash: signing.update_template_hash.clone(),
            update_signature: update_signature.to_string(),
            server_signature_count: u64::from(next_state),
        };
        let mut history = self
            .snapshot
            .state_history(&record.statechain_id)
            .ok_or_else(|| "statecoin is missing its saved recovery history".to_string())?
            .to_vec();
        if history.len() != record.latest_state_number as usize {
            return Err("statecoin recovery history is incomplete".to_string());
        }
        let latest_state = build_funding_latest_state(
            &Secp256k1::new(),
            &PublicKey::from_str(&record.aggregate_pubkey).map_err(error_string)?,
            &artifacts,
            metadata,
            Vec::new(),
        )
        .map_err(error_string)?;
        history.push(state_history_entry(
            &latest_state,
            receiver.x_only_public_key().0,
        ));
        let x1_bytes = scalar_bytes(x1, "transfer x1")?;
        let t1 = PrivateKey::from_wif(&coin.user_privkey)
            .map_err(error_string)?
            .inner
            .add_tweak(&Scalar::from_be_bytes(x1_bytes).map_err(error_string)?)
            .map_err(error_string)?
            .to_secret_bytes();
        let transfer_signature = create_transfer_signature(
            &pending.recipient_address,
            &record.funding_outpoint.txid,
            record.funding_outpoint.vout,
            &coin.user_privkey,
        )
        .map_err(error_string)?;
        let message = Bip448TransferMsg {
            msg_version: BIP448_TRANSFER_MESSAGE_VERSION,
            statechain_id: record.statechain_id.clone(),
            transfer_signature,
            sender_user_public_key: coin.user_pubkey.clone(),
            receiver_user_public_key: receiver.to_string(),
            server_public_key: required(&coin.server_pubkey, "server key")?,
            aggregate_pubkey: record.aggregate_pubkey.clone(),
            funding_outpoint: record.funding_outpoint.clone(),
            latest_state_number: next_state,
            challenge_delay: record.challenge_delay,
            amount_sats: record.amount_sats,
            network: record.network.clone(),
            value_schedule: latest_state.value_schedule.clone(),
            latest_state,
            server_signature_count: u64::from(next_state),
            t1,
            state_history: history,
        };
        let observed = self.statechain_info(&record.statechain_id).await?;
        let verification_info = statechain_info_for_transfer_verification(&observed)?;
        let facts = transfer_chain_facts(self, &message, *receiver).await?;
        verify_bip448_transfer_msg(&message, &verification_info, &facts).map_err(error_string)?;
        self.snapshot
            .pending_outgoing_transfer
            .as_mut()
            .ok_or_else(|| "offchain send state disappeared".to_string())?
            .message = Some(message);
        self.checkpoint()
    }

    async fn deliver_transfer_message(
        &mut self,
        coin: &Coin,
        recipient_auth: &PublicKey,
    ) -> Result<(), String> {
        if self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .and_then(|pending| pending.encrypted_message.as_ref())
            .is_none()
        {
            let message = self
                .snapshot
                .pending_outgoing_transfer
                .as_ref()
                .and_then(|pending| pending.message.as_ref())
                .ok_or_else(|| "offchain transfer message is missing".to_string())?;
            let encrypted = message.encrypt(recipient_auth).map_err(error_string)?;
            self.snapshot
                .pending_outgoing_transfer
                .as_mut()
                .ok_or_else(|| "offchain send state disappeared".to_string())?
                .encrypted_message = Some(encrypted);
            self.checkpoint()?;
        }
        let pending = self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .ok_or_else(|| "offchain send state disappeared".to_string())?;
        let encrypted = pending
            .encrypted_message
            .as_ref()
            .ok_or_else(|| "encrypted transfer message is missing".to_string())?;
        let decoded = hex::decode(encrypted).map_err(error_string)?;
        let x1 = scalar_bytes(
            pending
                .x1
                .as_deref()
                .ok_or_else(|| "transfer x1 is missing".to_string())?,
            "transfer x1",
        )?;
        let x1_pub = SecretKey::from_secret_bytes(x1)
            .map_err(error_string)?
            .public_key(&Secp256k1::new());
        let digest = bip448_transfer_update_msg_auth_digest(
            &pending.statechain_id,
            recipient_auth,
            &x1_pub,
            &decoded,
        )
        .map_err(error_string)?;
        let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)
            .map_err(error_string)?
            .inner;
        let auth_keypair = KeyPair::from_secret_key(&Secp256k1::new(), &auth_secret);
        let payload = TransferUpdateMsgRequestPayload {
            statechain_id: pending.statechain_id.clone(),
            auth_sig: schnorr::sign(&digest, &auth_keypair).to_string(),
            new_user_auth_key: recipient_auth.to_string(),
            x1_pub: x1_pub.to_string(),
            enc_transfer_msg: encrypted.clone(),
        };
        let body = serde_json::to_string(&payload).map_err(error_string)?;
        let response = self
            .backend
            .post_json(
                &self.snapshot.deployment.mercury_url,
                "transfer/update_msg",
                &body,
            )
            .await?;
        checked_response(response, "offchain transfer delivery")?;
        let mailbox: GetMsgAddrResponsePayload = get_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            &format!("transfer/get_msg_addr/{}", recipient_auth),
            "offchain transfer mailbox confirmation",
        )
        .await?;
        if !mailbox
            .list_enc_transfer_msg
            .iter()
            .any(|candidate| candidate == encrypted)
        {
            return Err("Mercury did not retain the exact encrypted transfer message".to_string());
        }
        Ok(())
    }

    async fn resume_incoming_transfer(&mut self) -> Result<String, String> {
        let pending = self
            .snapshot
            .pending_incoming_transfer
            .clone()
            .ok_or_else(|| "incoming transfer state disappeared".to_string())?;
        let coin = self
            .snapshot
            .wallet
            .coins
            .iter()
            .find(|coin| {
                coin.status == CoinStatus::INITIALISED
                    && coin.auth_pubkey == pending.receiver_auth_pubkey
            })
            .cloned()
            .ok_or_else(|| "incoming transfer address is no longer available".to_string())?;
        let message = decrypt_bip448_transfer_msg(&pending.encrypted_message, &coin.auth_privkey)
            .map_err(error_string)?;

        if pending.receiver_request.is_none() {
            let observed = self.statechain_info(&message.statechain_id).await?;
            let verification_info = statechain_info_for_transfer_verification(&observed)?;
            let receiver = PublicKey::from_str(&coin.user_pubkey).map_err(error_string)?;
            let facts = transfer_chain_facts(self, &message, receiver).await?;
            verify_bip448_transfer_msg(&message, &verification_info, &facts)
                .map_err(error_string)?;
            let x1_generation =
                PublicKey::from_slice(observed.x1_pub.as_bytes()).map_err(error_string)?;
            let unlock_digest = bip448_transfer_unlock_auth_digest(
                Bip448TransferUnlockRole::Recipient,
                &message.statechain_id,
                &x1_generation,
            )
            .map_err(error_string)?;
            let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)
                .map_err(error_string)?
                .inner;
            let auth_keypair = KeyPair::from_secret_key(&Secp256k1::new(), &auth_secret);
            let unlock_signature = schnorr::sign(&unlock_digest, &auth_keypair);
            let recipient_unlock_auth_sig =
                Bip448SchnorrSignature::try_from(unlock_signature.to_string().as_str())
                    .map_err(error_string)?;
            let receiver_secret = PrivateKey::from_wif(&coin.user_privkey)
                .map_err(error_string)?
                .inner;
            let t1 = Scalar::from_be_bytes(message.t1).map_err(error_string)?;
            let t2 = receiver_secret
                .negate()
                .add_tweak(&t1)
                .map_err(error_string)?
                .to_secret_bytes();
            let operation_id = Bip448OperationId::from_bytes(scalar_bytes(
                &pending.operation_id,
                "incoming operation id",
            )?);
            let mut request = TransferReceiverRequestPayloadV1 {
                protocol_version: Bip448ProtocolVersionV1,
                operation_id,
                statechain_id: Bip448StatechainId::try_from(message.statechain_id.as_str())
                    .map_err(error_string)?,
                t2: Bip448SecretScalar::from_bytes(t2).map_err(error_string)?,
                transfer_generation_pubkey: Bip448CompressedPublicKey::from_bytes(
                    x1_generation.serialize(),
                )
                .map_err(error_string)?,
                expected_sig_count: observed.num_sigs,
                expected_key_generation: observed.lockbox_key_generation,
                expected_server_pubkey: observed.enclave_public_key,
                recipient_unlock_auth_sig,
                auth_sig: recipient_unlock_auth_sig,
            };
            request.auth_sig = Bip448SchnorrSignature::try_from(
                schnorr::sign(&request.auth_digest().map_err(error_string)?, &auth_keypair)
                    .to_string()
                    .as_str(),
            )
            .map_err(error_string)?;
            let expected_server = expected_receiver_server(&message, &receiver)?;
            let pending_mut = self
                .snapshot
                .pending_incoming_transfer
                .as_mut()
                .ok_or_else(|| "incoming transfer state disappeared".to_string())?;
            pending_mut.receiver_request = Some(request);
            pending_mut.expected_server_pubkey = Some(expected_server.to_string());
            self.checkpoint()?;
        }

        let pending = self
            .snapshot
            .pending_incoming_transfer
            .clone()
            .ok_or_else(|| "incoming transfer state disappeared".to_string())?;
        let request = pending
            .receiver_request
            .as_ref()
            .ok_or_else(|| "incoming receiver request is missing".to_string())?;
        let x1_generation = PublicKey::from_slice(request.transfer_generation_pubkey.as_bytes())
            .map_err(error_string)?;
        let auth_secret = PrivateKey::from_wif(&coin.auth_privkey)
            .map_err(error_string)?
            .inner;
        let auth_keypair = KeyPair::from_secret_key(&Secp256k1::new(), &auth_secret);
        let unlock_digest = bip448_transfer_unlock_auth_digest(
            Bip448TransferUnlockRole::Recipient,
            &message.statechain_id,
            &x1_generation,
        )
        .map_err(error_string)?;
        let unlock = TransferUnlockRequestPayload {
            statechain_id: message.statechain_id.clone(),
            auth_sig: schnorr::sign(&unlock_digest, &auth_keypair).to_string(),
            auth_pub_key: Some(x1_generation.to_string()),
        };
        let unlock_body = serde_json::to_string(&unlock).map_err(error_string)?;
        checked_response(
            self.backend
                .post_json(
                    &self.snapshot.deployment.mercury_url,
                    "transfer/unlock",
                    &unlock_body,
                )
                .await?,
            "incoming statecoin unlock",
        )?;
        let receipt: Bip448KeyUpdateAppliedReceiptPayloadV1 = post_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            "transfer/receiver",
            request,
            "incoming statecoin key update",
        )
        .await?;
        let live_after = self.statechain_info(&message.statechain_id).await?;
        let resulting_server = verify_keyupdate_receipt(request, &receipt, &live_after)?;
        if pending.expected_server_pubkey.as_deref() != Some(resulting_server.to_string().as_str())
        {
            return Err("incoming key update produced an unexpected server share".to_string());
        }
        // C2: the receipt and the live state above are both Mercury-proxied, and
        // Mercury saw `t2`, so it can fabricate algebraically consistent values
        // without the enclave ever applying the update. Confirm against the
        // enclave directly before persisting the received coin.
        let (attested_server, _) = self
            .prove_enclave_server_share(&message.statechain_id)
            .await
            .map_err(|error| format!("incoming key update enclave proof failed: {error}"))?;
        if attested_server != normalize_hex(&resulting_server.to_string()) {
            return Err("signing enclave did not apply the incoming key update".to_string());
        }
        let facts = transfer_chain_facts(
            self,
            &message,
            PublicKey::from_str(&coin.user_pubkey).map_err(error_string)?,
        )
        .await?;
        let record = received_record(&self.snapshot.wallet.name, &message, &facts)?;
        let updated_coin = received_coin(&coin, &record, &resulting_server)?;
        let statechain_id = record.statechain_id.clone();
        let cancellation = self
            .snapshot
            .pending_outgoing_transfer
            .as_ref()
            .is_some_and(|outgoing| {
                outgoing.intent_kind == "cancellation"
                    && outgoing.statechain_id == statechain_id
                    && outgoing.recipient_auth_pubkey == pending.receiver_auth_pubkey
            });
        for candidate in &mut self.snapshot.wallet.coins {
            if candidate.statechain_id.as_deref() == Some(statechain_id.as_str())
                && candidate.auth_pubkey != pending.receiver_auth_pubkey
            {
                candidate.status = CoinStatus::TRANSFERRED;
            }
        }
        let coin_slot = self
            .snapshot
            .wallet
            .coins
            .iter_mut()
            .find(|candidate| candidate.auth_pubkey == pending.receiver_auth_pubkey)
            .ok_or_else(|| "incoming transfer address disappeared".to_string())?;
        *coin_slot = updated_coin;
        if let Some(slot) = self
            .snapshot
            .statechains
            .iter_mut()
            .find(|existing| existing.statechain_id == statechain_id)
        {
            *slot = record.clone();
        } else {
            self.snapshot.statechains.push(record.clone());
        }
        self.snapshot
            .state_histories
            .insert(statechain_id.clone(), message.state_history.clone());
        let received_owner = PublicKey::from_str(&message.receiver_user_public_key)
            .map_err(error_string)?
            .x_only_public_key()
            .0
            .to_string();
        for binding in &mut self.snapshot.funding_bindings {
            if binding.statechain_id == statechain_id {
                binding.owner_user_pubkey = received_owner.clone();
                binding.owner_state_number = record.latest_state_number;
            }
        }
        self.snapshot.wallet.activities.push(Activity {
            utxo: format!(
                "{}:{}",
                record.funding_outpoint.txid, record.funding_outpoint.vout
            ),
            amount: u32::try_from(record.amount_sats)
                .map_err(|_| "statecoin amount does not fit wallet format".to_string())?,
            action: if cancellation {
                "Transfer cancellation accepted".to_string()
            } else {
                "Offchain receive accepted".to_string()
            },
            date: self.backend.now_iso(),
        });
        self.snapshot.pending_incoming_transfer = None;
        if cancellation {
            self.snapshot.pending_outgoing_transfer = None;
        }
        self.checkpoint()?;
        Ok(statechain_id)
    }

    async fn signature_count(&self, statechain_id: &str) -> Result<u64, String> {
        let count: Bip448SignatureCountResponsePayload = get_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            &format!("bip448-statechain/signature-count/{statechain_id}"),
            "BIP448 signature count",
        )
        .await?;
        Ok(count.sig_count)
    }

    async fn statechain_info(
        &self,
        statechain_id: &str,
    ) -> Result<Bip448StatechainInfoResponsePayloadV1, String> {
        get_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            &format!("info/statechain/{statechain_id}"),
            "BIP448 statechain information",
        )
        .await
    }
}

fn owned_coin<'a>(coins: &'a [Coin], statechain_id: &str) -> Result<&'a Coin, String> {
    coins
        .iter()
        .filter(|coin| {
            coin.statechain_id.as_deref() == Some(statechain_id)
                && coin.status != CoinStatus::TRANSFERRED
        })
        .max_by_key(|coin| coin.locktime.unwrap_or_default())
        .ok_or_else(|| format!("wallet coin {statechain_id} is missing"))
}

fn transfer_artifacts(
    record: &Bip448StatechainRecord,
    receiver: &PublicKey,
    state_number: u32,
    state_locktime: u32,
) -> Result<Bip448RecoveryArtifacts, String> {
    let secp = Secp256k1::new();
    let network = Network::from_str(&record.network).map_err(error_string)?;
    let recovery_script =
        Address::p2tr(&secp, receiver.x_only_public_key().0, None, network).script_pubkey();
    build_funding_recovery_artifacts(
        &secp,
        &PublicKey::from_str(&record.aggregate_pubkey).map_err(error_string)?,
        OutPoint {
            txid: Txid::from_str(&record.funding_outpoint.txid).map_err(error_string)?,
            vout: record.funding_outpoint.vout,
        },
        record.funding_outpoint.value_sats,
        recovery_script,
        state_number,
        absolute::LockTime::from_consensus(state_locktime),
        record.challenge_delay,
        record.latest_state.fee_bump_policy,
    )
    .map_err(error_string)
}

fn validate_signing(
    signing: &PendingBip448Signing,
    record: &Bip448StatechainRecord,
    artifacts: &Bip448RecoveryArtifacts,
) -> Result<(), String> {
    if signing.funding_txid != record.funding_outpoint.txid
        || signing.funding_vout != record.funding_outpoint.vout
        || signing.funding_value_sats != record.funding_outpoint.value_sats
        || signing.update_template_hash
            != hex::encode(artifacts.update_template_hash.to_byte_array())
        || signing.settlement_template_hash
            != hex::encode(artifacts.settlement_template_hash.to_byte_array())
    {
        return Err(
            "saved offchain signing data does not match the next recovery state".to_string(),
        );
    }
    Ok(())
}

pub(crate) fn state_history_entry(
    state: &mercurylib::bip448_statechain::storage::Bip448LatestState,
    owner: secp256k1::XOnlyPublicKey,
) -> Bip448StateHistoryEntry {
    Bip448StateHistoryEntry {
        state_number: state.state_number,
        state_locktime: state.state_locktime,
        owner_public_key: owner.to_string(),
        update_template_hash: state.update_template_hash.clone(),
        settlement_template_hash: state.settlement_template_hash.clone(),
        update_signature: state.signing_metadata.update_signature.clone(),
        client_public_nonce: state.signing_metadata.client_public_nonce.clone(),
        server_public_nonce: state.signing_metadata.server_public_nonce.clone(),
        blinding_factor: state.signing_metadata.blinding_factor.clone(),
    }
}

fn statechain_info_for_transfer_verification(
    observed: &Bip448StatechainInfoResponsePayloadV1,
) -> Result<StatechainInfoResponsePayload, String> {
    Ok(StatechainInfoResponsePayload {
        enclave_public_key: hex::encode(observed.enclave_public_key.as_bytes()),
        num_sigs: observed.num_sigs.try_into().map_err(error_string)?,
        statechain_info: observed
            .statechain_info
            .iter()
            .map(|item| StatechainInfo {
                statechain_id: item.statechain_id.as_str().to_string(),
                server_pubnonce: hex::encode(item.server_pubnonce.as_bytes()),
                challenge: hex::encode(item.challenge.as_bytes()),
                tx_n: item.tx_n,
            })
            .collect(),
        x1_pub: Some(hex::encode(observed.x1_pub.as_bytes())),
    })
}

async fn transfer_chain_facts<B: Backend>(
    client: &WalletClient<B>,
    message: &Bip448TransferMsg,
    receiver_user_pubkey: PublicKey,
) -> Result<Bip448TransferChainFacts, String> {
    let txid = Txid::from_str(&message.funding_outpoint.txid).map_err(error_string)?;
    let tx_hex = checked_response(
        client
            .backend
            .get(
                &client.snapshot.deployment.chain_url,
                &format!("tx/{txid}/hex"),
            )
            .await?,
        "Mutinynet funding transaction",
    )?;
    let transaction: Transaction =
        deserialize(&hex::decode(tx_hex.trim()).map_err(error_string)?).map_err(error_string)?;
    if transaction.txid() != txid {
        return Err("Mutinynet returned the wrong funding transaction".to_string());
    }
    let funding_output = transaction
        .output
        .get(message.funding_outpoint.vout as usize)
        .cloned()
        .ok_or_else(|| "funding transaction output is missing".to_string())?;
    let funding_address = Address::from_script(&funding_output.script_pubkey, Network::Signet)
        .map_err(error_string)?;
    let utxos: Vec<EsploraTransferUtxo> = get_json(
        &client.backend,
        &client.snapshot.deployment.chain_url,
        &format!("address/{funding_address}/utxo"),
        "Mutinynet funding output",
    )
    .await?;
    let status = utxos
        .iter()
        .find(|utxo| utxo.txid == txid.to_string() && utxo.vout == message.funding_outpoint.vout)
        .ok_or_else(|| "funding output is already spent".to_string())?;
    let tip = chain_tip(&client.backend, &client.snapshot.deployment.chain_url).await?;
    let confirmations = if status.status.confirmed {
        status
            .status
            .block_height
            .map_or(0, |height| tip.saturating_sub(height).saturating_add(1))
    } else {
        0
    };
    Ok(Bip448TransferChainFacts {
        expected_network: Network::Signet,
        median_time_past: median_time_past(&client.backend, &client.snapshot.deployment.chain_url)
            .await?,
        funding_outpoint: OutPoint {
            txid,
            vout: message.funding_outpoint.vout,
        },
        funding_output,
        tx0_confirmed: confirmations >= CONFIRMATION_TARGET,
        tx0_unspent: true,
        receiver_user_pubkey,
    })
}

fn expected_receiver_server(
    message: &Bip448TransferMsg,
    receiver: &PublicKey,
) -> Result<PublicKey, String> {
    PublicKey::from_str(&message.aggregate_pubkey)
        .map_err(error_string)?
        .combine(&receiver.negate())
        .map_err(error_string)
}

fn verify_keyupdate_receipt(
    request: &TransferReceiverRequestPayloadV1,
    receipt: &Bip448KeyUpdateAppliedReceiptPayloadV1,
    live: &Bip448StatechainInfoResponsePayloadV1,
) -> Result<PublicKey, String> {
    let resulting_generation = request
        .expected_key_generation
        .get()
        .checked_add(1)
        .ok_or_else(|| "Lockbox key generation overflowed".to_string())?;
    if receipt.operation_id != request.operation_id
        || receipt.statechain_id != request.statechain_id
        || receipt.accepted_sig_count != request.expected_sig_count
        || receipt.previous_key_generation != request.expected_key_generation
        || receipt.resulting_key_generation.get() != resulting_generation
        || receipt.previous_server_pubkey != request.expected_server_pubkey
        || receipt.transfer_generation_pubkey != request.transfer_generation_pubkey
    {
        return Err(
            "Lockbox key-update receipt does not match the saved receive request".to_string(),
        );
    }
    let previous_server =
        PublicKey::from_slice(request.expected_server_pubkey.as_bytes()).map_err(error_string)?;
    let t2 = SecretKey::from_secret_bytes(*request.t2.as_bytes()).map_err(error_string)?;
    let generation = PublicKey::from_slice(request.transfer_generation_pubkey.as_bytes())
        .map_err(error_string)?;
    let expected = previous_server
        .combine(&t2.public_key(&Secp256k1::new()))
        .map_err(error_string)?
        .combine(&generation.negate())
        .map_err(error_string)?;
    let resulting =
        PublicKey::from_slice(receipt.resulting_server_pubkey.as_bytes()).map_err(error_string)?;
    if resulting != expected
        || live.num_sigs != receipt.accepted_sig_count
        || live.lockbox_key_generation != receipt.resulting_key_generation
        || live.enclave_public_key != receipt.resulting_server_pubkey
        || live.x1_pub != receipt.transfer_generation_pubkey
    {
        return Err("Lockbox key-update receipt does not match live enclave state".to_string());
    }
    Ok(resulting)
}

fn received_record(
    wallet_name: &str,
    message: &Bip448TransferMsg,
    facts: &Bip448TransferChainFacts,
) -> Result<Bip448StatechainRecord, String> {
    let secp = Secp256k1::new();
    let aggregate = PublicKey::from_str(&message.aggregate_pubkey).map_err(error_string)?;
    let recovery_script = Address::p2tr(
        &secp,
        facts.receiver_user_pubkey.x_only_public_key().0,
        None,
        facts.expected_network,
    )
    .script_pubkey();
    let artifacts = build_funding_recovery_artifacts(
        &secp,
        &aggregate,
        facts.funding_outpoint,
        facts.funding_output.value,
        recovery_script,
        message.latest_state_number,
        absolute::LockTime::from_consensus(message.latest_state.state_locktime),
        message.challenge_delay,
        message.latest_state.fee_bump_policy,
    )
    .map_err(error_string)?;
    if artifacts.funding_output_script_pubkey != facts.funding_output.script_pubkey {
        return Err("received statecoin funding script does not match the blockchain".to_string());
    }
    let latest_state = build_funding_latest_state(
        &secp,
        &aggregate,
        &artifacts,
        message.latest_state.signing_metadata.clone(),
        Vec::new(),
    )
    .map_err(error_string)?;
    if latest_state != message.latest_state {
        return Err("received statecoin recovery state is not canonical".to_string());
    }
    Ok(Bip448StatechainRecord {
        wallet_name: wallet_name.to_string(),
        statechain_id: message.statechain_id.clone(),
        aggregate_pubkey: aggregate.to_string(),
        funding_outpoint: mercurylib::bip448_statechain::storage::Bip448FundingOutpoint {
            txid: facts.funding_outpoint.txid.to_string(),
            vout: facts.funding_outpoint.vout,
            value_sats: facts.funding_output.value,
        },
        latest_state_number: latest_state.state_number,
        challenge_delay: latest_state.challenge_delay,
        amount_sats: facts.funding_output.value,
        network: facts.expected_network.to_string(),
        latest_state,
    })
}

fn received_coin(
    coin: &Coin,
    record: &Bip448StatechainRecord,
    server_pubkey: &PublicKey,
) -> Result<Coin, String> {
    let mut coin = coin.clone();
    let aggregate = PublicKey::from_str(&record.aggregate_pubkey).map_err(error_string)?;
    let spend_info = funding_spend_info(&Secp256k1::new(), aggregate.x_only_public_key().0)
        .map_err(error_string)?;
    let address = Address::from_script(
        &output_script_pubkey(&spend_info),
        Network::from_str(&record.network).map_err(error_string)?,
    )
    .map_err(error_string)?;
    coin.server_pubkey = Some(server_pubkey.to_string());
    coin.aggregated_pubkey = Some(record.aggregate_pubkey.clone());
    coin.aggregated_address = Some(address.to_string());
    coin.statechain_protocol = Some(BIP448_COIN_PROTOCOL.to_string());
    coin.utxo_txid = Some(record.funding_outpoint.txid.clone());
    coin.utxo_vout = Some(record.funding_outpoint.vout);
    coin.amount = Some(
        u32::try_from(record.amount_sats)
            .map_err(|_| "statecoin amount does not fit wallet format".to_string())?,
    );
    coin.statechain_id = Some(record.statechain_id.clone());
    coin.signed_statechain_id =
        Some(sign_message(&record.statechain_id, &coin).map_err(error_string)?);
    coin.locktime = Some(record.latest_state.state_locktime);
    coin.public_nonce = Some(
        record
            .latest_state
            .signing_metadata
            .client_public_nonce
            .clone(),
    );
    coin.server_public_nonce = Some(
        record
            .latest_state
            .signing_metadata
            .server_public_nonce
            .clone(),
    );
    coin.blinding_factor = Some(record.latest_state.signing_metadata.blinding_factor.clone());
    coin.status = CoinStatus::CONFIRMED;
    Ok(coin)
}

fn scalar_bytes(value: &str, description: &str) -> Result<[u8; 32], String> {
    let bytes: [u8; 32] = hex::decode(normalize_hex(value))
        .map_err(error_string)?
        .try_into()
        .map_err(|_| format!("{description} must be exactly 32 bytes"))?;
    SecretKey::from_secret_bytes(bytes).map_err(error_string)?;
    Ok(bytes)
}

fn scalar_hex(value: &str, description: &str) -> Result<String, String> {
    Ok(hex::encode(scalar_bytes(value, description)?))
}

fn error_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

    use bitcoin::sighash::TemplateHash;
    use secp256k1::musig::{SecretNonce as MusigSecretNonce, Session as MusigSession};

    use super::*;
    use crate::api::ApiResponse;

    struct ProtocolNonce {
        secret: Option<MusigSecretNonce>,
        public: String,
    }

    struct ProtocolState {
        server_secret: SecretKey,
        signature_count: u64,
        key_generation: u64,
        x1_secret: Option<SecretKey>,
        transfer_counter: u8,
        rows: Vec<serde_json::Value>,
        nonces: BTreeMap<String, ProtocolNonce>,
        partials: BTreeMap<String, String>,
        mailboxes: BTreeMap<String, Vec<String>>,
        // When true, the Mercury face claims key updates applied (receipt and
        // info/statechain) while the enclave face keeps reporting the previous
        // share — a compromised-Mercury forgery the wallet must reject.
        forge_key_updates: bool,
        forged_rotation: Option<(PublicKey, u64)>,
    }

    #[derive(Clone)]
    struct ProtocolBackend {
        state: Rc<RefCell<ProtocolState>>,
        checkpoints: Rc<RefCell<Vec<String>>>,
        funding_tx_hex: String,
        funding_txid: String,
        funding_address: String,
    }

    impl ProtocolBackend {
        fn new() -> Self {
            let snapshot = crate::test_support::recovery_snapshot();
            let record = &snapshot.statechains[0];
            let metadata = &record.latest_state.signing_metadata;
            let server_secret = SecretKey::from_secret_bytes([7; 32]).unwrap();
            let server_public_key = PublicKey::from_secret_key(&Secp256k1::new(), &server_secret);
            let client_public_key =
                PublicKey::from_str(snapshot.wallet.coins[0].user_pubkey.as_str()).unwrap();
            let client_public_nonce =
                PublicNonce::from_slice(&hex::decode(&metadata.client_public_nonce).unwrap())
                    .unwrap();
            let server_public_nonce =
                PublicNonce::from_slice(&hex::decode(&metadata.server_public_nonce).unwrap())
                    .unwrap();
            let blinding_factor =
                BlindingFactor::from_slice(&hex::decode(&metadata.blinding_factor).unwrap())
                    .unwrap();
            let update_template_hash = TemplateHash::from_slice(
                &hex::decode(&record.latest_state.update_template_hash).unwrap(),
            )
            .unwrap();
            let session = CsfsSigningSession::new(
                &Secp256k1::new(),
                CsfsSigningRole::FundingUpdate,
                client_public_key.combine(&server_public_key).unwrap(),
                &client_public_nonce,
                &server_public_nonce,
                update_template_hash,
                &blinding_factor,
            )
            .unwrap();
            let funding_tx = crate::test_support::funding_transaction(&snapshot);
            Self {
                state: Rc::new(RefCell::new(ProtocolState {
                    server_secret,
                    signature_count: 1,
                    key_generation: 0,
                    x1_secret: None,
                    transfer_counter: 0,
                    forge_key_updates: false,
                    forged_rotation: None,
                    rows: vec![serde_json::json!({
                        "statechain_id": "statechain",
                        "server_pubnonce": metadata.server_public_nonce,
                        "challenge": hex::encode(session.blinded_challenge()),
                        "tx_n": 1
                    })],
                    nonces: BTreeMap::new(),
                    partials: BTreeMap::new(),
                    mailboxes: BTreeMap::new(),
                })),
                checkpoints: Rc::new(RefCell::new(Vec::new())),
                funding_tx_hex: hex::encode(bitcoin::consensus::serialize(&funding_tx)),
                funding_txid: funding_tx.txid().to_string(),
                funding_address: snapshot.wallet.coins[0].aggregated_address.clone().unwrap(),
            }
        }

        fn response(body: impl Into<String>) -> ApiResponse {
            ApiResponse {
                status: 200,
                body: body.into(),
            }
        }

        fn state_info(&self) -> String {
            let state = self.state.borrow();
            let enclave_public_key =
                PublicKey::from_secret_key(&Secp256k1::new(), &state.server_secret);
            let x1_pub = state
                .x1_secret
                .as_ref()
                .map(|secret| PublicKey::from_secret_key(&Secp256k1::new(), secret))
                .unwrap_or(enclave_public_key);
            let (claimed_public_key, claimed_generation) = state
                .forged_rotation
                .unwrap_or((enclave_public_key, state.key_generation));
            serde_json::json!({
                "protocol_version": 1,
                "enclave_public_key": claimed_public_key.to_string(),
                "num_sigs": state.signature_count,
                "lockbox_key_generation": claimed_generation,
                "statechain_info": state.rows,
                "x1_pub": x1_pub.to_string()
            })
            .to_string()
        }
    }

    impl Backend for ProtocolBackend {
        async fn get(&self, _base_url: &str, path: &str) -> Result<ApiResponse, String> {
            if path == "info/config" {
                return Ok(Self::response(
                    serde_json::json!({"version": "0.1.0", "batchtimeout": 10}).to_string(),
                ));
            }
            if path == "blocks/tip/height" {
                return Ok(Self::response("105"));
            }
            if path == "blocks/tip/hash" {
                return Ok(Self::response("tip"));
            }
            if path == "block/tip" {
                return Ok(Self::response(
                    serde_json::json!({"mediantime": 1_000_000_000_u32}).to_string(),
                ));
            }
            if path == format!("tx/{}/hex", self.funding_txid) {
                return Ok(Self::response(self.funding_tx_hex.clone()));
            }
            if path == format!("address/{}/utxo", self.funding_address) {
                return Ok(Self::response(
                    serde_json::json!([{
                        "txid": self.funding_txid,
                        "vout": 0,
                        "value": 50_000,
                        "status": {"confirmed": true, "block_height": 100}
                    }])
                    .to_string(),
                ));
            }
            if path == "bip448-statechain/signature-count/statechain" {
                let count = self.state.borrow().signature_count;
                return Ok(Self::response(
                    serde_json::json!({"sig_count": count}).to_string(),
                ));
            }
            if path == "info/statechain/statechain" {
                return Ok(Self::response(self.state_info()));
            }
            if let Some(auth_key) = path.strip_prefix("transfer/get_msg_addr/") {
                let messages = self
                    .state
                    .borrow()
                    .mailboxes
                    .get(auth_key)
                    .cloned()
                    .unwrap_or_default();
                return Ok(Self::response(
                    serde_json::json!({"list_enc_transfer_msg": messages}).to_string(),
                ));
            }
            Err(format!("unexpected protocol GET {path}"))
        }

        async fn post_json(
            &self,
            _base_url: &str,
            path: &str,
            body: &str,
        ) -> Result<ApiResponse, String> {
            let response = match path {
                "transfer/sender" => {
                    let mut state = self.state.borrow_mut();
                    state.transfer_counter = state.transfer_counter.checked_add(1).unwrap();
                    let secret =
                        SecretKey::from_secret_bytes([8 + state.transfer_counter; 32]).unwrap();
                    state.x1_secret = Some(secret);
                    serde_json::json!({"x1": hex::encode(secret.to_secret_bytes())}).to_string()
                }
                "bip448-statechain/sign/first" => {
                    let request: Bip448SignFirstRequestPayload =
                        serde_json::from_str(body).map_err(error_string)?;
                    let mut state = self.state.borrow_mut();
                    if !state.nonces.contains_key(&request.signing_id) {
                        let keypair =
                            KeyPair::from_secret_key(&Secp256k1::new(), &state.server_secret);
                        let session_id: [u8; 32] = hex::decode(&request.signing_id)
                            .map_err(error_string)?
                            .try_into()
                            .map_err(|_| "signing ID is not 32 bytes".to_string())?;
                        let (secret, public) = new_musig_nonce_pair(
                            &Secp256k1::new(),
                            MusigSessionId::assume_unique_per_nonce_gen(session_id),
                            None,
                            Some(state.server_secret),
                            keypair.public_key(),
                            None,
                            None,
                        )
                        .map_err(error_string)?;
                        state.nonces.insert(
                            request.signing_id.clone(),
                            ProtocolNonce {
                                secret: Some(secret),
                                public: hex::encode(public.serialize()),
                            },
                        );
                    }
                    let public = state.nonces[&request.signing_id].public.clone();
                    serde_json::json!({"server_pubnonce": public}).to_string()
                }
                "bip448-statechain/sign/second" => {
                    let request: Bip448PartialSignatureRequestPayload =
                        serde_json::from_str(body).map_err(error_string)?;
                    let mut state = self.state.borrow_mut();
                    if let Some(partial) = state.partials.get(&request.signing_id) {
                        serde_json::json!({"partial_sig": partial}).to_string()
                    } else {
                        let secret_nonce = state
                            .nonces
                            .get_mut(&request.signing_id)
                            .and_then(|nonce| nonce.secret.take())
                            .ok_or_else(|| "server nonce is missing".to_string())?;
                        let server_public_nonce = state.nonces[&request.signing_id].public.clone();
                        let encoded_session: [u8; 133] = hex::decode(&request.session)
                            .map_err(error_string)?
                            .try_into()
                            .map_err(|_| "blinded session is not 133 bytes".to_string())?;
                        let session = MusigSession::from_slice(encoded_session);
                        let keypair =
                            KeyPair::from_secret_key(&Secp256k1::new(), &state.server_secret);
                        let partial = session
                            .blinded_partial_sign_without_keyaggcoeff(
                                &Secp256k1::new(),
                                secret_nonce,
                                &keypair,
                                request.negate_seckey == 1,
                            )
                            .map_err(error_string)?;
                        let partial = hex::encode(partial.serialize());
                        state
                            .partials
                            .insert(request.signing_id.clone(), partial.clone());
                        state.signature_count = state.signature_count.checked_add(1).unwrap();
                        let tx_n = u32::try_from(state.signature_count).unwrap();
                        state.rows.push(serde_json::json!({
                            "statechain_id": "statechain",
                            "server_pubnonce": server_public_nonce,
                            "challenge": hex::encode(session.get_challenge_from_session()),
                            "tx_n": tx_n
                        }));
                        serde_json::json!({"partial_sig": partial}).to_string()
                    }
                }
                "transfer/update_msg" => {
                    let request: TransferUpdateMsgRequestPayload =
                        serde_json::from_str(body).map_err(error_string)?;
                    self.state
                        .borrow_mut()
                        .mailboxes
                        .entry(request.new_user_auth_key)
                        .or_default()
                        .push(request.enc_transfer_msg);
                    serde_json::json!({"message": "updated"}).to_string()
                }
                "transfer/unlock" => serde_json::json!({"message": "unlocked"}).to_string(),
                "transfer/receiver" => {
                    let request: serde_json::Value =
                        serde_json::from_str(body).map_err(error_string)?;
                    let t2_bytes: [u8; 32] = hex::decode(
                        request["t2"]
                            .as_str()
                            .ok_or_else(|| "missing t2".to_string())?,
                    )
                    .map_err(error_string)?
                    .try_into()
                    .map_err(|_| "t2 is not 32 bytes".to_string())?;
                    let tweak = Scalar::from_be_bytes(t2_bytes)
                        .map_err(|_| "t2 is not a canonical scalar".to_string())?;
                    let mut state = self.state.borrow_mut();
                    let previous_secret = state.server_secret;
                    let previous_public =
                        PublicKey::from_secret_key(&Secp256k1::new(), &previous_secret);
                    let previous_generation = state.key_generation;
                    let generation_secret = state
                        .x1_secret
                        .ok_or_else(|| "transfer generation secret is missing".to_string())?;
                    let generation_cancellation =
                        Scalar::from_be_bytes(generation_secret.negate().to_secret_bytes())
                            .map_err(|_| "negated transfer generation is invalid".to_string())?;
                    let resulting_secret = previous_secret
                        .add_tweak(&tweak)
                        .and_then(|secret| secret.add_tweak(&generation_cancellation))
                        .map_err(error_string)?;
                    let resulting_public =
                        PublicKey::from_secret_key(&Secp256k1::new(), &resulting_secret);
                    let claimed_generation = state.key_generation.checked_add(1).unwrap();
                    if state.forge_key_updates {
                        state.forged_rotation = Some((resulting_public, claimed_generation));
                    } else {
                        state.server_secret = resulting_secret;
                        state.key_generation = claimed_generation;
                    }
                    serde_json::json!({
                        "protocol_version": 1,
                        "operation_id": request["operation_id"],
                        "statechain_id": "statechain",
                        "status": "applied",
                        "accepted_sig_count": state.signature_count,
                        "previous_key_generation": previous_generation,
                        "resulting_key_generation": claimed_generation,
                        "previous_server_pubkey": previous_public.to_string(),
                        "resulting_server_pubkey": resulting_public.to_string(),
                        "transfer_generation_pubkey": request["transfer_generation_pubkey"]
                    })
                    .to_string()
                }
                _ => return Err(format!("unexpected protocol POST {path}")),
            };
            Ok(Self::response(response))
        }

        // The mock enclave reports the same authoritative share its Mercury
        // face serves from `state_info`, including post-keyupdate rotations.
        async fn verify_enclave_statechain(
            &self,
            _endpoint: &str,
            _pcrs: [&str; 3],
            _debug: bool,
            statechain_id: &str,
            challenge: &str,
        ) -> Result<ApiResponse, String> {
            assert_eq!(statechain_id, "statechain");
            let state = self.state.borrow();
            let server_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &state.server_secret);
            Ok(Self::response(
                serde_json::json!({
                    "statechain_id": statechain_id,
                    "challenge": challenge,
                    "server_pubkey": server_pubkey.to_string(),
                })
                .to_string(),
            ))
        }

        fn checkpoint(&self, snapshot: &str) -> Result<(), String> {
            self.checkpoints.borrow_mut().push(snapshot.to_string());
            Ok(())
        }

        fn now_iso(&self) -> String {
            "2026-01-01T00:00:00.000Z".to_string()
        }
    }

    async fn empty_recipient(backend: ProtocolBackend) -> WalletClient<ProtocolBackend> {
        WalletClient::create_from_mnemonic(
            backend,
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
                .to_string(),
        )
        .await
        .unwrap()
    }

    fn assert_all_protocol_checkpoints_restore(backend: &ProtocolBackend) {
        let checkpoints = backend.checkpoints.borrow();
        assert!(!checkpoints.is_empty());
        for checkpoint in checkpoints.iter() {
            WalletClient::from_snapshot(checkpoint, backend.clone())
                .expect("every durable protocol checkpoint must restore");
        }
    }

    #[tokio::test]
    async fn complete_transfer_rotates_lockbox_and_reconciles_both_wallets() {
        let backend = ProtocolBackend::new();
        let mut sender = WalletClient::from_snapshot(
            include_str!("../tests/fixtures/recovery-ready.json"),
            backend.clone(),
        )
        .unwrap();
        let mut recipient = empty_recipient(backend.clone()).await;
        let transfer_address = recipient.create_transfer_address().unwrap().address;

        let sent = sender
            .send_statecoin("statechain", &transfer_address)
            .await
            .unwrap();
        assert_eq!(sent.status, "sent; completes when recipient wallet syncs");
        assert!(
            sender
                .snapshot
                .pending_outgoing_transfer
                .as_ref()
                .unwrap()
                .delivered
        );
        let sender_view = sender.view().unwrap();
        assert_eq!(
            sender_view
                .pending_outgoing_transfer
                .as_ref()
                .unwrap()
                .status,
            "Sent · completes when recipient wallet syncs"
        );
        assert_eq!(
            sender_view.coins[0].offchain_transfer_status.as_deref(),
            Some("Sent · completes when recipient wallet syncs")
        );

        let received = recipient.sync_transfers().await.unwrap();
        assert!(received.warnings.is_empty());
        assert_eq!(received.accepted_statechain_ids, vec!["statechain"]);
        assert_eq!(
            recipient
                .snapshot
                .statechain("statechain")
                .unwrap()
                .latest_state_number,
            2
        );
        assert!(recipient.snapshot.wallet.coins.iter().any(|coin| {
            coin.statechain_id.as_deref() == Some("statechain")
                && coin.status == CoinStatus::CONFIRMED
        }));

        let reconciled = sender.sync_transfers().await.unwrap();
        assert!(reconciled.warnings.is_empty());
        assert!(reconciled.accepted_statechain_ids.is_empty());
        assert!(sender.snapshot.statechain("statechain").is_none());
        assert!(sender.snapshot.pending_outgoing_transfer.is_none());
        assert_eq!(backend.state.borrow().signature_count, 2);
        assert_eq!(backend.state.borrow().key_generation, 1);
        assert_all_protocol_checkpoints_restore(&backend);
    }

    #[tokio::test]
    async fn cancellation_signs_successor_and_returns_ownership_to_sender() {
        let backend = ProtocolBackend::new();
        let mut sender = WalletClient::from_snapshot(
            include_str!("../tests/fixtures/recovery-ready.json"),
            backend.clone(),
        )
        .unwrap();
        let mut intended_recipient = empty_recipient(backend.clone()).await;
        let transfer_address = intended_recipient
            .create_transfer_address()
            .unwrap()
            .address;
        sender
            .send_statecoin("statechain", &transfer_address)
            .await
            .unwrap();

        let cancelled = sender
            .cancel_statecoin_transfer("statechain")
            .await
            .unwrap();
        assert_eq!(cancelled.status, "cancelled back to this wallet");
        assert_eq!(cancelled.state_number, 3);
        assert!(sender.snapshot.pending_outgoing_transfer.is_none());
        assert!(sender.snapshot.pending_incoming_transfer.is_none());
        assert_eq!(
            sender
                .snapshot
                .statechain("statechain")
                .unwrap()
                .latest_state_number,
            3
        );
        assert!(sender.snapshot.wallet.coins.iter().any(|coin| {
            coin.statechain_id.as_deref() == Some("statechain")
                && coin.status == CoinStatus::CONFIRMED
        }));
        assert_eq!(backend.state.borrow().signature_count, 3);
        assert_eq!(backend.state.borrow().key_generation, 1);
        assert_all_protocol_checkpoints_restore(&backend);
    }

    #[tokio::test]
    async fn forged_keyupdate_receipt_is_rejected_by_the_enclave_proof() {
        let backend = ProtocolBackend::new();
        backend.state.borrow_mut().forge_key_updates = true;
        let mut sender = WalletClient::from_snapshot(
            include_str!("../tests/fixtures/recovery-ready.json"),
            backend.clone(),
        )
        .unwrap();
        let mut recipient = empty_recipient(backend.clone()).await;
        let transfer_address = recipient.create_transfer_address().unwrap().address;
        sender
            .send_statecoin("statechain", &transfer_address)
            .await
            .unwrap();

        // Mercury serves a fully consistent forged receipt and live state, but
        // the enclave never applied the update: the receive must fail closed
        // and the coin must not be persisted.
        let received = recipient.sync_transfers().await.unwrap();
        assert!(received.accepted_statechain_ids.is_empty());
        assert!(
            received.warnings.iter().any(|warning| {
                warning.contains("signing enclave did not apply the incoming key update")
            }),
            "unexpected warnings: {:?}",
            received.warnings
        );
        assert!(recipient.snapshot.statechain("statechain").is_none());
        assert!(!recipient
            .snapshot
            .wallet
            .coins
            .iter()
            .any(|coin| { coin.statechain_id.as_deref() == Some("statechain") }));
        assert!(recipient.snapshot.pending_incoming_transfer.is_some());

        // The sender's recovery material survives: the enclave still reports
        // the sender's share, so reconciliation makes no progress.
        let reconciled = sender.sync_transfers().await.unwrap();
        assert!(reconciled.warnings.is_empty());
        assert!(reconciled.accepted_statechain_ids.is_empty());
        assert!(sender.snapshot.statechain("statechain").is_some());
        assert!(sender.snapshot.state_histories.contains_key("statechain"));
        assert!(sender.snapshot.pending_outgoing_transfer.is_some());
        assert_eq!(backend.state.borrow().key_generation, 0);
    }

    #[tokio::test]
    async fn sender_state_survives_until_the_enclave_confirms_rotation() {
        let backend = ProtocolBackend::new();
        let mut sender = WalletClient::from_snapshot(
            include_str!("../tests/fixtures/recovery-ready.json"),
            backend.clone(),
        )
        .unwrap();
        let mut recipient = empty_recipient(backend.clone()).await;
        let transfer_address = recipient.create_transfer_address().unwrap().address;
        sender
            .send_statecoin("statechain", &transfer_address)
            .await
            .unwrap();

        // The recipient never processes the transfer; the enclave still holds
        // the sender's share. Reconciliation must retain every recovery
        // artifact rather than trusting message delivery.
        let progress = sender.sync_transfers().await.unwrap();
        assert!(progress.warnings.is_empty());
        assert!(progress.accepted_statechain_ids.is_empty());
        assert!(sender.snapshot.statechain("statechain").is_some());
        assert!(sender.snapshot.state_histories.contains_key("statechain"));
        assert!(sender.snapshot.pending_outgoing_transfer.is_some());
        assert!(sender
            .snapshot
            .wallet
            .coins
            .iter()
            .any(|coin| { coin.statechain_id.as_deref() == Some("statechain") }));
    }

    #[derive(Clone, Default)]
    struct JournalBackend {
        checkpoints: Rc<RefCell<Vec<String>>>,
    }

    impl Backend for JournalBackend {
        async fn get(&self, _base_url: &str, path: &str) -> Result<ApiResponse, String> {
            Err(format!("intentional stop at {path}"))
        }

        async fn post_json(
            &self,
            _base_url: &str,
            path: &str,
            _body: &str,
        ) -> Result<ApiResponse, String> {
            if path == "transfer/sender" {
                return Ok(ApiResponse {
                    status: 200,
                    body: serde_json::json!({"x1": hex::encode([9_u8; 32])}).to_string(),
                });
            }
            Err(format!("unexpected POST {path}"))
        }

        fn checkpoint(&self, snapshot: &str) -> Result<(), String> {
            self.checkpoints.borrow_mut().push(snapshot.to_string());
            Ok(())
        }

        fn now_iso(&self) -> String {
            "test-time".to_string()
        }
    }

    fn fixture_client() -> WalletClient<JournalBackend> {
        WalletClient::from_snapshot(
            include_str!("../tests/fixtures/recovery-ready.json"),
            JournalBackend::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn interrupted_send_persists_exact_recipient_x1_and_signing_journal() {
        let mut sender = fixture_client();
        let mut recipient = fixture_client();
        let first_recipient = recipient.create_transfer_address().unwrap().address;
        let second_recipient = recipient.create_transfer_address().unwrap().address;

        let error = sender
            .send_statecoin("statechain", &first_recipient)
            .await
            .unwrap_err();

        assert!(error.contains("intentional stop at bip448-statechain/signature-count"));
        let pending = sender.snapshot.pending_outgoing_transfer.as_ref().unwrap();
        assert_eq!(pending.recipient_address, first_recipient);
        assert_eq!(
            pending.x1.as_deref(),
            Some(hex::encode([9_u8; 32]).as_str())
        );
        assert!(pending.signing.is_some());
        assert!(!pending.delivered);

        let serialized = sender.export_snapshot().unwrap();
        let mut restored =
            WalletClient::from_snapshot(&serialized, JournalBackend::default()).unwrap();
        assert_eq!(
            restored
                .snapshot
                .pending_outgoing_transfer
                .as_ref()
                .unwrap()
                .recipient_address,
            first_recipient
        );
        assert_eq!(
            restored
                .send_statecoin("statechain", &second_recipient)
                .await
                .unwrap_err(),
            "finish the existing offchain send before starting another"
        );
    }

    #[test]
    fn incoming_receive_journal_survives_snapshot_roundtrip_with_its_key() {
        let mut receiver = fixture_client();
        receiver.create_transfer_address().unwrap();
        let receive_key = receiver
            .snapshot
            .wallet
            .coins
            .iter()
            .find(|coin| coin.status == CoinStatus::INITIALISED)
            .unwrap()
            .auth_pubkey
            .clone();
        receiver.snapshot.pending_incoming_transfer = Some(PendingIncomingTransfer {
            receiver_auth_pubkey: receive_key.clone(),
            encrypted_message: "00".to_string(),
            operation_id: hex::encode([11_u8; 32]),
            receiver_request: None,
            expected_server_pubkey: None,
        });

        let serialized = receiver.export_snapshot().unwrap();
        let restored = WalletClient::from_snapshot(&serialized, JournalBackend::default()).unwrap();

        assert_eq!(
            restored
                .snapshot
                .pending_incoming_transfer
                .as_ref()
                .unwrap()
                .receiver_auth_pubkey,
            receive_key
        );
    }

    #[tokio::test]
    async fn duplicate_acknowledgement_and_atomic_batch_survive_restart() {
        let mut sender = fixture_client();
        let mut recipient = fixture_client();
        let recipient_address = recipient.create_transfer_address().unwrap().address;
        let mut duplicate = sender.snapshot.funding_bindings[0].clone();
        duplicate.binding_index = 1;
        duplicate.txid = Txid::from_slice(&[13; 32]).unwrap().to_string();
        duplicate.vout = 2;
        sender.snapshot.funding_bindings.push(duplicate);

        let error = sender
            .send_statecoin_with_options(
                "statechain",
                &recipient_address,
                Some("atomic-batch".to_string()),
                false,
            )
            .await
            .unwrap_err();
        assert!(error.contains("explicit acknowledgement"));
        assert!(sender.snapshot.pending_outgoing_transfer.is_none());

        let interrupted = sender
            .send_statecoin_with_options(
                "statechain",
                &recipient_address,
                Some("atomic-batch".to_string()),
                true,
            )
            .await
            .unwrap_err();
        assert!(interrupted.contains("intentional stop at bip448-statechain/signature-count"));
        let pending = sender.snapshot.pending_outgoing_transfer.as_ref().unwrap();
        assert_eq!(pending.batch_id.as_deref(), Some("atomic-batch"));
        assert!(pending.acknowledge_cooperative_duplicates);

        let serialized = sender.export_snapshot().unwrap();
        let mut restored =
            WalletClient::from_snapshot(&serialized, JournalBackend::default()).unwrap();
        assert_eq!(
            restored
                .cancel_statecoin_transfer("statechain")
                .await
                .unwrap_err(),
            "a batched transfer cannot be cancelled; wait for its unlock or expiry"
        );
    }
}
