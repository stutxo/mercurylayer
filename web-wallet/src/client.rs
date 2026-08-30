use std::{collections::BTreeSet, str::FromStr};

use bitcoin::{
    absolute, consensus::encode, hashes::Hash, Address, Network, OutPoint, PrivateKey, Transaction,
    TxOut, Txid,
};
use mercurylib::{
    bip448_statechain::{
        deposit as bip448_deposit,
        package::{
            build_latest_state_recovery_package, fee_signing::sign_cpfp_fee_inputs,
            Bip448CpfpFeeInput, Bip448PackageError,
        },
        signing::{CsfsSigningParticipant, CsfsSigningRole, CsfsSigningSession},
        signing_api::{
            Bip448PartialSignatureRequestPayload, Bip448PartialSignatureResponsePayload,
            Bip448SignFirstRequestPayload, Bip448SignFirstResponsePayload,
            Bip448SignatureCountResponsePayload,
        },
        storage::{Bip448FundingOutpoint, Bip448RecoveryTemplateRole, Bip448StatechainRecord},
        transaction::validate_immediately_final,
    },
    deposit::{
        create_deposit_msg1, handle_deposit_msg_1_response, DepositMsg1Response, TokenResponse,
    },
    utils::ServerConfig,
    wallet::{generate_mnemonic, Activity, Coin, CoinStatus, Settings, Wallet},
};
use secp256k1::{
    musig::{
        new_musig_nonce_pair, BlindingFactor, MusigSessionId, PartialSignature, PublicNonce,
        SecretNonce as MusigSecNonce,
    },
    rand, KeyPair, Message, PublicKey, Secp256k1, SecretKey,
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{ApiResponse, Backend},
    model::{
        CoinView, DeploymentConfig, DepositResult, DuplicateView, EnclaveRuntimeProof,
        EnclaveVerification, ExitResult, FundingBinding, PendingBip448Signing, PendingDeposit,
        PendingDepositView, PendingOutgoingTransferView, RecoveryAttempt, RecoveryFeeUtxo,
        RecoveryFeeUtxoView, SyncResult, TransferAddressView, WalletSnapshot, WalletView,
        WithdrawalBroadcastStatus, WithdrawalCompletionStatus, WithdrawalPhase,
        CONFIRMATION_TARGET, DEFAULT_STATECHAIN_ENDPOINT, MAX_FEE_RATE, MIN_DEPOSIT_AMOUNT,
        MIN_FEE_RATE, NETWORK, SNAPSHOT_VERSION,
    },
};

const DIRECT_ENCLAVE_PROOF_METHOD: &str = "browser-direct-enclavia-sdk-v1";

#[derive(Debug, Deserialize)]
struct EsploraStatus {
    confirmed: bool,
    block_height: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    value: u64,
    status: EsploraStatus,
}

#[derive(Debug, Deserialize)]
struct EsploraOutspend {
    spent: bool,
    txid: Option<String>,
    status: Option<EsploraStatus>,
}

#[derive(Debug, Deserialize)]
struct EsploraBlock {
    mediantime: u32,
}

#[derive(Debug, Deserialize)]
struct VerifyStatechainResponse {
    statechain_id: String,
    challenge: String,
    server_pubkey: String,
}

pub struct WalletClient<B> {
    pub snapshot: WalletSnapshot,
    pub(crate) backend: B,
}

impl<B: Backend> WalletClient<B> {
    pub async fn create(backend: B) -> Result<Self, String> {
        let mnemonic = generate_mnemonic().map_err(error_string)?;
        Self::create_from_mnemonic(backend, mnemonic).await
    }

    pub async fn create_from_mnemonic(backend: B, mnemonic: String) -> Result<Self, String> {
        let mnemonic = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
        if mnemonic.is_empty() {
            return Err("seed phrase is empty".to_string());
        }
        let deployment = DeploymentConfig::default();
        let server_config: ServerConfig = get_json(
            &backend,
            &deployment.mercury_url,
            "info/config",
            "Mercury configuration",
        )
        .await?;
        let blockheight = chain_tip(&backend, &deployment.chain_url).await?;
        let settings = Settings {
            network: NETWORK.to_string(),
            block_explorerURL: Some(deployment.explorer_url.clone()),
            torProxyHost: None,
            torProxyPort: None,
            torProxyControlPassword: None,
            torProxyControlPort: None,
            statechainEntityApi: deployment.mercury_url.clone(),
            torStatechainEntityApi: None,
            chainBackend: "esplora".to_string(),
            chainUrl: deployment.chain_url.clone(),
            chainType: Some("esplora".to_string()),
            notifications: false,
            tutorials: false,
        };
        let wallet = Wallet {
            name: "browser".to_string(),
            mnemonic,
            version: server_config.version,
            state_entity_endpoint: deployment.mercury_url.clone(),
            chain_backend: "esplora".to_string(),
            chain_endpoint: deployment.chain_url.clone(),
            network: NETWORK.to_string(),
            blockheight,
            activities: Vec::new(),
            coins: Vec::new(),
            settings,
        };
        wallet
            .bip448_recovery_fee_key()
            .map_err(|error| format!("invalid seed phrase: {error}"))?;
        Ok(Self {
            snapshot: WalletSnapshot {
                snapshot_version: SNAPSHOT_VERSION,
                wallet,
                deployment,
                statechains: Vec::new(),
                state_histories: Default::default(),
                pending_deposits: Vec::new(),
                cancelled_deposits: Vec::new(),
                recovery_attempts: Vec::new(),
                recovery_fee_utxos: Vec::new(),
                enclave_verification: None,
                enclave_verifications: Vec::new(),
                pending_outgoing_transfer: None,
                pending_incoming_transfer: None,
                enclave_runtime_proof: None,
                funding_bindings: Vec::new(),
                withdrawal_attempts: Vec::new(),
            },
            backend,
        })
    }

    pub fn from_snapshot(snapshot_json: &str, backend: B) -> Result<Self, String> {
        if snapshot_json.len() > 5 * 1024 * 1024 {
            return Err("backup exceeds the 5 MiB browser-wallet limit".to_string());
        }
        let mut snapshot: WalletSnapshot = serde_json::from_str(snapshot_json)
            .map_err(|error| format!("invalid backup: {error}"))?;
        normalize_enclave_proofs(&mut snapshot);
        validate_snapshot(&snapshot)?;
        Ok(Self { snapshot, backend })
    }

    pub fn export_snapshot(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.snapshot).map_err(error_string)
    }

    pub fn mnemonic(&self) -> &str {
        &self.snapshot.wallet.mnemonic
    }

    pub fn view(&self) -> Result<WalletView, String> {
        let recovery_fee_address = self
            .snapshot
            .wallet
            .bip448_recovery_fee_key()
            .map_err(error_string)?
            .address
            .to_string();
        let reserved_fee_outpoints = reserved_fee_outpoints(&self.snapshot.recovery_attempts)?;
        let recovery_fee_observation = self
            .snapshot
            .recovery_fee_utxos
            .iter()
            .filter(|utxo| !reserved_fee_outpoints.contains(&(utxo.txid.clone(), utxo.vout)))
            .max_by(|left, right| {
                left.confirmations
                    .min(1)
                    .cmp(&right.confirmations.min(1))
                    .then_with(|| left.value_sats.cmp(&right.value_sats))
                    .then_with(|| right.txid.cmp(&left.txid))
                    .then_with(|| right.vout.cmp(&left.vout))
            });
        let recovery_fee_utxo = recovery_fee_observation.map(|utxo| RecoveryFeeUtxoView {
            txid: utxo.txid.clone(),
            amount_sats: utxo.value_sats,
            confirmation_blocks_remaining: 1_u32.saturating_sub(utxo.confirmations),
            ready: utxo.confirmations > 0,
        });
        let mut coins = Vec::new();
        for record in &self.snapshot.statechains {
            let coin = current_wallet_coin(&self.snapshot.wallet.coins, &record.statechain_id)?;
            let update_txid = txid_from_hex(&record.latest_state.update_tx)?;
            let settlement_txid = txid_from_hex(&record.latest_state.settlement_tx)?;
            let update_attempt = self.snapshot.recovery_attempt(
                &record.statechain_id,
                Bip448RecoveryTemplateRole::FundingUpdate,
            );
            let settlement_attempt = self.snapshot.recovery_attempt(
                &record.statechain_id,
                Bip448RecoveryTemplateRole::Settlement,
            );
            let update_confirmations = update_attempt.map_or(0, |value| value.parent_confirmations);
            let settlement_confirmations =
                settlement_attempt.map_or(0, |value| value.parent_confirmations);
            let displayed_status = if settlement_confirmations > 0 {
                CoinStatus::WITHDRAWN
            } else if update_attempt.is_some() {
                CoinStatus::WITHDRAWING
            } else {
                coin.status.clone()
            };
            let remaining = u32::from(record.challenge_delay).saturating_sub(update_confirmations);
            let statechain_attempts = self
                .snapshot
                .withdrawal_attempts
                .iter()
                .filter(|attempt| attempt.statechain_id == record.statechain_id)
                .collect::<Vec<_>>();
            let canonical_attempt = statechain_attempts
                .iter()
                .copied()
                .find(|attempt| attempt.binding_index == 0);
            let exit_complete = settlement_confirmations > 0
                || canonical_attempt.is_some_and(|attempt| {
                    attempt.completion_status == WithdrawalCompletionStatus::Closed
                });
            let exit_only = !exit_complete
                && (update_attempt.is_some()
                    || statechain_attempts.iter().any(|attempt| {
                        matches!(
                            attempt.phase,
                            WithdrawalPhase::SecondArmed | WithdrawalPhase::Signed
                        )
                    }));
            let duplicates = self
                .snapshot
                .funding_bindings
                .iter()
                .filter(|binding| {
                    binding.statechain_id == record.statechain_id && binding.binding_index != 0
                })
                .map(|binding| {
                    let attempt = statechain_attempts
                        .iter()
                        .copied()
                        .find(|attempt| attempt.binding_index == binding.binding_index);
                    let signed = attempt.is_some_and(|attempt| {
                        attempt.phase == WithdrawalPhase::Signed
                            && matches!(
                                attempt.broadcast_status,
                                WithdrawalBroadcastStatus::Accepted
                                    | WithdrawalBroadcastStatus::Confirmed
                                    | WithdrawalBroadcastStatus::Conflicted
                            )
                    });
                    let independently_spent = binding.observation_status == "SpentConfirmed";
                    let cooperative_only = !signed && !independently_spent;
                    let current_owner = binding.owner_state_number == record.latest_state_number;
                    DuplicateView {
                        duplicate_index: binding.binding_index,
                        txid: binding.txid.clone(),
                        vout: binding.vout,
                        amount_sats: binding.value_sats,
                        observation_status: binding.observation_status.clone(),
                        sweep_phase: attempt.map(|attempt| attempt.phase),
                        broadcast_status: attempt.map(|attempt| attempt.broadcast_status),
                        spend_txid: binding.spend_txid.clone(),
                        cooperative_only,
                        server_dependent: current_owner
                            && cooperative_only
                            && matches!(
                                binding.observation_status.as_str(),
                                "Mempool" | "Unconfirmed" | "Confirmed"
                            ),
                        can_sweep: attempt.is_some_and(|attempt| {
                            attempt.phase != WithdrawalPhase::Signed
                                || matches!(
                                    attempt.broadcast_status,
                                    WithdrawalBroadcastStatus::NotBroadcast
                                        | WithdrawalBroadcastStatus::NeedsRebroadcast
                                )
                        }) || (current_owner
                            && binding.observation_status == "Confirmed"
                            && update_attempt.is_none()
                            && canonical_attempt.is_none()),
                    }
                })
                .collect::<Vec<_>>();
            let unresolved_duplicates = duplicates.iter().any(|duplicate| {
                duplicate.server_dependent
                    || duplicate.observation_status != "SpentConfirmed"
                        && duplicate.cooperative_only
            });
            let pending_for_coin = self
                .snapshot
                .pending_outgoing_transfer
                .as_ref()
                .filter(|pending| pending.statechain_id == record.statechain_id);
            coins.push(CoinView {
                statechain_id: record.statechain_id.clone(),
                amount: record.amount_sats,
                status: displayed_status.to_string(),
                deposit_address: coin.aggregated_address.clone().unwrap_or_default(),
                funding_txid: record.funding_outpoint.txid.clone(),
                funding_vout: record.funding_outpoint.vout,
                latest_state_number: record.latest_state_number,
                challenge_delay_blocks: record.challenge_delay,
                update_txid,
                settlement_txid,
                update_tx_hex: record.latest_state.update_tx.clone(),
                settlement_tx_hex: record.latest_state.settlement_tx.clone(),
                update_confirmations,
                settlement_confirmations,
                settlement_blocks_remaining: remaining,
                can_start_unilateral_exit: coin.status == CoinStatus::CONFIRMED
                    && settlement_attempt.is_none()
                    && update_attempt.is_none_or(|attempt| attempt.status != "confirmed")
                    && statechain_attempts.is_empty()
                    && self.snapshot.pending_outgoing_transfer.is_none(),
                can_settle_unilateral_exit: coin.status == CoinStatus::CONFIRMED
                    && update_attempt.is_some()
                    && settlement_attempt.is_none_or(|attempt| attempt.status != "confirmed"),
                can_send_offchain: coin.status == CoinStatus::CONFIRMED
                    && update_attempt.is_none()
                    && statechain_attempts.is_empty()
                    && self.snapshot.pending_outgoing_transfer.is_none(),
                offchain_transfer_status: pending_for_coin.map(|pending| {
                    if pending.delivered {
                        "Sent · completes when recipient wallet syncs".to_string()
                    } else {
                        "Send interrupted; retry the same recipient".to_string()
                    }
                }),
                exit_only,
                can_withdraw: canonical_attempt.is_some_and(|attempt| {
                    attempt.completion_status != WithdrawalCompletionStatus::Closed
                }) || (coin.status == CoinStatus::CONFIRMED
                    && update_attempt.is_none()
                    && pending_for_coin.is_none()
                    && !unresolved_duplicates),
                can_cancel_transfer: pending_for_coin.is_some_and(|pending| {
                    pending.intent_kind == "user_transfer" && pending.batch_id.is_none()
                }),
                withdrawal_status: canonical_attempt.map(|attempt| {
                    if attempt.completion_status == WithdrawalCompletionStatus::Closed {
                        "complete".to_string()
                    } else {
                        format!(
                            "{} · {}",
                            withdrawal_phase_label(attempt.phase),
                            withdrawal_broadcast_label(attempt.broadcast_status)
                        )
                    }
                }),
                duplicates,
            });
        }
        let pending_deposits = self
            .snapshot
            .pending_deposits
            .iter()
            .map(|pending| PendingDepositView {
                statechain_id: pending.coin.statechain_id.clone().unwrap_or_default(),
                address: pending.coin.aggregated_address.clone().unwrap_or_default(),
                amount: pending.amount,
                funding_txid: pending.coin.utxo_txid.clone().unwrap_or_default(),
                confirmation_blocks_remaining: CONFIRMATION_TARGET
                    .saturating_sub(pending.funding_confirmations),
                signing_started: pending.signing.is_some(),
                second_armed: pending
                    .signing
                    .as_ref()
                    .is_some_and(|signing| signing.second_armed),
            })
            .collect();
        let receive_addresses = self
            .snapshot
            .wallet
            .coins
            .iter()
            .filter(|coin| coin.status == CoinStatus::INITIALISED)
            .map(|coin| TransferAddressView {
                address: coin.address.clone(),
                status: "Ready to receive one statecoin".to_string(),
            })
            .collect();
        let pending_outgoing_transfer =
            self.snapshot
                .pending_outgoing_transfer
                .as_ref()
                .map(|pending| PendingOutgoingTransferView {
                    statechain_id: pending.statechain_id.clone(),
                    recipient_address: pending.recipient_address.clone(),
                    status: if pending.delivered {
                        "Sent · completes when recipient wallet syncs".to_string()
                    } else {
                        "Saved locally; retry to continue".to_string()
                    },
                    batch_id: pending.batch_id.clone(),
                    intent_kind: pending.intent_kind.clone(),
                    acknowledge_cooperative_duplicates: pending.acknowledge_cooperative_duplicates,
                });
        Ok(WalletView {
            network: NETWORK,
            deployment: self.snapshot.deployment.clone(),
            recovery_fee_address,
            recovery_fee_utxo,
            coins,
            activities: self.snapshot.wallet.activities.clone(),
            pending_deposits,
            recovery_attempts: self.snapshot.recovery_attempts.clone(),
            enclave_verifications: self.snapshot.enclave_verifications.clone(),
            receive_addresses,
            pending_outgoing_transfer,
            pending_incoming: self.snapshot.pending_incoming_transfer.is_some(),
            enclave_runtime_proof: self.snapshot.enclave_runtime_proof.clone(),
            withdrawal_attempts: self.snapshot.withdrawal_attempts.clone(),
        })
    }

    pub(crate) fn get_new_unreserved_coin(&self) -> Result<Coin, String> {
        let mut derivation_wallet = self.snapshot.wallet.clone();
        derivation_wallet.coins.extend(
            self.snapshot
                .cancelled_deposits
                .iter()
                .chain(self.snapshot.pending_deposits.iter())
                .map(|pending| pending.coin.clone()),
        );
        derivation_wallet.get_new_coin().map_err(error_string)
    }

    pub async fn request_deposit_token(&self) -> Result<TokenResponse, String> {
        get_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            "deposit/get_token",
            "deposit token",
        )
        .await
    }

    pub async fn create_deposit(&mut self, amount: u32) -> Result<DepositResult, String> {
        self.create_deposit_with_token(amount, None).await
    }

    pub async fn create_deposit_with_token(
        &mut self,
        amount: u32,
        token_id: Option<String>,
    ) -> Result<DepositResult, String> {
        if amount < MIN_DEPOSIT_AMOUNT {
            return Err(format!(
                "deposit amount must be at least {MIN_DEPOSIT_AMOUNT} sats"
            ));
        }
        let token_id = token_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let incomplete_index = self.snapshot.pending_deposits.iter().position(|pending| {
            pending.coin.statechain_id.is_none() && pending.coin.aggregated_address.is_none()
        });

        let (token_id, mut coin, pending_index) = match incomplete_index {
            Some(index) => {
                let pending = self.snapshot.pending_deposits[index].clone();
                if pending.amount != amount {
                    return Err(format!(
                        "retry the pending {}-sat deposit before changing the amount",
                        pending.amount
                    ));
                }
                if token_id
                    .as_ref()
                    .is_some_and(|provided| provided != &pending.token_id)
                {
                    return Err("retry the pending deposit with its original token".to_string());
                }
                (pending.token_id, pending.coin, index)
            }
            None => {
                let token_id = match token_id {
                    Some(token_id) => token_id,
                    None => self.request_deposit_token().await?.token_id,
                };
                let mut coin = self.get_new_unreserved_coin()?;
                coin.statechain_protocol = Some(bip448_deposit::BIP448_COIN_PROTOCOL.to_string());
                self.snapshot.pending_deposits.push(PendingDeposit {
                    token_id: token_id.clone(),
                    amount,
                    funding_confirmations: 0,
                    coin: coin.clone(),
                    signing: None,
                });
                let index = self.snapshot.pending_deposits.len() - 1;
                self.checkpoint()?;
                (token_id, coin, index)
            }
        };

        let message = create_deposit_msg1(&coin, &token_id).map_err(error_string)?;
        let response: DepositMsg1Response = post_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            "deposit/init/pod",
            &message,
            "deposit initialization",
        )
        .await?;
        let initialized = handle_deposit_msg_1_response(&coin, &response).map_err(error_string)?;
        coin.statechain_id = Some(initialized.statechain_id.clone());
        coin.signed_statechain_id = Some(initialized.signed_statechain_id);
        coin.server_pubkey = Some(initialized.server_pubkey);
        let address =
            bip448_deposit::create_deposit_address(&coin, NETWORK).map_err(error_string)?;
        coin.amount = Some(amount);
        coin.aggregated_address = Some(address.address.clone());
        coin.aggregated_pubkey = Some(address.aggregate_pubkey);
        self.snapshot.pending_deposits[pending_index] = PendingDeposit {
            token_id,
            amount,
            funding_confirmations: 0,
            coin,
            signing: None,
        };
        self.checkpoint()?;

        Ok(DepositResult {
            statechain_id: initialized.statechain_id,
            deposit_address: address.address,
            amount,
        })
    }

    pub async fn sync(&mut self) -> Result<SyncResult, String> {
        let mut accepted = Vec::new();
        let mut warnings = Vec::new();
        let tip = chain_tip(&self.backend, &self.snapshot.deployment.chain_url).await?;
        self.snapshot.wallet.blockheight = tip;

        for pending in self.snapshot.pending_deposits.clone() {
            match self.sync_pending_deposit(pending, tip).await {
                Ok(Some(statechain_id)) => accepted.push(statechain_id),
                Ok(None) => {}
                Err(error) => warnings.push(error),
            }
        }
        self.sync_transfer_activity(&mut accepted, &mut warnings)
            .await;
        if let Err(error) = self.sync_funding_bindings(tip).await {
            warnings.push(error);
        }
        if self.snapshot.statechains.is_empty() {
            self.snapshot.recovery_fee_utxos.clear();
        } else if let Err(error) = self.sync_recovery_fee_utxos(tip).await {
            self.snapshot.recovery_fee_utxos.clear();
            warnings.push(error);
        }

        for attempt_index in 0..self.snapshot.recovery_attempts.len() {
            let txid = self.snapshot.recovery_attempts[attempt_index]
                .parent_txid
                .clone();
            match transaction_confirmations(
                &self.backend,
                &self.snapshot.deployment.chain_url,
                &txid,
                tip,
            )
            .await
            {
                Ok(confirmations) => {
                    self.snapshot.recovery_attempts[attempt_index].parent_confirmations =
                        confirmations;
                    if confirmations > 0 {
                        self.snapshot.recovery_attempts[attempt_index].status =
                            "confirmed".to_string();
                    }
                }
                Err(error) => warnings.push(error),
            }
        }
        self.checkpoint()?;
        Ok(SyncResult {
            accepted_statechain_ids: accepted,
            warnings,
        })
    }

    pub async fn sync_transfers(&mut self) -> Result<SyncResult, String> {
        let mut accepted = Vec::new();
        let mut warnings = Vec::new();
        self.sync_transfer_activity(&mut accepted, &mut warnings)
            .await;
        Ok(SyncResult {
            accepted_statechain_ids: accepted,
            warnings,
        })
    }

    async fn sync_transfer_activity(
        &mut self,
        accepted: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        if let Err(error) = self.reconcile_outgoing_transfer().await {
            warnings.push(error);
        }
        match self.receive_statecoins().await {
            Ok(received) => accepted.extend(received.received_statechain_ids),
            Err(error) => warnings.push(error),
        }
    }

    async fn sync_recovery_fee_utxos(&mut self, tip: u32) -> Result<(), String> {
        let address = self
            .snapshot
            .wallet
            .bip448_recovery_fee_key()
            .map_err(error_string)?
            .address
            .to_string();
        let utxos =
            address_utxos(&self.backend, &self.snapshot.deployment.chain_url, &address).await?;
        let mut observations = Vec::with_capacity(utxos.len());
        for utxo in utxos {
            Txid::from_str(&utxo.txid).map_err(error_string)?;
            if utxo.value == 0 {
                continue;
            }
            observations.push(RecoveryFeeUtxo {
                txid: utxo.txid,
                vout: utxo.vout,
                value_sats: utxo.value,
                confirmations: confirmations(&utxo.status, tip),
            });
        }
        observations.sort_by(|left, right| {
            left.txid
                .cmp(&right.txid)
                .then_with(|| left.vout.cmp(&right.vout))
        });
        self.snapshot.recovery_fee_utxos = observations;
        Ok(())
    }

    pub(crate) async fn sync_funding_bindings(&mut self, tip: u32) -> Result<(), String> {
        let records = self.snapshot.statechains.clone();
        for record in records {
            let coin =
                current_wallet_coin(&self.snapshot.wallet.coins, &record.statechain_id)?.clone();
            let address = coin.aggregated_address.clone().ok_or_else(|| {
                format!("statechain {} has no funding address", record.statechain_id)
            })?;
            let owner_user_pubkey = PublicKey::from_str(&coin.user_pubkey)
                .map_err(error_string)?
                .x_only_public_key()
                .0
                .to_string();
            let mut utxos =
                address_utxos(&self.backend, &self.snapshot.deployment.chain_url, &address).await?;
            utxos.sort_by(|left, right| {
                left.txid
                    .cmp(&right.txid)
                    .then_with(|| left.vout.cmp(&right.vout))
            });
            let observed = utxos
                .iter()
                .map(|utxo| (utxo.txid.clone(), utxo.vout))
                .collect::<BTreeSet<_>>();

            for utxo in utxos {
                let canonical = utxo.txid == record.funding_outpoint.txid
                    && utxo.vout == record.funding_outpoint.vout;
                if canonical && utxo.value != record.amount_sats {
                    return Err(format!(
                        "canonical funding value changed for statechain {}",
                        record.statechain_id
                    ));
                }
                let existing = self.snapshot.funding_bindings.iter().position(|binding| {
                    binding.statechain_id == record.statechain_id
                        && binding.txid == utxo.txid
                        && binding.vout == utxo.vout
                });
                let binding_index = if canonical {
                    0
                } else if let Some(index) = existing {
                    self.snapshot.funding_bindings[index].binding_index
                } else {
                    self.snapshot
                        .funding_bindings
                        .iter()
                        .filter(|binding| binding.statechain_id == record.statechain_id)
                        .map(|binding| binding.binding_index)
                        .max()
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or_else(|| "duplicate index overflowed".to_string())?
                };
                let next = FundingBinding {
                    statechain_id: record.statechain_id.clone(),
                    binding_index,
                    txid: utxo.txid,
                    vout: utxo.vout,
                    value_sats: utxo.value,
                    observation_status: funding_observation_status(&utxo.status, tip).to_string(),
                    funding_height: utxo.status.block_height,
                    spend_txid: None,
                    spend_height: None,
                    owner_user_pubkey: owner_user_pubkey.clone(),
                    owner_state_number: record.latest_state_number,
                };
                if let Some(index) = existing {
                    self.snapshot.funding_bindings[index] = next;
                } else {
                    self.snapshot.funding_bindings.push(next);
                }
            }

            if !self.snapshot.funding_bindings.iter().any(|binding| {
                binding.statechain_id == record.statechain_id && binding.binding_index == 0
            }) {
                let status: EsploraStatus = get_json(
                    &self.backend,
                    &self.snapshot.deployment.chain_url,
                    &format!("tx/{}/status", record.funding_outpoint.txid),
                    "canonical funding transaction status",
                )
                .await?;
                self.snapshot.funding_bindings.push(FundingBinding {
                    statechain_id: record.statechain_id.clone(),
                    binding_index: 0,
                    txid: record.funding_outpoint.txid.clone(),
                    vout: record.funding_outpoint.vout,
                    value_sats: record.funding_outpoint.value_sats,
                    observation_status: funding_observation_status(&status, tip).to_string(),
                    funding_height: status.block_height,
                    spend_txid: None,
                    spend_height: None,
                    owner_user_pubkey: owner_user_pubkey.clone(),
                    owner_state_number: record.latest_state_number,
                });
            }

            let known = self
                .snapshot
                .funding_bindings
                .iter()
                .enumerate()
                .filter(|(_, binding)| binding.statechain_id == record.statechain_id)
                .map(|(index, binding)| (index, binding.txid.clone(), binding.vout))
                .collect::<Vec<_>>();
            for (index, txid, vout) in known {
                if observed.contains(&(txid.clone(), vout)) {
                    continue;
                }
                let outspend: EsploraOutspend = get_json(
                    &self.backend,
                    &self.snapshot.deployment.chain_url,
                    &format!("tx/{txid}/outspend/{vout}"),
                    "funding output spend status",
                )
                .await?;
                if outspend.spent {
                    let status = outspend.status.ok_or_else(|| {
                        "spent output response has no transaction status".to_string()
                    })?;
                    let spend_txid = outspend.txid;
                    {
                        let binding = &mut self.snapshot.funding_bindings[index];
                        binding.observation_status =
                            spend_observation_status(&status, tip).to_string();
                        binding.spend_txid = spend_txid.clone();
                        binding.spend_height = status.block_height;
                    }
                    if status.confirmed {
                        for attempt in &mut self.snapshot.withdrawal_attempts {
                            if attempt.txid.as_ref() == spend_txid.as_ref() {
                                attempt.broadcast_status = WithdrawalBroadcastStatus::Confirmed;
                            }
                        }
                    }
                } else {
                    let status: EsploraStatus = get_json(
                        &self.backend,
                        &self.snapshot.deployment.chain_url,
                        &format!("tx/{txid}/status"),
                        "funding transaction status",
                    )
                    .await?;
                    let binding = &mut self.snapshot.funding_bindings[index];
                    binding.observation_status =
                        funding_observation_status(&status, tip).to_string();
                    binding.funding_height = status.block_height;
                    binding.spend_txid = None;
                    binding.spend_height = None;
                }
            }

            let canonical_status = self
                .snapshot
                .funding_bindings
                .iter()
                .find(|binding| {
                    binding.statechain_id == record.statechain_id && binding.binding_index == 0
                })
                .map(|binding| binding.observation_status.as_str())
                .ok_or_else(|| "canonical funding binding disappeared".to_string())?;
            if let Some(wallet_coin) = self
                .snapshot
                .wallet
                .coins
                .iter_mut()
                .filter(|candidate| {
                    candidate.statechain_id.as_deref() == Some(record.statechain_id.as_str())
                        && candidate.status != CoinStatus::TRANSFERRED
                })
                .max_by_key(|candidate| candidate.locktime.unwrap_or_default())
            {
                wallet_coin.status = match canonical_status {
                    "Mempool" => CoinStatus::IN_MEMPOOL,
                    "Unconfirmed" => CoinStatus::UNCONFIRMED,
                    "Confirmed"
                        if self
                            .snapshot
                            .pending_outgoing_transfer
                            .as_ref()
                            .is_some_and(|pending| {
                                pending.statechain_id == record.statechain_id
                            }) =>
                    {
                        CoinStatus::IN_TRANSFER
                    }
                    "Confirmed" => CoinStatus::CONFIRMED,
                    "SpentMempool" | "SpentUnconfirmed"
                        if self
                            .snapshot
                            .recovery_attempts
                            .iter()
                            .all(|attempt| attempt.statechain_id != record.statechain_id) =>
                    {
                        CoinStatus::WITHDRAWING
                    }
                    "SpentConfirmed"
                        if self
                            .snapshot
                            .recovery_attempts
                            .iter()
                            .all(|attempt| attempt.statechain_id != record.statechain_id) =>
                    {
                        CoinStatus::WITHDRAWN
                    }
                    _ => wallet_coin.status.clone(),
                };
            }
        }
        self.snapshot.funding_bindings.sort_by(|left, right| {
            left.statechain_id
                .cmp(&right.statechain_id)
                .then_with(|| left.binding_index.cmp(&right.binding_index))
        });
        Ok(())
    }

    fn checkpoint_pending_deposit(&mut self, pending: &PendingDeposit) -> Result<(), String> {
        let stored = self
            .snapshot
            .pending_deposits
            .iter_mut()
            .find(|candidate| candidate.coin.index == pending.coin.index)
            .ok_or_else(|| "pending deposit disappeared from the wallet".to_string())?;
        *stored = pending.clone();
        self.checkpoint()
    }

    async fn sync_pending_deposit(
        &mut self,
        mut pending: PendingDeposit,
        tip: u32,
    ) -> Result<Option<String>, String> {
        let pending_position = self
            .snapshot
            .pending_deposits
            .iter()
            .position(|candidate| candidate.coin.index == pending.coin.index)
            .ok_or_else(|| "pending deposit disappeared from the wallet".to_string())?;
        let address = pending
            .coin
            .aggregated_address
            .clone()
            .ok_or_else(|| "pending deposit initialization is incomplete".to_string())?;
        let utxos =
            address_utxos(&self.backend, &self.snapshot.deployment.chain_url, &address).await?;
        let matches = utxos
            .into_iter()
            .filter(|utxo| utxo.value == u64::from(pending.amount))
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err("multiple exact-value funding outputs require operator review".to_string());
        }
        let Some(funding) = matches.into_iter().next() else {
            return Ok(None);
        };
        let confirmations = confirmations(&funding.status, tip);
        pending.funding_confirmations = confirmations;
        pending.coin.utxo_txid = Some(funding.txid.clone());
        pending.coin.utxo_vout = Some(funding.vout);
        pending.coin.status = if confirmations == 0 {
            CoinStatus::IN_MEMPOOL
        } else if confirmations < CONFIRMATION_TARGET {
            CoinStatus::UNCONFIRMED
        } else {
            CoinStatus::CONFIRMED
        };
        self.checkpoint_pending_deposit(&pending)?;
        if confirmations < CONFIRMATION_TARGET {
            return Ok(None);
        }

        let statechain_id = pending
            .coin
            .statechain_id
            .clone()
            .ok_or_else(|| "pending deposit has no statechain id".to_string())?;
        let record = self.complete_bip448_deposit(&mut pending, funding).await?;
        pending.coin.locktime = Some(record.latest_state.state_locktime);
        pending.coin.public_nonce = Some(
            record
                .latest_state
                .signing_metadata
                .client_public_nonce
                .clone(),
        );
        pending.coin.server_public_nonce = Some(
            record
                .latest_state
                .signing_metadata
                .server_public_nonce
                .clone(),
        );
        pending.coin.blinding_factor =
            Some(record.latest_state.signing_metadata.blinding_factor.clone());
        pending.coin.status = CoinStatus::CONFIRMED;
        let owner = PublicKey::from_str(&pending.coin.user_pubkey)
            .map_err(error_string)?
            .x_only_public_key()
            .0;
        self.snapshot.state_histories.insert(
            statechain_id.clone(),
            vec![crate::transfer::state_history_entry(
                &record.latest_state,
                owner,
            )],
        );
        self.snapshot.wallet.coins.push(pending.coin);
        self.snapshot.wallet.activities.push(Activity {
            utxo: format!(
                "{}:{}",
                record.funding_outpoint.txid, record.funding_outpoint.vout
            ),
            amount: pending.amount,
            action: "BIP448 deposit accepted".to_string(),
            date: self.backend.now_iso(),
        });
        self.snapshot.statechains.push(record);
        self.snapshot.pending_deposits.remove(pending_position);
        self.checkpoint()?;
        Ok(Some(statechain_id))
    }

    async fn complete_bip448_deposit(
        &mut self,
        pending: &mut PendingDeposit,
        funding: EsploraUtxo,
    ) -> Result<Bip448StatechainRecord, String> {
        let funding_outpoint = Bip448FundingOutpoint {
            txid: funding.txid,
            vout: funding.vout,
            value_sats: funding.value,
        };
        let statechain_id = pending
            .coin
            .statechain_id
            .clone()
            .ok_or_else(|| "pending deposit has no statechain id".to_string())?;

        if pending.signing.is_none() {
            let signing = new_pending_signing(&pending.coin, funding_outpoint.clone())?;
            pending.signing = Some(signing);
            self.checkpoint_pending_deposit(pending)?;
        }
        let mut signing = pending.signing.clone().unwrap();
        let templates = templates_from_pending(&pending.coin, funding_outpoint, &signing)?;

        if signing.server_public_nonce.is_none() {
            let response: Bip448SignFirstResponsePayload = post_json(
                &self.backend,
                &self.snapshot.deployment.mercury_url,
                "bip448-statechain/sign/first",
                &Bip448SignFirstRequestPayload {
                    statechain_id: statechain_id.clone(),
                    signed_statechain_id: required(
                        &pending.coin.signed_statechain_id,
                        "signature",
                    )?,
                    signing_id: signing.signing_id.clone(),
                },
                "BIP448 sign/first",
            )
            .await?;
            signing.server_public_nonce = Some(normalize_hex(&response.server_pubnonce));
            pending.signing = Some(signing.clone());
            self.checkpoint_pending_deposit(pending)?;
        }

        let secp = Secp256k1::new();
        let client_secret = PrivateKey::from_wif(&pending.coin.user_privkey)
            .map_err(error_string)?
            .inner;
        let client_keypair = KeyPair::from_secret_key(&secp, &client_secret);
        let client_pubkey = PublicKey::from_str(&pending.coin.user_pubkey).map_err(error_string)?;
        let server_pubkey =
            PublicKey::from_str(&required(&pending.coin.server_pubkey, "server public key")?)
                .map_err(error_string)?;
        let aggregate_pubkey = client_pubkey
            .combine(&server_pubkey)
            .map_err(error_string)?;
        let client_secret_nonce = secret_nonce_from_hex(&signing.client_secret_nonce)?;
        let client_public_nonce = PublicNonce::from_slice(
            &hex::decode(&signing.client_public_nonce).map_err(error_string)?,
        )
        .map_err(error_string)?;
        let server_public_nonce_string = signing.server_public_nonce.clone().unwrap();
        let server_public_nonce = PublicNonce::from_slice(
            &hex::decode(&server_public_nonce_string).map_err(error_string)?,
        )
        .map_err(error_string)?;
        let blinding_factor = BlindingFactor::from_slice(
            &hex::decode(&signing.blinding_factor).map_err(error_string)?,
        )
        .map_err(error_string)?;
        let session = CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::FundingUpdate,
            aggregate_pubkey,
            &client_public_nonce,
            &server_public_nonce,
            templates.artifacts.update_template_hash,
            &blinding_factor,
        )
        .map_err(error_string)?;
        let client_partial = session
            .partial_sign_verified(
                &secp,
                CsfsSigningParticipant::Client,
                client_secret_nonce,
                &client_public_nonce,
                &client_keypair,
            )
            .map_err(error_string)?;

        if !signing.second_armed {
            signing.second_armed = true;
            pending.signing = Some(signing.clone());
            self.checkpoint_pending_deposit(pending)?;
        }
        let second: Bip448PartialSignatureResponsePayload = post_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            "bip448-statechain/sign/second",
            &Bip448PartialSignatureRequestPayload {
                statechain_id: statechain_id.clone(),
                signed_statechain_id: required(&pending.coin.signed_statechain_id, "signature")?,
                signing_id: signing.signing_id.clone(),
                negate_seckey: u8::from(session.negate_seckey()),
                session: hex::encode(session.blinded_server_session().serialize()),
                server_pub_nonce: server_public_nonce_string.clone(),
            },
            "BIP448 sign/second",
        )
        .await?;
        let server_partial = PartialSignature::from_slice(
            &hex::decode(normalize_hex(&second.partial_sig)).map_err(error_string)?,
        )
        .map_err(error_string)?;
        session
            .verify_partial(
                &secp,
                CsfsSigningParticipant::Server,
                &server_partial,
                &server_public_nonce,
                &server_pubkey,
            )
            .map_err(error_string)?;
        let signature = session
            .aggregate_and_verify(&[&client_partial, &server_partial])
            .map_err(error_string)?;
        let count: Bip448SignatureCountResponsePayload = get_json(
            &self.backend,
            &self.snapshot.deployment.mercury_url,
            &format!("bip448-statechain/signature-count/{statechain_id}"),
            "BIP448 signature count",
        )
        .await?;
        let signing_data = bip448_deposit::Bip448DepositSigningData {
            signing_id: signing.signing_id,
            client_public_nonce: signing.client_public_nonce,
            server_public_nonce: server_public_nonce_string,
            blinding_factor: signing.blinding_factor,
            update_signature: signature.to_string(),
            server_signature_count: count.sig_count,
        };
        let record = bip448_deposit::build_deposit_record(
            &self.snapshot.wallet.name,
            &statechain_id,
            NETWORK,
            &templates,
            signing_data,
        )
        .map_err(error_string)?;
        validate_accepted_record(
            &record,
            &templates,
            median_time_past(&self.backend, &self.snapshot.deployment.chain_url).await?,
        )?;
        Ok(record)
    }

    pub async fn submit_unilateral_exit(
        &mut self,
        statechain_id: &str,
        role_name: &str,
        fee_rate: f64,
    ) -> Result<ExitResult, String> {
        if !fee_rate.is_finite() || !(MIN_FEE_RATE..=MAX_FEE_RATE).contains(&fee_rate) {
            return Err(format!(
                "fee rate must be between {MIN_FEE_RATE} and {MAX_FEE_RATE} sat/vB"
            ));
        }
        let role = parse_recovery_role(role_name)?;
        let record = self
            .snapshot
            .statechain(statechain_id)
            .cloned()
            .ok_or_else(|| format!("statechain {statechain_id} is not in this wallet"))?;
        if let Some(attempt) = self
            .snapshot
            .recovery_attempts
            .iter()
            .find(|attempt| attempt.statechain_id == statechain_id && attempt.role == role)
            .cloned()
        {
            return self.resubmit_attempt(attempt).await;
        }
        if role == Bip448RecoveryTemplateRole::Settlement {
            let update_index = self
                .snapshot
                .recovery_attempts
                .iter()
                .position(|attempt| {
                    attempt.statechain_id == statechain_id
                        && attempt.role == Bip448RecoveryTemplateRole::FundingUpdate
                })
                .ok_or_else(|| "broadcast funding_update before settlement".to_string())?;
            let challenge_delay = u32::from(record.challenge_delay);
            if self.snapshot.recovery_attempts[update_index].parent_confirmations < challenge_delay
            {
                let tip = chain_tip(&self.backend, &self.snapshot.deployment.chain_url).await?;
                let update_txid = self.snapshot.recovery_attempts[update_index]
                    .parent_txid
                    .clone();
                let confirmations = transaction_confirmations(
                    &self.backend,
                    &self.snapshot.deployment.chain_url,
                    &update_txid,
                    tip,
                )
                .await?;
                let update = &mut self.snapshot.recovery_attempts[update_index];
                update.parent_confirmations = confirmations;
                if confirmations > 0 {
                    update.status = "confirmed".to_string();
                }
                self.checkpoint()?;
            }
            let confirmations = self.snapshot.recovery_attempts[update_index].parent_confirmations;
            if confirmations < challenge_delay {
                return Err(format!(
                    "settlement is timelocked for {} more Mutinynet blocks",
                    challenge_delay - confirmations
                ));
            }
        }

        let fee_key = self
            .snapshot
            .wallet
            .bip448_recovery_fee_key()
            .map_err(error_string)?;
        let mut utxos = address_utxos(
            &self.backend,
            &self.snapshot.deployment.chain_url,
            &fee_key.address.to_string(),
        )
        .await?
        .into_iter()
        .filter(|utxo| utxo.status.confirmed)
        .collect::<Vec<_>>();
        let reserved = reserved_fee_outpoints(&self.snapshot.recovery_attempts)?;
        utxos.retain(|utxo| !reserved.contains(&(utxo.txid.clone(), utxo.vout)));
        utxos.sort_by(|left, right| {
            right
                .value
                .cmp(&left.value)
                .then_with(|| left.txid.cmp(&right.txid))
                .then_with(|| left.vout.cmp(&right.vout))
        });
        let mut fee_inputs = Vec::new();
        let mut package = None;
        for utxo in utxos {
            fee_inputs.push(Bip448CpfpFeeInput::signed(
                OutPoint {
                    txid: Txid::from_str(&utxo.txid).map_err(error_string)?,
                    vout: utxo.vout,
                },
                utxo.value,
            ));
            match build_latest_state_recovery_package(
                &record,
                role,
                &fee_inputs,
                fee_key.address.script_pubkey(),
                fee_rate,
            ) {
                Ok(value) => {
                    package = Some(value);
                    break;
                }
                Err(Bip448PackageError::FeeExceedsFeeInputs { .. })
                | Err(Bip448PackageError::ChangeWouldBeDust { .. }) => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        let mut package = package.ok_or_else(|| {
            format!(
                "fund the confirmed recovery-fee address {} before broadcasting",
                fee_key.address
            )
        })?;
        sign_cpfp_fee_inputs(
            &mut package,
            &fee_inputs,
            &fee_key.address.script_pubkey(),
            &fee_key.secret_key,
        )
        .map_err(error_string)?;
        let parent_tx_hex = hex::encode(encode::serialize(&package.parent_tx));
        let child_tx_hex = hex::encode(encode::serialize(&package.cpfp_child_tx));
        let attempt = RecoveryAttempt {
            statechain_id: statechain_id.to_string(),
            role,
            parent_tx_hex,
            child_tx_hex,
            parent_txid: package.parent_tx.txid().to_string(),
            child_txid: package.cpfp_child_tx.txid().to_string(),
            package_fee_sats: package.package_fee_sats,
            package_vbytes: package.package_vbytes,
            package_feerate_sat_per_vbyte: package.package_feerate_sat_per_vbyte,
            status: "prepared".to_string(),
            parent_confirmations: 0,
            response: None,
        };
        self.snapshot.recovery_attempts.push(attempt.clone());
        self.checkpoint()?;
        self.resubmit_attempt(attempt).await
    }

    async fn resubmit_attempt(&mut self, attempt: RecoveryAttempt) -> Result<ExitResult, String> {
        let body = serde_json::to_string(&vec![
            attempt.parent_tx_hex.clone(),
            attempt.child_tx_hex.clone(),
        ])
        .map_err(error_string)?;
        let response = self
            .backend
            .post_json(&self.snapshot.deployment.chain_url, "txs/package", &body)
            .await?;
        if !response.is_success() && !response.body.contains("already") {
            return Err(format!(
                "Mutinynet package submission returned {}: {}",
                response.status, response.body
            ));
        }
        let stored = self
            .snapshot
            .recovery_attempts
            .iter_mut()
            .find(|stored| {
                stored.statechain_id == attempt.statechain_id && stored.role == attempt.role
            })
            .ok_or_else(|| "prepared recovery attempt disappeared".to_string())?;
        stored.status = "submitted".to_string();
        stored.response = Some(response.body.clone());
        let result = exit_result(stored, response.body);
        self.checkpoint()?;
        Ok(result)
    }

    pub async fn verify_enclave(
        &mut self,
        statechain_id: &str,
    ) -> Result<EnclaveVerification, String> {
        let deployment = self.snapshot.deployment.clone();
        validate_enclave_configuration(&deployment)?;
        let coin = current_wallet_coin(&self.snapshot.wallet.coins, statechain_id)?;
        let expected_server_pubkey = normalize_hex(&required(&coin.server_pubkey, "server key")?);

        let mut challenge_bytes = [0u8; 32];
        getrandom_03::fill(&mut challenge_bytes).map_err(error_string)?;
        let challenge = hex::encode(challenge_bytes);
        let response = self
            .backend
            .verify_enclave_statechain(
                &deployment.enclavia_proxy_url,
                [
                    &deployment.expected_pcr0,
                    &deployment.expected_pcr1,
                    &deployment.expected_pcr2,
                ],
                deployment.enclavia_debug,
                statechain_id,
                &challenge,
            )
            .await?;
        let body = checked_response(response, "direct Lockbox statechain proof")?;
        let proof: VerifyStatechainResponse = serde_json::from_str(&body).map_err(error_string)?;
        if proof.statechain_id != statechain_id || proof.challenge != challenge {
            return Err(
                "Lockbox proof did not echo the requested statechain and challenge".to_string(),
            );
        }
        if normalize_hex(&proof.server_pubkey) != expected_server_pubkey {
            return Err("Lockbox key does not match the wallet server share".to_string());
        }
        let pcr0 = normalize_hex(&deployment.expected_pcr0);
        let pcr1 = normalize_hex(&deployment.expected_pcr1);
        let pcr2 = normalize_hex(&deployment.expected_pcr2);
        let verification = EnclaveVerification {
            verification_method: DIRECT_ENCLAVE_PROOF_METHOD.to_string(),
            statechain_id: statechain_id.to_string(),
            verified_at: self.backend.now_iso(),
            challenge,
            server_pubkey: expected_server_pubkey,
            pcr0,
            pcr1,
            pcr2,
            trust_model: if deployment.enclavia_debug {
                "Browser-direct Enclavia SDK challenge response over a pinned debug/QEMU Noise channel; no Nitro hardware isolation".to_string()
            } else {
                "Browser-direct Enclavia SDK challenge response over an attested Noise channel with pinned production Nitro PCRs; Mercury cannot read or forge the exchange".to_string()
            },
        };

        self.snapshot
            .enclave_verifications
            .retain(|proof| proof.statechain_id != statechain_id);
        self.snapshot
            .enclave_verifications
            .push(verification.clone());
        self.checkpoint()?;
        Ok(verification)
    }
    pub async fn verify_enclave_runtime(&mut self) -> Result<EnclaveRuntimeProof, String> {
        validate_enclave_configuration(&self.snapshot.deployment)?;
        self.backend
            .attest_enclave(
                &self.snapshot.deployment.enclavia_proxy_url,
                [
                    &self.snapshot.deployment.expected_pcr0,
                    &self.snapshot.deployment.expected_pcr1,
                    &self.snapshot.deployment.expected_pcr2,
                ],
                self.snapshot.deployment.enclavia_debug,
            )
            .await?;
        let mode = if self.snapshot.deployment.enclavia_debug {
            "debug"
        } else {
            "production"
        };
        let proof = EnclaveRuntimeProof {
            verification_method: DIRECT_ENCLAVE_PROOF_METHOD.to_string(),
            checked_at: self.backend.now_iso(),
            endpoint: self
                .snapshot
                .deployment
                .enclavia_proxy_url
                .replacen("https://", "wss://", 1),
            mode: mode.to_string(),
            pcr0: normalize_hex(&self.snapshot.deployment.expected_pcr0),
            pcr1: normalize_hex(&self.snapshot.deployment.expected_pcr1),
            pcr2: normalize_hex(&self.snapshot.deployment.expected_pcr2),
            authentication: "attested Noise".to_string(),
            trust_model: if self.snapshot.deployment.enclavia_debug {
                "Browser established a direct Enclavia SDK Noise channel and matched the pinned debug/QEMU measurements; no Nitro hardware isolation".to_string()
            } else {
                "Browser established an end-to-end Enclavia SDK Noise channel, verified the AWS Nitro attestation certificate chain, bound it to this handshake, and matched the pinned production PCR measurements".to_string()
            },
        };
        self.snapshot.enclave_runtime_proof = Some(proof.clone());
        self.checkpoint()?;
        Ok(proof)
    }

    pub(crate) fn checkpoint(&self) -> Result<(), String> {
        let snapshot = serde_json::to_string(&self.snapshot).map_err(error_string)?;
        self.backend.checkpoint(&snapshot)
    }
}

fn current_wallet_coin<'a>(coins: &'a [Coin], statechain_id: &str) -> Result<&'a Coin, String> {
    coins
        .iter()
        .filter(|coin| {
            coin.statechain_id.as_deref() == Some(statechain_id)
                && coin.status != CoinStatus::TRANSFERRED
        })
        .max_by_key(|coin| coin.locktime.unwrap_or_default())
        .ok_or_else(|| format!("wallet coin {statechain_id} is missing"))
}

fn withdrawal_phase_label(phase: WithdrawalPhase) -> &'static str {
    match phase {
        WithdrawalPhase::Prepared => "prepared",
        WithdrawalPhase::FirstArmed => "signing",
        WithdrawalPhase::NonceStored => "nonce saved",
        WithdrawalPhase::SecondArmed => "exit-only",
        WithdrawalPhase::Signed => "signed",
    }
}

fn withdrawal_broadcast_label(status: WithdrawalBroadcastStatus) -> &'static str {
    match status {
        WithdrawalBroadcastStatus::NotBroadcast => "not broadcast",
        WithdrawalBroadcastStatus::Accepted => "broadcast",
        WithdrawalBroadcastStatus::Confirmed => "confirmed",
        WithdrawalBroadcastStatus::NeedsRebroadcast => "needs rebroadcast",
        WithdrawalBroadcastStatus::Conflicting => "conflicting spend",
        WithdrawalBroadcastStatus::Conflicted => "spent elsewhere",
    }
}

fn new_pending_signing(
    coin: &mercurylib::wallet::Coin,
    funding_outpoint: Bip448FundingOutpoint,
) -> Result<PendingBip448Signing, String> {
    let state_locktime = bip448_deposit::sample_initial_state_locktime().to_consensus_u32();
    let templates = bip448_deposit::build_deposit_templates(
        coin,
        funding_outpoint.clone(),
        absolute::LockTime::from_consensus(state_locktime),
        bip448_deposit::DEFAULT_BIP448_CHALLENGE_DELAY,
        NETWORK,
    )
    .map_err(error_string)?;
    let client_secret = PrivateKey::from_wif(&coin.user_privkey)
        .map_err(error_string)?
        .inner;
    let client_pubkey = PublicKey::from_str(&coin.user_pubkey).map_err(error_string)?;
    let secp = Secp256k1::new();
    let mut rng = rand::rng();
    let signing_message: Message = templates.artifacts.update_template_hash.into();
    let (client_secret_nonce, client_public_nonce) = new_musig_nonce_pair(
        &secp,
        MusigSessionId::new(&mut rng),
        None,
        Some(client_secret),
        client_pubkey,
        Some(signing_message),
        None,
    )
    .map_err(error_string)?;
    let blinding_secret = SecretKey::new(&mut rng);
    let blinding_factor =
        BlindingFactor::from_slice(&blinding_secret.to_secret_bytes()).map_err(error_string)?;
    Ok(PendingBip448Signing {
        funding_txid: funding_outpoint.txid,
        funding_vout: funding_outpoint.vout,
        funding_value_sats: funding_outpoint.value_sats,
        state_locktime,
        update_template_hash: hex::encode(templates.artifacts.update_template_hash.to_byte_array()),
        settlement_template_hash: hex::encode(
            templates.artifacts.settlement_template_hash.to_byte_array(),
        ),
        signing_id: hex::encode(SecretKey::new(&mut rng).to_secret_bytes()),
        client_secret_nonce: hex::encode(client_secret_nonce.serialize()),
        client_public_nonce: hex::encode(client_public_nonce.serialize()),
        blinding_factor: hex::encode(blinding_factor.as_bytes()),
        server_public_nonce: None,
        second_armed: false,
    })
}

fn templates_from_pending(
    coin: &mercurylib::wallet::Coin,
    funding_outpoint: Bip448FundingOutpoint,
    pending: &PendingBip448Signing,
) -> Result<bip448_deposit::Bip448DepositTemplates, String> {
    if pending.funding_txid != funding_outpoint.txid
        || pending.funding_vout != funding_outpoint.vout
        || pending.funding_value_sats != funding_outpoint.value_sats
    {
        return Err("persisted signing state does not match the funding output".to_string());
    }
    let templates = bip448_deposit::build_deposit_templates(
        coin,
        funding_outpoint,
        absolute::LockTime::from_consensus(pending.state_locktime),
        bip448_deposit::DEFAULT_BIP448_CHALLENGE_DELAY,
        NETWORK,
    )
    .map_err(error_string)?;
    if pending.update_template_hash
        != hex::encode(templates.artifacts.update_template_hash.to_byte_array())
        || pending.settlement_template_hash
            != hex::encode(templates.artifacts.settlement_template_hash.to_byte_array())
    {
        return Err("persisted signing state does not match reconstructed templates".to_string());
    }
    Ok(templates)
}

fn validate_accepted_record(
    record: &Bip448StatechainRecord,
    templates: &bip448_deposit::Bip448DepositTemplates,
    median_time_past: u32,
) -> Result<(), String> {
    if record.latest_state_number != bip448_deposit::INITIAL_BIP448_STATE_NUMBER
        || record.latest_state.signing_metadata.server_signature_count
            != u64::from(bip448_deposit::INITIAL_BIP448_STATE_NUMBER)
    {
        return Err("accepted deposit is not BIP448 logical state 1".to_string());
    }
    let aggregate_pubkey = PublicKey::from_str(&record.aggregate_pubkey).map_err(error_string)?;
    let funding_outpoint = OutPoint {
        txid: Txid::from_str(&record.funding_outpoint.txid).map_err(error_string)?,
        vout: record.funding_outpoint.vout,
    };
    let funding_output = TxOut {
        value: record.funding_outpoint.value_sats,
        script_pubkey: templates.artifacts.funding_output_script_pubkey.clone(),
    };
    let recovery_script = templates
        .artifacts
        .settlement_tx
        .output
        .first()
        .ok_or_else(|| "settlement template has no recovery output".to_string())?
        .script_pubkey
        .clone();
    let canonical = record
        .latest_state
        .verify_reconstructed_templates(
            &Secp256k1::new(),
            &aggregate_pubkey,
            funding_outpoint,
            &funding_output,
            &recovery_script,
        )
        .map_err(error_string)?;
    if canonical != record.latest_state {
        return Err("accepted BIP448 record is not canonical".to_string());
    }
    validate_immediately_final(
        absolute::LockTime::from_consensus(record.latest_state.state_locktime),
        median_time_past,
    )
    .map_err(error_string)
}

pub(crate) fn secret_nonce_from_hex(value: &str) -> Result<MusigSecNonce, String> {
    let bytes: [u8; 132] = hex::decode(value)
        .map_err(error_string)?
        .try_into()
        .map_err(|_| "client secret nonce must be 132 bytes".to_string())?;
    Ok(MusigSecNonce::from_slice(bytes))
}

pub(crate) async fn chain_tip<B: Backend>(backend: &B, chain_url: &str) -> Result<u32, String> {
    let response = backend.get(chain_url, "blocks/tip/height").await?;
    checked_response(response, "Mutinynet tip")?
        .trim()
        .parse::<u32>()
        .map_err(error_string)
}

pub(crate) async fn median_time_past<B: Backend>(
    backend: &B,
    chain_url: &str,
) -> Result<u32, String> {
    let hash = checked_response(
        backend.get(chain_url, "blocks/tip/hash").await?,
        "Mutinynet tip hash",
    )?;
    let block: EsploraBlock = get_json(
        backend,
        chain_url,
        &format!("block/{}", hash.trim()),
        "Mutinynet tip block",
    )
    .await?;
    Ok(block.mediantime)
}

async fn address_utxos<B: Backend>(
    backend: &B,
    chain_url: &str,
    address: &str,
) -> Result<Vec<EsploraUtxo>, String> {
    get_json(
        backend,
        chain_url,
        &format!("address/{address}/utxo"),
        "Mutinynet address UTXOs",
    )
    .await
}

async fn transaction_confirmations<B: Backend>(
    backend: &B,
    chain_url: &str,
    txid: &str,
    tip: u32,
) -> Result<u32, String> {
    let response = backend.get(chain_url, &format!("tx/{txid}/status")).await?;
    if response.status == 404 {
        return Ok(0);
    }
    let status: EsploraStatus =
        serde_json::from_str(&checked_response(response, "Mutinynet transaction status")?)
            .map_err(error_string)?;
    Ok(confirmations(&status, tip))
}

fn confirmations(status: &EsploraStatus, tip: u32) -> u32 {
    if !status.confirmed {
        return 0;
    }
    status
        .block_height
        .map_or(0, |height| tip.saturating_sub(height).saturating_add(1))
}

fn funding_observation_status(status: &EsploraStatus, tip: u32) -> &'static str {
    if !status.confirmed {
        "Mempool"
    } else if confirmations(status, tip) >= CONFIRMATION_TARGET {
        "Confirmed"
    } else {
        "Unconfirmed"
    }
}

fn spend_observation_status(status: &EsploraStatus, tip: u32) -> &'static str {
    if !status.confirmed {
        "SpentMempool"
    } else if confirmations(status, tip) >= CONFIRMATION_TARGET {
        "SpentConfirmed"
    } else {
        "SpentUnconfirmed"
    }
}

pub(crate) async fn get_json<B: Backend, T: for<'de> Deserialize<'de>>(
    backend: &B,
    base_url: &str,
    path: &str,
    context: &str,
) -> Result<T, String> {
    let response = backend.get(base_url, path).await?;
    serde_json::from_str(&checked_response(response, context)?).map_err(error_string)
}

pub(crate) async fn post_json<B: Backend, P: Serialize, T: for<'de> Deserialize<'de>>(
    backend: &B,
    base_url: &str,
    path: &str,
    payload: &P,
    context: &str,
) -> Result<T, String> {
    let body = serde_json::to_string(payload).map_err(error_string)?;
    let response = backend.post_json(base_url, path, &body).await?;
    serde_json::from_str(&checked_response(response, context)?).map_err(error_string)
}

pub(crate) fn checked_response(response: ApiResponse, context: &str) -> Result<String, String> {
    if response.is_success() {
        Ok(response.body)
    } else {
        Err(format!(
            "{context} returned {}: {}",
            response.status, response.body
        ))
    }
}

pub(crate) fn required(value: &Option<String>, description: &str) -> Result<String, String> {
    value
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("coin is missing {description}"))
}

pub(crate) fn normalize_hex(value: &str) -> String {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn parse_recovery_role(value: &str) -> Result<Bip448RecoveryTemplateRole, String> {
    match value {
        "funding_update" => Ok(Bip448RecoveryTemplateRole::FundingUpdate),
        "settlement" => Ok(Bip448RecoveryTemplateRole::Settlement),
        _ => Err("recovery role must be funding_update or settlement".to_string()),
    }
}

fn reserved_fee_outpoints(attempts: &[RecoveryAttempt]) -> Result<BTreeSet<(String, u32)>, String> {
    let mut outpoints = BTreeSet::new();
    for attempt in attempts {
        let child: Transaction =
            encode::deserialize(&hex::decode(&attempt.child_tx_hex).map_err(error_string)?)
                .map_err(error_string)?;
        for input in child.input.iter().skip(1) {
            outpoints.insert((
                input.previous_output.txid.to_string(),
                input.previous_output.vout,
            ));
        }
    }
    Ok(outpoints)
}

fn exit_result(attempt: &RecoveryAttempt, response: String) -> ExitResult {
    ExitResult {
        statechain_id: attempt.statechain_id.clone(),
        role: attempt.role.as_str().to_string(),
        parent_txid: attempt.parent_txid.clone(),
        child_txid: attempt.child_txid.clone(),
        package_fee_sats: attempt.package_fee_sats,
        package_vbytes: attempt.package_vbytes,
        package_feerate_sat_per_vbyte: attempt.package_feerate_sat_per_vbyte,
        response,
    }
}

fn txid_from_hex(value: &str) -> Result<String, String> {
    let transaction: Transaction =
        encode::deserialize(&hex::decode(value).map_err(error_string)?).map_err(error_string)?;
    Ok(transaction.txid().to_string())
}

fn normalize_enclave_proofs(snapshot: &mut WalletSnapshot) {
    if snapshot
        .enclave_runtime_proof
        .as_ref()
        .is_some_and(|proof| proof.verification_method != DIRECT_ENCLAVE_PROOF_METHOD)
    {
        snapshot.enclave_runtime_proof = None;
    }
    let mut statechain_ids = BTreeSet::new();
    snapshot.enclave_verifications.retain(|proof| {
        proof.verification_method == DIRECT_ENCLAVE_PROOF_METHOD
            && statechain_ids.insert(proof.statechain_id.clone())
    });
    if let Some(proof) = snapshot.enclave_verification.take() {
        if proof.verification_method == DIRECT_ENCLAVE_PROOF_METHOD
            && statechain_ids.insert(proof.statechain_id.clone())
        {
            snapshot.enclave_verifications.push(proof);
        }
    }
}

fn validate_snapshot(snapshot: &WalletSnapshot) -> Result<(), String> {
    if snapshot.snapshot_version != SNAPSHOT_VERSION {
        return Err(format!(
            "unsupported backup version {}",
            snapshot.snapshot_version
        ));
    }
    if snapshot.wallet.name != "browser" || snapshot.wallet.network != NETWORK {
        return Err("backup is not the BIP448 Mutinynet browser wallet".to_string());
    }
    validate_deployment(&snapshot.deployment)?;
    let mut reserved_coin_indices = BTreeSet::new();
    for coin in &snapshot.wallet.coins {
        if !reserved_coin_indices.insert(coin.index) {
            return Err("backup reuses a wallet key index".to_string());
        }
    }
    for retired in &snapshot.cancelled_deposits {
        // Older wallets could reuse a cancelled deposit key for a receive
        // address. Preserve those backups, but reserve the index from now on.
        reserved_coin_indices.insert(retired.coin.index);
    }
    let mut pending_statechain_ids = BTreeSet::new();
    let mut incomplete_deposits = 0;
    for pending in &snapshot.pending_deposits {
        let initialized_fields = [
            pending.coin.statechain_id.is_some(),
            pending.coin.signed_statechain_id.is_some(),
            pending.coin.server_pubkey.is_some(),
            pending.coin.aggregated_address.is_some(),
            pending.coin.aggregated_pubkey.is_some(),
        ];
        let initialized = initialized_fields.iter().all(|present| *present);
        let incomplete = initialized_fields.iter().all(|present| !*present);
        if pending.token_id.trim().is_empty()
            || pending.amount < MIN_DEPOSIT_AMOUNT
            || pending.coin.statechain_protocol.as_deref()
                != Some(bip448_deposit::BIP448_COIN_PROTOCOL)
            || !reserved_coin_indices.insert(pending.coin.index)
            || (!initialized && !incomplete)
            || (initialized && pending.coin.amount != Some(pending.amount))
            || (incomplete && pending.coin.amount.is_some())
            || pending.coin.utxo_txid.is_some() != pending.coin.utxo_vout.is_some()
            || (pending.coin.utxo_txid.is_none()
                && (pending.funding_confirmations != 0 || pending.signing.is_some()))
        {
            return Err("backup contains an inconsistent pending deposit".to_string());
        }
        if let Some(txid) = pending.coin.utxo_txid.as_deref() {
            Txid::from_str(txid).map_err(error_string)?;
        }
        if incomplete {
            incomplete_deposits += 1;
        } else {
            let statechain_id = pending.coin.statechain_id.as_ref().unwrap();
            if snapshot.statechain(statechain_id).is_some()
                || !pending_statechain_ids.insert(statechain_id.clone())
            {
                return Err("backup reuses a pending deposit statechain ID".to_string());
            }
        }
    }
    if incomplete_deposits > 1 {
        return Err("backup contains multiple incomplete deposit requests".to_string());
    }

    let mut ids = BTreeSet::new();
    for record in &snapshot.statechains {
        if record.wallet_name != snapshot.wallet.name
            || record.network != NETWORK
            || !ids.insert(record.statechain_id.clone())
        {
            return Err("backup contains inconsistent BIP448 statechain records".to_string());
        }
        let history = snapshot
            .state_history(&record.statechain_id)
            .ok_or_else(|| "backup is missing statecoin recovery history".to_string())?;
        if history.len() != record.latest_state_number as usize
            || history
                .iter()
                .enumerate()
                .any(|(index, entry)| entry.state_number != index as u32 + 1)
        {
            return Err("backup contains incomplete statecoin recovery history".to_string());
        }
        let coin = current_wallet_coin(&snapshot.wallet.coins, &record.statechain_id)
            .map_err(|_| "backup is missing a current statecoin wallet key".to_string())?;
        let mut owner = PublicKey::from_str(&coin.user_pubkey)
            .map_err(error_string)?
            .x_only_public_key()
            .0
            .to_string();
        if let Some(predecessor) = snapshot
            .pending_outgoing_transfer
            .as_ref()
            .filter(|pending| {
                pending.statechain_id == record.statechain_id
                    && pending.intent_kind == "cancellation"
            })
            .and_then(|pending| pending.predecessor_message.as_ref())
        {
            if predecessor.statechain_id != record.statechain_id
                || predecessor.latest_state_number != record.latest_state_number
                || predecessor.state_history.as_slice() != history
            {
                return Err("backup cancellation predecessor changed history".to_string());
            }
            owner = PublicKey::from_str(&predecessor.receiver_user_public_key)
                .map_err(error_string)?
                .x_only_public_key()
                .0
                .to_string();
        }
        if history.last().is_none_or(|entry| {
            entry.owner_public_key != owner
                || entry.state_number != record.latest_state.state_number
                || entry.state_locktime != record.latest_state.state_locktime
                || entry.update_template_hash != record.latest_state.update_template_hash
                || entry.settlement_template_hash != record.latest_state.settlement_template_hash
                || entry.update_signature != record.latest_state.signing_metadata.update_signature
        }) {
            return Err(
                "backup statecoin history does not match its latest recovery state".to_string(),
            );
        }
    }
    if snapshot
        .recovery_attempts
        .iter()
        .any(|attempt| snapshot.statechain(&attempt.statechain_id).is_none())
    {
        return Err("backup contains recovery attempts for unknown statechains".to_string());
    }
    let mut binding_keys = BTreeSet::new();
    let mut binding_outpoints = BTreeSet::new();
    for binding in &snapshot.funding_bindings {
        let record = snapshot.statechain(&binding.statechain_id).ok_or_else(|| {
            "backup contains funding bindings for unknown statechains".to_string()
        })?;
        Txid::from_str(&binding.txid).map_err(error_string)?;
        if binding.value_sats == 0
            || binding.owner_state_number == 0
            || binding.owner_state_number > record.latest_state_number
            || !binding_keys.insert((binding.statechain_id.clone(), binding.binding_index))
            || !binding_outpoints.insert((binding.txid.clone(), binding.vout))
            || !matches!(
                binding.observation_status.as_str(),
                "Mempool"
                    | "Unconfirmed"
                    | "Confirmed"
                    | "SpentMempool"
                    | "SpentUnconfirmed"
                    | "SpentConfirmed"
            )
        {
            return Err("backup contains inconsistent funding bindings".to_string());
        }
        if binding.binding_index == 0
            && (binding.txid != record.funding_outpoint.txid
                || binding.vout != record.funding_outpoint.vout
                || binding.value_sats != record.funding_outpoint.value_sats)
        {
            return Err("backup canonical funding binding changed identity".to_string());
        }
        let spent_status = binding.observation_status.starts_with("Spent");
        if binding
            .spend_txid
            .as_ref()
            .is_some_and(|txid| Txid::from_str(txid).is_err())
            || binding.spend_txid.is_some() != spent_status
            || (binding.spend_height.is_some() && binding.spend_txid.is_none())
        {
            return Err("backup contains an invalid funding spend observation".to_string());
        }
    }
    for record in &snapshot.statechains {
        let bindings = snapshot
            .funding_bindings
            .iter()
            .filter(|binding| binding.statechain_id == record.statechain_id)
            .collect::<Vec<_>>();
        if !bindings.is_empty() && !bindings.iter().any(|binding| binding.binding_index == 0) {
            return Err("backup is missing a canonical funding binding".to_string());
        }
    }
    let mut recovery_fee_outpoints = BTreeSet::new();
    for utxo in &snapshot.recovery_fee_utxos {
        if Txid::from_str(&utxo.txid).is_err()
            || utxo.value_sats == 0
            || !recovery_fee_outpoints.insert((utxo.txid.clone(), utxo.vout))
        {
            return Err("backup contains invalid recovery-fee UTXOs".to_string());
        }
    }

    let mut withdrawal_keys = BTreeSet::new();
    let mut withdrawal_signing_ids = BTreeSet::new();
    for attempt in &snapshot.withdrawal_attempts {
        let binding = snapshot
            .funding_bindings
            .iter()
            .find(|binding| {
                binding.statechain_id == attempt.statechain_id
                    && binding.binding_index == attempt.binding_index
            })
            .ok_or_else(|| "backup withdrawal attempt has no funding binding".to_string())?;
        let kind_matches_index = matches!(
            (attempt.kind, attempt.binding_index),
            (crate::model::WithdrawalKind::Canonical, 0)
        ) || (attempt.kind == crate::model::WithdrawalKind::Duplicate
            && attempt.binding_index > 0);
        if !kind_matches_index
            || !withdrawal_keys.insert((attempt.statechain_id.clone(), attempt.binding_index))
            || !withdrawal_signing_ids.insert(attempt.signing_id.clone())
            || attempt.source_txid != binding.txid
            || attempt.source_vout != binding.vout
            || attempt.source_value_sats != binding.value_sats
            || attempt.owner_state_number != binding.owner_state_number
            || attempt.owner_user_pubkey != binding.owner_user_pubkey
            || !attempt.fee_rate_sat_per_vbyte.is_finite()
            || !(MIN_FEE_RATE..=MAX_FEE_RATE).contains(&attempt.fee_rate_sat_per_vbyte)
            || attempt.fee_sats == 0
            || attempt.fee_sats >= attempt.source_value_sats
        {
            return Err("backup contains an inconsistent withdrawal attempt".to_string());
        }
        let network = Network::from_str(NETWORK).map_err(error_string)?;
        Address::from_str(&attempt.destination_address)
            .map_err(error_string)?
            .require_network(network)
            .map_err(error_string)?;
        let unsigned: Transaction =
            encode::deserialize(&hex::decode(&attempt.unsigned_tx_hex).map_err(error_string)?)
                .map_err(error_string)?;
        if unsigned.input.len() != 1
            || unsigned.input[0].previous_output.txid.to_string() != attempt.source_txid
            || unsigned.input[0].previous_output.vout != attempt.source_vout
            || unsigned.output.len() != 1
            || unsigned.output[0].value + attempt.fee_sats != attempt.source_value_sats
            || unsigned.lock_time.to_consensus_u32() != attempt.lock_time
            || hex::encode(unsigned.output[0].script_pubkey.as_bytes())
                != attempt.destination_script_pubkey
        {
            return Err("backup withdrawal transaction changed its prepared intent".to_string());
        }
        let nonce_material = [
            attempt.server_public_nonce.as_ref(),
            attempt.message_hex.as_ref(),
            attempt.output_pubkey.as_ref(),
            attempt.client_partial_sig.as_ref(),
            attempt.encoded_session.as_ref(),
        ];
        let phase_has_nonce = matches!(
            attempt.phase,
            WithdrawalPhase::NonceStored | WithdrawalPhase::SecondArmed | WithdrawalPhase::Signed
        );
        if nonce_material.iter().all(|value| value.is_some()) != phase_has_nonce
            || attempt.sign_second_payload.is_some() != phase_has_nonce
            || (attempt.phase != WithdrawalPhase::Signed
                && (attempt.server_partial_sig.is_some()
                    || attempt.aggregate_signature.is_some()
                    || attempt.signed_tx_hex.is_some()
                    || attempt.txid.is_some()
                    || attempt.broadcast_status != WithdrawalBroadcastStatus::NotBroadcast))
        {
            return Err("backup withdrawal journal has an invalid phase".to_string());
        }
        if attempt.phase == WithdrawalPhase::Signed {
            let signed_hex = attempt
                .signed_tx_hex
                .as_ref()
                .ok_or_else(|| "backup signed withdrawal has no transaction".to_string())?;
            if attempt.server_partial_sig.is_none()
                || attempt.aggregate_signature.is_none()
                || attempt.txid.is_none()
            {
                return Err("backup signed withdrawal is missing signature material".to_string());
            }
            let signed: Transaction =
                encode::deserialize(&hex::decode(signed_hex).map_err(error_string)?)
                    .map_err(error_string)?;
            if attempt.txid.as_deref() != Some(signed.txid().to_string().as_str())
                || signed.txid() != unsigned.txid()
            {
                return Err("backup signed withdrawal transaction changed identity".to_string());
            }
        }
        let completion_is_valid = match attempt.kind {
            crate::model::WithdrawalKind::Canonical => {
                attempt.completion_status != WithdrawalCompletionStatus::NotApplicable
            }
            crate::model::WithdrawalKind::Duplicate => {
                attempt.completion_status == WithdrawalCompletionStatus::NotApplicable
            }
        };
        if !completion_is_valid {
            return Err("backup withdrawal completion state is inconsistent".to_string());
        }
    }

    if let Some(pending) = snapshot.pending_outgoing_transfer.as_ref() {
        if !matches!(
            pending.intent_kind.as_str(),
            "user_transfer" | "cancellation"
        ) || pending
            .batch_id
            .as_ref()
            .is_some_and(|batch| batch.trim().is_empty())
            || (pending.intent_kind == "cancellation") != pending.predecessor_message.is_some()
        {
            return Err("backup contains an invalid outgoing transfer intent".to_string());
        }
        let record = snapshot.statechain(&pending.statechain_id).ok_or_else(|| {
            "backup contains an outgoing transfer for an unknown statecoin".to_string()
        })?;
        let (_, receiver, recipient_auth) =
            mercurylib::decode_transfer_address(&pending.recipient_address)
                .map_err(error_string)?;
        if receiver.to_string() != pending.receiver_user_pubkey
            || recipient_auth.to_string() != pending.recipient_auth_pubkey
            || (pending.delivered
                && (pending.message.is_none()
                    || pending.encrypted_message.is_none()
                    || !snapshot.wallet.coins.iter().any(|coin| {
                        coin.statechain_id.as_deref() == Some(pending.statechain_id.as_str())
                            && coin.status == CoinStatus::IN_TRANSFER
                    })))
        {
            return Err("backup contains inconsistent outgoing transfer state".to_string());
        }
        if let Some(message) = pending.message.as_ref() {
            let history = snapshot
                .state_history(&pending.statechain_id)
                .ok_or_else(|| "outgoing transfer is missing recovery history".to_string())?;
            if message.statechain_id != pending.statechain_id
                || message.receiver_user_public_key != pending.receiver_user_pubkey
                || message.latest_state_number != record.latest_state_number + 1
                || message.state_history.len() != history.len() + 1
                || message.state_history.get(..history.len()) != Some(history)
            {
                return Err(
                    "backup outgoing transfer message changed identity or history".to_string(),
                );
            }
        }
    }
    if snapshot
        .pending_incoming_transfer
        .as_ref()
        .is_some_and(|pending| {
            !snapshot.wallet.coins.iter().any(|coin| {
                coin.status == CoinStatus::INITIALISED
                    && coin.auth_pubkey == pending.receiver_auth_pubkey
            })
        })
    {
        return Err("backup contains an incoming transfer without its receive key".to_string());
    }
    Ok(())
}

fn validate_deployment(deployment: &DeploymentConfig) -> Result<(), String> {
    validate_url("Mercury URL", &deployment.mercury_url)?;
    validate_url("chain URL", &deployment.chain_url)?;
    validate_url("explorer URL", &deployment.explorer_url)?;
    if !is_loopback_url(&deployment.mercury_url)
        && deployment.mercury_url != DEFAULT_STATECHAIN_ENDPOINT
    {
        return Err(
            "Mercury URL must be the deployed Mutinynet endpoint or loopback HTTP".to_string(),
        );
    }
    if !is_loopback_url(&deployment.chain_url)
        && deployment.chain_url != "https://mutinynet.com/api"
    {
        return Err("chain URL must be the Mutinynet Esplora API or loopback HTTP".to_string());
    }
    if !is_loopback_url(&deployment.explorer_url)
        && deployment.explorer_url != "https://mutinynet.com"
    {
        return Err("explorer URL must be mutinynet.com or loopback HTTP".to_string());
    }
    if !deployment.enclavia_proxy_url.is_empty() {
        validate_url("Enclavia proxy URL", &deployment.enclavia_proxy_url)?;
        if !https_host_ends_with(&deployment.enclavia_proxy_url, ".enclaves.beta.enclavia.io") {
            return Err(
                "Enclavia proxy URL must be a beta.enclavia.io enclave HTTPS host".to_string(),
            );
        }
        validate_pcr("PCR0", &deployment.expected_pcr0)?;
        validate_pcr("PCR1", &deployment.expected_pcr1)?;
        validate_pcr("PCR2", &deployment.expected_pcr2)?;
    }
    Ok(())
}

fn validate_enclave_configuration(deployment: &DeploymentConfig) -> Result<(), String> {
    if deployment.enclavia_proxy_url.is_empty() {
        return Err("configure the Enclavia HTTPS endpoint and PCR pins first".to_string());
    }
    validate_deployment(deployment)
}

fn validate_url(name: &str, value: &str) -> Result<(), String> {
    let valid = value.starts_with("https://")
        || value.starts_with("http://127.0.0.1:")
        || value.starts_with("http://localhost:");
    if !valid || value.chars().any(char::is_whitespace) || value.ends_with('/') {
        return Err(format!(
            "{name} must be HTTPS (or loopback HTTP) without whitespace or a trailing slash"
        ));
    }
    Ok(())
}

fn is_loopback_url(value: &str) -> bool {
    value.starts_with("http://127.0.0.1:") || value.starts_with("http://localhost:")
}

fn https_host_ends_with(value: &str, suffix: &str) -> bool {
    let Some(host) = value.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && !host.contains(['/', '?', '#'])
        && host.ends_with(suffix)
        && host.len() > suffix.len()
}

fn validate_pcr(name: &str, value: &str) -> Result<(), String> {
    let normalized = normalize_hex(value);
    if normalized.len() != 96 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{name} must contain exactly 96 hexadecimal characters"
        ));
    }
    Ok(())
}

fn error_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        rc::Rc,
    };

    use secp256k1::musig::Session as MusigSession;

    #[test]
    fn deployment_defaults_pin_selected_production_enclave() {
        let mut deployment = DeploymentConfig::default();
        assert!(validate_deployment(&deployment).is_ok());
        assert!(!deployment.enclavia_debug);

        deployment.expected_pcr0.clear();
        assert!(validate_deployment(&deployment).is_err());
    }

    #[test]
    fn deployment_rejects_arbitrary_mercury_hosts() {
        let mut deployment = DeploymentConfig::default();
        deployment.mercury_url = "https://attacker.lx.dev".to_string();
        assert!(validate_deployment(&deployment).is_err());
    }

    #[test]
    fn recovery_roles_are_intentionally_bounded() {
        assert_eq!(
            parse_recovery_role("funding_update").unwrap(),
            Bip448RecoveryTemplateRole::FundingUpdate
        );
        assert_eq!(
            parse_recovery_role("settlement").unwrap(),
            Bip448RecoveryTemplateRole::Settlement
        );
        assert!(parse_recovery_role("state_update").is_err());
    }

    #[test]
    fn confirmations_are_tip_relative() {
        assert_eq!(
            confirmations(
                &EsploraStatus {
                    confirmed: true,
                    block_height: Some(100),
                },
                105,
            ),
            6
        );
        assert_eq!(
            confirmations(
                &EsploraStatus {
                    confirmed: false,
                    block_height: None,
                },
                105,
            ),
            0
        );
    }

    struct DepositRetryBackend {
        responses: Vec<String>,
        posts: std::rc::Rc<std::cell::Cell<u32>>,
    }

    impl Backend for DepositRetryBackend {
        async fn get(&self, _base_url: &str, _path: &str) -> Result<ApiResponse, String> {
            Err("unexpected GET".to_string())
        }

        async fn post_json(
            &self,
            _base_url: &str,
            path: &str,
            _body: &str,
        ) -> Result<ApiResponse, String> {
            assert_eq!(path, "deposit/init/pod");
            let index = self.posts.get() as usize;
            let body = self
                .responses
                .get(index)
                .cloned()
                .ok_or_else(|| "unexpected extra deposit request".to_string())?;
            self.posts.set(self.posts.get() + 1);
            Ok(ApiResponse { status: 200, body })
        }

        fn checkpoint(&self, _snapshot: &str) -> Result<(), String> {
            Ok(())
        }

        fn now_iso(&self) -> String {
            "time".to_string()
        }
    }

    #[tokio::test]
    async fn incomplete_deposit_retries_the_same_token_and_client_key() {
        let (mut snapshot, _) = recovery_fixture();
        snapshot.wallet.coins.clear();
        snapshot.statechains.clear();
        let mut coin = snapshot.wallet.get_new_coin().unwrap();
        coin.statechain_protocol = Some(bip448_deposit::BIP448_COIN_PROTOCOL.to_string());
        let original_user_pubkey = coin.user_pubkey.clone();
        snapshot.pending_deposits = vec![PendingDeposit {
            token_id: "retry-token".to_string(),
            amount: 1_500,
            funding_confirmations: 0,
            coin,
            signing: None,
        }];
        let server_key = SecretKey::from_secret_bytes([9; 32])
            .unwrap()
            .public_key(&Secp256k1::new());
        let response = serde_json::to_string(&DepositMsg1Response {
            server_pubkey: server_key.to_string(),
            statechain_id: "ab".repeat(16),
        })
        .unwrap();
        let posts = std::rc::Rc::new(std::cell::Cell::new(0));
        let backend = DepositRetryBackend {
            responses: vec![response],
            posts: posts.clone(),
        };
        let mut client = WalletClient { snapshot, backend };

        assert_eq!(
            client
                .create_deposit_with_token(1_500, Some("different-token".to_string()))
                .await
                .unwrap_err(),
            "retry the pending deposit with its original token"
        );
        assert_eq!(posts.get(), 0);

        let result = client.create_deposit(1_500).await.unwrap();

        assert_eq!(posts.get(), 1);
        assert_eq!(result.statechain_id, "ab".repeat(16));
        let pending = &client.snapshot.pending_deposits[0];
        assert_eq!(pending.token_id, "retry-token");
        assert_eq!(pending.coin.user_pubkey, original_user_pubkey);
        assert_eq!(
            pending.coin.statechain_id.as_deref(),
            Some(result.statechain_id.as_str())
        );
        assert_eq!(
            pending.coin.aggregated_address.as_deref(),
            Some(result.deposit_address.as_str())
        );
    }

    struct DepositProtocolNonce {
        secret: Option<MusigSecNonce>,
        public: String,
    }

    #[derive(Clone)]
    struct DepositProtocolBackend {
        server_secret: SecretKey,
        signature_count: Rc<Cell<u64>>,
        nonces: Rc<RefCell<BTreeMap<String, DepositProtocolNonce>>>,
        partials: Rc<RefCell<BTreeMap<String, String>>>,
        checkpoints: Rc<RefCell<Vec<String>>>,
        funding_txid: String,
        funding_available: Rc<Cell<bool>>,
    }

    impl Default for DepositProtocolBackend {
        fn default() -> Self {
            Self {
                server_secret: SecretKey::from_secret_bytes([7; 32]).unwrap(),
                signature_count: Rc::new(Cell::new(0)),
                nonces: Rc::new(RefCell::new(BTreeMap::new())),
                partials: Rc::new(RefCell::new(BTreeMap::new())),
                checkpoints: Rc::new(RefCell::new(Vec::new())),
                funding_txid: Txid::from_slice(&[31; 32]).unwrap().to_string(),
                funding_available: Rc::new(Cell::new(true)),
            }
        }
    }

    impl DepositProtocolBackend {
        fn response(body: impl Into<String>) -> ApiResponse {
            ApiResponse {
                status: 200,
                body: body.into(),
            }
        }
    }

    impl Backend for DepositProtocolBackend {
        async fn get(&self, _base_url: &str, path: &str) -> Result<ApiResponse, String> {
            if path == "deposit/get_token" {
                return Ok(Self::response(
                    json!({
                        "token_id": "deposit-token",
                        "payment_method": "free",
                        "deposit_address": null,
                        "fee": 0,
                        "confirmation_target": 0
                    })
                    .to_string(),
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
                    json!({"mediantime": 1_000_000_000_u32}).to_string(),
                ));
            }
            if path.starts_with("address/") && path.ends_with("/utxo") {
                let utxos = if self.funding_available.get() {
                    json!([{
                        "txid": self.funding_txid,
                        "vout": 0,
                        "value": 1_500,
                        "status": {"confirmed": true, "block_height": 100}
                    }])
                } else {
                    json!([])
                };
                return Ok(Self::response(utxos.to_string()));
            }
            if path == "bip448-statechain/signature-count/deposit-statechain" {
                return Ok(Self::response(
                    json!({"sig_count": self.signature_count.get()}).to_string(),
                ));
            }
            Err(format!("unexpected deposit protocol GET {path}"))
        }

        async fn post_json(
            &self,
            _base_url: &str,
            path: &str,
            body: &str,
        ) -> Result<ApiResponse, String> {
            let response = match path {
                "deposit/init/pod" => json!({
                    "server_pubkey": PublicKey::from_secret_key(
                        &Secp256k1::new(),
                        &self.server_secret
                    ).to_string(),
                    "statechain_id": "deposit-statechain"
                })
                .to_string(),
                "bip448-statechain/sign/first" => {
                    let request: Bip448SignFirstRequestPayload =
                        serde_json::from_str(body).map_err(error_string)?;
                    if !self.nonces.borrow().contains_key(&request.signing_id) {
                        let keypair =
                            KeyPair::from_secret_key(&Secp256k1::new(), &self.server_secret);
                        let session_id: [u8; 32] = hex::decode(&request.signing_id)
                            .map_err(error_string)?
                            .try_into()
                            .map_err(|_| "deposit signing ID is not 32 bytes".to_string())?;
                        let (secret, public) = new_musig_nonce_pair(
                            &Secp256k1::new(),
                            MusigSessionId::assume_unique_per_nonce_gen(session_id),
                            None,
                            Some(self.server_secret),
                            keypair.public_key(),
                            None,
                            None,
                        )
                        .map_err(error_string)?;
                        self.nonces.borrow_mut().insert(
                            request.signing_id.clone(),
                            DepositProtocolNonce {
                                secret: Some(secret),
                                public: hex::encode(public.serialize()),
                            },
                        );
                    }
                    let public = self.nonces.borrow()[&request.signing_id].public.clone();
                    json!({"server_pubnonce": public}).to_string()
                }
                "bip448-statechain/sign/second" => {
                    let request: Bip448PartialSignatureRequestPayload =
                        serde_json::from_str(body).map_err(error_string)?;
                    let cached = self.partials.borrow().get(&request.signing_id).cloned();
                    if let Some(partial) = cached {
                        json!({"partial_sig": partial}).to_string()
                    } else {
                        let secret_nonce = self
                            .nonces
                            .borrow_mut()
                            .get_mut(&request.signing_id)
                            .and_then(|nonce| nonce.secret.take())
                            .ok_or_else(|| "deposit server nonce is missing".to_string())?;
                        let encoded_session: [u8; 133] = hex::decode(&request.session)
                            .map_err(error_string)?
                            .try_into()
                            .map_err(|_| "deposit session is not 133 bytes".to_string())?;
                        let keypair =
                            KeyPair::from_secret_key(&Secp256k1::new(), &self.server_secret);
                        let partial = MusigSession::from_slice(encoded_session)
                            .blinded_partial_sign_without_keyaggcoeff(
                                &Secp256k1::new(),
                                secret_nonce,
                                &keypair,
                                request.negate_seckey == 1,
                            )
                            .map_err(error_string)?;
                        let partial = hex::encode(partial.serialize());
                        self.partials
                            .borrow_mut()
                            .insert(request.signing_id, partial.clone());
                        self.signature_count
                            .set(self.signature_count.get().checked_add(1).unwrap());
                        json!({"partial_sig": partial}).to_string()
                    }
                }
                _ => return Err(format!("unexpected deposit protocol POST {path}")),
            };
            Ok(Self::response(response))
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
    async fn token_to_confirmed_deposit_runs_both_signing_rounds_and_restores() {
        let (mut snapshot, _) = recovery_fixture();
        snapshot.wallet.coins.clear();
        snapshot.wallet.activities.clear();
        snapshot.statechains.clear();
        snapshot.state_histories.clear();
        snapshot.funding_bindings.clear();
        snapshot.withdrawal_attempts.clear();
        snapshot.recovery_attempts.clear();
        snapshot.pending_deposits.clear();
        snapshot.pending_outgoing_transfer = None;
        snapshot.pending_incoming_transfer = None;
        let backend = DepositProtocolBackend::default();
        let observed = backend.clone();
        let mut client = WalletClient { snapshot, backend };

        let deposit = client.create_deposit(1_500).await.unwrap();
        assert_eq!(deposit.statechain_id, "deposit-statechain");
        assert_eq!(
            client.snapshot.pending_deposits[0].token_id,
            "deposit-token"
        );

        let sync = client.sync().await.unwrap();
        assert_eq!(sync.accepted_statechain_ids, vec!["deposit-statechain"]);
        assert!(sync.warnings.is_empty());
        assert!(client.snapshot.pending_deposits.is_empty());
        assert_eq!(observed.signature_count.get(), 1);
        let record = client.snapshot.statechain("deposit-statechain").unwrap();
        assert_eq!(record.latest_state_number, 1);
        assert_eq!(
            record.latest_state.signing_metadata.server_signature_count,
            1
        );
        assert!(client.snapshot.funding_bindings.iter().any(|binding| {
            binding.statechain_id == "deposit-statechain"
                && binding.binding_index == 0
                && binding.observation_status == "Confirmed"
        }));

        for checkpoint in observed.checkpoints.borrow().iter() {
            WalletClient::from_snapshot(checkpoint, observed.clone())
                .expect("every deposit protocol checkpoint must restore");
        }
    }
    #[tokio::test]
    async fn unused_deposit_addresses_remain_available_while_creating_more() {
        let (mut snapshot, _) = recovery_fixture();
        snapshot.wallet.coins.clear();
        snapshot.wallet.activities.clear();
        snapshot.statechains.clear();
        snapshot.state_histories.clear();
        snapshot.funding_bindings.clear();
        snapshot.withdrawal_attempts.clear();
        snapshot.recovery_attempts.clear();
        snapshot.pending_deposits.clear();
        snapshot.cancelled_deposits.clear();
        snapshot.pending_outgoing_transfer = None;
        snapshot.pending_incoming_transfer = None;

        let server_pubkey = SecretKey::from_secret_bytes([9; 32])
            .unwrap()
            .public_key(&Secp256k1::new())
            .to_string();
        let response = |statechain_id: &str| {
            serde_json::to_string(&DepositMsg1Response {
                server_pubkey: server_pubkey.clone(),
                statechain_id: statechain_id.to_string(),
            })
            .unwrap()
        };
        let posts = Rc::new(Cell::new(0));
        let backend = DepositRetryBackend {
            responses: vec![response("first-statechain"), response("second-statechain")],
            posts: posts.clone(),
        };
        let mut client = WalletClient { snapshot, backend };

        let first = client
            .create_deposit_with_token(1_500, Some("first-token".to_string()))
            .await
            .unwrap();
        let second = client
            .create_deposit_with_token(2_500, Some("second-token".to_string()))
            .await
            .unwrap();

        assert_eq!(posts.get(), 2);
        assert_ne!(first.deposit_address, second.deposit_address);
        assert_eq!(client.snapshot.pending_deposits.len(), 2);
        assert_eq!(
            client
                .snapshot
                .pending_deposits
                .iter()
                .map(|pending| (pending.amount, pending.coin.index))
                .collect::<Vec<_>>(),
            vec![(1_500, 0), (2_500, 1)]
        );
        assert!(client.snapshot.cancelled_deposits.is_empty());
        client.create_transfer_address().unwrap();
        assert_eq!(client.snapshot.wallet.coins[0].index, 2);
        let view = client.view().unwrap();
        assert_eq!(view.pending_deposits.len(), 2);

        let exported = client.export_snapshot().unwrap();
        let restored = WalletClient::from_snapshot(
            &exported,
            DepositRetryBackend {
                responses: Vec::new(),
                posts: Rc::new(Cell::new(0)),
            },
        )
        .unwrap();
        assert_eq!(restored.snapshot.pending_deposits.len(), 2);
    }

    #[derive(Clone, Default)]
    struct RecoveryBackend {
        posted_packages: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        checkpoints: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        mature: std::rc::Rc<std::cell::Cell<bool>>,
    }

    impl Backend for RecoveryBackend {
        async fn get(&self, _base_url: &str, path: &str) -> Result<ApiResponse, String> {
            if path == "blocks/tip/height" {
                return Ok(ApiResponse {
                    status: 200,
                    body: if self.mature.get() { "300" } else { "105" }.to_string(),
                });
            }
            if path.starts_with("tx/") && path.ends_with("/status") {
                return Ok(ApiResponse {
                    status: 200,
                    body: if self.mature.get() {
                        json!({"confirmed": true, "block_height": 157}).to_string()
                    } else {
                        json!({"confirmed": false}).to_string()
                    },
                });
            }
            if path.contains("/utxo") {
                return Ok(ApiResponse {
                    status: 200,
                    body: json!([
                        {
                            "txid": Txid::from_slice(&[2; 32]).unwrap().to_string(),
                            "vout": 0,
                            "value": 10_000,
                            "status": {"confirmed": true, "block_height": 100}
                        },
                        {
                            "txid": Txid::from_slice(&[3; 32]).unwrap().to_string(),
                            "vout": 1,
                            "value": 10_000,
                            "status": {"confirmed": true, "block_height": 100}
                        }
                    ])
                    .to_string(),
                });
            }
            Err(format!("unexpected test GET {path}"))
        }

        async fn post_json(
            &self,
            _base_url: &str,
            path: &str,
            body: &str,
        ) -> Result<ApiResponse, String> {
            assert_eq!(path, "txs/package");
            self.posted_packages.borrow_mut().push(body.to_string());
            Ok(ApiResponse {
                status: 200,
                body: r#"{"package_msg":"success"}"#.to_string(),
            })
        }

        fn checkpoint(&self, snapshot: &str) -> Result<(), String> {
            self.checkpoints.borrow_mut().push(snapshot.to_string());
            Ok(())
        }

        fn now_iso(&self) -> String {
            "time".to_string()
        }
    }

    fn recovery_fixture() -> (WalletSnapshot, String) {
        let settings = Settings {
            network: NETWORK.to_string(),
            block_explorerURL: Some("https://mutinynet.com".to_string()),
            torProxyHost: None,
            torProxyPort: None,
            torProxyControlPassword: None,
            torProxyControlPort: None,
            statechainEntityApi: DEFAULT_STATECHAIN_ENDPOINT.to_string(),
            torStatechainEntityApi: None,
            chainBackend: "esplora".to_string(),
            chainUrl: "https://mutinynet.com/api".to_string(),
            chainType: Some("esplora".to_string()),
            notifications: false,
            tutorials: false,
        };
        let mut wallet = Wallet {
            name: "browser".to_string(),
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            version: "test".to_string(),
            state_entity_endpoint: DEFAULT_STATECHAIN_ENDPOINT.to_string(),
            chain_backend: "esplora".to_string(),
            chain_endpoint: "https://mutinynet.com/api".to_string(),
            network: NETWORK.to_string(),
            blockheight: 100,
            activities: Vec::new(),
            coins: Vec::new(),
            settings,
        };
        let secp = Secp256k1::new();
        let mut coin = wallet.get_new_coin().unwrap();
        let server_secret = SecretKey::from_secret_bytes([7; 32]).unwrap();
        let server_pubkey = server_secret.public_key(&secp);
        let user_pubkey = PublicKey::from_str(&coin.user_pubkey).unwrap();
        coin.server_pubkey = Some(server_pubkey.to_string());
        coin.aggregated_pubkey = Some(user_pubkey.combine(&server_pubkey).unwrap().to_string());
        coin.statechain_protocol = Some(bip448_deposit::BIP448_COIN_PROTOCOL.to_string());
        coin.statechain_id = Some("statechain".to_string());
        coin.signed_statechain_id = Some("signed".to_string());
        coin.amount = Some(50_000);
        coin.status = CoinStatus::CONFIRMED;
        let deposit_address = bip448_deposit::create_deposit_address(&coin, NETWORK).unwrap();
        let funding_script = Address::from_str(&deposit_address.address)
            .unwrap()
            .require_network(Network::Signet)
            .unwrap()
            .script_pubkey();
        coin.aggregated_address = Some(deposit_address.address);
        let funding_transaction = Transaction {
            version: 2,
            lock_time: absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_slice(&[42; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![TxOut {
                value: 50_000,
                script_pubkey: funding_script,
            }],
        };
        coin.utxo_txid = Some(funding_transaction.txid().to_string());
        coin.utxo_vout = Some(0);

        let funding = Bip448FundingOutpoint {
            txid: coin.utxo_txid.clone().unwrap(),
            vout: 0,
            value_sats: 50_000,
        };
        let templates = bip448_deposit::build_deposit_templates(
            &coin,
            funding,
            absolute::LockTime::from_consensus(
                mercurylib::bip448_statechain::script::INITIAL_STATE_LOCKTIME_MIN,
            ),
            bip448_deposit::DEFAULT_BIP448_CHALLENGE_DELAY,
            NETWORK,
        )
        .unwrap();
        let user_secret = PrivateKey::from_wif(&coin.user_privkey).unwrap().inner;
        let user_keypair = KeyPair::from_secret_key(&secp, &user_secret);
        let server_keypair = KeyPair::from_secret_key(&secp, &server_secret);
        let message = Message::from(templates.artifacts.update_template_hash);
        let (client_secret_nonce, client_public_nonce) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen([1; 32]),
            None,
            Some(user_secret),
            user_keypair.public_key(),
            Some(message),
            None,
        )
        .unwrap();
        let (server_secret_nonce, server_public_nonce) = new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen([2; 32]),
            None,
            Some(server_secret),
            server_keypair.public_key(),
            None,
            None,
        )
        .unwrap();
        let blinding_factor = BlindingFactor::from_slice(&[4; 32]).unwrap();
        let aggregate_pubkey = user_pubkey.combine(&server_pubkey).unwrap();
        let session = CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::FundingUpdate,
            aggregate_pubkey,
            &client_public_nonce,
            &server_public_nonce,
            templates.artifacts.update_template_hash,
            &blinding_factor,
        )
        .unwrap();
        let client_partial = session
            .partial_sign_verified(
                &secp,
                CsfsSigningParticipant::Client,
                client_secret_nonce,
                &client_public_nonce,
                &user_keypair,
            )
            .unwrap();
        let server_partial = session
            .partial_sign_verified(
                &secp,
                CsfsSigningParticipant::Server,
                server_secret_nonce,
                &server_public_nonce,
                &server_keypair,
            )
            .unwrap();
        let signature = session
            .aggregate_and_verify(&[&client_partial, &server_partial])
            .unwrap();
        let record = bip448_deposit::build_deposit_record(
            "browser",
            "statechain",
            NETWORK,
            &templates,
            bip448_deposit::Bip448DepositSigningData {
                signing_id: "11".repeat(32),
                client_public_nonce: hex::encode(client_public_nonce.serialize()),
                server_public_nonce: hex::encode(server_public_nonce.serialize()),
                blinding_factor: hex::encode(blinding_factor.as_bytes()),
                update_signature: signature.to_string(),
                server_signature_count: 1,
            },
        )
        .unwrap();
        let history = crate::transfer::state_history_entry(
            &record.latest_state,
            PublicKey::from_str(&coin.user_pubkey)
                .unwrap()
                .x_only_public_key()
                .0,
        );
        let funding_binding = FundingBinding {
            statechain_id: record.statechain_id.clone(),
            binding_index: 0,
            txid: record.funding_outpoint.txid.clone(),
            vout: record.funding_outpoint.vout,
            value_sats: record.funding_outpoint.value_sats,
            observation_status: "Confirmed".to_string(),
            funding_height: Some(100),
            spend_txid: None,
            spend_height: None,
            owner_user_pubkey: history.owner_public_key.clone(),
            owner_state_number: record.latest_state_number,
        };
        let state_histories =
            std::collections::BTreeMap::from([("statechain".to_string(), vec![history])]);
        wallet.coins.push(coin);
        (
            WalletSnapshot {
                snapshot_version: SNAPSHOT_VERSION,
                wallet,
                deployment: DeploymentConfig::default(),
                statechains: vec![record],
                state_histories,
                pending_deposits: Vec::new(),
                cancelled_deposits: Vec::new(),
                recovery_attempts: Vec::new(),
                recovery_fee_utxos: Vec::new(),
                enclave_verification: None,
                enclave_verifications: Vec::new(),
                pending_outgoing_transfer: None,
                pending_incoming_transfer: None,
                enclave_runtime_proof: None,
                funding_bindings: vec![funding_binding],
                withdrawal_attempts: Vec::new(),
            },
            "statechain".to_string(),
        )
    }

    #[test]
    fn recovery_ready_browser_fixture_matches_protocol_builder() {
        let (snapshot, _) = recovery_fixture();
        let expected = serde_json::to_value(snapshot).unwrap();
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/recovery-ready.json");
        if std::env::var_os("UPDATE_WEB_WALLET_FIXTURES").is_some() {
            std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
            std::fs::write(
                &fixture_path,
                format!("{}\n", serde_json::to_string_pretty(&expected).unwrap()),
            )
            .unwrap();
        }
        let actual: Value =
            serde_json::from_str(&std::fs::read_to_string(fixture_path).unwrap()).unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn unilateral_exit_builds_and_replays_both_exact_packages() {
        let (snapshot, statechain_id) = recovery_fixture();
        let backend = RecoveryBackend::default();
        let posted = backend.posted_packages.clone();
        let mature = backend.mature.clone();
        let mut client = WalletClient { snapshot, backend };
        let below_minimum = client
            .submit_unilateral_exit(&statechain_id, "funding_update", 0.09)
            .await
            .unwrap_err();
        assert_eq!(below_minimum, "fee rate must be between 0.1 and 10 sat/vB");
        assert!(
            client.view().unwrap().coins[0].can_start_unilateral_exit,
            "the update button must surface a missing fee input as an actionable error"
        );

        let update = client
            .submit_unilateral_exit(&statechain_id, "funding_update", 0.1)
            .await
            .unwrap();
        assert_eq!(update.role, "funding_update");
        let first_wire: Vec<String> = serde_json::from_str(&posted.borrow()[0]).unwrap();
        assert_eq!(first_wire.len(), 2);
        assert_eq!(txid_from_hex(&first_wire[0]).unwrap(), update.parent_txid);

        let replay = client
            .submit_unilateral_exit(&statechain_id, "funding_update", 0.1)
            .await
            .unwrap();
        assert_eq!(replay.parent_txid, update.parent_txid);
        assert_eq!(posted.borrow()[0], posted.borrow()[1]);

        assert!(client
            .submit_unilateral_exit(&statechain_id, "settlement", 0.1)
            .await
            .unwrap_err()
            .contains("timelocked"));
        assert!(
            client.view().unwrap().coins[0].can_settle_unilateral_exit,
            "the settlement check must stay actionable while the saved view is stale"
        );
        mature.set(true);
        let settlement = client
            .submit_unilateral_exit(&statechain_id, "settlement", 0.1)
            .await
            .unwrap();
        assert_eq!(settlement.role, "settlement");
        assert_ne!(settlement.parent_txid, update.parent_txid);
        let settlement_wire: Vec<String> =
            serde_json::from_str(posted.borrow().last().unwrap()).unwrap();
        assert_eq!(settlement_wire.len(), 2);
        assert_eq!(
            txid_from_hex(&settlement_wire[0]).unwrap(),
            settlement.parent_txid
        );
    }

    #[derive(Clone)]
    struct ProofBackend {
        server_pubkey: String,
    }

    impl ProofBackend {
        fn assert_target(endpoint: &str, pcrs: [&str; 3], debug: bool) {
            assert_eq!(
                endpoint,
                "https://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io"
            );
            assert_eq!(pcrs, ["a".repeat(96), "b".repeat(96), "c".repeat(96)]);
            assert!(!debug);
        }
    }

    impl Backend for ProofBackend {
        async fn get(&self, _base_url: &str, path: &str) -> Result<ApiResponse, String> {
            Err(format!(
                "Mercury GET must not be used for enclave proof: {path}"
            ))
        }

        async fn post_json(
            &self,
            _base_url: &str,
            path: &str,
            _body: &str,
        ) -> Result<ApiResponse, String> {
            Err(format!(
                "Mercury POST must not be used for enclave proof: {path}"
            ))
        }

        async fn attest_enclave(
            &self,
            endpoint: &str,
            pcrs: [&str; 3],
            debug: bool,
        ) -> Result<(), String> {
            Self::assert_target(endpoint, pcrs, debug);
            Ok(())
        }

        async fn verify_enclave_statechain(
            &self,
            endpoint: &str,
            pcrs: [&str; 3],
            debug: bool,
            statechain_id: &str,
            challenge: &str,
        ) -> Result<ApiResponse, String> {
            Self::assert_target(endpoint, pcrs, debug);
            Ok(ApiResponse {
                status: 200,
                body: json!({
                    "statechain_id": statechain_id,
                    "challenge": challenge,
                    "server_pubkey": self.server_pubkey,
                })
                .to_string(),
            })
        }

        fn checkpoint(&self, _snapshot: &str) -> Result<(), String> {
            Ok(())
        }

        fn now_iso(&self) -> String {
            "verified-time".to_string()
        }
    }

    #[test]
    fn transfer_receive_address_and_recovery_history_survive_snapshot_roundtrip() {
        let (snapshot, _) = recovery_fixture();
        let mut client = WalletClient {
            snapshot,
            backend: RecoveryBackend::default(),
        };

        let result = client.create_transfer_address().unwrap();
        assert!(result.address.starts_with("tml1"));
        let serialized = client.export_snapshot().unwrap();
        let restored =
            WalletClient::from_snapshot(&serialized, RecoveryBackend::default()).unwrap();
        let view = restored.view().unwrap();

        assert_eq!(view.receive_addresses.len(), 1);
        assert_eq!(view.receive_addresses[0].address, result.address);
        assert_eq!(
            restored.snapshot.state_history("statechain").unwrap().len(),
            1
        );
    }

    #[test]
    fn coin_view_exposes_saved_unilateral_exit_transactions() {
        let (snapshot, _) = recovery_fixture();
        let expected_update = snapshot.statechains[0].latest_state.update_tx.clone();
        let expected_settlement = snapshot.statechains[0].latest_state.settlement_tx.clone();
        let client = WalletClient {
            snapshot,
            backend: RecoveryBackend::default(),
        };

        let view = client.view().unwrap();

        assert_eq!(view.coins[0].update_tx_hex, expected_update);
        assert_eq!(view.coins[0].settlement_tx_hex, expected_settlement);
    }

    #[test]
    fn mercury_relay_proofs_are_not_upgraded_to_direct_proofs() {
        let (snapshot, statechain_id) = recovery_fixture();
        let mut serialized = serde_json::to_value(snapshot).unwrap();
        serialized["enclave_runtime_proof"] = json!({
            "checkedAt": "untrusted-time",
            "endpoint": "wss://untrusted.enclaves.beta.enclavia.io",
            "mode": "production",
            "pcr0": "aa".repeat(48),
            "pcr1": "bb".repeat(48),
            "pcr2": "cc".repeat(48),
            "authentication": "bearer",
            "trustModel": "Verified by Mercury",
        });
        serialized["enclave_verification"] = json!({
            "statechainId": statechain_id,
            "verifiedAt": "untrusted-time",
            "challenge": "dd".repeat(32),
            "serverPubkey": "02".to_string() + &"11".repeat(32),
            "pcr0": "aa".repeat(48),
            "pcr1": "bb".repeat(48),
            "pcr2": "cc".repeat(48),
            "trustModel": "Mercury relay",
        });

        let restored = WalletClient::from_snapshot(
            &serde_json::to_string(&serialized).unwrap(),
            RecoveryBackend::default(),
        )
        .unwrap();

        assert!(restored.snapshot.enclave_runtime_proof.is_none());
        assert!(restored.snapshot.enclave_verification.is_none());
        assert!(restored.snapshot.enclave_verifications.is_empty());
    }

    #[tokio::test]
    async fn runtime_proof_persists_direct_sdk_measurements() {
        let (mut snapshot, _) = recovery_fixture();
        snapshot.deployment.enclavia_proxy_url =
            "https://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io".to_string();
        snapshot.deployment.expected_pcr0 = "aa".repeat(48);
        snapshot.deployment.expected_pcr1 = "bb".repeat(48);
        snapshot.deployment.expected_pcr2 = "cc".repeat(48);
        let server_pubkey = snapshot.wallet.coins[0].server_pubkey.clone().unwrap();
        let mut client = WalletClient {
            snapshot,
            backend: ProofBackend { server_pubkey },
        };

        let proof = client.verify_enclave_runtime().await.unwrap();

        assert_eq!(proof.mode, "production");
        assert_eq!(proof.pcr0, "aa".repeat(48));
        assert_eq!(proof.authentication, "attested Noise");
        assert!(proof.trust_model.contains("end-to-end Enclavia SDK"));
        assert_eq!(
            client
                .snapshot
                .enclave_runtime_proof
                .as_ref()
                .unwrap()
                .checked_at,
            "verified-time"
        );
    }

    #[tokio::test]
    async fn browser_proof_binds_wallet_key_challenge_and_all_pcrs() {
        let (mut snapshot, statechain_id) = recovery_fixture();
        snapshot.deployment.enclavia_proxy_url =
            "https://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io".to_string();
        snapshot.deployment.expected_pcr0 = "aa".repeat(48);
        snapshot.deployment.expected_pcr1 = "bb".repeat(48);
        snapshot.deployment.expected_pcr2 = "cc".repeat(48);
        let server_pubkey = snapshot.wallet.coins[0].server_pubkey.clone().unwrap();
        let mut client = WalletClient {
            snapshot,
            backend: ProofBackend { server_pubkey },
        };

        let verification = client.verify_enclave(&statechain_id).await.unwrap();
        assert_eq!(verification.statechain_id, statechain_id);
        assert_eq!(verification.challenge.len(), 64);
        assert_eq!(verification.pcr0, "aa".repeat(48));
        assert_eq!(verification.pcr1, "bb".repeat(48));
        assert_eq!(verification.pcr2, "cc".repeat(48));
        assert!(verification
            .trust_model
            .contains("Browser-direct Enclavia SDK"));
        assert!(verification
            .trust_model
            .contains("Mercury cannot read or forge"));
        assert!(client
            .snapshot
            .enclave_verifications
            .iter()
            .any(|proof| proof.statechain_id == statechain_id));
    }

    #[tokio::test]
    async fn browser_proof_rejects_a_different_enclave_server_share() {
        let (mut snapshot, statechain_id) = recovery_fixture();
        snapshot.deployment.enclavia_proxy_url =
            "https://00000000-0000-0000-0000-000000000000.enclaves.beta.enclavia.io".to_string();
        snapshot.deployment.expected_pcr0 = "aa".repeat(48);
        snapshot.deployment.expected_pcr1 = "bb".repeat(48);
        snapshot.deployment.expected_pcr2 = "cc".repeat(48);
        let wrong_server_pubkey = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array([42_u8; 32]).unwrap(),
        )
        .to_string();
        let mut client = WalletClient {
            snapshot,
            backend: ProofBackend {
                server_pubkey: wrong_server_pubkey,
            },
        };

        let error = client.verify_enclave(&statechain_id).await.unwrap_err();

        assert_eq!(error, "Lockbox key does not match the wallet server share");
        assert!(client.snapshot.enclave_verifications.is_empty());
    }
}
