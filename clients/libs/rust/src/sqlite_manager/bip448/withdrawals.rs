use std::{collections::HashMap, str::FromStr};

use anyhow::{anyhow, Result};
use chrono::Utc;
use mercurylib::wallet::{Activity, Coin, CoinStatus, Wallet};
use secp256k1::{PublicKey, XOnlyPublicKey};
use sqlx::{Pool, Sqlite};

use crate::bip448_funding::{
    self, Bip448BindingRole, Bip448BroadcastStatus, Bip448CloseBlockReason, Bip448CloseGate,
    Bip448CompletionStatus, Bip448FundingBinding, Bip448ObservationStatus, Bip448OwnershipStatus,
    Bip448TransferIntentActivityStatus, Bip448WithdrawalAttempt, Bip448WithdrawalAttemptKind,
    Bip448WithdrawalPhase,
};

use super::super::{
    canonical_block_hash, canonical_txid, canonical_wallet_json,
    validate_bip448_transfer_intent_lineage,
};
use super::{
    accepted_funding_script, accepted_record_and_history_on, begin_bip448_mutation_guard,
    get_bip448_statechain, list_bip448_funding_bindings_on, list_bip448_transfer_intents_on,
    list_bip448_withdrawal_attempts, list_bip448_withdrawal_attempts_on,
    require_selected_bip448_wallet_coin_on, row_to_bip448_attempt, row_to_bip448_binding,
    validate_selected_bip448_coin, Bip448MutationGuard, Bip448WalletCoinRequirement,
    BIP448_ATTEMPT_COLUMNS, BIP448_BINDING_COLUMNS,
};

impl Bip448MutationGuard {
    pub async fn withdrawal_signature_count_expectation(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
    ) -> Result<bip448_funding::Bip448SignatureCountExpectation> {
        let (record, _) =
            accepted_record_and_history_on(self.connection(), wallet_name, statechain_id).await?;
        let attempts =
            list_bip448_withdrawal_attempts_on(self.connection(), wallet_name, statechain_id)
                .await?;
        bip448_funding::bip448_signature_count_expectation(record.latest_state_number, &attempts)
    }

    pub async fn latch_creation_coin(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        expected_owner_user_pubkey: &str,
        expected_signed_statechain_id: &str,
    ) -> Result<Coin> {
        if !list_bip448_withdrawal_attempts_on(self.connection(), wallet_name, statechain_id)
            .await?
            .is_empty()
        {
            return Err(anyhow!(
                "BIP448 withdrawal attempt blocks lightning-latch creation"
            ));
        }
        let intents =
            list_bip448_transfer_intents_on(self.connection(), wallet_name, statechain_id).await?;
        if validate_bip448_transfer_intent_lineage(&intents)?.is_some() {
            return Err(anyhow!(
                "active BIP448 transfer intent blocks lightning-latch creation"
            ));
        }
        let wallet_json = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name = $1",
        )
        .bind(wallet_name)
        .fetch_optional(self.connection())
        .await?
        .ok_or_else(|| anyhow!("BIP448 lightning-latch wallet is missing"))?;
        let wallet: Wallet = serde_json::from_str(&wallet_json)?;
        if wallet.name != wallet_name {
            return Err(anyhow!("BIP448 lightning-latch wallet identity changed"));
        }
        let mut matches = wallet.coins.iter().filter_map(|coin| {
            if coin.statechain_id.as_deref() != Some(statechain_id)
                || coin.signed_statechain_id.as_deref() != Some(expected_signed_statechain_id)
            {
                return None;
            }
            let owner = PublicKey::from_str(&coin.user_pubkey)
                .ok()?
                .x_only_public_key()
                .0
                .to_string();
            (owner == expected_owner_user_pubkey).then(|| coin.clone())
        });
        let coin = matches.next().ok_or_else(|| {
            anyhow!("BIP448 lightning-latch current-owner Coin changed before creation")
        })?;
        if matches.next().is_some() {
            return Err(anyhow!(
                "multiple BIP448 lightning-latch current-owner Coins match"
            ));
        }
        Ok(coin)
    }
    pub async fn reconcile_withdrawal_attempt_observations(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        bindings: &[Bip448FundingBinding],
    ) -> Result<Vec<Bip448WithdrawalAttempt>> {
        let by_index = bindings
            .iter()
            .map(|binding| (binding.binding_index, binding))
            .collect::<HashMap<_, _>>();
        let attempts =
            list_bip448_withdrawal_attempts_on(self.connection(), wallet_name, statechain_id)
                .await?;
        for attempt in &attempts {
            if attempt.phase != Bip448WithdrawalPhase::Signed {
                continue;
            }
            let binding = by_index.get(&attempt.binding_index).ok_or_else(|| {
                anyhow!("BIP448 signed attempt lost its funding binding during synchronization")
            })?;
            if binding.txid != attempt.source_txid
                || binding.vout != attempt.source_vout
                || binding.value_sats != attempt.source_value_sats
                || binding.script_pubkey != attempt.source_script_pubkey
            {
                return Err(anyhow!(
                    "BIP448 signed attempt source changed during synchronization"
                ));
            }
            let expected_txid = attempt
                .txid
                .as_deref()
                .ok_or_else(|| anyhow!("BIP448 Signed attempt has no transaction ID"))?;
            let next = match binding.observation_status {
                Bip448ObservationStatus::SpentMempool
                | Bip448ObservationStatus::SpentUnconfirmed
                    if binding.spend_txid.as_deref() == Some(expected_txid) =>
                {
                    Bip448BroadcastStatus::Accepted
                }
                Bip448ObservationStatus::SpentConfirmed
                    if binding.spend_txid.as_deref() == Some(expected_txid) =>
                {
                    Bip448BroadcastStatus::Confirmed
                }
                Bip448ObservationStatus::SpentConfirmed => Bip448BroadcastStatus::Conflicted,
                Bip448ObservationStatus::SpentMempool
                | Bip448ObservationStatus::SpentUnconfirmed => Bip448BroadcastStatus::Conflicting,
                _ => Bip448BroadcastStatus::NeedsRebroadcast,
            };
            if next == attempt.broadcast_status {
                continue;
            }
            if !legal_broadcast_transition(attempt.broadcast_status, next) {
                return Err(anyhow!(
                    "illegal BIP448 synchronization broadcast-status transition"
                ));
            }
            let updated = sqlx::query(
                "UPDATE bip448_withdrawal_attempts SET broadcast_status=$1,\
                 updated_at=CURRENT_TIMESTAMP WHERE wallet_name=$2 AND statechain_id=$3 \
                 AND binding_index=$4 AND signing_id=$5 AND phase='Signed' \
                 AND broadcast_status=$6 AND txid=$7",
            )
            .bind(next.as_str())
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(i64::from(attempt.binding_index))
            .bind(&attempt.signing_id)
            .bind(attempt.broadcast_status.as_str())
            .bind(expected_txid)
            .execute(self.connection())
            .await?;
            if updated.rows_affected() != 1 {
                return Err(anyhow!("BIP448 attempt observation compare-and-set lost"));
            }
        }
        list_bip448_withdrawal_attempts_on(self.connection(), wallet_name, statechain_id).await
    }

    pub async fn update_withdrawal_broadcast_status(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        binding_index: u32,
        signing_id: &str,
        expected: Bip448BroadcastStatus,
        next: Bip448BroadcastStatus,
    ) -> Result<Bip448WithdrawalAttempt> {
        if !legal_broadcast_transition(expected, next) {
            return Err(anyhow!("illegal BIP448 broadcast-status regression"));
        }
        let result = sqlx::query(
            "UPDATE bip448_withdrawal_attempts SET broadcast_status = $1, \
             updated_at = CURRENT_TIMESTAMP WHERE wallet_name = $2 AND statechain_id = $3 \
             AND binding_index = $4 AND signing_id = $5 AND phase = 'Signed' \
             AND broadcast_status = $6",
        )
        .bind(next.as_str())
        .bind(wallet_name)
        .bind(statechain_id)
        .bind(i64::from(binding_index))
        .bind(signing_id)
        .bind(expected.as_str())
        .execute(self.connection())
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!("BIP448 broadcast-status compare-and-set lost"));
        }
        self.exact_attempt(wallet_name, statechain_id, binding_index)
            .await?
            .ok_or_else(|| anyhow!("BIP448 attempt disappeared after broadcast update"))
    }

    pub(super) async fn exact_binding(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        binding_index: u32,
    ) -> Result<Option<Bip448FundingBinding>> {
        let query = format!(
            "SELECT {BIP448_BINDING_COLUMNS} FROM bip448_funding_bindings \
             WHERE wallet_name = $1 AND statechain_id = $2 AND binding_index = $3"
        );
        sqlx::query(&query)
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(i64::from(binding_index))
            .fetch_optional(self.connection())
            .await?
            .map(row_to_bip448_binding)
            .transpose()
    }

    async fn exact_attempt(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        binding_index: u32,
    ) -> Result<Option<Bip448WithdrawalAttempt>> {
        let query = format!(
            "SELECT {BIP448_ATTEMPT_COLUMNS} FROM bip448_withdrawal_attempts \
             WHERE wallet_name = $1 AND statechain_id = $2 AND binding_index = $3"
        );
        sqlx::query(&query)
            .bind(wallet_name)
            .bind(statechain_id)
            .bind(i64::from(binding_index))
            .fetch_optional(self.connection())
            .await?
            .map(row_to_bip448_attempt)
            .transpose()
    }

    async fn ensure_attempt_insert_blockers(
        &mut self,
        attempt: &Bip448WithdrawalAttempt,
    ) -> Result<()> {
        let intents = list_bip448_transfer_intents_on(
            self.connection(),
            &attempt.wallet_name,
            &attempt.statechain_id,
        )
        .await?;
        if !intents.is_empty() {
            validate_bip448_transfer_intent_lineage(&intents)?;
            return Err(anyhow!(
                "active BIP448 transfer intent blocks withdrawal signing"
            ));
        }
        let pending = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_pending_transfer_signings \
             WHERE wallet_name = $1 AND statechain_id = $2",
        )
        .bind(&attempt.wallet_name)
        .bind(&attempt.statechain_id)
        .fetch_one(self.connection())
        .await?;
        if pending != 0 {
            return Err(anyhow!(
                "pending BIP448 transfer signing blocks withdrawal signing"
            ));
        }
        let messages = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bip448_transfer_messages \
             WHERE wallet_name = $1 AND statechain_id = $2",
        )
        .bind(&attempt.wallet_name)
        .bind(&attempt.statechain_id)
        .fetch_one(self.connection())
        .await?;
        if messages != 0 {
            return Err(anyhow!(
                "outgoing BIP448 transfer message blocks withdrawal signing"
            ));
        }
        let wallet_json = sqlx::query_scalar::<_, String>(
            "SELECT wallet_json FROM wallet WHERE wallet_name = $1",
        )
        .bind(&attempt.wallet_name)
        .fetch_optional(self.connection())
        .await?;
        if let Some(wallet_json) = wallet_json {
            let wallet: Wallet = serde_json::from_str(&wallet_json)?;
            if wallet.coins.iter().any(|coin| {
                coin.statechain_id.as_deref() == Some(attempt.statechain_id.as_str())
                    && coin.status == mercurylib::wallet::CoinStatus::IN_TRANSFER
            }) {
                return Err(anyhow!("IN_TRANSFER BIP448 Coin blocks withdrawal signing"));
            }
        }
        Ok(())
    }

    async fn require_attempt_binding_and_owner_identity(
        &mut self,
        attempt: &Bip448WithdrawalAttempt,
    ) -> Result<Bip448FundingBinding> {
        let (record, history) = accepted_record_and_history_on(
            self.connection(),
            &attempt.wallet_name,
            &attempt.statechain_id,
        )
        .await?;
        let accepted_owner = history
            .get(
                usize::try_from(record.latest_state_number)?
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
            )
            .ok_or_else(|| anyhow!("BIP448 accepted owner history is missing"))?;
        if record.wallet_name != attempt.wallet_name
            || record.statechain_id != attempt.statechain_id
            || record.latest_state_number != attempt.owner_state_number
            || accepted_owner.owner_public_key != attempt.owner_user_pubkey
            || accepted_funding_script(&record)? != attempt.source_script_pubkey
        {
            return Err(anyhow!(
                "BIP448 withdrawal attempt does not match accepted owner history"
            ));
        }
        let binding = self
            .exact_binding(
                &attempt.wallet_name,
                &attempt.statechain_id,
                attempt.binding_index,
            )
            .await?
            .ok_or_else(|| anyhow!("BIP448 withdrawal attempt binding is missing"))?;
        if binding.ownership_status != Bip448OwnershipStatus::Current
            || binding.owner_user_pubkey != attempt.owner_user_pubkey
            || binding.owner_state_number != attempt.owner_state_number
            || binding.txid != attempt.source_txid
            || binding.vout != attempt.source_vout
            || binding.value_sats != attempt.source_value_sats
            || binding.script_pubkey != attempt.source_script_pubkey
            || match binding.role {
                Bip448BindingRole::Canonical => {
                    attempt.attempt_kind != Bip448WithdrawalAttemptKind::Canonical
                }
                Bip448BindingRole::Duplicate => {
                    attempt.attempt_kind != Bip448WithdrawalAttemptKind::Duplicate
                }
            }
        {
            return Err(anyhow!(
                "BIP448 withdrawal attempt does not match its current-owner binding"
            ));
        }
        Ok(binding)
    }

    async fn require_confirmed_canonical_owner_coin(
        &mut self,
        attempt: &Bip448WithdrawalAttempt,
    ) -> Result<()> {
        let (record, history) = accepted_record_and_history_on(
            self.connection(),
            &attempt.wallet_name,
            &attempt.statechain_id,
        )
        .await?;
        let accepted_owner = history
            .get(
                usize::try_from(record.latest_state_number)?
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
            )
            .ok_or_else(|| anyhow!("BIP448 accepted owner history is missing"))?;
        let owner = XOnlyPublicKey::from_str(&accepted_owner.owner_public_key)?;
        require_selected_bip448_wallet_coin_on(
            self.connection(),
            &record,
            owner,
            Bip448WalletCoinRequirement::ConfirmedCanonicalAttempt,
        )
        .await
    }

    pub async fn insert_withdrawal_attempt_if_absent(
        &mut self,
        attempt: &Bip448WithdrawalAttempt,
    ) -> Result<Bip448WithdrawalAttempt> {
        bip448_funding::validate_withdrawal_attempt(attempt)?;
        if attempt.phase != Bip448WithdrawalPhase::Prepared
            || attempt.broadcast_status != Bip448BroadcastStatus::NotBroadcast
        {
            return Err(anyhow!("new BIP448 withdrawal attempt must be Prepared"));
        }
        if let Some(existing) = self
            .exact_attempt(
                &attempt.wallet_name,
                &attempt.statechain_id,
                attempt.binding_index,
            )
            .await?
        {
            if !bip448_funding::withdrawal_attempt_immutable_eq(&existing, attempt) {
                return Err(anyhow!(
                    "BIP448 withdrawal attempt conflicts with immutable persisted identity"
                ));
            }
            self.require_attempt_binding_and_owner_identity(&existing)
                .await?;
            return Ok(existing);
        }

        self.ensure_attempt_insert_blockers(attempt).await?;
        let binding = self
            .require_attempt_binding_and_owner_identity(attempt)
            .await?;
        if binding.observation_status != Bip448ObservationStatus::Confirmed {
            return Err(anyhow!(
                "new BIP448 withdrawal attempt requires a Confirmed binding"
            ));
        }
        if attempt.attempt_kind == Bip448WithdrawalAttemptKind::Canonical {
            self.require_confirmed_canonical_owner_coin(attempt).await?;
            let closing_tip_height = attempt
                .closing_tip_height
                .ok_or_else(|| anyhow!("canonical BIP448 attempt closing tip is missing"))?;
            let closing_tip_hash = attempt
                .closing_tip_hash
                .as_deref()
                .ok_or_else(|| anyhow!("canonical BIP448 attempt closing tip is missing"))?;
            let cursor_match = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bip448_scan_cursors WHERE wallet_name = $1 \
                 AND script_pubkey = $2 AND coverage_start_height = 0 \
                 AND last_scanned_height = $3 AND last_scanned_block_hash = $4",
            )
            .bind(&attempt.wallet_name)
            .bind(&attempt.source_script_pubkey)
            .bind(i64::from(closing_tip_height))
            .bind(closing_tip_hash)
            .fetch_one(self.connection())
            .await?;
            if cursor_match != 1 {
                return Err(anyhow!(
                    "canonical BIP448 close tip is not the current height-0 scan"
                ));
            }
            let bindings = list_bip448_funding_bindings_on(
                self.connection(),
                &attempt.wallet_name,
                &attempt.statechain_id,
            )
            .await?;
            let attempts = list_bip448_withdrawal_attempts_on(
                self.connection(),
                &attempt.wallet_name,
                &attempt.statechain_id,
            )
            .await?;
            match bip448_funding::evaluate_bip448_close_gate(&bindings, &attempts)? {
                Bip448CloseGate::Ready {
                    closing_bindings_json,
                    ..
                } if Some(closing_bindings_json.as_str())
                    == attempt.closing_bindings_json.as_deref() => {}
                Bip448CloseGate::Ready { .. } => {
                    return Err(anyhow!(
                        "canonical BIP448 close snapshot does not match the exact gate rows"
                    ));
                }
                Bip448CloseGate::Blocked { .. } => {
                    return Err(anyhow!(
                        "current BIP448 duplicate rows block canonical attempt insertion"
                    ));
                }
            }
        }
        let attempts = list_bip448_withdrawal_attempts_on(
            self.connection(),
            &attempt.wallet_name,
            &attempt.statechain_id,
        )
        .await?;
        if attempt.attempt_kind == Bip448WithdrawalAttemptKind::Duplicate
            && attempts.iter().any(|row| row.binding_index == 0)
        {
            return Err(anyhow!(
                "BIP448 address is retired by a canonical withdrawal attempt"
            ));
        }
        for prior in &attempts {
            if prior.phase != Bip448WithdrawalPhase::Signed {
                return Err(anyhow!("another BIP448 withdrawal signing is active"));
            }
            if !matches!(
                prior.broadcast_status,
                Bip448BroadcastStatus::Accepted
                    | Bip448BroadcastStatus::Confirmed
                    | Bip448BroadcastStatus::Conflicted
            ) {
                return Err(anyhow!(
                    "prior BIP448 withdrawal bytes require reconciliation"
                ));
            }
            if prior.broadcast_status == Bip448BroadcastStatus::Conflicted {
                let prior_binding = self
                    .exact_binding(
                        &prior.wallet_name,
                        &prior.statechain_id,
                        prior.binding_index,
                    )
                    .await?
                    .ok_or_else(|| anyhow!("conflicted BIP448 attempt binding is missing"))?;
                if prior_binding.observation_status != Bip448ObservationStatus::SpentConfirmed
                    || prior_binding.spend_txid.is_none()
                    || prior_binding.spend_txid == prior.txid
                {
                    return Err(anyhow!(
                        "prior BIP448 conflict is not target-confirmed by a different spender"
                    ));
                }
            }
        }

        let result = sqlx::query(
            "INSERT INTO bip448_withdrawal_attempts (\
                wallet_name, statechain_id, binding_index, attempt_kind, owner_user_pubkey, \
                owner_state_number, source_txid, source_vout, source_value_sats, \
                source_script_pubkey, destination_address, destination_script_pubkey, \
                fee_rate_sat_per_vbyte, fee_sats, lock_time, unsigned_tx_hex, signing_id, \
                signed_statechain_id, sign_first_payload_json, client_secret_nonce, \
                client_public_nonce, blinding_factor, server_public_nonce, message_hex, \
                output_pubkey, client_partial_sig, encoded_session, sign_second_payload_json, \
                server_partial_sig, aggregate_signature, signed_tx_hex, txid, phase, \
                broadcast_status, completion_status, closing_tip_height, closing_tip_hash, \
                closing_bindings_json\
             ) VALUES (\
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,\
                $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38\
             )",
        )
        .bind(&attempt.wallet_name)
        .bind(&attempt.statechain_id)
        .bind(i64::from(attempt.binding_index))
        .bind(attempt.attempt_kind.as_str())
        .bind(&attempt.owner_user_pubkey)
        .bind(i64::from(attempt.owner_state_number))
        .bind(&attempt.source_txid)
        .bind(i64::from(attempt.source_vout))
        .bind(i64::try_from(attempt.source_value_sats)?)
        .bind(&attempt.source_script_pubkey)
        .bind(&attempt.destination_address)
        .bind(&attempt.destination_script_pubkey)
        .bind(attempt.fee_rate_sat_per_vbyte)
        .bind(i64::try_from(attempt.fee_sats)?)
        .bind(i64::from(attempt.lock_time))
        .bind(&attempt.unsigned_tx_hex)
        .bind(&attempt.signing_id)
        .bind(&attempt.signed_statechain_id)
        .bind(&attempt.sign_first_payload_json)
        .bind(&attempt.client_secret_nonce)
        .bind(&attempt.client_public_nonce)
        .bind(&attempt.blinding_factor)
        .bind(&attempt.server_public_nonce)
        .bind(&attempt.message_hex)
        .bind(&attempt.output_pubkey)
        .bind(&attempt.client_partial_sig)
        .bind(&attempt.encoded_session)
        .bind(&attempt.sign_second_payload_json)
        .bind(&attempt.server_partial_sig)
        .bind(&attempt.aggregate_signature)
        .bind(&attempt.signed_tx_hex)
        .bind(&attempt.txid)
        .bind(attempt.phase.as_str())
        .bind(attempt.broadcast_status.as_str())
        .bind(attempt.completion_status.as_str())
        .bind(attempt.closing_tip_height.map(i64::from))
        .bind(&attempt.closing_tip_hash)
        .bind(&attempt.closing_bindings_json)
        .execute(self.connection())
        .await?;
        if result.rows_affected() != 1 {
            return Err(anyhow!(
                "BIP448 withdrawal attempt insert affected an unexpected row count"
            ));
        }
        self.exact_attempt(
            &attempt.wallet_name,
            &attempt.statechain_id,
            attempt.binding_index,
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 withdrawal attempt disappeared after insertion"))
    }

    pub async fn persist_canonical_withdrawal_wallet(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        signing_id: &str,
    ) -> Result<Wallet> {
        let attempt = self
            .exact_attempt(wallet_name, statechain_id, 0)
            .await?
            .ok_or_else(|| anyhow!("canonical BIP448 withdrawal attempt is missing"))?;
        if attempt.signing_id != signing_id
            || attempt.attempt_kind != Bip448WithdrawalAttemptKind::Canonical
            || attempt.phase != Bip448WithdrawalPhase::Signed
            || !matches!(
                attempt.broadcast_status,
                Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
            )
        {
            return Err(anyhow!(
                "canonical BIP448 wallet persistence requires exact accepted signed bytes"
            ));
        }
        self.require_attempt_binding_and_owner_identity(&attempt)
            .await?;
        let (record, history) =
            accepted_record_and_history_on(self.connection(), wallet_name, statechain_id).await?;
        let accepted_owner = history
            .get(
                usize::try_from(record.latest_state_number)?
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("BIP448 accepted state number must be positive"))?,
            )
            .ok_or_else(|| anyhow!("BIP448 accepted owner history is missing"))?;
        if accepted_owner.owner_public_key != attempt.owner_user_pubkey {
            return Err(anyhow!(
                "canonical BIP448 wallet owner changed before persistence"
            ));
        }

        let raw_wallet =
            sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name=$1")
                .bind(wallet_name)
                .fetch_optional(self.connection())
                .await?
                .ok_or_else(|| anyhow!("canonical BIP448 withdrawal wallet is missing"))?;
        let mut wallet: Wallet = serde_json::from_str(&raw_wallet)?;
        if wallet.name != wallet_name || wallet.network != record.network {
            return Err(anyhow!(
                "canonical BIP448 withdrawal wallet identity changed"
            ));
        }
        let owner = XOnlyPublicKey::from_str(&attempt.owner_user_pubkey)?;
        let matches = wallet
            .coins
            .iter()
            .enumerate()
            .filter_map(|(index, coin)| {
                let coin_owner = PublicKey::from_str(&coin.user_pubkey)
                    .ok()?
                    .x_only_public_key()
                    .0;
                (coin.statechain_id.as_deref() == Some(statechain_id) && coin_owner == owner)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let [coin_index] = matches.as_slice() else {
            return Err(anyhow!(
                "canonical BIP448 withdrawal requires one exact wallet Coin"
            ));
        };
        let txid = attempt
            .txid
            .as_deref()
            .ok_or_else(|| anyhow!("canonical BIP448 signed attempt has no txid"))?;
        let server_public_nonce = attempt
            .server_public_nonce
            .as_deref()
            .ok_or_else(|| anyhow!("canonical BIP448 signed attempt has no server nonce"))?;
        let activity_amount;
        {
            let coin = wallet
                .coins
                .get_mut(*coin_index)
                .ok_or_else(|| anyhow!("canonical BIP448 withdrawal Coin disappeared"))?;
            match coin.status {
                CoinStatus::CONFIRMED => {
                    validate_selected_bip448_coin(
                        coin,
                        &record,
                        owner,
                        Bip448WalletCoinRequirement::ConfirmedCanonicalAttempt,
                    )?;
                    coin.secret_nonce = Some(attempt.client_secret_nonce.clone());
                    coin.public_nonce = Some(attempt.client_public_nonce.clone());
                    coin.server_public_nonce = Some(server_public_nonce.to_owned());
                    coin.blinding_factor = Some(attempt.blinding_factor.clone());
                    coin.tx_withdraw = Some(txid.to_owned());
                    coin.withdrawal_address = Some(attempt.destination_address.clone());
                    coin.status = CoinStatus::WITHDRAWING;
                }
                CoinStatus::WITHDRAWING | CoinStatus::WITHDRAWN => {
                    validate_selected_bip448_coin(
                        coin,
                        &record,
                        owner,
                        Bip448WalletCoinRequirement::PassiveBindingSync,
                    )?;
                    if coin.secret_nonce.as_deref() != Some(attempt.client_secret_nonce.as_str())
                        || coin.public_nonce.as_deref()
                            != Some(attempt.client_public_nonce.as_str())
                        || coin.server_public_nonce.as_deref() != Some(server_public_nonce)
                        || coin.blinding_factor.as_deref() != Some(attempt.blinding_factor.as_str())
                        || coin.tx_withdraw.as_deref() != Some(txid)
                        || coin.withdrawal_address.as_deref()
                            != Some(attempt.destination_address.as_str())
                    {
                        return Err(anyhow!(
                            "canonical BIP448 withdrawal wallet replay identity changed"
                        ));
                    }
                }
                _ => {
                    return Err(anyhow!(
                        "canonical BIP448 withdrawal wallet has an illegal Coin status"
                    ));
                }
            }
            activity_amount = coin
                .amount
                .ok_or_else(|| anyhow!("canonical BIP448 withdrawal Coin has no amount"))?;
            if u64::from(activity_amount) != record.amount_sats {
                return Err(anyhow!(
                    "canonical BIP448 withdrawal activity amount changed"
                ));
            }
        }

        let matching_activities = wallet
            .activities
            .iter()
            .filter(|activity| activity.utxo == txid)
            .collect::<Vec<_>>();
        match matching_activities.as_slice() {
            [] => wallet.activities.push(Activity {
                utxo: txid.to_owned(),
                amount: activity_amount,
                action: "Withdraw".to_owned(),
                date: Utc::now().to_rfc3339(),
            }),
            [activity] if activity.amount == activity_amount && activity.action == "Withdraw" => {}
            _ => {
                return Err(anyhow!(
                    "canonical BIP448 withdrawal activity replay identity changed"
                ));
            }
        }

        let replacement = canonical_wallet_json(&wallet)?;
        let updated =
            sqlx::query("UPDATE wallet SET wallet_json=$1 WHERE wallet_name=$2 AND wallet_json=$3")
                .bind(replacement)
                .bind(wallet_name)
                .bind(&raw_wallet)
                .execute(self.connection())
                .await?;
        if updated.rows_affected() != 1 {
            return Err(anyhow!(
                "canonical BIP448 withdrawal wallet compare-and-set lost"
            ));
        }
        Ok(wallet)
    }

    async fn validate_canonical_completion_request(
        &mut self,
        wallet_name: &str,
        statechain_id: &str,
        signing_id: &str,
    ) -> Result<Bip448WithdrawalAttempt> {
        validate_canonical_close_snapshot_on(self, wallet_name, statechain_id, signing_id).await?;
        let canonical = self
            .exact_attempt(wallet_name, statechain_id, 0)
            .await?
            .ok_or_else(|| anyhow!("canonical BIP448 completion attempt is missing"))?;
        if canonical.phase != Bip448WithdrawalPhase::Signed
            || canonical.completion_status != Bip448CompletionStatus::CloseArmed
            || !matches!(
                canonical.broadcast_status,
                Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
            )
        {
            return Err(anyhow!(
                "canonical BIP448 completion requires exact accepted CloseArmed bytes"
            ));
        }
        self.require_attempt_binding_and_owner_identity(&canonical)
            .await?;
        Ok(canonical)
    }
}

/// Runs only the bounded canonical completion operation after the final
/// guarded snapshot reload. Timeout and callback errors explicitly roll back
/// the read-only fence before the caller performs journal-first reconciliation;
/// cancellation or unwinding retains SQLx's rollback-on-drop behavior.
pub(crate) async fn with_bip448_canonical_completion_fence<T, F, Fut>(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
    completion_timeout: std::time::Duration,
    completion: F,
) -> Result<(Bip448WithdrawalAttempt, Result<T>)>
where
    F: FnOnce(Bip448WithdrawalAttempt) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let canonical = guard
        .validate_canonical_completion_request(wallet_name, statechain_id, signing_id)
        .await?;
    let completion_result = match tokio::time::timeout(
        completion_timeout,
        completion(canonical.clone()),
    )
    .await
    {
        Ok(Ok(value)) => match guard.commit().await {
            Ok(()) => Ok(value),
            Err(error) => Err(error.context(
                "BIP448 canonical completion returned, but releasing its mutation fence failed",
            )),
        },
        Ok(Err(error)) => match guard.rollback().await {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(error.context(format!(
                "BIP448 canonical completion failed and its mutation-fence rollback also failed: {rollback_error}"
            ))),
        },
        Err(_) => {
            let timeout_error = anyhow!(
                "BIP448 canonical completion timed out after {} seconds",
                completion_timeout.as_secs_f64()
            );
            match guard.rollback().await {
                Ok(()) => Err(timeout_error),
                Err(rollback_error) => Err(timeout_error.context(format!(
                    "BIP448 canonical completion timed out and its mutation-fence rollback also failed: {rollback_error}"
                ))),
            }
        }
    };
    Ok((canonical, completion_result))
}

pub async fn insert_bip448_withdrawal_attempt_if_absent(
    pool: &Pool<Sqlite>,
    attempt: &Bip448WithdrawalAttempt,
) -> Result<Bip448WithdrawalAttempt> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let persisted = guard.insert_withdrawal_attempt_if_absent(attempt).await?;
    guard.commit().await?;
    Ok(persisted)
}

pub async fn persist_bip448_canonical_withdrawal_wallet(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
) -> Result<Wallet> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let wallet = guard
        .persist_canonical_withdrawal_wallet(wallet_name, statechain_id, signing_id)
        .await?;
    guard.commit().await?;
    Ok(wallet)
}

async fn update_attempt_phase_on(
    guard: &mut Bip448MutationGuard,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    expected_phase: Bip448WithdrawalPhase,
    next_phase: Bip448WithdrawalPhase,
) -> Result<Bip448WithdrawalAttempt> {
    if !matches!(
        (expected_phase, next_phase),
        (
            Bip448WithdrawalPhase::Prepared,
            Bip448WithdrawalPhase::FirstArmed
        ) | (
            Bip448WithdrawalPhase::NonceStored,
            Bip448WithdrawalPhase::SecondArmed
        )
    ) {
        return Err(anyhow!("illegal BIP448 withdrawal phase transition"));
    }
    let attempt = guard
        .exact_attempt(wallet_name, statechain_id, binding_index)
        .await?
        .ok_or_else(|| anyhow!("BIP448 withdrawal attempt is missing"))?;
    if attempt.signing_id != signing_id || attempt.phase != expected_phase {
        return Err(anyhow!("stale BIP448 withdrawal phase identity"));
    }
    let binding = guard
        .require_attempt_binding_and_owner_identity(&attempt)
        .await?;
    match (expected_phase, next_phase) {
        (Bip448WithdrawalPhase::Prepared, Bip448WithdrawalPhase::FirstArmed)
            if binding.observation_status != Bip448ObservationStatus::Confirmed =>
        {
            return Err(anyhow!(
                "BIP448 Prepared attempt source is not target-confirmed and unspent"
            ));
        }
        (Bip448WithdrawalPhase::NonceStored, Bip448WithdrawalPhase::SecondArmed) => {
            let prospective_txid = bip448_funding::expected_withdrawal_txid(&attempt)?;
            let exact_confirmed_conflict = binding.observation_status
                == Bip448ObservationStatus::SpentConfirmed
                && binding
                    .spend_txid
                    .as_deref()
                    .is_some_and(|spend_txid| spend_txid != prospective_txid.as_str());
            if binding.observation_status != Bip448ObservationStatus::Confirmed
                && !exact_confirmed_conflict
            {
                return Err(anyhow!(
                    "BIP448 NonceStored attempt must wait for an unspent source or a target-confirmed conflict"
                ));
            }
        }
        _ => {}
    }
    if binding_index == 0 && next_phase == Bip448WithdrawalPhase::SecondArmed {
        validate_canonical_close_snapshot_on(guard, wallet_name, statechain_id, signing_id).await?;
    }
    let result = sqlx::query(
        "UPDATE bip448_withdrawal_attempts SET phase = $1, updated_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $2 AND statechain_id = $3 AND binding_index = $4 \
           AND signing_id = $5 AND phase = $6 AND broadcast_status = 'NotBroadcast'",
    )
    .bind(next_phase.as_str())
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(binding_index))
    .bind(signing_id)
    .bind(expected_phase.as_str())
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 withdrawal phase compare-and-set lost"));
    }
    guard
        .exact_attempt(wallet_name, statechain_id, binding_index)
        .await?
        .ok_or_else(|| anyhow!("BIP448 withdrawal attempt disappeared after transition"))
}

pub async fn transition_bip448_withdrawal_phase(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    expected_phase: Bip448WithdrawalPhase,
    next_phase: Bip448WithdrawalPhase,
) -> Result<Bip448WithdrawalAttempt> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let row = update_attempt_phase_on(
        &mut guard,
        wallet_name,
        statechain_id,
        binding_index,
        signing_id,
        expected_phase,
        next_phase,
    )
    .await?;
    guard.commit().await?;
    Ok(row)
}

async fn validate_canonical_close_snapshot_on(
    guard: &mut Bip448MutationGuard,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
) -> Result<()> {
    let canonical = guard
        .exact_attempt(wallet_name, statechain_id, 0)
        .await?
        .ok_or_else(|| anyhow!("canonical BIP448 close attempt is missing"))?;
    if canonical.signing_id != signing_id
        || canonical.attempt_kind != Bip448WithdrawalAttemptKind::Canonical
    {
        return Err(anyhow!("canonical BIP448 close signing identity changed"));
    }
    let frozen = canonical
        .closing_bindings_json
        .as_deref()
        .ok_or_else(|| anyhow!("canonical BIP448 close snapshot is missing"))?;
    bip448_funding::decode_bip448_closing_bindings(frozen)?;
    let bindings =
        list_bip448_funding_bindings_on(guard.connection(), wallet_name, statechain_id).await?;
    let attempts =
        list_bip448_withdrawal_attempts_on(guard.connection(), wallet_name, statechain_id).await?;
    match bip448_funding::evaluate_bip448_close_gate(&bindings, &attempts)? {
        Bip448CloseGate::Ready {
            closing_bindings_json,
            ..
        } if closing_bindings_json == frozen => Ok(()),
        Bip448CloseGate::Ready { .. } => Err(anyhow!(
            "BIP448 close binding set changed outside the frozen snapshot"
        )),
        Bip448CloseGate::Blocked { reasons } => Err(anyhow!(
            "BIP448 frozen close snapshot is no longer satisfied: {reasons:?}"
        )),
    }
}

pub async fn validate_bip448_canonical_close_snapshot(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
) -> Result<()> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    validate_canonical_close_snapshot_on(&mut guard, wallet_name, statechain_id, signing_id)
        .await?;
    guard.commit().await
}

pub async fn arm_bip448_withdrawal_sign_first(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
) -> Result<Bip448WithdrawalAttempt> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let row = update_attempt_phase_on(
        &mut guard,
        wallet_name,
        statechain_id,
        binding_index,
        signing_id,
        Bip448WithdrawalPhase::Prepared,
        Bip448WithdrawalPhase::FirstArmed,
    )
    .await?;
    guard.commit().await?;
    Ok(row)
}

pub async fn store_bip448_withdrawal_nonce_session(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    server_public_nonce: &str,
    message_hex: &str,
    output_pubkey: &str,
    client_partial_sig: &str,
    encoded_session: &str,
    sign_second_payload_json: &str,
) -> Result<Bip448WithdrawalAttempt> {
    for value in [
        server_public_nonce,
        message_hex,
        output_pubkey,
        client_partial_sig,
    ] {
        bip448_funding::require_canonical_hex(value, None)?;
    }
    let sign_second =
        bip448_funding::parse_canonical_sign_second_payload(sign_second_payload_json)?;
    bip448_funding::require_bip448_session_relationship(encoded_session, &sign_second.session)?;
    if sign_second.statechain_id != statechain_id
        || sign_second.signing_id != signing_id
        || sign_second.server_pub_nonce != server_public_nonce
        || !matches!(sign_second.negate_seckey, 0 | 1)
    {
        return Err(anyhow!(
            "BIP448 sign/second payload does not match the persisted session"
        ));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let result = sqlx::query(
        "UPDATE bip448_withdrawal_attempts SET server_public_nonce = $1, message_hex = $2, \
            output_pubkey = $3, client_partial_sig = $4, encoded_session = $5, \
            sign_second_payload_json = $6, phase = 'NonceStored', updated_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $7 AND statechain_id = $8 AND binding_index = $9 \
           AND signing_id = $10 AND phase = 'FirstArmed' AND broadcast_status = 'NotBroadcast' \
           AND server_public_nonce IS NULL AND message_hex IS NULL AND output_pubkey IS NULL \
           AND client_partial_sig IS NULL AND encoded_session IS NULL \
           AND sign_second_payload_json IS NULL",
    )
    .bind(server_public_nonce)
    .bind(message_hex)
    .bind(output_pubkey)
    .bind(client_partial_sig)
    .bind(encoded_session)
    .bind(sign_second_payload_json)
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(binding_index))
    .bind(signing_id)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 withdrawal nonce compare-and-set lost"));
    }
    let row = guard
        .exact_attempt(wallet_name, statechain_id, binding_index)
        .await?
        .ok_or_else(|| anyhow!("BIP448 withdrawal attempt disappeared after nonce storage"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn store_bip448_withdrawal_nonce_artifacts(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    server_public_nonce: &str,
    message_hex: &str,
    output_pubkey: &str,
    client_partial_sig: &str,
    encoded_session: &str,
    sign_second_payload_json: &str,
) -> Result<Bip448WithdrawalAttempt> {
    store_bip448_withdrawal_nonce_session(
        pool,
        wallet_name,
        statechain_id,
        binding_index,
        signing_id,
        server_public_nonce,
        message_hex,
        output_pubkey,
        client_partial_sig,
        encoded_session,
        sign_second_payload_json,
    )
    .await
}

pub async fn arm_bip448_withdrawal_sign_second(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
) -> Result<Bip448WithdrawalAttempt> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let row = update_attempt_phase_on(
        &mut guard,
        wallet_name,
        statechain_id,
        binding_index,
        signing_id,
        Bip448WithdrawalPhase::NonceStored,
        Bip448WithdrawalPhase::SecondArmed,
    )
    .await?;
    guard.commit().await?;
    Ok(row)
}

pub async fn store_signed_bip448_withdrawal(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    server_partial_sig: &str,
    aggregate_signature: &str,
    signed_tx_hex: &str,
    txid: &str,
    initial_broadcast_status: Bip448BroadcastStatus,
) -> Result<Bip448WithdrawalAttempt> {
    for value in [server_partial_sig, aggregate_signature, signed_tx_hex] {
        bip448_funding::require_canonical_hex(value, None)?;
    }
    let txid = canonical_txid(txid)?;
    if !matches!(
        initial_broadcast_status,
        Bip448BroadcastStatus::NotBroadcast
            | Bip448BroadcastStatus::Conflicting
            | Bip448BroadcastStatus::Conflicted
    ) {
        return Err(anyhow!(
            "illegal initial BIP448 withdrawal broadcast status"
        ));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let result = sqlx::query(
        "UPDATE bip448_withdrawal_attempts SET server_partial_sig = $1, \
            aggregate_signature = $2, signed_tx_hex = $3, txid = $4, phase = 'Signed', \
            broadcast_status = $5, updated_at = CURRENT_TIMESTAMP \
         WHERE wallet_name = $6 AND statechain_id = $7 AND binding_index = $8 \
           AND signing_id = $9 AND phase = 'SecondArmed' \
           AND broadcast_status = 'NotBroadcast' AND server_partial_sig IS NULL \
           AND aggregate_signature IS NULL AND signed_tx_hex IS NULL AND txid IS NULL",
    )
    .bind(server_partial_sig)
    .bind(aggregate_signature)
    .bind(signed_tx_hex)
    .bind(&txid)
    .bind(initial_broadcast_status.as_str())
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(i64::from(binding_index))
    .bind(signing_id)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 signed-artifact compare-and-set lost"));
    }
    let row = guard
        .exact_attempt(wallet_name, statechain_id, binding_index)
        .await?
        .ok_or_else(|| anyhow!("BIP448 attempt disappeared after signed-artifact storage"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn store_bip448_withdrawal_signed_artifacts(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    server_partial_sig: &str,
    aggregate_signature: &str,
    signed_tx_hex: &str,
    txid: &str,
    initial_broadcast_status: Bip448BroadcastStatus,
) -> Result<Bip448WithdrawalAttempt> {
    store_signed_bip448_withdrawal(
        pool,
        wallet_name,
        statechain_id,
        binding_index,
        signing_id,
        server_partial_sig,
        aggregate_signature,
        signed_tx_hex,
        txid,
        initial_broadcast_status,
    )
    .await
}

pub(super) fn legal_broadcast_transition(
    from: Bip448BroadcastStatus,
    to: Bip448BroadcastStatus,
) -> bool {
    use Bip448BroadcastStatus::*;
    from == to
        || matches!(
            (from, to),
            (
                NotBroadcast,
                Accepted | Confirmed | NeedsRebroadcast | Conflicting | Conflicted
            ) | (
                Accepted,
                Confirmed | NeedsRebroadcast | Conflicting | Conflicted
            ) | (
                Confirmed,
                Accepted | NeedsRebroadcast | Conflicting | Conflicted
            ) | (
                NeedsRebroadcast,
                Accepted | Confirmed | Conflicting | Conflicted
            ) | (
                Conflicting,
                Accepted | Confirmed | NeedsRebroadcast | Conflicted
            ) | (
                Conflicted,
                Accepted | Confirmed | NeedsRebroadcast | Conflicting
            )
        )
}

pub async fn transition_bip448_withdrawal_broadcast_status(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    expected: Bip448BroadcastStatus,
    next: Bip448BroadcastStatus,
) -> Result<Bip448WithdrawalAttempt> {
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let row = guard
        .update_withdrawal_broadcast_status(
            wallet_name,
            statechain_id,
            binding_index,
            signing_id,
            expected,
            next,
        )
        .await?;
    guard.commit().await?;
    Ok(row)
}

pub async fn update_bip448_withdrawal_broadcast_status(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    binding_index: u32,
    signing_id: &str,
    expected: Bip448BroadcastStatus,
    next: Bip448BroadcastStatus,
) -> Result<Bip448WithdrawalAttempt> {
    transition_bip448_withdrawal_broadcast_status(
        pool,
        wallet_name,
        statechain_id,
        binding_index,
        signing_id,
        expected,
        next,
    )
    .await
}

pub async fn transition_bip448_withdrawal_completion_status(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
    expected: Bip448CompletionStatus,
    next: Bip448CompletionStatus,
) -> Result<Bip448WithdrawalAttempt> {
    if !matches!(
        (expected, next),
        (
            Bip448CompletionStatus::Open,
            Bip448CompletionStatus::CloseArmed
        ) | (
            Bip448CompletionStatus::CloseArmed,
            Bip448CompletionStatus::Closed
        )
    ) {
        return Err(anyhow!("illegal BIP448 completion-status transition"));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    if expected == Bip448CompletionStatus::Open && next == Bip448CompletionStatus::CloseArmed {
        validate_canonical_close_snapshot_on(&mut guard, wallet_name, statechain_id, signing_id)
            .await?;
        let canonical = guard
            .exact_attempt(wallet_name, statechain_id, 0)
            .await?
            .ok_or_else(|| anyhow!("canonical BIP448 attempt is missing"))?;
        if !matches!(
            canonical.broadcast_status,
            Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
        ) {
            return Err(anyhow!(
                "canonical BIP448 close can arm only while exact bytes are accepted"
            ));
        }
    } else if expected == Bip448CompletionStatus::CloseArmed
        && next == Bip448CompletionStatus::Closed
    {
        let canonical = guard
            .exact_attempt(wallet_name, statechain_id, 0)
            .await?
            .ok_or_else(|| anyhow!("canonical BIP448 attempt is missing"))?;
        if canonical.signing_id != signing_id
            || !matches!(
                canonical.broadcast_status,
                Bip448BroadcastStatus::Accepted | Bip448BroadcastStatus::Confirmed
            )
        {
            return Err(anyhow!(
                "canonical BIP448 close can finish only while exact bytes are accepted"
            ));
        }
    }
    let result = sqlx::query(
        "UPDATE bip448_withdrawal_attempts SET completion_status = $1, \
            updated_at = CURRENT_TIMESTAMP WHERE wallet_name = $2 AND statechain_id = $3 \
            AND binding_index = 0 AND signing_id = $4 AND phase = 'Signed' \
            AND broadcast_status <> 'NotBroadcast' AND completion_status = $5",
    )
    .bind(next.as_str())
    .bind(wallet_name)
    .bind(statechain_id)
    .bind(signing_id)
    .bind(expected.as_str())
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 completion-status compare-and-set lost"));
    }
    let row = guard
        .exact_attempt(wallet_name, statechain_id, 0)
        .await?
        .ok_or_else(|| anyhow!("canonical BIP448 attempt disappeared after completion update"))?;
    guard.commit().await?;
    Ok(row)
}

pub async fn update_bip448_withdrawal_completion_status(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
    signing_id: &str,
    expected: Bip448CompletionStatus,
    next: Bip448CompletionStatus,
) -> Result<Bip448WithdrawalAttempt> {
    transition_bip448_withdrawal_completion_status(
        pool,
        wallet_name,
        statechain_id,
        signing_id,
        expected,
        next,
    )
    .await
}

pub async fn delete_prepared_bip448_withdrawal_attempt_for_confirmed_spend(
    pool: &Pool<Sqlite>,
    expected: &Bip448WithdrawalAttempt,
    competing_spend_txid: &str,
    stable_tip_height: u32,
    stable_tip_hash: &str,
) -> Result<()> {
    bip448_funding::validate_withdrawal_attempt(expected)?;
    let competing_spend_txid = canonical_txid(competing_spend_txid)?;
    let stable_tip_hash = canonical_block_hash(stable_tip_hash)?;
    let prospective_sweep_txid = bip448_funding::expected_withdrawal_txid(expected)?;
    if expected.binding_index == 0
        || expected.attempt_kind != Bip448WithdrawalAttemptKind::Duplicate
        || expected.phase != Bip448WithdrawalPhase::Prepared
        || expected.broadcast_status != Bip448BroadcastStatus::NotBroadcast
    {
        return Err(anyhow!(
            "only a duplicate Prepared BIP448 attempt may be compare-deleted"
        ));
    }
    let mut guard = begin_bip448_mutation_guard(pool).await?;
    let live = guard
        .exact_attempt(
            &expected.wallet_name,
            &expected.statechain_id,
            expected.binding_index,
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 attempt is missing"))?;
    if live != *expected {
        return Err(anyhow!("BIP448 attempt changed before compare-delete"));
    }
    let binding = guard
        .exact_binding(
            &expected.wallet_name,
            &expected.statechain_id,
            expected.binding_index,
        )
        .await?
        .ok_or_else(|| anyhow!("BIP448 binding is missing"))?;
    if binding.observation_status != Bip448ObservationStatus::SpentConfirmed
        || binding.spend_txid.as_deref() != Some(competing_spend_txid.as_str())
        || competing_spend_txid == prospective_sweep_txid
        || binding.last_scanned_height != stable_tip_height
    {
        return Err(anyhow!(
            "BIP448 competing spend is not the stable confirmed binding fact"
        ));
    }
    let cursor_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM bip448_scan_cursors WHERE wallet_name = $1 \
         AND script_pubkey = $2 AND last_scanned_height = $3 \
         AND last_scanned_block_hash = $4",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.source_script_pubkey)
    .bind(i64::from(stable_tip_height))
    .bind(&stable_tip_hash)
    .fetch_one(guard.connection())
    .await?;
    if cursor_count != 1 {
        return Err(anyhow!(
            "BIP448 stable tip changed before duplicate compare-delete"
        ));
    }
    let result = sqlx::query(
        "DELETE FROM bip448_withdrawal_attempts WHERE wallet_name = $1 \
         AND statechain_id = $2 AND binding_index = $3 AND binding_index > 0 \
         AND attempt_kind = 'Duplicate' AND signing_id = $4 AND phase = 'Prepared' \
         AND broadcast_status = 'NotBroadcast' AND source_txid = $5 AND source_vout = $6 \
         AND source_value_sats = $7 AND source_script_pubkey = $8",
    )
    .bind(&expected.wallet_name)
    .bind(&expected.statechain_id)
    .bind(i64::from(expected.binding_index))
    .bind(&expected.signing_id)
    .bind(&expected.source_txid)
    .bind(i64::from(expected.source_vout))
    .bind(i64::try_from(expected.source_value_sats)?)
    .bind(&expected.source_script_pubkey)
    .execute(guard.connection())
    .await?;
    if result.rows_affected() != 1 {
        return Err(anyhow!("BIP448 duplicate compare-delete lost"));
    }
    guard.commit().await?;
    Ok(())
}

pub async fn bip448_active_withdrawal_attempt(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Option<Bip448WithdrawalAttempt>> {
    let attempts = list_bip448_withdrawal_attempts(pool, wallet_name, statechain_id).await?;
    let mut active = attempts
        .into_iter()
        .filter(|attempt| attempt.phase != Bip448WithdrawalPhase::Signed);
    let result = active.next();
    if active.next().is_some() {
        return Err(anyhow!("multiple active BIP448 withdrawal attempts"));
    }
    Ok(result)
}

pub async fn bip448_statechain_is_exit_only(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<bool> {
    let attempts = list_bip448_withdrawal_attempts(pool, wallet_name, statechain_id).await?;
    Ok(bip448_funding::bip448_attempts_are_exit_only(&attempts))
}

pub async fn bip448_expected_signature_count(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<bip448_funding::Bip448SignatureCountExpectation> {
    let record = get_bip448_statechain(pool, wallet_name, statechain_id).await?;
    let attempts = list_bip448_withdrawal_attempts(pool, wallet_name, statechain_id).await?;
    bip448_funding::bip448_signature_count_expectation(record.latest_state_number, &attempts)
}

pub async fn classify_bip448_close_gate(
    pool: &Pool<Sqlite>,
    wallet_name: &str,
    statechain_id: &str,
) -> Result<Bip448CloseGate> {
    let mut connection = pool.acquire().await?;
    let intents =
        list_bip448_transfer_intents_on(&mut connection, wallet_name, statechain_id).await?;
    if !intents.is_empty() {
        if let Err(error) = validate_bip448_transfer_intent_lineage(&intents) {
            return Ok(Bip448CloseGate::Blocked {
                reasons: vec![Bip448CloseBlockReason::InvalidTransferIntentLineage {
                    detail: error.to_string(),
                }],
            });
        }
        let active = intents
            .iter()
            .find(|intent| intent.activity_status == Bip448TransferIntentActivityStatus::Active)
            .ok_or_else(|| anyhow!("BIP448 intent lineage has no active row"))?;
        return Ok(Bip448CloseGate::Blocked {
            reasons: vec![Bip448CloseBlockReason::ActiveTransferIntent {
                intent_id: active.intent_id.clone(),
            }],
        });
    }
    if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM bip448_pending_transfer_signings WHERE wallet_name = $1 AND statechain_id = $2")
        .bind(wallet_name).bind(statechain_id).fetch_one(&mut *connection).await? != 0 {
        return Ok(Bip448CloseGate::Blocked { reasons: vec![Bip448CloseBlockReason::PendingTransferSigning] });
    }
    let messages = sqlx::query_scalar::<_, String>("SELECT recipient_auth_pubkey FROM bip448_transfer_messages WHERE wallet_name = $1 AND statechain_id = $2 ORDER BY recipient_auth_pubkey")
        .bind(wallet_name).bind(statechain_id).fetch_all(&mut *connection).await?;
    if let Some(recipient_auth_pubkey) = messages.first() {
        return Ok(Bip448CloseGate::Blocked {
            reasons: vec![Bip448CloseBlockReason::OutgoingTransferMessage {
                recipient_auth_pubkey: recipient_auth_pubkey.clone(),
            }],
        });
    }
    let wallet_json =
        sqlx::query_scalar::<_, String>("SELECT wallet_json FROM wallet WHERE wallet_name = $1")
            .bind(wallet_name)
            .fetch_optional(&mut *connection)
            .await?;
    if wallet_json.is_some_and(|json| {
        serde_json::from_str::<Wallet>(&json).is_ok_and(|wallet| {
            wallet.coins.iter().any(|coin| {
                coin.statechain_id.as_deref() == Some(statechain_id)
                    && coin.status == mercurylib::wallet::CoinStatus::IN_TRANSFER
            })
        })
    }) {
        return Ok(Bip448CloseGate::Blocked {
            reasons: vec![Bip448CloseBlockReason::CoinInTransfer],
        });
    }
    let bindings =
        list_bip448_funding_bindings_on(&mut connection, wallet_name, statechain_id).await?;
    let attempts =
        list_bip448_withdrawal_attempts_on(&mut connection, wallet_name, statechain_id).await?;
    bip448_funding::evaluate_bip448_close_gate(&bindings, &attempts)
}
