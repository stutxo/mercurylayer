//! BIP448 CSFS blinded MuSig signing over BIP446 `TemplateHash` messages.
//!
//! This adapts Mercury's blinded two-party MuSig flow (see
//! `crate::transaction::calculate_musig_session` and `docs/blind_musig.md`) to
//! produce the raw BIP340 signatures consumed by the
//! `OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK` update leaves. It
//! deliberately differs from the legacy Taproot key-path flow in three ways:
//!
//! - **The message is the 32-byte `TemplateHash`, not a `TapSighash`.**
//!   BIP348 verifies the BIP340 signature over the stack message directly, so
//!   no additional hashing happens and no sighash type byte is ever appended:
//!   the witness item is exactly the 64-byte signature.
//! - **The signing key is the untweaked aggregate key `P`, not the Taproot
//!   output key `Q`.** `OP_INTERNALKEY` pushes the internal key from the
//!   control block, so the CSFS check runs against `P.x`. No
//!   `TapTweakHash` is applied anywhere in this module; the blinded session is
//!   created with a zero tweak scalar so the aggregated signature carries no
//!   `e * tweak` term.
//! - **The x-only parity flag is derived from the untweaked aggregate point
//!   `P_full`.** BIP340 verification lifts `P.x` to the even-Y point, so when
//!   `P_full` has odd Y both participants must negate their secret shares.
//!   The legacy flow derives this flag from the tweaked `Q` and its tweak
//!   parity accumulator; reusing that flag here would be wrong whenever the
//!   parities of `P_full` and `Q` differ.
//!
//! Only update roles exist. Settlement is authorized by the
//! `state_settlement_leaf` template-hash equality and must never have a CSFS
//! signing session; [`CsfsSigningRole`] has no settlement variant and role
//! parsing rejects it explicitly.

use std::{error::Error, fmt, str::FromStr};

use bitcoin::{hashes::Hash, sighash::TemplateHash, taproot::ControlBlock, Script, Witness};
use secp256k1::{
    musig::{
        blinded_musig_negate_seckey, AggregatedNonce, BlindingFactor, MusigSignError,
        PartialSignature, PublicNonce, SecretNonce, Session,
    },
    schnorr, KeyPair, Message, PublicKey, Scalar, Secp256k1, SecretKey, Signing, XOnlyPublicKey,
};

/// CSFS signatures are raw BIP340 signatures: exactly 64 bytes, no sighash
/// type byte.
pub const CSFS_SIGNATURE_SIZE: usize = 64;

pub type CsfsWitnessSignature = [u8; CSFS_SIGNATURE_SIZE];

/// Serializes a CSFS witness signature as the exact 64-byte BIP340 item that
/// BIP348 expects. Do not wrap this in `taproot::Signature`: Taproot key-path
/// serialization appends a sighash byte and produces an invalid CSFS witness.
pub fn csfs_witness_signature(signature: &schnorr::Signature) -> CsfsWitnessSignature {
    signature.to_byte_array()
}

/// Builds the tapscript witness for a CSFS spend using the 64-byte raw BIP340
/// signature item. This is intentionally separate from legacy Taproot key-path
/// witness construction, which serializes `taproot::Signature` and may append a
/// sighash byte.
pub fn csfs_script_witness(
    signature: &schnorr::Signature,
    script: &Script,
    control_block: &ControlBlock,
) -> Witness {
    let mut witness = Witness::new();
    witness.push(csfs_witness_signature(signature));
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    witness
}

/// Phase 4 uses Mercury's two-party client/server MuSig flow.
pub const CSFS_PARTIAL_SIGNATURE_COUNT: usize = 2;

/// Participant label used to attribute partial-signature verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsfsSigningParticipant {
    Client,
    Server,
}

impl CsfsSigningParticipant {
    pub fn as_str(&self) -> &'static str {
        match self {
            CsfsSigningParticipant::Client => "client",
            CsfsSigningParticipant::Server => "server",
        }
    }
}

impl fmt::Display for CsfsSigningParticipant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The parity accumulator for the untweaked CSFS flow. The legacy key-path
/// flow accumulates tweak parities in `blinded_musig_pubkey_xonly_tweak_add`;
/// no tweak is ever applied here, so the accumulator stays zero and the
/// negation flag reduces to the parity of the untweaked aggregate point.
const UNTWEAKED_PARITY_ACC: i32 = 0;

/// The signing roles that may request a BIP448 CSFS signature.
///
/// There is deliberately no settlement variant: `S(n)` is authorized by the
/// settlement leaf's template-hash equality, and creating a settlement
/// signing session is a protocol violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsfsSigningRole {
    /// The update transaction spending the funding output `Tx0`.
    FundingUpdate,
    /// An update transaction spending (fast-forwarding) a state output.
    StateUpdate,
}

impl CsfsSigningRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            CsfsSigningRole::FundingUpdate => "funding_update",
            CsfsSigningRole::StateUpdate => "state_update",
        }
    }
}

impl fmt::Display for CsfsSigningRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CsfsSigningRole {
    type Err = CsfsSigningError;

    fn from_str(role: &str) -> Result<Self, Self::Err> {
        match role {
            "funding_update" => Ok(CsfsSigningRole::FundingUpdate),
            "state_update" => Ok(CsfsSigningRole::StateUpdate),
            "state_settlement" | "settlement" => Err(CsfsSigningError::SettlementSigningRejected),
            other => Err(CsfsSigningError::UnknownSigningRole {
                role: other.to_string(),
            }),
        }
    }
}

#[derive(Debug)]
pub enum CsfsSigningError {
    SettlementSigningRejected,
    UnknownSigningRole { role: String },
    InvalidBlindingFactor,
    InvalidPartialSignatureCount { expected: usize, actual: usize },
    InvalidPartialSignature { participant: CsfsSigningParticipant },
    PartialSignature(MusigSignError),
    SignatureVerification,
}

impl fmt::Display for CsfsSigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CsfsSigningError::SettlementSigningRejected => f.write_str(
                "BIP448 settlement is authorized by the settlement leaf's template-hash \
                 equality; a settlement CSFS signing session must not be created",
            ),
            CsfsSigningError::UnknownSigningRole { role } => {
                write!(f, "unknown BIP448 CSFS signing role {role}")
            }
            CsfsSigningError::InvalidBlindingFactor => {
                f.write_str("BIP448 CSFS blinding factor is not a valid nonzero secp256k1 scalar")
            }
            CsfsSigningError::InvalidPartialSignatureCount { expected, actual } => write!(
                f,
                "BIP448 CSFS signing session expected {expected} partial signatures, got {actual}"
            ),
            CsfsSigningError::InvalidPartialSignature { participant } => write!(
                f,
                "BIP448 CSFS {participant} partial signature does not verify"
            ),
            CsfsSigningError::PartialSignature(err) => {
                write!(f, "BIP448 CSFS partial signature failure: {err}")
            }
            CsfsSigningError::SignatureVerification => f.write_str(
                "aggregated BIP448 CSFS signature does not verify against the untweaked \
                 aggregate key",
            ),
        }
    }
}

impl Error for CsfsSigningError {}

impl From<MusigSignError> for CsfsSigningError {
    fn from(err: MusigSignError) -> Self {
        CsfsSigningError::PartialSignature(err)
    }
}

/// Whether participants must negate their secret shares so the aggregated
/// signature verifies against BIP340's even-Y lift of `P.x`.
///
/// The flag is derived from the **untweaked** aggregate point `P_full` with a
/// zero parity accumulator. Do not substitute the legacy flag derived from
/// the tweaked Taproot output key `Q`: the two disagree whenever `P_full` and
/// `Q` have different y parities.
pub fn csfs_negate_seckey<C: Signing>(secp: &Secp256k1<C>, aggregate_pubkey: &PublicKey) -> bool {
    blinded_musig_negate_seckey(secp, aggregate_pubkey, UNTWEAKED_PARITY_ACC)
}

/// A blinded two-party MuSig session over a BIP446 `TemplateHash` message,
/// keyed to the untweaked aggregate key `P`.
pub struct CsfsSigningSession {
    role: CsfsSigningRole,
    template_hash: TemplateHash,
    aggregate_pubkey: PublicKey,
    session: Session,
    negate_seckey: bool,
}

impl CsfsSigningSession {
    /// Creates the signing session for an update role.
    ///
    /// `aggregate_pubkey` must be the full (not x-only) untweaked Mercury
    /// aggregate point `P_full = user_share + server_share`. The session is
    /// blinded exactly like the legacy flow, but with a zero tweak scalar so
    /// the final signature verifies against `P.x` rather than a tweaked
    /// output key.
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        role: CsfsSigningRole,
        aggregate_pubkey: PublicKey,
        client_pub_nonce: &PublicNonce,
        server_pub_nonce: &PublicNonce,
        template_hash: TemplateHash,
        blinding_factor: &BlindingFactor,
    ) -> Result<Self, CsfsSigningError> {
        validate_blinding_factor(blinding_factor)?;

        let aggregated_nonce = AggregatedNonce::new(&[client_pub_nonce, server_pub_nonce]);
        // TemplateHash is the raw 32-byte BIP340 message; it is not hashed
        // again and no sighash type byte exists in this flow.
        let msg: Message = template_hash.into();

        let session = Session::new_blinded_without_key_agg_cache(
            secp,
            &aggregate_pubkey,
            aggregated_nonce,
            msg,
            None,
            blinding_factor,
            // No Taproot tweak: CSFS verifies against the untweaked internal
            // key pushed by OP_INTERNALKEY, so the session must not carry an
            // `e * tweak` term.
            Scalar::ZERO,
        );

        let negate_seckey = csfs_negate_seckey(secp, &aggregate_pubkey);

        Ok(Self {
            role,
            template_hash,
            aggregate_pubkey,
            session,
            negate_seckey,
        })
    }

    pub fn role(&self) -> CsfsSigningRole {
        self.role
    }

    pub fn template_hash(&self) -> TemplateHash {
        self.template_hash
    }

    /// The untweaked x-only aggregate key the final signature verifies
    /// against; this is the key `OP_INTERNALKEY` pushes on the stack.
    pub fn aggregate_xonly_key(&self) -> XOnlyPublicKey {
        self.aggregate_pubkey.x_only_public_key().0
    }

    /// The share-negation flag for this session, derived from the untweaked
    /// aggregate point. Both participants must sign with this flag.
    pub fn negate_seckey(&self) -> bool {
        self.negate_seckey
    }

    /// The session with the final nonce removed, as transmitted to the blind
    /// server. The server can produce its partial signature from this without
    /// learning the final nonce (and therefore the on-chain signature).
    pub fn blinded_server_session(&self) -> Session {
        self.session.remove_fin_nonce_from_session()
    }

    /// The blinded MuSig challenge committed by the server signing row.
    pub fn blinded_challenge(&self) -> [u8; 32] {
        self.session.get_challenge_from_session()
    }

    /// Produces and verifies one participant's partial signature with the
    /// session's parity flag applied. The secret nonce is consumed to prevent
    /// reuse.
    pub fn partial_sign_verified<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        participant: CsfsSigningParticipant,
        secret_nonce: SecretNonce,
        public_nonce: &PublicNonce,
        keypair: &KeyPair,
    ) -> Result<PartialSignature, CsfsSigningError> {
        let partial_signature = self.session.blinded_partial_sign_without_keyaggcoeff(
            secp,
            secret_nonce,
            keypair,
            self.negate_seckey,
        )?;

        self.verify_partial(
            secp,
            participant,
            &partial_signature,
            public_nonce,
            &keypair.public_key(),
        )?;

        Ok(partial_signature)
    }

    /// Verifies one participant's partial signature against their public
    /// nonce and public key share, returning an attributable error on failure.
    pub fn verify_partial<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        participant: CsfsSigningParticipant,
        partial_signature: &PartialSignature,
        public_nonce: &PublicNonce,
        public_key: &PublicKey,
    ) -> Result<(), CsfsSigningError> {
        if !self.session.blinded_musig_partial_sig_verify(
            secp,
            partial_signature,
            public_nonce,
            public_key,
            &self.aggregate_pubkey,
            UNTWEAKED_PARITY_ACC,
        ) {
            return Err(CsfsSigningError::InvalidPartialSignature { participant });
        }

        Ok(())
    }

    /// Aggregates the partial signatures and verifies the result against the
    /// untweaked x-only aggregate key over the raw template-hash message.
    ///
    /// Returns the raw BIP340 signature. Use [`csfs_witness_signature`] when
    /// pushing it to a CSFS witness so no Taproot sighash byte is appended.
    pub fn aggregate_and_verify(
        &self,
        partial_signatures: &[&PartialSignature],
    ) -> Result<schnorr::Signature, CsfsSigningError> {
        if partial_signatures.len() != CSFS_PARTIAL_SIGNATURE_COUNT {
            return Err(CsfsSigningError::InvalidPartialSignatureCount {
                expected: CSFS_PARTIAL_SIGNATURE_COUNT,
                actual: partial_signatures.len(),
            });
        }

        self.session
            .partial_sig_agg(partial_signatures)
            .verify(
                &self.aggregate_xonly_key(),
                self.template_hash.as_byte_array(),
            )
            .map_err(|_| CsfsSigningError::SignatureVerification)
    }
}

fn validate_blinding_factor(blinding_factor: &BlindingFactor) -> Result<(), CsfsSigningError> {
    SecretKey::from_secret_bytes(*blinding_factor.as_bytes())
        .map(|_| ())
        .map_err(|_| CsfsSigningError::InvalidBlindingFactor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip448::template_hash::template_hash;
    use crate::bip448_statechain::transaction::placeholder_outpoint;
    use bitcoin::{
        absolute, hashes::sha256, sighash::TapSighashType, taproot::TapTweakHash, OutPoint,
        ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use secp256k1::{
        musig::{blinded_musig_pubkey_xonly_tweak_add, new_musig_nonce_pair, MusigSessionId},
        SecretKey,
    };

    struct Participants {
        client: KeyPair,
        server: KeyPair,
        aggregate_pubkey: PublicKey,
    }

    fn secp() -> Secp256k1<secp256k1::All> {
        Secp256k1::new()
    }

    fn keypair(seed: u8) -> KeyPair {
        let secp = secp();
        KeyPair::from_secret_key(&secp, &SecretKey::from_secret_bytes([seed; 32]).unwrap())
    }

    fn is_odd(pubkey: &PublicKey) -> bool {
        pubkey.serialize()[0] == 0x03
    }

    /// Finds a deterministic two-party key set whose full aggregate point has
    /// the requested y parity.
    fn participants_with_parity(want_odd: bool) -> Participants {
        let server = keypair(200);
        for seed in 1u8..=64 {
            let client = keypair(seed);
            let aggregate_pubkey = client
                .public_key()
                .combine(&server.public_key())
                .expect("aggregate key");
            if is_odd(&aggregate_pubkey) == want_odd {
                return Participants {
                    client,
                    server,
                    aggregate_pubkey,
                };
            }
        }
        unreachable!("no client seed produced the requested aggregate parity");
    }

    fn nonce_pair(
        session_label: u8,
        signer_label: &[u8],
        aggregate_pubkey: &PublicKey,
        hash: TemplateHash,
        keypair: &KeyPair,
    ) -> (SecretNonce, PublicNonce) {
        let secp = secp();
        let msg: Message = hash.into();
        new_musig_nonce_pair(
            &secp,
            MusigSessionId::assume_unique_per_nonce_gen(nonce_seed(
                session_label,
                signer_label,
                aggregate_pubkey,
                hash,
                keypair,
            )),
            None,
            Some(keypair.secret_key()),
            keypair.public_key(),
            Some(msg),
            None,
        )
        .expect("nonce pair")
    }

    fn nonce_seed(
        session_label: u8,
        signer_label: &[u8],
        aggregate_pubkey: &PublicKey,
        hash: TemplateHash,
        keypair: &KeyPair,
    ) -> [u8; 32] {
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(b"mercury-bip448-csfs-test-nonce-v1");
        seed_material.push(session_label);
        seed_material.extend_from_slice(signer_label);
        seed_material.extend_from_slice(&aggregate_pubkey.serialize());
        seed_material.extend_from_slice(&keypair.public_key().serialize());
        seed_material.extend_from_slice(hash.as_byte_array());

        let mut seed = sha256::Hash::hash(&seed_material).to_byte_array();
        if seed.iter().all(|byte| *byte == 0) {
            seed[0] = 1;
        }
        seed
    }

    fn sample_update_tx() -> Transaction {
        Transaction {
            version: 3,
            lock_time: absolute::LockTime::from_consensus(500_000_009),
            input: vec![TxIn {
                previous_output: placeholder_outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: 50_000,
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    /// Runs the full blinded two-party flow: the client signs with the full
    /// session and the server signs with the fin-nonce-removed blinded
    /// session, exactly as the real server would.
    fn sign_two_party(
        participants: &Participants,
        hash: TemplateHash,
        nonce_seed: u8,
    ) -> (CsfsSigningSession, schnorr::Signature) {
        let secp = secp();
        let (client_sec_nonce, client_pub_nonce) = nonce_pair(
            nonce_seed,
            b"client",
            &participants.aggregate_pubkey,
            hash,
            &participants.client,
        );
        let (server_sec_nonce, server_pub_nonce) = nonce_pair(
            nonce_seed,
            b"server",
            &participants.aggregate_pubkey,
            hash,
            &participants.server,
        );
        let blinding_factor = BlindingFactor::from_slice(&[7u8; 32]).unwrap();

        let session = CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::StateUpdate,
            participants.aggregate_pubkey,
            &client_pub_nonce,
            &server_pub_nonce,
            hash,
            &blinding_factor,
        )
        .unwrap();

        let client_partial = session
            .partial_sign_verified(
                &secp,
                CsfsSigningParticipant::Client,
                client_sec_nonce,
                &client_pub_nonce,
                &participants.client,
            )
            .unwrap();

        // The server signs from the blinded session (final nonce removed),
        // mirroring the real blind-server flow.
        let server_partial = session
            .blinded_server_session()
            .blinded_partial_sign_without_keyaggcoeff(
                &secp,
                server_sec_nonce,
                &participants.server,
                session.negate_seckey(),
            )
            .unwrap();
        assert!(matches!(
            session.verify_partial(
                &secp,
                CsfsSigningParticipant::Server,
                &client_partial,
                &server_pub_nonce,
                &participants.server.public_key(),
            ),
            Err(CsfsSigningError::InvalidPartialSignature {
                participant: CsfsSigningParticipant::Server
            })
        ));

        session
            .verify_partial(
                &secp,
                CsfsSigningParticipant::Client,
                &client_partial,
                &client_pub_nonce,
                &participants.client.public_key(),
            )
            .unwrap();

        session
            .verify_partial(
                &secp,
                CsfsSigningParticipant::Server,
                &server_partial,
                &server_pub_nonce,
                &participants.server.public_key(),
            )
            .unwrap();

        let signature = session
            .aggregate_and_verify(&[&client_partial, &server_partial])
            .unwrap();

        (session, signature)
    }
    #[test]
    fn two_party_signing_verifies_against_untweaked_aggregate_key() {
        let secp = secp();

        for want_odd in [false, true] {
            let participants = participants_with_parity(want_odd);
            let tx = sample_update_tx();
            let hash = template_hash(&tx, 0, None).unwrap();

            let (session, signature) = sign_two_party(&participants, hash, 10);

            assert_eq!(session.role(), CsfsSigningRole::StateUpdate);
            assert_eq!(session.template_hash(), hash);

            // The parity flag equals the parity of the untweaked aggregate
            // point.
            assert_eq!(session.negate_seckey(), want_odd);

            // Raw 64-byte BIP340 signature over the raw message bytes; no
            // Taproot sighash byte exists anywhere in this witness item.
            let witness_signature = csfs_witness_signature(&signature);
            assert_eq!(witness_signature.len(), CSFS_SIGNATURE_SIZE);
            assert_eq!(witness_signature, signature.to_byte_array());
            let aggregate_xonly = participants.aggregate_pubkey.x_only_public_key().0;
            assert!(
                schnorr::verify(&signature, hash.as_byte_array(), &aggregate_xonly).is_ok(),
                "signature must verify against untweaked P.x (parity odd = {want_odd})"
            );

            // The same signature must NOT verify against the tweaked Taproot
            // output key Q used by the legacy key-path flow.
            let tap_tweak = TapTweakHash::from_key_and_tweak(aggregate_xonly, None);
            let tweak = SecretKey::from_secret_bytes(*tap_tweak.as_byte_array()).unwrap();
            let (_, tweaked_output_key, _) =
                blinded_musig_pubkey_xonly_tweak_add(&secp, &participants.aggregate_pubkey, tweak);
            assert!(schnorr::verify(
                &signature,
                hash.as_byte_array(),
                &tweaked_output_key.x_only_public_key().0,
            )
            .is_err());
        }
    }

    #[test]
    fn csfs_witness_signature_omits_taproot_sighash_byte() {
        let participants = participants_with_parity(false);
        let tx = sample_update_tx();
        let hash = template_hash(&tx, 0, None).unwrap();
        let (_, signature) = sign_two_party(&participants, hash, 60);

        let witness_signature = csfs_witness_signature(&signature);
        let taproot_signature = bitcoin::taproot::Signature {
            sig: signature,
            hash_ty: TapSighashType::All,
        }
        .to_vec();

        assert_eq!(witness_signature.len(), CSFS_SIGNATURE_SIZE);
        assert_eq!(taproot_signature.len(), CSFS_SIGNATURE_SIZE + 1);
        assert_eq!(
            &taproot_signature[..CSFS_SIGNATURE_SIZE],
            witness_signature.as_slice()
        );
        assert_eq!(
            taproot_signature[CSFS_SIGNATURE_SIZE],
            TapSighashType::All as u8
        );
    }

    #[test]
    fn partial_signature_error_uses_musig_display_string() {
        let err = CsfsSigningError::PartialSignature(MusigSignError::NonceReuse).to_string();

        assert_eq!(
            err,
            "BIP448 CSFS partial signature failure: Musig signing nonce re-used"
        );
        assert!(!err.contains("NonceReuse"));
    }

    #[test]
    fn signing_role_strings_round_trip_through_display_and_from_str() {
        for role in [CsfsSigningRole::FundingUpdate, CsfsSigningRole::StateUpdate] {
            let role_string = role.to_string();

            assert_eq!(role_string, role.as_str());
            assert_eq!(CsfsSigningRole::from_str(&role_string).unwrap(), role);
        }
    }

    #[test]
    fn odd_parity_signing_fails_without_share_negation() {
        let secp = secp();
        let participants = participants_with_parity(true);
        let tx = sample_update_tx();
        let hash = template_hash(&tx, 0, None).unwrap();

        let (client_sec_nonce, client_pub_nonce) = nonce_pair(
            20,
            b"client",
            &participants.aggregate_pubkey,
            hash,
            &participants.client,
        );
        let (server_sec_nonce, server_pub_nonce) = nonce_pair(
            20,
            b"server",
            &participants.aggregate_pubkey,
            hash,
            &participants.server,
        );
        let blinding_factor = BlindingFactor::from_slice(&[9u8; 32]).unwrap();

        let session = CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::StateUpdate,
            participants.aggregate_pubkey,
            &client_pub_nonce,
            &server_pub_nonce,
            hash,
            &blinding_factor,
        )
        .unwrap();
        assert!(session.negate_seckey());

        // Omit the required negation on both shares: the aggregate must fail
        // verification against P.x.
        let client_partial = session
            .session
            .blinded_partial_sign_without_keyaggcoeff(
                &secp,
                client_sec_nonce,
                &participants.client,
                false,
            )
            .unwrap();
        let server_partial = session
            .session
            .blinded_partial_sign_without_keyaggcoeff(
                &secp,
                server_sec_nonce,
                &participants.server,
                false,
            )
            .unwrap();

        assert!(matches!(
            session.aggregate_and_verify(&[&client_partial, &server_partial]),
            Err(CsfsSigningError::SignatureVerification)
        ));
    }

    #[test]
    fn signing_session_rejects_invalid_blinding_factor() {
        let secp = secp();
        let participants = participants_with_parity(false);
        let tx = sample_update_tx();
        let hash = template_hash(&tx, 0, None).unwrap();
        let (_, client_pub_nonce) = nonce_pair(
            40,
            b"client",
            &participants.aggregate_pubkey,
            hash,
            &participants.client,
        );
        let (_, server_pub_nonce) = nonce_pair(
            40,
            b"server",
            &participants.aggregate_pubkey,
            hash,
            &participants.server,
        );

        for bytes in [[0u8; 32], [0xff; 32]] {
            let blinding_factor = BlindingFactor::from_slice(&bytes).unwrap();

            assert!(matches!(
                CsfsSigningSession::new(
                    &secp,
                    CsfsSigningRole::StateUpdate,
                    participants.aggregate_pubkey,
                    &client_pub_nonce,
                    &server_pub_nonce,
                    hash,
                    &blinding_factor,
                ),
                Err(CsfsSigningError::InvalidBlindingFactor)
            ));
        }
    }

    #[test]
    fn aggregate_and_verify_rejects_wrong_partial_signature_count() {
        let secp = secp();
        let participants = participants_with_parity(false);
        let tx = sample_update_tx();
        let hash = template_hash(&tx, 0, None).unwrap();
        let (client_sec_nonce, client_pub_nonce) = nonce_pair(
            50,
            b"client",
            &participants.aggregate_pubkey,
            hash,
            &participants.client,
        );
        let (_, server_pub_nonce) = nonce_pair(
            50,
            b"server",
            &participants.aggregate_pubkey,
            hash,
            &participants.server,
        );
        let blinding_factor = BlindingFactor::from_slice(&[11u8; 32]).unwrap();

        let session = CsfsSigningSession::new(
            &secp,
            CsfsSigningRole::StateUpdate,
            participants.aggregate_pubkey,
            &client_pub_nonce,
            &server_pub_nonce,
            hash,
            &blinding_factor,
        )
        .unwrap();

        assert!(matches!(
            session.aggregate_and_verify(&[]),
            Err(CsfsSigningError::InvalidPartialSignatureCount {
                expected: CSFS_PARTIAL_SIGNATURE_COUNT,
                actual: 0
            })
        ));

        let client_partial = session
            .partial_sign_verified(
                &secp,
                CsfsSigningParticipant::Client,
                client_sec_nonce,
                &client_pub_nonce,
                &participants.client,
            )
            .unwrap();
        assert!(matches!(
            session.aggregate_and_verify(&[&client_partial]),
            Err(CsfsSigningError::InvalidPartialSignatureCount {
                expected: CSFS_PARTIAL_SIGNATURE_COUNT,
                actual: 1
            })
        ));
    }

    #[test]
    fn csfs_parity_flag_comes_from_untweaked_p_not_tweaked_q() {
        let secp = secp();

        // Find a key set where the untweaked P parity and the legacy
        // tweaked-Q negation flag disagree, proving the two are not
        // interchangeable.
        let server = keypair(200);
        let mut found = false;
        for seed in 1u8..=64 {
            let client = keypair(seed);
            let aggregate_pubkey = client
                .public_key()
                .combine(&server.public_key())
                .expect("aggregate key");

            let csfs_flag = csfs_negate_seckey(&secp, &aggregate_pubkey);
            assert_eq!(csfs_flag, is_odd(&aggregate_pubkey));

            let aggregate_xonly = aggregate_pubkey.x_only_public_key().0;
            let tap_tweak = TapTweakHash::from_key_and_tweak(aggregate_xonly, None);
            let tweak = SecretKey::from_secret_bytes(*tap_tweak.as_byte_array()).unwrap();
            let (parity_acc, tweaked_output_key, _) =
                blinded_musig_pubkey_xonly_tweak_add(&secp, &aggregate_pubkey, tweak);
            let legacy_flag = blinded_musig_negate_seckey(&secp, &tweaked_output_key, parity_acc);

            if csfs_flag != legacy_flag {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "expected at least one key set where untweaked-P and tweaked-Q parity flags differ"
        );
    }

    #[test]
    fn signature_survives_rebinding_and_breaks_on_committed_field_mutation() {
        let participants = participants_with_parity(false);
        let tx = sample_update_tx();
        let hash = template_hash(&tx, 0, None).unwrap();
        let (_, signature) = sign_two_party(&participants, hash, 30);
        let aggregate_xonly = participants.aggregate_pubkey.x_only_public_key().0;

        // Rebinding the prevout leaves the template hash unchanged, so the
        // already-produced signature keeps verifying.
        let mut rebound = tx.clone();
        rebound.input[0].previous_output = OutPoint {
            txid: Txid::from_slice(&[9u8; 32]).unwrap(),
            vout: 1,
        };
        let rebound_hash = template_hash(&rebound, 0, None).unwrap();
        assert_eq!(hash, rebound_hash);
        assert!(
            schnorr::verify(&signature, rebound_hash.as_byte_array(), &aggregate_xonly).is_ok()
        );

        // Mutating a committed field changes the message; the signature no
        // longer applies.
        let mut mutated = tx.clone();
        mutated.output[0].value -= 1;
        let mutated_hash = template_hash(&mutated, 0, None).unwrap();
        assert_ne!(hash, mutated_hash);
        assert!(
            schnorr::verify(&signature, mutated_hash.as_byte_array(), &aggregate_xonly).is_err()
        );
    }

    #[test]
    fn settlement_signing_role_is_rejected() {
        // Type-level: CsfsSigningRole has no settlement variant, so a
        // settlement session cannot be constructed. API-level: parsing the
        // settlement role names fails with the dedicated error.
        assert!(matches!(
            CsfsSigningRole::from_str("state_settlement"),
            Err(CsfsSigningError::SettlementSigningRejected)
        ));
        assert!(matches!(
            CsfsSigningRole::from_str("settlement"),
            Err(CsfsSigningError::SettlementSigningRejected)
        ));
        assert!(matches!(
            CsfsSigningRole::from_str("withdrawal"),
            Err(CsfsSigningError::UnknownSigningRole { role }) if role == "withdrawal"
        ));

        assert_eq!(
            CsfsSigningRole::from_str("funding_update").unwrap(),
            CsfsSigningRole::FundingUpdate
        );
        assert_eq!(
            CsfsSigningRole::from_str("state_update").unwrap(),
            CsfsSigningRole::StateUpdate
        );
        assert_eq!(CsfsSigningRole::StateUpdate.as_str(), "state_update");
    }
}
