use bitcoin::{
    hashes::Hash,
    sighash::{Annex, Error as SighashError, SighashCache, TemplateHash},
    Transaction,
};

pub fn template_hash(
    tx: &Transaction,
    input_index: usize,
    annex: Option<Annex<'_>>,
) -> Result<TemplateHash, SighashError> {
    let mut cache = SighashCache::new(tx);
    cache.template_hash(input_index, annex)
}

pub fn template_hash_message(
    tx: &Transaction,
    input_index: usize,
    annex: Option<Annex<'_>>,
) -> Result<[u8; 32], SighashError> {
    Ok(template_hash(tx, input_index, annex)?.to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute, hashes::Hash, script::Builder, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Txid, Witness,
    };

    // Known-answer test data. The other tests in this module only assert
    // relative properties (mutating field X changes the hash), which would
    // still pass if the underlying rust-bitcoin `SighashCache::template_hash`
    // serialization drifted in an absolute way. This vector pins the wrapper to
    // an external, authoritative digest so any such drift fails default CI
    // before Phase 4 signs against it.
    //
    // `BIP446_VECTOR_TX` and `BIP446_NO_ANNEX_HASH` are copied verbatim from the
    // official BIP446 test vectors (bips/bip-0446/basics.json, first `valid`
    // case, input_index 0), which Bitcoin Inquisition's consensus
    // `OP_TEMPLATEHASH` also conforms to. `BIP446_ANNEX_HASH` is the digest of
    // the same transaction and input with the annex `0x50 || "data"`, computed
    // independently from the BIP341/BIP446 tagged-hash definition.
    const BIP446_VECTOR_TX: &str = "02000000000102c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37041500000000ffffffff169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f40c00000000ffffffff01327906000000000016001482074bdf6ce32b071dd120a17cf99cbc01ad3080022320d1f1955b1327167cb7ae3dc39d52c277be39d75737b9cb80514ce6e825fd8eeace8721c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00000000000";
    const BIP446_NO_ANNEX_HASH: &str =
        "d1f1955b1327167cb7ae3dc39d52c277be39d75737b9cb80514ce6e825fd8eea";
    const BIP446_ANNEX_HASH: &str =
        "40ee92735bd9b32fc51d9b6df6be4dafc834cf383506dcb45a61151aeee3460c";

    #[test]
    fn template_hash_matches_bip446_known_answer() {
        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(BIP446_VECTOR_TX).unwrap()).unwrap();

        assert_eq!(
            template_hash_message(&tx, 0, None).unwrap().to_vec(),
            hex::decode(BIP446_NO_ANNEX_HASH).unwrap(),
            "no-annex TemplateHash diverged from the BIP446 vector; the rust-bitcoin \
             OP_TEMPLATEHASH serialization may have changed"
        );

        let annex_bytes = hex::decode("5064617461").unwrap();
        let annex = Annex::new(&annex_bytes).unwrap();
        assert_eq!(
            template_hash_message(&tx, 0, Some(annex)).unwrap().to_vec(),
            hex::decode(BIP446_ANNEX_HASH).unwrap(),
            "annex-present TemplateHash diverged from the independently-computed \
             BIP341/BIP446 digest; annex serialization may have changed"
        );
    }

    #[test]
    fn prevout_and_script_sig_are_not_committed() {
        let tx = sample_tx();
        let base_hash = template_hash(&tx, 0, None).unwrap();

        let mut rebound_tx = tx.clone();
        rebound_tx.input[0].previous_output = outpoint(9, 42);
        rebound_tx.input[0].script_sig = Builder::new().push_int(1).into_script();

        assert_eq!(base_hash, template_hash(&rebound_tx, 0, None).unwrap());
    }

    #[test]
    fn transaction_version_is_committed() {
        let tx = sample_tx();
        let mut changed_tx = tx.clone();
        changed_tx.version += 1;

        assert_template_hash_changed(&tx, &changed_tx);
    }

    #[test]
    fn lock_time_is_committed() {
        let tx = sample_tx();
        let mut changed_tx = tx.clone();
        changed_tx.lock_time = absolute::LockTime::from_consensus(750_001);

        assert_template_hash_changed(&tx, &changed_tx);
    }

    #[test]
    fn input_sequences_are_committed() {
        let tx = sample_tx();
        let mut changed_tx = tx.clone();
        changed_tx.input[1].sequence = Sequence::from_consensus(12);

        assert_template_hash_changed(&tx, &changed_tx);
    }

    #[test]
    fn outputs_are_committed() {
        let tx = sample_tx();
        let mut changed_tx = tx.clone();
        changed_tx.output[0].value += 1;

        assert_template_hash_changed(&tx, &changed_tx);
    }

    #[test]
    fn input_index_is_committed() {
        let tx = sample_tx();

        assert_ne!(
            template_hash(&tx, 0, None).unwrap(),
            template_hash(&tx, 1, None).unwrap()
        );
    }

    #[test]
    fn annex_presence_and_contents_are_committed() {
        let tx = sample_tx();
        let annex_a_bytes = [0x50, 0x01];
        let annex_b_bytes = [0x50, 0x02];
        let annex_a = Annex::new(&annex_a_bytes).unwrap();
        let annex_b = Annex::new(&annex_b_bytes).unwrap();

        let no_annex_hash = template_hash(&tx, 0, None).unwrap();
        let annex_a_hash = template_hash(&tx, 0, Some(annex_a)).unwrap();
        let annex_b_hash = template_hash(&tx, 0, Some(annex_b)).unwrap();

        assert_ne!(no_annex_hash, annex_a_hash);
        assert_ne!(annex_a_hash, annex_b_hash);
    }

    fn assert_template_hash_changed(original_tx: &Transaction, changed_tx: &Transaction) {
        assert_ne!(
            template_hash(original_tx, 0, None).unwrap(),
            template_hash(changed_tx, 0, None).unwrap()
        );
    }

    fn sample_tx() -> Transaction {
        Transaction {
            version: 3,
            lock_time: absolute::LockTime::from_consensus(750_000),
            input: vec![txin(1, 0, 10), txin(2, 1, 11)],
            output: vec![TxOut {
                value: 50_000,
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn txin(txid_seed: u8, vout: u32, sequence: u32) -> TxIn {
        TxIn {
            previous_output: outpoint(txid_seed, vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }
    }

    fn outpoint(txid_seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_slice(&[txid_seed; 32]).unwrap(),
            vout,
        }
    }
}
