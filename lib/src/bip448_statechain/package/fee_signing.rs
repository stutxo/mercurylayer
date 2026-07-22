use bitcoin::{
    key::TapTweak,
    secp256k1::{self, Message, Secp256k1, SecretKey},
    sighash::{self, SighashCache, TapSighashType},
    taproot, ScriptBuf, TxOut, Witness,
};
use thiserror::Error;

use super::{Bip448CpfpFeeInput, Bip448PackageError, Bip448RecoveryPackage};

#[derive(Debug, Error)]
pub enum Bip448FeeSigningError {
    #[error("BIP448 CPFP child has no anchor input")]
    MissingAnchorInput,
    #[error("BIP448 CPFP child fee-input count {child_count} does not match signer input count {signer_count}")]
    FeeInputCountMismatch {
        child_count: usize,
        signer_count: usize,
    },
    #[error("BIP448 CPFP child fee input {input_index} does not match signer outpoint")]
    FeeInputOutpointMismatch { input_index: usize },
    #[error("BIP448 CPFP anchor output {output_index} is missing from its parent")]
    MissingAnchorOutput { output_index: u32 },
    #[error(transparent)]
    Sighash(#[from] sighash::Error),
    #[error(transparent)]
    Package(#[from] Bip448PackageError),
}

pub fn sign_cpfp_fee_inputs(
    package: &mut Bip448RecoveryPackage,
    fee_inputs: &[Bip448CpfpFeeInput],
    fee_script_pubkey: &ScriptBuf,
    fee_secret_key: &SecretKey,
) -> Result<(), Bip448FeeSigningError> {
    let anchor_input = package
        .cpfp_child_tx
        .input
        .first()
        .ok_or(Bip448FeeSigningError::MissingAnchorInput)?;
    let child_fee_inputs = package.cpfp_child_tx.input.len().saturating_sub(1);
    if child_fee_inputs != fee_inputs.len() {
        return Err(Bip448FeeSigningError::FeeInputCountMismatch {
            child_count: child_fee_inputs,
            signer_count: fee_inputs.len(),
        });
    }
    for (input_index, (child_input, fee_input)) in package
        .cpfp_child_tx
        .input
        .iter()
        .skip(1)
        .zip(fee_inputs)
        .enumerate()
    {
        if child_input.previous_output != fee_input.previous_output {
            return Err(Bip448FeeSigningError::FeeInputOutpointMismatch {
                input_index: input_index + 1,
            });
        }
    }

    let anchor_output_index = anchor_input.previous_output.vout;
    let anchor_output = package
        .parent_tx
        .output
        .get(anchor_output_index as usize)
        .cloned()
        .ok_or(Bip448FeeSigningError::MissingAnchorOutput {
            output_index: anchor_output_index,
        })?;
    let mut prevouts = Vec::with_capacity(fee_inputs.len() + 1);
    prevouts.push(anchor_output);
    prevouts.extend(fee_inputs.iter().map(|input| TxOut {
        value: input.value_sats,
        script_pubkey: fee_script_pubkey.clone(),
    }));

    let secp = Secp256k1::new();
    let keypair = secp256k1::KeyPair::from_secret_key(&secp, fee_secret_key)
        .tap_tweak(&secp, None)
        .to_inner();
    let mut witnesses = Vec::with_capacity(fee_inputs.len());
    for input_index in 1..package.cpfp_child_tx.input.len() {
        let sighash = SighashCache::new(&package.cpfp_child_tx).taproot_key_spend_signature_hash(
            input_index,
            &sighash::Prevouts::All(&prevouts),
            TapSighashType::Default,
        )?;
        let message: Message = sighash.into();
        let signature = secp.sign_schnorr(message.as_ref(), &keypair);
        let signature = taproot::Signature {
            sig: signature,
            hash_ty: TapSighashType::Default,
        };
        let mut witness = Witness::new();
        witness.push(signature.to_vec());
        witnesses.push(witness);
    }

    package.replace_fee_input_witnesses(witnesses)?;
    Ok(())
}
