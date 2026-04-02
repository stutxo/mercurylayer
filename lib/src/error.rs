use bitcoin::{bip32, sighash::SighashTypeParseError};
use secp256k1::{musig::{MusigNonceGenError, MusigSignError, ParseError}, scalar::OutOfRangeError, Error as UpstreamError};

#[derive(Debug, thiserror::Error)]
pub enum MercuryError {
    Bip39Error,
    Bip32Error,
    NetworkConversionError,
    Secp256k1UpstreamError,
    KeyError,
    Bech32Error,
    HexError,
    LocktimeNotBlockHeightError,
    LocktimeTooLow,
    LocktimeTooHigh,
    TransactionReconstructionError,
    TransactionVersionError,
    TransactionSequenceDifferentThanZeroError,
    BitcoinConsensusEncodeError,
    MusigNonceGenError,
    InvalidStatechainAddressError,
    InvalidBitcoinAddressError,
    StatechainAddressMismatchNetworkError,
    BitcoinAddressMismatchNetworkError,
    BitcoinAddressError,
    BitcoinAbsoluteError,
    BitcoinHashHexError,
    BitcoinPsbtError,
    SighashTypeParseError,
    BitcoinSighashError,
    ParseError,
    MusigSignError,
    SchnorrSignatureValidationError,
    MoreThanOneInputError,
    UnkownNetwork,
    BackupTransactionDoesNotPayUser,
    FeeTooHigh,
    FeeTooLow,
    OutOfRangeError,
    SerdeJsonError,
    SecpError,
    NoBackupTransactionFound,
    Tx1HasMoreThanOneInput,
    TxHasMoreThanOneOutput,
    EmptyInput,
    InvalidSignature,
    EmptyWitness,
    EmptyWitnessData,
    IncorrectChallenge,
    InvalidT1,
    IncorrectAggregatedPublicKey,
    T1MustBeExactly32BytesError,
    NoX1Pub,
    NoAggregatedPubkeyError,
    CoinNotFound,
    SignatureSchemeValidationError,
    NoPreviousLockTimeError,
}

impl core::fmt::Display for MercuryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl From<bip39::Error> for MercuryError {
    fn from(_: bip39::Error) -> Self {
        MercuryError::Bip39Error
    }
}

impl From<bip32::Error> for MercuryError {
    fn from(_: bip32::Error) -> Self {
        MercuryError::Bip32Error
    }
}

impl From<UpstreamError> for MercuryError {
    fn from(_: UpstreamError) -> Self {
        MercuryError::Secp256k1UpstreamError
    }
}

impl From<bitcoin::key::Error> for MercuryError {
    fn from(_: bitcoin::key::Error) -> Self {
        MercuryError::KeyError
    }
}

impl From<bech32::Error> for MercuryError {
    fn from(_: bech32::Error) -> Self {
        MercuryError::Bech32Error
    }
}

impl From<hex::FromHexError> for MercuryError {
    fn from(_: hex::FromHexError) -> Self {
        MercuryError::HexError
    }
}

impl From<bitcoin::consensus::encode::Error> for MercuryError {
    fn from(_: bitcoin::consensus::encode::Error) -> Self {
        MercuryError::BitcoinConsensusEncodeError
    }
}

impl From<MusigNonceGenError> for MercuryError {
    fn from(_: MusigNonceGenError) -> Self {
        MercuryError::MusigNonceGenError
    }
}

impl From<bitcoin::address::Error> for MercuryError {
    fn from(_: bitcoin::address::Error) -> Self {
        MercuryError::BitcoinAddressError
    }
}

impl From<bitcoin::absolute::Error> for MercuryError {
    fn from(_: bitcoin::absolute::Error) -> Self {
        MercuryError::BitcoinAbsoluteError
    }
}

impl From<bitcoin::hashes::hex::Error> for MercuryError {
    fn from(_: bitcoin::hashes::hex::Error) -> Self {
        MercuryError::BitcoinHashHexError
    }
}

impl From<bitcoin::psbt::Error> for MercuryError {
    fn from(_: bitcoin::psbt::Error) -> Self {
        MercuryError::BitcoinPsbtError
    }
}

impl From<SighashTypeParseError> for MercuryError {
    fn from(_: SighashTypeParseError) -> Self {
        MercuryError::SighashTypeParseError
    }
}

impl From<bitcoin::sighash::Error> for MercuryError {
    fn from(_: bitcoin::sighash::Error) -> Self {
        MercuryError::BitcoinSighashError
    }
}

impl From<ParseError> for MercuryError {
    fn from(_: ParseError) -> Self {
        MercuryError::ParseError
    }
}

impl From<MusigSignError> for MercuryError {
    fn from(_: MusigSignError) -> Self {
        MercuryError::MusigSignError
    }
}

impl From<OutOfRangeError> for MercuryError {
    fn from(_: OutOfRangeError) -> Self {
        MercuryError::OutOfRangeError
    }
}

impl From<serde_json::Error> for MercuryError {
    fn from(_: serde_json::Error) -> Self {
        MercuryError::SerdeJsonError
    }
}
