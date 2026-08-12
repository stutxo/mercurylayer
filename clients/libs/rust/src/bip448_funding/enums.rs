use std::{fmt, str::FromStr};

use anyhow::{anyhow, Result};

macro_rules! parsed_enum {
    ($name:ident { $($variant:ident => $literal:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $literal),+
                }
            }

            pub fn parse(value: &str) -> Result<Self> {
                value.parse()
            }
        }

        impl FromStr for $name {
            type Err = anyhow::Error;

            fn from_str(value: &str) -> Result<Self> {
                match value {
                    $($literal => Ok(Self::$variant),)+
                    _ => Err(anyhow!(concat!("invalid ", stringify!($name), " literal: {}"), value)),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

parsed_enum!(Bip448BindingRole {
    Canonical => "Canonical",
    Duplicate => "Duplicate",
});

parsed_enum!(Bip448ObservationStatus {
    Mempool => "Mempool",
    Unconfirmed => "Unconfirmed",
    Confirmed => "Confirmed",
    SpentMempool => "SpentMempool",
    SpentUnconfirmed => "SpentUnconfirmed",
    SpentConfirmed => "SpentConfirmed",
    Absent => "Absent",
});

parsed_enum!(Bip448OwnershipStatus {
    Current => "Current",
    Previous => "Previous",
});

parsed_enum!(Bip448WithdrawalAttemptKind {
    Duplicate => "Duplicate",
    Canonical => "Canonical",
});

parsed_enum!(Bip448WithdrawalPhase {
    Prepared => "Prepared",
    FirstArmed => "FirstArmed",
    NonceStored => "NonceStored",
    SecondArmed => "SecondArmed",
    Signed => "Signed",
});

parsed_enum!(Bip448BroadcastStatus {
    NotBroadcast => "NotBroadcast",
    Accepted => "Accepted",
    Confirmed => "Confirmed",
    NeedsRebroadcast => "NeedsRebroadcast",
    Conflicting => "Conflicting",
    Conflicted => "Conflicted",
});

parsed_enum!(Bip448CompletionStatus {
    NotApplicable => "NotApplicable",
    Open => "Open",
    CloseArmed => "CloseArmed",
    Closed => "Closed",
});

parsed_enum!(Bip448TransferIntentKind {
    UserTransfer => "UserTransfer",
    Cancellation => "Cancellation",
});

parsed_enum!(Bip448TransferIntentActivityStatus {
    Active => "Active",
    Superseded => "Superseded",
});

parsed_enum!(Bip448TransferIntentPhase {
    Prepared => "Prepared",
    SenderArmed => "SenderArmed",
    X1Stored => "X1Stored",
    SenderFinished => "SenderFinished",
    ReceiverAccepted => "ReceiverAccepted",
});

parsed_enum!(Bip448TransferStateSigningPhase {
    NotStarted => "NotStarted",
    FirstArmed => "FirstArmed",
    NonceStored => "NonceStored",
    SecondArmed => "SecondArmed",
    Signed => "Signed",
});
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_storage_enum_has_exact_literal_roundtrip_and_rejects_debug_aliases() {
        macro_rules! check {
                ($type:ty, [$($variant:expr),+ $(,)?]) => {{
                    $(assert_eq!(<$type>::parse($variant.as_str()).unwrap(), $variant);)+
                    assert!(<$type>::parse("canonical").is_err());
                    assert!(<$type>::parse("Unknown").is_err());
                    assert!(<$type>::parse("").is_err());
                }};
            }
        check!(
            Bip448BindingRole,
            [Bip448BindingRole::Canonical, Bip448BindingRole::Duplicate]
        );
        check!(
            Bip448ObservationStatus,
            [
                Bip448ObservationStatus::Mempool,
                Bip448ObservationStatus::Unconfirmed,
                Bip448ObservationStatus::Confirmed,
                Bip448ObservationStatus::SpentMempool,
                Bip448ObservationStatus::SpentUnconfirmed,
                Bip448ObservationStatus::SpentConfirmed,
                Bip448ObservationStatus::Absent
            ]
        );
        check!(
            Bip448OwnershipStatus,
            [
                Bip448OwnershipStatus::Current,
                Bip448OwnershipStatus::Previous
            ]
        );
        check!(
            Bip448WithdrawalAttemptKind,
            [
                Bip448WithdrawalAttemptKind::Duplicate,
                Bip448WithdrawalAttemptKind::Canonical
            ]
        );
        check!(
            Bip448WithdrawalPhase,
            [
                Bip448WithdrawalPhase::Prepared,
                Bip448WithdrawalPhase::FirstArmed,
                Bip448WithdrawalPhase::NonceStored,
                Bip448WithdrawalPhase::SecondArmed,
                Bip448WithdrawalPhase::Signed
            ]
        );
        check!(
            Bip448BroadcastStatus,
            [
                Bip448BroadcastStatus::NotBroadcast,
                Bip448BroadcastStatus::Accepted,
                Bip448BroadcastStatus::Confirmed,
                Bip448BroadcastStatus::NeedsRebroadcast,
                Bip448BroadcastStatus::Conflicting,
                Bip448BroadcastStatus::Conflicted
            ]
        );
        check!(
            Bip448CompletionStatus,
            [
                Bip448CompletionStatus::NotApplicable,
                Bip448CompletionStatus::Open,
                Bip448CompletionStatus::CloseArmed,
                Bip448CompletionStatus::Closed
            ]
        );
        check!(
            Bip448TransferIntentKind,
            [
                Bip448TransferIntentKind::UserTransfer,
                Bip448TransferIntentKind::Cancellation
            ]
        );
        check!(
            Bip448TransferIntentActivityStatus,
            [
                Bip448TransferIntentActivityStatus::Active,
                Bip448TransferIntentActivityStatus::Superseded
            ]
        );
        check!(
            Bip448TransferIntentPhase,
            [
                Bip448TransferIntentPhase::Prepared,
                Bip448TransferIntentPhase::SenderArmed,
                Bip448TransferIntentPhase::X1Stored,
                Bip448TransferIntentPhase::SenderFinished,
                Bip448TransferIntentPhase::ReceiverAccepted
            ]
        );
        check!(
            Bip448TransferStateSigningPhase,
            [
                Bip448TransferStateSigningPhase::NotStarted,
                Bip448TransferStateSigningPhase::FirstArmed,
                Bip448TransferStateSigningPhase::NonceStored,
                Bip448TransferStateSigningPhase::SecondArmed,
                Bip448TransferStateSigningPhase::Signed
            ]
        );
    }
}
