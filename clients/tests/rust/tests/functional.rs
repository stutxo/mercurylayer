mod common;

#[path = "scenarios/ta01_sign_second_not_called.rs"]
mod ta01_sign_second_not_called;
#[path = "scenarios/ta02_duplicate_deposits.rs"]
mod ta02_duplicate_deposits;
#[path = "scenarios/ta03_multiple_deposits.rs"]
mod ta03_multiple_deposits;
#[path = "scenarios/tb01_simple_transfer.rs"]
mod tb01_simple_transfer;
#[path = "scenarios/tb02_transfer_address_reuse.rs"]
mod tb02_transfer_address_reuse;
#[path = "scenarios/tb03_simple_atomic_transfer.rs"]
mod tb03_simple_atomic_transfer;
#[path = "scenarios/tb04_simple_lightning_latch.rs"]
mod tb04_simple_lightning_latch;
#[path = "scenarios/tb05_timelock.rs"]
mod tb05_timelock;
#[path = "scenarios/tb06_bip448_lightning_latch.rs"]
mod tb06_bip448_lightning_latch;
#[path = "scenarios/tm01_sender_double_spends.rs"]
mod tm01_sender_double_spends;
#[path = "scenarios/tv01.rs"]
mod tv01;
