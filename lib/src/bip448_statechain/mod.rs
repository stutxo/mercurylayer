pub mod script;
pub mod transaction;

#[cfg(test)]
pub(crate) mod test_helpers {
    use bitcoin::secp256k1::{KeyPair, Secp256k1, SecretKey, XOnlyPublicKey};

    pub(crate) fn aggregate_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_secret_bytes([7u8; 32]).unwrap();
        let keypair = KeyPair::from_secret_key(&secp, &secret_key);

        keypair.x_only_public_key().0
    }
}
