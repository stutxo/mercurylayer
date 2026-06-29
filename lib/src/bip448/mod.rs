pub mod template_hash;

use bitcoin::{
    blockdata::opcodes::{OP_CHECKSIGFROMSTACK, OP_INTERNALKEY, OP_TEMPLATEHASH},
    script::Builder,
    ScriptBuf,
};

pub fn primitive_script() -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_TEMPLATEHASH)
        .push_opcode(OP_INTERNALKEY)
        .push_opcode(OP_CHECKSIGFROMSTACK)
        .into_script()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP_INTERNALKEY_BYTE: u8 = 0xcb;
    const OP_CHECKSIGFROMSTACK_BYTE: u8 = 0xcc;
    const OP_TEMPLATEHASH_BYTE: u8 = 0xce;

    #[test]
    fn bip448_opcode_bytes_match_inquisition() {
        assert_eq!(OP_INTERNALKEY.to_u8(), OP_INTERNALKEY_BYTE);
        assert_eq!(OP_CHECKSIGFROMSTACK.to_u8(), OP_CHECKSIGFROMSTACK_BYTE);
        assert_eq!(OP_TEMPLATEHASH.to_u8(), OP_TEMPLATEHASH_BYTE);
    }

    #[test]
    fn primitive_script_uses_bip448_template_hash_internal_key_csfs() {
        assert_eq!(
            primitive_script().as_bytes(),
            [
                OP_TEMPLATEHASH_BYTE,
                OP_INTERNALKEY_BYTE,
                OP_CHECKSIGFROMSTACK_BYTE,
            ]
        );
    }
}
