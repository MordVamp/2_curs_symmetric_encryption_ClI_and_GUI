use crypto_app::core::crypto::keygen::derive_key;
use hex_literal::hex;



#[test]
fn key_derivation_consistency() {
    let key1 = derive_key(b"secret");
    let key2 = derive_key(b"secret");
    assert_eq!(key1, key2);
}

