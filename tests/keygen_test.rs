use crypto_app::core::crypto::keygen::derive_key;
use hex_literal::hex;



#[test]
fn key_derivation_consistency() {
    let key1 = derive_key(b"secret", b"salt123");
    let key2 = derive_key(b"secret", b"salt123");
    assert_eq!(key1, key2);
}

#[test]
fn different_salts_produce_different_keys() {
    let key1 = derive_key(b"password", b"salt1");
    let key2 = derive_key(b"password", b"salt2");
    assert_ne!(key1, key2);
}