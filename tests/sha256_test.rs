use crypto_app::core::crypto::sha256::Sha256;
use hex_literal::hex;

#[test]
fn empty_string() {
    let hash = Sha256::new().finalize();
    assert_eq!(
        hash,
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

#[test]
fn basic_hashes() {
    let mut sha = Sha256::new();
    sha.update(b"hello world");
    assert_eq!(
        sha.finalize(),
        hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    );
}

#[test]
fn incremental_hashing() {
    let mut sha = Sha256::new();
    sha.update(b"The quick brown fox ");
    sha.update(b"jumps over the lazy dog");
    assert_eq!(
        sha.finalize(),
        hex!("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
    );
}