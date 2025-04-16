use std::path::Path;
use crypto_app::core::io::file::{encrypt_file, decrypt_file};

#[test]
fn test_file_encryption_cycle() {
    let plain_path = Path::new("test_plain.txt");
    let encrypted_path = Path::new("test_encrypted.crypt");
    let decrypted_path = Path::new("test_decrypted.txt");
    let password = "strong_password_123";

    // Encrypt
    encrypt_file(plain_path, encrypted_path, password)
        .expect("Encryption failed");

    // Decrypt
    decrypt_file(encrypted_path, decrypted_path, password)
        .expect("Decryption failed");

    // Verify
    let original = std::fs::read_to_string(plain_path).unwrap();
    let decrypted = std::fs::read_to_string(decrypted_path).unwrap();
    
    assert_eq!(original, decrypted);

    // Cleanup
    std::fs::remove_file(encrypted_path).unwrap();
    std::fs::remove_file(decrypted_path).unwrap();
}