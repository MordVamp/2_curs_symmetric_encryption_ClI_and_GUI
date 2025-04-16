//! File encryption/decryption operations
use std::fs;
use std::path::Path;
use super::meta::Metadata;
use crate::core::crypto::{keygen::derive_key, cipher::Cipher};

/// Encrypt a file with password and save metadata
pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<(), String> {
    // Read raw data without padding
    let data = fs::read(input_path)
        .map_err(|e| format!("Read error: {}", e))?;
    
    // Generate metadata
    let metadata = Metadata::new();
    
    // Derive key
    let key = derive_key(password.as_bytes(), &metadata.salt);
    
    // Encrypt data (padding handled internally)
    let cipher = Cipher::new(key);
    let encrypted_data = cipher.encrypt(&data, &metadata.iv);

    // Validate output structure
    if encrypted_data.len() < 16 || (encrypted_data.len() - 16) % 16 != 0 {
        return Err("Invalid encryption output format".into());
    }

    // Write output (metadata || encrypted data)
    let mut output = metadata.to_bytes();
    output.extend(encrypted_data);
    
    fs::write(output_path, output)
        .map_err(|e| format!("Error writing file: {}", e))?;

    Ok(())
}

/// Decrypt a file using password
// Updated decrypt_file function
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
) -> Result<(), String> {
    let encrypted_data = fs::read(input_path)
        .map_err(|e| format!("Error reading file: {}", e))?;

    if encrypted_data.len() < 48 {
        return Err("File too short to contain metadata".into());
    }

    let metadata = Metadata::from_bytes(&encrypted_data[0..48])
        .map_err(|e| format!("Metadata error: {}", e))?;

    let key = derive_key(password.as_bytes(), &metadata.salt);
    let cipher = Cipher::new(key);

    // Get encrypted payload (without metadata)
    let ciphertext = &encrypted_data[48..];
    
    // Let cipher handle unpadding internally
    let decrypted_data = cipher.decrypt(ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))?;

    fs::write(output_path, decrypted_data)
        .map_err(|e| format!("Write error: {}", e))?;

    Ok(())
}