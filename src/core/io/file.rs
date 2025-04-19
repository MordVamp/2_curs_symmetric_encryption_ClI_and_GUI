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
/// Decrypt a file using password
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    password: &str,
) -> Result<(), String> {
    // Чтение зашифрованных данных
    let encrypted_data = fs::read(input_path)
        .map_err(|e| format!("Error reading file: {}", e))?;

    // Проверка наличия метаданных
    if encrypted_data.len() < 48 {
        return Err("File too short to contain metadata".into());
    }

    // Извлечение метаданных
    let metadata = Metadata::from_bytes(&encrypted_data[0..48])
        .map_err(|e| format!("Metadata error: {}", e))?;

    // Получение IV из метаданных
    let iv = &metadata.iv;

    // Деривация ключа
    let key = derive_key(password.as_bytes(), &metadata.salt);
    let cipher = Cipher::new(key);

    // Дешифрование данных (без метаданных)
    let ciphertext = &encrypted_data[48..];
    let decrypted_data = cipher.decrypt(ciphertext, iv)
        .map_err(|e| format!("Decryption error: {}", e))?;

    // Запись расшифрованных данных
    fs::write(output_path, decrypted_data)
        .map_err(|e| format!("Write error: {}", e))?;

    Ok(())
}