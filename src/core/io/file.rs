use std::fs;
use std::path::Path;
use super::meta::Metadata;
use crate::core::crypto::{keygen::derive_key, cipher::Cipher};


pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<(), String> {
    let data = fs::read(input_path)
        .map_err(|e| e.to_string())?; // Преобразование ошибки
    
    let mut metadata = Metadata::new(); 
    
    let key = derive_key(password.as_bytes());
    let cipher = Cipher::new(key);
    
    let encrypted_data = cipher.encrypt(&data, &metadata.iv);
    
    let mut output = metadata.to_bytes();
    output.extend(encrypted_data);
    
    fs::write(output_path, output)
        .map_err(|e| e.to_string())?; // Преобразование ошибки
    Ok(())
}

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

    let key = derive_key(password.as_bytes());
    let cipher = Cipher::new(key);

    let decrypted_data = cipher.decrypt(&encrypted_data[48..], &metadata.iv)
        .map_err(|e| format!("Decryption error: {}", e))?;

    fs::write(output_path, decrypted_data)
        .map_err(|e| format!("Write error: {}", e))?;

    Ok(())
}