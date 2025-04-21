//! Directory encryption/decryption operations
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tar::{Builder, Archive};
use tempfile::NamedTempFile;
use super::file::{encrypt_file, decrypt_file};

/// Encrypt a directory into a tar archive and encrypt it
pub fn encrypt_directory(
    input_dir: &Path,
    output_path: &Path,
    password: &str,
) -> Result<(), String> {
    // Validate input directory exists
    if !input_dir.exists() {
        return Err(format!("Directory '{}' does not exist", input_dir.display()));
    }
    if !input_dir.is_dir() {
        return Err(format!("'{}' is not a directory", input_dir.display()));
    }

    // Create temporary tar archive
    let temp_file = NamedTempFile::new()
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    
    // Build tar archive
    {
        let file = File::create(temp_file.path())
            .map_err(|e| format!("Failed to create tar file: {}", e))?;
        let mut builder = Builder::new(file);
        builder.append_dir_all(".", input_dir)
            .map_err(|e| format!("Tar build failed: {}", e))?;
        builder.finish()
            .map_err(|e| format!("Tar finalization failed: {}", e))?;
    } // File is automatically closed here

    // Encrypt the tar file
    encrypt_file(temp_file.path(), output_path, password)?;
    
    // Explicitly persist and delete temp file (optional)
    temp_file.close()
        .map_err(|e| format!("Temp file cleanup failed: {}", e))?;

    Ok(())
}

/// Decrypt a directory encrypted with encrypt_directory
pub fn decrypt_directory(
    encrypted_path: &Path,
    output_dir: &Path,
    password: &str,
) -> Result<(), String> {
    // Validate encrypted file exists
    if !encrypted_path.exists() {
        return Err(format!("File '{}' does not exist", encrypted_path.display()));
    }
    if !encrypted_path.is_file() {
        return Err(format!("'{}' is not a file", encrypted_path.display()));
    }

    // Create temporary tar file
    let temp_file = NamedTempFile::new()
        .map_err(|e| format!("Temp file error: {}", e))?;

    // Decrypt to temporary file
    decrypt_file(encrypted_path, temp_file.path(), password)?;

    // Unpack tar archive
    {
        let file = File::open(temp_file.path())
            .map_err(|e| format!("Failed to open tar: {}", e))?;
        let mut archive = Archive::new(file);
        archive.unpack(output_dir)
            .map_err(|e| format!("Unpack failed: {}", e))?;
    }

    Ok(())
}

