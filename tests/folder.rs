// tests/folder_test.rs
use crypto_app::core::io::folder::{encrypt_directory, decrypt_directory};
use tempfile::TempDir;
use rand::{RngCore, thread_rng};
use std::fs;
use std::path::{Path, PathBuf};

fn create_test_directory() -> (TempDir, Vec<PathBuf>) {
    let dir = TempDir::new().unwrap();
    let sub_dir = dir.path().join("test_subdir");
    fs::create_dir(&sub_dir).unwrap();
    
    let files = vec![
        dir.path().join("file1.txt"),
        dir.path().join("file2.dat"),
        sub_dir.join("nested_file.bin"),
    ];

    let mut rng = thread_rng();
    for file in &files {
        let mut content = vec![0u8; 1024];
        rng.fill_bytes(&mut content);
        fs::write(file, &content).unwrap();
    }

    (dir, files)
}

#[test]
fn test_full_directory_cycle() {
    let (input_dir, files) = create_test_directory();
    let encrypted_file = input_dir.path().join("encrypted.dir");
    let output_dir = TempDir::new().unwrap();

    // Encryption test
    encrypt_directory(input_dir.path(), &encrypted_file, "password")
        .expect("Directory encryption failed");

    // Verify encryption
    assert!(encrypted_file.exists());
    assert!(encrypted_file.metadata().unwrap().len() > 0);

    // Decryption test
    decrypt_directory(&encrypted_file, output_dir.path(), "password")
        .expect("Directory decryption failed");

    // Verify structure and content
    for file in files {
        let rel_path = file.strip_prefix(input_dir.path()).unwrap();
        let decrypted_file = output_dir.path().join(rel_path);
        
        assert!(decrypted_file.exists(), 
            "Missing file: {}", decrypted_file.display());
        
        let original = fs::read(&file).unwrap();
        let decrypted = fs::read(decrypted_file).unwrap();
        assert_eq!(original, decrypted, "Content mismatch");
    }
}

#[test]
fn test_invalid_directory_operations() {
    let fake_path = Path::new("/non/existent/path");
    let temp_out = Path::new("temp.out");
    let temp_dir = TempDir::new().unwrap();

    // Test non-existent input
    let res = encrypt_directory(fake_path, temp_out, "pass");
    assert!(res.is_err());

    // Test file instead of directory
    let res = encrypt_directory(Path::new("Cargo.toml"), temp_out, "pass");
    assert!(res.is_err());

    // Test wrong password
    let encrypted_file = temp_dir.path().join("test.enc");
    encrypt_directory(temp_dir.path(), &encrypted_file, "right_pass").unwrap();
    
    let res = decrypt_directory(&encrypted_file, temp_dir.path(), "wrong_pass");
    assert!(res.is_err());
}