use std::time::Instant;
use tempfile::NamedTempFile;
use crypto_app::core::io::RCTMPrng::RCTMPrng;
use crypto_app::core::io::file::{encrypt_file, decrypt_file};

const TEST_FILE_SIZE_MB: usize = 1; // Размер тестового файла в мегабайтах

#[test]
fn encryption_speed_test() {
    // Генерируем тестовые данные
    let mut test_data = vec![0u8; TEST_FILE_SIZE_MB * 1024 * 1024];
    let mut rng = RCTMPrng::from_entropy().expect("Failed to initialize CSPRNG");
    rng.fill_bytes(&mut test_data);

    // Создаем временные файлы
    let original_file = NamedTempFile::new().expect("Failed to create temp file");
    let encrypted_file = NamedTempFile::new().expect("Failed to create temp file");
    let decrypted_file = NamedTempFile::new().expect("Failed to create temp file");

    // Записываем тестовые данные
    std::fs::write(original_file.path(), &test_data).expect("Failed to write test data");

    let password = "secure_password_123";

    // Тест скорости шифрования
    let encrypt_start = Instant::now();
    encrypt_file(original_file.path(), encrypted_file.path(), password)
        .expect("Encryption failed");
    let encrypt_duration = encrypt_start.elapsed();

    // Тест скорости дешифрования
    let decrypt_start = Instant::now();
    decrypt_file(encrypted_file.path(), decrypted_file.path(), password)
        .expect("Decryption failed");
    let decrypt_duration = decrypt_start.elapsed();

    // Проверка целостности данных
    let decrypted_data = std::fs::read(decrypted_file.path()).expect("Failed to read decrypted file");
    assert_eq!(
        test_data, decrypted_data,
        "Decrypted data does not match original!"
    );

    // Вывод результатов
    println!("\nSpeed test results ({}MB):", TEST_FILE_SIZE_MB);
    println!("Encryption time: {:?}", encrypt_duration);
    println!("Decryption time: {:?}", decrypt_duration);
    println!("Encryption speed: {:.2} MB/s", 
        TEST_FILE_SIZE_MB as f64 / encrypt_duration.as_secs_f64());
    println!("Decryption speed: {:.2} MB/s\n",
        TEST_FILE_SIZE_MB as f64 / decrypt_duration.as_secs_f64());
}