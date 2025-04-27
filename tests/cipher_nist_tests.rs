// crypto-app/tests/cipher_nist_tests.rs

use crypto_app::core::crypto::{cipher::Cipher, keygen::derive_key};
use nistrs::prelude::*;
use rand::Rng;

const SAMPLE_SIZE: usize = 1_000_000;
const NIST_THRESHOLD: f64 = 0.01;

#[test]
fn test_cipher_nist_full() {
    let mut rng = rand::thread_rng();
    
    // Генерация ключа и данных
    let mut password = [0u8; 32];
    let mut salt = [0u8; 32];
    rng.fill(&mut password);
    rng.fill(&mut salt);
    
    let key = derive_key(&password, &salt);
    let cipher = Cipher::new(key);
    let iv = [0u8; 16];
    
    // Генерация случайного plaintext
    let mut plaintext = vec![0u8; SAMPLE_SIZE];
    rng.fill(&mut plaintext[..]);
    
    // Шифрование
    let ciphertext = cipher.encrypt(&plaintext, &iv);
    
    let data = BitsData::from_binary(ciphertext);
    let mut passed = 0;

    // Frequency Test
    let (res, p) = frequency_test(&data);
    assert!(p >= NIST_THRESHOLD, "Frequency test failed: p = {:.4}", p);
    if res { passed += 1; }

    // Block Frequency Test
    match block_frequency_test(&data, 128) {
        Ok((res, p)) => {
            assert!(p >= NIST_THRESHOLD, "Block Frequency test failed: p = {:.4}", p);
            if res { passed += 1; }
        }
        Err(e) => panic!("Block Frequency test error: {}", e),
    }

    // Cumulative Sums Test (оба направления)
    for (i, (res, p)) in cumulative_sums_test(&data).into_iter().enumerate() {
        assert!(p >= NIST_THRESHOLD, "Cusum test {} failed: p = {:.4}", i, p);
        if res { passed += 1; }
    }

    // Runs Test
    let (res, p) = runs_test(&data);
    assert!(p >= NIST_THRESHOLD, "Runs test failed: p = {:.4}", p);
    if res { passed += 1; }

    // Longest Run Test
    match longest_run_of_ones_test(&data) {
        Ok((res, p)) => {
            assert!(p >= NIST_THRESHOLD, "Longest Run test failed: p = {:.4}", p);
            if res { passed += 1; }
        }
        Err(e) => panic!("Longest Run test error: {}", e),
    }

    // FFT Test
    let (res, p) = fft_test(&data);
    assert!(p >= NIST_THRESHOLD, "FFT test failed: p = {:.4}", p);
    if res { passed += 1; }

    // Rank Test
    match rank_test(&data) {
        Ok((res, p)) => {
            assert!(p >= NIST_THRESHOLD, "Rank test failed: p = {:.4}", p);
            if res { passed += 1; }
        }
        Err(e) => panic!("Rank test error: {}", e),
    }

    // Serial Test (два результата)
    for (i, (res, p)) in serial_test(&data, 3).into_iter().enumerate() {
        assert!(p >= NIST_THRESHOLD, "Serial test {} failed: p = {:.4}", i, p);
        if res { passed += 1; }
    }

    // Approximate Entropy Test
    let (res, p) = approximate_entropy_test(&data, 2);
    assert!(p >= NIST_THRESHOLD, "Approx Entropy test failed: p = {:.4}", p);
    if res { passed += 1; }

    assert!(passed >= 7, "Only {} tests passed", passed);
}