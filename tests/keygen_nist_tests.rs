// use only $cargo test 
use crypto_app::core::crypto::keygen::derive_key;
use nistrs::prelude::*;
use rand::Rng;

const SAMPLE_SIZE: usize = 6_000;
const NIST_THRESHOLD: f64 = 0.01;

#[test]
fn test_keygen_nist_full() {
    let mut rng = rand::thread_rng();
    let mut key_bits = Vec::new();
    
    // Генерация тестовых данных
    for _ in 0..SAMPLE_SIZE / 32 {
        let mut password = [0u8; 32];
        let mut salt = [0u8; 32];
        rng.fill(&mut password);
        rng.fill(&mut salt);
        
        let key = derive_key(&password);
        key_bits.extend(key);
    }

    let data = BitsData::from_binary(key_bits);
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

    assert!(passed >= 5, "Only {} tests passed", passed);
}