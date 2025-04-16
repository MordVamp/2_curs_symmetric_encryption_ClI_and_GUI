//! PBKDF2-like key derivation
use super::sha256::Sha256;

const ITERATIONS: usize = 100_000;

pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac(password, salt, ITERATIONS, &mut key);
    key
}

fn pbkdf2_hmac(password: &[u8], salt: &[u8], iterations: usize, key: &mut [u8]) {
    let hmac = HmacSha256::new(password);
    let mut salt_block = vec![0u8; salt.len() + 4];
    salt_block[..salt.len()].copy_from_slice(salt);

    for (block_idx, key_chunk) in key.chunks_mut(32).enumerate() {
        salt_block[salt.len()..].copy_from_slice(&(block_idx as u32 + 1).to_be_bytes());
        
        let mut t = hmac.compute(&salt_block);
        let mut u = t;

        for _ in 1..iterations {
            u = hmac.compute(&u);
            xor_bytes(&mut t, &u);
        }

        key_chunk.copy_from_slice(&t);
    }
}

struct HmacSha256 {
    inner_key: [u8; 64],
    outer_key: [u8; 64],
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        let mut processed_key = [0u8; 64];
        if key.len() > 64 {
            let hash = Sha256::new().update(key).finalize();
            processed_key[..32].copy_from_slice(&hash);
        } else {
            processed_key[..key.len()].copy_from_slice(key);
        }

        let mut inner_key = [0u8; 64];
        let mut outer_key = [0u8; 64];
        
        for i in 0..64 {
            inner_key[i] = processed_key[i] ^ 0x36;
            outer_key[i] = processed_key[i] ^ 0x5c;
        }

        HmacSha256 { inner_key, outer_key }
    }

    fn compute(&self, data: &[u8]) -> [u8; 32] {
        let inner_hash = Sha256::new()
            .update(&self.inner_key)
            .update(data)
            .finalize();
        
        Sha256::new()
            .update(&self.outer_key)
            .update(&inner_hash)
            .finalize()
    }
}

fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for (a_byte, b_byte) in a.iter_mut().zip(b) {
        *a_byte ^= b_byte;
    }
}