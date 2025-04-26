//! PBKDF2-like key derivation
use super::sha256::Sha256;
//все исправления не забыть  убрать  в следущем коммитте
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
        let block_num = (block_idx as u32 + 1).to_be_bytes();
        salt_block[salt.len()..].copy_from_slice(&block_num);
        
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
        // Исправление: использование мутабельного hasher
        if key.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hash = hasher.finalize();
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
        // Исправление: правильная работа с мутабельными ссылками
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&self.inner_key);
        inner_hasher.update(data);
        let inner_hash = inner_hasher.finalize();
        
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&self.outer_key);
        outer_hasher.update(&inner_hash);
        outer_hasher.finalize()
    }
}

fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for (a_byte, b_byte) in a.iter_mut().zip(b) {
        *a_byte ^= b_byte;
    }
}