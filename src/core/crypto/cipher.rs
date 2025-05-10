use super::{s_box::S_BOX, p_box::P_BOX};
use arrayref::array_ref;
use rayon::prelude::*; // Добавлен параллелизм

const BLOCK_SIZE: usize = 16;

pub struct Cipher {
    key: [u8; 32],
    key1: [u8; 16],
    key2: [u8; 16],
}

impl Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        let key1 = *array_ref!(key, 0, 16);
        let key2 = *array_ref!(key, 16, 16);
        Cipher { key, key1, key2 }
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let (nonce, counter_part) = iv.split_at(12);
        let initial_counter = u32::from_be_bytes(counter_part.try_into().unwrap()) as u64;

        // Параллельная обработка блоков
        let encrypted_chunks: Vec<Vec<u8>> = data
            .par_chunks(BLOCK_SIZE)
            .enumerate()
            .map(|(i, chunk)| {
                let mut ctr_block = [0u8; 16];
                ctr_block[..12].copy_from_slice(nonce);
                let counter = initial_counter + i as u64;
                ctr_block[12..].copy_from_slice(&counter.to_be_bytes()[4..]);

                let mut key_stream = [0u8; BLOCK_SIZE];
                self.process_block(&mut ctr_block, &mut key_stream);

                chunk.iter()
                    .zip(key_stream.iter())
                    .map(|(d, k)| d ^ k)
                    .collect()
            })
            .collect();

        let mut encrypted = iv.to_vec();
        encrypted.extend(encrypted_chunks.concat());
        encrypted
    }
    pub fn decrypt(&self, data: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        if data.len() < BLOCK_SIZE {
            return Err("Invalid ciphertext length");
        }

        let (nonce, counter_part) = iv.split_at(12);
        let initial_counter = u32::from_be_bytes(counter_part.try_into().unwrap()) as u64;

        // Параллельная обработка блоков (кроме IV)
        let decrypted_chunks: Vec<Vec<u8>> = data[BLOCK_SIZE..]
            .par_chunks(BLOCK_SIZE)
            .enumerate()
            .map(|(i, chunk)| {
                let mut ctr_block = [0u8; 16];
                ctr_block[..12].copy_from_slice(nonce);
                let counter = initial_counter + i as u64;
                ctr_block[12..].copy_from_slice(&counter.to_be_bytes()[4..]);

                let mut key_stream = [0u8; BLOCK_SIZE];
                self.process_block(&mut ctr_block, &mut key_stream);

                chunk.iter()
                    .zip(key_stream.iter())
                    .map(|(c, k)| c ^ k)
                    .collect()
            })
            .collect();

        Ok(decrypted_chunks.concat())
    }

    #[inline(always)] // Агрессивная оптимизация
    fn process_block(&self, input: &mut [u8; 16], output: &mut [u8; 16]) {
        let mut block = *input;
        
        // Объединенные операции для минимизации циклов
        for byte in &mut block {
            *byte = S_BOX[*byte as usize];
        }
        permute_bits(&mut block);
        xor_bytes(&mut block, &self.key1);

        for byte in &mut block {
            *byte = S_BOX[*byte as usize];
        }
        permute_bits(&mut block);
        xor_bytes(&mut block, &self.key2);
        
        output.copy_from_slice(&block);
    }
}

// Оптимизированные функции
#[inline(always)]
fn permute_bits(block: &mut [u8; 16]) {
    let mut new_block = [0u8; 16];
    for i in 0..128 {
        let old_byte = P_BOX[i] / 8;
        let old_bit = 7 - (P_BOX[i] % 8);
        let bit = (block[old_byte] >> old_bit) & 1;
        
        let new_byte = i / 8;
        let new_bit = 7 - (i % 8);
        new_block[new_byte] |= bit << new_bit;
    }
    *block = new_block;
}

#[inline(always)]
fn xor_bytes(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}