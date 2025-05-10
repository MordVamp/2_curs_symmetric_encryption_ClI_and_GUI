use super::{s_box::S_BOX, p_box::P_BOX};
use arrayref::array_ref;
use rayon::prelude::*;
use std::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
use core::array;

const BLOCK_SIZE: usize = 16;

#[derive(Copy, Clone)] // Добавлены трейты Copy и Clone
struct PermutationInfo {
    old_byte: usize,
    old_bit: u8,
}

// Предварительно вычисленная таблица перестановок с использованием array::from_fn
const PERMUTATION_TABLE: [[PermutationInfo; 8]; 16] = {
    let mut table = [[PermutationInfo { old_byte: 0, old_bit: 0 }; 8]; 16];
    
    // Вычисление значений для каждого элемента в константном контексте
    let mut new_byte = 0;
    while new_byte < 16 {
        let mut new_bit = 0;
        while new_bit < 8 {
            let pos = new_byte * 8 + (7 - new_bit);
            let old_pos = P_BOX[pos];
            table[new_byte][new_bit] = PermutationInfo {
                old_byte: old_pos / 8,
                old_bit: (7 - (old_pos % 8)) as u8,
            };
            new_bit += 1;
        }
        new_byte += 1;
    }
    table
};
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

    #[inline(always)]
    fn process_block(&self, input: &mut [u8; 16], output: &mut [u8; 16]) {
        let mut block = *input;
        
        // Первый раунд
        block.iter_mut().for_each(|byte| *byte = S_BOX[*byte as usize]);
        permute_bits(&mut block);
        xor_bytes_simd(&mut block, &self.key1);

        // Второй раунд
        block.iter_mut().for_each(|byte| *byte = S_BOX[*byte as usize]);
        permute_bits(&mut block);
        xor_bytes_simd(&mut block, &self.key2);
        
        output.copy_from_slice(&block);
    }
}

#[inline(always)]
fn permute_bits(block: &mut [u8; 16]) {
    let mut new_block = [0u8; 16];
    for (new_byte, bits) in PERMUTATION_TABLE.iter().enumerate() {
        new_block[new_byte] = bits.iter().enumerate()
            .fold(0u8, |acc, (new_bit, info)| {
                let bit = (block[info.old_byte] >> info.old_bit) & 1;
                acc | (bit << (7 - new_bit))
            });
    }
    *block = new_block;
}

#[inline(always)]
fn xor_bytes_simd(a: &mut [u8; 16], b: &[u8; 16]) {
    unsafe {
        let a_ptr = a.as_mut_ptr() as *mut __m128i;
        let b_ptr = b.as_ptr() as *const __m128i;
        let a_vec = _mm_loadu_si128(a_ptr);
        let b_vec = _mm_loadu_si128(b_ptr);
        let res = _mm_xor_si128(a_vec, b_vec);
        _mm_storeu_si128(a_ptr, res);
    }
}