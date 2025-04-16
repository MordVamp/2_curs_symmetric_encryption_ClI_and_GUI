use super::{s_box::{S_BOX, INV_S_BOX}, p_box::{P_BOX, INV_P_BOX}}; // Add INV_P_BOX import

const BLOCK_SIZE: usize = 16;

pub struct Cipher {
    key: [u8; 32],
}

impl Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        Cipher { key }
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let padded_data = pad_data(data);
        let mut encrypted = Vec::with_capacity(padded_data.len());
        
        let mut prev_block = *iv;
        for chunk in padded_data.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(chunk);
            
            xor_bytes(&mut block, &prev_block);
            self.process_block(&mut block);
            
            encrypted.extend_from_slice(&block);
            prev_block = block;
        }
        encrypted
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 16 || (data.len() - 16) % BLOCK_SIZE != 0 {
            return Err("Invalid ciphertext length");
        }
        
        let iv = &data[..16];
        let mut decrypted = Vec::with_capacity(data.len() - 16);
        let mut prev_block = iv.to_vec();

        for chunk in data[16..].chunks(BLOCK_SIZE) {
            let mut block = chunk.to_vec();
            self.invert_block(&mut block);
            
            xor_bytes(&mut block, &prev_block);
            decrypted.extend_from_slice(&block);
            prev_block = chunk.to_vec();
        }
        
        unpad_data(&decrypted) // Remove padding and validate
    }

    fn process_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let key1 = &self.key[..16];
        let key2 = &self.key[16..32];
        
        // Round 1
        substitute_bytes(block, &S_BOX);
        permute_bits(block, &P_BOX);
        xor_bytes(block, key1);
        
        // Round 2
        substitute_bytes(block, &S_BOX);
        permute_bits(block, &P_BOX);
        xor_bytes(block, key2);
    }

    fn invert_block(&self, block: &mut [u8]) {
        let key1 = &self.key[..16];
        let key2 = &self.key[16..32];
        
        // Reverse Round 2
        xor_bytes(block, key2);
        inverse_permute_bits(block, &INV_P_BOX); // Use inverse P-box
        inverse_substitute_bytes(block, &INV_S_BOX);
        
        // Reverse Round 1
        xor_bytes(block, key1);
        inverse_permute_bits(block, &INV_P_BOX); // Use inverse P-box
        inverse_substitute_bytes(block, &INV_S_BOX);
    }
}


// Helper functions (similar to earlier explanation)
fn substitute_bytes(block: &mut [u8], s_box: &[u8; 256]) {
    for byte in block.iter_mut() {
        *byte = s_box[*byte as usize];
    }
}

fn inverse_substitute_bytes(block: &mut [u8], inv_s_box: &[u8; 256]) {
    for byte in block.iter_mut() {
        *byte = inv_s_box[*byte as usize];
    }
}

fn permute_bits(block: &mut [u8], p_box: &[usize; 128]) {
    let mut new_block = [0u8; 16];
    
    // Process each bit position
    for (new_bit_idx, &old_bit_idx) in p_box.iter().enumerate() {
        let old_byte_idx = old_bit_idx / 8;
        let old_bit_pos = 7 - (old_bit_idx % 8);
        let new_byte_idx = new_bit_idx / 8;
        let new_bit_pos = 7 - (new_bit_idx % 8);
        
        // Get bit value from original block
        let bit = (block[old_byte_idx] >> old_bit_pos) & 1;
        
        // Set bit in new block
        new_block[new_byte_idx] |= bit << new_bit_pos;
    }
    
    block.copy_from_slice(&new_block);
}

fn inverse_permute_bits(block: &mut [u8], inv_p_box: &[usize; 128]) {
    let mut new_block = [0u8; 16];
    
    // Process each bit position using inverse permutation
    for (old_bit_idx, &new_bit_idx) in inv_p_box.iter().enumerate() {
        let old_byte_idx = old_bit_idx / 8;
        let old_bit_pos = 7 - (old_bit_idx % 8);
        let new_byte_idx = new_bit_idx / 8;
        let new_bit_pos = 7 - (new_bit_idx % 8);
        
        // Get bit value from permuted block
        let bit = (block[new_byte_idx] >> new_bit_pos) & 1;
        
        // Set bit in original position
        new_block[old_byte_idx] |= bit << old_bit_pos;
    }
    
    block.copy_from_slice(&new_block);
}

fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for (a_byte, b_byte) in a.iter_mut().zip(b) {
        *a_byte ^= b_byte;
    }

}
 // Add PKCS#7 padding
 pub fn pad_data(data: &[u8]) -> Vec<u8> {
    let block_size = BLOCK_SIZE;
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(vec![pad_len as u8; pad_len]);
    padded
}

// Remove PKCS#7 padding
pub fn unpad_data(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE {
        return Err("Invalid padding");
    }
    
    let len = data.len() - pad_len;
    if data[len..].iter().any(|&b| b != pad_len as u8) {
        return Err("Invalid padding");
    }
    
    Ok(data[..len].to_vec())
}