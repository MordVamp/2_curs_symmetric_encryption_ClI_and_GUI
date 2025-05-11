//! Metadata handling for encrypted files
use crate::core::io::RCTMPrng::RCTMPrng;

#[derive(Debug, PartialEq)]
pub struct Metadata {
    pub salt: [u8; 32],
    pub iv: [u8; 16],
}

impl Metadata {
    /// Generate new metadata with random salt and IV (nonce + counter)    
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];
        
        let mut rng = RCTMPrng::from_entropy().expect("Failed to initialize CSPRNG");
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut iv[..12]);
        
        Metadata { salt, iv }
    }
    pub fn increment_counter(&mut self) {
        let counter_bytes = &mut self.iv[12..16];
        let mut counter = u32::from_be_bytes(counter_bytes.try_into().unwrap());
        counter += 1;
        counter_bytes.copy_from_slice(&counter.to_be_bytes());
    }

    /// Serialize metadata to bytes (salt || iv)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.iv);
        bytes
    }

    /// Deserialize metadata from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 48 {
            return Err("Invalid metadata length");
        }

        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];
        
        salt.copy_from_slice(&data[0..32]);
        iv.copy_from_slice(&data[32..48]);

        Ok(Metadata { salt, iv })
    }
}