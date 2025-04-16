//! Metadata handling for encrypted files
use rand::RngCore;

#[derive(Debug, PartialEq)]
pub struct Metadata {
    pub salt: [u8; 32],
    pub iv: [u8; 16],
}

impl Metadata {
    /// Generate new random metadata
    pub fn new() -> Self {
        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];
        
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut iv);

        Metadata { salt, iv }
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