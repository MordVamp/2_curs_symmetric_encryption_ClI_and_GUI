//! Обработка метаданных зашифрованных файлов

use crate::core::sys;

#[derive(Debug, PartialEq)]
pub struct Metadata {
    pub salt: [u8; 32],
    pub iv: [u8; 16],
}

impl Metadata {
    /// Генерация новых метаданных с использованием системного CSPRNG
    pub fn new() -> Self {
        Metadata {
            salt: sys::random_array().expect("Failed to generate salt"),
            iv: sys::random_array().expect("Failed to generate IV"),
        }
    }

    /// Сериализация метаданных в байты (salt || iv)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.iv);
        bytes
    }

    /// Десериализация метаданных из байтов
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_serialization_roundtrip() {
        let original = Metadata::new();
        let bytes = original.to_bytes();
        let restored = Metadata::from_bytes(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn invalid_data_length() {
        let data = vec![0u8; 47];
        assert!(Metadata::from_bytes(&data).is_err());
    }
}