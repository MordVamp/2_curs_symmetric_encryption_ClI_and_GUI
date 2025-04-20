//! Платформозависимые системные операции

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

use std::io::Error;

/// Кроссплатформенный интерфейс для CSPRNG
pub fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}

#[cfg(target_os = "linux")]
use self::linux::fill_random;
#[cfg(target_os = "windows")]
use self::windows::fill_random;