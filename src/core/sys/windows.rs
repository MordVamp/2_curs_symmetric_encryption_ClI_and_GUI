use winapi::um::wincrypt::{CryptGenRandom, HCRYPTPROV};
use winapi::um::wincrypt::{PROV_RSA_FULL, CRYPT_VERIFYCONTEXT};
use std::ptr::null_mut;
use std::io::Error;

pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    let mut hprov: HCRYPTPROV = null_mut();

    unsafe {
        if winapi::um::wincrypt::CryptAcquireContextW(
            &mut hprov,
            null_mut(),
            null_mut(),
            PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT,
        ) == 0
        {
            return Err(Error::last_os_error());
        }

        if CryptGenRandom(hprov, buf.len() as u32, buf.as_mut_ptr()) == 0 {
            let err = Error::last_os_error();
            winapi::um::wincrypt::CryptReleaseContext(hprov, 0);
            return Err(err);
        }

        winapi::um::wincrypt::CryptReleaseContext(hprov, 0);
    }

    Ok(())
}