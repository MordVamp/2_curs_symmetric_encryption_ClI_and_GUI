use libc::{self, c_void, size_t};
use std::io::Error;

pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    let mut filled = 0;
    while filled < buf.len() {
        let result = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr() as *mut c_void,
                (buf.len() - filled) as size_t,
                0
            )
        };

        if result < 0 {
            let err = Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }

        filled += result as usize;
    }
    Ok(())
}