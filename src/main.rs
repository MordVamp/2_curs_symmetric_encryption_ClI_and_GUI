//! CLI entry point
use crypto_app::cli::{self, Args};
use clap::Parser;
use crypto_app::core::io::{file, folder};
use std::path::{PathBuf, Path};
use libc::{time_t, time, localtime_r, strftime, tm};
use std::ffi::CStr;
use std::fs;

const MAX_LOG_FILES: usize = 20;
const LOG_DIR: &str = "logs";

fn get_timestamp() -> String {
    let mut raw_time: time_t = 0;
    unsafe { time(&mut raw_time) };
    
    let mut tm_struct: tm = unsafe { std::mem::zeroed() };
    unsafe { localtime_r(&raw_time, &mut tm_struct) };
    
    let mut buffer = [0i8; 64];
    unsafe {
        strftime(
            buffer.as_mut_ptr(),
            buffer.len(),
            "%Y-%m-%d_%H-%M-%S".as_ptr() as *const _,
            &tm_struct
        );
    }
    
    unsafe {
        CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

fn ensure_log_dir() -> std::io::Result<()> {
    if !Path::new(LOG_DIR).exists() {
        fs::create_dir(LOG_DIR)?;
    }
    Ok(())
}

fn clean_old_logs() -> std::io::Result<()> {
    let mut entries = fs::read_dir(LOG_DIR)?
        .filter_map(|e| e.ok())
        .collect::<Vec<_>>();
    
    entries.sort_by_key(|e| e.metadata().ok()?.modified().ok());
    
    if entries.len() >= MAX_LOG_FILES {
        for entry in entries.drain(..entries.len() - MAX_LOG_FILES + 1) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn write_session_log(command: &str, status: &str, input: &PathBuf, output: &PathBuf, error: Option<String>) {
    let _ = ensure_log_dir();
    let _ = clean_old_logs();
    
    let timestamp = get_timestamp();
    let error_msg = error.map(|e| format!(" error: \"{}\"", e)).unwrap_or_default();
    let log_entry = format!(
        "[{}] {} {} input: \"{}\" output: \"{}\"{}",
        timestamp, command, status, input.display(), output.display(), error_msg
    );
    
    let filename = format!("{}/session_{}.log", LOG_DIR, timestamp);
    let _ = fs::write(filename, log_entry);
}

fn main() {
    let args = cli::Args::parse();
    
    match &args.command {
        cli::Command::EncryptFile { password, input, output } => {
            if let Err(e) = file::encrypt_file(input, output, password) {
                eprintln!("❌Ошибка шифрования файла: {}💧", e);
                write_session_log("EncryptFile", "FAILURE", input, output, Some(e.to_string()));
            } else {
                println!("✅ Файл успешно зашифрован и сохранен в: {}", output.display());
                write_session_log("EncryptFile", "SUCCESS", input, output, None);
            }
        }
        
        cli::Command::DecryptFile { password, input, output } => {
            if let Err(e) = file::decrypt_file(input, output, password) {
                eprintln!("❌Ошибка дешифрования файла: {}", e);
                write_session_log("DecryptFile", "FAILURE", input, output, Some(e.to_string()));
            } else {
                println!("✅ Файл успешно дешифрован и сохранен в: {}", output.display());
                write_session_log("DecryptFile", "SUCCESS", input, output, None);
            }
        }
        
        cli::Command::EncryptDir { password, input, output } => {
            if let Err(e) = folder::encrypt_directory(input, output, password) {
                eprintln!("Ошибка шифрования директории: {}", e);
                write_session_log("EncryptDir", "FAILURE", input, output, Some(e.to_string()));
            } else {
                println!("✅ Директория успешно зашифрована и сохранена в: {}", output.display());
                write_session_log("EncryptDir", "SUCCESS", input, output, None);
            }
        }
        
        cli::Command::DecryptDir { password, input, output } => {
            if let Err(e) = folder::decrypt_directory(input, output, password) {
                eprintln!("Ошибка дешифрования директории: {}", e);
                write_session_log("DecryptDir", "FAILURE", input, output, Some(e.to_string()));
            } else {
                println!("✅ Директория успешно дешифрована и сохранена в: {}", output.display());
                write_session_log("DecryptDir", "SUCCESS", input, output, None);
            }
        }
    }
}