//! CLI entry point
use crypto_app::cli::{self, Args};
use clap::Parser;
use crypto_app::core::io::{file, folder};

fn main() {
    let args = cli::Args::parse();
    
    match &args.command {
        cli::Command::EncryptFile { password, input, output } => {
            if let Err(e) = file::encrypt_file(input, output, password) {
                eprintln!("❌Ошибка шифрования файла: {}💧", e);
            } else {
                println!("✅ Файл успешно зашифрован и сохранен в: {}", output.display());
            }
        }
        cli::Command::DecryptFile { password, input, output } => {
            if let Err(e) = file::decrypt_file(input, output, password) {
                eprintln!("❌Ошибка дешифрования файла: {}", e);
            } else {
                println!("✅ Файл успешно дешифрован и сохранен в: {}", output.display());
            }
        }
        cli::Command::EncryptDir { password, input, output } => {
            if let Err(e) = folder::encrypt_directory(input, output, password) {
                eprintln!("Ошибка шифрования директории: {}", e);
            } else {
                println!("✅ Директория успешно зашифрована и сохранена в: {}", output.display());
            }
        }
        cli::Command::DecryptDir { password, input, output } => {
            if let Err(e) = folder::decrypt_directory(input, output, password) {
                eprintln!("Ошибка дешифрования директории: {}", e);
            } else {
                println!("✅ Директория успешно дешифрована и сохранена в: {}", output.display());
            }
        }
    }
}