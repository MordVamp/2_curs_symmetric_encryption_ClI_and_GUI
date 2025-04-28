//! CLI entry point
use crypto_app::cli::{self, Args};
use clap::Parser;
use crypto_app::core::io::{file, folder};

fn main() {
    let args = cli::Args::parse();
    
    match &args.command {
        cli::Command::EncryptFile { password, input, output } => {
            file::encrypt_file(input, output, password)
                .unwrap_or_else(|e| eprintln!("Error: {}", e));
        }
        cli::Command::DecryptFile { password, input, output } => {
            file::decrypt_file(input, output, password)
                .unwrap_or_else(|e| eprintln!("Error: {}", e));
        }
        cli::Command::EncryptDir { password, input, output } => {
            folder::encrypt_directory(input, output, password)
                .unwrap_or_else(|e| eprintln!("Error: {}", e));
        }
        cli::Command::DecryptDir { password, input, output } => {
            folder::decrypt_directory(input, output, password)
                .unwrap_or_else(|e| eprintln!("Error: {}", e));
        }
    }
}