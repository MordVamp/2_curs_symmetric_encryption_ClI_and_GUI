//! CLI logic using clap
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
    #[clap(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Command {
    EncryptFile {
        #[clap(short, long)]
        password: String,
        #[clap(short, long)]
        input: PathBuf,
        #[clap(short, long)]
        output: PathBuf,
    },
    DecryptFile {
        #[clap(short, long)]
        password: String,
        #[clap(short, long)]
        input: PathBuf,
        #[clap(short, long)]
        output: PathBuf,
    },
    EncryptDir {
        #[clap(short, long)]
        password: String,
        #[clap(short, long)]
        input: PathBuf,
        #[clap(short, long)]
        output: PathBuf,
    },
    DecryptDir {
        #[clap(short, long)]
        password: String,
        #[clap(short, long)]
        input: PathBuf,
        #[clap(short, long)]
        output: PathBuf,
    },
}