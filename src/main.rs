//! BeCeeded command-line interface
//!
//! This module provides a command-line interface for the BeCeeded library.

use beceeded::{
    init_with_log_level,
    mnemonic::Mnemonic,
    parser::{Parser, ParserConfig},
    wallet::{Network, Wallet},
};
use clap::{Parser as ClapParser, Subcommand};
use clap::builder::TypedValueParser;
use log::LevelFilter;
use std::path::PathBuf;

#[derive(ClapParser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets the log level
    #[arg(short, long, value_name = "LEVEL", 
          default_value_t = LevelFilter::Info,
          value_parser = clap::builder::PossibleValuesParser::new(["off", "error", "warn", "info", "debug", "trace"])
          .map(|s| match s.as_str() {
              "off" => LevelFilter::Off,
              "error" => LevelFilter::Error,
              "warn" => LevelFilter::Warn,
              "info" => LevelFilter::Info,
              "debug" => LevelFilter::Debug,
              "trace" => LevelFilter::Trace,
              _ => unreachable!(),
          }))]
    log_level: LevelFilter,

    /// Path to wordlist directory
    #[arg(short, long, value_name = "DIR", default_value = "data")]
    wordlist_dir: PathBuf,

    /// Which wordlist to use
    #[arg(short, long, value_name = "NAME", default_value = "english")]
    wordlist: String,
    
    /// Use interactive CLI mode
    #[arg(short, long)]
    interactive: bool,

    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new mnemonic seed phrase
    Generate {
        /// Number of words in the mnemonic
        #[arg(short, long, default_value_t = 12)]
        words: usize,
    },
    /// Parse and validate a seed phrase
    Parse {
        /// The mnemonic seed phrase to parse
        #[arg(value_name = "PHRASE")]
        phrase: String,
    },
    /// Generate a wallet from a seed phrase
    Wallet {
        /// The mnemonic seed phrase to use
        #[arg(value_name = "PHRASE")]
        phrase: String,

        /// Optional passphrase for additional security
        #[arg(short, long)]
        passphrase: Option<String>,

        /// Network to generate wallet for
        #[arg(short, long, default_value = "bitcoin")]
        network: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Initialize logger
    init_with_log_level(cli.log_level)?;

    // Create parser config
    let config = ParserConfig {
        // Core config parameters
        validate_checksum: true,
        max_words: 24,
        valid_word_counts: vec![12, 15, 18, 21, 24],
        wordlist_name: cli.wordlist.clone(),
    };

    // Create parser
    let parser = Parser::new(cli.wordlist_dir, cli.wordlist.clone(), config)?;

    // Check if interactive mode was requested
    if cli.interactive {
        // Launch interactive CLI
        use beceeded::interactive::InteractiveCli;
        let interactive_cli = InteractiveCli::new();
        return interactive_cli.run();
    }

    // Execute subcommand in standard mode
    match &cli.command {
        Commands::Generate { words } => {
            // Generate a new mnemonic
            let mnemonic = Mnemonic::generate(*words, parser)?;
            println!("Generated mnemonic: {}", mnemonic.to_phrase());
            Ok(())
        }
        Commands::Parse { phrase } => {
            // Parse and validate the mnemonic
            let mnemonic = Mnemonic::from_phrase(phrase, parser)?;
            
            // Verify checksum
            let valid = mnemonic.verify_checksum()?;
            
            println!("Mnemonic is valid: {}", valid);
            println!("Word count: {}", mnemonic.word_count());
            
            Ok(())
        }
        Commands::Wallet { phrase, passphrase, network } => {
            // Parse the mnemonic
            let mnemonic = Mnemonic::from_phrase(phrase, parser)?;
            
            // Determine the network
            let network = match network.to_lowercase().as_str() {
                "bitcoin" => Network::Bitcoin,
                "ethereum" => Network::Ethereum,
                _ => {
                    return Err(format!("Unsupported network: {}", network).into());
                }
            };
            
            // Generate wallet
            let wallet = Wallet::from_mnemonic(&mnemonic, network, passphrase.as_deref())?;
            
            // Display wallet info
            println!("Network: {:?}", wallet.network());
            println!("Address: {}", wallet.address());
            println!("Public Key: {}", wallet.export_public_key_hex());
            
            Ok(())
        }
    }
}
