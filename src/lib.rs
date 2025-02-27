//! BeCeeded - A Rust implementation of the CEED Parser
//!
//! This library provides functionality for parsing and validating cryptocurrency seed phrases,
//! generating wallets, and other related cryptographic operations.

// Re-export modules
pub mod parser;
pub mod mnemonic;
pub mod wallet;
pub mod memory;
pub mod logger;

// Public re-exports
pub use parser::{Parser, ParserConfig, ParserError};
pub use mnemonic::{Mnemonic, MnemonicError};
pub use wallet::{Wallet, WalletError};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the library with default settings
pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    logger::init_logger(log::LevelFilter::Info)?;
    log::info!("BeCeeded v{} initialized", VERSION);
    Ok(())
}

/// Initialize the library with custom log level
pub fn init_with_log_level(level: log::LevelFilter) -> Result<(), Box<dyn std::error::Error>> {
    logger::init_logger(level)?;
    log::info!("BeCeeded v{} initialized with log level {:?}", VERSION, level);
    Ok(())
} 