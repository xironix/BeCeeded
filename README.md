# BeCeeded

A Rust implementation of the CEED Parser, providing high-performance cryptocurrency seed phrase parsing and wallet generation.

## Features

- **High-Performance Parsing**: Efficiently parse and validate BIP-39 seed phrases
- **Mnemonic Generation**: Generate new random mnemonics with various word counts (12, 15, 18, 21, 24)
- **Wallet Support**: Create wallets for Bitcoin, Bitcoin Testnet, and Ethereum
- **Multi-language Support**: Process seed phrases in multiple languages
- **Memory Safety**: Secure memory handling for sensitive cryptographic material
- **Command-line Interface**: Easy-to-use CLI for common operations
- **Advanced Scanner**: Scan files and directories for potential cryptocurrency seed phrases and private keys
- **Multiple Scan Modes**: Configure scan depth and performance trade-offs based on your needs

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/beceeded.git
cd beceeded

# Build in release mode
cargo build --release

# The binary will be in target/release/beceeded
```

### Using Cargo

```bash
cargo install beceeded
```

## Usage

### Command-line Interface

```bash
# Generate a new 12-word mnemonic
beceeded generate

# Generate a 24-word mnemonic
beceeded generate --words 24

# Parse and validate a mnemonic
beceeded parse "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Generate a Bitcoin wallet from a mnemonic
beceeded wallet "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Generate an Ethereum wallet with a passphrase
beceeded wallet "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --passphrase "my secure passphrase" --network ethereum
```

### Library Usage

```rust
use beceeded::{
    init,
    parser::Parser,
    mnemonic::Mnemonic,
    wallet::{Wallet, Network},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    init()?;
    
    // Create a parser
    let parser = Parser::default()?;
    
    // Parse a mnemonic
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase, parser.clone())?;
    
    // Generate a wallet
    let wallet = Wallet::from_mnemonic(&mnemonic, Network::Bitcoin, None)?;
    
    // Print the wallet address
    println!("Wallet address: {}", wallet.address());
    
    Ok(())
}
```

## Benchmarks

Run benchmarks with:

```bash
cargo bench
```

## Testing

Run tests with:

```bash
cargo test
```

## Security Considerations

- **Memory Safety**: Sensitive data like private keys and seed phrases are stored in secure memory that is zeroed when dropped
- **No Logging**: Sensitive information is never logged
- **No Network**: The library doesn't make any network requests, ensuring all operations are local

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Original C implementation: [CEED Parser](https://github.com/yourusername/ceed_parser)
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for mnemonic seed phrase specification
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) and [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) for hierarchical deterministic wallet specification

### Scanner Usage

BeCeeded includes a powerful scanner for finding cryptocurrency seed phrases and private keys in files:

```bash
# Basic scan of a directory
bcscan --directory /path/to/scan

# Use fast mode for quick results
bcscan --directory /path/to/scan --mode fast

# Comprehensive scan with all features enabled
bcscan --directory /path/to/scan --mode comprehensive

# Scan with 8 threads
bcscan --directory /path/to/scan --threads 8

# Scan with custom database path
bcscan --directory /path/to/scan --database results.db
```

#### Scan Modes

The scanner offers four operational modes that allow you to balance between speed and thoroughness:

| Mode | Description | Use Case | Relative Speed |
|------|-------------|----------|---------------|
| `fast` | Text files only, no fuzzy matching | Initial quick scan | 10x |
| `default` | Text files with fuzzy matching | General usage | 5x |
| `enhanced` | Adds OCR for images | When images might contain phrases | 2x |
| `comprehensive` | All file types including archives, docs, PDFs | Forensic analysis | 1x | 