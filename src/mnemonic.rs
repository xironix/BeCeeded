/**
 * Mnemonic seed phrase implementation for BeCeeded
 * 
 * This module provides a secure implementation of BIP-39 and Monero mnemonics
 * with a focus on performance and security.
 * 
 * # Performance Considerations
 * 
 * - Critical path functions are marked with `#[inline]` to encourage inlining
 * - Memory-sensitive operations use pre-allocation when possible
 * - Entropy generation and validation is optimized for speed
 * - Unicode normalization is handled efficiently for all languages
 */

use crate::memory::{SecureBytes, SecureString};
use crate::parser::{Parser, ParserError};
use ring::digest::{Context, SHA256};
use ring::hmac::{HMAC_SHA512, Key, sign};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, Secret};
use std::fmt;
use thiserror::Error;
#[cfg(test)]
use secrecy::ExposeSecret;

/// Errors related to mnemonic operations
#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("Invalid entropy size: expected {expected:?}, got {actual:?}")]
    InvalidEntropySize { expected: Vec<usize>, actual: usize },
    
    #[error("Error generating entropy: {0}")]
    EntropyGenerationError(String),
    
    #[error("Parser error: {0}")]
    ParserError(#[from] ParserError),
    
    #[error("Invalid word count: expected one of {expected:?}, got {actual:?}")]
    InvalidWordCount { expected: Vec<usize>, actual: usize },
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Represents a mnemonic phrase with associated functionality
#[derive(Clone)]
pub struct Mnemonic {
    /// The words of the mnemonic
    words: Vec<String>,
    
    /// The parser used to validate and manipulate the mnemonic
    parser: Parser,
}

impl Mnemonic {
    /// Create a new mnemonic from a phrase
    #[inline]
    pub fn from_phrase(phrase: &str, parser: Parser) -> Result<Self, MnemonicError> {
        let words = parser.parse(phrase)?;
        
        Ok(Self { words, parser })
    }
    
    /// Create a new mnemonic from entropy bytes
    #[inline]
    pub fn from_entropy(entropy: &[u8], parser: Parser) -> Result<Self, MnemonicError> {
        // Validate entropy length
        let entropy_len = entropy.len() * 8;
        
        // Calculate expected word count based on entropy bits
        let word_count = match entropy_len {
            128 => 12,
            160 => 15,
            192 => 18,
            224 => 21,
            256 => 24,
            _ => {
                let valid_sizes = vec![128, 160, 192, 224, 256];
                let expected_bytes = valid_sizes.iter().map(|bits| bits / 8).collect();
                return Err(MnemonicError::InvalidEntropySize {
                    expected: expected_bytes,
                    actual: entropy.len(),
                });
            }
        };
        
        // Calculate checksum bits (1 bit per 32 bits of entropy)
        let checksum_bits = word_count / 3;
        
        // Calculate total bits needed
        let total_bits = entropy_len + checksum_bits;
        
        // Create a buffer for entropy + checksum bits
        let mut bits = Vec::with_capacity((total_bits + 7) / 8);
        bits.extend_from_slice(entropy);
        
        // Calculate checksum by taking the first [checksum_bits] bits of the SHA-256 hash
        let checksum_byte = {
            let mut context = Context::new(&SHA256);
            context.update(entropy);
            context.finish().as_ref()[0]
        };
        
        // Add the checksum byte
        bits.push(checksum_byte);
        
        // Convert bits to indices
        let mut indices = Vec::with_capacity(word_count);
        for i in 0..word_count {
            let start_bit = i * 11;
            let mut index: u16 = 0;
            
            // Fast path for common bit patterns using unsafe for performance
            #[allow(unsafe_code)]
            unsafe {
                let byte_idx = start_bit / 8;
                let bit_offset = start_bit % 8;
                
                // First byte contribution
                let first_byte = *bits.get_unchecked(byte_idx);
                let bits_from_first = 8 - bit_offset;
                let mask = 0xFF >> bit_offset;
                let contribution = (first_byte & mask) as u16;
                
                index = contribution << (11 - bits_from_first);
                
                // Second byte contribution (always needed for 11 bits)
                if byte_idx + 1 < bits.len() {
                    let second_byte = *bits.get_unchecked(byte_idx + 1);
                    let bits_from_second = if bits_from_first >= 11 { 0 } else { 
                        std::cmp::min(8, 11 - bits_from_first) 
                    };
                    
                    if bits_from_second > 0 {
                        index |= (second_byte >> (8 - bits_from_second)) as u16;
                    }
                }
                
                // Third byte contribution (only needed in some cases)
                if bits_from_first + 8 < 11 && byte_idx + 2 < bits.len() {
                    let third_byte = *bits.get_unchecked(byte_idx + 2);
                    let bits_from_third = 11 - bits_from_first - 8;
                    
                    if bits_from_third > 0 {
                        let mask = 0xFF << (8 - bits_from_third);
                        let contribution = (third_byte & mask) as u16;
                        index |= contribution >> (8 - bits_from_third);
                    }
                }
            }
            
            indices.push(index);
        }
        
        // Convert indices to words
        let words = parser.indices_to_words(&indices)?;
        
        Ok(Self { words, parser })
    }
    
    /// Generate a new random mnemonic
    #[inline]
    pub fn generate(word_count: usize, parser: Parser) -> Result<Self, MnemonicError> {
        // Calculate the entropy length based on word count
        let entropy_bytes = match word_count {
            12 => 16, // 128 bits
            15 => 20, // 160 bits
            18 => 24, // 192 bits
            21 => 28, // 224 bits
            24 => 32, // 256 bits
            _ => {
                return Err(MnemonicError::InvalidWordCount {
                    expected: vec![12, 15, 18, 21, 24],
                    actual: word_count,
                });
            }
        };
        
        // Generate random entropy
        let rng = SystemRandom::new();
        let mut entropy = vec![0u8; entropy_bytes];
        
        rng.fill(&mut entropy)
            .map_err(|_| MnemonicError::EntropyGenerationError("Failed to generate random entropy".to_string()))?;
        
        // Create a mnemonic from the entropy
        Self::from_entropy(&entropy, parser)
    }
    
    /// Get the number of words in the mnemonic
    #[inline]
    pub fn word_count(&self) -> usize {
        self.words.len()
    }
    
    /// Get the mnemonic phrase as a string
    #[inline]
    pub fn to_phrase(&self) -> String {
        // Handle CJK languages differently (no spaces)
        let is_cjk = self.parser.wordlist_name().contains("chinese") || 
                     self.parser.wordlist_name().contains("japanese") || 
                     self.parser.wordlist_name().contains("korean");
        
        // Handle special case for Chinese Monero wordlists
        let is_chinese_monero = 
            self.parser.wordlist_name().starts_with("monero_") && 
            self.parser.wordlist_name().contains("chinese");
        
        if is_cjk && !is_chinese_monero {
            // Join without spaces for CJK languages (except Chinese Monero)
            self.words.join("")
        } else {
            // Join with spaces for all other languages
            self.words.join(" ")
        }
    }
    
    /// Get the mnemonic phrase as a secure string
    #[inline]
    pub fn to_secure_phrase(&self) -> SecureString {
        SecureString::from(self.to_phrase())
    }
    
    /// Verify the checksum of the mnemonic
    #[inline]
    pub fn verify_checksum(&self) -> Result<bool, MnemonicError> {
        // Create a parser with checksum validation enabled
        let mut config = self.parser.config().clone();
        config.validate_checksum = true;
        
        let parser_with_checksum = Parser::with_provider(
            self.parser.provider(),
            config,
        ).map_err(MnemonicError::ParserError)?;
        
        // Try to parse the mnemonic with checksum validation
        match parser_with_checksum.parse(&self.to_phrase()) {
            Ok(_) => Ok(true),
            Err(ParserError::ChecksumError) | Err(ParserError::MoneroChecksumError) => Ok(false),
            Err(e) => Err(MnemonicError::ParserError(e)),
        }
    }
    
    /// Generate a seed from the mnemonic
    /// 
    /// This is a performance-critical function as it's used in wallet derivation paths
    #[inline]
    pub fn to_seed(&self, passphrase: Option<&str>) -> Secret<Vec<u8>> {
        // Prepare the mnemonic input
        let mnemonic = self.to_phrase();
        
        // Prepare the salt with the passphrase
        let salt = format!("mnemonic{}", passphrase.unwrap_or(""));
        
        // Use PBKDF2 to derive the seed
        // Parameters from BIP-39: HMAC-SHA512, 2048 iterations
        const PBKDF2_ITERATIONS: u32 = 2048;
        const PBKDF2_DIGEST: hmac::Algorithm = hmac::HMAC_SHA512;
        
        // Pre-allocate output buffer (64 bytes for SHA-512)
        let mut seed = vec![0u8; 64];
        
        // Use PBKDF2 from ring crate
        pbkdf2::derive(
            PBKDF2_DIGEST,
            std::num::NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt.as_bytes(),
            mnemonic.as_bytes(),
            &mut seed,
        );
        
        Secret::new(seed)
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mnemonic")
            .field("word_count", &self.words.len())
            .field("wordlist", &self.parser.wordlist_name())
            .finish()
    }
}

/// Expose the first few characters of each word for debugging
#[cfg(test)]
impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let masked_words: Vec<String> = self.words.iter()
            .map(|word| {
                let chars: Vec<char> = word.chars().collect();
                if chars.len() <= 2 {
                    word.clone()
                } else {
                    let visible: String = chars.iter().take(2).collect();
                    format!("{}...", visible)
                }
            })
            .collect();
        
        write!(f, "[{}]", masked_words.join(" "))
    }
}

/// Reexport the PBKDF2 implementation for seed generation 
pub use pbkdf2;

/// Module with benchmarking instructions
#[cfg(feature = "criterion")]
pub mod benchmarks {
    use super::*;
    
    /// Benchmark mnemonic generation with different word counts
    pub fn bench_mnemonic_generation(criterion: &mut criterion::Criterion) {
        let parser = Parser::default().expect("Failed to create parser");
        
        let mut group = criterion.benchmark_group("mnemonic_generation");
        for &word_count in &[12, 15, 18, 21, 24] {
            group.bench_function(format!("generate_{}_words", word_count), |b| {
                b.iter(|| Mnemonic::generate(word_count, parser.clone()))
            });
        }
        group.finish();
    }
    
    /// Benchmark seed generation with and without passphrase
    pub fn bench_seed_generation(criterion: &mut criterion::Criterion) {
        let parser = Parser::default().expect("Failed to create parser");
        let mnemonic = Mnemonic::generate(12, parser).expect("Failed to generate mnemonic");
        
        let mut group = criterion.benchmark_group("seed_generation");
        group.bench_function("without_passphrase", |b| {
            b.iter(|| mnemonic.to_seed(None))
        });
        
        group.bench_function("with_passphrase", |b| {
            b.iter(|| mnemonic.to_seed(Some("test_passphrase")))
        });
        group.finish();
    }
    
    /// Benchmark checksum verification
    pub fn bench_verify_checksum(criterion: &mut criterion::Criterion) {
        let parser = Parser::default().expect("Failed to create parser");
        let mnemonic = Mnemonic::generate(12, parser).expect("Failed to generate mnemonic");
        
        criterion.bench_function("verify_checksum", |b| {
            b.iter(|| mnemonic.verify_checksum())
        });
    }
} 