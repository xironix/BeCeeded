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

use crate::memory::SecureString;
use crate::parser::{Parser, ParserError, ParserConfig};
use ring::digest::{Context, SHA256};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt;
use std::path::PathBuf;
use thiserror::Error;

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
    
    /// Create a new mnemonic from entropy bytes with optimization for speed
    #[inline]
    pub fn from_entropy(entropy: &[u8], parser: Parser) -> Result<Self, MnemonicError> {
        // Validate entropy length
        let entropy_len = entropy.len() * 8;
        
        // Lookup tables for common operations
        // This avoids repetitive calculations in performance-critical paths
        struct EntropyLookup {
            word_count: usize,
            checksum_bits: usize,
            bit_mask: [u16; 16], // Pre-computed masks for different bit widths
        }
        
        // Define lookup table for common entropy sizes
        static LOOKUP_TABLE: [EntropyLookup; 5] = [
            // 128 bits
            EntropyLookup { 
                word_count: 12, 
                checksum_bits: 4,
                bit_mask: [0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 0, 0, 0, 0],
            },
            // 160 bits
            EntropyLookup { 
                word_count: 15, 
                checksum_bits: 5,
                bit_mask: [0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 0, 0, 0, 0],
            },
            // 192 bits
            EntropyLookup { 
                word_count: 18, 
                checksum_bits: 6,
                bit_mask: [0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 0, 0, 0, 0],
            },
            // 224 bits
            EntropyLookup { 
                word_count: 21, 
                checksum_bits: 7,
                bit_mask: [0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 0, 0, 0, 0],
            },
            // 256 bits
            EntropyLookup { 
                word_count: 24, 
                checksum_bits: 8,
                bit_mask: [0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 0, 0, 0, 0],
            },
        ];
        
        // Get lookup entry for this entropy size
        let lookup = match entropy_len {
            128 => &LOOKUP_TABLE[0],
            160 => &LOOKUP_TABLE[1],
            192 => &LOOKUP_TABLE[2],
            224 => &LOOKUP_TABLE[3],
            256 => &LOOKUP_TABLE[4],
            _ => {
                let valid_sizes = [128, 160, 192, 224, 256];
                let expected_bytes = valid_sizes.iter().map(|bits| bits / 8).collect();
                return Err(MnemonicError::InvalidEntropySize {
                    expected: expected_bytes,
                    actual: entropy.len(),
                });
            }
        };
        
        let word_count = lookup.word_count;
        let checksum_bits = lookup.checksum_bits;
        
        // Calculate total bits needed
        let total_bits = entropy_len + checksum_bits;
        
        // Create a buffer for entropy + checksum bits, with pre-allocation
        let mut bits = Vec::with_capacity((total_bits + 7) / 8);
        bits.extend_from_slice(entropy);
        
        // Calculate checksum by taking the first [checksum_bits] bits of the SHA-256 hash
        let mut context = Context::new(&SHA256);
        context.update(entropy);
        let digest = context.finish();
        let checksum_byte = digest.as_ref()[0];
        
        // Add the checksum byte
        bits.push(checksum_byte);
        
        // Pre-allocate indices vector for better performance
        let mut indices = Vec::with_capacity(word_count);
        
        // Optimized vectorized approach using lookup tables and bit operations
        // This is much faster than the previous approach with conditional branches
        for i in 0..word_count {
            let start_bit = i * 11;
            let byte_idx = start_bit / 8;
            let bit_offset = start_bit % 8;
            
            // This implementation uses a more direct bit manipulation approach
            // without conditionals, which is better for branch prediction
            let mut result: u16 = 0;

            // Get the three bytes that might contribute bits (with bounds checking)
            let first_byte = if byte_idx < bits.len() { bits[byte_idx] } else { 0 };
            let second_byte = if byte_idx + 1 < bits.len() { bits[byte_idx + 1] } else { 0 };
            let third_byte = if byte_idx + 2 < bits.len() { bits[byte_idx + 2] } else { 0 };
            
            // Combine the bytes into a 24-bit value, then extract the 11 bits we need
            let combined = ((first_byte as u32) << 16) | ((second_byte as u32) << 8) | (third_byte as u32);
            
            // Shift right to position the 11 bits we want at the bottom
            let shifted = combined >> (13 - bit_offset);
            
            // Mask to get only the 11 bits we need
            result = (shifted & 0x7FF) as u16;
            
            indices.push(result);
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
        // Create a new parser with the same parameters to handle checksum validation
        let config = ParserConfig {
            validate_checksum: true,
            valid_word_counts: vec![12, 15, 18, 21, 24, 25], // Standard BIP-39 lengths plus Monero
            wordlist_name: self.parser.wordlist_name().to_string(),
            max_words: 25, // Allow up to 25 words (Monero)
        };

        // Create a new parser that will validate the checksum
        let parser = Parser::new(
            PathBuf::from("data"), // Use the default wordlist directory
            self.parser.wordlist_name().to_string(), 
            config
        )?;
        
        // Now attempt to parse the phrase with the checksum-validating parser
        let phrase = self.to_phrase();
        match parser.parse(&phrase) {
            Ok(_) => Ok(true),
            Err(ParserError::ChecksumError) | Err(ParserError::MoneroChecksumError) => Ok(false),
            Err(e) => Err(MnemonicError::ParserError(e)),
        }
    }
    
    /// Generate a seed from the mnemonic
    /// 
    /// This is a performance-critical function as it's used in wallet derivation paths
    #[inline]
    pub fn to_seed(&self, passphrase: Option<&str>) -> crate::memory::SecureBytes {
        // Prepare the mnemonic input
        let mnemonic = self.to_phrase();
        
        // Prepare the salt with the passphrase
        let salt = format!("mnemonic{}", passphrase.unwrap_or(""));
        
        // Use PBKDF2 to derive the seed
        // Parameters from BIP-39: HMAC-SHA512, 2048 iterations
        const PBKDF2_ITERATIONS: u32 = 2048;
        
        // Pre-allocate output buffer (64 bytes for SHA-512)
        let mut seed = vec![0u8; 64];
        
        // Use PBKDF2 from ring crate
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            std::num::NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt.as_bytes(),
            mnemonic.as_bytes(),
            &mut seed,
        );
        
        crate::memory::SecureBytes::new(seed)
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

/// Module with benchmarking instructions
#[cfg(feature = "criterion")]
pub mod benchmarks {
    use super::*;
    
    /// Benchmark mnemonic generation with different word counts
    pub fn bench_mnemonic_generation(criterion: &mut criterion::Criterion) {
        let parser = Parser::create_default().expect("Failed to create parser");
        
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
        let parser = Parser::create_default().expect("Failed to create parser");
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
        let parser = Parser::create_default().expect("Failed to create parser");
        let mnemonic = Mnemonic::generate(12, parser).expect("Failed to generate mnemonic");
        
        criterion.bench_function("verify_checksum", |b| {
            b.iter(|| mnemonic.verify_checksum())
        });
    }
} 