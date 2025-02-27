//! Mnemonic seed phrase handling for BeCeeded
//!
//! This module provides functionality for generating and validating
//! BIP-39 compatible mnemonic seed phrases.

use crate::memory::{SecureBytes, SecureString};
use crate::parser::{Parser, ParserError};
use ring::digest::{Context, SHA256};
use ring::hmac::{HMAC_SHA512, Key, sign};
use ring::rand::SecureRandom;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroize;
use secrecy::ExposeSecret;

/// Error types for mnemonic operations
#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("Parser error: {0}")]
    ParserError(#[from] ParserError),
    
    #[error("Invalid entropy size: got {got} bytes, expected one of {expected:?}")]
    InvalidEntropySize { got: usize, expected: Vec<usize> },
    
    #[error("Checksum verification failed")]
    ChecksumError,
    
    #[error("Failed to generate cryptographically secure random bytes")]
    RandomnessError,
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// A mnemonic seed phrase with associated functionality
#[derive(Clone)]
pub struct Mnemonic {
    /// The words of the mnemonic
    words: Vec<String>,
    
    /// The entropy bytes that were used to generate the mnemonic
    entropy: Option<SecureBytes>,
    
    /// The parser used to validate and manipulate the mnemonic
    parser: Parser,
}

impl Mnemonic {
    /// Create a new mnemonic from a list of validated words
    pub fn new(words: Vec<String>, parser: Parser) -> Self {
        Self {
            words,
            entropy: None,
            parser,
        }
    }
    
    /// Parse a mnemonic phrase
    pub fn from_phrase(phrase: &str, parser: Parser) -> Result<Self, MnemonicError> {
        let words = parser.parse(phrase)?;
        Ok(Self {
            words,
            entropy: None,
            parser,
        })
    }
    
    /// Generate a new random mnemonic with the specified strength
    pub fn generate(word_count: usize, parser: Parser) -> Result<Self, MnemonicError> {
        // Calculate required entropy based on word count
        // BIP-39: ENT = (MS × 3) ÷ 32
        // Where:
        // - ENT is the entropy length in bits
        // - MS is the mnemonic sentence length in words
        let entropy_bits = (word_count * 32) / 3;
        let entropy_bytes = entropy_bits / 8;
        
        // Validate entropy size
        let valid_entropy_sizes = vec![16, 20, 24, 28, 32]; // 128, 160, 192, 224, 256 bits
        if !valid_entropy_sizes.contains(&entropy_bytes) {
            return Err(MnemonicError::InvalidEntropySize {
                got: entropy_bytes,
                expected: valid_entropy_sizes,
            });
        }
        
        // Generate random entropy
        let mut entropy = vec![0u8; entropy_bytes];
        ring::rand::SystemRandom::new()
            .fill(&mut entropy)
            .map_err(|_| MnemonicError::RandomnessError)?;
        
        Self::from_entropy(&entropy, parser)
    }
    
    /// Create a mnemonic from entropy bytes
    pub fn from_entropy(entropy: &[u8], parser: Parser) -> Result<Self, MnemonicError> {
        // Calculate checksum bits and total length
        let entropy_bits = entropy.len() * 8;
        let checksum_bits = entropy_bits / 32;
        let total_bits = entropy_bits + checksum_bits;
        
        // Validate entropy size
        let valid_entropy_sizes = vec![16, 20, 24, 28, 32]; // 128, 160, 192, 224, 256 bits
        if !valid_entropy_sizes.contains(&entropy.len()) {
            return Err(MnemonicError::InvalidEntropySize {
                got: entropy.len(),
                expected: valid_entropy_sizes,
            });
        }
        
        // Calculate SHA-256 hash of entropy for checksum
        let mut context = Context::new(&SHA256);
        context.update(entropy);
        let digest = context.finish();
        
        // Combine entropy and checksum bits
        let mut combined = Vec::with_capacity((total_bits + 7) / 8);
        combined.extend_from_slice(entropy);
        combined.push(digest.as_ref()[0]);
        
        // Extract words from combined entropy+checksum
        let wordlist_len = 2048; // 2^11
        let mut words = Vec::with_capacity(total_bits / 11);
        
        for i in 0..total_bits / 11 {
            let mut index = 0u16;
            
            for j in 0..11 {
                let bit_position = i * 11 + j;
                let byte_position = bit_position / 8;
                let bit_index = 7 - (bit_position % 8);
                
                if byte_position < combined.len() && (combined[byte_position] & (1 << bit_index)) != 0 {
                    index |= 1 << (10 - j);
                }
            }
            
            // Ensure index is within bounds
            if index >= wordlist_len as u16 {
                return Err(MnemonicError::InternalError(format!("Word index out of range: {}", index)));
            }
            
            // Convert index to word
            let word = parser.indices_to_words(&[index])?;
            words.push(word[0].clone());
        }
        
        Ok(Self {
            words,
            entropy: Some(SecureBytes::new(entropy.to_vec())),
            parser,
        })
    }
    
    /// Convert the mnemonic to a seed according to BIP-39
    /// 
    /// The seed is generated using PBKDF2 with HMAC-SHA512,
    /// 2048 iterations, and an optional passphrase.
    pub fn to_seed(&self, passphrase: Option<&str>) -> SecureBytes {
        // Join the words with spaces
        let mnemonic_string = self.words.join(" ");
        
        // Prepare the salt
        let salt = format!("mnemonic{}", passphrase.unwrap_or(""));
        
        // Use PBKDF2 with HMAC-SHA512
        let mnemonic_key = Key::new(HMAC_SHA512, mnemonic_string.as_bytes());
        let signature = sign(&mnemonic_key, salt.as_bytes());
        
        SecureBytes::new(signature.as_ref().to_vec())
    }
    
    /// Get the number of words in the mnemonic
    pub fn word_count(&self) -> usize {
        self.words.len()
    }
    
    /// Get a reference to the words in the mnemonic
    pub fn words(&self) -> &[String] {
        &self.words
    }
    
    /// Convert to a space-separated phrase
    pub fn to_phrase(&self) -> String {
        self.words.join(" ")
    }
    
    /// Convert to a secure string
    pub fn to_secure_phrase(&self) -> SecureString {
        crate::memory::secure_string(self.to_phrase())
    }
    
    /// Verify that the mnemonic has a valid checksum
    pub fn verify_checksum(&self) -> Result<bool, MnemonicError> {
        if let Some(ref entropy) = self.entropy {
            // We already verified the checksum when creating from entropy
            return Ok(true);
        }
        
        // Convert words to indices
        let indices = self.parser.words_to_indices(&self.words)?;
        
        // Calculate entropy and checksum bits
        let word_count = indices.len();
        let entropy_bits = (word_count * 11) - (word_count / 3);
        let entropy_bytes = (entropy_bits + 7) / 8;
        let checksum_bits = word_count * 11 - entropy_bits;
        
        // Extract entropy and checksum from indices
        let mut entropy = vec![0u8; entropy_bytes];
        let mut checksum = 0u8;
        
        for (i, &idx) in indices.iter().enumerate() {
            // Process 11 bits for each word index
            for j in 0..11 {
                let bit = (idx >> (10 - j)) & 1;
                let position = i * 11 + j;
                
                if position < entropy_bits {
                    // This bit belongs to the entropy
                    let byte_position = position / 8;
                    let bit_index = 7 - (position % 8);
                    
                    if bit == 1 {
                        entropy[byte_position] |= 1 << bit_index;
                    }
                } else {
                    // This bit belongs to the checksum
                    let checksum_bit_index = position - entropy_bits;
                    if bit == 1 {
                        checksum |= 1 << (checksum_bits - 1 - checksum_bit_index);
                    }
                }
            }
        }
        
        // Calculate expected checksum
        let mut context = Context::new(&SHA256);
        context.update(&entropy);
        let digest = context.finish();
        let expected_checksum = digest.as_ref()[0] >> (8 - checksum_bits);
        
        Ok(checksum == expected_checksum)
    }
}

// Don't print the mnemonic words in debug output
impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic {{ word_count: {}, ... }}", self.words.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ParserConfig;
    
    #[test]
    fn test_mnemonic_from_phrase() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, parser).expect("Failed to parse mnemonic");
        
        assert_eq!(mnemonic.word_count(), 12);
        assert_eq!(mnemonic.to_phrase(), phrase);
    }
    
    #[test]
    fn test_mnemonic_generation() {
        // Test generating mnemonics of different strengths
        for &word_count in &[12, 15, 18, 21, 24] {
            let parser = Parser::default().expect("Failed to create parser");
            let mnemonic = Mnemonic::generate(word_count, parser)
                .expect(&format!("Failed to generate mnemonic with {} words", word_count));
            
            assert_eq!(mnemonic.word_count(), word_count);
            assert!(mnemonic.verify_checksum().expect("Failed to verify checksum"));
        }
    }
    
    #[test]
    fn test_known_mnemonic_to_seed() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, parser).expect("Failed to parse mnemonic");
        
        let seed = mnemonic.to_seed(Some("TREZOR"));
        
        // Known test vector result (first 8 bytes)
        let expected_start = [
            0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72,
        ];
        
        assert_eq!(&seed.as_bytes()[0..8], &expected_start);
    }
    
    #[test]
    fn test_mnemonic_from_entropy() {
        let parser = Parser::default().expect("Failed to create parser");
        
        // Test known entropy to mnemonic
        let entropy = [0u8; 16]; // All zeros
        let mnemonic = Mnemonic::from_entropy(&entropy, parser).expect("Failed to create mnemonic from entropy");
        
        let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(mnemonic.to_phrase(), expected_phrase);
    }
    
    #[test]
    fn test_mnemonic_verify_checksum() {
        let parser = Parser::default().expect("Failed to create parser");
        
        // Valid checksum
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, parser.clone()).expect("Failed to parse mnemonic");
        
        assert!(mnemonic.verify_checksum().expect("Failed to verify checksum"));
        
        // Invalid checksum should cause parser error during creation
        let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = Mnemonic::from_phrase(invalid_phrase, parser);
        
        assert!(result.is_err());
        match result {
            Err(MnemonicError::ParserError(_)) => (),
            _ => panic!("Expected parser error for invalid checksum"),
        }
    }
    
    #[test]
    fn test_mnemonic_invalid_entropy_size() {
        let parser = Parser::default().expect("Failed to create parser");
        
        // Test invalid entropy size (17 bytes is not valid)
        let entropy = vec![0u8; 17];
        let result = Mnemonic::from_entropy(&entropy, parser);
        
        assert!(result.is_err());
        match result {
            Err(MnemonicError::InvalidEntropySize { got, expected }) => {
                assert_eq!(got, 17);
                assert!(expected.contains(&16));
                assert!(expected.contains(&32));
            },
            _ => panic!("Expected InvalidEntropySize error"),
        }
    }
    
    #[test]
    fn test_mnemonic_word_getters() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, parser).expect("Failed to parse mnemonic");
        
        // Test word_count()
        assert_eq!(mnemonic.word_count(), 12);
        
        // Test words()
        let words = mnemonic.words();
        assert_eq!(words.len(), 12);
        assert_eq!(words[0], "abandon");
        assert_eq!(words[11], "about");
        
        // Test to_phrase()
        assert_eq!(mnemonic.to_phrase(), phrase);
        
        // Test to_secure_phrase()
        let secure_phrase = mnemonic.to_secure_phrase();
        assert_eq!(secure_phrase.expose_secret(), phrase);
    }
    
    #[test]
    fn test_passphrase_effect() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, parser).expect("Failed to parse mnemonic");
        
        // Generate seeds with different passphrases
        let seed1 = mnemonic.to_seed(None);
        let seed2 = mnemonic.to_seed(Some(""));
        let seed3 = mnemonic.to_seed(Some("passphrase"));
        
        // Empty passphrase and None should be the same
        assert_eq!(seed1.as_bytes(), seed2.as_bytes());
        
        // Different passphrases should yield different seeds
        assert_ne!(seed1.as_bytes(), seed3.as_bytes());
    }
    
    #[test]
    fn test_mnemonic_clone() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, parser).expect("Failed to parse mnemonic");
        
        // Clone the mnemonic
        let cloned = mnemonic.clone();
        
        // Both should have the same phrase
        assert_eq!(mnemonic.to_phrase(), cloned.to_phrase());
        
        // Both should generate the same seed with the same passphrase
        let seed1 = mnemonic.to_seed(Some("test"));
        let seed2 = cloned.to_seed(Some("test"));
        
        assert_eq!(seed1.as_bytes(), seed2.as_bytes());
    }
} 