//! Seed phrase parser for BeCeeded
//!
//! This module provides functionality to parse and validate seed phrases
//! based on BIP-39 and other standards.

use crate::memory::SecureString;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use thiserror::Error;
use ring::digest::{Context, SHA256};
#[cfg(test)]
use secrecy::ExposeSecret;
use unicode_normalization::UnicodeNormalization;

/// Errors that can occur during parsing
#[derive(Debug, Error)]
pub enum ParserError {
    #[error("Failed to open wordlist file: {0}")]
    WordlistError(#[from] io::Error),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Word not found in wordlist: {0}")]
    WordNotFound(String),
    
    #[error("Checksum verification failed")]
    ChecksumError,
    
    #[error("Invalid word count: expected one of {expected:?}, got {actual}")]
    InvalidWordCount { expected: Vec<usize>, actual: usize },
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Configuration for the parser
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Path to the wordlist directory
    pub wordlist_dir: PathBuf,
    
    /// Name of the wordlist to use (e.g., "english")
    pub wordlist_name: String,
    
    /// Maximum number of words to accept (default: 24)
    pub max_words: usize,
    
    /// Whether to validate the checksum
    pub validate_checksum: bool,
    
    /// Valid word counts (typically 12, 15, 18, 21, 24)
    pub valid_word_counts: Vec<usize>,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            wordlist_dir: PathBuf::from("data"),
            wordlist_name: "english".to_string(),
            max_words: 24,
            validate_checksum: true,
            valid_word_counts: vec![12, 15, 18, 21, 24],
        }
    }
}

/// The seed phrase parser
#[derive(Debug, Clone)]
pub struct Parser {
    config: ParserConfig,
    wordlist: Vec<String>,
    word_indices: HashMap<String, u16>,
}

impl Parser {
    /// Create a new parser with the given configuration
    pub fn new(config: ParserConfig) -> Result<Self, ParserError> {
        let wordlist_path = config.wordlist_dir.join(format!("{}.txt", config.wordlist_name));
        let (wordlist, word_indices) = Self::load_wordlist(&wordlist_path)?;
        
        Ok(Self {
            config,
            wordlist,
            word_indices,
        })
    }
    
    /// Create a new parser with default configuration
    pub fn default() -> Result<Self, ParserError> {
        Self::new(ParserConfig::default())
    }
    
    /// Load wordlist from the given path
    fn load_wordlist(path: &Path) -> Result<(Vec<String>, HashMap<String, u16>), ParserError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let mut wordlist = Vec::with_capacity(2048);
        let mut word_indices = HashMap::with_capacity(2048);
        
        for (i, line) in reader.lines().enumerate() {
            // Normalize each word with NFKD
            let word = line?.nfkd().collect::<String>();
            word_indices.insert(word.clone(), i as u16);
            wordlist.push(word);
        }
        
        Ok((wordlist, word_indices))
    }
    
    /// Parse a mnemonic phrase into a list of validated words
    pub fn parse(&self, input: &str) -> Result<Vec<String>, ParserError> {
        // Clean the input and normalize with NFKD
        let input = input.trim().to_lowercase().nfkd().collect::<String>();
        
        // Split into words
        let words: Vec<&str> = input
            .split(|c: char| c.is_whitespace() || c.is_ascii_punctuation())
            .filter(|s| !s.is_empty())
            .collect();
        
        // Validate word count
        let word_count = words.len();
        if !self.config.valid_word_counts.contains(&word_count) {
            return Err(ParserError::InvalidWordCount {
                expected: self.config.valid_word_counts.clone(),
                actual: word_count,
            });
        }
        
        // Validate each word
        let mut validated_words = Vec::with_capacity(word_count);
        for word in words {
            if let Some(idx) = self.word_indices.get(word) {
                validated_words.push(self.wordlist[*idx as usize].clone());
            } else {
                return Err(ParserError::WordNotFound(word.to_string()));
            }
        }
        
        // Validate checksum if required
        if self.config.validate_checksum {
            self.validate_checksum(&validated_words)?;
        }
        
        Ok(validated_words)
    }
    
    /// Validate the checksum of a mnemonic according to BIP-39
    fn validate_checksum(&self, words: &[String]) -> Result<(), ParserError> {
        // Convert words to indices
        let indices = self.words_to_indices(words)?;
        
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
        
        // Calculate expected checksum using SHA-256
        let mut context = Context::new(&SHA256);
        context.update(&entropy);
        let digest = context.finish();
        let expected_checksum = digest.as_ref()[0] >> (8 - checksum_bits);
        
        // Compare checksums
        if checksum != expected_checksum {
            return Err(ParserError::ChecksumError);
        }
        
        Ok(())
    }
    
    /// Convert a list of words into their indices in the wordlist
    pub fn words_to_indices(&self, words: &[String]) -> Result<Vec<u16>, ParserError> {
        let mut indices = Vec::with_capacity(words.len());
        
        for word in words {
            if let Some(idx) = self.word_indices.get(word) {
                indices.push(*idx);
            } else {
                return Err(ParserError::WordNotFound(word.clone()));
            }
        }
        
        Ok(indices)
    }
    
    /// Convert a list of indices into their corresponding words
    pub fn indices_to_words(&self, indices: &[u16]) -> Result<Vec<String>, ParserError> {
        let mut words = Vec::with_capacity(indices.len());
        
        for &idx in indices {
            if idx < self.wordlist.len() as u16 {
                words.push(self.wordlist[idx as usize].clone());
            } else {
                return Err(ParserError::InternalError(format!("Index out of range: {}", idx)));
            }
        }
        
        Ok(words)
    }
    
    /// Parse securely, returning a SecureString
    pub fn parse_secure(&self, input: &str) -> Result<SecureString, ParserError> {
        let words = self.parse(input)?;
        Ok(crate::memory::secure_string(words.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parser_initialization() {
        let config = ParserConfig::default();
        let parser = Parser::new(config).expect("Failed to create parser");
        
        assert_eq!(parser.wordlist.len(), 2048);
        assert_eq!(parser.word_indices.len(), 2048);
    }
    
    #[test]
    fn test_parse_valid_mnemonic() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let words = parser.parse(mnemonic).expect("Failed to parse valid mnemonic");
        
        assert_eq!(words.len(), 12);
        assert_eq!(words[0], "abandon");
        assert_eq!(words[11], "about");
    }
    
    #[test]
    fn test_parse_invalid_word() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        let result = parser.parse(mnemonic);
        
        assert!(result.is_err());
        if let Err(ParserError::WordNotFound(word)) = result {
            assert_eq!(word, "notaword");
        } else {
            panic!("Expected WordNotFound error");
        }
    }
    
    #[test]
    fn test_parse_invalid_word_count() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let mnemonic = "abandon abandon";
        let result = parser.parse(mnemonic);
        
        assert!(result.is_err());
        if let Err(ParserError::InvalidWordCount { expected, actual }) = result {
            assert_eq!(actual, 2);
            assert!(expected.contains(&12));
            assert!(expected.contains(&24));
        } else {
            panic!("Expected InvalidWordCount error");
        }
    }
    
    #[test]
    fn test_checksum_validation_valid() {
        let parser = Parser::default().expect("Failed to create parser");
        
        // This is a valid mnemonic with correct checksum
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = parser.parse(mnemonic);
        
        assert!(result.is_ok(), "Valid mnemonic with correct checksum should be accepted");
    }
    
    #[test]
    fn test_checksum_validation_invalid() {
        let parser = Parser::default().expect("Failed to create parser");
        
        // This is an invalid mnemonic with incorrect checksum
        // "zoo" is replaced with "zero" which breaks the checksum
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zero";
        let result = parser.parse(mnemonic);
        
        assert!(result.is_err(), "Invalid checksum should be rejected");
        if let Err(ParserError::ChecksumError) = result {
            // This is the expected error
        } else if let Err(ParserError::WordNotFound(word)) = result {
            panic!("Word '{}' not found in wordlist, but this test requires valid words with invalid checksum", word);
        } else {
            panic!("Expected ChecksumError, got {:?}", result);
        }
    }
    
    #[test]
    fn test_parse_with_different_separators() {
        let parser = Parser::default().expect("Failed to create parser");
        
        // Test with different separators
        let mnemonic_spaces = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic_commas = "abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,about";
        let mnemonic_mixed = "abandon abandon,abandon\tabandon;abandon-abandon abandon.abandon\nabandon abandon abandon about";
        
        let words_spaces = parser.parse(mnemonic_spaces).expect("Failed to parse with spaces");
        let words_commas = parser.parse(mnemonic_commas).expect("Failed to parse with commas");
        let words_mixed = parser.parse(mnemonic_mixed).expect("Failed to parse with mixed separators");
        
        assert_eq!(words_spaces, words_commas);
        assert_eq!(words_spaces, words_mixed);
    }
    
    #[test]
    fn test_word_to_indices_conversion() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let words = vec![
            "abandon".to_string(),
            "ability".to_string(),
            "able".to_string(),
        ];
        
        let indices = parser.words_to_indices(&words).expect("Failed to convert words to indices");
        assert_eq!(indices, vec![0, 1, 2]);
        
        let converted_words = parser.indices_to_words(&indices).expect("Failed to convert indices to words");
        assert_eq!(converted_words, words);
    }
    
    #[test]
    fn test_different_wordlist() {
        // Create a config for the spanish wordlist
        let mut config = ParserConfig::default();
        config.wordlist_name = "spanish".to_string();
        config.validate_checksum = false; // Disable checksum validation for this test
        
        let parser = Parser::new(config).expect("Failed to create spanish parser");
        
        // Debug: Check if the Spanish wordlist is loaded correctly
        println!("Spanish wordlist length: {}", parser.wordlist.len());
        println!("First 5 words in Spanish wordlist: {:?}", &parser.wordlist[0..5]);
        
        // Spanish wordlist test with accented characters
        // The first word is "ábaco" with an accent on the first 'a'
        let spanish_mnemonic = "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abeja";
        let result = parser.parse(spanish_mnemonic);
        
        // Debug: Print the error if parsing failed
        if let Err(ref e) = result {
            println!("Error parsing Spanish mnemonic: {:?}", e);
        }
        
        assert!(result.is_ok(), "Valid Spanish words should be accepted with Unicode normalization");
        let words1 = result.as_ref().expect("Failed to parse valid Spanish words").clone();
        assert_eq!(words1.len(), 12);
        
        // Test with a different representation of the same accented character
        // Here we use a decomposed form of "á" (a + combining acute accent)
        let decomposed_a = "a\u{0301}"; // 'a' with combining acute accent
        let decomposed_mnemonic = format!("{}baco {}baco {}baco {}baco {}baco {}baco {}baco {}baco {}baco {}baco {}baco abeja",
            decomposed_a, decomposed_a, decomposed_a, decomposed_a, decomposed_a,
            decomposed_a, decomposed_a, decomposed_a, decomposed_a, decomposed_a, decomposed_a);
        
        let result2 = parser.parse(&decomposed_mnemonic);
        assert!(result2.is_ok(), "Decomposed Unicode form should also be accepted");
        
        // Both should parse to the same normalized words
        let words2 = result2.unwrap();
        assert_eq!(words1, words2, "Different Unicode representations should normalize to the same result");
    }
    
    #[test]
    fn test_secure_parsing() {
        let parser = Parser::default().expect("Failed to create parser");
        
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let secure = parser.parse_secure(mnemonic).expect("Failed to parse securely");
        
        // Just verify that we got a result - we can't check the contents directly
        // as that would defeat the purpose of secure storage
        assert!(!secure.expose_secret().is_empty());
    }
} 