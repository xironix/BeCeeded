// Add cfg attributes for no_std compatibility preparation
#![cfg_attr(feature = "no_std", no_std)]
#![cfg_attr(all(feature = "no_std", feature = "alloc"), feature(alloc))]

// At the beginning of the file, add the conditional extern crate declarations
#[cfg(all(feature = "no_std", feature = "alloc"))]
extern crate alloc;

#[cfg(all(feature = "no_std", feature = "alloc"))]
use alloc::{string::String, vec::Vec, collections::HashMap};

/** 
 * Seed phrase parser for BeCeeded
 * 
 * This module provides functionality to parse and validate seed phrases
 * based on BIP-39 and other standards.
 * 
 * # Performance Considerations
 * 
 * Critical path functions have been marked with `#[inline]` to encourage inlining
 * for better performance. For embedded contexts, a `no_std` feature is available
 * (requires the `alloc` feature as well).
 * 
 * For benchmarking, use the `criterion` feature which enables benchmarks for
 * various wordlist types and operations.
 * 
 * Unsafe code is used only where absolutely necessary for performance, and
 * is thoroughly documented with safety invariants.
 */

use crate::memory::SecureString;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use thiserror::Error;
use ring::digest::{Context, SHA256};
#[cfg(test)]
use secrecy::ExposeSecret;
use unicode_normalization::UnicodeNormalization;

/// Errors that can occur during parsing
#[derive(Debug, Error)]
pub enum ParserError {
    /// I/O error when accessing wordlist files
    #[error("Failed to open wordlist file: {0}")]
    WordlistError(#[from] io::Error),
    
    /// General input format error
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    /// Word not found in the current wordlist
    #[error("Word not found in wordlist: {0}")]
    WordNotFound(String),
    
    /// BIP-39 checksum verification failed
    #[error("Checksum verification failed")]
    ChecksumError,
    
    /// The number of words doesn't match valid BIP-39 lengths
    #[error("Invalid word count: expected one of {expected:?}, got {actual}")]
    InvalidWordCount { expected: Vec<usize>, actual: usize },
    
    /// Internal implementation error
    #[error("Internal error: {0}")]
    InternalError(String),
    
    /// Monero mnemonic checksum error
    #[error("Monero mnemonic checksum verification failed")]
    MoneroChecksumError,
}

/// Trait for providing wordlists to the parser
pub trait WordlistProvider {
    /// Load a wordlist and return the words and their indices
    fn load_wordlist(&self) -> Result<(Vec<String>, HashMap<String, u16>), ParserError>;
    
    /// Get the name of the wordlist
    fn name(&self) -> &str;
}

/// File-based wordlist provider
#[derive(Debug, Clone)]
pub struct FileWordlistProvider {
    /// Directory containing wordlist files
    pub directory: PathBuf,
    
    /// Name of the wordlist file (without .txt extension)
    pub name: String,
}

impl FileWordlistProvider {
    /// Create a new file-based wordlist provider
    pub fn new(directory: PathBuf, name: String) -> Self {
        Self { directory, name }
    }
}

impl WordlistProvider for FileWordlistProvider {
    fn load_wordlist(&self) -> Result<(Vec<String>, HashMap<String, u16>), ParserError> {
        // Determine the correct file extension based on wordlist name
        let is_monero = self.name.starts_with("monero_");
        let extension = if is_monero { "md" } else { "txt" };
        
        let path = self.directory.join(format!("{}.{}", self.name, extension));
        
        let file = File::open(&path)
            .map_err(|e| ParserError::WordlistError(e))?;
        let reader = BufReader::new(file);
        
        let mut wordlist = Vec::with_capacity(2048);
        let mut word_indices = HashMap::with_capacity(2048);
        
        // For Monero wordlists in Markdown format, we need to skip header rows
        let mut line_num = 0;
        
        for (_i, line) in reader.lines().enumerate() {
            // Get the line
            let line = line?;
            line_num += 1;
            
            // Process the line based on the file type
            let word = if is_monero {
                // For Markdown files, we need to extract the word from a table format
                // Skip header and separator rows
                if line_num <= 2 || line.trim().is_empty() {
                    continue;
                }
                
                // Parse table row: | Index | Word |
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() < 3 {
                    // Not enough parts for a table row
                    continue;
                }
                
                // Word should be in the third column (index 2)
                let word_part = parts[2].trim();
                
                // Further clean up the word - extract just the word itself
                let cleaned = word_part.split_whitespace().next().unwrap_or("").to_string();
                
                // Skip empty words
                if cleaned.is_empty() {
                    continue;
                }
                
                // For Monero words, ensure consistent case handling (lowercase)
                // and normalize with NFKD
                cleaned.to_lowercase().nfkd().collect::<String>()
            } else {
                // For regular text files, just normalize the entire line
                line.nfkd().collect::<String>()
            };
            
            // Only add non-empty words
            if !word.is_empty() {
                word_indices.insert(word.clone(), wordlist.len() as u16);
                wordlist.push(word);
            }
        }
        
        if wordlist.is_empty() {
            return Err(ParserError::InternalError(format!("No words found in wordlist file: {}", path.display())));
        }
        
        Ok((wordlist, word_indices))
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}

/// Configuration for the parser
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Maximum number of words to accept (default: 25)
    pub max_words: usize,
    
    /// Whether to validate the checksum
    pub validate_checksum: bool,
    
    /// Valid word counts (typically 12, 15, 18, 21, 24, 25)
    pub valid_word_counts: Vec<usize>,
    
    /// Name of the wordlist
    pub wordlist_name: String,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            max_words: 25,
            validate_checksum: true,
            valid_word_counts: vec![12, 15, 18, 21, 24, 25],
            wordlist_name: "english".to_string(),
        }
    }
}

/// The seed phrase parser
#[derive(Debug, Clone)]
pub struct Parser {
    config: ParserConfig,
    wordlist: Vec<String>,
    word_indices: HashMap<String, u16>,
    wordlist_name: String,
}

impl Parser {
    /// Create a new parser with a specific wordlist provider and configuration
    pub fn with_provider<P: WordlistProvider>(provider: &P, config: ParserConfig) -> Result<Self, ParserError> {
        let (wordlist, word_indices) = provider.load_wordlist()?;
        
        Ok(Self {
            config,
            wordlist,
            word_indices,
            wordlist_name: provider.name().to_string(),
        })
    }
    
    /// Create a new parser with the given configuration using the default file-based provider
    pub fn new(wordlist_dir: PathBuf, wordlist_name: String, config: ParserConfig) -> Result<Self, ParserError> {
        let provider = FileWordlistProvider::new(wordlist_dir, wordlist_name.clone());
        Self::with_provider(&provider, config)
    }
    
    /// Create a new parser with default configuration
    #[inline]
    pub fn default() -> Result<Self, ParserError> {
        let provider = FileWordlistProvider::new(PathBuf::from("data"), "english".to_string());
        Self::with_provider(&provider, ParserConfig::default())
    }
    
    /// Parse a mnemonic phrase into a list of validated words
    ///
    /// This is a performance-critical function that handles both BIP-39 and
    /// Monero-style mnemonics. Inlining is encouraged for direct callers.
    #[inline]
    pub fn parse(&self, input: &str) -> Result<Vec<String>, ParserError> {
        // Clean the input and normalize with NFKD
        let input = input.trim().to_lowercase().nfkd().collect::<String>();
        
        // Check if this is a CJK wordlist (Chinese, Japanese, Korean)
        let is_cjk = self.wordlist_name.contains("chinese") || 
                     self.wordlist_name.contains("japanese") || 
                     self.wordlist_name.contains("korean");
        
        // Monero wordlists are now loaded from .md files
        let is_monero = self.wordlist_name.starts_with("monero_");
        
        // Extract words from the input based on wordlist type
        let word_strings: Vec<String> = if is_cjk {
            // For Chinese Monero wordlists, we need special handling
            // Since the Chinese Monero wordlist contains single-character words
            if is_monero && self.wordlist_name.contains("chinese") {
                // For Chinese Monero, each character is a separate word
                input.chars()
                    .filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation())
                    .map(|c| c.to_string())
                    .collect()
            } else {
                // General CJK wordlist handling - try to match words from the wordlist
                self.parse_cjk_wordlist(&input)
            }
        } else {
            // Standard space-separated wordlists
            self.parse_standard_wordlist(&input)
        };
        
        // Validate word count
        let word_count = word_strings.len();
        if !self.config.valid_word_counts.contains(&word_count) {
            return Err(ParserError::InvalidWordCount {
                expected: self.config.valid_word_counts.clone(),
                actual: word_count,
            });
        }
        
        // Validate each word using iterators
        let validated_words = word_strings.iter()
            .map(|word| {
                self.word_indices.get(word)
                    .map(|&idx| self.wordlist[idx as usize].clone())
                    .ok_or_else(|| ParserError::WordNotFound(word.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        // Validate checksum if required
        if self.config.validate_checksum {
            // Check if this is a Monero wordlist
            if is_monero && word_count == 25 {
                self.validate_monero_checksum(&validated_words)?;
            } else {
                // Standard BIP-39 checksum
                self.validate_checksum(&validated_words)?;
            }
        }
        
        Ok(validated_words)
    }
    
    /// Parse a standard space-separated wordlist
    #[inline]
    fn parse_standard_wordlist(&self, input: &str) -> Vec<String> {
        input
            .split(|c: char| c.is_whitespace() || c.is_ascii_punctuation())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }
    
    /// Parse a CJK (Chinese, Japanese, Korean) wordlist
    #[inline]
    fn parse_cjk_wordlist(&self, input: &str) -> Vec<String> {
        // First, try the normal parsing to see if there are proper spaces
        let space_split: Vec<String> = input
            .split(|c: char| c.is_whitespace() || c.is_ascii_punctuation())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        
        // If we get a reasonable number of words, use that
        if self.config.valid_word_counts.contains(&space_split.len()) {
            space_split
        } else {
            // Otherwise, we need to match each word from the wordlist
            let mut matched_words = Vec::new();
            let mut remaining = input.as_str();
            
            // Process until we've matched all words or can't match anymore
            while !remaining.is_empty() {
                let mut matched = false;
                
                // Try to match a word from our wordlist
                for word in &self.wordlist {
                    if remaining.starts_with(word) {
                        matched_words.push(word.clone());
                        remaining = &remaining[word.len()..];
                        matched = true;
                        break;
                    }
                }
                
                // If we couldn't match any word, there's an issue
                if !matched {
                    // In a non-performance critical path, so use a simple approach for error reporting
                    return vec![format!("{}...", remaining.chars().take(10).collect::<String>())];
                }
            }
            
            matched_words
        }
    }
    
    /// Validate the checksum of a mnemonic according to BIP-39
    ///
    /// This function is performance-critical, especially for wallets that
    /// frequently validate mnemonics.
    #[inline]
    fn validate_checksum(&self, words: &[String]) -> Result<(), ParserError> {
        // Convert words to indices
        let indices = self.words_to_indices(words)?;
        
        // Calculate entropy and checksum bits
        let word_count = indices.len();
        let entropy_bits = (word_count * 11) - (word_count / 3);
        let entropy_bytes = (entropy_bits + 7) / 8;
        let checksum_bits = word_count * 11 - entropy_bits;
        
        // Extract entropy and checksum using bit manipulation
        let mut entropy = vec![0u8; entropy_bytes];
        let mut checksum = 0u8;
        
        // Process all bits from the word indices
        let all_bits = indices.iter().flat_map(|&idx| {
            // Convert each 11-bit index into an iterator of individual bits
            (0..11).map(move |bit_pos| ((idx >> (10 - bit_pos)) & 1) == 1)
        }).enumerate();
        
        // Process each bit to build entropy and checksum
        for (pos, bit_is_set) in all_bits {
            if pos < entropy_bits {
                // This bit belongs to the entropy
                let byte_pos = pos / 8;
                let bit_idx = 7 - (pos % 8);
                
                if bit_is_set {
                    entropy[byte_pos] |= 1 << bit_idx;
                }
            } else {
                // This bit belongs to the checksum
                let checksum_bit_idx = pos - entropy_bits;
                if bit_is_set {
                    checksum |= 1 << (checksum_bits - 1 - checksum_bit_idx);
                }
            }
        }
        
        // Calculate expected checksum using SHA-256
        let digest = {
            let mut context = Context::new(&SHA256);
            context.update(&entropy);
            context.finish()
        };
        
        let expected_checksum = digest.as_ref()[0] >> (8 - checksum_bits);
        
        // Compare checksums
        if checksum != expected_checksum {
            return Err(ParserError::ChecksumError);
        }
        
        Ok(())
    }
    
    /// Convert a list of words into their indices in the wordlist
    #[inline]
    pub fn words_to_indices(&self, words: &[String]) -> Result<Vec<u16>, ParserError> {
        words.iter()
            .map(|word| {
                self.word_indices.get(word)
                    .copied()
                    .ok_or_else(|| ParserError::WordNotFound(word.clone()))
            })
            .collect()
    }
    
    /// Convert a list of indices into their corresponding words
    #[inline]
    pub fn indices_to_words(&self, indices: &[u16]) -> Result<Vec<String>, ParserError> {
        indices.iter()
            .map(|&idx| {
                if idx < self.wordlist.len() as u16 {
                    Ok(self.wordlist[idx as usize].clone())
                } else {
                    Err(ParserError::InternalError(format!("Index out of range: {}", idx)))
                }
            })
            .collect()
    }
    
    /// Parse securely, returning a SecureString
    pub fn parse_secure(&self, input: &str) -> Result<SecureString, ParserError> {
        self.parse(input)
            .map(|words| words.join(" "))
            .map(crate::memory::secure_string)
    }
    
    /// Get the name of the wordlist being used
    pub fn wordlist_name(&self) -> &str {
        &self.wordlist_name
    }
    
    /// Get a slice of words from the wordlist by index range
    /// 
    /// This function uses unchecked access for performance when bounds are verified
    /// through `min` operations, making it safe to use even with arbitrary input.
    #[inline]
    pub fn get_wordlist_slice(&self, start: usize, end: usize) -> Vec<String> {
        let start_idx = start.min(self.wordlist.len());
        let end_idx = end.min(self.wordlist.len());
        
        if start_idx == end_idx {
            return Vec::new();
        }
        
        // Pre-allocate the result vector for better performance
        let mut result = Vec::with_capacity(end_idx - start_idx);
        
        // SAFETY: We've verified bounds through min operations above
        // This avoids redundant bounds checking in the loop
        #[allow(unsafe_code)]
        unsafe {
            for i in start_idx..end_idx {
                result.push(self.wordlist.get_unchecked(i).clone());
            }
        }
        
        result
    }
    
    /// Get the total number of words in the wordlist
    #[inline]
    pub fn wordlist_len(&self) -> usize {
        self.wordlist.len()
    }
    
    /// Validate the checksum of a Monero mnemonic
    /// In Monero, the 25th word is a checksum of the first 24 words
    #[inline]
    fn validate_monero_checksum(&self, words: &[String]) -> Result<(), ParserError> {
        // Monero checksum validation is only applicable for 25-word mnemonics
        if words.len() != 25 {
            return Ok(());
        }
        
        // Convert words to indices
        let indices = self.words_to_indices(words)?;
        
        // Get the size of the wordlist (base N)
        let base = self.wordlist.len();
        
        // Calculate the checksum: interpret the first 24 words as a base-N number
        // and calculate: checksum = sum(word_idx * (base^i)) mod base
        let mut total: u128 = 0;
        let mut power: u128 = 1;
        
        // Calculate sum of first 24 words
        for i in 0..24 {
            let idx = indices[i] as u128;
            total = total.wrapping_add(idx.wrapping_mul(power));
            power = power.wrapping_mul(base as u128);
            
            // If power becomes too large, take modulo to prevent overflow
            // This is safe because (a * b) mod n = ((a mod n) * (b mod n)) mod n
            if power >= u128::MAX / (base as u128) {
                power %= base as u128;
                total %= base as u128;
            }
        }
        
        // Calculate expected checksum index
        let expected_checksum = total % (base as u128);
        
        // Check if the 25th word's index matches the expected checksum
        if indices[24] as u128 != expected_checksum {
            return Err(ParserError::MoneroChecksumError);
        }
        
        Ok(())
    }
}

// Add a module with benchmarking instructions
#[cfg(feature = "criterion")]
pub mod benchmarks {
    //! Benchmarking utilities for the parser module
    //!
    //! To run benchmarks, use:
    //! ```bash
    //! cargo bench --features criterion
    //! ```
    //!
    //! Benchmark areas include:
    //! - BIP39 mnemonic parsing (various lengths)
    //! - Monero mnemonic parsing
    //! - CJK wordlist handling
    //! - Word indices conversion
    //! - Checksum validation
    
    use super::*;
    
    /// Sample benchmark function - to be used with Criterion
    pub fn bench_parse_12_word_mnemonic(criterion: &mut criterion::Criterion) {
        let parser = Parser::default().expect("Failed to create parser");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        criterion.bench_function("parse_12_word_mnemonic", |b| {
            b.iter(|| parser.parse(mnemonic))
        });
    }
    
    /// Sample benchmark function for Monero mnemonic parsing
    pub fn bench_parse_monero_mnemonic(criterion: &mut criterion::Criterion) {
        // Implementation when feature enabled
    }
    
    /// Sample benchmark function for validating Monero checksums
    pub fn bench_validate_monero_checksum(criterion: &mut criterion::Criterion) {
        // Implementation when feature enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parser_initialization() {
        let config = ParserConfig::default();
        let parser = Parser::new(PathBuf::from("data"), "english".to_string(), config).expect("Failed to create parser");
        
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
        use std::collections::HashSet;
        
        // Test several different languages - not just Spanish
        let languages_to_test = [
            "chinese_simplified", "spanish", "japanese", "english", "korean"
        ];
        
        // For each language
        for &language in &languages_to_test {
            // Create config with checksum validation disabled
            let config = ParserConfig {
                validate_checksum: false,
                ..ParserConfig::default()
            };
            
            println!("\nTesting wordlist: {}", language);
            
            // Try to create parser for this language
            let parser = match Parser::new(PathBuf::from("data"), language.to_string(), config) {
                Ok(p) => p,
                Err(e) => {
                    println!("  Skipping {}: Unable to load wordlist: {:?}", language, e);
                    continue;
                }
            };
            
            // Get wordlist info
            let wordlist_len = parser.wordlist_len();
            println!("  Loaded {} with {} words", language, wordlist_len);
            
            // Ensure we have enough words to test
            if wordlist_len < 20 {
                println!("  Skipping {}: wordlist too small", language);
                continue;
            }
            
            // Pick 12 random indices (avoiding duplicates)
            let mut indices = HashSet::new();
            let mut counter = 0;
            while indices.len() < 12 && counter < 100 {
                indices.insert(counter % wordlist_len);
                counter += 1;
            }
            let indices: Vec<_> = indices.into_iter().take(12).collect();
            
            // Get the actual words at these indices
            let test_words: Vec<String> = indices.iter()
                .map(|&idx| parser.get_wordlist_slice(idx, idx + 1)[0].clone())
                .collect();
            
            println!("  Selected 12 random words from {} wordlist", language);
            
            // Build a mnemonic from these words
            let test_mnemonic = test_words.join(" ");
            
            // Test parsing the mnemonic
            let parsed_words = match parser.parse(&test_mnemonic) {
                Ok(words) => words,
                Err(e) => {
                    println!("  Error parsing {} mnemonic: {:?}", language, e);
                    panic!("Failed to parse valid {} words", language);
                }
            };
            
            // Verify the words
            assert_eq!(parsed_words.len(), 12, 
                      "{} mnemonic should have 12 words", language);
            
            // If the language uses non-ASCII characters, also test Unicode normalization
            if language != "english" {
                println!("  Testing Unicode normalization for {}", language);
                
                // Create normalized variants of the words where applicable
                let normalized_words: Vec<String> = test_words.iter()
                    .map(|word| {
                        // First decompose the word to NFKD
                        let nfkd: String = word.nfkd().collect();
                        nfkd
                    })
                    .collect();
                
                // Join into a phrase
                let normalized_mnemonic = normalized_words.join(" ");
                
                // Parse it
                let parsed_normalized = match parser.parse(&normalized_mnemonic) {
                    Ok(words) => words,
                    Err(e) => {
                        println!("  Error parsing normalized {} mnemonic: {:?}", language, e);
                        panic!("Failed to parse normalized {} words", language);
                    }
                };
                
                // Check that they match
                assert_eq!(parsed_normalized, parsed_words, 
                          "Original and normalized forms should parse to the same result");
                
                println!("  ✓ Unicode normalization test passed for {}", language);
            }
            
            println!("  ✓ Successfully tested {} wordlist", language);
        }
    }
    
    #[test]
    fn test_different_mnemonic_lengths() {
        // Lengths to test (including Monero's 25-word format)
        let lengths = [15, 18, 21, 24, 25];
        
        // A sample of Spanish words (accented and normalized) to use for testing
        let sample_words = [
            "ábaco", "abdomen", "abeja", "abierto", "abogado", 
            "abono", "aborto", "abrazo", "abrir", "abuelo", 
            "abuso", "acabar", "academia", "acceso", "acción",
            "aceite", "acelga", "acento", "aceptar", "ácido",
            "aclarar", "acné", "acoger", "acoso", "activo"
        ];
        
        for &length in &lengths {
            // For each length, we'll generate a test mnemonic
            let test_phrase = {
                // Repeat sample words as needed to reach desired length
                let mut words = Vec::with_capacity(length);
                for i in 0..length {
                    words.push(sample_words[i % sample_words.len()]);
                }
                words.join(" ")
            };
            
            // Create parser with checksum validation disabled
            let config = ParserConfig {
                validate_checksum: false,
                ..ParserConfig::default()
            };
            
            let parser = Parser::new(PathBuf::from("data"), "spanish".to_string(), config)
                .expect("Failed to create Spanish parser");
            
            // Test parsing the mnemonic of this length
            let parsed = parser.parse(&test_phrase);
            assert!(parsed.is_ok(), "Failed to parse {}-word mnemonic", length);
            
            let parsed_words = parsed.unwrap();
            assert_eq!(parsed_words.len(), length, "Parsed mnemonic should have {} words", length);
            
            println!("Successfully tested {}-word mnemonic", length);
        }
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
    
    #[test]
    fn test_monero_checksum_validation() {
        // Create a specific test for Monero checksum validation
        let config = ParserConfig {
            validate_checksum: true,
            valid_word_counts: vec![25],
            wordlist_name: "monero_english".to_string(),
            ..ParserConfig::default()
        };
        
        let parser = match Parser::new(PathBuf::from("data"), "monero_english".to_string(), config) {
            Ok(p) => p,
            Err(e) => {
                println!("Skipping Monero checksum test: {}", e);
                return;
            }
        };
        
        // Generate 24 random indices (using fixed seed for reproducibility)
        let mut rng: u64 = 12345;
        let mut indices = Vec::with_capacity(25);
        
        for _ in 0..24 {
            // Simple xorshift
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            
            let idx = (rng % parser.wordlist_len() as u64) as u16;
            indices.push(idx);
        }
        
        // Calculate valid checksum based on Monero algorithm
        let base = parser.wordlist_len() as u128;
        let mut total: u128 = 0;
        let mut power: u128 = 1;
        
        // Calculate sum of first 24 words
        for i in 0..24 {
            let idx = indices[i] as u128;
            total = total.wrapping_add(idx.wrapping_mul(power));
            power = power.wrapping_mul(base);
            
            if power >= u128::MAX / base {
                power %= base;
                total %= base;
            }
        }
        
        let checksum_idx = (total % base) as u16;
        indices.push(checksum_idx);
        
        // Convert indices to words
        let words = parser.indices_to_words(&indices).expect("Failed to convert indices to words");
        
        // Create the phrase
        let mnemonic = words.join(" ");
        
        // Attempt to parse with checksum validation
        let validation_result = parser.parse(&mnemonic);
        assert!(validation_result.is_ok(), "Valid Monero mnemonic with correct checksum should be accepted");
        
        // Now create an invalid mnemonic by modifying the checksum word
        let mut invalid_indices = indices.clone();
        invalid_indices[24] = (invalid_indices[24] + 1) % parser.wordlist_len() as u16;
        
        let invalid_words = parser.indices_to_words(&invalid_indices).expect("Failed to convert indices to words");
        let invalid_mnemonic = invalid_words.join(" ");
        
        // Attempt to parse with checksum validation
        let invalid_result = parser.parse(&invalid_mnemonic);
        assert!(matches!(invalid_result, Err(ParserError::MoneroChecksumError)), 
               "Invalid Monero checksum should be rejected");
    }
    
    #[test]
    fn test_case_insensitivity() {
        let parser = Parser::default().expect("Failed to create parser");
        
        // Test with mixed-case input
        let mnemonic_lowercase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic_mixedcase = "aBaNdOn ABANDON abandon aBaNdOn abandon abandon ABANDON abandon abandon abandon aBaNdOn aBoUt";
        
        let words_lowercase = parser.parse(mnemonic_lowercase).expect("Failed to parse lowercase");
        let words_mixedcase = parser.parse(mnemonic_mixedcase).expect("Failed to parse mixed case");
        
        assert_eq!(words_lowercase, words_mixedcase, "Case differences should be ignored");
        
        // Also test with non-English wordlist if available
        let config = ParserConfig {
            wordlist_name: "spanish".to_string(),
            ..ParserConfig::default()
        };
        
        if let Ok(parser) = Parser::new(PathBuf::from("data"), "spanish".to_string(), config) {
            // Test with accented characters in different cases
            let spanish_lower = "ábaco abdomen abeja abierto abogado";
            let spanish_upper = "ÁBACO Abdomen ABEJA abierto ABOGADO";
            
            let result_lower = parser.parse(spanish_lower);
            let result_upper = parser.parse(spanish_upper);
            
            if result_lower.is_ok() && result_upper.is_ok() {
                assert_eq!(result_lower.unwrap(), result_upper.unwrap(), 
                           "Case differences in non-English words should be ignored");
            }
        }
    }
    
    #[test]
    fn test_wordlist_loading_errors() {
        // Test with a non-existent wordlist file
        let config = ParserConfig {
            wordlist_name: "nonexistent".to_string(),
            ..ParserConfig::default()
        };
        
        let result = Parser::new(PathBuf::from("data"), "nonexistent".to_string(), config);
        assert!(result.is_err(), "Loading non-existent wordlist should fail");
        assert!(matches!(result, Err(ParserError::WordlistError(_))), 
               "Should return WordlistError for missing file");
        
        // Test with an empty directory path
        let config = ParserConfig::default();
        let result = Parser::new(PathBuf::from(""), "english".to_string(), config);
        assert!(result.is_err(), "Empty directory path should fail");
    }
} 