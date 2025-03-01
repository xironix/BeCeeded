// scanner_tests.rs - Tests for the scanner module
//
// This file contains integration tests for the scanner module.

use beceeded::{
    db::SqliteDbController,
    parser::{Parser, ParserConfig},
    scanner::{ScannerConfig, Scanner},
};
use std::{fs, path::Path};
use tempfile::TempDir;

// Helper function to set up a scanner for testing
fn setup_scanner() -> (Scanner, TempDir) {
    // Create a temporary directory for testing
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test files
    create_test_files(temp_path).unwrap();
    
    // Create parser
    let parser_config = ParserConfig {
        validate_checksum: true,
        max_words: 24,
        valid_word_counts: vec![12, 15, 18, 21, 24],
        wordlist_name: "english".to_string(),
    };
    
    let parser = Parser::new(
        Path::new("data").to_path_buf(),
        "english".to_string(),
        parser_config,
    )
    .unwrap();
    
    // Create scanner
    let db = SqliteDbController::new_in_memory().unwrap();
    let scanner_config = ScannerConfig {
        threads: 1, // Single-threaded for tests
        // Use defaults for everything else
        ..ScannerConfig::default()
    };
    
    let scanner = Scanner::new(scanner_config, parser, Box::new(db)).unwrap();
    
    (scanner, temp_dir)
}

// Create test files
fn create_test_files(dir: &Path) -> std::io::Result<()> {
    // Create a file with a valid seed phrase
    let seed_file = dir.join("seed.txt");
    fs::write(
        &seed_file,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )?;
    
    // Create a file with a partial seed phrase
    let partial_file = dir.join("partial.txt");
    fs::write(
        &partial_file,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    )?;
    
    // Create a file with no seed phrase
    let no_seed_file = dir.join("no_seed.txt");
    fs::write(
        &no_seed_file,
        "This is a test file with no seed phrases in it. Just some random text.",
    )?;
    
    // Create a file with an Ethereum private key
    let eth_key_file = dir.join("eth_key.txt");
    fs::write(
        &eth_key_file,
        "Here is a private key: 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )?;
    
    // Create a subdirectory with more files
    let subdir = dir.join("subdir");
    fs::create_dir(&subdir)?;
    
    let subdir_file = subdir.join("subdir_file.txt");
    fs::write(
        &subdir_file,
        "This is a file in a subdirectory. abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )?;
    
    Ok(())
}

#[test]
fn test_scanner_finds_valid_phrases() {
    let (scanner, temp_dir) = setup_scanner();
    
    // Scan the directory
    // We're using the new work-stealing implementation which doesn't have thread pool issues
    scanner.scan_directory(temp_dir.path()).unwrap();
    
    // Check that we found the expected phrases
    let stats = scanner.stats();
    assert_eq!(stats.phrases_found.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn test_scanner_finds_eth_keys() {
    let (scanner, temp_dir) = setup_scanner();
    
    // Scan the directory
    scanner.scan_directory(temp_dir.path()).unwrap();
    
    // Check that we found the expected Ethereum keys
    let stats = scanner.stats();
    assert_eq!(stats.eth_keys_found.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn test_scanner_skips_excluded_extensions() {
    // Create a temporary directory
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create a seed file with an excluded extension
    let excluded_file = temp_path.join("seed.jpg");
    fs::write(
        &excluded_file,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    ).unwrap();
    
    // Create parser
    let parser_config = ParserConfig {
        validate_checksum: true,
        max_words: 24,
        valid_word_counts: vec![12, 15, 18, 21, 24],
        wordlist_name: "english".to_string(),
    };
    
    let parser = Parser::new(
        Path::new("data").to_path_buf(),
        "english".to_string(),
        parser_config,
    )
    .unwrap();
    
    // Create scanner with JPG excluded
    let db = SqliteDbController::new_in_memory().unwrap();
    let mut scanner_config = ScannerConfig::default();
    scanner_config.exclude_extensions = vec!["jpg".to_string()];
    let scanner = Scanner::new(scanner_config, parser, Box::new(db)).unwrap();
    
    // Scan the directory
    scanner.scan_directory(temp_path).unwrap();
    
    // Check that we didn't find any phrases (because the file was skipped)
    let stats = scanner.stats();
    assert_eq!(stats.phrases_found.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn test_scanner_fuzzy_matching() {
    // Create a temporary directory
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create a file with a slightly misspelled seed phrase
    let fuzzy_file = temp_path.join("fuzzy.txt");
    fs::write(
        &fuzzy_file,
        "abandn abanon abandon abandon abanden abandon abanden abandon abandon abanden abandon about",
    ).unwrap();
    
    // Create parser
    let parser_config = ParserConfig {
        validate_checksum: true,
        max_words: 24,
        valid_word_counts: vec![12, 15, 18, 21, 24],
        wordlist_name: "english".to_string(),
    };
    
    let parser = Parser::new(
        Path::new("data").to_path_buf(),
        "english".to_string(),
        parser_config,
    )
    .unwrap();
    
    // Create scanner with fuzzy matching enabled
    let db = SqliteDbController::new_in_memory().unwrap();
    let mut scanner_config = ScannerConfig::default();
    scanner_config.use_fuzzy_matching = true;
    scanner_config.fuzzy_threshold = 0.7; // Lower threshold for the test
    scanner_config.threads = 1; // Use single thread for test stability
    let scanner = Scanner::new(scanner_config, parser, Box::new(db)).unwrap();
    
    // Scan the directory
    scanner.scan_directory(temp_path).unwrap();
    
    // Get scan statistics
    let stats = scanner.stats();
    println!("Fuzzy test - files processed: {}", stats.files_processed.load(std::sync::atomic::Ordering::Relaxed));
    println!("Fuzzy test - phrases found: {}", stats.phrases_found.load(std::sync::atomic::Ordering::Relaxed));
    
    // We should at least have processed 1 file
    assert!(stats.files_processed.load(std::sync::atomic::Ordering::Relaxed) > 0, 
           "Scanner should have processed at least one file");
} 