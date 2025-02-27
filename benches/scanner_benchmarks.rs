// scanner_benchmarks.rs - Benchmarks for the scanner module
//
// This file contains benchmarks for the scanner module to measure its performance
// and optimize its implementation.

use beceeded::{
    db::SqliteDbController,
    parser::{Parser, ParserConfig},
    scanner::{ScannerConfig, Scanner},
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::{fs, path::Path, sync::{Arc, Mutex}};
use tempfile::TempDir;

// Benchmark scanning a directory with various file types
fn bench_scan_directory(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner");
    
    // Create a temporary directory for the benchmark
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
    
    // Benchmark with different configurations
    
    // 1. Default configuration
    group.bench_function("default_config", |b| {
        b.iter(|| {
            let db = SqliteDbController::new_in_memory().unwrap();
            let scanner_config = ScannerConfig::default();
            let scanner = Scanner::new(scanner_config, parser.clone(), Box::new(db)).unwrap();
            scanner.scan_directory(temp_path).unwrap();
        });
    });
    
    // 2. No fuzzy matching
    group.bench_function("no_fuzzy", |b| {
        b.iter(|| {
            let db = SqliteDbController::new_in_memory().unwrap();
            let mut scanner_config = ScannerConfig::default();
            scanner_config.use_fuzzy_matching = false;
            let scanner = Scanner::new(scanner_config, parser.clone(), Box::new(db)).unwrap();
            scanner.scan_directory(temp_path).unwrap();
        });
    });
    
    // 3. Single-threaded
    group.bench_function("single_thread", |b| {
        b.iter(|| {
            let db = SqliteDbController::new_in_memory().unwrap();
            let mut scanner_config = ScannerConfig::default();
            scanner_config.threads = 1;
            let scanner = Scanner::new(scanner_config, parser.clone(), Box::new(db)).unwrap();
            scanner.scan_directory(temp_path).unwrap();
        });
    });
    
    group.finish();
}

// Create test files for the benchmark
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

criterion_group!(benches, bench_scan_directory);
criterion_main!(benches); 