// scanner.rs - Cryptocurrency seed phrase and private key scanner
//
// This module provides functionality for scanning files and directories for
// potential cryptocurrency seed phrases and private keys using advanced
// pattern matching and OCR techniques.

use crate::{
    mnemonic::{Mnemonic, MnemonicError},
    parser::{Parser, ParserError},
    wallet::{Network, Wallet, WalletError},
};
use log::{debug, error, info, trace, warn};
use rayon::prelude::*;
use secrecy::ExposeSecret;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
use hex;
use secp256k1;
use tiny_keccak;
use strsim;

/// Errors that can occur during scanning operations
#[derive(Debug, Error)]
pub enum ScannerError {
    /// I/O error when accessing files
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Parser error
    #[error("Parser error: {0}")]
    ParserError(#[from] ParserError),

    /// Mnemonic error
    #[error("Mnemonic error: {0}")]
    MnemonicError(#[from] MnemonicError),

    /// Wallet error
    #[error("Wallet error: {0}")]
    WalletError(#[from] WalletError),

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// OCR error
    #[error("OCR error: {0}")]
    OcrError(String),

    /// Other errors
    #[error("Error: {0}")]
    Other(String),
}

/// Result type for scanner operations
pub type Result<T> = std::result::Result<T, ScannerError>;

/// Scanning mode to control processing depth and performance tradeoffs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Fast mode - Only processes plain text files, no advanced features
    /// Optimized for speed, might miss some seed phrases
    Fast,
    
    /// Default mode - Processes text files and other common formats
    /// Balanced approach between speed and thoroughness
    Default,
    
    /// Enhanced mode - Adds OCR for image files
    /// More thorough but slower than default
    Enhanced,
    
    /// Comprehensive mode - Processes all supported file types
    /// Most thorough but slowest option
    Comprehensive,
}

/// Configuration for the scanner
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Scanning mode that determines processing depth
    pub scan_mode: ScanMode,

    /// Number of threads to use for scanning
    pub threads: usize,

    /// Maximum memory usage in bytes
    pub max_memory: usize,

    /// Batch size for processing
    pub batch_size: usize,

    /// Whether to scan for Ethereum private keys
    pub scan_eth_keys: bool,

    /// File extensions to include (if empty, all files are considered)
    pub include_extensions: Vec<String>,

    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,

    /// Whether to use fuzzy matching for seed phrases
    pub use_fuzzy_matching: bool,

    /// Whether to use OCR for image files
    pub use_ocr: bool,

    /// Whether to scan inside archive files (zip)
    pub scan_archives: bool,

    /// Whether to scan inside document files (docx, xlsx)
    pub scan_documents: bool,

    /// Whether to scan inside PDF files
    pub scan_pdfs: bool,

    /// Minimum number of BIP39 words required to trigger a match
    pub min_bip39_words: usize,

    /// Threshold for fuzzy matching (0.0-1.0, where 1.0 is exact match)
    pub fuzzy_threshold: f32,

    /// Whether to write detailed logs
    pub write_logs: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            scan_mode: ScanMode::Default,
            threads: num_cpus::get(),
            max_memory: 1024 * 1024 * 1024, // 1GB
            batch_size: 1000,
            scan_eth_keys: true,
            include_extensions: vec![],
            exclude_extensions: vec![
                "mp3".to_string(),
                "mp4".to_string(),
                "avi".to_string(),
                "mov".to_string(),
                "mkv".to_string(),
                "exe".to_string(),
                "dll".to_string(),
                "so".to_string(),
                "bin".to_string(),
                "dat".to_string(),
            ],
            use_fuzzy_matching: true,
            use_ocr: true,
            scan_archives: true,
            scan_documents: true,
            scan_pdfs: true,
            min_bip39_words: 11, // Lower than 12 to catch partial phrases
            fuzzy_threshold: 0.85,
            write_logs: true,
        }
    }
}

impl ScannerConfig {
    /// Create a new configuration with Fast mode
    pub fn fast() -> Self {
        Self {
            scan_mode: ScanMode::Fast,
            use_fuzzy_matching: false,
            use_ocr: false,
            scan_archives: false,
            scan_documents: false,
            scan_pdfs: false,
            min_bip39_words: 12, // Require full phrases for higher precision
            fuzzy_threshold: 0.95, // Higher threshold for less false positives
            ..Default::default()
        }
    }

    /// Create a new configuration with Default mode
    pub fn default_mode() -> Self {
        Self {
            scan_mode: ScanMode::Default,
            use_fuzzy_matching: true,
            use_ocr: false,
            scan_archives: false,
            scan_documents: false,
            scan_pdfs: false,
            ..Default::default()
        }
    }

    /// Create a new configuration with Enhanced mode
    pub fn enhanced() -> Self {
        Self {
            scan_mode: ScanMode::Enhanced,
            use_fuzzy_matching: true,
            use_ocr: true,
            scan_archives: false,
            scan_documents: false,
            scan_pdfs: false,
            ..Default::default()
        }
    }

    /// Create a new configuration with Comprehensive mode
    pub fn comprehensive() -> Self {
        Self {
            scan_mode: ScanMode::Comprehensive,
            use_fuzzy_matching: true,
            use_ocr: true,
            scan_archives: true,
            scan_documents: true,
            scan_pdfs: true,
            ..Default::default()
        }
    }

    /// Apply settings based on the scan mode
    pub fn apply_scan_mode(&mut self) {
        match self.scan_mode {
            ScanMode::Fast => {
                self.use_fuzzy_matching = false;
                self.use_ocr = false;
                self.scan_archives = false;
                self.scan_documents = false;
                self.scan_pdfs = false;
                self.min_bip39_words = 12;
                self.fuzzy_threshold = 0.95;
            },
            ScanMode::Default => {
                self.use_fuzzy_matching = true;
                self.use_ocr = false;
                self.scan_archives = false;
                self.scan_documents = false;
                self.scan_pdfs = false;
            },
            ScanMode::Enhanced => {
                self.use_fuzzy_matching = true;
                self.use_ocr = true;
                self.scan_archives = false;
                self.scan_documents = false;
                self.scan_pdfs = false;
            },
            ScanMode::Comprehensive => {
                self.use_fuzzy_matching = true;
                self.use_ocr = true;
                self.scan_archives = true;
                self.scan_documents = true;
                self.scan_pdfs = true;
            },
        }
    }
}

/// Statistics for scanning operations
#[derive(Debug, Default)]
pub struct ScanStats {
    /// Number of files processed
    pub files_processed: AtomicU64,

    /// Number of directories processed
    pub dirs_processed: AtomicU64,

    /// Number of bytes processed
    pub bytes_processed: AtomicU64,

    /// Number of seed phrases found
    pub phrases_found: AtomicU64,

    /// Number of Ethereum private keys found
    pub eth_keys_found: AtomicU64,

    /// Number of errors encountered
    pub errors: AtomicU64,

    /// Start time of the scan
    pub start_time: Instant,
}

impl ScanStats {
    /// Create new scanning statistics
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            ..Default::default()
        }
    }

    /// Get elapsed time in seconds
    pub fn elapsed_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get processing rate in MB/s
    pub fn processing_rate(&self) -> f64 {
        let bytes = self.bytes_processed.load(Ordering::Relaxed) as f64;
        let secs = self.elapsed_seconds() as f64;
        if secs > 0.0 {
            bytes / 1_048_576.0 / secs
        } else {
            0.0
        }
    }
}

/// Found seed phrase information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FoundPhrase {
    /// The seed phrase
    pub phrase: String,

    /// The file path where it was found
    pub file_path: String,

    /// Line number in the file (if applicable)
    pub line_number: Option<usize>,

    /// Wallet addresses derived from this phrase
    pub wallet_addresses: Vec<String>,

    /// Whether this was found through fuzzy matching
    pub fuzzy_matched: bool,

    /// Confidence level for fuzzy matches (0.0-1.0)
    pub confidence: Option<f32>,
}

/// Found Ethereum private key information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FoundEthKey {
    /// The private key (hex format)
    pub private_key: String,

    /// The file path where it was found
    pub file_path: String,

    /// Line number in the file (if applicable)
    pub line_number: Option<usize>,

    /// Ethereum address derived from this key
    pub eth_address: String,
}

/// Database controller trait for storing found phrases and keys
pub trait DbController: Send + Sync {
    /// Initialize the database
    fn init(&self) -> Result<()>;

    /// Insert a found phrase
    fn insert_phrase(&self, phrase: &FoundPhrase) -> Result<bool>;

    /// Insert a found Ethereum private key
    fn insert_eth_key(&self, key: &FoundEthKey) -> Result<bool>;

    /// Get all found phrases
    fn get_all_phrases(&self) -> Result<Vec<FoundPhrase>>;

    /// Get all found Ethereum private keys
    fn get_all_eth_keys(&self) -> Result<Vec<FoundEthKey>>;

    /// Close the database connection
    fn close(&self) -> Result<()>;
}

/// The scanner for cryptocurrency seed phrases and private keys
pub struct Scanner {
    /// Configuration for the scanner
    config: ScannerConfig,

    /// Parser for validating seed phrases
    parser: Parser,

    /// Database controller for storing found phrases
    db: Arc<Box<dyn DbController>>,

    /// Scanning statistics
    stats: Arc<ScanStats>,

    /// Set of processed files to avoid duplicates
    processed_files: Arc<Mutex<HashSet<PathBuf>>>,

    /// Flag to signal scanner shutdown
    shutdown: Arc<AtomicBool>,
}

impl Scanner {
    /// Create a new scanner with the given configuration, parser, and database controller
    pub fn new(
        mut config: ScannerConfig,
        parser: Parser,
        db: Box<dyn DbController>,
    ) -> Result<Self> {
        // Apply settings based on scan mode
        config.apply_scan_mode();
        
        let scanner = Self {
            config,
            parser,
            db: Arc::new(db),
            stats: Arc::new(ScanStats::new()),
            processed_files: Arc::new(Mutex::new(HashSet::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Initialize the database
        scanner.db.init()?;

        Ok(scanner)
    }

    /// Start scanning a directory
    pub fn scan_directory(&self, directory: &Path) -> Result<()> {
        // Validate the directory
        if !directory.exists() {
            return Err(ScannerError::IoError(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory not found: {}", directory.display()),
            )));
        }

        if !directory.is_dir() {
            return Err(ScannerError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Not a directory: {}", directory.display()),
            )));
        }

        info!("Starting scan of directory: {}", directory.display());
        info!("Using {} threads", self.config.threads);

        // Set up thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.config.threads)
            .build_global()
            .map_err(|e| ScannerError::Other(format!("Failed to build thread pool: {}", e)))?;

        // Walk the directory and process files
        self.process_directory(directory)?;

        info!(
            "Scan completed. Processed {} files ({} MB) in {} seconds",
            self.stats.files_processed.load(Ordering::Relaxed),
            self.stats.bytes_processed.load(Ordering::Relaxed) / 1_048_576,
            self.stats.elapsed_seconds()
        );
        info!(
            "Found {} seed phrases and {} Ethereum private keys",
            self.stats.phrases_found.load(Ordering::Relaxed),
            self.stats.eth_keys_found.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Process a directory recursively
    fn process_directory(&self, directory: &Path) -> Result<()> {
        // Check for shutdown signal
        if self.shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Update stats
        self.stats.dirs_processed.fetch_add(1, Ordering::Relaxed);

        // Read directory entries
        let entries = fs::read_dir(directory).map_err(|e| {
            error!("Failed to read directory {}: {}", directory.display(), e);
            ScannerError::IoError(e)
        })?;

        // Process each entry
        for entry in entries {
            // Check for shutdown signal
            if self.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }

            let entry = entry.map_err(|e| {
                error!("Failed to read directory entry: {}", e);
                ScannerError::IoError(e)
            })?;

            let path = entry.path();

            if path.is_dir() {
                // Recursively process subdirectory
                self.process_directory(&path)?;
            } else if path.is_file() {
                // Process file if not already processed
                let mut processed_files = self.processed_files.lock().unwrap();
                if !processed_files.contains(&path) {
                    processed_files.insert(path.clone());
                    drop(processed_files); // Release lock before processing

                    // Process the file
                    if let Err(e) = self.process_file(&path) {
                        error!("Error processing file {}: {}", path.display(), e);
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a single file
    fn process_file(&self, file_path: &Path) -> Result<()> {
        // Check if we should skip this file based on extension
        if self.should_skip_file(file_path) {
            trace!("Skipping file: {}", file_path.display());
            return Ok(());
        }

        debug!("Processing file: {}", file_path.display());

        // Update stats
        self.stats.files_processed.fetch_add(1, Ordering::Relaxed);

        // Update processed bytes in stats
        if let Ok(metadata) = fs::metadata(file_path) {
            self.stats
                .bytes_processed
                .fetch_add(metadata.len(), Ordering::Relaxed);
        }

        // Handle different file types based on scan mode
        match self.config.scan_mode {
            ScanMode::Fast => {
                // Fast mode: Only process plain text files
                self.process_text_file(file_path)
            },
            ScanMode::Default => {
                // Default mode: Process text files and emails
                self.process_text_file(file_path)
            },
            ScanMode::Enhanced => {
                // Enhanced mode: Also process images with OCR
                if self.config.use_ocr && self.is_image_file(file_path) {
                    self.process_image_file(file_path)
                } else {
                    self.process_text_file(file_path)
                }
            },
            ScanMode::Comprehensive => {
                // Comprehensive mode: Process all supported file types
                if self.config.use_ocr && self.is_image_file(file_path) {
                    self.process_image_file(file_path)
                } else if self.config.scan_archives && self.is_archive_file(file_path) {
                    self.process_archive_file(file_path)
                } else if self.config.scan_documents && self.is_document_file(file_path) {
                    self.process_document_file(file_path)
                } else if self.config.scan_pdfs && self.is_pdf_file(file_path) {
                    self.process_pdf_file(file_path)
                } else {
                    self.process_text_file(file_path)
                }
            }
        }
    }

    /// Check if a file should be skipped based on extension
    fn should_skip_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();

            // Check exclude list
            if self.config.exclude_extensions.iter().any(|e| e == &ext_str) {
                return true;
            }

            // Check include list (if not empty)
            if !self.config.include_extensions.is_empty()
                && !self.config.include_extensions.iter().any(|e| e == &ext_str)
            {
                return true;
            }
        }

        false
    }

    /// Check if a file is an image file
    fn is_image_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            matches!(ext_str.as_str(), "jpg" | "jpeg" | "png" | "gif" | "bmp")
        } else {
            false
        }
    }

    /// Check if a file is a ZIP archive
    fn is_archive_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            matches!(ext_str.as_str(), "zip" | "tar" | "gz" | "7z" | "rar")
        } else {
            false
        }
    }

    /// Check if a file is a document file (DOCX, XLSX)
    fn is_document_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            matches!(ext_str.as_str(), "docx" | "xlsx" | "pptx" | "odt" | "ods")
        } else {
            false
        }
    }

    /// Check if a file is a PDF file
    fn is_pdf_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            ext_str.as_str() == "pdf"
        } else {
            false
        }
    }

    /// Process a text file
    fn process_text_file(&self, file_path: &Path) -> Result<()> {
        // Open the file
        let file = File::open(file_path).map_err(|e| {
            error!("Failed to open file {}: {}", file_path.display(), e);
            ScannerError::IoError(e)
        })?;

        let file_size = file.metadata()?.len();
        let reader = BufReader::new(file);

        // Update stats
        self.stats
            .bytes_processed
            .fetch_add(file_size, Ordering::Relaxed);

        // Process the file line by line
        let mut line_number = 0;
        for line in reader.lines() {
            line_number += 1;

            let line = match line {
                Ok(line) => line,
                Err(e) => {
                    error!(
                        "Error reading line {} from file {}: {}",
                        line_number,
                        file_path.display(),
                        e
                    );
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            // Look for seed phrases
            self.scan_for_seed_phrases(&line, file_path, Some(line_number))?;

            // Look for Ethereum private keys if enabled
            if self.config.scan_eth_keys {
                self.scan_for_eth_keys(&line, file_path, Some(line_number))?;
            }
        }

        Ok(())
    }

    /// Process an image file using OCR
    fn process_image_file(&self, file_path: &Path) -> Result<()> {
        info!("Processing image file with OCR: {}", file_path.display());
        
        // Update file count in stats
        self.stats.files_processed.fetch_add(1, Ordering::Relaxed);
        
        // Update processed bytes in stats
        if let Ok(metadata) = fs::metadata(file_path) {
            self.stats
                .bytes_processed
                .fetch_add(metadata.len(), Ordering::Relaxed);
        }
        
        // Check if we have OCR support
        #[cfg(feature = "ocr")]
        {
            use crate::ocr::{OcrEngine, OcrOptions, TesseractOcr};
            
            // Initialize OCR engine
            let mut ocr = TesseractOcr::new();
            let options = OcrOptions {
                language: "eng".to_string(),
                phrase_mode: true,
                preprocessing: true,
                confidence_threshold: 60.0,
            };
            
            if let Err(e) = ocr.init(&options) {
                error!("Failed to initialize OCR engine: {}", e);
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                return Err(ScannerError::OcrError(format!("OCR initialization failed: {}", e)));
            }
            
            // Process the image
            match ocr.process_image(file_path) {
                Ok(text) => {
                    // Scan the extracted text for seed phrases
                    if !text.is_empty() {
                        debug!("OCR extracted {} characters from {}", text.len(), file_path.display());
                        
                        // Split the text into lines and scan each line
                        for (i, line) in text.lines().enumerate() {
                            if !line.trim().is_empty() {
                                // Scan for seed phrases
                                if let Err(e) = self.scan_for_seed_phrases(line, file_path, Some(i + 1)) {
                                    error!("Error scanning OCR text: {}", e);
                                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                                }
                                
                                // Scan for Ethereum private keys if enabled
                                if self.config.scan_eth_keys {
                                    if let Err(e) = self.scan_for_eth_keys(line, file_path, Some(i + 1)) {
                                        error!("Error scanning OCR text for ETH keys: {}", e);
                                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    } else {
                        debug!("OCR extracted no text from {}", file_path.display());
                    }
                    
                    // Clean up OCR resources
                    if let Err(e) = ocr.cleanup() {
                        error!("Error cleaning up OCR resources: {}", e);
                    }
                    
                    Ok(())
                }
                Err(e) => {
                    error!("OCR processing failed for {}: {}", file_path.display(), e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    Err(ScannerError::OcrError(format!("OCR processing failed: {}", e)))
                }
            }
        }
        
        // If OCR support is not enabled
        #[cfg(not(feature = "ocr"))]
        {
            warn!("OCR support not enabled. Skipping image file: {}", file_path.display());
            Ok(())
        }
    }

    /// Scan text for potential seed phrases
    fn scan_for_seed_phrases(
        &self,
        text: &str,
        file_path: &Path,
        line_number: Option<usize>,
    ) -> Result<()> {
        // Normalize and clean the text
        let normalized_text = text.to_lowercase();
        
        // Extract words from the text
        let words: Vec<&str> = normalized_text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect();
        
        // Check for potential seed phrases using a sliding window
        let valid_word_counts = vec![12, 15, 18, 21, 24]; // BIP-39 standard word counts
        
        for window_size in valid_word_counts {
            if words.len() < window_size {
                continue;
            }
            
            for window in words.windows(window_size) {
                let potential_phrase = window.join(" ");
                
                // Try to parse as a valid seed phrase
                match Mnemonic::from_phrase(&potential_phrase, self.parser.clone()) {
                    Ok(mnemonic) => {
                        // Found a valid seed phrase!
                        let phrase = mnemonic.to_phrase();
                        
                        // Generate wallet addresses
                        let mut wallet_addresses = Vec::new();
                        
                        // Try different networks - excluding Bitcoin testnet as per requirements
                        for network in &[Network::Bitcoin, Network::Ethereum] {
                            if let Ok(wallet) = Wallet::from_mnemonic(&mnemonic, *network, None) {
                                wallet_addresses.push(wallet.address().to_string());
                            }
                        }
                        
                        let found_phrase = FoundPhrase {
                            phrase,
                            file_path: file_path.display().to_string(),
                            line_number,
                            wallet_addresses,
                            fuzzy_matched: false,
                            confidence: Some(1.0), // Exact match
                        };
                        
                        // Store in database
                        if let Ok(is_new) = self.db.insert_phrase(&found_phrase) {
                            if is_new {
                                self.stats.phrases_found.fetch_add(1, Ordering::Relaxed);
                                info!(
                                    "Found seed phrase in {} (line {:?})",
                                    file_path.display(),
                                    line_number
                                );
                            }
                        }
                    }
                    Err(_) => {
                        // Not a valid seed phrase, try fuzzy matching if enabled
                        if self.config.use_fuzzy_matching {
                            self.try_fuzzy_match_seed_phrase(
                                &potential_phrase,
                                file_path,
                                line_number,
                            )?;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Try to fuzzy match a potential seed phrase
    fn try_fuzzy_match_seed_phrase(
        &self,
        potential_phrase: &str,
        file_path: &Path,
        line_number: Option<usize>,
    ) -> Result<()> {
        // Split the potential phrase into words
        let words: Vec<&str> = potential_phrase.split_whitespace().collect();
        
        // For each word, find the closest BIP-39 word
        let mut corrected_words = Vec::with_capacity(words.len());
        let mut total_similarity = 0.0;
        let mut valid_words = 0;
        
        for word in &words {
            // Check if the word is already valid
            if self.parser.is_valid_word(word) {
                corrected_words.push(word.to_string());
                total_similarity += 1.0;
                valid_words += 1;
                continue;
            }
            
            // Find the closest BIP-39 word
            let (closest_word, similarity) = self.find_closest_bip39_word(word);
            corrected_words.push(closest_word.to_string());
            total_similarity += similarity;
            
            if similarity > 0.7 {
                valid_words += 1;
            }
        }
        
        // Calculate average similarity
        let avg_similarity = total_similarity / words.len() as f32;
        
        // If we have enough valid words and the average similarity is high enough,
        // consider this a potential seed phrase
        if valid_words >= self.config.min_bip39_words && avg_similarity >= self.config.fuzzy_threshold {
            // Construct the corrected phrase
            let corrected_phrase = corrected_words.join(" ");
            
            // Try to parse it as a valid seed phrase
            if let Ok(mnemonic) = Mnemonic::from_phrase(&corrected_phrase, self.parser.clone()) {
                // Generate wallet addresses
                let mut wallet_addresses = Vec::new();
                
                // Try different networks - excluding Bitcoin testnet as per requirements
                for network in &[Network::Bitcoin, Network::Ethereum] {
                    if let Ok(wallet) = Wallet::from_mnemonic(&mnemonic, *network, None) {
                        wallet_addresses.push(wallet.address().to_string());
                    }
                }
                
                let found_phrase = FoundPhrase {
                    phrase: corrected_phrase,
                    file_path: file_path.display().to_string(),
                    line_number,
                    wallet_addresses,
                    fuzzy_matched: true,
                    confidence: Some(avg_similarity),
                };
                
                // Store in database
                if let Ok(is_new) = self.db.insert_phrase(&found_phrase) {
                    if is_new {
                        self.stats.phrases_found.fetch_add(1, Ordering::Relaxed);
                        info!(
                            "Found fuzzy-matched seed phrase in {} (line {:?}), confidence: {:.2}",
                            file_path.display(),
                            line_number,
                            avg_similarity
                        );
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Find the closest BIP-39 word to a given word
    fn find_closest_bip39_word(&self, word: &str) -> (String, f32) {
        use strsim::jaro_winkler;
        
        let wordlist = self.parser.wordlist();
        let mut best_match = String::new();
        let mut best_similarity = 0.0;
        
        for valid_word in wordlist {
            let similarity = jaro_winkler(word, valid_word);
            
            if similarity > best_similarity {
                best_similarity = similarity;
                best_match = valid_word.to_string();
            }
        }
        
        (best_match, best_similarity)
    }

    /// Scan text for Ethereum private keys
    fn scan_for_eth_keys(
        &self,
        text: &str,
        file_path: &Path,
        line_number: Option<usize>,
    ) -> Result<()> {
        // Ethereum private keys are 64 character hex strings
        // They may be prefixed with 0x or not
        
        // Simple regex-like search
        let normalized_text = text.trim().to_lowercase();
        
        // Look for 64-character hex strings
        for word in normalized_text.split_whitespace() {
            let key_str = word.trim_start_matches("0x");
            
            // Check if it's a potential Ethereum private key
            if key_str.len() == 64 && key_str.chars().all(|c| c.is_ascii_hexdigit()) {
                debug!(
                    "Found potential Ethereum private key in {} (line {:?})",
                    file_path.display(),
                    line_number
                );
                
                // Validate by deriving address
                if let Ok(eth_address) = self.derive_eth_address(key_str) {
                    let found_key = FoundEthKey {
                        private_key: key_str.to_string(),
                        file_path: file_path.display().to_string(),
                        line_number,
                        eth_address,
                    };
                    
                    // Store in database
                    if let Ok(is_new) = self.db.insert_eth_key(&found_key) {
                        if is_new {
                            self.stats.eth_keys_found.fetch_add(1, Ordering::Relaxed);
                            info!(
                                "Found Ethereum private key in {} (line {:?})",
                                file_path.display(),
                                line_number
                            );
                        }
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Derive Ethereum address from private key
    fn derive_eth_address(&self, private_key_hex: &str) -> Result<String> {
        // Convert hex to bytes
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| ScannerError::Other(format!("Invalid private key hex: {}", e)))?;
        
        if private_key_bytes.len() != 32 {
            return Err(ScannerError::Other(format!(
                "Invalid Ethereum private key length: got {} bytes, expected 32",
                private_key_bytes.len()
            )));
        }
        
        // Generate public key using secp256k1
        let secp = secp256k1::Secp256k1::new();
        let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| ScannerError::Other(format!("Invalid private key: {}", e)))?;
        
        // Get the public key (uncompressed format)
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_serialized = public_key.serialize_uncompressed();
        
        // Take the last 64 bytes of the public key (remove the prefix 0x04)
        let public_key_without_prefix = &public_key_serialized[1..];
        
        // Hash the public key with Keccak-256
        use tiny_keccak::{Hasher, Keccak};
        let mut keccak = Keccak::v256();
        let mut hash = [0u8; 32];
        keccak.update(public_key_without_prefix);
        keccak.finalize(&mut hash);
        
        // Take the last 20 bytes and format as Ethereum address
        let eth_address = format!("0x{}", hex::encode(&hash[12..32]));
        
        Ok(eth_address)
    }

    /// Process an archive file (ZIP, etc.)
    fn process_archive_file(&self, file_path: &Path) -> Result<()> {
        info!("Processing archive file: {}", file_path.display());
        
        #[cfg(feature = "archive")]
        {
            use std::io::{Cursor, Read};
            use tempfile::tempdir;
            use zip::ZipArchive;
            
            // Open the ZIP file
            let file = fs::File::open(file_path).map_err(|e| {
                error!("Failed to open archive file {}: {}", file_path.display(), e);
                ScannerError::IoError(e)
            })?;
            
            // Create a ZIP archive reader
            let mut archive = ZipArchive::new(file).map_err(|e| {
                error!("Failed to read ZIP archive {}: {}", file_path.display(), e);
                ScannerError::Other(format!("ZIP error: {}", e))
            })?;
            
            // Create a temporary directory for extracted files
            let temp_dir = tempdir().map_err(|e| {
                error!("Failed to create temporary directory: {}", e);
                ScannerError::IoError(e)
            })?;
            
            debug!("Created temporary directory for archive extraction: {}", temp_dir.path().display());
            
            // Process each file in the archive
            for i in 0..archive.len() {
                // Check for shutdown signal
                if self.shutdown.load(Ordering::Relaxed) {
                    return Ok(());
                }
                
                let mut file = match archive.by_index(i) {
                    Ok(file) => file,
                    Err(e) => {
                        error!("Failed to access file in archive at index {}: {}", i, e);
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                
                if file.is_dir() {
                    // Skip directories
                    continue;
                }
                
                let filename = match file.enclosed_name() {
                    Some(path) => path.to_path_buf(),
                    None => {
                        error!("Invalid file name in archive at index {}", i);
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                
                // Create a temporary path for this file
                let temp_path = temp_dir.path().join(&filename);
                
                // Create parent directories if needed
                if let Some(parent) = temp_path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        error!("Failed to create directory {}: {}", parent.display(), e);
                        ScannerError::IoError(e)
                    })?;
                }
                
                // Extract the file
                let mut contents = Vec::new();
                if let Err(e) = file.read_to_end(&mut contents) {
                    error!("Failed to read file from archive: {}", e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                
                // Write to temporary file
                if let Err(e) = fs::write(&temp_path, &contents) {
                    error!("Failed to write temporary file {}: {}", temp_path.display(), e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                
                // Process the extracted file
                if let Err(e) = self.process_file(&temp_path) {
                    error!("Error processing extracted file {}: {}", temp_path.display(), e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            
            debug!("Finished processing archive: {}", file_path.display());
            Ok(())
        }
        
        #[cfg(not(feature = "archive"))]
        {
            warn!("Archive support not enabled. Skipping archive file: {}", file_path.display());
            Ok(())
        }
    }

    /// Process a document file (DOCX, XLSX)
    fn process_document_file(&self, file_path: &Path) -> Result<()> {
        info!("Processing document file: {}", file_path.display());
        
        #[cfg(any(feature = "docx", feature = "xlsx"))]
        {
            use std::io::{Cursor, Read};
            use tempfile::tempdir;
            use zip::ZipArchive;
            
            // Office documents (DOCX, XLSX) are ZIP archives with XML content
            let file = fs::File::open(file_path).map_err(|e| {
                error!("Failed to open document file {}: {}", file_path.display(), e);
                ScannerError::IoError(e)
            })?;
            
            // Create a ZIP archive reader
            let mut archive = ZipArchive::new(file).map_err(|e| {
                error!("Failed to read document as ZIP archive {}: {}", file_path.display(), e);
                ScannerError::Other(format!("ZIP error: {}", e))
            })?;
            
            // Create a temporary directory
            let temp_dir = tempdir().map_err(|e| {
                error!("Failed to create temporary directory: {}", e);
                ScannerError::IoError(e)
            })?;
            
            // Office XML document formats store text in different files based on type
            let text_files = match file_path.extension().and_then(|ext| ext.to_str()) {
                Some("docx") => vec!["word/document.xml"],
                Some("xlsx") => vec!["xl/sharedStrings.xml", "xl/worksheets/sheet1.xml"],
                Some("pptx") => vec!["ppt/slides/slide1.xml"],
                _ => vec![],
            };
            
            let mut all_text = String::new();
            
            // Extract and read XML files containing text
            for xml_file in &text_files {
                if let Ok(mut file) = archive.by_name(xml_file) {
                    let mut contents = String::new();
                    if let Err(e) = file.read_to_string(&mut contents) {
                        error!("Failed to read XML file from document: {}", e);
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    
                    // Extract text from XML using quick-xml
                    if let Some(extracted_text) = self.extract_text_from_xml(&contents) {
                        all_text.push_str(&extracted_text);
                        all_text.push('\n');
                    }
                }
            }
            
            // Process the extracted text
            if !all_text.is_empty() {
                debug!("Extracted {} characters from document", all_text.len());
                
                // Process each line of text
                for (i, line) in all_text.lines().enumerate() {
                    if !line.trim().is_empty() {
                        // Scan for seed phrases
                        if let Err(e) = self.scan_for_seed_phrases(line, file_path, Some(i + 1)) {
                            error!("Error scanning document text: {}", e);
                            self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                        
                        // Scan for Ethereum private keys if enabled
                        if self.config.scan_eth_keys {
                            if let Err(e) = self.scan_for_eth_keys(line, file_path, Some(i + 1)) {
                                error!("Error scanning document text for ETH keys: {}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            } else {
                debug!("No text extracted from document: {}", file_path.display());
            }
            
            Ok(())
        }
        
        #[cfg(not(any(feature = "docx", feature = "xlsx")))]
        {
            warn!("Document support not enabled. Skipping document file: {}", file_path.display());
            Ok(())
        }
    }
    
    /// Extract text from XML content
    #[cfg(any(feature = "docx", feature = "xlsx"))]
    fn extract_text_from_xml(&self, xml_content: &str) -> Option<String> {
        use quick_xml::events::Event;
        use quick_xml::reader::Reader;
        
        let mut reader = Reader::from_str(xml_content);
        reader.trim_text(true);
        
        let mut text = String::new();
        let mut buf = Vec::new();
        
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Text(e)) => {
                    if let Ok(txt) = e.unescape() {
                        if !txt.trim().is_empty() {
                            text.push_str(&txt);
                            text.push(' ');
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    error!("Error parsing XML: {}", e);
                    break;
                }
                _ => (),
            }
            buf.clear();
        }
        
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }
    
    #[cfg(not(any(feature = "docx", feature = "xlsx")))]
    fn extract_text_from_xml(&self, _xml_content: &str) -> Option<String> {
        None
    }

    /// Process a PDF file
    fn process_pdf_file(&self, file_path: &Path) -> Result<()> {
        info!("Processing PDF file: {}", file_path.display());
        
        #[cfg(feature = "pdf_support")]
        {
            use pdf::file::File as PdfFile;
            use pdf::object::*;
            use pdf::primitive::Primitive;
            use std::io::Read;
            
            // Open the PDF file
            let file = std::fs::File::open(file_path).map_err(|e| {
                error!("Failed to open PDF file {}: {}", file_path.display(), e);
                ScannerError::IoError(e)
            })?;
            
            // Parse the PDF
            let pdf = PdfFile::from_reader(file).map_err(|e| {
                error!("Failed to parse PDF file {}: {}", file_path.display(), e);
                ScannerError::Other(format!("PDF error: {}", e))
            })?;
            
            // Extract text from each page
            let mut all_text = String::new();
            
            for i in 1..=pdf.num_pages() {
                // Check for shutdown signal
                if self.shutdown.load(Ordering::Relaxed) {
                    return Ok(());
                }
                
                if let Ok(page) = pdf.get_page(i) {
                    if let Ok(content) = page.contents() {
                        // Extract text from content streams
                        if let Some(text) = self.extract_text_from_pdf_content(&content) {
                            all_text.push_str(&text);
                            all_text.push('\n');
                        }
                    }
                }
            }
            
            // Process the extracted text
            if !all_text.is_empty() {
                debug!("Extracted {} characters from PDF", all_text.len());
                
                // Process each line of text
                for (i, line) in all_text.lines().enumerate() {
                    if !line.trim().is_empty() {
                        // Scan for seed phrases
                        if let Err(e) = self.scan_for_seed_phrases(line, file_path, Some(i + 1)) {
                            error!("Error scanning PDF text: {}", e);
                            self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                        
                        // Scan for Ethereum private keys if enabled
                        if self.config.scan_eth_keys {
                            if let Err(e) = self.scan_for_eth_keys(line, file_path, Some(i + 1)) {
                                error!("Error scanning PDF text for ETH keys: {}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            } else {
                debug!("No text extracted from PDF: {}", file_path.display());
            }
            
            Ok(())
        }
        
        #[cfg(not(feature = "pdf_support"))]
        {
            warn!("PDF support not enabled. Skipping PDF file: {}", file_path.display());
            Ok(())
        }
    }
    
    #[cfg(feature = "pdf_support")]
    /// Helper function to extract text from PDF content stream
    fn extract_text_from_pdf_content(&self, content: &[u8]) -> Option<String> {
        // This is a simplified extraction - real PDF text extraction is complex
        // For a production implementation, consider using a more robust PDF text extraction library
        let content_str = String::from_utf8_lossy(content);
        let mut text = String::new();
        
        // Simple extraction of text between BT and ET markers (Begin Text/End Text)
        let parts: Vec<&str> = content_str.split("BT").collect();
        for part in parts.iter().skip(1) {
            if let Some(end_idx) = part.find("ET") {
                let text_section = &part[..end_idx];
                
                // Extract text operators (Tj, TJ, etc.)
                if let Some(idx) = text_section.find("(") {
                    if let Some(end) = text_section[idx..].find(")") {
                        let extracted = &text_section[idx + 1..idx + end];
                        text.push_str(extracted);
                        text.push(' ');
                    }
                }
            }
        }
        
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Signal the scanner to shut down
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Get reference to the scanning statistics
    pub fn stats(&self) -> &Arc<ScanStats> {
        &self.stats
    }

    /// Check if a word is a valid BIP39 word
    pub fn is_valid_bip39_word(&self, word: &str) -> bool {
        self.parser.is_valid_word(word)
    }
}

// Unit tests for the scanner module
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    // Mock database controller for testing
    struct MockDbController {
        phrases: Arc<Mutex<Vec<FoundPhrase>>>,
        eth_keys: Arc<Mutex<Vec<FoundEthKey>>>,
    }

    impl MockDbController {
        fn new() -> Self {
            Self {
                phrases: Arc::new(Mutex::new(Vec::new())),
                eth_keys: Arc::new(Mutex::new(Vec::new())),
            }
        }
        
        fn phrases(&self) -> Vec<FoundPhrase> {
            self.phrases.lock().unwrap().clone()
        }
        
        fn eth_keys(&self) -> Vec<FoundEthKey> {
            self.eth_keys.lock().unwrap().clone()
        }
    }

    impl DbController for MockDbController {
        fn init(&self) -> Result<()> {
            Ok(())
        }

        fn insert_phrase(&self, phrase: &FoundPhrase) -> Result<bool> {
            let mut phrases = self.phrases.lock().unwrap();
            // Check for duplicates
            if phrases.contains(phrase) {
                return Ok(false);
            }
            phrases.push(phrase.clone());
            Ok(true)
        }

        fn insert_eth_key(&self, key: &FoundEthKey) -> Result<bool> {
            let mut eth_keys = self.eth_keys.lock().unwrap();
            // Check for duplicates
            if eth_keys.contains(key) {
                return Ok(false);
            }
            eth_keys.push(key.clone());
            Ok(true)
        }

        fn get_all_phrases(&self) -> Result<Vec<FoundPhrase>> {
            Ok(self.phrases.lock().unwrap().clone())
        }

        fn get_all_eth_keys(&self) -> Result<Vec<FoundEthKey>> {
            Ok(self.eth_keys.lock().unwrap().clone())
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    // Helper function to create a test parser
    fn create_test_parser() -> Parser {
        let parser_config = ParserConfig {
            validate_checksum: true,
            max_words: 24,
            valid_word_counts: vec![12, 15, 18, 21, 24],
            wordlist_name: "english".to_string(),
        };
        
        Parser::new(
            Path::new("data").to_path_buf(),
            "english".to_string(),
            parser_config,
        )
        .unwrap()
    }

    #[test]
    fn test_scan_config_default() {
        let config = ScannerConfig::default();
        assert_eq!(config.threads, num_cpus::get());
        assert_eq!(config.max_memory, 1024 * 1024 * 1024);
        assert_eq!(config.batch_size, 1000);
        assert!(config.scan_eth_keys);
        assert!(config.use_fuzzy_matching);
        assert!(config.use_ocr);
        assert_eq!(config.min_bip39_words, 11);
        assert!((config.fuzzy_threshold - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_scan_stats() {
        let stats = ScanStats::new();
        stats.files_processed.store(100, Ordering::Relaxed);
        stats.bytes_processed.store(1024 * 1024 * 50, Ordering::Relaxed); // 50 MB
        
        // Sleep to make elapsed time non-zero
        std::thread::sleep(Duration::from_millis(100));
        
        let rate = stats.processing_rate();
        assert!(rate > 0.0);
        
        let elapsed = stats.elapsed_seconds();
        assert!(elapsed > 0);
    }

    #[test]
    fn test_should_skip_file() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create test files with different extensions
        let txt_file = temp_path.join("test.txt");
        let jpg_file = temp_path.join("test.jpg");
        let rs_file = temp_path.join("test.rs");
        
        File::create(&txt_file).unwrap();
        File::create(&jpg_file).unwrap();
        File::create(&rs_file).unwrap();
        
        // Create scanner with default config (excludes jpg)
        let db = Box::new(MockDbController::new());
        let scanner = Scanner::new(
            ScannerConfig::default(),
            create_test_parser(),
            db,
        ).unwrap();
        
        // JPG should be skipped
        assert!(scanner.should_skip_file(&jpg_file));
        
        // TXT and RS should not be skipped
        assert!(!scanner.should_skip_file(&txt_file));
        assert!(!scanner.should_skip_file(&rs_file));
        
        // Now create a scanner with custom include list
        let mut config = ScannerConfig::default();
        config.include_extensions = vec!["txt".to_string()];
        
        let db = Box::new(MockDbController::new());
        let scanner = Scanner::new(
            config,
            create_test_parser(),
            db,
        ).unwrap();
        
        // Only TXT should not be skipped
        assert!(!scanner.should_skip_file(&txt_file));
        assert!(scanner.should_skip_file(&jpg_file));
        assert!(scanner.should_skip_file(&rs_file));
    }

    #[test]
    fn test_is_image_file() {
        let scanner = Scanner::new(
            ScannerConfig::default(),
            create_test_parser(),
            Box::new(MockDbController::new()),
        ).unwrap();
        
        assert!(scanner.is_image_file(Path::new("test.jpg")));
        assert!(scanner.is_image_file(Path::new("test.jpeg")));
        assert!(scanner.is_image_file(Path::new("test.png")));
        assert!(scanner.is_image_file(Path::new("test.gif")));
        assert!(scanner.is_image_file(Path::new("test.bmp")));
        
        assert!(!scanner.is_image_file(Path::new("test.txt")));
        assert!(!scanner.is_image_file(Path::new("test.pdf")));
        assert!(!scanner.is_image_file(Path::new("test")));
    }

    #[test]
    fn test_scan_for_eth_keys() {
        let db_controller = MockDbController::new();
        let db = Box::new(db_controller.clone());
        
        let scanner = Scanner::new(
            ScannerConfig::default(),
            create_test_parser(),
            db,
        ).unwrap();
        
        // Test valid Ethereum key
        let text = "Here is a private key: 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        scanner.scan_for_eth_keys(text, Path::new("test.txt"), Some(1)).unwrap();
        
        let eth_keys = db_controller.eth_keys();
        assert_eq!(eth_keys.len(), 1);
        assert_eq!(eth_keys[0].private_key, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        
        // Test invalid keys
        let text = "This is not a key: 0x01234 and this is too short: 0x0123456789";
        scanner.scan_for_eth_keys(text, Path::new("test.txt"), Some(2)).unwrap();
        
        let eth_keys = db_controller.eth_keys();
        assert_eq!(eth_keys.len(), 1); // Still just 1
    }

    #[test]
    fn test_is_valid_bip39_word() {
        let scanner = Scanner::new(
            ScannerConfig::default(),
            create_test_parser(),
            Box::new(MockDbController::new()),
        ).unwrap();
        
        // Valid BIP39 words
        assert!(scanner.is_valid_bip39_word("abandon"));
        assert!(scanner.is_valid_bip39_word("about"));
        assert!(scanner.is_valid_bip39_word("zoo"));
        
        // Invalid BIP39 words
        assert!(!scanner.is_valid_bip39_word("notaword"));
        assert!(!scanner.is_valid_bip39_word("xxxxx"));
    }

    #[test]
    fn test_shutdown_functionality() {
        let scanner = Scanner::new(
            ScannerConfig::default(),
            create_test_parser(),
            Box::new(MockDbController::new()),
        ).unwrap();
        
        // Initially not shutdown
        assert!(!scanner.shutdown.load(Ordering::Relaxed));
        
        // Signal shutdown
        scanner.shutdown();
        
        // Now should be shutdown
        assert!(scanner.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn test_file_type_detection() {
        let scanner = Scanner::new(
            ScannerConfig::default(),
            create_test_parser(),
            Box::new(MockDbController::new()),
        ).unwrap();
        
        // Image files
        assert!(scanner.is_image_file(Path::new("test.jpg")));
        assert!(scanner.is_image_file(Path::new("test.png")));
        assert!(!scanner.is_image_file(Path::new("test.txt")));
        
        // Document files
        assert!(scanner.is_document_file(Path::new("test.docx")));
        assert!(scanner.is_document_file(Path::new("test.xlsx")));
        assert!(scanner.is_document_file(Path::new("test.pptx")));
        assert!(!scanner.is_document_file(Path::new("test.txt")));
        
        // Archive files
        assert!(scanner.is_archive_file(Path::new("test.zip")));
        assert!(scanner.is_archive_file(Path::new("test.tar.gz")));
        assert!(!scanner.is_archive_file(Path::new("test.txt")));
        
        // PDF files
        assert!(scanner.is_pdf_file(Path::new("test.pdf")));
        assert!(!scanner.is_pdf_file(Path::new("test.txt")));
    }

    #[test]
    fn test_scan_modes() {
        // Test Fast mode
        let config = ScannerConfig::fast();
        assert_eq!(config.scan_mode, ScanMode::Fast);
        assert!(!config.use_fuzzy_matching);
        assert!(!config.use_ocr);
        assert!(!config.scan_archives);
        assert!(!config.scan_documents);
        assert!(!config.scan_pdfs);
        assert_eq!(config.min_bip39_words, 12);
        assert!((config.fuzzy_threshold - 0.95).abs() < 0.001);
        
        // Test Default mode
        let config = ScannerConfig::default_mode();
        assert_eq!(config.scan_mode, ScanMode::Default);
        assert!(config.use_fuzzy_matching);
        assert!(!config.use_ocr);
        assert!(!config.scan_archives);
        assert!(!config.scan_documents);
        assert!(!config.scan_pdfs);
        
        // Test Enhanced mode
        let config = ScannerConfig::enhanced();
        assert_eq!(config.scan_mode, ScanMode::Enhanced);
        assert!(config.use_fuzzy_matching);
        assert!(config.use_ocr);
        assert!(!config.scan_archives);
        assert!(!config.scan_documents);
        assert!(!config.scan_pdfs);
        
        // Test Comprehensive mode
        let config = ScannerConfig::comprehensive();
        assert_eq!(config.scan_mode, ScanMode::Comprehensive);
        assert!(config.use_fuzzy_matching);
        assert!(config.use_ocr);
        assert!(config.scan_archives);
        assert!(config.scan_documents);
        assert!(config.scan_pdfs);
        
        // Test apply_scan_mode
        let mut config = ScannerConfig::default();
        config.use_fuzzy_matching = false;
        config.use_ocr = true;
        config.scan_mode = ScanMode::Fast;
        config.apply_scan_mode();
        
        assert_eq!(config.scan_mode, ScanMode::Fast);
        assert!(!config.use_fuzzy_matching);
        assert!(!config.use_ocr); // Should be false now
        assert!(!config.scan_archives);
        assert!(!config.scan_documents);
        assert!(!config.scan_pdfs);
    }
} 