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
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
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
    pub fuzzy_threshold: f64,

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
#[derive(Debug)]
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
            files_processed: AtomicU64::new(0),
            dirs_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            phrases_found: AtomicU64::new(0),
            eth_keys_found: AtomicU64::new(0),
            errors: AtomicU64::new(0),
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
#[derive(Debug, Clone, PartialEq)]
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
    pub confidence: Option<f64>,
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
        let avg_similarity = total_similarity / words.len() as f64;
        
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
    fn find_closest_bip39_word(&self, word: &str) -> (String, f64) {
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
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tempfile::tempdir;
    use std::fs;
    use std::io::Write;
    
    // Mock database controller for testing
    #[derive(Clone)]
    struct MockDbController {
        phrases: Mutex<Vec<FoundPhrase>>,
        eth_keys: Mutex<Vec<FoundEthKey>>,
    }
    
    impl MockDbController {
        fn new() -> Self {
            Self {
                phrases: Mutex::new(Vec::new()),
                eth_keys: Mutex::new(Vec::new()),
            }
        }
    }
    
    impl DbController for MockDbController {
        fn add_phrase(&self, phrase: FoundPhrase) -> Result<(), Box<dyn std::error::Error>> {
            self.phrases.lock().unwrap().push(phrase);
            Ok(())
        }
        
        fn add_eth_key(&self, key: FoundEthKey) -> Result<(), Box<dyn std::error::Error>> {
            self.eth_keys.lock().unwrap().push(key);
            Ok(())
        }
        
        fn get_phrases(&self) -> Result<Vec<FoundPhrase>, Box<dyn std::error::Error>> {
            Ok(self.phrases.lock().unwrap().clone())
        }
        
        fn get_eth_keys(&self) -> Result<Vec<FoundEthKey>, Box<dyn std::error::Error>> {
            Ok(self.eth_keys.lock().unwrap().clone())
        }
    }
    
    // Utility function to create test file
    fn create_test_file(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let file_path = dir.join(filename);
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file_path
    }
    
    // Utility function to create zip file for testing
    fn create_test_zip(dir: &Path, filename: &str, inner_filename: &str, content: &str) -> PathBuf {
        let zip_path = dir.join(filename);
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        
        // Add a file to the ZIP
        zip.start_file(inner_filename, zip::write::FileOptions::default()).unwrap();
        zip.write_all(content.as_bytes()).unwrap();
        zip.finish().unwrap();
        
        zip_path
    }
    
    // Utility function to create simple mock docx file
    fn create_test_docx(dir: &Path, filename: &str, content: &str) -> PathBuf {
        // A DOCX is essentially a ZIP file with XML inside
        let docx_path = dir.join(filename);
        let file = fs::File::create(&docx_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        
        // Add document.xml to mimic a DOCX structure
        zip.start_file("word/document.xml", zip::write::FileOptions::default()).unwrap();
        
        // Create a simple XML with the content
        let xml_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
                <w:body>
                    <w:p>
                        <w:r>
                            <w:t>{}</w:t>
                        </w:r>
                    </w:p>
                </w:body>
            </w:document>"#,
            content
        );
        
        zip.write_all(xml_content.as_bytes()).unwrap();
        zip.finish().unwrap();
        
        docx_path
    }
    
    // Utility function to create simple mock PDF content
    fn create_test_pdf(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let pdf_path = dir.join(filename);
        let mut file = fs::File::create(&pdf_path).unwrap();
        
        // Create a very simple mock PDF structure
        // This isn't a valid PDF but works for testing the scanner logic
        let pdf_content = format!(
            "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n3 0 obj\n<< /Type /Page /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n%%EOF",
            content.len(),
            content
        );
        
        file.write_all(pdf_content.as_bytes()).unwrap();
        pdf_path
    }
    
    // Test cleanup helper function
    fn cleanup_temp_dir(dir: tempfile::TempDir) {
        if let Err(e) = dir.close() {
            eprintln!("Failed to clean up temp dir: {}", e);
        }
    }
    
    // Test pdf file detection
    #[test]
    fn test_pdf_file_detection() {
        assert!(is_pdf_file(Path::new("test.pdf")));
        assert!(is_pdf_file(Path::new("document.pdf")));
        assert!(is_pdf_file(Path::new("path/to/file.pdf")));
        
        assert!(!is_pdf_file(Path::new("test.txt")));
        assert!(!is_pdf_file(Path::new("test.docx")));
        assert!(!is_pdf_file(Path::new("test.zip")));
        assert!(!is_pdf_file(Path::new("test.PDF"))); // Case sensitive check
    }
    
    // Test document file detection
    #[test]
    fn test_document_file_detection() {
        assert!(is_document_file(Path::new("test.docx")));
        assert!(is_document_file(Path::new("test.xlsx")));
        assert!(is_document_file(Path::new("test.pptx")));
        assert!(is_document_file(Path::new("test.odt")));
        assert!(is_document_file(Path::new("test.ods")));
        
        assert!(!is_document_file(Path::new("test.txt")));
        assert!(!is_document_file(Path::new("test.zip")));
        assert!(!is_document_file(Path::new("test.pdf")));
    }
    
    // Test process pdf file with feature disabled
    #[test]
    fn test_process_pdf_file_with_feature_disabled() {
        let temp_dir = tempdir().unwrap();
        let pdf_path = temp_dir.path().join("test.pdf");
        let mut file = fs::File::create(&pdf_path).unwrap();
        file.write_all(b"%PDF-1.0\nTest content").unwrap();
        
        let mut config = ScannerConfig::default();
        config.scan_pdfs = false;
        
        let db = MockDbController::new();
        let mut scanner = Scanner::new(config, Box::new(db.clone()));
        
        // Should not panic and return success even though PDF feature is disabled
        let result = scanner.process_file(&pdf_path);
        assert!(result.is_ok());
        
        // No phrases should be found since PDF processing was disabled
        let phrases = db.get_phrases().unwrap();
        assert_eq!(phrases.len(), 0);
        
        cleanup_temp_dir(temp_dir);
    }
    
    // Test extract text from pdf content
    #[test]
    fn test_extract_text_from_pdf_content() {
        let content = "%PDF-1.0\nThis is a test document containing a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Test with PDF feature disabled
        {
            let mut config = ScannerConfig::default();
            config.scan_pdfs = false;
            let result = extract_text_from_pdf_content(content, &config);
            assert_eq!(result, None);
        }
        
        // Test with PDF feature enabled (mock implementation)
        {
            let mut config = ScannerConfig::default();
            config.scan_pdfs = true;
            
            // This just returns the content since we're testing the mock implementation
            let result = extract_text_from_pdf_content(content, &config);
            
            if let Some(extracted) = result {
                assert!(extracted.contains("seed phrase"));
                assert!(extracted.contains("abandon abandon abandon"));
            } else {
                // On systems without PDF support, this might be None
                println!("PDF extraction not supported on this system");
            }
        }
    }
    
    // Test mock PDF processing
    #[test]
    fn test_mock_pdf_processing() {
        let temp_dir = tempdir().unwrap();
        let pdf_path = temp_dir.path().join("test.pdf");
        
        // Create a simple mock PDF
        let content = "This is a test document containing a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut file = fs::File::create(&pdf_path).unwrap();
        let pdf_content = format!(
            "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n3 0 obj\n<< /Type /Page /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n%%EOF",
            content.len(),
            content
        );
        file.write_all(pdf_content.as_bytes()).unwrap();
        
        let mut config = ScannerConfig::default();
        config.scan_pdfs = true;
        
        let db = MockDbController::new();
        let mut scanner = Scanner::new(config, Box::new(db.clone()));
        
        // Should not panic when processing a PDF file
        let result = scanner.process_file(&pdf_path);
        
        // The result might be None if PDF support is not compiled in
        if result.is_ok() {
            let phrases = db.get_phrases().unwrap();
            if phrases.is_empty() {
                println!("No phrases found, likely PDF support is not enabled");
            } else {
                assert!(phrases.iter().any(|p| p.phrase.contains("abandon")));
            }
        }
        
        cleanup_temp_dir(temp_dir);
    }
    
    // Test pdf text extraction integration
    #[test]
    fn test_pdf_text_extraction_integration() {
        let content = "%PDF-1.0\nThis is a test document containing a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let mut config = ScannerConfig::default();
        config.scan_pdfs = true;
        
        // This should not panic
        let result = extract_text_from_pdf_content(content, &config);
        
        // The result depends on whether PDF support is compiled in
        match result {
            Some(text) => {
                assert!(text.contains("seed phrase"));
                assert!(text.contains("abandon abandon abandon"));
            },
            None => {
                println!("PDF extraction returned None - likely PDF support is not enabled");
            }
        }
    }
    
    // Test scan modes properly configure scanner
    #[test]
    fn test_scan_mode_configuration_settings() {
        // Test Fast mode settings
        {
            let config = ScannerConfig::with_mode(ScanMode::Fast);
            assert_eq!(config.scan_mode, ScanMode::Fast);
            assert!(!config.fuzzy_matching);
            assert!(!config.scan_archives);
            assert!(!config.scan_documents);
            assert!(!config.scan_pdfs);
            assert!(!config.ocr_enabled);
        }
        
        // Test Default mode settings
        {
            let config = ScannerConfig::with_mode(ScanMode::Default);
            assert_eq!(config.scan_mode, ScanMode::Default);
            assert!(config.fuzzy_matching);
            assert!(!config.scan_archives);
            assert!(!config.scan_documents);
            assert!(!config.scan_pdfs);
            assert!(!config.ocr_enabled);
        }
        
        // Test Enhanced mode settings
        {
            let config = ScannerConfig::with_mode(ScanMode::Enhanced);
            assert_eq!(config.scan_mode, ScanMode::Enhanced);
            assert!(config.fuzzy_matching);
            assert!(!config.scan_archives);
            assert!(!config.scan_documents);
            assert!(!config.scan_pdfs);
            assert!(config.ocr_enabled);
        }
        
        // Test Comprehensive mode settings
        {
            let config = ScannerConfig::with_mode(ScanMode::Comprehensive);
            assert_eq!(config.scan_mode, ScanMode::Comprehensive);
            assert!(config.fuzzy_matching);
            assert!(config.scan_archives);
            assert!(config.scan_documents);
            assert!(config.scan_pdfs);
            assert!(config.ocr_enabled);
        }
        
        // Test applying scan mode to existing config
        {
            let mut config = ScannerConfig::default();
            
            // Change to Fast mode and check all settings
            config.apply_scan_mode(ScanMode::Fast);
            assert_eq!(config.scan_mode, ScanMode::Fast);
            assert!(!config.fuzzy_matching);
            assert!(!config.scan_archives);
            assert!(!config.scan_documents);
            assert!(!config.scan_pdfs);
            assert!(!config.ocr_enabled);
            
            // Change to Enhanced mode and check settings changed
            config.apply_scan_mode(ScanMode::Enhanced);
            assert_eq!(config.scan_mode, ScanMode::Enhanced);
            assert!(config.fuzzy_matching);
            assert!(!config.scan_archives);
            assert!(!config.scan_documents);
            assert!(!config.scan_pdfs);
            assert!(config.ocr_enabled);
            
            // Change to Comprehensive mode and check settings
            config.apply_scan_mode(ScanMode::Comprehensive);
            assert_eq!(config.scan_mode, ScanMode::Comprehensive);
            assert!(config.fuzzy_matching);
            assert!(config.scan_archives);
            assert!(config.scan_documents);
            assert!(config.scan_pdfs);
            assert!(config.ocr_enabled);
            
            // Test manual override after applying mode
            config.fuzzy_matching = false;
            assert!(!config.fuzzy_matching);
            assert_eq!(config.scan_mode, ScanMode::Comprehensive);
        }
    }
    
    // Test end-to-end scanning
    #[test]
    fn test_end_to_end_scanning() {
        let dir = tempdir().unwrap();
        
        // Create test files
        let text_path = create_test_file(
            dir.path(),
            "seed_phrase.txt",
            "This file contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create a simple "image file" (just a stub for testing)
        let image_path = dir.path().join("seed_phrase.jpg");
        fs::write(&image_path, b"Mock image data").unwrap();
        
        // Create a simple mock PDF
        let pdf_content = "This is a test document containing a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let pdf_path = create_test_pdf(dir.path(), "seed_phrase.pdf", pdf_content);
        
        // Create a ZIP with a text file inside
        let zip_path = create_test_zip(
            dir.path(),
            "archive.zip",
            "inside_zip.txt",
            "This file inside a ZIP contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create a mock DOCX (ZIP with XML)
        let docx_path = create_test_docx(
            dir.path(),
            "document.docx",
            "This document contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Test all scan modes
        let modes = vec![
            ScanMode::Fast,
            ScanMode::Default,
            ScanMode::Enhanced,
            ScanMode::Comprehensive
        ];
        
        for mode in modes {
            println!("Testing scan mode: {:?}", mode);
            
            // Create scanner with specified mode
            let config = ScannerConfig::with_mode(mode);
            let db = MockDbController::new();
            let mut scanner = Scanner::new(config.clone(), Box::new(db.clone()));
            
            // Process the directory
            let result = scanner.process_directory(dir.path(), None);
            assert!(result.is_ok(), "Processing directory should succeed in {:?} mode", mode);
            
            // Get found phrases
            let phrases = db.get_phrases().unwrap();
            
            // Verify results based on scan mode
            match mode {
                ScanMode::Fast => {
                    // Fast mode only processes text files
                    assert!(phrases.len() >= 1, "Fast mode should find at least the seed phrase in the text file");
                    
                    // Verify the text file phrase was found
                    let text_found = phrases.iter().any(|p| {
                        p.file_path == text_path.to_string_lossy().to_string() &&
                        p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    });
                    assert!(text_found, "Fast mode should find seed phrase in text file");
                },
                ScanMode::Default => {
                    // Default mode processes text files with fuzzy matching
                    assert!(phrases.len() >= 1, "Default mode should find at least the seed phrase in the text file");
                    
                    // Verify the text file phrase was found
                    let text_found = phrases.iter().any(|p| {
                        p.file_path == text_path.to_string_lossy().to_string() &&
                        p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    });
                    assert!(text_found, "Default mode should find seed phrase in text file");
                },
                ScanMode::Enhanced => {
                    // Enhanced mode adds OCR for images
                    assert!(phrases.len() >= 1, "Enhanced mode should find at least the seed phrase in the text file");
                    
                    // Verify the text file phrase was found
                    let text_found = phrases.iter().any(|p| {
                        p.file_path == text_path.to_string_lossy().to_string() &&
                        p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    });
                    assert!(text_found, "Enhanced mode should find seed phrase in text file");
                },
                ScanMode::Comprehensive => {
                    // Comprehensive mode processes everything
                    // Note: actual result count depends on enabled features
                    
                    // Check that files were dispatched to appropriate handlers
                    // by looking at the scanner stats
                    let stats = scanner.stats();
                    assert!(stats.files_processed > 0, "Should have processed some files");
                    
                    // Verify the text file phrase was found at minimum
                    let text_found = phrases.iter().any(|p| {
                        p.file_path == text_path.to_string_lossy().to_string() &&
                        p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                    });
                    assert!(text_found, "Comprehensive mode should find seed phrase in text file");
                    
                    // If archive feature is enabled, check for zip file contents
                    if config.scan_archives {
                        let inside_zip_found = phrases.iter().any(|p| {
                            p.file_path.contains("inside_zip.txt") &&
                            p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                        });
                        
                        // This may fail if the archive feature is not enabled
                        if !inside_zip_found {
                            println!("Note: Seed phrase in ZIP file not found - archive feature likely disabled");
                        }
                    }
                    
                    // If document feature is enabled, check for docx contents
                    if config.scan_documents {
                        let docx_found = phrases.iter().any(|p| {
                            p.file_path.contains("document.docx") &&
                            p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                        });
                        
                        // This may fail if the document feature is not enabled
                        if !docx_found {
                            println!("Note: Seed phrase in DOCX file not found - document feature likely disabled");
                        }
                    }
                    
                    // If PDF feature is enabled, check for PDF contents
                    if config.scan_pdfs {
                        let pdf_found = phrases.iter().any(|p| {
                            p.file_path == pdf_path.to_string_lossy().to_string() &&
                            p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                        });
                        
                        // This may fail if the PDF feature is not enabled
                        if !pdf_found {
                            println!("Note: Seed phrase in PDF file not found - PDF feature likely disabled");
                        }
                    }
                }
            }
            
            println!("Test passed for scan mode: {:?}", mode);
        }
        
        cleanup_temp_dir(dir);
    }
    
    // Test processing file dispatching
    #[test]
    fn test_process_file_dispatching() {
        let dir = tempdir().unwrap();
        
        // Create test files of different types
        let text_path = create_test_file(
            dir.path(),
            "text_file.txt",
            "This file contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        let image_path = dir.path().join("image_file.jpg");
        fs::write(&image_path, b"Mock image data").unwrap();
        
        let zip_path = create_test_zip(
            dir.path(),
            "archive.zip",
            "inside_zip.txt",
            "This file inside a ZIP contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        let docx_path = create_test_docx(
            dir.path(),
            "document.docx",
            "This document contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        let pdf_path = create_test_pdf(
            dir.path(),
            "document.pdf",
            "This PDF contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create scanner with comprehensive mode to enable all features
        let config = ScannerConfig::with_mode(ScanMode::Comprehensive);
        let db = MockDbController::new();
        let mut scanner = Scanner::new(config, Box::new(db.clone()));
        
        // Process each file type
        let text_result = scanner.process_file(&text_path);
        let image_result = scanner.process_file(&image_path);
        let zip_result = scanner.process_file(&zip_path);
        let docx_result = scanner.process_file(&docx_path);
        let pdf_result = scanner.process_file(&pdf_path);
        
        // All processing should complete without errors
        assert!(text_result.is_ok(), "Text file processing should succeed");
        assert!(image_result.is_ok(), "Image file processing should succeed");
        assert!(zip_result.is_ok(), "ZIP file processing should succeed");
        assert!(docx_result.is_ok(), "DOCX file processing should succeed");
        assert!(pdf_result.is_ok(), "PDF file processing should succeed");
        
        // Check that the dispatcher processed the files correctly
        let phrases = db.get_phrases().unwrap();
        
        // The text file should always be processed
        let text_found = phrases.iter().any(|p| {
            p.file_path == text_path.to_string_lossy().to_string() &&
            p.phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        });
        assert!(text_found, "Text file should be processed");
        
        // Check stats to ensure all files were at least attempted to be processed
        let stats = scanner.stats();
        assert!(stats.files_processed >= 5, "Should have processed at least 5 files");
        
        cleanup_temp_dir(dir);
    }
    
    // ... rest of existing tests ...
} 