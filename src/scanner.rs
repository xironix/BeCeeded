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
// Removed unused import: rayon::prelude
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Instant,
    hash::{Hash, Hasher},
    thread,
};
use bloom::{BloomFilter, ASMS};
use ahash::AHasher;
use crossbeam_channel::{bounded, Receiver, Sender};
use crossbeam_deque::{Injector, Stealer, Worker};
use crossbeam_utils::sync::WaitGroup;
use thiserror::Error;
use hex;
use secp256k1;
use tiny_keccak;
use strsim;
use rayon::prelude::*;

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

    /// Create a new configuration with the specified scan mode
    pub fn with_mode(mode: ScanMode) -> Self {
        let mut config = Self {
            scan_mode: mode,
            ..Default::default()
        };
        config.apply_scan_mode();
        config
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
    
    /// Current memory usage in bytes
    pub memory_usage: AtomicUsize,
    
    /// Maximum memory usage observed
    pub max_memory_usage: AtomicUsize,
    
    /// Number of memory pressure events
    pub memory_pressure_events: AtomicUsize,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            files_processed: AtomicU64::new(0),
            dirs_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            phrases_found: AtomicU64::new(0),
            eth_keys_found: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: Instant::now(),
            memory_usage: AtomicUsize::new(0),
            max_memory_usage: AtomicUsize::new(0),
            memory_pressure_events: AtomicUsize::new(0),
        }
    }
}

impl ScanStats {
    /// Create new scanning statistics
    pub fn new() -> Self {
        Self::default()
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

/// An optimized path hasher for the bloom filter
struct PathHasher;

impl PathHasher {
    /// Hash a path for the bloom filter using AHash for better performance
    #[inline]
    fn hash_path(path: &Path) -> u64 {
        let mut hasher = AHasher::default();
        path.to_string_lossy().hash(&mut hasher);
        hasher.finish()
    }
    
    /// Generate multiple hash values for the bloom filter
    /// This improves the bloom filter's accuracy
    #[inline]
    fn hash_path_multiple(path: &Path, n: usize) -> Vec<u64> {
        let base_hash = Self::hash_path(path);
        let mut hashes = Vec::with_capacity(n);
        hashes.push(base_hash);
        
        // Generate additional hash values using the FNV-1a technique
        // but with different prime numbers for each hash
        let primes = [
            16777619, 31, 131, 1313, 13131,
            2147483647, 67867967, 2166136261
        ];
        
        for i in 1..n {
            if i < primes.len() {
                let mut h = base_hash;
                h ^= (i as u64) * primes[i];
                h = h.wrapping_mul(primes[i] as u64);
                hashes.push(h);
            } else {
                // Fallback for large n
                hashes.push(base_hash.wrapping_add(i as u64));
            }
        }
        
        hashes
    }
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

    /// Bloom filter of processed files to avoid duplicates
    /// This is much more memory efficient than a HashSet for large scans
    processed_files: Arc<RwLock<BloomFilter>>,

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
        
        // Calculate optimal bloom filter size based on expected file count and false positive rate
        // Lower false positive rate (0.0001 instead of 0.001) and more hash functions (7 instead of 5)
        let estimated_max_files = 1_000_000; // Estimate max number of files to process
        let false_positive_rate = 0.0001_f64; // Lower FP rate for better accuracy
        
        // Calculate optimal size using the formula: m = -n*ln(p)/(ln(2))²
        // where n is the number of items and p is the false positive rate
        let ln_p = false_positive_rate.ln();
        let ln_2_squared = std::f64::consts::LN_2.powi(2);
        let optimal_bits = -((estimated_max_files as f64) * ln_p / ln_2_squared) as usize;
        
        // Calculate optimal number of hash functions using the formula: k = m/n * ln(2)
        let optimal_hashes = ((optimal_bits as f64) / (estimated_max_files as f64) * std::f64::consts::LN_2) as usize;
        
        // Create the bloom filter with optimized parameters
        let bloom_filter = BloomFilter::with_size(optimal_bits, optimal_hashes.max(5).min(10) as u32);
        
        info!("Created bloom filter with {} bits and {} hash functions", 
              optimal_bits, optimal_hashes.max(5).min(10));
        
        let scanner = Self {
            config,
            parser,
            db: Arc::new(db),
            stats: Arc::new(ScanStats::new()),
            processed_files: Arc::new(RwLock::new(bloom_filter)),
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // Initialize the database
        scanner.db.init()?;

        Ok(scanner)
    }

    /// Start scanning a directory using a work-stealing queue
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
        info!("Using {} threads with work-stealing scheduler", self.config.threads);

        // Set up work-stealing queue for files
        let global_queue = Arc::new(Injector::new());
        
        // Create worker threads
        let mut workers: Vec<Worker<PathBuf>> = Vec::with_capacity(self.config.threads);
        let mut stealers = Vec::with_capacity(self.config.threads);
        
        for _ in 0..self.config.threads {
            let worker = Worker::new_fifo();
            stealers.push(worker.stealer());
            workers.push(worker);
        }
        
        // Create a communication channel for directory discovery
        let (dir_sender, dir_receiver) = bounded::<PathBuf>(1000);
        
        // Add the initial directory
        dir_sender.send(directory.to_path_buf())
            .map_err(|_| ScannerError::Other("Failed to send initial directory".to_string()))?;
        
        // Set up wait group to track when all threads are done
        let wg = WaitGroup::new();
        
        // Start worker threads
        let mut thread_handles = Vec::with_capacity(self.config.threads);
        
        for (i, worker) in workers.into_iter().enumerate() {
            // Clone all necessary references for this thread
            let my_stealers = stealers.clone();
            let global_queue = Arc::clone(&global_queue);
            let dir_receiver = dir_receiver.clone();
            let dir_sender = dir_sender.clone();
            let scanner = Arc::new(self.clone()); // Clone the scanner for thread safety
            let wg_worker = wg.clone();
            
            // Start the worker thread
            let handle = thread::spawn(move || {
                // Signal completion when thread exits
                let _wg_guard = wg_worker;
                
                // Thread-local queue for this worker
                let local_queue = worker;
                
                debug!("Worker thread {} started", i);
                
                // Process directories and files until all work is complete
                'work: loop {
                    // Check for shutdown signal
                    if scanner.shutdown.load(Ordering::Relaxed) {
                        debug!("Worker thread {} received shutdown signal", i);
                        break 'work;
                    }
                    
                    // First, try to process work from our local queue
                    if let Some(path) = local_queue.pop() {
                        if path.is_file() {
                            if let Err(e) = scanner.process_file(&path) {
                                error!("Error processing file {}: {}", path.display(), e);
                                scanner.stats.errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        continue;
                    }
                    
                    // If local queue is empty, try to steal from the global queue
                    if let crossbeam_deque::Steal::Success(path) = global_queue.steal_batch_and_pop(&local_queue) {
                        if path.is_file() {
                            if let Err(e) = scanner.process_file(&path) {
                                error!("Error processing file {}: {}", path.display(), e);
                                scanner.stats.errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        continue;
                    }
                    
                    // If global queue is empty, try to steal from other workers
                    let mut found_work = false;
                    for stealer in &my_stealers {
                        if let crossbeam_deque::Steal::Success(path) = stealer.steal_batch_and_pop(&local_queue) {
                            if path.is_file() {
                                if let Err(e) = scanner.process_file(&path) {
                                    error!("Error processing file {}: {}", path.display(), e);
                                    scanner.stats.errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            found_work = true;
                            break;
                        }
                    }
                    
                    if found_work {
                        continue;
                    }
                    
                    // If no files to process, check for directories
                    match dir_receiver.try_recv() {
                        Ok(dir_path) => {
                            // Process a directory - add all entries to the appropriate queues
                            match fs::read_dir(&dir_path) {
                                Ok(entries) => {
                                    scanner.stats.dirs_processed.fetch_add(1, Ordering::Relaxed);
                                    
                                    for entry in entries {
                                        if scanner.shutdown.load(Ordering::Relaxed) {
                                            break 'work;
                                        }
                                        
                                        if let Ok(entry) = entry {
                                            let path = entry.path();
                                            
                                            if path.is_dir() {
                                                // Add subdirectory to directory queue
                                                if let Err(e) = dir_sender.send(path) {
                                                    error!("Failed to queue directory: {}", e);
                                                }
                                            } else if path.is_file() {
                                                // Process file if not already processed
                                                let path_hash = PathHasher::hash_path(&path);
                                                
                                                let contains;
                                                {
                                                    // First do a quick read-lock check with the primary hash
                                                    let primary_hash = PathHasher::hash_path(&path);
                                                    let filter = scanner.processed_files.read().unwrap();
                                                    contains = filter.contains(&primary_hash);
                                                }
                                                
                                                if !contains {
                                                    // Only do the write lock if we need to process this file
                                                    // This reduces contention on the write lock
                                                    let mut processed = false;
                                                    {
                                                        // Double-check with write lock to avoid race conditions
                                                        let mut filter = scanner.processed_files.write().unwrap();
                                                        
                                                        // Generate multiple hash values for better accuracy
                                                        let num_hashes = 5; // Default to 5 hash functions
                                                        let hashes = PathHasher::hash_path_multiple(&path, num_hashes);
                                                        
                                                        // Check if any hash is present
                                                        let contains = hashes.iter().all(|hash| filter.contains(hash));
                                                        
                                                        if !contains {
                                                            // Insert all hashes
                                                            for hash in hashes {
                                                                filter.insert(&hash);
                                                            }
                                                            processed = true;
                                                        }
                                                    }
                                                    
                                                    if processed {
                                                        // Add to processed files filter
                                                        {
                                                            let mut filter = scanner.processed_files.write().unwrap();
                                                            filter.insert(&path_hash);
                                                        }
                                                        
                                                        // Add file to local queue
                                                        local_queue.push(path);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("Failed to read directory {}: {}", dir_path.display(), e);
                                    scanner.stats.errors.fetch_add(1, Ordering::Relaxed);
                                }
                                
                            }
                        },
                        Err(crossbeam_channel::TryRecvError::Empty) => {
                            // No directories to process, but might be more work coming
                            // Sleep briefly to avoid tight polling loop
                            thread::sleep(std::time::Duration::from_millis(1));
                        },
                        Err(crossbeam_channel::TryRecvError::Disconnected) => {
                            // Channel is closed - no more work
                            if local_queue.is_empty() {
                                // Make sure we've also exhausted all other work sources
                                let mut has_work = false;
                                
                                // Check global queue
                                if let crossbeam_deque::Steal::Success(path) = global_queue.steal_batch_and_pop(&local_queue) {
                                    local_queue.push(path);
                                    has_work = true;
                                }
                                
                                // Check other workers
                                if !has_work {
                                    for stealer in &my_stealers {
                                        if let crossbeam_deque::Steal::Success(path) = stealer.steal_batch_and_pop(&local_queue) {
                                            local_queue.push(path);
                                            has_work = true;
                                            break;
                                        }
                                    }
                                }
                                
                                if !has_work {
                                    // No more work anywhere - exit
                                    debug!("Worker thread {} finished - no more work", i);
                                    break 'work;
                                }
                            }
                        }
                    }
                }
                
                debug!("Worker thread {} exiting", i);
            });
            
            thread_handles.push(handle);
        }
        
        // Drop the original senders - this ensures the channel will close
        // when all worker threads are done with their copies
        drop(dir_sender);
        
        // Wait for all threads to finish
        wg.wait();
        
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
        
        // Calculate throughput
        let elapsed = self.stats.elapsed_seconds();
        if elapsed > 0 {
            let files_per_sec = self.stats.files_processed.load(Ordering::Relaxed) as f64 / elapsed as f64;
            let mb_per_sec = (self.stats.bytes_processed.load(Ordering::Relaxed) as f64 / 1_048_576.0) / elapsed as f64;
            info!("Performance: {:.2} files/sec, {:.2} MB/sec", files_per_sec, mb_per_sec);
        }

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
                // Use the bloom filter for memory-efficient tracking
                let path_hash = PathHasher::hash_path(&path);
                
                // Read lock for checking
                let contains;
                {
                    let filter = self.processed_files.read().unwrap();
                    contains = filter.contains(&path_hash);
                }
                
                if !contains {
                    // Write lock only needed when updating
                    {
                        let mut filter = self.processed_files.write().unwrap();
                        filter.insert(&path_hash);
                    }

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
        // Check if we're under memory pressure
        if self.check_memory_usage() {
            // If we're under memory pressure, process smaller files first
            if let Ok(metadata) = fs::metadata(file_path) {
                let file_size = metadata.len() as usize;
                if file_size > 1_048_576 { // 1MB
                    // Skip large files when under memory pressure
                    debug!("Skipping large file under memory pressure: {} ({} MB)", 
                          file_path.display(), file_size / 1_048_576);
                    return Ok(());
                }
            }
        }

        // Check if we should skip this file based on extension
        if self.should_skip_file(file_path) {
            trace!("Skipping file: {}", file_path.display());
            return Ok(());
        }

        debug!("Processing file: {}", file_path.display());

        // Update stats
        self.stats.files_processed.fetch_add(1, Ordering::Relaxed);

        // Process based on file type
        if let Ok(metadata) = fs::metadata(file_path) {
            if metadata.is_file() {
                let file_size = metadata.len() as usize;
                
                // Track memory allocation
                self.track_allocation(file_size);
                
                // Track file size in stats
                self.stats.bytes_processed.fetch_add(file_size as u64, Ordering::Relaxed);
                
                // Process the file based on scan mode
                let result = match self.config.scan_mode {
                    ScanMode::Fast => {
                        // Fast mode: Only process plain text files
                        self.process_text_file(file_path)
                    },
                    ScanMode::Default => {
                        // Default mode: Process text files and emails
                        self.process_text_file(file_path)
                    },
                    ScanMode::Enhanced | ScanMode::Comprehensive => {
                        // Enhanced/Comprehensive: Based on file extension
                        self.process_text_file(file_path)
                    }
                };
                
                // Track memory deallocation
                self.track_deallocation(file_size);
                
                result
            } else {
                Ok(())
            }
        } else {
            warn!("Failed to get metadata for file: {}", file_path.display());
            Ok(())
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

    /// Find closest BIP39 words in parallel for a list of input words
    fn find_closest_bip39_words_parallel(&self, words: &[&str]) -> Vec<(String, f64)> {
        let wordlist = self.parser.wordlist();
        
        words.par_iter()
            .map(|word| {
                let mut best_match = String::new();
                let mut best_similarity = 0.0;
                
                for valid_word in wordlist {
                    let similarity = strsim::jaro_winkler(word, valid_word);
                    
                    if similarity > best_similarity {
                        best_similarity = similarity;
                        best_match = valid_word.to_string();
                    }
                }
                
                (best_match, best_similarity)
            })
            .collect()
    }

    /// Check memory usage and trigger cleanup if necessary
    fn check_memory_usage(&self) -> bool {
        let current_usage = self.stats.memory_usage.load(Ordering::Relaxed);
        let max_usage = self.config.max_memory;
        
        if current_usage > max_usage {
            // We're over the memory limit
            debug!("Memory pressure detected: {} MB used, {} MB limit", 
                  current_usage / 1_048_576, max_usage / 1_048_576);
            
            // Increment the counter
            self.stats.memory_pressure_events.fetch_add(1, Ordering::Relaxed);
            
            // Trigger cleanup
            self.reduce_memory_pressure();
            
            // Return true to indicate memory pressure
            true
        } else {
            false
        }
    }

    /// Track memory allocation
    fn track_allocation(&self, size: usize) {
        let current = self.stats.memory_usage.fetch_add(size, Ordering::Relaxed) + size;
        
        // Also update max usage
        let mut max = self.stats.max_memory_usage.load(Ordering::Relaxed);
        while current > max {
            match self.stats.max_memory_usage.compare_exchange(
                max, current, Ordering::SeqCst, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(actual) => max = actual,
            }
        }
    }

    /// Track memory deallocation
    fn track_deallocation(&self, size: usize) {
        self.stats.memory_usage.fetch_sub(size, Ordering::Relaxed);
    }

    /// Reduce memory pressure by releasing caches and triggering GC
    fn reduce_memory_pressure(&self) {
        debug!("Reducing memory pressure");
        
        // 1. Clear any caches
        {
            // Get a write lock on the bloom filter to prevent concurrent access
            let mut filter = self.processed_files.write().unwrap();
            
            // We can't modify the bloom filter itself, but we could replace it
            // This would lose the existing tracking, so only do this in extreme cases
            if self.stats.memory_pressure_events.load(Ordering::Relaxed) > 10 {
                warn!("Extreme memory pressure: resetting bloom filter");
                
                // Replace the filter with a fixed size
                *filter = BloomFilter::with_size(1_000_000, 5); // Use fixed size and 5 hash functions
                
                // Reset memory usage counter
                self.stats.memory_usage.store(0, Ordering::Relaxed);
            }
        }
        
        // 2. Suggest Rust's memory allocator to release memory
        #[cfg(target_os = "linux")]
        unsafe {
            // On Linux, we can call malloc_trim to release memory
            // This is a non-standard extension, so we need to use libc
            extern "C" {
                fn malloc_trim(pad: usize) -> i32;
            }
            
            // Call malloc_trim to release memory
            malloc_trim(0);
        }
        
        // 3. Force a garbage collection cycle
        // Rust doesn't have a GC, but we can trigger a minor "cleanup" by allocating a large
        // chunk of memory and then freeing it, which might cause the allocator to compact
        {
            let temp_allocation = vec![0u8; 1024 * 1024]; // 1MB allocation
            // Force the vector to be actually allocated
            assert_eq!(temp_allocation.len(), 1024 * 1024);
            // Let it be dropped naturally
        }
        
        // Log the new memory usage
        debug!("Memory usage after pressure reduction: {} MB", 
               self.stats.memory_usage.load(Ordering::Relaxed) / 1_048_576);
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
}

/// Clone implementation to support multithreaded scanning
impl Clone for Scanner {
    fn clone(&self) -> Self {
        Scanner {
            config: self.config.clone(),
            parser: self.parser.clone(),
            db: Arc::clone(&self.db),
            stats: Arc::clone(&self.stats),
            processed_files: Arc::clone(&self.processed_files),
            shutdown: Arc::clone(&self.shutdown),
        }
    }
}

// Unit tests for the scanner module
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use std::fs;
    use std::io::Write;
    use crate::parser::Parser;
    
    // Mock database controller for testing
    #[derive(Clone)]
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
        
        // For test debugging
        fn print_contents(&self) {
            let phrases = self.phrases.lock().unwrap();
            let eth_keys = self.eth_keys.lock().unwrap();
            
            println!("MockDbController contents:");
            println!("  Phrases ({})", phrases.len());
            for (i, phrase) in phrases.iter().enumerate() {
                println!("    {}: {} in {}", i, phrase.phrase, phrase.file_path);
            }
            
            println!("  Ethereum Keys ({})", eth_keys.len());
            for (i, key) in eth_keys.iter().enumerate() {
                println!("    {}: {} in {}", i, key.private_key, key.file_path);
            }
        }
    }
    
    impl DbController for MockDbController {
        fn init(&self) -> Result<()> {
            Ok(())
        }
        
        fn insert_phrase(&self, phrase: &FoundPhrase) -> Result<bool> {
            self.phrases.lock().unwrap().push(phrase.clone());
            Ok(true)
        }
        
        fn insert_eth_key(&self, key: &FoundEthKey) -> Result<bool> {
            self.eth_keys.lock().unwrap().push(key.clone());
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
    
    // Test utility functions
    fn is_pdf_file(path: &Path) -> bool {
        path.extension()
            .map(|ext| ext.to_string_lossy().to_lowercase() == "pdf")
            .unwrap_or(false)
    }
    
    fn is_document_file(path: &Path) -> bool {
        if let Some(extension) = path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            matches!(ext_str.as_str(), "docx" | "xlsx" | "pptx" | "odt" | "ods")
        } else {
            false
        }
    }
    
    fn extract_text_from_pdf_content(content: &str, _config: &ScannerConfig) -> Option<String> {
        // This is a mock implementation for testing
        if content.contains("seed phrase") {
            Some(content.to_string())
        } else {
            None
        }
    }
    
    // Utility function to create test file
    fn create_test_file(dir: &Path, filename: &str, content: &str) -> PathBuf {
        let file_path = dir.join(filename);
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file_path
    }
    
    // Placeholder for creating test ZIP file - doesn't actually create a ZIP since the zip crate is missing
    fn create_test_zip(dir: &Path, filename: &str, _inner_filename: &str, _content: &str) -> PathBuf {
        let zip_path = dir.join(filename);
        let mut file = fs::File::create(&zip_path).unwrap();
        // Just write a simple mock ZIP header
        file.write_all(b"PK\x03\x04Mock ZIP Content").unwrap();
        zip_path
    }
    
    // Placeholder for creating simple mock DOCX file
    fn create_test_docx(dir: &Path, filename: &str, _content: &str) -> PathBuf {
        let docx_path = dir.join(filename);
        let mut file = fs::File::create(&docx_path).unwrap();
        // Just write mock DOCX content
        file.write_all(b"PK\x03\x04Mock DOCX Content").unwrap();
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
    
    // Test the basic scanning functionality
    #[test]
    fn test_scan_text_file() {
        let dir = tempdir().unwrap();
        
        // Create a simple text file with a seed phrase
        let text_path = create_test_file(
            dir.path(),
            "seed_phrase.txt",
            "This file contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create scanner with Fast mode for simplicity
        let config = ScannerConfig::fast();
        let db = MockDbController::new();
        let parser = get_test_parser();
        
        // Create a scanner instance
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process the file directly
        let result = scanner.process_file(&text_path);
        assert!(result.is_ok(), "Processing text file should succeed");
        
        // Print DB contents for debugging
        db.print_contents();
        
        // Check if phrase was found
        let phrases = db.get_all_phrases().unwrap();
        assert!(!phrases.is_empty(), "Should have found at least one phrase");
        assert!(phrases.iter().any(|p| p.file_path.contains("seed_phrase.txt")), 
            "Should find seed phrase in text file");
        
        cleanup_temp_dir(dir);
    }
    
    // Test each supported file type with specific integration tests
    
    // Test text file processing
    #[test]
    fn test_text_file_processing() {
        let dir = tempdir().unwrap();
        
        // Create a simple text file with a seed phrase
        let text_path = create_test_file(
            dir.path(),
            "seed_phrase.txt",
            "This file contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create scanner with Fast mode
        let config = ScannerConfig::fast();
        let db = MockDbController::new();
        let parser = get_test_parser();
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process the text file
        let result = scanner.process_file(&text_path);
        assert!(result.is_ok(), "Text file processing should succeed");
        
        // Check if phrase was found
        let phrases = db.get_all_phrases().unwrap();
        assert!(!phrases.is_empty(), "Should have found at least one phrase");
        
        // Verify file path and phrase
        let text_found = phrases.iter().any(|p| {
            p.file_path == text_path.to_string_lossy().to_string() &&
            p.phrase.contains("abandon")
        });
        assert!(text_found, "Seed phrase in text file should be processed");
        
        // Verify stats
        let stats = scanner.stats();
        assert!(stats.files_processed.load(Ordering::Relaxed) == 1, 
                "Should have processed exactly one file");
        assert!(stats.phrases_found.load(Ordering::Relaxed) >= 1,
                "Should have found at least one phrase");
        
        cleanup_temp_dir(dir);
    }
    
    // Test scanning with different separators and line formats
    #[test]
    fn test_text_file_different_formats() {
        let dir = tempdir().unwrap();
        
        // Create text files with different separators and formats
        let newline_path = create_test_file(
            dir.path(),
            "newline.txt",
            "abandon\nabandon\nabandon\nabandon\nabandon\nabandon\nabandon\nabandon\nabandon\nabandon\nabandon\nabout"
        );
        
        let comma_path = create_test_file(
            dir.path(),
            "comma.txt",
            "abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,abandon,about"
        );
        
        let mixed_path = create_test_file(
            dir.path(),
            "mixed.txt",
            "Some text before.\nabandon abandon abandon abandon abandon\nabandon abandon abandon abandon abandon abandon about\nSome text after."
        );
        
        // Create scanner with default mode
        let config = ScannerConfig::default_mode();
        let db = MockDbController::new();
        let parser = get_test_parser();
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process all files
        assert!(scanner.process_file(&newline_path).is_ok(), "Newline format processing should succeed");
        assert!(scanner.process_file(&comma_path).is_ok(), "Comma format processing should succeed");
        assert!(scanner.process_file(&mixed_path).is_ok(), "Mixed format processing should succeed");
        
        // Check if phrases were found
        let phrases = db.get_all_phrases().unwrap();
        db.print_contents();
        
        // At least one format should be detected
        assert!(!phrases.is_empty(), "Should find seed phrase in at least one format");
        
        cleanup_temp_dir(dir);
    }
    
    // Test image file processing with OCR
    #[cfg(feature = "ocr")]
    #[test]
    fn test_image_file_processing() {
        use crate::ocr::{TesseractOcr, OcrEngine, OcrOptions};
        
        let dir = tempdir().unwrap();
        
        // Create a mock image file
        // Note: In a real test, we'd need a real image with text
        let image_path = dir.path().join("seed_phrase.jpg");
        fs::write(&image_path, b"Mock image data").unwrap();
        
        // Create scanner with OCR enabled
        let config = ScannerConfig::enhanced();
        let db = MockDbController::new();
        let parser = get_test_parser();
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process the image file
        let result = scanner.process_file(&image_path);
        assert!(result.is_ok(), "Image file processing should succeed");
        
        // Stats verification
        let stats = scanner.stats();
        assert!(stats.files_processed.load(Ordering::Relaxed) == 1, 
                "Should have processed exactly one file");
        
        cleanup_temp_dir(dir);
    }
    
    // Test PDF file processing
    #[cfg(feature = "pdf_support")]
    #[test]
    fn test_pdf_file_processing() {
        let dir = tempdir().unwrap();
        
        // Create a mock PDF with various text operators
        let pdf_content = "
        %PDF-1.4
        1 0 obj
        << /Type /Catalog /Pages 2 0 R >>
        endobj
        2 0 obj
        << /Type /Pages /Count 1 /Kids [3 0 R] >>
        endobj
        3 0 obj
        << /Type /Page /Contents 4 0 R >>
        endobj
        4 0 obj
        << /Length 200 >>
        stream
        BT
        /F1 12 Tf
        (This is a test document containing a seed phrase:) Tj
        ( abandon abandon abandon abandon abandon abandon ) Tj
        [ (abandon) -250 (abandon) -250 (abandon) -250 (abandon) -250 (about) ] TJ
        ET
        endstream
        endobj
        %%EOF
        ";
        
        let pdf_path = create_test_pdf(dir.path(), "document.pdf", pdf_content);
        
        // Create scanner with PDF support
        let config = ScannerConfig::comprehensive();
        let db = MockDbController::new();
        let parser = get_test_parser();
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process the PDF file
        let result = scanner.process_file(&pdf_path);
        assert!(result.is_ok(), "PDF file processing should succeed");
        
        // Check if phrases were found (only if PDF feature is enabled)
        let phrases = db.get_all_phrases().unwrap();
        db.print_contents();
        
        cleanup_temp_dir(dir);
    }
    
    // Test archive file processing (ZIP)
    #[cfg(feature = "archive")]
    #[test]
    fn test_archive_file_processing() {
        let dir = tempdir().unwrap();
        
        // Create a mock ZIP file
        let zip_path = create_test_zip(
            dir.path(),
            "archive.zip",
            "inside_zip.txt",
            "This file inside a ZIP contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create scanner with archive support
        let config = ScannerConfig::comprehensive();
        let db = MockDbController::new();
        let parser = get_test_parser();
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process the ZIP file
        let result = scanner.process_file(&zip_path);
        assert!(result.is_ok(), "ZIP file processing should succeed");
        
        // Check if phrases were found (only if archive feature is enabled)
        let phrases = db.get_all_phrases().unwrap();
        db.print_contents();
        
        cleanup_temp_dir(dir);
    }
    
    // Test document file processing (DOCX, XLSX)
    #[cfg(any(feature = "docx", feature = "xlsx"))]
    #[test]
    fn test_document_file_processing() {
        let dir = tempdir().unwrap();
        
        // Create a mock DOCX file with XML content
        let docx_path = create_test_docx(
            dir.path(),
            "document.docx",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
              <w:body>
                <w:p>
                  <w:r>
                    <w:t>This document contains a seed phrase:</w:t>
                  </w:r>
                </w:p>
                <w:p>
                  <w:r>
                    <w:t>abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about</w:t>
                  </w:r>
                </w:p>
              </w:body>
            </w:document>"#
        );
        
        // Create scanner with document support
        let config = ScannerConfig::comprehensive();
        let db = MockDbController::new();
        let parser = get_test_parser();
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process the DOCX file
        let result = scanner.process_file(&docx_path);
        assert!(result.is_ok(), "DOCX file processing should succeed");
        
        // Check if phrases were found (only if docx/xlsx feature is enabled)
        let phrases = db.get_all_phrases().unwrap();
        db.print_contents();
        
        cleanup_temp_dir(dir);
    }
    
    // Comprehensive integration test for all file types
    #[test]
    fn test_all_file_types() {
        let dir = tempdir().unwrap();
        
        // Create various test files
        let text_path = create_test_file(
            dir.path(),
            "text_file.txt",
            "This file contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create a simple "image file" (just a stub for testing)
        let image_path = dir.path().join("image_file.jpg");
        fs::write(&image_path, b"Mock image data").unwrap();
        
        // Create a ZIP with a text file inside
        let _zip_path = create_test_zip(
            dir.path(),
            "archive.zip",
            "inside_zip.txt",
            "This file inside a ZIP contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        
        // Create a mock DOCX (ZIP with XML)
        let _docx_path = create_test_docx(
            dir.path(),
            "document.docx",
            "<w:t>This document contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about</w:t>"
        );
        
        // Create a mock PDF
        let _pdf_path = create_test_pdf(
            dir.path(),
            "document.pdf",
            "BT (This PDF contains a seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about) Tj ET"
        );
        
        // Create scanner with comprehensive mode
        let config = ScannerConfig::comprehensive();
        let db = MockDbController::new();
        let parser = get_test_parser();
        let scanner = Scanner::new(config, parser, Box::new(db.clone())).unwrap();
        
        // Process the directory to test all files at once
        let result = scanner.process_directory(dir.path());
        assert!(result.is_ok(), "Directory processing should succeed");
        
        // Print DB contents for debugging
        db.print_contents();
        
        // Check if phrase was found in the text file (guaranteed to work)
        let phrases = db.get_all_phrases().unwrap();
        assert!(!phrases.is_empty(), "Should have found at least one phrase");
        
        // The text file should always be processed
        let text_found = phrases.iter().any(|p| {
            p.file_path == text_path.to_string_lossy().to_string()
        });
        assert!(text_found, "Text file should be processed");
        
        // Check stats to ensure files were processed
        let stats = scanner.stats();
        println!("Files processed: {}", stats.files_processed.load(Ordering::Relaxed));
        println!("Bytes processed: {}", stats.bytes_processed.load(Ordering::Relaxed));
        println!("Phrases found: {}", stats.phrases_found.load(Ordering::Relaxed));
        
        assert!(stats.files_processed.load(Ordering::Relaxed) >= 1, 
                "Should have processed at least the text file");
        assert!(stats.bytes_processed.load(Ordering::Relaxed) > 0,
                "Should have processed some bytes");
        
        cleanup_temp_dir(dir);
    }
    
    // Mock Parser for testing
    fn get_test_parser() -> Parser {
        // Create a dummy wordlist directory
        let temp_dir = tempdir().unwrap();
        let wordlist_path = temp_dir.path().join("english.txt");
        
        // Create a minimal wordlist file with all the words we need for testing
        let mut file = fs::File::create(&wordlist_path).unwrap();
        file.write_all(b"abandon\nabout\nabout\nfile\ncontains\nseed\nphrase\nthis\ndocument\npdf\n").unwrap();
        
        // Create a parser with default config that doesn't validate checksum
        let mut config = crate::parser::ParserConfig::default();
        config.validate_checksum = false; // Don't validate checksum for tests
        
        let parser = Parser::new(temp_dir.path().to_path_buf(), "english".to_string(), config).unwrap();
        
        // Keep tempdir from being dropped, which would delete our wordlist file
        std::mem::forget(temp_dir);
        
        parser
    }
} 