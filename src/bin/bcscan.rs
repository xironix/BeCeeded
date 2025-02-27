// bcscan.rs - BeCeeded Scanner CLI
//
// This binary provides a command-line interface for scanning files and directories
// for potential cryptocurrency seed phrases and private keys.

use beceeded::{
    db::{SqliteDbController, get_default_db_path},
    init_with_log_level,
    parser::{Parser, ParserConfig},
    scanner::{ScanMode, ScannerConfig, Scanner},
};
use clap::{Parser as ClapParser, ValueEnum};
use std::{
    path::PathBuf,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use log::{error, info, LevelFilter};
use ctrlc;

#[derive(ClapParser)]
#[command(
    name = "bcscan",
    version = env!("CARGO_PKG_VERSION"),
    author = "BeCeeded Team",
    about = "Scan files and directories for cryptocurrency seed phrases and private keys"
)]
struct Cli {
    /// Directory to scan
    #[arg(short, long, value_name = "DIR", required = true)]
    directory: PathBuf,

    /// Scan mode - controls processing depth and performance tradeoffs
    #[arg(short, long, value_enum, default_value_t = CliScanMode::Default)]
    mode: CliScanMode,

    /// Number of threads to use
    #[arg(short, long, default_value_t = num_cpus::get())]
    threads: usize,

    /// Path to wordlist directory
    #[arg(short = 'w', long, value_name = "DIR", default_value = "data")]
    wordlist_dir: PathBuf,

    /// Which wordlist to use
    #[arg(short = 'l', long, value_name = "NAME", default_value = "english")]
    wordlist: String,

    /// Database file path (if not specified, uses ~/.local/share/BeCeeded/beceeded.db on Linux)
    #[arg(short, long, value_name = "FILE")]
    database: Option<String>,

    /// Use in-memory database (faster but doesn't persist data)
    #[arg(long)]
    memory_db: bool,
    
    /// Use encrypted database (prompts for password)
    #[cfg(feature = "encrypted_db")]
    #[arg(long)]
    encrypted: bool,

    /// Disable Ethereum private key scanning
    #[arg(long)]
    no_eth: bool,

    /// Disable fuzzy matching for seed phrases
    #[arg(long)]
    no_fuzzy: bool,

    /// Disable OCR for image files
    #[arg(long)]
    no_ocr: bool,
    
    /// Disable scanning of archive files (zip, tar, etc.)
    #[arg(long)]
    no_archives: bool,
    
    /// Disable scanning of document files (docx, xlsx, etc.)
    #[arg(long)]
    no_documents: bool,
    
    /// Disable scanning of PDF files
    #[arg(long)]
    no_pdfs: bool,

    /// File extensions to include (comma-separated)
    #[arg(long, value_name = "EXT1,EXT2,...")]
    include: Option<String>,

    /// File extensions to exclude (comma-separated)
    #[arg(long, value_name = "EXT1,EXT2,...")]
    exclude: Option<String>,

    /// Minimum number of BIP39 words to trigger a match
    #[arg(long, default_value_t = 11)]
    min_words: usize,

    /// Fuzzy matching threshold (0.0-1.0)
    #[arg(long, default_value_t = 0.85)]
    fuzzy_threshold: f32,

    /// Sets the log level
    #[arg(short = 'v', long, default_value = "info")]
    log_level: LogLevel,

    /// Disable detailed logging
    #[arg(long)]
    no_logs: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum CliScanMode {
    /// Fast mode - Only processes plain text files, skips OCR/fuzzy/archives 
    /// Fastest option with ~10x speedup over comprehensive, may miss some matches
    Fast,
    
    /// Default mode - Processes text files with fuzzy matching 
    /// Good balance of speed and accuracy, skips resource-intensive operations
    Default,
    
    /// Enhanced mode - Adds OCR for image files 
    /// Slower but can detect phrases in screenshots and photos
    Enhanced,
    
    /// Comprehensive mode - Processes all supported file types 
    /// Slowest but most thorough, searches inside archives, documents, PDFs
    Comprehensive,
}

impl From<CliScanMode> for ScanMode {
    fn from(cli_mode: CliScanMode) -> Self {
        match cli_mode {
            CliScanMode::Fast => ScanMode::Fast,
            CliScanMode::Default => ScanMode::Default,
            CliScanMode::Enhanced => ScanMode::Enhanced,
            CliScanMode::Comprehensive => ScanMode::Comprehensive,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

fn main() {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Initialize logging
    let log_level: LevelFilter = cli.log_level.into();
    if let Err(e) = init_with_log_level(log_level) {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }

    // Validate directory
    if !cli.directory.exists() || !cli.directory.is_dir() {
        error!("Directory does not exist or is not a directory: {}", cli.directory.display());
        process::exit(1);
    }

    // Create parser
    let parser_config = ParserConfig {
        validate_checksum: true,
        max_words: 24,
        valid_word_counts: vec![12, 15, 18, 21, 24],
        wordlist_name: cli.wordlist.clone(),
    };

    let parser = match Parser::new(cli.wordlist_dir, cli.wordlist.clone(), parser_config) {
        Ok(parser) => parser,
        Err(e) => {
            error!("Failed to create parser: {}", e);
            process::exit(1);
        }
    };

    // Create database controller
    let db = if cli.memory_db {
        info!("Using in-memory database");
        match SqliteDbController::new_in_memory() {
            Ok(db) => Box::new(db),
            Err(e) => {
                error!("Failed to create in-memory database: {}", e);
                process::exit(1);
            }
        }
    } else {
        // Get database path
        let db_path = match &cli.database {
            Some(path) => path.clone(),
            None => match get_default_db_path() {
                Ok(path) => {
                    info!("Using default database path: {}", path);
                    path
                },
                Err(e) => {
                    error!("Failed to determine default database path: {}", e);
                    process::exit(1);
                }
            }
        };

        #[cfg(feature = "encrypted_db")]
        if cli.encrypted {
            use std::io::{self, Write};
            use rpassword::read_password;
            
            // Prompt for password
            print!("Enter database encryption password: ");
            io::stdout().flush().unwrap();
            let password = match read_password() {
                Ok(pwd) => pwd,
                Err(e) => {
                    error!("Failed to read password: {}", e);
                    process::exit(1);
                }
            };
            
            info!("Using encrypted database file: {}", db_path);
            match SqliteDbController::new_encrypted(&db_path, &password) {
                Ok(db) => Box::new(db),
                Err(e) => {
                    error!("Failed to create encrypted database: {}", e);
                    process::exit(1);
                }
            }
        } else {
            info!("Using database file: {}", db_path);
            match SqliteDbController::new(&db_path) {
                Ok(db) => Box::new(db),
                Err(e) => {
                    error!("Failed to create database: {}", e);
                    process::exit(1);
                }
            }
        }
        
        #[cfg(not(feature = "encrypted_db"))]
        {
            info!("Using database file: {}", db_path);
            match SqliteDbController::new(&db_path) {
                Ok(db) => Box::new(db),
                Err(e) => {
                    error!("Failed to create database: {}", e);
                    process::exit(1);
                }
            }
        }
    };

    // Parse include/exclude extensions
    let include_extensions = cli
        .include
        .map(|s| {
            s.split(',')
                .map(|ext| ext.trim().to_lowercase())
                .filter(|ext| !ext.is_empty())
                .collect()
        })
        .unwrap_or_else(Vec::new);

    let exclude_extensions = match cli.exclude {
        Some(s) => s
            .split(',')
            .map(|ext| ext.trim().to_lowercase())
            .filter(|ext| !ext.is_empty())
            .collect(),
        None => vec![
            "jpg".to_string(),
            "jpeg".to_string(),
            "png".to_string(),
            "gif".to_string(),
            "bmp".to_string(),
            "mp3".to_string(),
            "mp4".to_string(),
            "zip".to_string(),
            "tar".to_string(),
            "gz".to_string(),
            "exe".to_string(),
            "dll".to_string(),
            "so".to_string(),
        ],
    };

    // Create scanner config
    let scanner_config = ScannerConfig {
        scan_mode: cli.mode.into(),
        threads: cli.threads,
        max_memory: 1024 * 1024 * 1024, // 1GB
        batch_size: 1000,
        scan_eth_keys: !cli.no_eth,
        include_extensions,
        exclude_extensions,
        use_fuzzy_matching: !cli.no_fuzzy,
        use_ocr: !cli.no_ocr,
        scan_archives: !cli.no_archives,
        scan_documents: !cli.no_documents,
        scan_pdfs: !cli.no_pdfs,
        min_bip39_words: 11,
        fuzzy_threshold: 0.85,
        write_logs: true,
    };

    // Create scanner
    let scanner = match Scanner::new(scanner_config, parser, db) {
        Ok(scanner) => scanner,
        Err(e) => {
            error!("Failed to create scanner: {}", e);
            process::exit(1);
        }
    };

    // Display scan mode
    info!("Using scan mode: {:?}", cli.mode);

    // Set up Ctrl+C handler
    let scanner_stats = scanner.stats().clone();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nReceived interrupt signal. Shutting down gracefully...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");

    // Start a thread to display progress
    let stats_clone = scanner_stats.clone();
    let mode_str = format!("{:?}", cli.mode);
    let r_thread = running.clone();
    let stats_thread = thread::spawn(move || {
        while r_thread.load(Ordering::SeqCst) {
            // Display stats
            println!(
                "[{} Mode] Processed: {} files, {} dirs, {} MB | Rate: {:.2} MB/s | Found: {} phrases, {} ETH keys | Errors: {}",
                mode_str,
                stats_clone.files_processed.load(Ordering::Relaxed),
                stats_clone.dirs_processed.load(Ordering::Relaxed),
                stats_clone.bytes_processed.load(Ordering::Relaxed) / 1_048_576,
                stats_clone.processing_rate(),
                stats_clone.phrases_found.load(Ordering::Relaxed),
                stats_clone.eth_keys_found.load(Ordering::Relaxed),
                stats_clone.errors.load(Ordering::Relaxed),
            );
            
            // Sleep for a bit
            thread::sleep(Duration::from_secs(1));
        }
    });

    // Start scanning
    info!("Starting scan of {}", cli.directory.display());
    if let Err(e) = scanner.scan_directory(&cli.directory) {
        error!("Scan failed: {}", e);
        running.store(false, Ordering::SeqCst);
        stats_thread.join().unwrap();
        process::exit(1);
    }

    // Wait for stats thread to finish
    running.store(false, Ordering::SeqCst);
    stats_thread.join().unwrap();

    // Display final results
    println!("\nScan completed!");
    println!(
        "Processed: {} files, {} dirs, {} MB in {} seconds",
        scanner_stats.files_processed.load(Ordering::Relaxed),
        scanner_stats.dirs_processed.load(Ordering::Relaxed),
        scanner_stats.bytes_processed.load(Ordering::Relaxed) / 1_048_576,
        scanner_stats.elapsed_seconds(),
    );
    println!(
        "Found: {} seed phrases and {} Ethereum private keys",
        scanner_stats.phrases_found.load(Ordering::Relaxed),
        scanner_stats.eth_keys_found.load(Ordering::Relaxed),
    );
    println!(
        "Average processing rate: {:.2} MB/s",
        scanner_stats.processing_rate(),
    );
} 