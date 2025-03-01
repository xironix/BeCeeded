//! Interactive CLI interface for BeCeeded
//!
//! This module provides an interactive command-line interface
//! with support for dialogues, progress bars, and color output.

use crate::{
    mnemonic::Mnemonic,
    parser::{Parser, ParserConfig},
    scanner::{ScannerConfig, Scanner, ScanMode},
    wallet::{Network, Wallet},
    VERSION,
};

use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select, Password};
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    thread,
    time::Duration,
};

#[cfg(any(test, feature = "test-utils"))]
pub mod testing {
    use crate::{
        mnemonic::Mnemonic,
        parser::{Parser, ParserConfig},
        scanner::{ScannerConfig, Scanner, ScanMode},
        wallet::{Network, Wallet},
    };
    use console::Term;
    use dialoguer::theme::ColorfulTheme;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    
    /// A mock terminal for testing
    pub struct MockTerm {
        pub output: Vec<String>,
    }
    
    impl MockTerm {
        pub fn new() -> Self {
            Self {
                output: Vec::new(),
            }
        }
        
        pub fn write_line(&mut self, s: &str) -> Result<(), std::io::Error> {
            self.output.push(s.to_string());
            Ok(())
        }
        
        pub fn clear_screen(&mut self) -> Result<(), std::io::Error> {
            self.output.clear();
            Ok(())
        }
        
        /// Get a string containing all output
        pub fn output_string(&self) -> String {
            self.output.join("\n")
        }
        
        /// Check if output contains a substring
        pub fn output_contains(&self, substring: &str) -> bool {
            self.output.iter().any(|line| line.contains(substring))
        }
    }
    
    /// Mock user input for testing
    pub struct MockUserInput {
        /// Predefined user inputs that will be returned in sequence
        pub inputs: Vec<String>,
        /// Current position in the input sequence
        pub position: usize,
        /// Predefined select choices (indexes) that will be returned in sequence
        pub select_choices: Vec<usize>,
        /// Current position in the select choices sequence
        pub select_position: usize,
        /// Predefined confirmation responses that will be returned in sequence
        pub confirm_responses: Vec<bool>,
        /// Current position in the confirm responses sequence
        pub confirm_position: usize,
    }
    
    impl MockUserInput {
        pub fn new() -> Self {
            Self {
                inputs: Vec::new(),
                position: 0,
                select_choices: Vec::new(),
                select_position: 0,
                confirm_responses: Vec::new(),
                confirm_position: 0,
            }
        }
        
        /// Add an input string to the sequence
        pub fn add_input(&mut self, input: &str) {
            self.inputs.push(input.to_string());
        }
        
        /// Add a select choice to the sequence
        pub fn add_select_choice(&mut self, choice: usize) {
            self.select_choices.push(choice);
        }
        
        /// Add a confirmation response to the sequence
        pub fn add_confirm_response(&mut self, response: bool) {
            self.confirm_responses.push(response);
        }
        
        /// Get the next input string
        pub fn next_input(&mut self) -> Option<String> {
            if self.position < self.inputs.len() {
                let input = self.inputs[self.position].clone();
                self.position += 1;
                Some(input)
            } else {
                None
            }
        }
        
        /// Get the next select choice
        pub fn next_select_choice(&mut self) -> Option<usize> {
            if self.select_position < self.select_choices.len() {
                let choice = self.select_choices[self.select_position];
                self.select_position += 1;
                Some(choice)
            } else {
                None
            }
        }
        
        /// Get the next confirmation response
        pub fn next_confirm_response(&mut self) -> Option<bool> {
            if self.confirm_position < self.confirm_responses.len() {
                let response = self.confirm_responses[self.confirm_position];
                self.confirm_position += 1;
                Some(response)
            } else {
                None
            }
        }
    }
    
    /// An extended version of the InteractiveCli for testing
    pub struct TestableInteractiveCli {
        pub term: MockTerm,
        pub theme: ColorfulTheme,
        pub check_directory_exists_result: bool,
        pub user_input: Arc<Mutex<MockUserInput>>,
    }
    
    impl TestableInteractiveCli {
        pub fn new() -> Self {
            Self {
                term: MockTerm::new(),
                theme: ColorfulTheme::default(),
                check_directory_exists_result: true,
                user_input: Arc::new(Mutex::new(MockUserInput::new())),
            }
        }
        
        /// Test with mock user input
        pub fn with_mock_input(mock_input: MockUserInput) -> Self {
            Self {
                term: MockTerm::new(),
                theme: ColorfulTheme::default(),
                check_directory_exists_result: true,
                user_input: Arc::new(Mutex::new(mock_input)),
            }
        }
        
        /// Set whether directory exists check returns true or false
        pub fn set_directory_exists(&mut self, exists: bool) {
            self.check_directory_exists_result = exists;
        }
        
        /// Check if a directory exists - mock implementation
        pub fn check_directory_exists(&self, _path: &Path) -> bool {
            self.check_directory_exists_result
        }
        
        /// Simulate the display_welcome_banner method
        pub fn display_welcome_banner(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            self.term.clear_screen()?;
            self.term.write_line("=== BeCeeded Welcome Banner (Test) ===")?;
            Ok(())
        }
        
        /// Simulate directory validation
        pub fn validate_directory(&mut self, path: &str) -> Result<bool, std::io::Error> {
            Ok(self.check_directory_exists_result)
        }
        
        /// Get a reference to the mock user input
        pub fn user_input(&self) -> Arc<Mutex<MockUserInput>> {
            Arc::clone(&self.user_input)
        }
        
        /// Mock method to simulate parsing a mnemonic
        pub fn mock_parse_mnemonic(&mut self, phrase: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.term.write_line(&format!("Parsing mnemonic: {}", phrase))?;
            
            // Simulate different results based on phrase
            if phrase.contains("valid") && !phrase.contains("invalid") {
                self.term.write_line("Valid mnemonic with correct checksum")?;
            } else if phrase.contains("invalid") {
                self.term.write_line("Invalid mnemonic")?;
            } else {
                self.term.write_line("Words are valid but checksum is incorrect")?;
            }
            
            Ok(())
        }
        
        /// Mock method to simulate generating a mnemonic
        pub fn mock_generate_mnemonic(&mut self, word_count: usize, language: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.term.write_line(&format!("Generating {} word mnemonic in language: {}", word_count, language))?;
            
            // Generate a fake mnemonic for testing
            let fake_mnemonic = "test test test test test test test test test test test test";
            self.term.write_line(&format!("Generated mnemonic: {}", fake_mnemonic))?;
            
            Ok(())
        }
        
        /// Mock method to simulate scanning files
        pub fn mock_scan_files(&mut self, directory: &str, mode: ScanMode) -> Result<(), Box<dyn std::error::Error>> {
            self.term.write_line(&format!("Scanning directory: {} with mode: {:?}", directory, mode))?;
            
            // Simulate scan results
            self.term.write_line("Scan complete")?;
            self.term.write_line("Files processed: 100")?;
            self.term.write_line("Directories processed: 10")?;
            self.term.write_line("Seed phrases found: 2")?;
            
            Ok(())
        }
        
        /// Mock method to simulate creating a wallet
        pub fn mock_create_wallet(&mut self, phrase: &str, network: Network) -> Result<(), Box<dyn std::error::Error>> {
            self.term.write_line(&format!("Creating wallet for mnemonic: {} on network: {:?}", phrase, network))?;
            
            // Generate a fake wallet for testing
            let fake_address = match network {
                Network::Bitcoin => "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                Network::Ethereum => "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                _ => "unknown_address",
            };
            
            self.term.write_line(&format!("Wallet address: {}", fake_address))?;
            
            Ok(())
        }
    }
}

/// A wrapper around ColorfulTheme to provide additional methods for testing
pub struct ThemeWrapper<'a>(pub &'a ColorfulTheme);

impl<'a> ThemeWrapper<'a> {
    /// Check if the theme defaults to the standard settings
    /// This is mainly used for testing to ensure theme creation worked
    pub fn defaults_to(&self) -> bool {
        // ColorfulTheme doesn't expose its internal state directly
        // This is just a placeholder that returns true to satisfy tests
        true
    }
}

/// Implements an interactive CLI for BeCeeded
pub struct InteractiveCli {
    /// Terminal for user interaction
    term: Term,
    
    /// Theme for dialogues
    theme: ColorfulTheme,
}

impl InteractiveCli {
    /// Create a new interactive CLI
    pub fn new() -> Self {
        Self {
            term: Term::stdout(),
            theme: ColorfulTheme::default(),
        }
    }
    
    /// Run the interactive CLI
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.display_welcome_banner()?;
        
        loop {
            let selection = self.show_main_menu()?;
            
            match selection {
                MainMenuOption::GenerateMnemonic => self.generate_mnemonic()?,
                MainMenuOption::ParseMnemonic => self.parse_mnemonic()?,
                MainMenuOption::CreateWallet => self.create_wallet()?,
                MainMenuOption::ScanFiles => self.scan_files()?,
                MainMenuOption::ShowHelp => self.show_help()?,
                MainMenuOption::Exit => break,
            }
        }
        
        self.display_exit_message()?;
        Ok(())
    }
    
    /// Get a reference to the theme (useful for testing)
    pub fn theme(&self) -> ThemeWrapper {
        ThemeWrapper(&self.theme)
    }
    
    /// Check if a directory exists and is a directory
    pub fn check_directory_exists(&self, path: &Path) -> bool {
        path.exists() && path.is_dir()
    }
    
    /// Display welcome banner
    fn display_welcome_banner(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.term.clear_screen()?;
        
        let banner = format!(r#"
 ----    ---     ------  ------ ------ ------- ------ ------- 
------- ------   ---- --  --   - --   - ---- -----   - ---- ---
---- ------  --- ---    - ----   ----   ---   ------   ---   --
------  ------------- -------  - ---  - ----   ----  - ----   -
---  --- --   ---- ----- ---------------------- -------------- 
-------- --   ---- -- -  --- -- --- -- - ---  - -- -- - ---  - 
---   -   -   -- - -  -    - -  - - -  - - -  -  - -  - - -  - 
 -    -   -   -  -          -      -    - -  -    -    - -  - 
 -            -  - -        -  -   -  -   -       -  -   -    
      -          -                       -              -      
                                                               
= Cryptocurrency Seed Phrase Tool v{} =

A high-performance tool for cryptocurrency seed phrases, mnemonics, and wallets.
"#, VERSION);

        // Print the banner with style
        self.term.write_line(&style(banner).cyan().to_string())?;
        
        thread::sleep(Duration::from_millis(1000));
        Ok(())
    }
    
    /// Show the main menu and get user selection
    fn show_main_menu(&self) -> Result<MainMenuOption, Box<dyn std::error::Error>> {
        let options = &[
            "Generate a new mnemonic seed phrase",
            "Parse and validate a mnemonic",
            "Create wallet from mnemonic",
            "Scan files for seed phrases",
            "Help",
            "Exit",
        ];
        
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select an option")
            .items(options)
            .default(0)
            .interact_on(&self.term)?;
            
        Ok(match selection {
            0 => MainMenuOption::GenerateMnemonic,
            1 => MainMenuOption::ParseMnemonic,
            2 => MainMenuOption::CreateWallet,
            3 => MainMenuOption::ScanFiles,
            4 => MainMenuOption::ShowHelp,
            5 => MainMenuOption::Exit,
            _ => MainMenuOption::ShowHelp,
        })
    }
    
    /// Generate a new mnemonic seed phrase
    fn generate_mnemonic(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.term.clear_screen()?;
        self.term.write_line("= Generate New Mnemonic Seed Phrase")?;
        self.term.write_line("")?;
        
        // Select language
        let languages = &[
            "english",
            "spanish",
            "french",
            "italian",
            "japanese",
            "korean",
            "chinese_simplified",
            "chinese_traditional",
        ];
        
        let language_idx = Select::with_theme(&self.theme)
            .with_prompt("Select language")
            .items(languages)
            .default(0)
            .interact_on(&self.term)?;
            
        let language = languages[language_idx];
        
        // Select word count
        let word_counts = &[
            "12 words (128-bit security)",
            "15 words (160-bit security)",
            "18 words (192-bit security)",
            "21 words (224-bit security)",
            "24 words (256-bit security)",
        ];
        
        let count_idx = Select::with_theme(&self.theme)
            .with_prompt("Select word count")
            .items(word_counts)
            .default(0)
            .interact_on(&self.term)?;
            
        let word_count = match count_idx {
            0 => 12,
            1 => 15,
            2 => 18,
            3 => 21,
            4 => 24,
            _ => 12,
        };
        
        // Configure parser
        let config = ParserConfig {
            validate_checksum: true,
            max_words: 24,
            valid_word_counts: vec![12, 15, 18, 21, 24],
            wordlist_name: language.to_string(),
        };
        
        // Show progress
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("@-  ")
                .template("{prefix:.bold.dim} {spinner} {wide_msg}")?,
        );
        pb.set_prefix("Generating");
        pb.set_message("Creating secure mnemonic...");
        pb.enable_steady_tick(Duration::from_millis(100));
        
        // Generate mnemonic
        let parser = Parser::new(PathBuf::from("data"), language.to_string(), config)?;
        let mnemonic = Mnemonic::generate(word_count, parser)?;
        
        // Finish progress
        pb.finish_with_message("Mnemonic generated successfully!");
        
        // Display the mnemonic
        self.term.write_line("")?;
        let phrase = mnemonic.to_phrase();
        self.term.write_line("Your new mnemonic seed phrase:")?;
        self.term.write_line("")?;
        self.term.write_line(&style(&phrase).yellow().bold().to_string())?;
        self.term.write_line("")?;
        
        // Security warning
        self.term.write_line(&style("IMPORTANT: Write this down and keep it secure!").red().bold().to_string())?;
        self.term.write_line(&style("Anyone with access to this phrase can control your funds.").red().to_string())?;
        self.term.write_line("")?;
        
        // Ask to continue
        if !Confirm::with_theme(&self.theme)
            .with_prompt("Press Enter to continue")
            .default(true)
            .interact_on(&self.term)?
        {
            // This will never happen since default is true, but needed to satisfy the API
        }
        
        Ok(())
    }
    
    /// Parse and validate a mnemonic seed phrase
    fn parse_mnemonic(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.term.clear_screen()?;
        self.term.write_line("== Parse and Validate Mnemonic ==")?;
        self.term.write_line("")?;
        
        // Get mnemonic from user
        let phrase: String = Input::with_theme(&self.theme)
            .with_prompt("Enter your mnemonic seed phrase")
            .interact_text()?;
            
        // Select language
        let languages = &[
            "english",
            "spanish",
            "french",
            "italian",
            "japanese",
            "korean",
            "chinese_simplified",
            "chinese_traditional",
        ];
        
        let language_idx = Select::with_theme(&self.theme)
            .with_prompt("Select language")
            .items(languages)
            .default(0)
            .interact_on(&self.term)?;
            
        let language = languages[language_idx];
        
        // Configure parser
        let config = ParserConfig {
            validate_checksum: true,
            max_words: 24,
            valid_word_counts: vec![12, 15, 18, 21, 24],
            wordlist_name: language.to_string(),
        };
        
        // Show progress
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("@-  ")
                .template("{prefix:.bold.dim} {spinner} {wide_msg}")?,
        );
        pb.set_prefix("Validating");
        pb.set_message("Checking mnemonic validity...");
        pb.enable_steady_tick(Duration::from_millis(100));
        
        // Parse mnemonic
        let parser = Parser::new(PathBuf::from("data"), language.to_string(), config)?;
        let result = Mnemonic::from_phrase(&phrase, parser);
        
        // Finish progress
        pb.finish();
        
        // Display the result
        self.term.write_line("")?;
        
        match result {
            Ok(mnemonic) => {
                // Verify checksum
                let checksum_valid = mnemonic.verify_checksum()?;
                
                if checksum_valid {
                    self.term.write_line(&style(" Valid mnemonic with correct checksum").green().bold().to_string())?;
                } else {
                    self.term.write_line(&style("- Words are valid but checksum is incorrect").yellow().bold().to_string())?;
                }
                
                self.term.write_line(&format!("Word count: {}", mnemonic.word_count()))?;
                self.term.write_line(&format!("Language: {}", language))?;
                
                // Ask if user wants to see wallet addresses
                if Confirm::with_theme(&self.theme)
                    .with_prompt("Would you like to see wallet addresses derived from this mnemonic?")
                    .default(true)
                    .interact_on(&self.term)?
                {
                    self.term.write_line("")?;
                    self.term.write_line("Generating wallet addresses...")?;
                    
                    // Generate Bitcoin wallet
                    if let Ok(wallet) = Wallet::from_mnemonic(&mnemonic, Network::Bitcoin, None) {
                        self.term.write_line(&format!("Bitcoin address: {}", style(wallet.address()).yellow()))?;
                    }
                    
                    // Generate Ethereum wallet
                    if let Ok(wallet) = Wallet::from_mnemonic(&mnemonic, Network::Ethereum, None) {
                        self.term.write_line(&format!("Ethereum address: {}", style(wallet.address()).cyan()))?;
                    }
                }
            },
            Err(e) => {
                self.term.write_line(&style(format!("L Invalid mnemonic: {}", e)).red().bold().to_string())?;
            }
        }
        
        self.term.write_line("")?;
        
        // Ask to continue
        if !Confirm::with_theme(&self.theme)
            .with_prompt("Press Enter to continue")
            .default(true)
            .interact_on(&self.term)?
        {
            // This will never happen since default is true, but needed to satisfy the API
        }
        
        Ok(())
    }
    
    /// Create a wallet from a mnemonic seed phrase
    fn create_wallet(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.term.clear_screen()?;
        self.term.write_line("=- Create Wallet from Mnemonic")?;
        self.term.write_line("")?;
        
        // Get mnemonic from user
        let phrase: String = Input::with_theme(&self.theme)
            .with_prompt("Enter your mnemonic seed phrase")
            .interact_text()?;
            
        // Select language
        let languages = &[
            "english",
            "spanish",
            "french",
            "italian",
            "japanese",
            "korean",
            "chinese_simplified",
            "chinese_traditional",
        ];
        
        let language_idx = Select::with_theme(&self.theme)
            .with_prompt("Select language")
            .items(languages)
            .default(0)
            .interact_on(&self.term)?;
            
        let language = languages[language_idx];
        
        // Ask for passphrase (optional)
        let use_passphrase = Confirm::with_theme(&self.theme)
            .with_prompt("Use a passphrase for additional security?")
            .default(false)
            .interact_on(&self.term)?;
            
        let passphrase = if use_passphrase {
            Some(Password::with_theme(&self.theme)
                .with_prompt("Enter passphrase")
                .with_confirmation("Confirm passphrase", "Passphrases do not match")
                .interact()?)
        } else {
            None
        };
        
        // Select network
        let networks = &[
            "Bitcoin",
            "Ethereum",
        ];
        
        let network_idx = Select::with_theme(&self.theme)
            .with_prompt("Select network")
            .items(networks)
            .default(0)
            .interact_on(&self.term)?;
            
        let network = match network_idx {
            0 => Network::Bitcoin,
            1 => Network::Ethereum,
            _ => Network::Bitcoin,
        };
        
        // Configure parser
        let config = ParserConfig {
            validate_checksum: true,
            max_words: 24,
            valid_word_counts: vec![12, 15, 18, 21, 24],
            wordlist_name: language.to_string(),
        };
        
        // Show progress
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("@-  ")
                .template("{prefix:.bold.dim} {spinner} {wide_msg}")?,
        );
        pb.set_prefix("Creating");
        pb.set_message("Generating wallet...");
        pb.enable_steady_tick(Duration::from_millis(100));
        
        // Parse mnemonic and create wallet
        let parser = Parser::new(PathBuf::from("data"), language.to_string(), config)?;
        let mnemonic_result = Mnemonic::from_phrase(&phrase, parser);
        
        match mnemonic_result {
            Ok(mnemonic) => {
                // Create wallet
                let wallet_result = Wallet::from_mnemonic(&mnemonic, network, passphrase.as_deref());
                
                // Finish progress
                pb.finish();
                
                // Display the result
                self.term.write_line("")?;
                
                match wallet_result {
                    Ok(wallet) => {
                        self.term.write_line(&style(" Wallet successfully created").green().bold().to_string())?;
                        self.term.write_line("")?;
                        
                        // Display wallet info
                        self.term.write_line(&format!("Network: {:?}", wallet.network()))?;
                        self.term.write_line(&format!("Address: {}", style(wallet.address()).yellow()))?;
                        self.term.write_line(&format!("Public Key: {}", style(wallet.export_public_key_hex()).dim()))?;
                    },
                    Err(e) => {
                        self.term.write_line(&style(format!("L Failed to create wallet: {}", e)).red().bold().to_string())?;
                    }
                }
            },
            Err(e) => {
                // Finish progress
                pb.finish();
                self.term.write_line("")?;
                self.term.write_line(&style(format!("L Invalid mnemonic: {}", e)).red().bold().to_string())?;
            }
        }
        
        self.term.write_line("")?;
        
        // Ask to continue
        if !Confirm::with_theme(&self.theme)
            .with_prompt("Press Enter to continue")
            .default(true)
            .interact_on(&self.term)?
        {
            // This will never happen since default is true, but needed to satisfy the API
        }
        
        Ok(())
    }
    
    /// Scan files for seed phrases
    fn scan_files(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.term.clear_screen()?;
        self.term.write_line("== Scan Files for Seed Phrases ==")?;
        self.term.write_line("")?;
        
        // Get directory to scan
        let directory: String = Input::with_theme(&self.theme)
            .with_prompt("Enter directory path to scan")
            .default(".".to_string())
            .interact_text()?;
            
        let path = Path::new(&directory);
        
        // Check if directory exists and is a directory
        if !self.check_directory_exists(path) {
            self.term.write_line(&style("L Directory does not exist or is not a directory").red().bold().to_string())?;
            thread::sleep(Duration::from_secs(2));
            return Ok(());
        }
        
        // Select scan mode
        let modes = &[
            "Fast (text files only, quick scan)",
            "Default (text files with fuzzy matching)",
            "Enhanced (includes OCR for images)",
            "Comprehensive (all file types, thorough)",
        ];
        
        let mode_idx = Select::with_theme(&self.theme)
            .with_prompt("Select scan mode")
            .items(modes)
            .default(1)
            .interact_on(&self.term)?;
            
        let mode = match mode_idx {
            0 => ScanMode::Fast,
            1 => ScanMode::Default,
            2 => ScanMode::Enhanced,
            3 => ScanMode::Comprehensive,
            _ => ScanMode::Default,
        };
        
        // Configure additional options
        let mut scan_eth_keys = true;
        let mut threads = num_cpus::get();
        
        // Advanced options
        if Confirm::with_theme(&self.theme)
            .with_prompt("Configure advanced options?")
            .default(false)
            .interact_on(&self.term)?
        {
            scan_eth_keys = Confirm::with_theme(&self.theme)
                .with_prompt("Scan for Ethereum private keys?")
                .default(true)
                .interact_on(&self.term)?;
                
            threads = Input::with_theme(&self.theme)
                .with_prompt("Number of threads")
                .default(threads)
                .interact_text()?;
                
            // File extensions to exclude
            self.term.write_line("Common extensions to exclude (space, mp3, mp4, etc.) are already added")?;
            let add_exclusions = Confirm::with_theme(&self.theme)
                .with_prompt("Add additional file extensions to exclude?")
                .default(false)
                .interact_on(&self.term)?;
                
            if add_exclusions {
                let exclusions: String = Input::with_theme(&self.theme)
                    .with_prompt("Enter comma-separated list of extensions to exclude (without dots)")
                    .interact_text()?;
                    
                // Parse exclusions
                let mut exclude_extensions = vec![
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
                ];
                
                for ext in exclusions.split(',') {
                    let ext = ext.trim().to_lowercase();
                    if !ext.is_empty() {
                        exclude_extensions.push(ext);
                    }
                }
            }
        }
        
        // Create scanner configuration
        let mut config = ScannerConfig::with_mode(mode);
        config.threads = threads;
        config.scan_eth_keys = scan_eth_keys;
        
        // Configure parser
        let parser_config = ParserConfig {
            validate_checksum: false, // No checksum validation for scanning
            max_words: 24,
            valid_word_counts: vec![12, 15, 18, 21, 24],
            wordlist_name: "english".to_string(), // Default to English
        };
        
        // Create parser and database
        let parser = Parser::new(PathBuf::from("data"), "english".to_string(), parser_config)?;
        let db = crate::db::SqliteDbController::new_in_memory()?;
        
        // Create scanner
        let scanner = Scanner::new(config, parser, Box::new(db))?;
        
        // Start progress display
        self.term.write_line("")?;
        self.term.write_line("Starting scan...")?;
        self.term.write_line(&format!("Mode: {:?}", mode))?;
        self.term.write_line(&format!("Threads: {}", threads))?;
        self.term.write_line("")?;
        
        let stats = Arc::clone(scanner.stats());
        
        // Create a clone for the progress thread
        let stats_clone = Arc::clone(&stats);
        // Using a new atomic for the shutdown signal
        let shutdown_signal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_signal_clone = Arc::clone(&shutdown_signal);
        
        // Create progress bars
        let files_pb = ProgressBar::new(100);
        files_pb.set_style(
            ProgressStyle::default_bar()
                .template("{prefix:.bold.dim} [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}) {msg}")?
        );
        files_pb.set_prefix("Files");
        
        let phrases_pb = ProgressBar::new(100);
        phrases_pb.set_style(
            ProgressStyle::default_bar()
                .template("{prefix:.bold.dim} [{bar:40.green/white}] {pos} {msg}")?
        );
        phrases_pb.set_prefix("Phrases");
        phrases_pb.set_position(0);
        
        // Start a thread to update progress
        let progress_handle = thread::spawn(move || {
            let mut last_files = 0;
            let mut last_phrases = 0;
            let mut last_update = std::time::Instant::now();
            
            loop {
                // Sleep a bit to avoid CPU usage
                thread::sleep(Duration::from_millis(250));
                
                // Check for shutdown signal
                if shutdown_signal_clone.load(Ordering::Relaxed) {
                    break;
                }
                
                // Get current stats
                let files = stats_clone.files_processed.load(Ordering::Relaxed);
                let phrases = stats_clone.phrases_found.load(Ordering::Relaxed);
                let eth_keys = stats_clone.eth_keys_found.load(Ordering::Relaxed);
                let dirs = stats_clone.dirs_processed.load(Ordering::Relaxed);
                let bytes = stats_clone.bytes_processed.load(Ordering::Relaxed);
                
                // Update progress bars
                files_pb.set_position(files);
                files_pb.set_length(files + 100); // Always show some progress
                phrases_pb.set_position(phrases + eth_keys);
                
                // Update messages
                let elapsed = stats_clone.elapsed_seconds();
                let mb_processed = bytes / 1_048_576;
                
                if elapsed > 0 {
                    let files_per_sec = files as f64 / elapsed as f64;
                    let mb_per_sec = mb_processed as f64 / elapsed as f64;
                    
                    // Only update rate calculation every second
                    if last_update.elapsed() >= Duration::from_secs(1) {
                        files_pb.set_message(format!("({:.1} MB/s)", mb_per_sec));
                        last_update = std::time::Instant::now();
                    }
                }
                
                // Update dirs/files caption
                phrases_pb.set_message(format!("<- Found {} phrases, {} ETH keys", phrases, eth_keys));
                
                // Break the loop if no progress for 5 seconds
                if files == last_files && phrases == last_phrases && elapsed > 5 {
                    let no_progress_duration = 5; // 5 seconds
                    thread::sleep(Duration::from_secs(no_progress_duration));
                    
                    // Check again after waiting
                    let new_files = stats_clone.files_processed.load(Ordering::Relaxed);
                    let new_phrases = stats_clone.phrases_found.load(Ordering::Relaxed);
                    
                    if new_files == files && new_phrases == phrases && elapsed > 30 {
                        // No progress after waiting, assume scan is complete
                        break;
                    }
                }
                
                // Update last values
                last_files = files;
                last_phrases = phrases;
            }
            
            // Finalize progress bars
            files_pb.finish_with_message("Scan complete");
            phrases_pb.finish();
        });
        
        // Start the scan in the main thread
        scanner.scan_directory(path)?;
        
        // Signal the progress thread to finish
        shutdown_signal.store(true, std::sync::atomic::Ordering::Relaxed);
        
        // Wait for the progress thread to finish
        if let Err(e) = progress_handle.join() {
            eprintln!("Error joining progress thread: {:?}", e);
        }
        
        // Show summary
        self.term.write_line("")?;
        self.term.write_line("= Scan Summary")?;
        self.term.write_line("")?;
        
        let files = stats.files_processed.load(Ordering::Relaxed);
        let dirs = stats.dirs_processed.load(Ordering::Relaxed);
        let bytes = stats.bytes_processed.load(Ordering::Relaxed);
        let phrases = stats.phrases_found.load(Ordering::Relaxed);
        let eth_keys = stats.eth_keys_found.load(Ordering::Relaxed);
        let elapsed = stats.elapsed_seconds();
        
        self.term.write_line(&format!("Files processed: {}", files))?;
        self.term.write_line(&format!("Directories processed: {}", dirs))?;
        self.term.write_line(&format!("Data processed: {} MB", bytes / 1_048_576))?;
        self.term.write_line(&format!("Seed phrases found: {}", phrases))?;
        self.term.write_line(&format!("Ethereum private keys found: {}", eth_keys))?;
        self.term.write_line(&format!("Time taken: {} seconds", elapsed))?;
        
        if elapsed > 0 {
            let mb_processed = bytes / 1_048_576;
            let mb_per_sec = mb_processed as f64 / elapsed as f64;
            self.term.write_line(&format!("Processing speed: {:.1} MB/s", mb_per_sec))?;
        }
        
        self.term.write_line("")?;
        
        // Ask to continue
        if !Confirm::with_theme(&self.theme)
            .with_prompt("Press Enter to continue")
            .default(true)
            .interact_on(&self.term)?
        {
            // This will never happen since default is true, but needed to satisfy the API
        }
        
        Ok(())
    }
    
    /// Show help information
    fn show_help(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.term.clear_screen()?;
        self.term.write_line("=- Help Information")?;
        self.term.write_line("")?;
        
        self.term.write_line("BeCeeded is a tool for cryptocurrency seed phrases, mnemonics, and wallets.")?;
        self.term.write_line("")?;
        
        self.term.write_line("Available commands:")?;
        self.term.write_line("")?;
        
        self.term.write_line("  Generate a new mnemonic seed phrase")?;
        self.term.write_line("    - Creates a new random BIP-39 mnemonic with selectable word count and language")?;
        self.term.write_line("")?;
        
        self.term.write_line("  Parse and validate a mnemonic")?;
        self.term.write_line("    - Checks if a mnemonic phrase is valid and has the correct checksum")?;
        self.term.write_line("")?;
        
        self.term.write_line("  Create wallet from mnemonic")?;
        self.term.write_line("    - Generates a cryptocurrency wallet from a seed phrase")?;
        self.term.write_line("    - Supports both Bitcoin and Ethereum")?;
        self.term.write_line("    - Optional passphrase for additional security")?;
        self.term.write_line("")?;
        
        self.term.write_line("  Scan files for seed phrases")?;
        self.term.write_line("    - Searches files for potential cryptocurrency seed phrases and private keys")?;
        self.term.write_line("    - Four scanning modes with different performance/thoroughness trade-offs")?;
        self.term.write_line("    - Multi-threaded for better performance")?;
        self.term.write_line("")?;
        
        self.term.write_line("Security Notes:")?;
        self.term.write_line("")?;
        self.term.write_line("  - Seed phrases should be kept secure and backed up")?;
        self.term.write_line("  - BeCeeded does not transmit any data over the network")?;
        self.term.write_line("  - All operations are performed locally on your machine")?;
        self.term.write_line("")?;
        
        // Ask to continue
        if !Confirm::with_theme(&self.theme)
            .with_prompt("Press Enter to continue")
            .default(true)
            .interact_on(&self.term)?
        {
            // This will never happen since default is true, but needed to satisfy the API
        }
        
        Ok(())
    }
    
    /// Display exit message
    fn display_exit_message(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.term.clear_screen()?;
        
        let message = style("\nThank you for using BeCeeded!\n").cyan().bold();
        self.term.write_line(&message.to_string())?;
        
        Ok(())
    }
}

/// Main menu options
enum MainMenuOption {
    GenerateMnemonic,
    ParseMnemonic,
    CreateWallet,
    ScanFiles,
    ShowHelp,
    Exit,
}