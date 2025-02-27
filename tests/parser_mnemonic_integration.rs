use beceeded::mnemonic::{Mnemonic, MnemonicError};
use beceeded::parser::{Parser, ParserConfig, ParserError};
use secrecy::ExposeSecret;

// Test vectors from BIP-39 specification
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
const TEST_ENTROPY_1: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const TEST_MNEMONIC_1: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TEST_SEED_1: &[u8] = &[
    0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x2b, 0x19, 0xbf, 0xfe, 0x65, 0xab, 0xa2, 0xca,
    0x08, 0x61, 0xe8, 0xf8, 0xbf, 0xa2, 0x2d, 0x2d, 0x17, 0x29, 0x32, 0x09, 0x05, 0xd3, 0x69, 0x4c,
];

const TEST_ENTROPY_2: &[u8] = &[
    0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
];
const TEST_MNEMONIC_2: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

const TEST_ENTROPY_3: &[u8] = &[
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
];
const TEST_MNEMONIC_3: &str = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

// Integration test for parser and mnemonic working together
#[test]
fn test_bip39_vectors() {
    let parser = Parser::default().expect("Failed to create parser");
    
    // Test Vector 1
    let words = parser.parse(TEST_MNEMONIC_1).expect("Failed to parse test vector 1");
    assert_eq!(words.len(), 12);
    
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC_1, parser.clone())
        .expect("Failed to create mnemonic from test vector 1");
    
    assert_eq!(mnemonic.to_phrase(), TEST_MNEMONIC_1);
    assert!(mnemonic.verify_checksum().expect("Failed to verify checksum"));
    
    let seed = mnemonic.to_seed(Some("TREZOR"));
    assert_eq!(&seed.as_bytes()[0..32], TEST_SEED_1);
    
    // Test creating mnemonic from entropy
    let parser = Parser::default().expect("Failed to create parser");
    let mnemonic = Mnemonic::from_entropy(TEST_ENTROPY_1, parser)
        .expect("Failed to create mnemonic from entropy");
    
    assert_eq!(mnemonic.to_phrase(), TEST_MNEMONIC_1);
}

// Test different wordlists with the parser and mnemonic
#[test]
fn test_different_wordlists() {
    let languages = ["english", "spanish", "french", "italian", "japanese", "korean"];
    
    for language in languages.iter() {
        let config = ParserConfig {
            wordlist_name: language.to_string(),
            ..ParserConfig::default()
        };
        
        // Create parser with the selected language
        let parser = match Parser::new(std::path::PathBuf::from("data"), language.to_string(), config) {
            Ok(p) => p,
            Err(_) => {
                println!("Skipping test for {}: wordlist not available", language);
                continue;
            }
        };
        
        // Generate a mnemonic with this language's wordlist
        let mnemonic = Mnemonic::generate(12, parser.clone())
            .expect(&format!("Failed to generate mnemonic with {} wordlist", language));
        
        // Verify the generated mnemonic
        assert_eq!(mnemonic.word_count(), 12);
        assert!(mnemonic.verify_checksum().expect("Failed to verify checksum"));
        
        // Parse the generated mnemonic with the same parser
        let words = parser.parse(&mnemonic.to_phrase())
            .expect(&format!("Failed to parse {} mnemonic", language));
        
        assert_eq!(words.len(), 12);
    }
}

// Test full round-trip from entropy to mnemonic to seed to wallet
#[test]
fn test_entropy_to_mnemonic_to_seed_round_trip() {
    // Create a parser
    let parser = Parser::default().expect("Failed to create parser");
    
    // Create a mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(TEST_ENTROPY_2, parser.clone())
        .expect("Failed to create mnemonic from entropy");
    
    // Verify the mnemonic phrase matches expected
    assert_eq!(mnemonic.to_phrase(), TEST_MNEMONIC_2);
    
    // Generate a seed from the mnemonic
    let seed = mnemonic.to_seed(Some("TREZOR"));
    
    // Create a new mnemonic from the same entropy
    let mnemonic2 = Mnemonic::from_entropy(TEST_ENTROPY_2, parser)
        .expect("Failed to create second mnemonic from same entropy");
    
    // Generate a seed from the second mnemonic
    let seed2 = mnemonic2.to_seed(Some("TREZOR"));
    
    // Verify both seeds are identical
    assert_eq!(seed.as_bytes(), seed2.as_bytes());
}

// Test invalid inputs
#[test]
fn test_invalid_inputs() {
    let parser = Parser::default().expect("Failed to create parser");
    
    // Test invalid word
    let result = parser.parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon INVALID");
    assert!(matches!(result, Err(ParserError::WordNotFound(_))));
    
    // Test invalid word count
    let result = parser.parse("abandon");
    assert!(matches!(result, Err(ParserError::InvalidWordCount { .. })));
    
    // Test invalid checksum
    let result = parser.parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
    assert!(matches!(result, Err(ParserError::ChecksumError)));
    
    // Test invalid entropy size for mnemonic generation
    let result = Mnemonic::generate(13, parser.clone());
    assert!(matches!(result, Err(MnemonicError::InvalidEntropySize { .. })));
}

// Test secure string handling
#[test]
fn test_secure_string_handling() {
    let parser = Parser::default().expect("Failed to create parser");
    
    // Create a mnemonic
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC_3, parser)
        .expect("Failed to create mnemonic");
    
    // Get a secure phrase
    let secure_phrase = mnemonic.to_secure_phrase();
    
    // Check that we can access it with the expose_secret method
    assert_eq!(secure_phrase.expose_secret(), TEST_MNEMONIC_3);
    
    // Get a seed with a passphrase
    let seed_with_pass = mnemonic.to_seed(Some("my_passphrase"));
    
    // Get a seed without a passphrase
    let seed_without_pass = mnemonic.to_seed(None);
    
    // They should be different
    assert_ne!(seed_with_pass.as_bytes(), seed_without_pass.as_bytes());
}

#[test]
fn test_comprehensive_wordlists_and_lengths() {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::collections::HashSet;
    
    // All available wordlists - both standard BIP-39 and Monero variants
    let all_wordlists = [
        // Standard BIP-39 wordlists
        "chinese_simplified", "chinese_traditional", "czech", "english", 
        "french", "italian", "japanese", "korean", "portuguese", "spanish",
        
        // Monero-specific wordlists
        "monero_chinese_simplified", "monero_dutch", "monero_english", 
        "monero_esperanto", "monero_french", "monero_german", "monero_italian", 
        "monero_japanese", "monero_lojban", "monero_portuguese", 
        "monero_russian", "monero_spanish"
    ];
    
    // Different mnemonic lengths to test
    let standard_lengths = [12, 15, 18, 21, 24];
    let monero_lengths = [25]; // Monero uses 25-word mnemonics
    
    // Basic seed for our random number generation
    let seed = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default().as_millis() as u64;
    
    println!("Testing with random seed: {}", seed);
    
    // Test each wordlist
    for language in all_wordlists.iter() {
        println!("\nTesting wordlist: {}", language);
        
        // Determine if this is a Monero wordlist
        let is_monero = language.starts_with("monero_");
        
        // Choose appropriate lengths based on wordlist type
        let lengths_to_test = if is_monero {
            &monero_lengths[..]
        } else {
            &standard_lengths[..]
        };
        
        // Create parser config for this language
        let config = ParserConfig {
            validate_checksum: false, // Initially disable checksum for testing flexibility
            valid_word_counts: if is_monero {
                vec![25] // Monero only uses 25-word phrases
            } else {
                standard_lengths.to_vec() // BIP-39 uses various lengths
            },
            wordlist_name: language.to_string(),
            ..ParserConfig::default()
        };
        
        // Try to load the wordlist
        let parser = match Parser::new(std::path::PathBuf::from("data"), language.to_string(), config) {
            Ok(p) => p,
            Err(e) => {
                println!("  Skipping {}: Unable to load wordlist: {:?}", language, e);
                continue;
            }
        };
        
        // Report wordlist size
        let wordlist_size = parser.wordlist_len();
        println!("  Loaded {} with {} words", language, wordlist_size);
        
        // For each mnemonic length
        for &length in lengths_to_test {
            // Skip if wordlist is too small
            if wordlist_size < length {
                println!("  Skipping {}-word test: wordlist too small", length);
                continue;
            }
            
            println!("  Testing {}-word mnemonic", length);
            
            // Generate truly random indices using our seed
            let mut rng = seed;
            let mut used_indices = HashSet::new();
            let mut random_indices = Vec::with_capacity(length);
            
            // Select 'length' unique random words from the wordlist
            while random_indices.len() < length {
                // Simple xorshift random number generation
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                
                // Get a random index within the wordlist range
                let idx = (rng % wordlist_size as u64) as usize;
                
                // Only use each word once in our test
                if !used_indices.contains(&idx) {
                    used_indices.insert(idx);
                    random_indices.push(idx);
                }
            }
            
            // For Monero 25-word mnemonics, the last word should be a valid checksum
            // But since we're testing with random words, we need to adjust the last word
            if is_monero && length == 25 {
                // For our test, we'll simply make the checksum word valid by calculation
                // This is a simplification for testing - we're just ensuring the parser accepts it
                // Replace the 25th word with a valid one if needed
                random_indices.pop(); // Remove the last word
                
                // Generate a valid checksum word index based on first 24 words
                let mut total: u128 = 0;
                let mut power: u128 = 1;
                let base = wordlist_size as u128;
                
                for i in 0..24 {
                    let idx = random_indices[i] as u128;
                    total = total.wrapping_add(idx.wrapping_mul(power));
                    power = power.wrapping_mul(base);
                    
                    if power >= u128::MAX / base {
                        power %= base;
                        total %= base;
                    }
                }
                
                let checksum_idx = (total % base) as usize;
                random_indices.push(checksum_idx);
                println!("    Generated valid checksum word at index {}", checksum_idx);
            }
            
            // Get the words at these random indices
            let random_words: Vec<String> = random_indices.iter()
                .map(|&idx| parser.get_wordlist_slice(idx, idx + 1)[0].clone())
                .collect();
            
            // Check if this is a CJK wordlist for display purposes
            let is_cjk = language.contains("chinese") || 
                        language.contains("japanese") || 
                        language.contains("korean");
                
            // Join into a mnemonic phrase with proper separator
            let test_phrase = if is_cjk {
                // For CJK languages, join without spaces for testing
                random_words.join("")
            } else {
                // For all other languages, separate with spaces
                random_words.join(" ")
            };
            
            // Create a new parser with checksum validation enabled for final test
            let config_with_checksum = ParserConfig {
                validate_checksum: true,
                valid_word_counts: if is_monero {
                    vec![25]
                } else {
                    standard_lengths.to_vec()
                },
                wordlist_name: language.to_string(),
                ..ParserConfig::default()
            };
            
            let parser_with_checksum = match Parser::new(
                std::path::PathBuf::from("data"), 
                language.to_string(), 
                config_with_checksum
            ) {
                Ok(p) => p,
                Err(e) => {
                    println!("  Skipping checksum validation: Unable to create parser: {:?}", e);
                    continue;
                }
            };
            
            // For non-Monero mnemonics, we need to disable checksum validation
            // because our random words won't have valid checksums
            let parser_to_use = if is_monero {
                // For Monero we constructed a valid checksum, so use the parser with validation
                parser_with_checksum
            } else {
                // For other wordlists, continue using the parser without checksum validation
                parser.clone()
            };
            
            // Test parsing the random mnemonic
            let parsed_result = parser_to_use.parse(&test_phrase);
            
            // Verify the result
            if let Err(ref e) = parsed_result {
                println!("    Error parsing {}-word {} mnemonic: {:?}", length, language, e);
                
                // Debug information
                println!("    Test phrase format: {}", if is_cjk { "no spaces" } else { "space-separated" });
                println!("    First 3 words: {:?}", &random_words[0..3.min(random_words.len())]);
                
                if is_monero {
                    println!("    First 5 word indices: {:?}", &random_indices[0..5.min(random_indices.len())]);
                }
            }
            
            assert!(parsed_result.is_ok(), 
                    "Failed to parse {}-word {} mnemonic", length, language);
            
            let words = parsed_result.unwrap();
            assert_eq!(words.len(), length, 
                      "Parsed {} mnemonic has wrong word count", language);
            
            // Verify each word matched what we expected
            for (i, word) in words.iter().enumerate() {
                assert_eq!(word, &random_words[i], 
                          "Word mismatch at position {} in {} mnemonic", i, language);
            }
            
            println!("    ✓ Successfully parsed random {}-word mnemonic", length);
        }
    }
    
    println!("\nAll wordlist and length combinations tested successfully!");
} 