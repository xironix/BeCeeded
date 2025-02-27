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
        let mut config = ParserConfig::default();
        config.wordlist_name = language.to_string();
        
        // Create parser with the selected language
        let parser = match Parser::new(config) {
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