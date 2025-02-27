//! Memory management for BeCeeded
//!
//! This module provides utilities for secure memory handling,
//! replacing the custom memory pool from the C implementation.
//! In Rust, we leverage the built-in memory safety features
//! and add secure handling for sensitive data.

use secrecy::{SecretBox, SecretString};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// A secure container for sensitive byte data that will be zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes {
    bytes: Vec<u8>,
}

impl SecureBytes {
    /// Create a new SecureBytes container
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    
    /// Get an immutable reference to the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get a mutable reference to the underlying bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
    
    /// Convert into a vector, consuming self
    pub fn into_vec(self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.bytes.len());
        result.extend_from_slice(&self.bytes);
        // self will be zeroed on drop
        result
    }
    
    /// Length of the contained data
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    
    /// Check if the container is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// Prevent debug printing of secure bytes
impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED {} bytes]", self.bytes.len())
    }
}

/// A secure wrapper around a String that will be zeroed on drop.
/// This is a type alias for secrecy::SecretString for compatibility.
pub type SecureString = SecretString;

/// Create a new secure string
pub fn secure_string(s: impl Into<String>) -> SecureString {
    s.into().into()
}

/// Create a new secure bytes container
pub fn secure_bytes(bytes: Vec<u8>) -> SecretBox<Vec<u8>> {
    SecretBox::new(Box::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    
    #[test]
    fn test_secure_bytes() {
        let test_data = vec![1, 2, 3, 4, 5];
        let secure = SecureBytes::new(test_data.clone());
        
        assert_eq!(secure.as_bytes(), &test_data[..]);
        assert_eq!(secure.len(), 5);
        assert!(!secure.is_empty());
        
        let retrieved = secure.into_vec();
        assert_eq!(retrieved, test_data);
    }
    
    #[test]
    fn test_secure_string() {
        let test_str = "sensitive data";
        let secure = secure_string(test_str);
        
        // We can access the string's content with expose_secret()
        assert_eq!(secure.expose_secret(), test_str);
    }
} 