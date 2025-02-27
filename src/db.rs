// db.rs - Database controller for BeCeeded scanner
//
// This module provides a database controller implementation using SQLite
// for storing and retrieving found seed phrases and private keys.

use crate::scanner::{DbController, FoundEthKey, FoundPhrase, Result, ScannerError};
use log::{debug, error, info};
use rusqlite::{params, Connection, TransactionBehavior};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

/// SQLite-based database controller
pub struct SqliteDbController {
    /// Database connection
    conn: Mutex<Connection>,
    
    /// Path to the database file
    db_path: Option<PathBuf>,
    
    /// Whether the database is in memory
    in_memory: bool,
    
    /// Whether the database is encrypted
    encrypted: bool,
}

impl SqliteDbController {
    /// Create a new SQLite database controller
    pub fn new(db_path: &str) -> Result<Self> {
        Self::new_with_options(db_path, None, false)
    }

    /// Create a new encrypted SQLite database controller
    pub fn new_encrypted(db_path: &str, encryption_key: &str) -> Result<Self> {
        Self::new_with_options(db_path, Some(encryption_key), false)
    }

    /// Create a new in-memory SQLite database controller
    pub fn new_in_memory() -> Result<Self> {
        Self::new_with_options(":memory:", None, true)
    }
    
    /// Create a new SQLite database controller with custom options
    fn new_with_options(db_path: &str, encryption_key: Option<&str>, in_memory: bool) -> Result<Self> {
        // Connect to the database
        let conn_result = if in_memory {
            Connection::open_in_memory()
        } else {
            // Ensure the parent directory exists
            if let Some(parent) = Path::new(db_path).parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| ScannerError::DatabaseError(format!("Failed to create database directory: {}", e)))?;
                }
            }
            
            Connection::open(db_path)
        };
        
        let conn = conn_result.map_err(|e| {
            ScannerError::DatabaseError(format!("Failed to connect to database: {}", e))
        })?;
        
        // Create controller
        let controller = Self {
            conn: Mutex::new(conn),
            db_path: if in_memory { None } else { Some(PathBuf::from(db_path)) },
            in_memory,
            encrypted: encryption_key.is_some(),
        };
        
        // Apply encryption if provided
        if let Some(key) = encryption_key {
            let conn = controller.conn.lock().unwrap();
            conn.execute_batch(&format!("PRAGMA key = '{}';", key))
                .map_err(|e| {
                    ScannerError::DatabaseError(format!("Failed to set encryption key: {}", e))
                })?;
        }
        
        // Initialize database schema
        controller.init()?;
        
        Ok(controller)
    }
    
    /// Execute a database transaction with the given function
    fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let mut conn_guard = self.conn.lock().unwrap();
        
        let tx = conn_guard.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|e| {
            error!("Failed to begin transaction: {}", e);
            ScannerError::DatabaseError(format!("Failed to begin transaction: {}", e))
        })?;
        
        let result = f(&tx)?;
        
        tx.commit().map_err(|e| {
            error!("Failed to commit transaction: {}", e);
            ScannerError::DatabaseError(format!("Failed to commit transaction: {}", e))
        })?;
        
        Ok(result)
    }
}

impl DbController for SqliteDbController {
    fn init(&self) -> Result<()> {
        debug!("Initializing database");
        
        // Create tables in a transaction
        self.transaction(|conn| {
            // Create phrases table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS phrases (
                    id INTEGER PRIMARY KEY,
                    phrase TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    line_number INTEGER,
                    fuzzy_matched INTEGER NOT NULL DEFAULT 0,
                    confidence REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                [],
            ).map_err(|e| {
                error!("Failed to create phrases table: {}", e);
                ScannerError::DatabaseError(format!("Failed to create phrases table: {}", e))
            })?;
            
            // Create wallet_addresses table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS wallet_addresses (
                    id INTEGER PRIMARY KEY,
                    phrase_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    FOREIGN KEY(phrase_id) REFERENCES phrases(id)
                )",
                [],
            ).map_err(|e| {
                error!("Failed to create wallet_addresses table: {}", e);
                ScannerError::DatabaseError(format!("Failed to create wallet_addresses table: {}", e))
            })?;
            
            // Create ethereum_keys table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS ethereum_keys (
                    id INTEGER PRIMARY KEY,
                    private_key TEXT NOT NULL UNIQUE,
                    file_path TEXT NOT NULL,
                    line_number INTEGER,
                    eth_address TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                [],
            ).map_err(|e| {
                error!("Failed to create ethereum_keys table: {}", e);
                ScannerError::DatabaseError(format!("Failed to create ethereum_keys table: {}", e))
            })?;
            
            // Create indexes
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_phrases_phrase ON phrases(phrase)",
                [],
            ).map_err(|e| {
                error!("Failed to create index on phrases: {}", e);
                ScannerError::DatabaseError(format!("Failed to create index on phrases: {}", e))
            })?;
            
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ethereum_keys_private_key ON ethereum_keys(private_key)",
                [],
            ).map_err(|e| {
                error!("Failed to create index on ethereum_keys: {}", e);
                ScannerError::DatabaseError(format!("Failed to create index on ethereum_keys: {}", e))
            })?;
            
            // Enable WAL journal mode for better concurrency
            conn.execute("PRAGMA journal_mode = WAL", []).map_err(|e| {
                error!("Failed to set WAL journal mode: {}", e);
                ScannerError::DatabaseError(format!("Failed to set WAL journal mode: {}", e))
            })?;
            
            info!("Database initialized successfully");
            Ok(())
        })
    }
    
    fn insert_phrase(&self, phrase: &FoundPhrase) -> Result<bool> {
        debug!("Inserting phrase into database: {}", phrase.phrase);
        
        let mut conn = self.conn.lock().unwrap();
        
        // Start a transaction
        let tx = conn.transaction().map_err(|e| {
            error!("Failed to start transaction: {}", e);
            ScannerError::DatabaseError(format!("Failed to start transaction: {}", e))
        })?;
        
        // Check if the phrase already exists
        let exists: bool = tx.query_row(
            "SELECT 1 FROM phrases WHERE phrase = ?1",
            [&phrase.phrase],
            |_| Ok(true),
        ).unwrap_or(false);
        
        if exists {
            debug!("Phrase already exists in database");
            tx.commit().map_err(|e| {
                error!("Failed to commit transaction: {}", e);
                ScannerError::DatabaseError(format!("Failed to commit transaction: {}", e))
            })?;
            return Ok(false);
        }
        
        // Insert the phrase
        let fuzzy_matched_value = if phrase.fuzzy_matched { 1 } else { 0 };
        let confidence_value = phrase.confidence.unwrap_or(0.0);
        
        tx.execute(
            "INSERT INTO phrases (phrase, file_path, line_number, fuzzy_matched, confidence)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                phrase.phrase,
                phrase.file_path,
                phrase.line_number.map(|n| n as i64),
                fuzzy_matched_value,
                confidence_value,
            ],
        ).map_err(|e| {
            error!("Failed to insert phrase: {}", e);
            ScannerError::DatabaseError(format!("Failed to insert phrase: {}", e))
        })?;
        
        let phrase_id = tx.last_insert_rowid();
        
        // Insert wallet addresses
        for address in &phrase.wallet_addresses {
            tx.execute(
                "INSERT INTO wallet_addresses (phrase_id, address) VALUES (?, ?)",
                params![phrase_id, address],
            ).map_err(|e| {
                error!("Failed to insert wallet address: {}", e);
                ScannerError::DatabaseError(format!("Failed to insert wallet address: {}", e))
            })?;
        }
        
        debug!("Inserted new phrase into database");
        tx.commit().map_err(|e| {
            error!("Failed to commit transaction: {}", e);
            ScannerError::DatabaseError(format!("Failed to commit transaction: {}", e))
        })?;
        Ok(true)
    }
    
    fn insert_eth_key(&self, key: &FoundEthKey) -> Result<bool> {
        // Insert the Ethereum key and return true if it was new, false if it already existed
        self.transaction(|conn| {
            // Check if the key already exists
            let mut stmt = conn.prepare("SELECT id FROM ethereum_keys WHERE private_key = ?").map_err(|e| {
                error!("Failed to prepare statement: {}", e);
                ScannerError::DatabaseError(format!("Failed to prepare statement: {}", e))
            })?;
            
            let rows = stmt.query_map([&key.private_key], |row| row.get::<_, i64>(0)).map_err(|e| {
                error!("Failed to query ethereum_keys: {}", e);
                ScannerError::DatabaseError(format!("Failed to query ethereum_keys: {}", e))
            })?;
            
            let existing_ids: Vec<i64> = rows.filter_map(|r| r.ok()).collect();
            
            if !existing_ids.is_empty() {
                // Key already exists
                debug!("Ethereum key already exists in database");
                return Ok(false);
            }
            
            // Insert the key
            let line_number_value = match key.line_number {
                Some(line) => line as i64,
                None => -1, // Use -1 to represent null
            };
            
            conn.execute(
                "INSERT INTO ethereum_keys (private_key, file_path, line_number, eth_address)
                 VALUES (?, ?, ?, ?)",
                params![
                    &key.private_key,
                    &key.file_path,
                    line_number_value,
                    &key.eth_address,
                ],
            ).map_err(|e| {
                error!("Failed to insert Ethereum key: {}", e);
                ScannerError::DatabaseError(format!("Failed to insert Ethereum key: {}", e))
            })?;
            
            debug!("Inserted new Ethereum key into database");
            Ok(true)
        })
    }
    
    fn get_all_phrases(&self) -> Result<Vec<FoundPhrase>> {
        debug!("Fetching all phrases from database");
        
        let conn = self.conn.lock().unwrap();
        
        // Prepare the query
        let mut stmt = conn.prepare(
            "SELECT p.id, p.phrase, p.file_path, p.line_number, p.fuzzy_matched, p.confidence
             FROM phrases p
             ORDER BY p.created_at DESC"
        ).map_err(|e| {
            error!("Failed to prepare statement: {}", e);
            ScannerError::DatabaseError(format!("Failed to prepare statement: {}", e))
        })?;
        
        // Execute the query and collect results
        let phrase_rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let phrase: String = row.get(1)?;
            let file_path: String = row.get(2)?;
            let line_number: i32 = row.get(3)?;
            let fuzzy_matched: i32 = row.get(4)?;
            let confidence: f64 = row.get(5)?;
            
            Ok((id, phrase, file_path, line_number, fuzzy_matched != 0, confidence))
        }).map_err(|e| {
            error!("Failed to query phrases: {}", e);
            ScannerError::DatabaseError(format!("Failed to query phrases: {}", e))
        })?;
        
        let phrase_data: Vec<(i64, String, String, i32, bool, f64)> = phrase_rows.filter_map(|r| r.ok()).collect();
        
        // Get wallet addresses for each phrase
        let mut result = Vec::new();
        
        for (id, phrase, file_path, line_number, fuzzy_matched, confidence) in phrase_data {
            // Get wallet addresses
            let mut addr_stmt = conn.prepare(
                "SELECT address FROM wallet_addresses WHERE phrase_id = ?"
            ).map_err(|e| {
                error!("Failed to prepare statement: {}", e);
                ScannerError::DatabaseError(format!("Failed to prepare statement: {}", e))
            })?;
            
            let address_rows = addr_stmt.query_map([id], |row| {
                let address: String = row.get(0)?;
                Ok(address)
            }).map_err(|e| {
                error!("Failed to query wallet addresses: {}", e);
                ScannerError::DatabaseError(format!("Failed to query wallet addresses: {}", e))
            })?;
            
            let wallet_addresses: Vec<String> = address_rows.filter_map(|r| r.ok()).collect();
            
            // Create the FoundPhrase
            let line_number = if line_number >= 0 {
                Some(line_number as usize)
            } else {
                None
            };
            
            let confidence = if confidence > 0.0 {
                Some(confidence)
            } else {
                None
            };
            
            result.push(FoundPhrase {
                phrase,
                file_path,
                line_number,
                wallet_addresses,
                fuzzy_matched,
                confidence,
            });
        }
        
        debug!("Fetched {} phrases from database", result.len());
        Ok(result)
    }
    
    fn get_all_eth_keys(&self) -> Result<Vec<FoundEthKey>> {
        debug!("Fetching all Ethereum keys from database");
        
        let conn = self.conn.lock().unwrap();
        
        // Prepare the query
        let mut stmt = conn.prepare(
            "SELECT private_key, file_path, line_number, eth_address
             FROM ethereum_keys
             ORDER BY created_at DESC"
        ).map_err(|e| {
            error!("Failed to prepare statement: {}", e);
            ScannerError::DatabaseError(format!("Failed to prepare statement: {}", e))
        })?;
        
        // Execute the query and collect results
        let key_rows = stmt.query_map([], |row| {
            let private_key: String = row.get(0)?;
            let file_path: String = row.get(1)?;
            let line_number: i64 = row.get(2)?;
            let eth_address: String = row.get(3)?;
            
            let line_number = if line_number >= 0 {
                Some(line_number as usize)
            } else {
                None
            };
            
            Ok(FoundEthKey {
                private_key,
                file_path,
                line_number,
                eth_address,
            })
        }).map_err(|e| {
            error!("Failed to query Ethereum keys: {}", e);
            ScannerError::DatabaseError(format!("Failed to query Ethereum keys: {}", e))
        })?;
        
        let result: Vec<FoundEthKey> = key_rows.filter_map(|r| r.ok()).collect();
        
        debug!("Fetched {} Ethereum keys from database", result.len());
        Ok(result)
    }
    
    fn close(&self) -> Result<()> {
        debug!("Closing database connection");
        
        // Nothing special to do for SQLite
        // The connection will be closed when it's dropped
        
        Ok(())
    }
}

/// Get the application data directory to store the SQLite database
pub fn get_app_data_dir() -> Result<PathBuf> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| ScannerError::DatabaseError("Could not determine home directory".to_string()))?;
    
    #[cfg(target_os = "macos")]
    let app_data_dir = home_dir.join("Library").join("Application Support").join("BeCeeded");
    
    #[cfg(target_os = "linux")]
    let app_data_dir = home_dir.join(".local").join("share").join("BeCeeded");
    
    #[cfg(target_os = "windows")]
    let app_data_dir = home_dir.join("AppData").join("Local").join("BeCeeded");
    
    // Create the directory if it doesn't exist
    if !app_data_dir.exists() {
        std::fs::create_dir_all(&app_data_dir)
            .map_err(|e| ScannerError::DatabaseError(format!("Failed to create app data directory: {}", e)))?;
    }
    
    Ok(app_data_dir)
}

/// Get the default database path for the application
pub fn get_default_db_path() -> Result<String> {
    let app_data_dir = get_app_data_dir()?;
    let db_path = app_data_dir.join("beceeded.db");
    Ok(db_path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Result as SqliteResult;
    use std::fs;
    use tempfile::TempDir;

    // Create a test phrase
    fn create_test_phrase() -> FoundPhrase {
        FoundPhrase {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            file_path: "/test/path/file.txt".to_string(),
            line_number: Some(42),
            wallet_addresses: vec![
                "0x1234567890abcdef1234567890abcdef12345678".to_string(),
                "bc1q123456789abcdef123456789abcdef123456789".to_string(),
            ],
            fuzzy_matched: false,
            confidence: Some(1.0),
        }
    }

    // Create a test Ethereum key
    fn create_test_eth_key() -> FoundEthKey {
        FoundEthKey {
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            file_path: "/test/path/file.txt".to_string(),
            line_number: Some(42),
            eth_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        }
    }

    #[test]
    fn test_in_memory_database() {
        // Create in-memory database
        let db = SqliteDbController::new_in_memory().unwrap();
        
        // Initialize
        db.init().unwrap();
        
        // Test phrase insertion
        let phrase = create_test_phrase();
        assert!(db.insert_phrase(&phrase).unwrap()); // New phrase
        assert!(!db.insert_phrase(&phrase).unwrap()); // Duplicate
        
        // Test key insertion
        let key = create_test_eth_key();
        assert!(db.insert_eth_key(&key).unwrap()); // New key
        assert!(!db.insert_eth_key(&key).unwrap()); // Duplicate
        
        // Test retrieval
        let phrases = db.get_all_phrases().unwrap();
        assert_eq!(phrases.len(), 1);
        assert_eq!(phrases[0].phrase, phrase.phrase);
        assert_eq!(phrases[0].wallet_addresses.len(), 2);
        
        let keys = db.get_all_eth_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].private_key, key.private_key);
        
        // Test close
        db.close().unwrap();
    }

    #[test]
    fn test_file_database() {
        // Create temporary directory for database file
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db_path_str = db_path.to_str().unwrap();
        
        // Create file database
        let db = SqliteDbController::new(db_path_str).unwrap();
        
        // Initialize
        db.init().unwrap();
        
        // Test phrase insertion
        let phrase = create_test_phrase();
        assert!(db.insert_phrase(&phrase).unwrap());
        
        // Test key insertion
        let key = create_test_eth_key();
        assert!(db.insert_eth_key(&key).unwrap());
        
        // Test retrieval
        let phrases = db.get_all_phrases().unwrap();
        assert_eq!(phrases.len(), 1);
        
        let keys = db.get_all_eth_keys().unwrap();
        assert_eq!(keys.len(), 1);
        
        // Close the database
        db.close().unwrap();
        
        // Verify the file exists
        assert!(db_path.exists());
        
        // Try opening the database again
        let db2 = SqliteDbController::new(db_path_str).unwrap();
        db2.init().unwrap();
        
        // Verify data persisted
        let phrases = db2.get_all_phrases().unwrap();
        assert_eq!(phrases.len(), 1);
        
        let keys = db2.get_all_eth_keys().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_line_number_and_confidence_handling() {
        let db = SqliteDbController::new_in_memory().unwrap();
        db.init().unwrap();
        
        // Create phrase with no line number and no confidence
        let mut phrase = create_test_phrase();
        phrase.line_number = None;
        phrase.confidence = None;
        
        // Insert and retrieve
        db.insert_phrase(&phrase).unwrap();
        let phrases = db.get_all_phrases().unwrap();
        
        // Verify data
        assert_eq!(phrases.len(), 1);
        assert_eq!(phrases[0].line_number, None);
        assert_eq!(phrases[0].confidence, None);
        
        // Create key with no line number
        let mut key = create_test_eth_key();
        key.line_number = None;
        
        // Insert and retrieve
        db.insert_eth_key(&key).unwrap();
        let keys = db.get_all_eth_keys().unwrap();
        
        // Verify data
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].line_number, None);
    }

    #[test]
    fn test_wallet_addresses_retrieval() {
        let db = SqliteDbController::new_in_memory().unwrap();
        db.init().unwrap();
        
        // Create phrase with multiple addresses
        let mut phrase = create_test_phrase();
        phrase.wallet_addresses = vec![
            "address1".to_string(),
            "address2".to_string(),
            "address3".to_string(),
        ];
        
        // Insert and retrieve
        db.insert_phrase(&phrase).unwrap();
        let phrases = db.get_all_phrases().unwrap();
        
        // Verify wallet addresses
        assert_eq!(phrases.len(), 1);
        assert_eq!(phrases[0].wallet_addresses.len(), 3);
        assert!(phrases[0].wallet_addresses.contains(&"address1".to_string()));
        assert!(phrases[0].wallet_addresses.contains(&"address2".to_string()));
        assert!(phrases[0].wallet_addresses.contains(&"address3".to_string()));
    }

    #[test]
    fn test_transaction_rollback() {
        let db = SqliteDbController::new_in_memory().unwrap();
        db.init().unwrap();
        
        // Override the connection to test transaction rollback
        let result: Result<()> = db.transaction(|conn| {
            // First insert succeeds
            conn.execute(
                "INSERT INTO phrases (phrase, file_path, line_number, fuzzy_matched, confidence)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    "test phrase 1",
                    "/test/path.txt",
                    42,
                    0,
                    1.0,
                ],
            ).unwrap();
            
            // Second insert fails (we'll force an error by using incorrect SQL)
            conn.execute(
                "INSERT INTO non_existent_table (phrase) VALUES (?)",
                params!["test phrase 2"],
            ).map_err(|e| {
                ScannerError::DatabaseError(format!("Test error: {}", e))
            })?;
            
            Ok(())
        });
        
        // The transaction should have failed
        assert!(result.is_err());
        
        // And no data should have been inserted
        let phrases = db.get_all_phrases().unwrap();
        assert_eq!(phrases.len(), 0);
    }
} 