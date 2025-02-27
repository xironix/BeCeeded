//! Logging functionality for BeCeeded
//!
//! This module provides logging capabilities using the standard `log` crate
//! with `env_logger` as the implementation.

use log::LevelFilter;
use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize the logger with the specified log level
///
/// # Arguments
///
/// * `level` - The minimum log level to display
///
/// # Returns
///
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error
///
/// # Examples
///
/// ```
/// use beceeded::logger;
/// use log::LevelFilter;
///
/// logger::init_logger(LevelFilter::Debug).unwrap();
/// log::debug!("Debug message");
/// ```
pub fn init_logger(level: LevelFilter) -> Result<(), Box<dyn std::error::Error>> {
    let mut result = Ok(());
    
    INIT.call_once(|| {
        result = match env_logger::Builder::new()
            .filter_level(level)
            .format_timestamp_millis()
            .try_init()
        {
            Ok(_) => Ok(()),
            Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
        };
    });
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::{debug, error, info, trace, warn};

    #[test]
    fn test_logger_initialization() {
        // This just tests that initialization doesn't panic
        let _ = init_logger(LevelFilter::Trace);
        
        trace!("Test trace message");
        debug!("Test debug message");
        info!("Test info message");
        warn!("Test warning message");
        error!("Test error message");
    }
} 