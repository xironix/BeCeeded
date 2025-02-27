// ocr.rs - OCR implementation for extracting text from images
//
// This module provides functionality for extracting text from images using OCR.
// It serves as an integration point for external OCR libraries.

use crate::scanner::{Result, ScannerError};
use log::warn;
use std::path::Path;

/// OCR engine options
#[derive(Debug, Clone)]
pub struct OcrOptions {
    /// Language to use for OCR (e.g., "eng")
    pub language: String,
    
    /// Whether to use page segmentation mode optimized for single words/phrases
    pub phrase_mode: bool,
    
    /// Whether to preprocess images for better OCR results
    pub preprocessing: bool,
    
    /// Minimum confidence threshold for OCR results (0.0-100.0)
    pub confidence_threshold: f32,
}

impl Default for OcrOptions {
    fn default() -> Self {
        Self {
            language: "eng".to_string(),
            phrase_mode: true,
            preprocessing: true,
            confidence_threshold: 50.0, // Default 50% confidence threshold
        }
    }
}

/// OCR engine trait
pub trait OcrEngine: Send + Sync {
    /// Initialize the OCR engine
    fn init(&mut self, options: &OcrOptions) -> Result<()>;
    
    /// Process an image file and extract text
    fn process_image(&self, image_path: &Path) -> Result<String>;
    
    /// Clean up resources
    fn cleanup(&self) -> Result<()>;
}

/// Tesseract OCR engine implementation
#[cfg(feature = "ocr")]
pub struct TesseractOcr {
    initialized: bool,
    options: Option<OcrOptions>,
    #[cfg(feature = "ocr")]
    tess: Option<leptess::LepTess>,
}

/// Tesseract OCR implementation with leptess
#[cfg(feature = "ocr")]
impl TesseractOcr {
    /// Create a new TesseractOcr engine
    pub fn new() -> Self {
        Self {
            initialized: false,
            options: None,
            tess: None,
        }
    }
    
    // Helper to set tesseract options
    fn configure_tesseract(&mut self, options: &OcrOptions) -> Result<()> {
        let tess = &mut self.tess.as_mut().unwrap();
        
        // Set page segmentation mode based on phrase mode setting
        let psm = if options.phrase_mode {
            // PSM_SINGLE_LINE mode is good for phrases
            leptess::PageSegMode::PSM_SINGLE_LINE
        } else {
            // PSM_AUTO mode for general text
            leptess::PageSegMode::PSM_AUTO
        };
        
        tess.set_page_seg_mode(psm)
            .map_err(|e| ScannerError::OcrError(format!("Failed to set page seg mode: {}", e)))?;
        
        // Set minimum confidence threshold
        tess.set_variable("lstm_choice_threshold", &format!("{:.2}", options.confidence_threshold / 100.0))
            .map_err(|e| ScannerError::OcrError(format!("Failed to set confidence threshold: {}", e)))?;
        
        Ok(())
    }
}

/// Tesseract OCR engine implementation for non-OCR builds
#[cfg(not(feature = "ocr"))]
pub struct TesseractOcr {
    initialized: bool,
    options: Option<OcrOptions>,
}

/// Fallback implementation for when OCR feature is disabled
#[cfg(not(feature = "ocr"))]
impl TesseractOcr {
    /// Create a new TesseractOcr engine
    pub fn new() -> Self {
        Self {
            initialized: false,
            options: None,
        }
    }
}

#[cfg(feature = "ocr")]
impl OcrEngine for TesseractOcr {
    fn init(&mut self, options: &OcrOptions) -> Result<()> {
        info!("Initializing Tesseract OCR engine with language: {}", options.language);
        
        // Initialize Tesseract
        let tess = leptess::LepTess::new(None, &options.language)
            .map_err(|e| ScannerError::OcrError(format!("Failed to initialize Tesseract: {}", e)))?;
        
        self.tess = Some(tess);
        
        // Configure Tesseract with options
        self.configure_tesseract(options)?;
        
        // Store options for later use
        self.options = Some(options.clone());
        self.initialized = true;
        
        debug!("Tesseract OCR engine initialized");
        Ok(())
    }
    
    fn process_image(&self, image_path: &Path) -> Result<String> {
        // Check if initialized
        if !self.initialized || self.tess.is_none() {
            return Err(ScannerError::OcrError("OCR engine not initialized".to_string()));
        }
        
        let options = self.options.as_ref().unwrap();
        let tess = self.tess.as_ref().unwrap();
        
        debug!("Processing image: {}", image_path.display());
        
        // Load the image
        let img = image::open(image_path)
            .map_err(|e| ScannerError::OcrError(format!("Failed to open image: {}", e)))?;
        
        // Preprocess the image if enabled
        let img = if options.preprocessing {
            debug!("Preprocessing image for better OCR results");
            preprocess_image_data(img)
        } else {
            img
        };
        
        // Convert image to PIX format for Tesseract
        let pix = leptess::leptonica::pix_from_image(&img)
            .map_err(|e| ScannerError::OcrError(format!("Failed to convert image: {}", e)))?;
        
        // Set the image for OCR
        let mut tess = tess.clone(); // We need a mutable copy
        tess.set_image(&pix)
            .map_err(|e| ScannerError::OcrError(format!("Failed to set image: {}", e)))?;
        
        // Perform OCR
        let text = tess.get_utf8_text()
            .map_err(|e| ScannerError::OcrError(format!("Failed to perform OCR: {}", e)))?;
        
        debug!("OCR completed with {} characters extracted", text.len());
        
        Ok(text)
    }
    
    fn cleanup(&self) -> Result<()> {
        debug!("Cleaning up Tesseract OCR engine");
        // Tesseract resources are cleaned up automatically when dropped
        Ok(())
    }
}

#[cfg(not(feature = "ocr"))]
impl OcrEngine for TesseractOcr {
    fn init(&mut self, options: &OcrOptions) -> Result<()> {
        warn!("OCR support not enabled. Initialization is a no-op.");
        self.options = Some(options.clone());
        self.initialized = true;
        Ok(())
    }
    
    fn process_image(&self, image_path: &Path) -> Result<String> {
        warn!("OCR support not enabled. Cannot process image: {}", image_path.display());
        Err(ScannerError::OcrError("OCR support not enabled".to_string()))
    }
    
    fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}

/// Image preprocessing for better OCR results
#[cfg(feature = "ocr")]
fn preprocess_image_data(img: image::DynamicImage) -> image::DynamicImage {
    use image::{DynamicImage, GenericImageView, Pixel};
    
    // Convert to grayscale
    let img = img.grayscale();
    
    // Increase contrast
    let img = DynamicImage::ImageLuma8(imageproc::contrast::stretch_contrast(&img.to_luma8(), 10, 240));
    
    // Perform adaptive threshold
    let img = DynamicImage::ImageLuma8(imageproc::contrast::adaptive_threshold(&img.to_luma8(), 11));
    
    img
}

/// Preprocess an image file for better OCR results
pub fn preprocess_image(image_path: &Path) -> Result<Vec<u8>> {
    #[cfg(feature = "ocr")]
    {
        // Load the image
        let img = image::open(image_path)
            .map_err(|e| ScannerError::OcrError(format!("Failed to open image: {}", e)))?;
        
        // Preprocess the image
        let processed = preprocess_image_data(img);
        
        // Create a buffer to hold the processed image
        let mut buffer = Vec::new();
        
        // Write the image to the buffer
        processed.write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageOutputFormat::Png)
            .map_err(|e| ScannerError::OcrError(format!("Failed to write processed image: {}", e)))?;
        
        Ok(buffer)
    }
    
    #[cfg(not(feature = "ocr"))]
    {
        warn!("Image preprocessing not available without OCR feature enabled");
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_ocr_options_default() {
        let options = OcrOptions::default();
        
        assert_eq!(options.language, "eng");
        assert!(options.phrase_mode);
        assert!(options.preprocessing);
        assert!((options.confidence_threshold - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_ocr_options_custom() {
        let options = OcrOptions {
            language: "deu".to_string(),
            phrase_mode: false,
            preprocessing: false,
            confidence_threshold: 75.0,
        };
        
        assert_eq!(options.language, "deu");
        assert!(!options.phrase_mode);
        assert!(!options.preprocessing);
        assert!((options.confidence_threshold - 75.0).abs() < 0.001);
    }

    #[test]
    fn test_tesseract_ocr_lifecycle() {
        let mut ocr = TesseractOcr::new();
        
        // Should not be initialized
        assert!(!ocr.initialized);
        assert!(ocr.options.is_none());
        
        // Initialize
        let options = OcrOptions::default();
        ocr.init(&options).unwrap();
        
        // Should now be initialized
        assert!(ocr.initialized);
        assert!(ocr.options.is_some());
        
        // Compare options
        let stored_options = ocr.options.as_ref().unwrap();
        assert_eq!(stored_options.language, options.language);
        assert_eq!(stored_options.phrase_mode, options.phrase_mode);
        assert_eq!(stored_options.preprocessing, options.preprocessing);
        assert_eq!(stored_options.confidence_threshold, options.confidence_threshold);
    }

    #[test]
    fn test_process_image_requires_init() {
        // Create a test image file
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("test.jpg");
        
        // Create an empty file
        let mut file = File::create(&image_path).unwrap();
        file.write_all(b"dummy image data").unwrap();
        
        // Create OCR engine without initialization
        let ocr = TesseractOcr::new();
        
        // Should fail because not initialized
        let result = ocr.process_image(&image_path);
        assert!(result.is_err());
        
        if let Err(ScannerError::OcrError(msg)) = result {
            assert!(msg.contains("not initialized"));
        } else {
            panic!("Expected OcrError, got something else");
        }
    }

    // Mock test for image processing since actual OCR is feature-gated
    #[test]
    fn test_process_image_after_init() {
        // Create a test image file
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("test.jpg");
        
        // Create an empty file
        let mut file = File::create(&image_path).unwrap();
        file.write_all(b"dummy image data").unwrap();
        
        // Create OCR engine with initialization
        let mut ocr = TesseractOcr::new();
        ocr.init(&OcrOptions::default()).unwrap();
        
        // Actual test behavior depends on feature flag
        let result = ocr.process_image(&image_path);
        
        #[cfg(not(feature = "ocr"))]
        {
            assert!(result.is_err());
            if let Err(ScannerError::OcrError(msg)) = result {
                assert!(msg.contains("not enabled"));
            } else {
                panic!("Expected OcrError about OCR not being enabled");
            }
        }
        
        // We don't test the actual OCR functionality in unit tests
        // since we don't want to depend on Tesseract being installed
    }

    #[test]
    fn test_cleanup() {
        let ocr = TesseractOcr::new();
        
        // Cleanup should always succeed
        let result = ocr.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn test_preprocess_image() {
        // Create a test image file
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("test.jpg");
        
        // Create an empty file
        let mut file = File::create(&image_path).unwrap();
        file.write_all(b"dummy image data").unwrap();
        
        // Test preprocessing
        let result = preprocess_image(&image_path);
        
        #[cfg(not(feature = "ocr"))]
        {
            // Without OCR feature, should return empty buffer
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }
        
        // We don't test actual preprocessing in unit tests
    }
} 