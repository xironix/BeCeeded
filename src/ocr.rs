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
    
    /// Process image data from a buffer rather than a file
    fn process_image_data(&self, image_data: &[u8], format_hint: Option<&str>) -> Result<String>;
    
    /// Clean up resources
    fn cleanup(&self) -> Result<()>;
}

/// Tesseract OCR engine implementation
#[cfg(feature = "ocr")]
#[derive(Default)]
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
        Self::default()
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
#[derive(Default)]
pub struct TesseractOcr {
    initialized: bool,
    options: Option<OcrOptions>,
}

/// Fallback implementation for when OCR feature is disabled
#[cfg(not(feature = "ocr"))]
impl TesseractOcr {
    /// Create a new TesseractOcr engine
    pub fn new() -> Self {
        Self::default()
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
        
        debug!("Processing image: {}", image_path.display());
        
        // Load the image
        let img = image::open(image_path)
            .map_err(|e| ScannerError::OcrError(format!("Failed to open image: {}", e)))?;
        
        // Use the shared implementation for processing image data
        self.process_image_impl(img)
    }
    
    fn process_image_data(&self, image_data: &[u8], format_hint: Option<&str>) -> Result<String> {
        // Check if initialized
        if !self.initialized || self.tess.is_none() {
            return Err(ScannerError::OcrError("OCR engine not initialized".to_string()));
        }
        
        debug!("Processing image data: {} bytes", image_data.len());
        
        // Determine image format
        let format = match format_hint {
            Some("jpg") | Some("jpeg") => image::ImageFormat::Jpeg,
            Some("png") => image::ImageFormat::Png,
            Some("gif") => image::ImageFormat::Gif,
            Some("bmp") => image::ImageFormat::Bmp,
            Some("tiff") => image::ImageFormat::Tiff,
            _ => {
                // Try to guess the format from the bytes
                image::guess_format(image_data)
                    .map_err(|e| ScannerError::OcrError(format!("Failed to determine image format: {}", e)))?
            }
        };
        
        // Load the image from memory
        let img = image::load_from_memory_with_format(image_data, format)
            .map_err(|e| ScannerError::OcrError(format!("Failed to load image from memory: {}", e)))?;
        
        // Use the shared implementation for processing image data
        self.process_image_impl(img)
    }
    
    fn cleanup(&self) -> Result<()> {
        debug!("Cleaning up Tesseract OCR engine");
        // Tesseract resources are cleaned up automatically when dropped
        Ok(())
    }
}

#[cfg(feature = "ocr")]
impl TesseractOcr {
    // Common implementation for processing an image after it's loaded
    fn process_image_impl(&self, img: image::DynamicImage) -> Result<String> {
        let options = self.options.as_ref().unwrap();
        let tess = self.tess.as_ref().unwrap();
        
        // Preprocess the image if enabled
        let img = if options.preprocessing {
            debug!("Preprocessing image for better OCR results");
            preprocess_image_data(img)
        } else {
            img
        };
        
        // Try multiple scaling factors for better text recognition
        let scaling_factors = [1.0, 1.5, 2.0, 0.75, 0.5];
        let mut best_text = String::new();
        let mut best_confidence = 0.0;
        
        for &scale in &scaling_factors {
            if scale != 1.0 {
                debug!("Trying image scale factor: {}", scale);
            }
            
            // Scale the image if needed
            let scaled_img = if (scale - 1.0).abs() > 0.01 {
                let width = (img.width() as f32 * scale) as u32;
                let height = (img.height() as f32 * scale) as u32;
                img.resize(width, height, image::imageops::FilterType::Lanczos3)
            } else {
                img.clone()
            };
            
            // Convert image to PIX format for Tesseract
            let pix = match leptess::leptonica::pix_from_image(&scaled_img) {
                Ok(pix) => pix,
                Err(e) => {
                    warn!("Failed to convert image at scale {}: {}", scale, e);
                    continue;
                }
            };
            
            // Set the image for OCR
            let mut tess_clone = tess.clone(); // We need a mutable copy
            if let Err(e) = tess_clone.set_image(&pix) {
                warn!("Failed to set image at scale {}: {}", scale, e);
                continue;
            }
            
            // Perform OCR
            let text = match tess_clone.get_utf8_text() {
                Ok(text) => text,
                Err(e) => {
                    warn!("Failed to perform OCR at scale {}: {}", scale, e);
                    continue;
                }
            };
            
            // Get mean confidence
            let confidence = tess_clone.mean_text_conf() as f64 / 100.0;
            debug!("OCR at scale {} completed: {} characters, confidence {:.2}", 
                   scale, text.len(), confidence);
            
            // Keep the result with the highest confidence
            if confidence > best_confidence && !text.trim().is_empty() {
                best_confidence = confidence;
                best_text = text;
            }
        }
        
        // If we found text with reasonable confidence
        if best_confidence >= options.confidence_threshold as f64 / 100.0 {
            debug!("Final OCR result: {} characters with confidence {:.2}", 
                   best_text.len(), best_confidence);
            Ok(best_text)
        } else if !best_text.is_empty() {
            // We have text but confidence is below threshold
            debug!("OCR confidence too low: {:.2} < {:.2}", 
                   best_confidence, options.confidence_threshold as f64 / 100.0);
            Ok(best_text) // Return the text anyway, let the caller decide
        } else {
            debug!("No text extracted from image");
            Ok(String::new())
        }
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
        // For tests, we need to check if the instance is properly initialized 
        // and return a specific error message to help the test assertion
        if !self.initialized {
            return Err(ScannerError::OcrError("OCR engine not initialized".to_string()));
        }
        
        warn!("OCR support not enabled. Cannot process image: {}", image_path.display());
        Err(ScannerError::OcrError("OCR support not enabled".to_string()))
    }
    
    fn process_image_data(&self, image_data: &[u8], format_hint: Option<&str>) -> Result<String> {
        // Check if initialized
        if !self.initialized {
            return Err(ScannerError::OcrError("OCR engine not initialized".to_string()));
        }
        
        warn!("OCR support not enabled. Cannot process image data: {} bytes", image_data.len());
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
    use imageproc::{contrast, filter, noise, morphology};
    
    // Convert to grayscale
    let mut gray_img = img.grayscale();
    
    // Take advantage of image dimension to decide the optimal approach
    let (width, height) = gray_img.dimensions();
    let is_small_image = width < 800 || height < 800;
    
    // Get the luma8 image for processing
    let mut luma_img = gray_img.to_luma8();
    
    // Apply some initial denoising only for larger images that might have noise
    if !is_small_image {
        // Gentle Gaussian blur to remove noise
        luma_img = filter::gaussian_blur_f32(&luma_img, 0.75);
    }
    
    // Apply contrast enhancement
    luma_img = contrast::stretch_contrast(&luma_img, 20, 230);
    
    if is_small_image {
        // For small images, simple binary threshold often works better
        // Apply binary threshold at a good point for text
        luma_img = contrast::threshold(&luma_img, 150);
    } else {
        // For larger or more complex images, adaptive threshold usually works better
        luma_img = contrast::adaptive_threshold(&luma_img, 15);
        
        // Apply morphological operations to enhance text connection
        // Useful for broken characters in scanned documents or photos
        let kernel = morphology::rect_kernel(2, 1);
        luma_img = morphology::close(&luma_img, &kernel);
    }
    
    // Convert back to DynamicImage
    DynamicImage::ImageLuma8(luma_img)
}

/// Preprocess an image file for better OCR results
pub fn preprocess_image(image_path: &Path) -> Result<Vec<u8>> {
    #[cfg(feature = "ocr")]
    {
        debug!("Preprocessing image: {}", image_path.display());
        
        // Check if file exists and is readable
        if !image_path.exists() {
            return Err(ScannerError::OcrError(format!(
                "Image file does not exist: {}", image_path.display()
            )));
        }
        
        if !image_path.is_file() {
            return Err(ScannerError::OcrError(format!(
                "Path is not a file: {}", image_path.display()
            )));
        }
        
        // Get the file extension for debugging
        let extension = image_path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| "unknown".into());
        
        debug!("Processing image of type: {}", extension);
        
        // Load the image
        let img = image::open(image_path)
            .map_err(|e| ScannerError::OcrError(format!(
                "Failed to open image {}: {}", image_path.display(), e
            )))?;
        
        // Get original dimensions for logging
        let (width, height) = img.dimensions();
        debug!("Original image dimensions: {}x{}", width, height);
        
        // Preprocess the image
        let processed = preprocess_image_data(img);
        
        // Get processed dimensions
        let (proc_width, proc_height) = processed.dimensions();
        debug!("Processed image dimensions: {}x{}", proc_width, proc_height);
        
        // Create a buffer to hold the processed image
        let mut buffer = Vec::new();
        
        // Write the image to the buffer
        processed.write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageOutputFormat::Png)
            .map_err(|e| ScannerError::OcrError(format!(
                "Failed to encode processed image: {}", e
            )))?;
        
        debug!("Image preprocessing completed: {} bytes", buffer.len());
        Ok(buffer)
    }
    
    #[cfg(not(feature = "ocr"))]
    {
        warn!("Image preprocessing not available without OCR feature enabled");
        Ok(Vec::new())
    }
}

/// Preprocess image data from a buffer
pub fn preprocess_image_data_from_buffer(image_data: &[u8], format_hint: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "ocr")]
    {
        debug!("Preprocessing image data: {} bytes", image_data.len());
        
        // Determine image format
        let format = match format_hint {
            Some("jpg") | Some("jpeg") => image::ImageFormat::Jpeg,
            Some("png") => image::ImageFormat::Png,
            Some("gif") => image::ImageFormat::Gif,
            Some("bmp") => image::ImageFormat::Bmp,
            Some("tiff") => image::ImageFormat::Tiff,
            _ => {
                // Try to guess the format from the bytes
                image::guess_format(image_data)
                    .map_err(|e| ScannerError::OcrError(format!(
                        "Failed to determine image format: {}", e
                    )))?
            }
        };
        
        debug!("Detected image format: {:?}", format);
        
        // Load the image from memory
        let img = image::load_from_memory_with_format(image_data, format)
            .map_err(|e| ScannerError::OcrError(format!(
                "Failed to load image from memory: {}", e
            )))?;
        
        // Get original dimensions for logging
        let (width, height) = img.dimensions();
        debug!("Original image dimensions: {}x{}", width, height);
        
        // Preprocess the image
        let processed = preprocess_image_data(img);
        
        // Get processed dimensions
        let (proc_width, proc_height) = processed.dimensions();
        debug!("Processed image dimensions: {}x{}", proc_width, proc_height);
        
        // Create a buffer to hold the processed image
        let mut buffer = Vec::new();
        
        // Write the image to the buffer
        processed.write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageOutputFormat::Png)
            .map_err(|e| ScannerError::OcrError(format!(
                "Failed to encode processed image: {}", e
            )))?;
        
        debug!("Image preprocessing completed: {} bytes", buffer.len());
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
    // PathBuf is imported but unused
    // use std::path::PathBuf;
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