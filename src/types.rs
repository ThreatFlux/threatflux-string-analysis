//! Core types used throughout the library

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for the string analysis system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Minimum entropy threshold for suspicious detection
    pub min_suspicious_entropy: f64,
    /// Maximum number of occurrences to track per string
    pub max_occurrences_per_string: usize,
    /// Enable time-based analysis features
    pub enable_time_analysis: bool,
    /// Custom metadata fields to track
    pub custom_metadata_fields: Vec<String>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            min_suspicious_entropy: 4.5,
            max_occurrences_per_string: 1000,
            enable_time_analysis: true,
            custom_metadata_fields: Vec::new(),
        }
    }
}

/// Result type for string analysis operations
pub type AnalysisResult<T> = anyhow::Result<T>;

/// Metadata that can be attached to strings
pub type StringMetadata = HashMap<String, serde_json::Value>;
