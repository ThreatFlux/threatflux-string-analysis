//! String analysis functionality

use crate::patterns::Pattern;
use crate::types::{AnalysisResult, StringMetadata};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents a suspicious indicator found in a string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousIndicator {
    /// The pattern that matched
    pub pattern_name: String,
    /// Description of why this is suspicious
    pub description: String,
    /// Severity level (0-10)
    pub severity: u8,
    /// The specific match within the string
    pub matched_text: Option<String>,
}

/// Result of analyzing a string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringAnalysis {
    /// Shannon entropy of the string
    pub entropy: f64,
    /// Categories the string belongs to
    pub categories: HashSet<String>,
    /// Suspicious indicators found
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    /// Additional metadata
    pub metadata: StringMetadata,
    /// Whether the string is considered suspicious overall
    pub is_suspicious: bool,
}

/// Trait for analyzing strings
pub trait StringAnalyzer: Send + Sync {
    /// Analyze a string and return analysis results
    fn analyze(&self, value: &str) -> StringAnalysis;

    /// Check if a string is suspicious
    fn is_suspicious(&self, value: &str) -> bool {
        self.analyze(value).is_suspicious
    }

    /// Calculate entropy of a string
    fn calculate_entropy(&self, value: &str) -> f64;

    /// Get the patterns used by this analyzer
    fn get_patterns(&self) -> &[Pattern];

    /// Add a custom pattern
    fn add_pattern(&mut self, pattern: Pattern) -> AnalysisResult<()>;
}

/// Default implementation of StringAnalyzer
pub struct DefaultStringAnalyzer {
    patterns: Vec<Pattern>,
    entropy_threshold: f64,
}

impl DefaultStringAnalyzer {
    /// Create a new analyzer with default settings
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            entropy_threshold: 4.5,
        }
    }

    /// Set the entropy threshold for suspicious detection
    #[allow(dead_code)]
    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    /// Add patterns to the analyzer
    pub fn with_patterns(mut self, patterns: Vec<Pattern>) -> Self {
        self.patterns = patterns;
        self
    }
}

impl StringAnalyzer for DefaultStringAnalyzer {
    fn analyze(&self, value: &str) -> StringAnalysis {
        let entropy = self.calculate_entropy(value);
        let mut suspicious_indicators = Vec::new();
        let mut categories = HashSet::new();

        // Check against patterns
        for pattern in &self.patterns {
            if pattern.regex.is_match(value) {
                if pattern.is_suspicious {
                    suspicious_indicators.push(SuspiciousIndicator {
                        pattern_name: pattern.name.clone(),
                        description: pattern.description.clone(),
                        severity: pattern.severity,
                        matched_text: pattern.regex.find(value).map(|m| m.as_str().to_string()),
                    });
                }
                categories.insert(pattern.category.clone());
            }
        }

        // Check entropy
        let high_entropy = entropy > self.entropy_threshold && value.len() > 10;
        if high_entropy {
            suspicious_indicators.push(SuspiciousIndicator {
                pattern_name: "high_entropy".to_string(),
                description: format!(
                    "High entropy ({:.2}) indicates possible encoding/encryption",
                    entropy
                ),
                severity: 6,
                matched_text: None,
            });
        }

        // Check for non-printable characters
        let has_non_printable = value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t');
        if has_non_printable {
            suspicious_indicators.push(SuspiciousIndicator {
                pattern_name: "non_printable_chars".to_string(),
                description: "Contains non-printable characters".to_string(),
                severity: 5,
                matched_text: None,
            });
        }

        let is_suspicious = !suspicious_indicators.is_empty();

        StringAnalysis {
            entropy,
            categories,
            suspicious_indicators,
            metadata: HashMap::new(),
            is_suspicious,
        }
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut char_counts = HashMap::new();
        for ch in s.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in char_counts.values() {
            let probability = *count as f64 / len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn get_patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    fn add_pattern(&mut self, pattern: Pattern) -> AnalysisResult<()> {
        self.patterns.push(pattern);
        Ok(())
    }
}

impl Default for DefaultStringAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
