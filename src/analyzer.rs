//! String analysis functionality.

use crate::patterns::{MAX_PATTERNS, Pattern};
use crate::types::{
    AnalysisError, AnalysisResult, DEFAULT_MAX_INDICATORS_PER_STRING, DEFAULT_SUSPICIOUS_ENTROPY,
};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::BTreeSet;

pub(crate) const MIN_ENTROPY_INPUT_BYTES: usize = 12;
const MAX_MATCHED_TEXT_BYTES: usize = 512;

/// Explainable evidence that contributed to a suspicious result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspiciousIndicator {
    /// Stable name of the matching pattern or built-in heuristic.
    pub pattern_name: String,
    /// Human-readable explanation of the indicator.
    pub description: String,
    /// Severity from 0 through 10.
    pub severity: u8,
    /// Bounded excerpt of the first match, when applicable.
    pub matched_text: Option<String>,
    /// Whether `matched_text` was shortened to the evidence byte limit.
    pub matched_text_truncated: bool,
}

/// Result of analyzing one string value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringAnalysis {
    /// Shannon entropy calculated over UTF-8 bytes.
    pub entropy: f64,
    /// Deterministically ordered categories assigned by matching patterns.
    pub categories: BTreeSet<String>,
    /// Bounded suspicious evidence retained in pattern evaluation order.
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    /// Whether suspicious evidence was omitted or declared without retained detail.
    pub indicators_truncated: bool,
    /// Whether at least one suspicious signal was retained, omitted, or declared.
    pub is_suspicious: bool,
}

/// Interface for deterministic, thread-safe string analyzers.
pub trait StringAnalyzer: Send + Sync {
    /// Analyze a string and return categories and suspicious evidence.
    fn analyze(&self, value: &str) -> StringAnalysis;

    /// Check whether analysis emits any suspicious evidence.
    fn is_suspicious(&self, value: &str) -> bool {
        self.analyze(value).is_suspicious
    }

    /// Calculate Shannon entropy over the value's UTF-8 bytes.
    fn calculate_entropy(&self, value: &str) -> f64;

    /// Return patterns in evaluation order.
    fn get_patterns(&self) -> &[Pattern];

    /// Validate and append a uniquely named compiled pattern.
    fn add_pattern(&mut self, pattern: Pattern) -> AnalysisResult<()>;
}

/// Default byte-entropy and regex-based analyzer.
pub struct DefaultStringAnalyzer {
    patterns: Vec<Pattern>,
    entropy_threshold: f64,
    max_indicators: usize,
}

impl DefaultStringAnalyzer {
    /// Create an analyzer without custom or built-in patterns.
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            entropy_threshold: DEFAULT_SUSPICIOUS_ENTROPY,
            max_indicators: DEFAULT_MAX_INDICATORS_PER_STRING,
        }
    }

    /// Set and validate the high-entropy threshold.
    pub fn with_entropy_threshold(mut self, threshold: f64) -> AnalysisResult<Self> {
        validate_entropy_threshold(threshold)?;
        self.entropy_threshold = threshold;
        Ok(self)
    }

    /// Set and validate the suspicious evidence limit.
    pub fn with_max_indicators(mut self, max_indicators: usize) -> AnalysisResult<Self> {
        if max_indicators == 0 {
            return Err(AnalysisError::InvalidConfiguration {
                field: "max_indicators_per_string",
                reason: "must be greater than zero".to_string(),
            });
        }
        self.max_indicators = max_indicators;
        Ok(self)
    }

    /// Replace the current pattern set after validating names and limits.
    pub fn with_patterns(mut self, patterns: Vec<Pattern>) -> AnalysisResult<Self> {
        if patterns.len() > MAX_PATTERNS {
            return Err(AnalysisError::CapacityExceeded {
                resource: "analyzer patterns",
                limit: MAX_PATTERNS,
            });
        }

        let mut names = BTreeSet::new();
        for pattern in &patterns {
            pattern.validate()?;
            if !names.insert(pattern.name.clone()) {
                return Err(AnalysisError::DuplicateName {
                    kind: "pattern",
                    name: pattern.name.to_string(),
                });
            }
        }
        self.patterns = patterns.into_iter().map(Pattern::compact).collect();
        Ok(self)
    }
}

impl StringAnalyzer for DefaultStringAnalyzer {
    fn analyze(&self, value: &str) -> StringAnalysis {
        let entropy = self.calculate_entropy(value);
        let mut retained_indicators = Vec::new();
        let mut categories = BTreeSet::new();
        let mut indicators_truncated = false;
        let mut indicator_order = 0usize;

        for pattern in &self.patterns {
            let Some(matched) = pattern.regex.find(value) else {
                continue;
            };
            categories.insert(pattern.category.clone());
            if pattern.is_suspicious {
                let (matched_text, matched_text_truncated) = bounded_excerpt(matched.as_str());
                retain_indicator(
                    &mut retained_indicators,
                    &mut indicators_truncated,
                    self.max_indicators,
                    indicator_order,
                    SuspiciousIndicator {
                        pattern_name: pattern.name.clone(),
                        description: pattern.description.clone(),
                        severity: pattern.severity,
                        matched_text: Some(matched_text),
                        matched_text_truncated,
                    },
                );
                indicator_order = indicator_order.saturating_add(1);
            }
        }

        if entropy >= self.entropy_threshold && value.len() >= MIN_ENTROPY_INPUT_BYTES {
            retain_indicator(
                &mut retained_indicators,
                &mut indicators_truncated,
                self.max_indicators,
                indicator_order,
                SuspiciousIndicator {
                    pattern_name: "high_entropy".to_string(),
                    description: format!(
                        "Byte entropy {entropy:.2} meets the configured {threshold:.2} threshold",
                        threshold = self.entropy_threshold,
                    ),
                    severity: 6,
                    matched_text: None,
                    matched_text_truncated: false,
                },
            );
            indicator_order = indicator_order.saturating_add(1);
        }

        if value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            retain_indicator(
                &mut retained_indicators,
                &mut indicators_truncated,
                self.max_indicators,
                indicator_order,
                SuspiciousIndicator {
                    pattern_name: "non_printable_characters".to_string(),
                    description: "Contains control characters other than tab or line breaks"
                        .to_string(),
                    severity: 5,
                    matched_text: None,
                    matched_text_truncated: false,
                },
            );
        }

        retained_indicators.sort_by_key(|ranked| ranked.order);
        let suspicious_indicators: Vec<_> = retained_indicators
            .into_iter()
            .map(|ranked| ranked.indicator)
            .collect();
        let is_suspicious = !suspicious_indicators.is_empty() || indicators_truncated;
        StringAnalysis {
            entropy,
            categories,
            suspicious_indicators,
            indicators_truncated,
            is_suspicious,
        }
    }

    fn calculate_entropy(&self, value: &str) -> f64 {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return 0.0;
        }

        let mut byte_counts = [0usize; 256];
        for &byte in bytes {
            byte_counts[usize::from(byte)] = byte_counts[usize::from(byte)].saturating_add(1);
        }

        let length = bytes.len() as f64;
        byte_counts
            .into_iter()
            .filter(|count| *count != 0)
            .fold(0.0, |entropy, count| {
                let probability = count as f64 / length;
                entropy - probability * probability.log2()
            })
    }

    fn get_patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    fn add_pattern(&mut self, pattern: Pattern) -> AnalysisResult<()> {
        pattern.validate()?;
        if self.patterns.len() >= MAX_PATTERNS {
            return Err(AnalysisError::CapacityExceeded {
                resource: "analyzer patterns",
                limit: MAX_PATTERNS,
            });
        }
        if self
            .patterns
            .iter()
            .any(|existing| existing.name == pattern.name)
        {
            return Err(AnalysisError::DuplicateName {
                kind: "pattern",
                name: pattern.name.to_string(),
            });
        }
        self.patterns.push(pattern.compact());
        Ok(())
    }
}

impl Default for DefaultStringAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_entropy_threshold(threshold: f64) -> AnalysisResult<()> {
    if threshold.is_finite() && (0.0..=8.0).contains(&threshold) {
        Ok(())
    } else {
        Err(AnalysisError::InvalidConfiguration {
            field: "min_suspicious_entropy",
            reason: "must be finite and between 0 and 8 inclusive".to_string(),
        })
    }
}

struct RankedIndicator {
    order: usize,
    indicator: SuspiciousIndicator,
}

fn retain_indicator(
    indicators: &mut Vec<RankedIndicator>,
    truncated: &mut bool,
    limit: usize,
    order: usize,
    indicator: SuspiciousIndicator,
) {
    if indicators.len() < limit {
        indicators.push(RankedIndicator { order, indicator });
        return;
    }

    *truncated = true;
    let Some((lowest_index, lowest)) = indicators
        .iter()
        .enumerate()
        .min_by_key(|(_, ranked)| (ranked.indicator.severity, Reverse(ranked.order)))
    else {
        return;
    };
    if indicator.severity > lowest.indicator.severity {
        indicators[lowest_index] = RankedIndicator { order, indicator };
    }
}

fn bounded_excerpt(value: &str) -> (String, bool) {
    if value.len() <= MAX_MATCHED_TEXT_BYTES {
        return (value.to_string(), false);
    }

    let mut end = MAX_MATCHED_TEXT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}
