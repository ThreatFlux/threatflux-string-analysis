//! Shared configuration and error types.

use thiserror::Error;

/// Default entropy threshold used to emit a high-entropy indicator.
pub const DEFAULT_SUSPICIOUS_ENTROPY: f64 = 4.5;
/// Default number of detailed occurrences retained for each distinct value.
pub const DEFAULT_MAX_OCCURRENCES_PER_STRING: usize = 1_000;
/// Default number of distinct string values retained by a tracker.
pub const DEFAULT_MAX_UNIQUE_STRINGS: usize = 100_000;
/// Default maximum UTF-8 byte length of an analyzed value.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 1_048_576;
/// Default maximum UTF-8 byte length of each source or context field.
pub const DEFAULT_MAX_SOURCE_BYTES: usize = 16_384;
/// Default number of distinct file identities retained for each value.
pub const DEFAULT_MAX_UNIQUE_FILE_IDENTITIES_PER_STRING: usize = 1_024;
/// Default number of aggregate category names retained for each value.
pub const DEFAULT_MAX_CATEGORIES_PER_STRING: usize = 64;
/// Default number of suspicious indicators retained for each value.
pub const DEFAULT_MAX_INDICATORS_PER_STRING: usize = 64;

/// Configuration for analysis and bounded in-memory tracking.
///
/// Byte limits are measured using [`str::len`], so they refer to UTF-8 encoded
/// bytes rather than Unicode scalar values. Every limit is enforced before a
/// tracking mutation is applied.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    /// Entropy threshold at or above which a sufficiently long value is flagged.
    pub min_suspicious_entropy: f64,
    /// Maximum detailed occurrence records retained for one distinct value.
    pub max_occurrences_per_string: usize,
    /// Maximum number of distinct values retained by the tracker.
    pub max_unique_strings: usize,
    /// Maximum UTF-8 byte length of a value passed to the analyzer.
    pub max_input_bytes: usize,
    /// Maximum UTF-8 byte length of each source and context string field.
    pub max_source_bytes: usize,
    /// Maximum distinct `(file_path, file_hash)` pairs retained for one value.
    pub max_unique_file_identities_per_string: usize,
    /// Maximum aggregate category names retained for one value.
    pub max_categories_per_string: usize,
    /// Maximum suspicious indicators retained for one value.
    pub max_indicators_per_string: usize,
}

impl AnalysisConfig {
    /// Validate that all thresholds and limits are usable.
    pub fn validate(&self) -> AnalysisResult<()> {
        if !self.min_suspicious_entropy.is_finite()
            || !(0.0..=8.0).contains(&self.min_suspicious_entropy)
        {
            return Err(AnalysisError::InvalidConfiguration {
                field: "min_suspicious_entropy",
                reason: "must be finite and between 0 and 8 inclusive".to_string(),
            });
        }

        for (field, value) in [
            (
                "max_occurrences_per_string",
                self.max_occurrences_per_string,
            ),
            ("max_unique_strings", self.max_unique_strings),
            ("max_input_bytes", self.max_input_bytes),
            ("max_source_bytes", self.max_source_bytes),
            (
                "max_unique_file_identities_per_string",
                self.max_unique_file_identities_per_string,
            ),
            ("max_categories_per_string", self.max_categories_per_string),
            ("max_indicators_per_string", self.max_indicators_per_string),
        ] {
            if value == 0 {
                return Err(AnalysisError::InvalidConfiguration {
                    field,
                    reason: "must be greater than zero".to_string(),
                });
            }
        }

        Ok(())
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            min_suspicious_entropy: DEFAULT_SUSPICIOUS_ENTROPY,
            max_occurrences_per_string: DEFAULT_MAX_OCCURRENCES_PER_STRING,
            max_unique_strings: DEFAULT_MAX_UNIQUE_STRINGS,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
            max_unique_file_identities_per_string: DEFAULT_MAX_UNIQUE_FILE_IDENTITIES_PER_STRING,
            max_categories_per_string: DEFAULT_MAX_CATEGORIES_PER_STRING,
            max_indicators_per_string: DEFAULT_MAX_INDICATORS_PER_STRING,
        }
    }
}

/// Errors returned by validation, analysis configuration, and bounded tracking.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AnalysisError {
    /// A tracker or analyzer configuration value is invalid.
    #[error("invalid configuration `{field}`: {reason}")]
    InvalidConfiguration {
        /// Configuration field that failed validation.
        field: &'static str,
        /// Human-readable validation failure.
        reason: String,
    },

    /// A statistics filter is malformed or internally contradictory.
    #[error("invalid filter `{field}`: {reason}")]
    InvalidFilter {
        /// Filter field that failed validation.
        field: &'static str,
        /// Human-readable validation failure.
        reason: String,
    },

    /// A custom analyzer or categorizer returned data outside API invariants.
    #[error("invalid component output `{field}`: {reason}")]
    InvalidComponentOutput {
        /// Component output field that failed validation.
        field: &'static str,
        /// Human-readable validation failure.
        reason: String,
    },

    /// A caller-provided field exceeds its configured UTF-8 byte limit.
    #[error("`{field}` is {actual} bytes; configured maximum is {limit}")]
    InputTooLarge {
        /// Name of the oversized input field.
        field: &'static str,
        /// Actual UTF-8 byte length.
        actual: usize,
        /// Configured UTF-8 byte limit.
        limit: usize,
    },

    /// Adding a new retained item would exceed a configured collection limit.
    #[error("capacity exceeded for {resource}: configured maximum is {limit}")]
    CapacityExceeded {
        /// Bounded resource that reached capacity.
        resource: &'static str,
        /// Configured maximum number of items.
        limit: usize,
    },

    /// A pattern, rule, or category identifier is invalid.
    #[error("invalid {kind} identifier: {reason}")]
    InvalidIdentifier {
        /// Kind of identifier being validated.
        kind: &'static str,
        /// Invalid identifier value.
        name: String,
        /// Human-readable validation failure.
        reason: &'static str,
    },

    /// Suspicious indicator severity lies outside the documented 0-10 range.
    #[error("invalid severity {severity}; expected a value from 0 through 10")]
    InvalidSeverity {
        /// Invalid severity value.
        severity: u8,
    },

    /// A named pattern or category rule already exists.
    #[error("duplicate {kind} name")]
    DuplicateName {
        /// Kind of named object.
        kind: &'static str,
        /// Duplicate name.
        name: String,
    },

    /// A named pattern or category rule could not be found.
    #[error("{kind} was not found")]
    NotFound {
        /// Kind of named object.
        kind: &'static str,
        /// Missing name.
        name: String,
    },

    /// A regular expression could not be compiled.
    #[error("invalid regular expression for {context}: {reason}")]
    InvalidRegex {
        /// Static description of the pattern or filter being compiled.
        context: &'static str,
        /// Sanitized failure class that never contains the expression source.
        reason: &'static str,
    },
}

/// Result type for string analysis operations.
pub type AnalysisResult<T> = Result<T, AnalysisError>;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 256;
pub(crate) const MAX_DESCRIPTION_BYTES: usize = 4_096;
pub(crate) const MAX_REGEX_BYTES: usize = 65_536;

pub(crate) fn validate_identifier(kind: &'static str, value: &str) -> AnalysisResult<()> {
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(AnalysisError::InputTooLarge {
            field: kind,
            actual: value.len(),
            limit: MAX_IDENTIFIER_BYTES,
        });
    }

    let reason = if value.trim().is_empty() {
        Some("must not be empty or whitespace-only")
    } else if value.chars().any(char::is_control) {
        Some("must not contain control characters")
    } else {
        None
    };

    if let Some(reason) = reason {
        return Err(AnalysisError::InvalidIdentifier {
            kind,
            name: value.to_string(),
            reason,
        });
    }

    Ok(())
}

pub(crate) fn compact_string(value: String) -> String {
    value.into_boxed_str().into_string()
}

pub(crate) fn regex_error_reason(error: &regex::Error) -> &'static str {
    match error {
        regex::Error::Syntax(_) => "syntax error",
        regex::Error::CompiledTooBig(_) => "compiled expression exceeds the size limit",
        _ => "regular expression compilation failed",
    }
}
