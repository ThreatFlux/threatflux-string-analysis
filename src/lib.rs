#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod analyzer;
mod categorizer;
mod patterns;
mod tracker;
mod types;

pub use analyzer::{DefaultStringAnalyzer, StringAnalysis, StringAnalyzer, SuspiciousIndicator};
pub use categorizer::{
    Categorizer, CategoryMatcher, CategoryRule, DefaultCategorizer, StringCategory,
};
pub use patterns::{DefaultPatternProvider, Pattern, PatternDef, PatternProvider};
pub use tracker::{
    DateTimeRange, FileIdentity, StringContext, StringEntry, StringFilter, StringOccurrence,
    StringStatistics, StringTracker,
};
pub use types::{
    AnalysisConfig, AnalysisError, AnalysisResult, DEFAULT_MAX_CATEGORIES_PER_STRING,
    DEFAULT_MAX_INDICATORS_PER_STRING, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_OCCURRENCES_PER_STRING,
    DEFAULT_MAX_SOURCE_BYTES, DEFAULT_MAX_UNIQUE_FILE_IDENTITIES_PER_STRING,
    DEFAULT_MAX_UNIQUE_STRINGS, DEFAULT_SUSPICIOUS_ENTROPY,
};

/// Version of the crate selected at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
