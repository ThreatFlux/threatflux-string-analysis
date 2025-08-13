//! # ThreatFlux String Analysis
//!
//! A comprehensive string analysis library for security applications, providing
//! advanced categorization, entropy analysis, and pattern detection capabilities.
//!
//! ## Features
//!
//! - **String Tracking**: Track string occurrences across multiple files with context
//! - **Automatic Categorization**: Identify URLs, paths, commands, registry keys, etc.
//! - **Entropy Analysis**: Detect potentially encoded or encrypted strings
//! - **Suspicious Pattern Detection**: Built-in patterns for malware and threat indicators
//! - **Statistical Analysis**: Generate insights about string distributions and relationships
//! - **Extensible Architecture**: Add custom patterns and categorization rules
//!
//! ## Quick Start
//!
//! ```rust
//! use threatflux_string_analysis::{StringTracker, StringContext};
//!
//! # fn main() -> anyhow::Result<()> {
//! let tracker = StringTracker::new();
//!
//! // Track a string
//! tracker.track_string(
//!     "http://suspicious.com/malware.exe",
//!     "/path/to/file.bin",
//!     "file_hash_123",
//!     "my_scanner",
//!     StringContext::FileString { offset: Some(1024) }
//! )?;
//!
//! // Get statistics
//! let stats = tracker.get_statistics(None);
//! println!("Suspicious strings found: {}", stats.suspicious_strings.len());
//! # Ok(())
//! # }
//! ```

mod analyzer;
mod categorizer;
mod patterns;
mod tracker;
mod types;

// Re-export main types
pub use analyzer::{DefaultStringAnalyzer, StringAnalysis, StringAnalyzer, SuspiciousIndicator};
pub use categorizer::{Categorizer, CategoryRule, DefaultCategorizer, StringCategory};
pub use patterns::{DefaultPatternProvider, Pattern, PatternDef, PatternProvider};
pub use tracker::{
    StringContext, StringEntry, StringFilter, StringOccurrence, StringStatistics, StringTracker,
};
pub use types::*;

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
