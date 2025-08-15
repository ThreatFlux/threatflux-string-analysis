//! String tracking and analysis functionality

use crate::analyzer::{DefaultStringAnalyzer, StringAnalyzer};
use crate::categorizer::{Categorizer, DefaultCategorizer};
use crate::patterns::{DefaultPatternProvider, PatternProvider};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

// Type aliases to reduce complexity
type StringCountVec = Vec<(String, usize)>;
type StringScoreVec = Vec<(String, f64)>;
type DateTimeRange = (DateTime<Utc>, DateTime<Utc>);
type StringEntryMap = Arc<Mutex<HashMap<String, StringEntry>>>;
type BoxedAnalyzer = Arc<Box<dyn StringAnalyzer>>;
type BoxedCategorizer = Arc<Box<dyn Categorizer>>;

/// Context in which a string was found
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringContext {
    /// String found in file content
    FileString {
        /// Byte offset within the file where the string was found
        offset: Option<usize>,
    },
    /// String found in import tables or dependencies
    Import {
        /// Name of the imported library or module
        library: String,
    },
    /// String found in export tables or exported symbols
    Export {
        /// Name of the exported symbol or function
        symbol: String,
    },
    /// String found in embedded resources
    Resource {
        /// Type of resource (icon, string table, etc.)
        resource_type: String,
    },
    /// String found in file sections
    Section {
        /// Name of the section where the string was found
        section_name: String,
    },
    /// String found in file metadata
    Metadata {
        /// Metadata field name where the string was found
        field: String,
    },
    /// String representing a file system path
    Path {
        /// Type of path (absolute, relative, UNC, etc.)
        path_type: String,
    },
    /// String representing a URL
    Url {
        /// URL protocol (http, https, ftp, etc.)
        protocol: Option<String>,
    },
    /// String found in Windows registry context
    Registry {
        /// Registry hive name (HKLM, HKCU, etc.)
        hive: Option<String>,
    },
    /// String found in command or script context
    Command {
        /// Type of command (shell, powershell, batch, etc.)
        command_type: String,
    },
    /// String found in other contexts
    Other {
        /// Category description for the context
        category: String,
    },
}

/// Record of a single string occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringOccurrence {
    /// Path to the file where the string was found
    pub file_path: String,
    /// Hash of the file where the string was found
    pub file_hash: String,
    /// Name of the tool that discovered this string
    pub tool_name: String,
    /// Timestamp when the string was discovered
    pub timestamp: DateTime<Utc>,
    /// Context in which the string was found
    pub context: StringContext,
}

/// Complete information about a tracked string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    /// The actual string value
    pub value: String,
    /// Timestamp when this string was first discovered
    pub first_seen: DateTime<Utc>,
    /// Timestamp when this string was last seen
    pub last_seen: DateTime<Utc>,
    /// Total number of times this string has been found
    pub total_occurrences: usize,
    /// Set of unique file paths where this string was found
    pub unique_files: HashSet<String>,
    /// Detailed records of each occurrence
    pub occurrences: Vec<StringOccurrence>,
    /// Set of categories this string belongs to
    pub categories: HashSet<String>,
    /// Whether this string is flagged as suspicious
    pub is_suspicious: bool,
    /// Shannon entropy score of the string
    pub entropy: f64,
}

/// Statistics about tracked strings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringStatistics {
    /// Total number of unique strings tracked
    pub total_unique_strings: usize,
    /// Total number of string occurrences across all files
    pub total_occurrences: usize,
    /// Total number of files that have been analyzed
    pub total_files_analyzed: usize,
    /// Most frequently occurring strings with their occurrence counts
    pub most_common: StringCountVec,
    /// List of strings flagged as suspicious
    pub suspicious_strings: Vec<String>,
    /// Strings with high entropy scores and their entropy values
    pub high_entropy_strings: StringScoreVec,
    /// Distribution of strings across different categories
    pub category_distribution: HashMap<String, usize>,
    /// Distribution of strings by length ranges
    pub length_distribution: HashMap<String, usize>,
}

/// Filter criteria for string queries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringFilter {
    /// Minimum number of occurrences a string must have
    pub min_occurrences: Option<usize>,
    /// Maximum number of occurrences a string can have
    pub max_occurrences: Option<usize>,
    /// Minimum length of strings to include
    pub min_length: Option<usize>,
    /// Maximum length of strings to include
    pub max_length: Option<usize>,
    /// Filter by specific categories
    pub categories: Option<Vec<String>>,
    /// Filter by specific file paths
    pub file_paths: Option<Vec<String>>,
    /// Filter by specific file hashes
    pub file_hashes: Option<Vec<String>>,
    /// If true, only return suspicious strings
    pub suspicious_only: Option<bool>,
    /// Regular expression pattern to match string values
    pub regex_pattern: Option<String>,
    /// Minimum entropy score for strings
    pub min_entropy: Option<f64>,
    /// Maximum entropy score for strings
    pub max_entropy: Option<f64>,
    /// Date range filter for when strings were discovered
    pub date_range: Option<DateTimeRange>,
}

/// Main string tracking system
#[derive(Clone)]
pub struct StringTracker {
    entries: StringEntryMap,
    analyzer: BoxedAnalyzer,
    categorizer: BoxedCategorizer,
    max_occurrences_per_string: usize,
}

impl Default for StringTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StringTracker {
    /// Create a new StringTracker with default analyzer and categorizer
    pub fn new() -> Self {
        let pattern_provider = DefaultPatternProvider::default();
        let analyzer = DefaultStringAnalyzer::new().with_patterns(pattern_provider.get_patterns());

        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            analyzer: Arc::new(Box::new(analyzer)),
            categorizer: Arc::new(Box::new(DefaultCategorizer::new())),
            max_occurrences_per_string: 1000,
        }
    }

    /// Create a StringTracker with custom analyzer and categorizer
    pub fn with_components(
        analyzer: Box<dyn StringAnalyzer>,
        categorizer: Box<dyn Categorizer>,
    ) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            analyzer: Arc::new(analyzer),
            categorizer: Arc::new(categorizer),
            max_occurrences_per_string: 1000,
        }
    }

    /// Set the maximum number of occurrences to track per string
    pub fn with_max_occurrences(mut self, max: usize) -> Self {
        self.max_occurrences_per_string = max;
        self
    }

    /// Track a string occurrence
    pub fn track_string(
        &self,
        value: &str,
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
        context: StringContext,
    ) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();

        let occurrence = StringOccurrence {
            file_path: file_path.to_string(),
            file_hash: file_hash.to_string(),
            tool_name: tool_name.to_string(),
            timestamp: Utc::now(),
            context: context.clone(),
        };

        // Get category from context
        let context_category = match &context {
            StringContext::FileString { .. } => "file_string",
            StringContext::Import { .. } => "import",
            StringContext::Export { .. } => "export",
            StringContext::Resource { .. } => "resource",
            StringContext::Section { .. } => "section",
            StringContext::Metadata { .. } => "metadata",
            StringContext::Path { .. } => "path",
            StringContext::Url { .. } => "url",
            StringContext::Registry { .. } => "registry",
            StringContext::Command { .. } => "command",
            StringContext::Other { category } => category,
        };

        let entry = entries.entry(value.to_string()).or_insert_with(|| {
            let analysis = self.analyzer.analyze(value);
            let categories = self.categorizer.categorize(value);

            let mut category_set =
                HashSet::with_capacity(categories.len() + analysis.categories.len() + 1);
            category_set.insert(context_category.to_string());
            for cat in categories {
                category_set.insert(cat.name);
            }
            category_set.extend(analysis.categories);

            let now = Utc::now();
            StringEntry {
                value: value.to_string(),
                first_seen: now,
                last_seen: now,
                total_occurrences: 0,
                unique_files: HashSet::new(),
                occurrences: Vec::new(),
                categories: category_set,
                is_suspicious: analysis.is_suspicious,
                entropy: analysis.entropy,
            }
        });

        entry.last_seen = Utc::now();
        entry.total_occurrences += 1;
        entry.unique_files.insert(file_path.to_string());
        entry.occurrences.push(occurrence);

        // Limit occurrences per string to prevent memory explosion
        if entry.occurrences.len() > self.max_occurrences_per_string {
            entry.occurrences.remove(0);
        }

        Ok(())
    }

    /// Track multiple strings from results
    pub fn track_strings_from_results(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> Result<()> {
        for string in strings {
            // Categorize the string using the categorizer
            let categories = self.categorizer.categorize(string);

            // Determine context based on categories
            let context = if categories.iter().any(|c| c.name == "url") {
                let protocol = string.split("://").next().map(|p| p.to_string());
                StringContext::Url { protocol }
            } else if categories.iter().any(|c| c.name == "path") {
                let path_type = if string.contains("\\Windows") || string.contains("/usr") {
                    "system"
                } else if string.contains("\\Temp") || string.contains("/tmp") {
                    "temp"
                } else {
                    "general"
                };
                StringContext::Path {
                    path_type: path_type.to_string(),
                }
            } else if categories.iter().any(|c| c.name == "registry") {
                let hive = string.split('\\').next().map(|h| h.to_string());
                StringContext::Registry { hive }
            } else if categories.iter().any(|c| c.name == "library") {
                StringContext::Import {
                    library: string.to_string(),
                }
            } else if categories.iter().any(|c| c.name == "command") {
                StringContext::Command {
                    command_type: "shell".to_string(),
                }
            } else {
                StringContext::FileString { offset: None }
            };

            self.track_string(string, file_path, file_hash, tool_name, context)?;
        }
        Ok(())
    }

    /// Get statistics about tracked strings
    pub fn get_statistics(&self, filter: Option<&StringFilter>) -> StringStatistics {
        let entries = self.entries.lock().unwrap();

        let filtered_entries: Vec<_> = entries
            .values()
            .filter(|entry| self.matches_filter(entry, filter))
            .collect();

        let total_unique_strings = filtered_entries.len();
        let total_occurrences: usize = filtered_entries.iter().map(|e| e.total_occurrences).sum();

        let total_files_analyzed: HashSet<_> = filtered_entries
            .iter()
            .flat_map(|e| e.unique_files.iter())
            .collect();

        // Most common strings
        let mut most_common: Vec<_> = filtered_entries
            .iter()
            .map(|e| (e.value.clone(), e.total_occurrences))
            .collect();
        most_common.sort_by(|a, b| b.1.cmp(&a.1));
        most_common.truncate(100);

        // Suspicious strings
        let suspicious_strings: Vec<_> = filtered_entries
            .iter()
            .filter(|e| e.is_suspicious)
            .map(|e| e.value.clone())
            .take(50)
            .collect();

        // High entropy strings
        let mut high_entropy_strings: Vec<_> = filtered_entries
            .iter()
            .filter(|e| e.entropy > 4.0)
            .map(|e| (e.value.clone(), e.entropy))
            .collect();
        high_entropy_strings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        high_entropy_strings.truncate(50);

        // Category distribution
        let mut category_distribution = HashMap::new();
        for entry in &filtered_entries {
            for category in &entry.categories {
                *category_distribution.entry(category.clone()).or_insert(0) += 1;
            }
        }

        // Length distribution
        let mut length_distribution = HashMap::new();
        for entry in &filtered_entries {
            let len_bucket = match entry.value.len() {
                0..=10 => "0-10",
                11..=20 => "11-20",
                21..=50 => "21-50",
                51..=100 => "51-100",
                101..=200 => "101-200",
                _ => "200+",
            };
            *length_distribution
                .entry(len_bucket.to_string())
                .or_insert(0) += 1;
        }

        StringStatistics {
            total_unique_strings,
            total_occurrences,
            total_files_analyzed: total_files_analyzed.len(),
            most_common,
            suspicious_strings,
            high_entropy_strings,
            category_distribution,
            length_distribution,
        }
    }

    fn matches_filter(&self, entry: &StringEntry, filter: Option<&StringFilter>) -> bool {
        let Some(f) = filter else {
            return true;
        };

        if let Some(min) = f.min_occurrences {
            if entry.total_occurrences < min {
                return false;
            }
        }

        if let Some(max) = f.max_occurrences {
            if entry.total_occurrences > max {
                return false;
            }
        }

        if let Some(min) = f.min_length {
            if entry.value.len() < min {
                return false;
            }
        }

        if let Some(max) = f.max_length {
            if entry.value.len() > max {
                return false;
            }
        }

        if let Some(ref categories) = f.categories {
            if !categories.iter().any(|c| entry.categories.contains(c)) {
                return false;
            }
        }

        if let Some(ref file_hashes) = f.file_hashes {
            if !file_hashes.iter().any(|h| entry.unique_files.contains(h)) {
                return false;
            }
        }

        if let Some(suspicious_only) = f.suspicious_only {
            if suspicious_only && !entry.is_suspicious {
                return false;
            }
        }

        if let Some(ref pattern) = f.regex_pattern {
            if let Ok(re) = regex::Regex::new(pattern) {
                if !re.is_match(&entry.value) {
                    return false;
                }
            }
        }

        if let Some(min_entropy) = f.min_entropy {
            if entry.entropy < min_entropy {
                return false;
            }
        }

        if let Some(max_entropy) = f.max_entropy {
            if entry.entropy > max_entropy {
                return false;
            }
        }

        true
    }

    /// Get detailed information about a specific string
    pub fn get_string_details(&self, value: &str) -> Option<StringEntry> {
        let entries = self.entries.lock().unwrap();
        entries.get(value).cloned()
    }

    /// Search for strings matching a query
    pub fn search_strings(&self, query: &str, limit: usize) -> Vec<StringEntry> {
        // Return empty results for empty queries
        if query.trim().is_empty() {
            return Vec::new();
        }

        let entries = self.entries.lock().unwrap();
        let query_lower = query.to_lowercase();

        let mut results: Vec<_> = entries
            .values()
            .filter(|e| e.value.to_lowercase().contains(&query_lower))
            .cloned()
            .collect();

        results.sort_by(|a, b| b.total_occurrences.cmp(&a.total_occurrences));
        results.truncate(limit);
        results
    }

    /// Get strings related to a given string
    pub fn get_related_strings(&self, value: &str, limit: usize) -> StringScoreVec {
        let entries = self.entries.lock().unwrap();

        let Some(target_entry) = entries.get(value) else {
            return vec![];
        };

        let mut similarities: Vec<_> = entries
            .iter()
            .filter(|(k, _)| *k != value)
            .map(|(k, v)| {
                let similarity = self.calculate_similarity(target_entry, v);
                (k.clone(), similarity)
            })
            .filter(|(_, sim)| *sim > 0.3)
            .collect();

        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        similarities.truncate(limit);
        similarities
    }

    fn calculate_similarity(&self, a: &StringEntry, b: &StringEntry) -> f64 {
        let mut score = 0.0;
        let mut factors = 0.0;

        // Shared files
        let shared_files: HashSet<_> = a.unique_files.intersection(&b.unique_files).collect();
        if !shared_files.is_empty() {
            score +=
                shared_files.len() as f64 / a.unique_files.len().min(b.unique_files.len()) as f64;
            factors += 1.0;
        }

        // Shared categories
        let shared_categories: HashSet<_> = a.categories.intersection(&b.categories).collect();
        if !shared_categories.is_empty() {
            score +=
                shared_categories.len() as f64 / a.categories.len().min(b.categories.len()) as f64;
            factors += 1.0;
        }

        // Similar entropy
        let entropy_diff = (a.entropy - b.entropy).abs();
        if entropy_diff < 0.5 {
            score += 1.0 - (entropy_diff / 0.5);
            factors += 1.0;
        }

        // Similar length
        let len_a = a.value.len() as f64;
        let len_b = b.value.len() as f64;
        let len_ratio = len_a.min(len_b) / len_a.max(len_b);
        score += len_ratio;
        factors += 1.0;

        if factors > 0.0 { score / factors } else { 0.0 }
    }

    /// Clear all tracked strings
    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear();
    }
}
