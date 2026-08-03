//! Bounded, concurrent string tracking and aggregate analysis.

use crate::analyzer::{
    DefaultStringAnalyzer, MIN_ENTROPY_INPUT_BYTES, StringAnalysis, StringAnalyzer,
    SuspiciousIndicator,
};
use crate::categorizer::{Categorizer, DefaultCategorizer, StringCategory, validate_category};
use crate::patterns::{DefaultPatternProvider, PatternProvider};
use crate::types::{
    AnalysisConfig, AnalysisError, AnalysisResult, MAX_DESCRIPTION_BYTES, MAX_REGEX_BYTES,
    compact_string, regex_error_reason, validate_identifier,
};
use chrono::{DateTime, Utc};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

const MOST_COMMON_LIMIT: usize = 100;
const SUSPICIOUS_SAMPLE_LIMIT: usize = 50;
const HIGH_ENTROPY_SAMPLE_LIMIT: usize = 50;
const FILTER_REGEX_COMPILED_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const FILTER_REGEX_DFA_SIZE_LIMIT: usize = 4 * 1024 * 1024;
const INDICATOR_MATCHED_TEXT_LIMIT: usize = 512;
const MIN_RELATED_SCORE: f64 = 0.30;

type StringEntryMap = Arc<Mutex<BTreeMap<String, StringEntry>>>;

/// Inclusive range applied to an entry's `first_seen` timestamp.
pub type DateTimeRange = (DateTime<Utc>, DateTime<Utc>);

/// Context in which a string was observed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum StringContext {
    /// String found in file content.
    FileString {
        /// Byte offset within the source file.
        offset: Option<u64>,
    },
    /// String found in an import table or dependency list.
    Import {
        /// Imported library or module.
        library: String,
    },
    /// String found in an export table.
    Export {
        /// Exported symbol or function.
        symbol: String,
    },
    /// String found in an embedded resource.
    Resource {
        /// Resource type.
        resource_type: String,
    },
    /// String found in a file section.
    Section {
        /// Section name.
        section_name: String,
    },
    /// String found in file metadata.
    Metadata {
        /// Metadata field name.
        field: String,
    },
    /// String representing a file-system path.
    Path {
        /// Application-defined path classification.
        path_type: String,
    },
    /// String representing a URL.
    Url {
        /// URL protocol, when known.
        protocol: Option<String>,
    },
    /// String representing a Windows registry key.
    Registry {
        /// Registry hive, when known.
        hive: Option<String>,
    },
    /// String representing a command or script.
    Command {
        /// Application-defined command classification.
        command_type: String,
    },
    /// Application-defined context.
    Other {
        /// Category name added to the aggregate entry.
        category: String,
    },
}

impl StringContext {
    fn category_name(&self) -> &str {
        match self {
            Self::FileString { .. } => "file_string",
            Self::Import { .. } => "import",
            Self::Export { .. } => "export",
            Self::Resource { .. } => "resource",
            Self::Section { .. } => "section",
            Self::Metadata { .. } => "metadata",
            Self::Path { .. } => "path",
            Self::Url { .. } => "url",
            Self::Registry { .. } => "registry",
            Self::Command { .. } => "command",
            Self::Other { category } => category,
        }
    }

    fn owned_field(&self) -> Option<(&'static str, &str)> {
        match self {
            Self::FileString { .. } => None,
            Self::Import { library } => Some(("context.import.library", library)),
            Self::Export { symbol } => Some(("context.export.symbol", symbol)),
            Self::Resource { resource_type } => {
                Some(("context.resource.resource_type", resource_type))
            }
            Self::Section { section_name } => Some(("context.section.section_name", section_name)),
            Self::Metadata { field } => Some(("context.metadata.field", field)),
            Self::Path { path_type } => Some(("context.path.path_type", path_type)),
            Self::Url { protocol } => protocol
                .as_deref()
                .map(|value| ("context.url.protocol", value)),
            Self::Registry { hive } => hive
                .as_deref()
                .map(|value| ("context.registry.hive", value)),
            Self::Command { command_type } => Some(("context.command.command_type", command_type)),
            Self::Other { category } => Some(("context.other.category", category)),
        }
    }

    fn compact(&mut self) {
        match self {
            Self::FileString { .. } => {}
            Self::Import { library } => compact_in_place(library),
            Self::Export { symbol } => compact_in_place(symbol),
            Self::Resource { resource_type } => compact_in_place(resource_type),
            Self::Section { section_name } => compact_in_place(section_name),
            Self::Metadata { field } => compact_in_place(field),
            Self::Path { path_type } => compact_in_place(path_type),
            Self::Url { protocol } => {
                if let Some(protocol) = protocol {
                    compact_in_place(protocol);
                }
            }
            Self::Registry { hive } => {
                if let Some(hive) = hive {
                    compact_in_place(hive);
                }
            }
            Self::Command { command_type } => compact_in_place(command_type),
            Self::Other { category } => compact_in_place(category),
        }
    }
}

/// Stable identity of a source file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    /// Source path supplied by the caller.
    pub file_path: String,
    /// Source content hash or other caller-defined stable identifier.
    pub file_hash: String,
}

/// Record of one string occurrence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringOccurrence {
    /// Path to the source file.
    pub file_path: String,
    /// Hash or stable identity of the source file.
    pub file_hash: String,
    /// Tool that produced the observation.
    pub tool_name: String,
    /// Caller-supplied event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Context in which the value was observed.
    pub context: StringContext,
}

impl StringOccurrence {
    /// Construct an occurrence with an explicit event timestamp.
    pub fn new(
        file_path: impl Into<String>,
        file_hash: impl Into<String>,
        tool_name: impl Into<String>,
        timestamp: DateTime<Utc>,
        context: StringContext,
    ) -> Self {
        let mut context = context;
        context.compact();
        Self {
            file_path: compact_string(file_path.into()),
            file_hash: compact_string(file_hash.into()),
            tool_name: compact_string(tool_name.into()),
            timestamp,
            context,
        }
    }

    fn file_identity(&self) -> FileIdentity {
        FileIdentity {
            file_path: self.file_path.as_str().to_string(),
            file_hash: self.file_hash.as_str().to_string(),
        }
    }

    fn compact(&mut self) {
        compact_in_place(&mut self.file_path);
        compact_in_place(&mut self.file_hash);
        compact_in_place(&mut self.tool_name);
        self.context.compact();
    }
}

/// Aggregate information retained for one distinct string value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringEntry {
    /// Actual string value.
    pub value: String,
    /// Earliest caller-supplied event timestamp.
    pub first_seen: DateTime<Utc>,
    /// Latest caller-supplied event timestamp.
    pub last_seen: DateTime<Utc>,
    /// Saturating total observation count, including evicted occurrence details.
    pub total_occurrences: u64,
    /// Bounded, ordered set of distinct source identities.
    pub unique_file_identities: BTreeSet<FileIdentity>,
    /// Bounded occurrence details in ingestion order, oldest retained first.
    pub occurrences: VecDeque<StringOccurrence>,
    /// Bounded, deterministically ordered aggregate category names.
    pub categories: BTreeSet<String>,
    /// Whether the analyzer reported a suspicious signal.
    pub is_suspicious: bool,
    /// Shannon entropy calculated over UTF-8 bytes.
    pub entropy: f64,
    /// Bounded explainable evidence retained from initial analysis.
    pub suspicious_indicators: Vec<SuspiciousIndicator>,
    /// Whether analyzer evidence was omitted or unavailable as retained detail.
    pub indicators_truncated: bool,
}

/// Statistics about a filtered tracker snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringStatistics {
    /// Number of distinct values matching the filter.
    pub total_unique_strings: u64,
    /// Saturating total occurrences for matching values.
    pub total_occurrences: u64,
    /// Number of distinct `(file_path, file_hash)` identities represented.
    pub total_files_analyzed: u64,
    /// Up to 100 values ordered by occurrence count descending, then value ascending.
    pub most_common: Vec<(String, u64)>,
    /// Total number of suspicious values before sampling.
    pub total_suspicious_strings: u64,
    /// Up to 50 suspicious values ordered by severity, count, then value.
    pub suspicious_strings: Vec<String>,
    /// Total number of values meeting the tracker's entropy threshold.
    pub total_high_entropy_strings: u64,
    /// Up to 50 high-entropy values ordered by entropy descending, then value.
    pub high_entropy_strings: Vec<(String, f64)>,
    /// Count of matching values in each category.
    pub category_distribution: BTreeMap<String, u64>,
    /// Distribution by UTF-8 byte length.
    pub length_distribution: BTreeMap<String, u64>,
}

/// Filter criteria applied to statistics.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StringFilter {
    /// Minimum aggregate observation count.
    pub min_occurrences: Option<u64>,
    /// Maximum aggregate observation count.
    pub max_occurrences: Option<u64>,
    /// Minimum UTF-8 byte length.
    pub min_length: Option<usize>,
    /// Maximum UTF-8 byte length.
    pub max_length: Option<usize>,
    /// Match entries containing at least one listed category.
    pub categories: Option<Vec<String>>,
    /// Match entries observed at least once at a listed file path.
    pub file_paths: Option<Vec<String>>,
    /// Match entries observed at least once with a listed file hash.
    pub file_hashes: Option<Vec<String>>,
    /// When `Some(true)`, match only suspicious values; `false` does not filter.
    pub suspicious_only: Option<bool>,
    /// Regular expression applied to the full string value.
    pub regex_pattern: Option<String>,
    /// Minimum byte entropy.
    pub min_entropy: Option<f64>,
    /// Maximum byte entropy.
    pub max_entropy: Option<f64>,
    /// Inclusive range applied to `first_seen`.
    pub date_range: Option<DateTimeRange>,
}

/// Thread-safe, bounded in-memory string tracker.
#[derive(Clone)]
pub struct StringTracker {
    entries: StringEntryMap,
    analyzer: Arc<dyn StringAnalyzer>,
    categorizer: Arc<dyn Categorizer>,
    config: Arc<AnalysisConfig>,
}

impl Default for StringTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StringTracker {
    /// Create a tracker with validated defaults and built-in heuristics.
    pub fn new() -> Self {
        match Self::with_config(AnalysisConfig::default()) {
            Ok(tracker) => tracker,
            Err(error) => panic!("built-in tracker defaults must be valid: {error}"),
        }
    }

    /// Create a tracker with built-in components and validated limits.
    pub fn with_config(config: AnalysisConfig) -> AnalysisResult<Self> {
        config.validate()?;
        let patterns = DefaultPatternProvider::new()?.get_patterns();
        let analyzer = DefaultStringAnalyzer::new()
            .with_entropy_threshold(config.min_suspicious_entropy)?
            .with_max_indicators(config.max_indicators_per_string)?
            .with_patterns(patterns)?;
        Self::with_components_and_config(
            Box::new(analyzer),
            Box::new(DefaultCategorizer::new()),
            config,
        )
    }

    /// Create a tracker with custom components and default limits.
    pub fn with_components(
        analyzer: Box<dyn StringAnalyzer>,
        categorizer: Box<dyn Categorizer>,
    ) -> Self {
        match Self::with_components_and_config(analyzer, categorizer, AnalysisConfig::default()) {
            Ok(tracker) => tracker,
            Err(error) => panic!("built-in tracker defaults must be valid: {error}"),
        }
    }

    /// Create a tracker with custom components and validated limits.
    pub fn with_components_and_config(
        analyzer: Box<dyn StringAnalyzer>,
        categorizer: Box<dyn Categorizer>,
        config: AnalysisConfig,
    ) -> AnalysisResult<Self> {
        config.validate()?;
        Ok(Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            analyzer: Arc::from(analyzer),
            categorizer: Arc::from(categorizer),
            config: Arc::new(config),
        })
    }

    /// Return this tracker's immutable configuration.
    pub fn config(&self) -> &AnalysisConfig {
        &self.config
    }

    /// Track an occurrence using the current UTC time.
    pub fn track_string(
        &self,
        value: &str,
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
        context: StringContext,
    ) -> AnalysisResult<()> {
        self.validate_tracking_fields(value, file_path, file_hash, tool_name, &context)?;
        self.track_occurrence(
            value,
            StringOccurrence::new(file_path, file_hash, tool_name, Utc::now(), context),
        )
    }

    /// Track an occurrence with a caller-supplied event timestamp.
    pub fn track_occurrence(
        &self,
        value: &str,
        occurrence: StringOccurrence,
    ) -> AnalysisResult<()> {
        self.track_occurrence_with_categories(value, occurrence, None)
    }

    fn track_occurrence_with_categories(
        &self,
        value: &str,
        mut occurrence: StringOccurrence,
        precomputed_categories: Option<Vec<StringCategory>>,
    ) -> AnalysisResult<()> {
        self.validate_tracking_input(value, &occurrence)?;
        occurrence.compact();
        let context_category = occurrence.context.category_name().to_string();

        // Fast path for an existing entry. No extension code runs while locked.
        {
            let mut entries = self.lock_entries();
            if let Some(entry) = entries.get_mut(value) {
                return self.update_existing_entry(entry, occurrence, context_category);
            }
            if entries.len() >= self.config.max_unique_strings {
                return Err(AnalysisError::CapacityExceeded {
                    resource: "unique strings",
                    limit: self.config.max_unique_strings,
                });
            }
        }

        // Custom extension code deliberately runs outside the state mutex.
        let categorized = match precomputed_categories {
            Some(categories) => categories,
            None => self.normalize_categories(self.categorizer.categorize(value))?,
        };
        let analysis = self.normalize_analysis(self.analyzer.analyze(value))?;
        let categories = self.aggregate_categories(&analysis, &categorized, &context_category)?;

        // Another thread may have inserted this value while analysis ran.
        let mut entries = self.lock_entries();
        if let Some(entry) = entries.get_mut(value) {
            return self.update_existing_entry(entry, occurrence, context_category);
        }
        if entries.len() >= self.config.max_unique_strings {
            return Err(AnalysisError::CapacityExceeded {
                resource: "unique strings",
                limit: self.config.max_unique_strings,
            });
        }

        let timestamp = occurrence.timestamp;
        let identity = occurrence.file_identity();
        // Do not reserve the configured maximum for every distinct value. The
        // collection grows with actual observations and remains bounded below.
        let mut occurrences = VecDeque::new();
        occurrences.push_back(occurrence);
        entries.insert(
            value.to_string(),
            StringEntry {
                value: value.to_string(),
                first_seen: timestamp,
                last_seen: timestamp,
                total_occurrences: 1,
                unique_file_identities: BTreeSet::from([identity]),
                occurrences,
                categories,
                is_suspicious: analysis.is_suspicious,
                entropy: analysis.entropy,
                suspicious_indicators: analysis.suspicious_indicators,
                indicators_truncated: analysis.indicators_truncated,
            },
        );
        Ok(())
    }

    /// Track a batch and infer a context for each value.
    ///
    /// The operation is sequential rather than transactional: if a later value
    /// fails validation or reaches capacity, earlier values remain tracked.
    pub fn track_strings(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> AnalysisResult<()> {
        for value in strings {
            // Validate all direct caller input before executing extension code.
            self.validate_bytes("value", value, self.config.max_input_bytes)?;
            self.validate_bytes("file_path", file_path, self.config.max_source_bytes)?;
            self.validate_bytes("file_hash", file_hash, self.config.max_source_bytes)?;
            self.validate_bytes("tool_name", tool_name, self.config.max_source_bytes)?;
            let categories = self.normalize_categories(self.categorizer.categorize(value))?;
            let context = inferred_context(value, &categories, self.config.max_source_bytes)?;
            self.track_occurrence_with_categories(
                value,
                StringOccurrence::new(file_path, file_hash, tool_name, Utc::now(), context),
                Some(categories),
            )?;
        }
        Ok(())
    }

    /// Compatibility alias for [`StringTracker::track_strings`].
    pub fn track_strings_from_results(
        &self,
        strings: &[String],
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
    ) -> AnalysisResult<()> {
        self.track_strings(strings, file_path, file_hash, tool_name)
    }

    /// Calculate deterministic statistics for an optional validated filter.
    pub fn get_statistics(
        &self,
        filter: Option<&StringFilter>,
    ) -> AnalysisResult<StringStatistics> {
        let compiled_filter = CompiledFilter::new(filter, &self.config)?;
        let entries = self.lock_entries();
        // Aggregate over borrowed entries while holding the snapshot lock.
        // Only bounded top-k buffers and exact borrowed-key accumulators grow;
        // payload strings are cloned once, after the final samples are known.
        let mut total_unique_strings = 0u64;
        let mut total_occurrences = 0u64;
        let mut file_identities: BTreeSet<&FileIdentity> = BTreeSet::new();
        let mut most_common = Vec::with_capacity(MOST_COMMON_LIMIT + 1);
        let mut total_suspicious_strings = 0u64;
        let mut suspicious = Vec::with_capacity(SUSPICIOUS_SAMPLE_LIMIT + 1);
        let mut total_high_entropy_strings = 0u64;
        let mut high_entropy = Vec::with_capacity(HIGH_ENTROPY_SAMPLE_LIMIT + 1);
        let mut category_counts: BTreeMap<&str, u64> = BTreeMap::new();
        let mut length_counts: BTreeMap<&'static str, u64> = BTreeMap::new();

        for entry in entries
            .values()
            .filter(|entry| compiled_filter.matches(entry))
        {
            total_unique_strings = total_unique_strings.saturating_add(1);
            total_occurrences = total_occurrences.saturating_add(entry.total_occurrences);
            file_identities.extend(entry.unique_file_identities.iter());
            insert_bounded_sorted(&mut most_common, entry, MOST_COMMON_LIMIT, |left, right| {
                right
                    .total_occurrences
                    .cmp(&left.total_occurrences)
                    .then_with(|| left.value.cmp(&right.value))
            });

            if entry.is_suspicious {
                total_suspicious_strings = total_suspicious_strings.saturating_add(1);
                let severity = entry
                    .suspicious_indicators
                    .iter()
                    .map(|indicator| indicator.severity)
                    .max()
                    .unwrap_or(0);
                insert_bounded_sorted(
                    &mut suspicious,
                    (entry, severity),
                    SUSPICIOUS_SAMPLE_LIMIT,
                    |left, right| {
                        right
                            .1
                            .cmp(&left.1)
                            .then_with(|| right.0.total_occurrences.cmp(&left.0.total_occurrences))
                            .then_with(|| left.0.value.cmp(&right.0.value))
                    },
                );
            }

            if entry.value.len() >= MIN_ENTROPY_INPUT_BYTES
                && entry.entropy >= self.config.min_suspicious_entropy
            {
                total_high_entropy_strings = total_high_entropy_strings.saturating_add(1);
                insert_bounded_sorted(
                    &mut high_entropy,
                    entry,
                    HIGH_ENTROPY_SAMPLE_LIMIT,
                    |left, right| {
                        right
                            .entropy
                            .total_cmp(&left.entropy)
                            .then_with(|| left.value.cmp(&right.value))
                    },
                );
            }

            for category in &entry.categories {
                let count = category_counts.entry(category).or_insert(0u64);
                *count = count.saturating_add(1);
            }
            let bucket = match entry.value.len() {
                0..=10 => "0-10",
                11..=20 => "11-20",
                21..=50 => "21-50",
                51..=100 => "51-100",
                101..=200 => "101-200",
                _ => "201+",
            };
            let count = length_counts.entry(bucket).or_insert(0u64);
            *count = count.saturating_add(1);
        }

        let total_files_analyzed = usize_to_u64(file_identities.len());
        let most_common = most_common
            .into_iter()
            .map(|entry| (entry.value.clone(), entry.total_occurrences))
            .collect();
        let suspicious_strings = suspicious
            .into_iter()
            .map(|(entry, _)| entry.value.clone())
            .collect();
        let high_entropy_strings = high_entropy
            .into_iter()
            .map(|entry| (entry.value.clone(), entry.entropy))
            .collect();
        let category_distribution = category_counts
            .into_iter()
            .map(|(category, count)| (category.to_string(), count))
            .collect();
        let length_distribution = length_counts
            .into_iter()
            .map(|(bucket, count)| (bucket.to_string(), count))
            .collect();

        Ok(StringStatistics {
            total_unique_strings,
            total_occurrences,
            total_files_analyzed,
            most_common,
            total_suspicious_strings,
            suspicious_strings,
            total_high_entropy_strings,
            high_entropy_strings,
            category_distribution,
            length_distribution,
        })
    }

    /// Return a cloned entry for an exact value.
    pub fn get_string_details(&self, value: &str) -> Option<StringEntry> {
        self.lock_entries().get(value).cloned()
    }

    /// Search values using Unicode lowercase substring matching.
    pub fn search_strings(&self, query: &str, limit: usize) -> AnalysisResult<Vec<StringEntry>> {
        self.validate_bytes("query", query, self.config.max_input_bytes)?;
        if query.trim().is_empty() || limit == 0 {
            return Ok(Vec::new());
        }

        let query_lower = query.to_lowercase();
        let entries = self.lock_entries();
        let mut matches: Vec<_> = entries
            .values()
            .filter(|entry| entry.value.to_lowercase().contains(&query_lower))
            .collect();
        matches.sort_by(|left, right| {
            right
                .total_occurrences
                .cmp(&left.total_occurrences)
                .then_with(|| left.value.cmp(&right.value))
        });
        matches.truncate(limit);
        Ok(matches.into_iter().cloned().collect())
    }

    /// Return related values using a deterministic, fixed-denominator score.
    pub fn get_related_strings(
        &self,
        value: &str,
        limit: usize,
    ) -> AnalysisResult<Vec<(String, f64)>> {
        self.validate_bytes("value", value, self.config.max_input_bytes)?;
        if limit == 0 {
            return Ok(Vec::new());
        }

        let entries = self.lock_entries();
        let Some(target) = entries.get(value) else {
            return Ok(Vec::new());
        };
        let mut related: Vec<_> = entries
            .iter()
            .filter(|(candidate, _)| candidate.as_str() != value)
            .filter_map(|(candidate, entry)| {
                let score = calculate_similarity(target, entry);
                (score >= MIN_RELATED_SCORE).then_some((candidate.as_str(), score))
            })
            .collect();
        related.sort_by(|left, right| right.1.total_cmp(&left.1).then_with(|| left.0.cmp(right.0)));
        related.truncate(limit);
        Ok(related
            .into_iter()
            .map(|(candidate, score)| (candidate.to_string(), score))
            .collect())
    }

    /// Clear all retained state without changing configuration or components.
    pub fn clear(&self) {
        self.lock_entries().clear();
    }

    fn update_existing_entry(
        &self,
        entry: &mut StringEntry,
        occurrence: StringOccurrence,
        context_category: String,
    ) -> AnalysisResult<()> {
        let identity = occurrence.file_identity();
        if !entry.unique_file_identities.contains(&identity)
            && entry.unique_file_identities.len()
                >= self.config.max_unique_file_identities_per_string
        {
            return Err(AnalysisError::CapacityExceeded {
                resource: "unique file identities per string",
                limit: self.config.max_unique_file_identities_per_string,
            });
        }
        if !entry.categories.contains(&context_category)
            && entry.categories.len() >= self.config.max_categories_per_string
        {
            return Err(AnalysisError::CapacityExceeded {
                resource: "categories per string",
                limit: self.config.max_categories_per_string,
            });
        }

        entry.first_seen = entry.first_seen.min(occurrence.timestamp);
        entry.last_seen = entry.last_seen.max(occurrence.timestamp);
        entry.total_occurrences = entry.total_occurrences.saturating_add(1);
        entry.unique_file_identities.insert(identity);
        entry.categories.insert(context_category);
        entry.occurrences.push_back(occurrence);
        while entry.occurrences.len() > self.config.max_occurrences_per_string {
            entry.occurrences.pop_front();
        }
        Ok(())
    }

    fn validate_tracking_input(
        &self,
        value: &str,
        occurrence: &StringOccurrence,
    ) -> AnalysisResult<()> {
        self.validate_tracking_fields(
            value,
            &occurrence.file_path,
            &occurrence.file_hash,
            &occurrence.tool_name,
            &occurrence.context,
        )
    }

    fn validate_tracking_fields(
        &self,
        value: &str,
        file_path: &str,
        file_hash: &str,
        tool_name: &str,
        context: &StringContext,
    ) -> AnalysisResult<()> {
        self.validate_bytes("value", value, self.config.max_input_bytes)?;
        self.validate_bytes("file_path", file_path, self.config.max_source_bytes)?;
        self.validate_bytes("file_hash", file_hash, self.config.max_source_bytes)?;
        self.validate_bytes("tool_name", tool_name, self.config.max_source_bytes)?;
        if let Some((field, source_value)) = context.owned_field() {
            self.validate_bytes(field, source_value, self.config.max_source_bytes)?;
        }
        if let StringContext::Other { category } = context {
            validate_identifier("context category", category)?;
        }
        Ok(())
    }

    fn validate_bytes(&self, field: &'static str, value: &str, limit: usize) -> AnalysisResult<()> {
        if value.len() > limit {
            Err(AnalysisError::InputTooLarge {
                field,
                actual: value.len(),
                limit,
            })
        } else {
            Ok(())
        }
    }

    fn normalize_analysis(&self, mut analysis: StringAnalysis) -> AnalysisResult<StringAnalysis> {
        if !analysis.entropy.is_finite() || !(0.0..=8.0).contains(&analysis.entropy) {
            return Err(AnalysisError::InvalidComponentOutput {
                field: "analysis.entropy",
                reason: "must be finite and between 0 and 8 inclusive".to_string(),
            });
        }
        if analysis.categories.len() > self.config.max_categories_per_string {
            return Err(AnalysisError::CapacityExceeded {
                resource: "analyzer categories per string",
                limit: self.config.max_categories_per_string,
            });
        }
        for category in &analysis.categories {
            validate_identifier("analyzer category", category)?;
        }
        analysis.categories = analysis
            .categories
            .into_iter()
            .map(compact_string)
            .collect();

        let (retained_indicators, truncated_by_limit) = retain_highest_severity_indicators(
            analysis.suspicious_indicators,
            self.config.max_indicators_per_string,
        );
        analysis.indicators_truncated |= truncated_by_limit;
        let mut normalized_indicators = Vec::with_capacity(retained_indicators.len());
        for mut indicator in retained_indicators {
            validate_identifier("indicator pattern", &indicator.pattern_name)?;
            if indicator.severity > 10 {
                return Err(AnalysisError::InvalidSeverity {
                    severity: indicator.severity,
                });
            }
            if indicator.description.len() > MAX_DESCRIPTION_BYTES {
                return Err(AnalysisError::InputTooLarge {
                    field: "indicator.description",
                    actual: indicator.description.len(),
                    limit: MAX_DESCRIPTION_BYTES,
                });
            }
            if indicator.description.trim().is_empty() {
                return Err(AnalysisError::InvalidComponentOutput {
                    field: "indicator.description",
                    reason: "must not be empty or whitespace-only".to_string(),
                });
            }
            if indicator.description.chars().any(char::is_control) {
                return Err(AnalysisError::InvalidComponentOutput {
                    field: "indicator.description",
                    reason: "must not contain control characters".to_string(),
                });
            }
            indicator.pattern_name = compact_string(indicator.pattern_name);
            indicator.description = compact_string(indicator.description);
            if let Some(matched_text) = indicator.matched_text.take() {
                let (matched_text, truncated) =
                    bounded_owned_string(matched_text, INDICATOR_MATCHED_TEXT_LIMIT);
                indicator.matched_text_truncated |= truncated;
                indicator.matched_text = Some(matched_text);
            } else {
                indicator.matched_text_truncated = false;
            }
            normalized_indicators.push(indicator);
        }
        analysis.suspicious_indicators = normalized_indicators;
        if !analysis.suspicious_indicators.is_empty() || analysis.indicators_truncated {
            analysis.is_suspicious = true;
        } else if analysis.is_suspicious {
            analysis.indicators_truncated = true;
        }
        Ok(analysis)
    }

    fn normalize_categories(
        &self,
        categories: Vec<StringCategory>,
    ) -> AnalysisResult<Vec<StringCategory>> {
        if categories.len() > self.config.max_categories_per_string {
            return Err(AnalysisError::CapacityExceeded {
                resource: "categorizer categories per string",
                limit: self.config.max_categories_per_string,
            });
        }

        let mut normalized = Vec::with_capacity(categories.len());
        for category in categories {
            validate_category(&category)?;
            normalized.push(category.compact());
        }
        Ok(normalized)
    }

    fn aggregate_categories(
        &self,
        analysis: &StringAnalysis,
        categorized: &[StringCategory],
        context_category: &str,
    ) -> AnalysisResult<BTreeSet<String>> {
        if categorized.len() > self.config.max_categories_per_string {
            return Err(AnalysisError::CapacityExceeded {
                resource: "categorizer categories per string",
                limit: self.config.max_categories_per_string,
            });
        }

        let mut categories = analysis.categories.clone();
        validate_identifier("context category", context_category)?;
        if !categories.contains(context_category)
            && categories.len() >= self.config.max_categories_per_string
        {
            return Err(AnalysisError::CapacityExceeded {
                resource: "categories per string",
                limit: self.config.max_categories_per_string,
            });
        }
        categories.insert(context_category.to_string());
        for category in categorized {
            validate_identifier("categorizer category", &category.name)?;
            if !categories.contains(&category.name)
                && categories.len() >= self.config.max_categories_per_string
            {
                return Err(AnalysisError::CapacityExceeded {
                    resource: "categories per string",
                    limit: self.config.max_categories_per_string,
                });
            }
            categories.insert(category.name.clone());
        }
        Ok(categories)
    }

    fn lock_entries(&self) -> MutexGuard<'_, BTreeMap<String, StringEntry>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

struct CompiledFilter<'a> {
    filter: Option<&'a StringFilter>,
    regex: Option<Regex>,
}

impl<'a> CompiledFilter<'a> {
    fn new(filter: Option<&'a StringFilter>, config: &AnalysisConfig) -> AnalysisResult<Self> {
        let Some(filter) = filter else {
            return Ok(Self {
                filter: None,
                regex: None,
            });
        };

        validate_ordered_filter(
            "occurrences",
            filter.min_occurrences,
            filter.max_occurrences,
        )?;
        validate_ordered_filter("length", filter.min_length, filter.max_length)?;
        validate_entropy_filter(filter.min_entropy, filter.max_entropy)?;
        if let Some((start, end)) = &filter.date_range
            && start > end
        {
            return Err(AnalysisError::InvalidFilter {
                field: "date_range",
                reason: "start must be earlier than or equal to end".to_string(),
            });
        }
        validate_filter_values(
            "categories",
            filter.categories.as_deref(),
            config.max_categories_per_string,
            config.max_source_bytes,
        )?;
        validate_filter_values(
            "file_paths",
            filter.file_paths.as_deref(),
            config.max_unique_file_identities_per_string,
            config.max_source_bytes,
        )?;
        validate_filter_values(
            "file_hashes",
            filter.file_hashes.as_deref(),
            config.max_unique_file_identities_per_string,
            config.max_source_bytes,
        )?;

        let regex = filter
            .regex_pattern
            .as_ref()
            .map(|pattern| {
                let regex_source_limit = config.max_source_bytes.min(MAX_REGEX_BYTES);
                if pattern.len() > regex_source_limit {
                    return Err(AnalysisError::InvalidFilter {
                        field: "regex_pattern",
                        reason: format!(
                            "is {} bytes; effective maximum is {}",
                            pattern.len(),
                            regex_source_limit
                        ),
                    });
                }
                RegexBuilder::new(pattern)
                    .size_limit(FILTER_REGEX_COMPILED_SIZE_LIMIT)
                    .dfa_size_limit(FILTER_REGEX_DFA_SIZE_LIMIT)
                    .build()
                    .map_err(|error| AnalysisError::InvalidRegex {
                        context: "statistics filter",
                        reason: regex_error_reason(&error),
                    })
            })
            .transpose()?;

        Ok(Self {
            filter: Some(filter),
            regex,
        })
    }

    fn matches(&self, entry: &StringEntry) -> bool {
        let Some(filter) = self.filter else {
            return true;
        };

        if filter
            .min_occurrences
            .is_some_and(|minimum| entry.total_occurrences < minimum)
            || filter
                .max_occurrences
                .is_some_and(|maximum| entry.total_occurrences > maximum)
            || filter
                .min_length
                .is_some_and(|minimum| entry.value.len() < minimum)
            || filter
                .max_length
                .is_some_and(|maximum| entry.value.len() > maximum)
            || filter
                .min_entropy
                .is_some_and(|minimum| entry.entropy < minimum)
            || filter
                .max_entropy
                .is_some_and(|maximum| entry.entropy > maximum)
        {
            return false;
        }

        if let Some(categories) = &filter.categories
            && !categories
                .iter()
                .any(|category| entry.categories.contains(category))
        {
            return false;
        }
        if let Some(paths) = &filter.file_paths
            && !paths.iter().any(|path| {
                entry
                    .unique_file_identities
                    .iter()
                    .any(|identity| identity.file_path == *path)
            })
        {
            return false;
        }
        if let Some(hashes) = &filter.file_hashes
            && !hashes.iter().any(|hash| {
                entry
                    .unique_file_identities
                    .iter()
                    .any(|identity| identity.file_hash == *hash)
            })
        {
            return false;
        }
        if filter.suspicious_only == Some(true) && !entry.is_suspicious {
            return false;
        }
        if self
            .regex
            .as_ref()
            .is_some_and(|regex| !regex.is_match(&entry.value))
        {
            return false;
        }
        if let Some((start, end)) = &filter.date_range
            && (entry.first_seen < *start || entry.first_seen > *end)
        {
            return false;
        }
        true
    }
}

fn inferred_context(
    value: &str,
    categories: &[StringCategory],
    max_source_bytes: usize,
) -> AnalysisResult<StringContext> {
    if categories.iter().any(|category| category.name == "url") {
        let protocol = value.split_once("://").map(|(protocol, _)| protocol);
        if let Some(protocol) = protocol
            && protocol.len() > max_source_bytes
        {
            return Err(AnalysisError::InputTooLarge {
                field: "context.url.protocol",
                actual: protocol.len(),
                limit: max_source_bytes,
            });
        }
        return Ok(StringContext::Url {
            protocol: protocol.map(str::to_ascii_lowercase),
        });
    }
    if categories.iter().any(|category| category.name == "path") {
        let path_type =
            if contains_ascii_case(value, "\\windows") || contains_ascii_case(value, "/usr") {
                "system"
            } else if contains_ascii_case(value, "\\temp") || contains_ascii_case(value, "/tmp") {
                "temporary"
            } else {
                "general"
            };
        return Ok(StringContext::Path {
            path_type: path_type.to_string(),
        });
    }
    if categories
        .iter()
        .any(|category| category.name == "registry")
    {
        let hive = value.split('\\').next();
        if let Some(hive) = hive
            && hive.len() > max_source_bytes
        {
            return Err(AnalysisError::InputTooLarge {
                field: "context.registry.hive",
                actual: hive.len(),
                limit: max_source_bytes,
            });
        }
        return Ok(StringContext::Registry {
            hive: hive.map(ToString::to_string),
        });
    }
    if categories.iter().any(|category| category.name == "library") {
        if value.len() > max_source_bytes {
            return Err(AnalysisError::InputTooLarge {
                field: "context.import.library",
                actual: value.len(),
                limit: max_source_bytes,
            });
        }
        return Ok(StringContext::Import {
            library: value.to_string(),
        });
    }
    if categories.iter().any(|category| category.name == "command") {
        return Ok(StringContext::Command {
            command_type: "shell".to_string(),
        });
    }
    Ok(StringContext::FileString { offset: None })
}

fn validate_ordered_filter<T>(
    field: &'static str,
    minimum: Option<T>,
    maximum: Option<T>,
) -> AnalysisResult<()>
where
    T: PartialOrd,
{
    if minimum.zip(maximum).is_some_and(|(min, max)| min > max) {
        Err(AnalysisError::InvalidFilter {
            field,
            reason: "minimum must be less than or equal to maximum".to_string(),
        })
    } else {
        Ok(())
    }
}

fn validate_entropy_filter(minimum: Option<f64>, maximum: Option<f64>) -> AnalysisResult<()> {
    for (field, value) in [("min_entropy", minimum), ("max_entropy", maximum)] {
        if let Some(value) = value
            && (!value.is_finite() || !(0.0..=8.0).contains(&value))
        {
            return Err(AnalysisError::InvalidFilter {
                field,
                reason: "must be finite and between 0 and 8 inclusive".to_string(),
            });
        }
    }
    validate_ordered_filter("entropy", minimum, maximum)
}

fn validate_filter_values(
    field: &'static str,
    values: Option<&[String]>,
    count_limit: usize,
    byte_limit: usize,
) -> AnalysisResult<()> {
    let Some(values) = values else {
        return Ok(());
    };
    if values.len() > count_limit {
        return Err(AnalysisError::InvalidFilter {
            field,
            reason: format!(
                "contains {} values; configured maximum is {count_limit}",
                values.len()
            ),
        });
    }
    if let Some(value) = values.iter().find(|value| value.len() > byte_limit) {
        return Err(AnalysisError::InvalidFilter {
            field,
            reason: format!(
                "contains a {}-byte value; configured maximum is {byte_limit}",
                value.len()
            ),
        });
    }
    Ok(())
}

fn calculate_similarity(left: &StringEntry, right: &StringEntry) -> f64 {
    const FILE_WEIGHT: f64 = 0.55;
    const CATEGORY_WEIGHT: f64 = 0.25;
    const ENTROPY_WEIGHT: f64 = 0.10;
    const LENGTH_WEIGHT: f64 = 0.10;

    let file_similarity = jaccard(&left.unique_file_identities, &right.unique_file_identities);
    let left_categories = meaningful_categories(&left.categories);
    let right_categories = meaningful_categories(&right.categories);
    let category_similarity = jaccard(&left_categories, &right_categories);
    let entropy_similarity = 1.0 - ((left.entropy - right.entropy).abs() / 8.0).min(1.0);
    let max_length = left.value.len().max(right.value.len());
    let length_similarity = if max_length == 0 {
        1.0
    } else {
        left.value.len().min(right.value.len()) as f64 / max_length as f64
    };

    file_similarity * FILE_WEIGHT
        + category_similarity * CATEGORY_WEIGHT
        + entropy_similarity * ENTROPY_WEIGHT
        + length_similarity * LENGTH_WEIGHT
}

fn meaningful_categories(categories: &BTreeSet<String>) -> BTreeSet<&str> {
    categories
        .iter()
        .map(String::as_str)
        .filter(|category| !matches!(*category, "generic" | "file_string"))
        .collect()
}

fn jaccard<T>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> f64
where
    T: Ord,
{
    let union = left.union(right).count();
    if union == 0 {
        0.0
    } else {
        left.intersection(right).count() as f64 / union as f64
    }
}

fn retain_highest_severity_indicators(
    indicators: Vec<SuspiciousIndicator>,
    limit: usize,
) -> (Vec<SuspiciousIndicator>, bool) {
    let truncated = indicators.len() > limit;
    let mut retained: Vec<(usize, SuspiciousIndicator)> =
        Vec::with_capacity(indicators.len().min(limit));

    for (order, indicator) in indicators.into_iter().enumerate() {
        if retained.len() < limit {
            retained.push((order, indicator));
            continue;
        }
        let Some((lowest_index, (_, lowest))) = retained
            .iter()
            .enumerate()
            .min_by_key(|(_, (order, indicator))| (indicator.severity, Reverse(*order)))
        else {
            continue;
        };
        if indicator.severity > lowest.severity {
            retained[lowest_index] = (order, indicator);
        }
    }

    retained.sort_by_key(|(order, _)| *order);
    let mut normalized = Vec::with_capacity(retained.len());
    normalized.extend(retained.into_iter().map(|(_, indicator)| indicator));
    (normalized, truncated)
}

fn insert_bounded_sorted<T>(
    values: &mut Vec<T>,
    value: T,
    limit: usize,
    mut compare: impl FnMut(&T, &T) -> Ordering,
) {
    let index = values
        .binary_search_by(|existing| compare(existing, &value))
        .unwrap_or_else(|index| index);
    values.insert(index, value);
    if values.len() > limit {
        values.pop();
    }
}

fn bounded_owned_string(value: String, limit: usize) -> (String, bool) {
    if value.len() <= limit {
        return (compact_string(value), false);
    }

    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_string(), true)
}

fn compact_in_place(value: &mut String) {
    *value = compact_string(std::mem::take(value));
}

fn contains_ascii_case(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|candidate| candidate.eq_ignore_ascii_case(needle.as_bytes()))
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_rebuilds_callback_owned_allocations_to_retained_size() {
        let tracker = StringTracker::new();
        let mut category = String::with_capacity(1_000_000);
        category.push_str("custom");
        let mut pattern_name = String::with_capacity(1_000_000);
        pattern_name.push_str("custom_signal");
        let mut description = String::with_capacity(1_000_000);
        description.push_str("Custom signal");
        let mut matched_text = String::with_capacity(1_000_000);
        matched_text.push_str(&"é".repeat(300));
        let mut indicators = Vec::with_capacity(1_000_000);
        indicators.push(SuspiciousIndicator {
            pattern_name,
            description,
            severity: 5,
            matched_text: Some(matched_text),
            matched_text_truncated: false,
        });

        let analysis = tracker
            .normalize_analysis(StringAnalysis {
                entropy: 1.0,
                categories: BTreeSet::from([category]),
                suspicious_indicators: indicators,
                indicators_truncated: false,
                is_suspicious: true,
            })
            .unwrap();

        assert_eq!(analysis.suspicious_indicators.capacity(), 1);
        assert_eq!(
            analysis.categories.first().unwrap().capacity(),
            analysis.categories.first().unwrap().len()
        );
        let indicator = &analysis.suspicious_indicators[0];
        assert_eq!(
            indicator.pattern_name.capacity(),
            indicator.pattern_name.len()
        );
        assert_eq!(
            indicator.description.capacity(),
            indicator.description.len()
        );
        let matched_text = indicator.matched_text.as_ref().unwrap();
        assert_eq!(matched_text.len(), INDICATOR_MATCHED_TEXT_LIMIT);
        assert_eq!(matched_text.capacity(), matched_text.len());
        assert!(indicator.matched_text_truncated);
    }

    #[test]
    fn tracking_compacts_occurrence_owned_allocations_before_retention() {
        let tracker = StringTracker::new();
        let mut file_path = String::with_capacity(1_000_000);
        file_path.push('p');
        let mut file_hash = String::with_capacity(1_000_000);
        file_hash.push('h');
        let mut tool_name = String::with_capacity(1_000_000);
        tool_name.push('t');
        let mut library = String::with_capacity(1_000_000);
        library.push('l');

        tracker
            .track_occurrence(
                "value",
                StringOccurrence {
                    file_path,
                    file_hash,
                    tool_name,
                    timestamp: Utc::now(),
                    context: StringContext::Import { library },
                },
            )
            .unwrap();

        let entries = tracker.lock_entries();
        let entry = entries.get("value").unwrap();
        let occurrence = &entry.occurrences[0];
        assert_eq!(occurrence.file_path.capacity(), occurrence.file_path.len());
        assert_eq!(occurrence.file_hash.capacity(), occurrence.file_hash.len());
        assert_eq!(occurrence.tool_name.capacity(), occurrence.tool_name.len());
        let StringContext::Import { library } = &occurrence.context else {
            panic!("expected import context");
        };
        assert_eq!(library.capacity(), library.len());
        let identity = entry.unique_file_identities.first().unwrap();
        assert_eq!(identity.file_path.capacity(), identity.file_path.len());
        assert_eq!(identity.file_hash.capacity(), identity.file_hash.len());
    }
}
