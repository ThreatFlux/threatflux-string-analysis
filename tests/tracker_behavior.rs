use chrono::{TimeZone, Utc};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use threatflux_string_analysis::{
    AnalysisConfig, AnalysisError, AnalysisResult, Categorizer, CategoryRule, DefaultCategorizer,
    DefaultStringAnalyzer, Pattern, StringAnalysis, StringAnalyzer, StringCategory, StringContext,
    StringOccurrence, StringTracker, SuspiciousIndicator,
};

fn context() -> StringContext {
    StringContext::FileString { offset: None }
}

#[test]
fn configuration_is_validated() {
    for field in [
        "max_occurrences_per_string",
        "max_unique_strings",
        "max_input_bytes",
        "max_source_bytes",
        "max_unique_file_identities_per_string",
        "max_categories_per_string",
        "max_indicators_per_string",
    ] {
        let mut config = AnalysisConfig::default();
        match field {
            "max_occurrences_per_string" => config.max_occurrences_per_string = 0,
            "max_unique_strings" => config.max_unique_strings = 0,
            "max_input_bytes" => config.max_input_bytes = 0,
            "max_source_bytes" => config.max_source_bytes = 0,
            "max_unique_file_identities_per_string" => {
                config.max_unique_file_identities_per_string = 0;
            }
            "max_categories_per_string" => config.max_categories_per_string = 0,
            "max_indicators_per_string" => config.max_indicators_per_string = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            config.validate(),
            Err(AnalysisError::InvalidConfiguration {
                field: actual,
                ..
            }) if actual == field
        ));
    }

    for threshold in [f64::NAN, f64::INFINITY, -0.1, 8.1] {
        let config = AnalysisConfig {
            min_suspicious_entropy: threshold,
            ..AnalysisConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(AnalysisError::InvalidConfiguration {
                field: "min_suspicious_entropy",
                ..
            })
        ));
    }
    for threshold in [0.0, 8.0] {
        AnalysisConfig {
            min_suspicious_entropy: threshold,
            ..AnalysisConfig::default()
        }
        .validate()
        .unwrap();
    }
}

#[test]
fn unique_capacity_rejects_only_new_values() -> AnalysisResult<()> {
    let config = AnalysisConfig {
        max_unique_strings: 1,
        ..AnalysisConfig::default()
    };
    let tracker = StringTracker::with_config(config)?;
    tracker.track_string("alpha", "a", "hash", "tool", context())?;
    tracker.track_string("alpha", "a", "hash", "tool", context())?;
    assert!(matches!(
        tracker.track_string("beta", "b", "hash", "tool", context()),
        Err(AnalysisError::CapacityExceeded {
            resource: "unique strings",
            limit: 1
        })
    ));
    assert_eq!(
        tracker
            .get_string_details("alpha")
            .unwrap()
            .total_occurrences,
        2
    );
    Ok(())
}

#[test]
fn occurrence_limit_is_not_eagerly_reserved_for_new_values() -> AnalysisResult<()> {
    let tracker = StringTracker::with_config(AnalysisConfig {
        // Eagerly passing this value to VecDeque::with_capacity would panic or
        // attempt an impossible allocation. It is only a retention ceiling.
        max_occurrences_per_string: usize::MAX,
        ..AnalysisConfig::default()
    })?;
    tracker.track_string("one", "a", "h", "tool", context())?;
    assert_eq!(
        tracker.get_string_details("one").unwrap().occurrences.len(),
        1
    );
    Ok(())
}

#[test]
fn batch_validates_before_extensions_and_categorizes_new_values_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let tracker = StringTracker::with_components_and_config(
        Box::new(DefaultStringAnalyzer::new()),
        Box::new(CountingCategorizer {
            calls: Arc::clone(&calls),
        }),
        AnalysisConfig {
            max_input_bytes: 3,
            ..AnalysisConfig::default()
        },
    )
    .unwrap();

    assert!(matches!(
        tracker.track_strings(&["four".to_string()], "p", "h", "tool"),
        Err(AnalysisError::InputTooLarge { field: "value", .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    tracker
        .track_strings(&["one".to_string()], "p", "h", "tool")
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn value_source_and_context_byte_limits_are_enforced_before_mutation() {
    let config = AnalysisConfig {
        max_input_bytes: 4,
        max_source_bytes: 3,
        ..AnalysisConfig::default()
    };
    let tracker = StringTracker::with_config(config).unwrap();

    assert!(matches!(
        tracker.track_string("12345", "p", "h", "t", context()),
        Err(AnalysisError::InputTooLarge { field: "value", .. })
    ));
    for (field, result) in [
        (
            "file_path",
            tracker.track_string("ok", "path", "h", "t", context()),
        ),
        (
            "file_hash",
            tracker.track_string("ok", "p", "hash", "t", context()),
        ),
        (
            "tool_name",
            tracker.track_string("ok", "p", "h", "tool", context()),
        ),
        (
            "context.import.library",
            tracker.track_string(
                "ok",
                "p",
                "h",
                "t",
                StringContext::Import {
                    library: "long".to_string(),
                },
            ),
        ),
    ] {
        assert!(matches!(
            result,
            Err(AnalysisError::InputTooLarge {
                field: actual,
                ..
            }) if actual == field
        ));
    }
    assert_eq!(
        tracker.get_statistics(None).unwrap().total_unique_strings,
        0
    );

    let context_boundaries = [
        (
            "context.import.library",
            StringContext::Import {
                library: "abc".to_string(),
            },
            StringContext::Import {
                library: "long".to_string(),
            },
        ),
        (
            "context.export.symbol",
            StringContext::Export {
                symbol: "abc".to_string(),
            },
            StringContext::Export {
                symbol: "long".to_string(),
            },
        ),
        (
            "context.resource.resource_type",
            StringContext::Resource {
                resource_type: "abc".to_string(),
            },
            StringContext::Resource {
                resource_type: "long".to_string(),
            },
        ),
        (
            "context.section.section_name",
            StringContext::Section {
                section_name: "abc".to_string(),
            },
            StringContext::Section {
                section_name: "long".to_string(),
            },
        ),
        (
            "context.metadata.field",
            StringContext::Metadata {
                field: "abc".to_string(),
            },
            StringContext::Metadata {
                field: "long".to_string(),
            },
        ),
        (
            "context.path.path_type",
            StringContext::Path {
                path_type: "abc".to_string(),
            },
            StringContext::Path {
                path_type: "long".to_string(),
            },
        ),
        (
            "context.url.protocol",
            StringContext::Url {
                protocol: Some("abc".to_string()),
            },
            StringContext::Url {
                protocol: Some("long".to_string()),
            },
        ),
        (
            "context.registry.hive",
            StringContext::Registry {
                hive: Some("abc".to_string()),
            },
            StringContext::Registry {
                hive: Some("long".to_string()),
            },
        ),
        (
            "context.command.command_type",
            StringContext::Command {
                command_type: "abc".to_string(),
            },
            StringContext::Command {
                command_type: "long".to_string(),
            },
        ),
        (
            "context.other.category",
            StringContext::Other {
                category: "abc".to_string(),
            },
            StringContext::Other {
                category: "long".to_string(),
            },
        ),
    ];
    for (index, (field, exact, over)) in context_boundaries.into_iter().enumerate() {
        tracker
            .track_string(&format!("v{index}"), "p", "h", "t", exact)
            .unwrap();
        assert!(matches!(
            tracker.track_string(&format!("x{index}"), "p", "h", "t", over),
            Err(AnalysisError::InputTooLarge {
                field: actual,
                actual: 4,
                limit: 3,
            }) if actual == field
        ));
    }
    assert_eq!(
        tracker.get_statistics(None).unwrap().total_unique_strings,
        10
    );
}

#[test]
fn explicit_timestamps_contexts_and_ingestion_retention_are_consistent() -> AnalysisResult<()> {
    let config = AnalysisConfig {
        max_occurrences_per_string: 2,
        max_unique_file_identities_per_string: 2,
        ..AnalysisConfig::default()
    };
    let tracker = StringTracker::with_config(config)?;
    let early = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
    let middle = Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap();
    let late = Utc.with_ymd_and_hms(2024, 1, 3, 0, 0, 0).unwrap();

    tracker.track_occurrence(
        "shared",
        StringOccurrence::new("a", "ha", "tool", late, context()),
    )?;
    tracker.track_occurrence(
        "shared",
        StringOccurrence::new(
            "b",
            "hb",
            "tool",
            early,
            StringContext::Url {
                protocol: Some("https".to_string()),
            },
        ),
    )?;
    tracker.track_occurrence(
        "shared",
        StringOccurrence::new(
            "b",
            "hb",
            "tool",
            middle,
            StringContext::Registry {
                hive: Some("HKCU".to_string()),
            },
        ),
    )?;

    let details = tracker.get_string_details("shared").unwrap();
    assert_eq!(details.first_seen, early);
    assert_eq!(details.last_seen, late);
    assert_eq!(details.total_occurrences, 3);
    assert_eq!(details.occurrences.len(), 2);
    assert_eq!(details.occurrences[0].timestamp, early);
    assert_eq!(details.occurrences[1].timestamp, middle);
    assert_eq!(details.unique_file_identities.len(), 2);
    assert!(details.categories.contains("file_string"));
    assert!(details.categories.contains("url"));
    assert!(details.categories.contains("registry"));

    let before = details.clone();
    assert!(matches!(
        tracker.track_string("shared", "c", "hc", "tool", context()),
        Err(AnalysisError::CapacityExceeded {
            resource: "unique file identities per string",
            limit: 2
        })
    ));
    assert_eq!(tracker.get_string_details("shared").unwrap(), before);
    Ok(())
}

#[test]
fn suspicious_entries_retain_bounded_evidence() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    tracker.track_string("cmd.exe /c whoami", "a", "h", "tool", context())?;
    let details = tracker.get_string_details("cmd.exe /c whoami").unwrap();
    assert!(details.is_suspicious);
    assert!(!details.suspicious_indicators.is_empty());
    assert!(
        details
            .suspicious_indicators
            .iter()
            .all(|indicator| indicator.matched_text.as_ref().map_or(0, String::len) <= 512)
    );
    Ok(())
}

#[test]
fn concurrent_updates_preserve_count_and_retention_invariants() {
    let config = AnalysisConfig {
        max_occurrences_per_string: 5,
        ..AnalysisConfig::default()
    };
    let tracker = Arc::new(StringTracker::with_config(config).unwrap());
    let handles: Vec<_> = (0..4)
        .map(|worker| {
            let tracker = Arc::clone(&tracker);
            thread::spawn(move || {
                for observation in 0..50 {
                    tracker
                        .track_string(
                            "shared",
                            &format!("file-{worker}"),
                            &format!("hash-{worker}"),
                            "tool",
                            StringContext::FileString {
                                offset: Some(observation),
                            },
                        )
                        .unwrap();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }

    let details = tracker.get_string_details("shared").unwrap();
    assert_eq!(details.total_occurrences, 200);
    assert_eq!(details.occurrences.len(), 5);
    assert_eq!(details.unique_file_identities.len(), 4);
}

#[test]
fn concurrent_reads_observe_valid_snapshots_during_writes() {
    let tracker = Arc::new(
        StringTracker::with_config(AnalysisConfig {
            max_occurrences_per_string: 5,
            ..AnalysisConfig::default()
        })
        .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(6));
    let writers_done = Arc::new(AtomicBool::new(false));

    let reader = {
        let tracker = Arc::clone(&tracker);
        let barrier = Arc::clone(&barrier);
        let writers_done = Arc::clone(&writers_done);
        thread::spawn(move || {
            barrier.wait();
            let mut reads = 0usize;
            loop {
                let statistics = tracker.get_statistics(None).unwrap();
                assert!(statistics.total_occurrences <= 200);
                if let Some(details) = tracker.get_string_details("shared") {
                    assert!(details.total_occurrences <= 200);
                    assert!(details.occurrences.len() <= 5);
                }
                reads = reads.saturating_add(1);
                if writers_done.load(Ordering::Acquire) {
                    return reads;
                }
                thread::yield_now();
            }
        })
    };

    let writers: Vec<_> = (0..4)
        .map(|worker| {
            let tracker = Arc::clone(&tracker);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for observation in 0..50 {
                    tracker
                        .track_string(
                            "shared",
                            &format!("file-{worker}"),
                            &format!("hash-{worker}"),
                            "tool",
                            StringContext::FileString {
                                offset: Some(observation),
                            },
                        )
                        .unwrap();
                }
            })
        })
        .collect();

    barrier.wait();
    for writer in writers {
        writer.join().unwrap();
    }
    writers_done.store(true, Ordering::Release);
    assert!(reader.join().unwrap() > 0);
    assert_eq!(
        tracker
            .get_string_details("shared")
            .unwrap()
            .total_occurrences,
        200
    );
}

#[test]
fn panicking_extension_does_not_poison_tracker_state() {
    let tracker = StringTracker::with_components(
        Box::new(PanickingAnalyzer),
        Box::new(DefaultCategorizer::new()),
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = tracker.track_string("panic", "a", "h", "tool", context());
        }))
        .is_err()
    );

    tracker
        .track_string("safe", "a", "h", "tool", context())
        .unwrap();
    assert!(tracker.get_string_details("safe").is_some());
}

#[test]
fn truncated_custom_evidence_preserves_the_suspicious_invariant() -> AnalysisResult<()> {
    let tracker = StringTracker::with_components(
        Box::new(TruncatedAnalyzer),
        Box::new(DefaultCategorizer::new()),
    );
    tracker.track_string("value", "a", "h", "tool", context())?;

    let details = tracker.get_string_details("value").unwrap();
    assert!(details.indicators_truncated);
    assert!(details.is_suspicious);
    assert!(details.suspicious_indicators.is_empty());
    Ok(())
}

#[test]
fn oversized_custom_category_output_is_rejected_before_retention() {
    let analyzer_calls = Arc::new(AtomicUsize::new(0));
    let tracker = StringTracker::with_components_and_config(
        Box::new(CountingAnalyzer {
            calls: Arc::clone(&analyzer_calls),
        }),
        Box::new(OversizedCategorizer),
        AnalysisConfig {
            max_categories_per_string: 2,
            ..AnalysisConfig::default()
        },
    )
    .unwrap();

    assert!(matches!(
        tracker.track_string("value", "a", "h", "tool", context()),
        Err(AnalysisError::CapacityExceeded {
            resource: "categorizer categories per string",
            limit: 2,
        })
    ));
    assert!(tracker.get_string_details("value").is_none());
    assert_eq!(analyzer_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn custom_analyzer_truncation_retains_the_highest_severity() -> AnalysisResult<()> {
    let tracker = StringTracker::with_components_and_config(
        Box::new(MultiIndicatorAnalyzer),
        Box::new(DefaultCategorizer::new()),
        AnalysisConfig {
            max_indicators_per_string: 1,
            ..AnalysisConfig::default()
        },
    )?;
    tracker.track_string("value", "a", "h", "tool", context())?;

    let details = tracker.get_string_details("value").unwrap();
    assert!(details.indicators_truncated);
    assert_eq!(details.suspicious_indicators.len(), 1);
    assert_eq!(details.suspicious_indicators[0].severity, 9);
    assert_eq!(details.suspicious_indicators[0].pattern_name, "strong");
    Ok(())
}

#[test]
fn custom_analyzer_entropy_and_statistics_thresholds_are_independent() -> AnalysisResult<()> {
    let tracker = StringTracker::with_components_and_config(
        Box::new(FixedEntropyAnalyzer),
        Box::new(DefaultCategorizer::new()),
        AnalysisConfig {
            min_suspicious_entropy: 4.5,
            ..AnalysisConfig::default()
        },
    )?;
    tracker.track_string(
        "twelve-bytes",
        "a",
        "h",
        "tool",
        StringContext::FileString { offset: None },
    )?;

    let details = tracker.get_string_details("twelve-bytes").unwrap();
    assert_eq!(details.entropy, 5.0);
    assert!(!details.is_suspicious);
    let statistics = tracker.get_statistics(None)?;
    assert_eq!(statistics.total_high_entropy_strings, 1);
    assert_eq!(statistics.total_suspicious_strings, 0);
    Ok(())
}

#[test]
fn invalid_custom_category_metadata_is_rejected_before_analysis() {
    for category in [
        StringCategory {
            name: "valid".to_string(),
            parent: Some("bad\u{1b}parent".to_string()),
            description: "Category validation regression".to_string(),
        },
        StringCategory {
            name: "valid".to_string(),
            parent: None,
            description: "\t".repeat(5_000),
        },
    ] {
        let analyzer_calls = Arc::new(AtomicUsize::new(0));
        let tracker = StringTracker::with_components(
            Box::new(CountingAnalyzer {
                calls: Arc::clone(&analyzer_calls),
            }),
            Box::new(OneCategoryCategorizer { category }),
        );
        assert!(
            tracker
                .track_string("value", "a", "h", "tool", context())
                .is_err()
        );
        assert_eq!(analyzer_calls.load(Ordering::SeqCst), 0);
        assert!(tracker.get_string_details("value").is_none());
    }
}

struct PanickingAnalyzer;

impl StringAnalyzer for PanickingAnalyzer {
    fn analyze(&self, value: &str) -> StringAnalysis {
        assert_ne!(value, "panic", "deliberate extension panic");
        StringAnalysis {
            entropy: 0.0,
            categories: Default::default(),
            suspicious_indicators: Vec::new(),
            indicators_truncated: false,
            is_suspicious: false,
        }
    }

    fn calculate_entropy(&self, _value: &str) -> f64 {
        0.0
    }

    fn get_patterns(&self) -> &[Pattern] {
        &[]
    }

    fn add_pattern(&mut self, _pattern: Pattern) -> AnalysisResult<()> {
        Ok(())
    }
}

struct CountingAnalyzer {
    calls: Arc<AtomicUsize>,
}

impl StringAnalyzer for CountingAnalyzer {
    fn analyze(&self, _value: &str) -> StringAnalysis {
        self.calls.fetch_add(1, Ordering::SeqCst);
        neutral_analysis()
    }

    fn calculate_entropy(&self, _value: &str) -> f64 {
        0.0
    }

    fn get_patterns(&self) -> &[Pattern] {
        &[]
    }

    fn add_pattern(&mut self, _pattern: Pattern) -> AnalysisResult<()> {
        Ok(())
    }
}

struct MultiIndicatorAnalyzer;

impl StringAnalyzer for MultiIndicatorAnalyzer {
    fn analyze(&self, _value: &str) -> StringAnalysis {
        StringAnalysis {
            entropy: 0.0,
            categories: Default::default(),
            suspicious_indicators: vec![test_indicator("weak", 6), test_indicator("strong", 9)],
            indicators_truncated: false,
            is_suspicious: true,
        }
    }

    fn calculate_entropy(&self, _value: &str) -> f64 {
        0.0
    }

    fn get_patterns(&self) -> &[Pattern] {
        &[]
    }

    fn add_pattern(&mut self, _pattern: Pattern) -> AnalysisResult<()> {
        Ok(())
    }
}

struct FixedEntropyAnalyzer;

impl StringAnalyzer for FixedEntropyAnalyzer {
    fn analyze(&self, _value: &str) -> StringAnalysis {
        StringAnalysis {
            entropy: 5.0,
            categories: Default::default(),
            suspicious_indicators: Vec::new(),
            indicators_truncated: false,
            is_suspicious: false,
        }
    }

    fn calculate_entropy(&self, _value: &str) -> f64 {
        5.0
    }

    fn get_patterns(&self) -> &[Pattern] {
        &[]
    }

    fn add_pattern(&mut self, _pattern: Pattern) -> AnalysisResult<()> {
        Ok(())
    }
}

struct TruncatedAnalyzer;

impl StringAnalyzer for TruncatedAnalyzer {
    fn analyze(&self, _value: &str) -> StringAnalysis {
        StringAnalysis {
            entropy: 0.0,
            categories: Default::default(),
            suspicious_indicators: Vec::new(),
            indicators_truncated: true,
            is_suspicious: false,
        }
    }

    fn calculate_entropy(&self, _value: &str) -> f64 {
        0.0
    }

    fn get_patterns(&self) -> &[Pattern] {
        &[]
    }

    fn add_pattern(&mut self, _pattern: Pattern) -> AnalysisResult<()> {
        Ok(())
    }
}

fn neutral_analysis() -> StringAnalysis {
    StringAnalysis {
        entropy: 0.0,
        categories: Default::default(),
        suspicious_indicators: Vec::new(),
        indicators_truncated: false,
        is_suspicious: false,
    }
}

fn test_indicator(pattern_name: &str, severity: u8) -> SuspiciousIndicator {
    SuspiciousIndicator {
        pattern_name: pattern_name.to_string(),
        description: "Custom analyzer retention regression".to_string(),
        severity,
        matched_text: None,
        matched_text_truncated: false,
    }
}

struct CountingCategorizer {
    calls: Arc<AtomicUsize>,
}

struct OversizedCategorizer;

impl Categorizer for OversizedCategorizer {
    fn categorize(&self, _value: &str) -> Vec<StringCategory> {
        ["one", "two", "three"]
            .into_iter()
            .map(|name| StringCategory {
                name: name.to_string(),
                parent: None,
                description: "Capacity regression".to_string(),
            })
            .collect()
    }

    fn add_rule(&mut self, _rule: CategoryRule) -> AnalysisResult<()> {
        Ok(())
    }

    fn remove_rule(&mut self, _name: &str) -> AnalysisResult<()> {
        Ok(())
    }

    fn get_categories(&self) -> Vec<StringCategory> {
        Vec::new()
    }
}

struct OneCategoryCategorizer {
    category: StringCategory,
}

impl Categorizer for OneCategoryCategorizer {
    fn categorize(&self, _value: &str) -> Vec<StringCategory> {
        vec![self.category.clone()]
    }

    fn add_rule(&mut self, _rule: CategoryRule) -> AnalysisResult<()> {
        Ok(())
    }

    fn remove_rule(&mut self, _name: &str) -> AnalysisResult<()> {
        Ok(())
    }

    fn get_categories(&self) -> Vec<StringCategory> {
        vec![self.category.clone()]
    }
}

impl Categorizer for CountingCategorizer {
    fn categorize(&self, _value: &str) -> Vec<StringCategory> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        vec![StringCategory {
            name: "generic".to_string(),
            parent: None,
            description: "Generic test category".to_string(),
        }]
    }

    fn add_rule(&mut self, _rule: CategoryRule) -> AnalysisResult<()> {
        Ok(())
    }

    fn remove_rule(&mut self, _name: &str) -> AnalysisResult<()> {
        Ok(())
    }

    fn get_categories(&self) -> Vec<StringCategory> {
        Vec::new()
    }
}

#[test]
fn clear_preserves_configuration() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    tracker.track_string("value", "a", "h", "tool", context())?;
    let config = tracker.config().clone();
    tracker.clear();
    assert_eq!(tracker.get_statistics(None)?.total_unique_strings, 0);
    assert_eq!(tracker.config(), &config);
    Ok(())
}
