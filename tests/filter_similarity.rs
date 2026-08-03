use chrono::{Duration, TimeZone, Utc};
use threatflux_string_analysis::{
    AnalysisConfig, AnalysisError, AnalysisResult, StringContext, StringFilter, StringOccurrence,
    StringTracker,
};

fn occurrence(path: &str, hash: &str, timestamp: chrono::DateTime<Utc>) -> StringOccurrence {
    StringOccurrence::new(
        path,
        hash,
        "tool",
        timestamp,
        StringContext::FileString { offset: None },
    )
}

#[test]
fn paths_hashes_regex_and_first_seen_ranges_filter_correctly() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    let first = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
    let second = first + Duration::days(1);
    tracker.track_occurrence("alpha", occurrence("/path/a", "hash_a", first))?;
    tracker.track_occurrence("beta", occurrence("/path/b", "hash_b", second))?;

    assert_eq!(
        tracker
            .get_statistics(Some(&StringFilter {
                file_paths: Some(vec!["/path/b".to_string()]),
                ..StringFilter::default()
            }))?
            .most_common[0]
            .0,
        "beta"
    );
    assert_eq!(
        tracker
            .get_statistics(Some(&StringFilter {
                file_hashes: Some(vec!["hash_a".to_string()]),
                ..StringFilter::default()
            }))?
            .most_common[0]
            .0,
        "alpha"
    );
    assert_eq!(
        tracker
            .get_statistics(Some(&StringFilter {
                // Regression: a path supplied as a hash must not match.
                file_hashes: Some(vec!["/path/b".to_string()]),
                ..StringFilter::default()
            }))?
            .total_unique_strings,
        0
    );
    assert_eq!(
        tracker
            .get_statistics(Some(&StringFilter {
                regex_pattern: Some("^alp".to_string()),
                ..StringFilter::default()
            }))?
            .most_common[0]
            .0,
        "alpha"
    );
    assert_eq!(
        tracker
            .get_statistics(Some(&StringFilter {
                date_range: Some((second, second)),
                ..StringFilter::default()
            }))?
            .most_common[0]
            .0,
        "beta"
    );
    Ok(())
}

#[test]
fn malformed_and_contradictory_filters_are_rejected() {
    let tracker = StringTracker::new();
    assert!(matches!(
        tracker.get_statistics(Some(&StringFilter {
            regex_pattern: Some("[".to_string()),
            ..StringFilter::default()
        })),
        Err(AnalysisError::InvalidRegex { .. })
    ));
    assert!(matches!(
        tracker.get_statistics(Some(&StringFilter {
            min_occurrences: Some(2),
            max_occurrences: Some(1),
            ..StringFilter::default()
        })),
        Err(AnalysisError::InvalidFilter {
            field: "occurrences",
            ..
        })
    ));
    assert!(matches!(
        tracker.get_statistics(Some(&StringFilter {
            min_entropy: Some(f64::NAN),
            ..StringFilter::default()
        })),
        Err(AnalysisError::InvalidFilter {
            field: "min_entropy",
            ..
        })
    ));
    let now = Utc::now();
    assert!(matches!(
        tracker.get_statistics(Some(&StringFilter {
            date_range: Some((now, now - Duration::seconds(1))),
            ..StringFilter::default()
        })),
        Err(AnalysisError::InvalidFilter {
            field: "date_range",
            ..
        })
    ));
}

#[test]
fn filter_fields_and_cross_field_and_semantics_match_the_contract() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    tracker.track_string(
        "rootkit",
        "/command",
        "hash-command",
        "tool",
        StringContext::Command {
            command_type: "shell".to_string(),
        },
    )?;
    tracker.track_string(
        "rootkit",
        "/command",
        "hash-command",
        "tool",
        StringContext::Command {
            command_type: "shell".to_string(),
        },
    )?;
    tracker.track_string(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "/entropy",
        "hash-entropy",
        "tool",
        StringContext::FileString { offset: None },
    )?;
    tracker.track_string(
        "plain",
        "/plain",
        "hash-plain",
        "tool",
        StringContext::FileString { offset: None },
    )?;

    for (filter, expected) in [
        (
            StringFilter {
                min_occurrences: Some(2),
                ..StringFilter::default()
            },
            1,
        ),
        (
            StringFilter {
                max_occurrences: Some(1),
                ..StringFilter::default()
            },
            2,
        ),
        (
            StringFilter {
                min_length: Some(30),
                ..StringFilter::default()
            },
            1,
        ),
        (
            StringFilter {
                max_length: Some(5),
                ..StringFilter::default()
            },
            1,
        ),
        (
            StringFilter {
                categories: Some(vec!["command".to_string()]),
                ..StringFilter::default()
            },
            1,
        ),
        (
            StringFilter {
                suspicious_only: Some(true),
                ..StringFilter::default()
            },
            2,
        ),
        (
            StringFilter {
                suspicious_only: Some(false),
                ..StringFilter::default()
            },
            3,
        ),
        (
            StringFilter {
                min_entropy: Some(4.5),
                ..StringFilter::default()
            },
            1,
        ),
        (
            StringFilter {
                max_entropy: Some(3.0),
                ..StringFilter::default()
            },
            2,
        ),
        (
            StringFilter {
                min_occurrences: Some(2),
                max_length: Some(10),
                categories: Some(vec!["command".to_string()]),
                suspicious_only: Some(true),
                max_entropy: Some(3.0),
                ..StringFilter::default()
            },
            1,
        ),
    ] {
        assert_eq!(
            tracker.get_statistics(Some(&filter))?.total_unique_strings,
            expected,
            "unexpected result for {filter:?}"
        );
    }

    for filter in [
        StringFilter {
            categories: Some(Vec::new()),
            ..StringFilter::default()
        },
        StringFilter {
            file_paths: Some(Vec::new()),
            ..StringFilter::default()
        },
        StringFilter {
            file_hashes: Some(Vec::new()),
            ..StringFilter::default()
        },
    ] {
        assert_eq!(
            tracker.get_statistics(Some(&filter))?.total_unique_strings,
            0
        );
    }
    Ok(())
}

#[test]
fn filter_regex_has_a_hard_source_limit() {
    let tracker = StringTracker::with_config(AnalysisConfig {
        max_source_bytes: usize::MAX,
        ..AnalysisConfig::default()
    })
    .unwrap();
    assert!(matches!(
        tracker.get_statistics(Some(&StringFilter {
            regex_pattern: Some(" ".repeat(65_537)),
            ..StringFilter::default()
        })),
        Err(AnalysisError::InvalidFilter {
            field: "regex_pattern",
            ..
        })
    ));
}

#[test]
fn statistics_and_search_ties_are_deterministic() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    for value in ["charlie", "alpha", "bravo"] {
        tracker.track_string(
            value,
            "path",
            "hash",
            "tool",
            StringContext::FileString { offset: None },
        )?;
    }

    let first = tracker.get_statistics(None)?;
    let second = tracker.get_statistics(None)?;
    assert_eq!(first, second);
    assert_eq!(
        first
            .most_common
            .iter()
            .map(|(value, _)| value.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "bravo", "charlie"]
    );
    let results = tracker.search_strings("a", 10)?;
    assert_eq!(
        results
            .iter()
            .map(|entry| entry.value.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "bravo", "charlie"]
    );
    assert!(tracker.search_strings("a", 0)?.is_empty());
    Ok(())
}

#[test]
fn search_input_is_bounded() {
    let tracker = StringTracker::with_config(AnalysisConfig {
        max_input_bytes: 3,
        ..AnalysisConfig::default()
    })
    .unwrap();
    assert!(matches!(
        tracker.search_strings("four", 1),
        Err(AnalysisError::InputTooLarge { field: "query", .. })
    ));
}

#[test]
fn search_uses_unicode_lowercase_matching() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    tracker.track_string(
        "CAFÉ-Δelta",
        "path",
        "hash",
        "tool",
        StringContext::FileString { offset: None },
    )?;

    let results = tracker.search_strings("café-δ", 10)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "CAFÉ-Δelta");
    Ok(())
}

#[test]
fn related_scores_require_contextual_evidence_and_never_nan() -> AnalysisResult<()> {
    let tracker = StringTracker::new();
    tracker.track_string(
        "alpha",
        "shared",
        "same",
        "tool",
        StringContext::FileString { offset: None },
    )?;
    tracker.track_string(
        "bravo",
        "shared",
        "same",
        "tool",
        StringContext::FileString { offset: None },
    )?;
    tracker.track_string(
        "charm",
        "other",
        "different",
        "tool",
        StringContext::FileString { offset: None },
    )?;

    let related = tracker.get_related_strings("alpha", 10)?;
    assert!(related.iter().any(|(value, _)| value == "bravo"));
    assert!(related.iter().all(|(value, _)| value != "charm"));
    assert!(related.iter().all(|(_, score)| score.is_finite()));
    assert!(tracker.get_related_strings("missing", 10)?.is_empty());
    assert!(tracker.get_related_strings("alpha", 0)?.is_empty());
    Ok(())
}

#[test]
fn high_entropy_statistics_use_the_configured_threshold() -> AnalysisResult<()> {
    let tracker = StringTracker::with_config(AnalysisConfig {
        min_suspicious_entropy: 7.5,
        ..AnalysisConfig::default()
    })?;
    tracker.track_string(
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "path",
        "hash",
        "tool",
        StringContext::FileString { offset: None },
    )?;
    let stats = tracker.get_statistics(None)?;
    assert_eq!(stats.total_high_entropy_strings, 0);
    assert!(stats.high_entropy_strings.is_empty());
    Ok(())
}

#[test]
fn high_entropy_statistics_apply_the_analyzers_minimum_input_length() -> AnalysisResult<()> {
    let tracker = StringTracker::with_config(AnalysisConfig {
        min_suspicious_entropy: 0.0,
        ..AnalysisConfig::default()
    })?;
    tracker.track_string(
        "short",
        "path",
        "hash",
        "tool",
        StringContext::FileString { offset: None },
    )?;

    let stats = tracker.get_statistics(None)?;
    assert_eq!(stats.total_high_entropy_strings, 0);
    assert!(stats.high_entropy_strings.is_empty());
    assert!(!tracker.get_string_details("short").unwrap().is_suspicious);
    Ok(())
}

#[test]
fn statistic_samples_are_bounded_without_losing_exact_totals() -> AnalysisResult<()> {
    let common_tracker = StringTracker::new();
    for index in 0..105 {
        common_tracker.track_string(
            &format!("ordinary-{index:03}"),
            "path",
            "hash",
            "tool",
            StringContext::FileString { offset: None },
        )?;
    }
    let stats = common_tracker.get_statistics(None)?;
    assert_eq!(stats.total_unique_strings, 105);
    assert_eq!(stats.most_common.len(), 100);
    assert_eq!(stats.most_common.first().unwrap().0, "ordinary-000");
    assert_eq!(stats.most_common.last().unwrap().0, "ordinary-099");

    let suspicious_tracker = StringTracker::new();
    for index in 0..55 {
        suspicious_tracker.track_string(
            &format!("rootkit-{index:03}"),
            "path",
            "hash",
            "tool",
            StringContext::FileString { offset: None },
        )?;
    }
    let stats = suspicious_tracker.get_statistics(None)?;
    assert_eq!(stats.total_suspicious_strings, 55);
    assert_eq!(stats.suspicious_strings.len(), 50);
    assert_eq!(stats.suspicious_strings.first().unwrap(), "rootkit-000");
    assert_eq!(stats.suspicious_strings.last().unwrap(), "rootkit-049");

    let entropy_tracker = StringTracker::new();
    for index in 0..55 {
        entropy_tracker.track_string(
            &format!("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-{index:03}"),
            "path",
            "hash",
            "tool",
            StringContext::FileString { offset: None },
        )?;
    }
    let stats = entropy_tracker.get_statistics(None)?;
    assert_eq!(stats.total_high_entropy_strings, 55);
    assert_eq!(stats.high_entropy_strings.len(), 50);
    Ok(())
}

#[test]
fn suspicious_ranking_uses_the_strongest_signal_seen_before_truncation() -> AnalysisResult<()> {
    let tracker = StringTracker::with_config(AnalysisConfig {
        max_indicators_per_string: 1,
        ..AnalysisConfig::default()
    })?;
    tracker.track_string(
        "cmd.exe /c load rootkit",
        "path",
        "hash",
        "tool",
        StringContext::FileString { offset: None },
    )?;
    tracker.track_string(
        "password = example",
        "path",
        "hash",
        "tool",
        StringContext::FileString { offset: None },
    )?;

    let stats = tracker.get_statistics(None)?;
    assert_eq!(stats.suspicious_strings[0], "cmd.exe /c load rootkit");
    assert_eq!(
        tracker
            .get_string_details("cmd.exe /c load rootkit")
            .unwrap()
            .suspicious_indicators[0]
            .severity,
        9
    );
    Ok(())
}
