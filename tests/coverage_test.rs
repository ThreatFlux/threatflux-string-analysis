use threatflux_string_analysis::{
    AnalysisConfig, DefaultCategorizer, DefaultPatternProvider, DefaultStringAnalyzer,
    Pattern, PatternDef, PatternProvider, StringAnalyzer, Categorizer,
};
use regex::Regex;

#[test]
fn test_analysis_config_default() {
    let mut config = AnalysisConfig::default();
    assert_eq!(config.min_suspicious_entropy, 4.5);
    assert_eq!(config.max_occurrences_per_string, 1000);
    assert!(config.enable_time_analysis);
    assert!(config.custom_metadata_fields.is_empty());
    config.custom_metadata_fields.push("source".to_string());
    assert_eq!(config.custom_metadata_fields.len(), 1);
}

#[test]
fn test_pattern_provider_modifications() {
    let mut provider = DefaultPatternProvider::empty();
    let pattern_def = PatternDef {
        name: "custom".to_string(),
        regex: r"foo".to_string(),
        category: "test".to_string(),
        description: "custom pattern".to_string(),
        is_suspicious: false,
        severity: 1,
    };

    provider.add_pattern(pattern_def.clone()).unwrap();
    assert_eq!(provider.get_patterns().len(), 1);

    provider
        .update_pattern(PatternDef {
            regex: r"bar".to_string(),
            ..pattern_def.clone()
        })
        .unwrap();
    let patterns = provider.get_patterns();
    assert_eq!(patterns.len(), 1);
    assert!(patterns[0].regex.is_match("bar"));

    provider.remove_pattern(&pattern_def.name).unwrap();
    assert!(provider.get_patterns().is_empty());

    // Invalid regex should error
    let bad_def = PatternDef {
        regex: "[".to_string(),
        ..pattern_def
    };
    assert!(bad_def.compile().is_err());
}

#[test]
fn test_analyzer_entropy_and_nonprintable() {
    let mut analyzer = DefaultStringAnalyzer::new();

    let high_entropy = "a1b2c3d4e5f6g7h8i9j0k!l@m#n$";
    let analysis = analyzer.analyze(high_entropy);
    assert!(analysis
        .suspicious_indicators
        .iter()
        .any(|i| i.pattern_name == "high_entropy"));

    let non_printable = "test\x07string";
    let analysis_np = analyzer.analyze(non_printable);
    assert!(analysis_np
        .suspicious_indicators
        .iter()
        .any(|i| i.pattern_name == "non_printable_chars"));

    assert_eq!(analyzer.calculate_entropy(""), 0.0);

    analyzer
        .add_pattern(Pattern {
            name: "foo".to_string(),
            regex: Regex::new("foo").unwrap(),
            category: "test".to_string(),
            description: "test pattern".to_string(),
            is_suspicious: true,
            severity: 5,
        })
        .unwrap();
    assert!(analyzer.is_suspicious("foo"));
    assert_eq!(analyzer.get_patterns().len(), 1);
}

#[test]
fn test_categorizer_additional_rules() {
    let categorizer = DefaultCategorizer::new();

    let command = categorizer.categorize("/bin/ls");
    assert!(command.iter().any(|c| c.name == "command"));

    let api = categorizer.categorize("CreateProcess");
    assert!(api.iter().any(|c| c.name == "api_call"));

    let ipv6 = categorizer.categorize("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assert!(ipv6.iter().any(|c| c.name == "ip_address"));
}
use threatflux_string_analysis::{StringTracker, StringContext, StringFilter};

#[test]
fn test_tracker_regex_and_hash_filter() {
    let tracker = StringTracker::new();
    tracker
        .track_string(
            "alpha",
            "/path/a",
            "hash_a",
            "tool",
            StringContext::FileString { offset: None },
        )
        .unwrap();
    tracker
        .track_string(
            "beta",
            "/path/b",
            "hash_b",
            "tool",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    let regex_filter = StringFilter {
        regex_pattern: Some("^alpha$".to_string()),
        ..Default::default()
    };
    let regex_stats = tracker.get_statistics(Some(&regex_filter));
    assert_eq!(regex_stats.total_unique_strings, 1);

    let hash_filter = StringFilter {
        file_hashes: Some(vec!["/path/b".to_string()]),
        ..Default::default()
    };
    let hash_stats = tracker.get_statistics(Some(&hash_filter));
    assert_eq!(hash_stats.total_unique_strings, 1);
}
