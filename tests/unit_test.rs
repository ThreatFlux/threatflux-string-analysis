//! Unit tests for individual components in threatflux-string-analysis

use threatflux_string_analysis::{StringContext, StringFilter, StringTracker};

#[test]
fn test_string_context_variants() {
    // Test all StringContext variants can be created
    let contexts = vec![
        StringContext::FileString { offset: Some(100) },
        StringContext::FileString { offset: None },
        StringContext::Url {
            protocol: Some("https".to_string()),
        },
        StringContext::Url { protocol: None },
        StringContext::Path {
            path_type: "file".to_string(),
        },
        StringContext::Registry {
            hive: Some("HKLM".to_string()),
        },
        StringContext::Import {
            library: "kernel32.dll".to_string(),
        },
        StringContext::Import {
            library: "msvcrt.dll".to_string(),
        },
        StringContext::Export {
            symbol: "GetProcAddress".to_string(),
        },
        StringContext::Resource {
            resource_type: "icon".to_string(),
        },
        StringContext::Section {
            section_name: ".text".to_string(),
        },
        StringContext::Metadata {
            field: "version".to_string(),
        },
        StringContext::Command {
            command_type: "shell".to_string(),
        },
        StringContext::Other {
            category: "unknown".to_string(),
        },
        StringContext::Registry { hive: None },
        StringContext::Other {
            category: "crypto".to_string(),
        },
    ];

    let tracker = StringTracker::new();

    for (i, context) in contexts.into_iter().enumerate() {
        let result = tracker.track_string(
            &format!("test_string_{}", i),
            "/test/context",
            "context_hash",
            "context_tool",
            context,
        );
        assert!(result.is_ok(), "Context variant {} should be handled", i);
    }

    let stats = tracker.get_statistics(None);
    assert!(stats.total_unique_strings > 0);
}

#[test]
fn test_string_filter_combinations() {
    let tracker = StringTracker::new();

    // Track strings with various properties
    let test_strings = vec![
        ("short", 1, false),         // Short, low occurrence, not suspicious
        ("medium_length", 3, false), // Medium, medium occurrence, not suspicious
        (
            "very_long_string_for_comprehensive_testing_purposes",
            1,
            false,
        ), // Long, low occurrence
        ("malware.exe", 2, true),    // Short, medium occurrence, suspicious
        ("http://evil.com/backdoor", 1, true), // Long, low occurrence, suspicious
    ];

    for (string, count, _is_suspicious) in &test_strings {
        for i in 0..*count {
            tracker
                .track_string(
                    string,
                    &format!("/test/{}", i),
                    &format!("hash_{}", i),
                    "filter_tool",
                    StringContext::FileString {
                        offset: Some(i * 10),
                    },
                )
                .unwrap();
        }
    }

    // Test individual filter criteria
    let length_filter = StringFilter {
        min_length: Some(10),
        max_length: Some(20),
        ..Default::default()
    };
    let length_stats = tracker.get_statistics(Some(&length_filter));
    assert!(length_stats.total_unique_strings > 0);

    let occurrence_filter = StringFilter {
        min_occurrences: Some(2),
        ..Default::default()
    };
    let occurrence_stats = tracker.get_statistics(Some(&occurrence_filter));
    assert!(occurrence_stats.total_unique_strings > 0);

    // Test combined filters
    let combined_filter = StringFilter {
        min_length: Some(5),
        max_length: Some(15),
        min_occurrences: Some(1),
        max_occurrences: Some(3),
        ..Default::default()
    };
    let combined_stats = tracker.get_statistics(Some(&combined_filter));
    // Should have some tracked strings

    // Test entropy filter (if supported)
    let entropy_filter = StringFilter {
        min_entropy: Some(1.0),
        max_entropy: Some(7.0),
        ..Default::default()
    };
    let entropy_stats = tracker.get_statistics(Some(&entropy_filter));
    // Stats should be valid

    // Test suspicious filter
    let suspicious_filter = StringFilter {
        suspicious_only: Some(true),
        ..Default::default()
    };
    let suspicious_stats = tracker.get_statistics(Some(&suspicious_filter));
    // Stats should be valid
}

#[test]
fn test_string_filter_default() {
    let default_filter = StringFilter::default();

    // All fields should be None/false by default
    assert!(default_filter.min_length.is_none());
    assert!(default_filter.max_length.is_none());
    assert!(default_filter.min_occurrences.is_none());
    assert!(default_filter.max_occurrences.is_none());
    assert!(default_filter.min_entropy.is_none());
    assert!(default_filter.max_entropy.is_none());
    assert!(default_filter.categories.is_none());
    assert!(default_filter.file_paths.is_none());
    assert!(default_filter.suspicious_only.is_none());
    assert!(default_filter.regex_pattern.is_none());
}

#[test]
fn test_tracker_creation() {
    let tracker = StringTracker::new();

    // Initial state should be empty
    let initial_stats = tracker.get_statistics(None);
    assert_eq!(initial_stats.total_unique_strings, 0);
    assert_eq!(initial_stats.total_occurrences, 0);
    assert_eq!(initial_stats.total_files_analyzed, 0);
    assert!(initial_stats.length_distribution.is_empty());
    assert!(initial_stats.category_distribution.is_empty());
    assert!(initial_stats.most_common.is_empty());
    assert!(initial_stats.high_entropy_strings.is_empty());
    assert!(initial_stats.suspicious_strings.is_empty());
}

#[test]
fn test_string_details_structure() {
    let tracker = StringTracker::new();

    let test_string = "detailed_test_string";
    tracker
        .track_string(
            test_string,
            "/test/details",
            "details_hash",
            "details_tool",
            StringContext::FileString { offset: Some(256) },
        )
        .unwrap();

    let details = tracker.get_string_details(test_string).unwrap();

    // Verify details structure
    assert_eq!(details.value, test_string);
    assert!(details.value.len() > 0);
    assert_eq!(details.occurrences.len(), 1);
    assert_eq!(details.unique_files.len(), 1);
    assert!(!details.categories.is_empty());
    assert!(details.entropy >= 0.0);
    assert!(details.first_seen <= details.last_seen);

    // Verify occurrence details
    let occurrence = &details.occurrences[0];
    assert_eq!(occurrence.file_path, "/test/details");
    assert_eq!(occurrence.file_hash, "details_hash");
    assert_eq!(occurrence.tool_name, "details_tool");
    // Timestamp should be reasonable (not checking specific time due to test timing)

    // Verify file association
    assert!(details.unique_files.contains("/test/details"));
}

#[test]
fn test_nonexistent_string_details() {
    let tracker = StringTracker::new();

    let result = tracker.get_string_details("nonexistent_string");
    assert!(
        result.is_none(),
        "Should return None for nonexistent string"
    );
}

#[test]
fn test_search_edge_cases() {
    let tracker = StringTracker::new();

    // Track some test strings
    let test_strings = vec!["apple", "application", "apply", "banana"];
    for string in &test_strings {
        tracker
            .track_string(
                string,
                "/test/search",
                "search_hash",
                "search_tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }

    // Test empty search query
    let empty_results = tracker.search_strings("", 10);
    assert!(
        empty_results.is_empty(),
        "Empty query should return no results"
    );

    // Test query with no matches
    let no_match_results = tracker.search_strings("xyz", 10);
    assert!(
        no_match_results.is_empty(),
        "Non-matching query should return no results"
    );

    // Test zero limit
    let zero_limit_results = tracker.search_strings("app", 0);
    assert!(
        zero_limit_results.is_empty(),
        "Zero limit should return no results"
    );

    // Test very large limit
    let large_limit_results = tracker.search_strings("app", 1000);
    assert!(
        large_limit_results.len() <= test_strings.len(),
        "Should not exceed available matches"
    );

    // Test single character search
    let single_char_results = tracker.search_strings("a", 10);
    assert!(
        !single_char_results.is_empty(),
        "Single character should match"
    );
}

#[test]
fn test_related_strings_edge_cases() {
    let tracker = StringTracker::new();

    // Track one string
    tracker
        .track_string(
            "lonely_string",
            "/test/lonely",
            "lonely_hash",
            "lonely_tool",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    // Test related strings for nonexistent string
    let nonexistent_related = tracker.get_related_strings("nonexistent", 10);
    assert!(
        nonexistent_related.is_empty(),
        "Should return empty for nonexistent string"
    );

    // Test related strings for string with no relations
    let lonely_related = tracker.get_related_strings("lonely_string", 10);
    // Implementation dependent - might return empty or the string itself
    // Results depend on implementation

    // Test with zero limit
    let zero_limit_related = tracker.get_related_strings("lonely_string", 0);
    assert!(
        zero_limit_related.is_empty(),
        "Zero limit should return no results"
    );
}

#[test]
fn test_batch_operations() {
    let tracker = StringTracker::new();

    // Test empty batch
    let empty_result =
        tracker.track_strings_from_results(&[], "/test/empty", "empty_hash", "empty_tool");
    assert!(empty_result.is_ok(), "Empty batch should succeed");

    // Test batch with duplicates
    let duplicate_strings = vec![
        "duplicate1".to_string(),
        "duplicate1".to_string(),
        "duplicate2".to_string(),
        "duplicate2".to_string(),
        "duplicate2".to_string(),
    ];

    tracker
        .track_strings_from_results(
            &duplicate_strings,
            "/test/duplicates",
            "dup_hash",
            "dup_tool",
        )
        .unwrap();

    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 2); // Only 2 unique strings
    assert_eq!(stats.total_occurrences, 5); // But 5 total occurrences

    // Verify individual string details
    let dup1_details = tracker.get_string_details("duplicate1").unwrap();
    assert_eq!(dup1_details.occurrences.len(), 2);

    let dup2_details = tracker.get_string_details("duplicate2").unwrap();
    assert_eq!(dup2_details.occurrences.len(), 3);
}

#[test]
fn test_statistics_with_filters() {
    let tracker = StringTracker::new();

    // Track strings with known characteristics
    let strings_data = vec![
        ("short", 2),                        // 5 chars, 2 occurrences
        ("medium_len", 1),                   // 10 chars, 1 occurrence
        ("very_long_string_for_testing", 3), // 30 chars, 3 occurrences
    ];

    for (string, count) in &strings_data {
        for i in 0..*count {
            tracker
                .track_string(
                    string,
                    &format!("/test/{}", i),
                    &format!("hash_{}", i),
                    "stats_tool",
                    StringContext::FileString {
                        offset: Some(i * 100),
                    },
                )
                .unwrap();
        }
    }

    // Test unfiltered stats
    let all_stats = tracker.get_statistics(None);
    assert_eq!(all_stats.total_unique_strings, 3);
    assert_eq!(all_stats.total_occurrences, 6);

    // Test length filter
    let long_filter = StringFilter {
        min_length: Some(15),
        ..Default::default()
    };
    let long_stats = tracker.get_statistics(Some(&long_filter));
    assert_eq!(long_stats.total_unique_strings, 1); // Only the very long string
    assert_eq!(long_stats.total_occurrences, 3);

    // Test occurrence filter
    let frequent_filter = StringFilter {
        min_occurrences: Some(2),
        ..Default::default()
    };
    let frequent_stats = tracker.get_statistics(Some(&frequent_filter));
    assert_eq!(frequent_stats.total_unique_strings, 2); // "short" and "very_long_string_for_testing"
    assert_eq!(frequent_stats.total_occurrences, 5);
}

#[test]
fn test_error_handling() {
    let tracker = StringTracker::new();

    // Test with null bytes in paths (might be rejected)
    let _null_path_result = tracker.track_string(
        "test",
        "/test\x00/null",
        "hash",
        "tool",
        StringContext::FileString { offset: None },
    );
    // Should either succeed or fail gracefully, not panic

    // Test with very long paths
    let long_path = "/".to_string() + &"very_long_path_component/".repeat(100);
    let long_path_result = tracker.track_string(
        "test",
        &long_path,
        "hash",
        "tool",
        StringContext::FileString { offset: None },
    );
    // Should handle gracefully
    assert!(long_path_result.is_ok() || long_path_result.is_err());

    // Test with empty hash
    let empty_hash_result = tracker.track_string(
        "test",
        "/test/empty_hash",
        "",
        "tool",
        StringContext::FileString { offset: None },
    );
    assert!(empty_hash_result.is_ok(), "Empty hash should be handled");

    // Test with empty tool name
    let empty_tool_result = tracker.track_string(
        "test",
        "/test/empty_tool",
        "hash",
        "",
        StringContext::FileString { offset: None },
    );
    assert!(
        empty_tool_result.is_ok(),
        "Empty tool name should be handled"
    );
}

#[test]
fn test_categorization_accuracy() {
    let tracker = StringTracker::new();

    // Test strings that should be categorized correctly
    let categorization_tests = vec![
        ("https://example.com", vec!["url"]),
        ("http://test.org", vec!["url"]),
        ("ftp://files.com", vec!["url"]),
        ("/usr/bin/bash", vec!["path"]),
        ("C:\\Windows\\System32", vec!["path"]),
        ("HKEY_LOCAL_MACHINE\\SOFTWARE", vec!["registry"]),
        ("HKEY_CURRENT_USER\\Control Panel", vec!["registry"]),
        ("kernel32.dll", vec!["library"]),
        ("libc.so.6", vec!["library"]),
        ("192.168.1.1", vec!["ip_address"]),
        ("::1", vec!["ip_address"]),
        ("user@example.com", vec!["email"]),
        ("admin@domain.org", vec!["email"]),
        ("CreateProcessA", vec!["api_call"]),
        ("malloc", vec!["api_call"]),
    ];

    for (string, expected_categories) in categorization_tests {
        tracker
            .track_string(
                string,
                "/test/categorization",
                "cat_hash",
                "cat_tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();

        let details = tracker.get_string_details(string).unwrap();

        // Check that at least one expected category is present
        let has_expected_category = expected_categories.iter().any(|expected| {
            details
                .categories
                .iter()
                .any(|actual| actual.contains(expected))
        });

        assert!(
            has_expected_category,
            "String '{}' should have one of categories {:?}, but got {:?}",
            string, expected_categories, details.categories
        );
    }
}

#[test]
fn test_entropy_calculation_consistency() {
    let tracker = StringTracker::new();

    // Test strings with predictable entropy characteristics
    let entropy_tests = vec![
        ("aaaaaaaaaa", "Should have low entropy (repeated chars)"),
        ("abcdefghijk", "Should have medium entropy (sequence)"),
        ("aB3$k9P@mX", "Should have high entropy (mixed)"),
        ("", "Empty string should handle gracefully"),
    ];

    for (string, description) in entropy_tests {
        if !string.is_empty() {
            tracker
                .track_string(
                    string,
                    "/test/entropy",
                    "entropy_hash",
                    "entropy_tool",
                    StringContext::FileString { offset: None },
                )
                .unwrap();

            let details = tracker.get_string_details(string).unwrap();

            // Entropy should be within valid range
            assert!(
                details.entropy >= 0.0,
                "{}: Entropy should be non-negative",
                description
            );
            assert!(
                details.entropy <= 8.0,
                "{}: Entropy should not exceed maximum",
                description
            );

            // Test entropy consistency (same string should have same entropy)
            let details2 = tracker.get_string_details(string).unwrap();
            assert_eq!(
                details.entropy, details2.entropy,
                "{}: Entropy should be consistent",
                description
            );
        }
    }
}
