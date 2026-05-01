use threatflux_string_analysis::{StringContext, StringFilter, StringTracker};

#[test]
fn test_basic_functionality() {
    let tracker = StringTracker::new();

    // Track a string
    tracker
        .track_string(
            "test string",
            "/test/file",
            "hash123",
            "test_tool",
            StringContext::FileString { offset: Some(100) },
        )
        .unwrap();

    // Get statistics
    let stats = tracker.get_statistics(None);
    assert_eq!(stats.total_unique_strings, 1);
    assert_eq!(stats.total_occurrences, 1);

    // Search for string
    let results = tracker.search_strings("test", 10);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].value, "test string");
}

#[test]
fn test_suspicious_detection() {
    let tracker = StringTracker::new();

    // Track a suspicious URL
    tracker
        .track_string(
            "http://malware.com/payload",
            "/malware.exe",
            "bad_hash",
            "scanner",
            StringContext::Url {
                protocol: Some("http".to_string()),
            },
        )
        .unwrap();

    // Track a benign string
    tracker
        .track_string(
            "Hello World",
            "/hello.txt",
            "good_hash",
            "scanner",
            StringContext::FileString { offset: None },
        )
        .unwrap();

    // Filter for suspicious only
    let filter = StringFilter {
        suspicious_only: Some(true),
        ..Default::default()
    };

    let stats = tracker.get_statistics(Some(&filter));
    assert_eq!(stats.total_unique_strings, 1);
    assert!(stats
        .suspicious_strings
        .contains(&"http://malware.com/payload".to_string()));
}

#[test]
fn test_categorization() {
    let tracker = StringTracker::new();

    // Track strings from different categories
    let test_cases = vec![
        ("https://example.com", "url"),
        ("/usr/bin/test", "path"),
        ("HKEY_LOCAL_MACHINE\\SOFTWARE", "registry"),
        ("kernel32.dll", "library"),
        ("192.168.1.1", "ip_address"),
    ];

    for (string, expected_category) in test_cases {
        tracker
            .track_strings_from_results(&[string.to_string()], "/test/file", "hash123", "test_tool")
            .unwrap();

        let details = tracker.get_string_details(string).unwrap();
        assert!(
            details
                .categories
                .iter()
                .any(|c| c.contains(expected_category)),
            "String '{}' should have category '{}'",
            string,
            expected_category
        );
    }
}
