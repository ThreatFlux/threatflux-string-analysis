use threatflux_string_analysis::{
    Categorizer, CategoryRule, DefaultCategorizer, StringCategory, StringContext, StringFilter,
    StringTracker,
};

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

#[test]
fn test_custom_categorizer_rules_are_priority_sorted() {
    let mut categorizer = DefaultCategorizer::empty();

    categorizer
        .add_rule(CategoryRule {
            name: "low_priority".to_string(),
            matcher: Box::new(|value| value == "shared"),
            category: StringCategory {
                name: "low".to_string(),
                parent: None,
                description: "Low priority match".to_string(),
            },
            priority: 1,
        })
        .unwrap();

    categorizer
        .add_rule(CategoryRule {
            name: "high_priority".to_string(),
            matcher: Box::new(|value| value == "shared"),
            category: StringCategory {
                name: "high".to_string(),
                parent: None,
                description: "High priority match".to_string(),
            },
            priority: 10,
        })
        .unwrap();

    let categories = categorizer.categorize("shared");
    let names: Vec<_> = categories
        .iter()
        .map(|category| category.name.as_str())
        .collect();
    assert_eq!(names, vec!["high", "low"]);
}

#[test]
fn test_high_entropy_statistics_are_sorted_descending() {
    let tracker = StringTracker::new();

    for value in [
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "a1B2c3D4e5F6g7H8i9J0kLmNoP",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        tracker
            .track_string(
                value,
                "/entropy.bin",
                value,
                "scanner",
                StringContext::FileString { offset: None },
            )
            .unwrap();
    }

    let stats = tracker.get_statistics(None);
    assert!(stats.high_entropy_strings.len() >= 2);
    assert!(stats
        .high_entropy_strings
        .windows(2)
        .all(|pair| pair[0].1 >= pair[1].1));
}
