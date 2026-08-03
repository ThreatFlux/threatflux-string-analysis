use threatflux_string_analysis::{
    AnalysisError, AnalysisResult, Categorizer, CategoryRule, DefaultCategorizer,
    DefaultPatternProvider, DefaultStringAnalyzer, Pattern, PatternDef, PatternProvider,
    StringAnalyzer, StringCategory,
};

fn default_analyzer() -> DefaultStringAnalyzer {
    let patterns = DefaultPatternProvider::default().get_patterns();
    DefaultStringAnalyzer::new()
        .with_patterns(patterns)
        .expect("built-in patterns are valid")
}

#[test]
fn generic_artifacts_are_informational_not_suspicious() {
    let analyzer = default_analyzer();
    for value in [
        "https://example.com",
        "192.0.2.1",
        "description",
        "English",
        "filesystem",
        "HKEY_CURRENT_USER\\Software",
        "kernel32.dll",
        "AES",
    ] {
        let analysis = analyzer.analyze(value);
        assert!(
            !analysis.is_suspicious,
            "ordinary artifact unexpectedly flagged: {value:?} ({:?})",
            analysis.suspicious_indicators
        );
    }

    assert!(
        analyzer
            .analyze("https://example.com")
            .categories
            .contains("network")
    );
    assert!(analyzer.analyze("192.0.2.1").categories.contains("network"));
    assert!(analyzer.analyze("AES").categories.contains("crypto"));
}

#[test]
fn high_signal_patterns_retain_explainable_evidence() {
    let analyzer = default_analyzer();
    for value in [
        "cmd.exe /c whoami",
        "powershell -EncodedCommand Zg==",
        "pwsh -Command Get-Process",
        "/bin/bash -c 'id'",
        "sh -c whoami",
        "eval(user_input)",
        "password = hunter2",
        "rootkit",
    ] {
        let analysis = analyzer.analyze(value);
        assert!(analysis.is_suspicious, "expected a signal for {value:?}");
        assert!(!analysis.suspicious_indicators.is_empty());
        assert!(
            analysis
                .suspicious_indicators
                .iter()
                .all(|indicator| indicator.severity <= 10)
        );
    }
}

#[test]
fn bare_posix_shell_names_are_not_suspicious_invocations() {
    let analyzer = default_analyzer();
    for value in ["sh", "bash", "bashful", "English"] {
        assert!(
            !analyzer.analyze(value).is_suspicious,
            "bare or embedded shell name unexpectedly flagged: {value:?}"
        );
    }
}

#[test]
fn padded_and_unpadded_base64_candidates_are_classified_precisely() {
    let analyzer = default_analyzer();
    let seven_quartets = "QUFB".repeat(7);
    let eight_quartets = "QUFB".repeat(8);
    for value in [
        eight_quartets.clone(),
        format!("{seven_quartets}QQ=="),
        format!("{seven_quartets}QUE="),
    ] {
        assert!(
            analyzer.analyze(&value).categories.contains("encoding"),
            "valid Base64 shape was not categorized: {value:?}"
        );
    }

    for value in [
        format!("{}QQ==", "QUFB".repeat(6)),
        format!("{seven_quartets}Q==="),
        format!("{seven_quartets}QU-F"),
    ] {
        assert!(
            !analyzer.analyze(&value).categories.contains("encoding"),
            "invalid Base64 near-miss was categorized: {value:?}"
        );
    }
}

#[test]
fn evidence_limit_retains_the_strongest_later_signal() -> AnalysisResult<()> {
    let analyzer = default_analyzer().with_max_indicators(1)?;
    let analysis = analyzer.analyze("cmd.exe /c load rootkit");

    assert!(analysis.indicators_truncated);
    assert_eq!(analysis.suspicious_indicators.len(), 1);
    assert_eq!(analysis.suspicious_indicators[0].severity, 9);
    assert_eq!(
        analysis.suspicious_indicators[0].pattern_name,
        "malware_behavior_term"
    );
    Ok(())
}

#[test]
fn equal_severity_evidence_keeps_the_earlier_pattern() -> AnalysisResult<()> {
    let patterns = ["first", "second"]
        .into_iter()
        .map(|name| {
            PatternDef {
                name: name.to_string(),
                regex: "match".to_string(),
                category: "test".to_string(),
                description: "Tie-order regression".to_string(),
                is_suspicious: true,
                severity: 8,
            }
            .compile()
        })
        .collect::<AnalysisResult<Vec<_>>>()?;
    let analyzer = DefaultStringAnalyzer::new()
        .with_patterns(patterns)?
        .with_max_indicators(1)?;

    let analysis = analyzer.analyze("match");
    assert!(analysis.indicators_truncated);
    assert_eq!(analysis.suspicious_indicators[0].pattern_name, "first");
    Ok(())
}

#[test]
fn unicode_evidence_is_truncated_on_a_utf8_boundary() -> AnalysisResult<()> {
    let analyzer = DefaultStringAnalyzer::new().with_patterns(vec![
        PatternDef {
            name: "unicode_evidence".to_string(),
            regex: "(?s).+".to_string(),
            category: "test".to_string(),
            description: "UTF-8 truncation regression".to_string(),
            is_suspicious: true,
            severity: 5,
        }
        .compile()?,
    ])?;
    let value = "é".repeat(300);
    let analysis = analyzer.analyze(&value);
    let indicator = &analysis.suspicious_indicators[0];
    let evidence = indicator.matched_text.as_ref().unwrap();

    assert!(indicator.matched_text_truncated);
    assert_eq!(evidence.len(), 512);
    assert_eq!(evidence.chars().count(), 256);
    assert!(evidence.is_char_boundary(evidence.len()));
    Ok(())
}

#[test]
fn entropy_is_byte_based_finite_and_bounded() {
    let analyzer = DefaultStringAnalyzer::new();
    assert_eq!(analyzer.calculate_entropy(""), 0.0);
    assert_eq!(analyzer.calculate_entropy("aaaaaaaa"), 0.0);
    for value in ["abc", "Hello, 世界", "a1B2c3D4!@#$"] {
        let entropy = analyzer.calculate_entropy(value);
        assert!(entropy.is_finite());
        assert!((0.0..=8.0).contains(&entropy));
    }
}

#[test]
fn pattern_validation_rejects_invalid_and_duplicate_definitions() {
    let mut provider = DefaultPatternProvider::empty();
    let valid = PatternDef {
        name: "custom_signal".to_string(),
        regex: r"\bexample\b".to_string(),
        category: "custom".to_string(),
        description: "Example signal".to_string(),
        is_suspicious: true,
        severity: 5,
    };
    provider.add_pattern(valid.clone()).unwrap();
    assert!(matches!(
        provider.add_pattern(valid.clone()),
        Err(AnalysisError::DuplicateName { .. })
    ));

    let invalid_severity = PatternDef {
        name: "invalid_severity".to_string(),
        severity: 11,
        ..valid.clone()
    };
    assert!(matches!(
        invalid_severity.compile(),
        Err(AnalysisError::InvalidSeverity { severity: 11 })
    ));

    let invalid_identifier = PatternDef {
        name: " ".to_string(),
        ..valid.clone()
    };
    assert!(matches!(
        invalid_identifier.compile(),
        Err(AnalysisError::InvalidIdentifier { .. })
    ));
    assert!(matches!(
        provider.remove_pattern("missing"),
        Err(AnalysisError::NotFound { .. })
    ));
}

#[test]
fn validation_errors_bound_and_sanitize_hostile_input() {
    let oversized_name = format!("SECRET\u{1b}{}", "x".repeat(1_000_000));
    let error = PatternDef {
        name: oversized_name.clone(),
        regex: "x".to_string(),
        category: "test".to_string(),
        description: "Hostile-input regression".to_string(),
        is_suspicious: false,
        severity: 0,
    }
    .compile()
    .unwrap_err();
    assert!(matches!(
        error,
        AnalysisError::InputTooLarge {
            field: "pattern",
            limit: 256,
            ..
        }
    ));
    let rendered = error.to_string();
    assert!(rendered.len() < 200);
    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains('\u{1b}'));

    let error = PatternDef {
        name: "description_limit".to_string(),
        regex: "x".to_string(),
        category: "test".to_string(),
        description: " \t".repeat(100_000),
        is_suspicious: false,
        severity: 0,
    }
    .compile()
    .unwrap_err();
    assert!(matches!(
        error,
        AnalysisError::InputTooLarge {
            field: "pattern.description",
            limit: 4_096,
            ..
        }
    ));
    assert!(error.to_string().len() < 200);

    let error = PatternDef {
        name: "description_control".to_string(),
        regex: "x".to_string(),
        category: "test".to_string(),
        description: "analyst\nSECRET".to_string(),
        is_suspicious: false,
        severity: 0,
    }
    .compile()
    .unwrap_err();
    let rendered = error.to_string();
    assert!(matches!(error, AnalysisError::InvalidIdentifier { .. }));
    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains('\n'));

    let error = PatternDef {
        name: "control\u{1b}SECRET".to_string(),
        regex: "x".to_string(),
        category: "test".to_string(),
        description: "Hostile-input regression".to_string(),
        is_suspicious: false,
        severity: 0,
    }
    .compile()
    .unwrap_err();
    let rendered = error.to_string();
    assert!(matches!(error, AnalysisError::InvalidIdentifier { .. }));
    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains('\u{1b}'));

    let error = PatternDef {
        name: "invalid_regex".to_string(),
        regex: "(\nSECRET\u{1b}".to_string(),
        category: "test".to_string(),
        description: "Hostile-input regression".to_string(),
        is_suspicious: false,
        severity: 0,
    }
    .compile()
    .unwrap_err();
    let rendered = error.to_string();
    assert!(matches!(error, AnalysisError::InvalidRegex { .. }));
    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains('\u{1b}'));
    assert!(std::error::Error::source(&error).is_none());

    let mut provider = DefaultPatternProvider::empty();
    assert!(matches!(
        provider.remove_pattern(&oversized_name),
        Err(AnalysisError::InputTooLarge {
            field: "pattern",
            limit: 256,
            ..
        })
    ));
    assert!(matches!(
        provider.update_pattern(PatternDef {
            name: oversized_name,
            regex: "x".to_string(),
            category: "test".to_string(),
            description: "Hostile-input regression".to_string(),
            is_suspicious: false,
            severity: 0,
        }),
        Err(AnalysisError::InputTooLarge {
            field: "pattern",
            limit: 256,
            ..
        })
    ));

    let mut categorizer = DefaultCategorizer::empty();
    assert!(matches!(
        categorizer.remove_rule("control\u{1b}SECRET"),
        Err(AnalysisError::InvalidIdentifier { .. })
    ));
}

#[test]
fn duplicate_errors_do_not_retain_caller_spare_capacity() -> AnalysisResult<()> {
    let mut provider = DefaultPatternProvider::empty();
    provider.add_pattern(PatternDef {
        name: "duplicate".to_string(),
        regex: "x".to_string(),
        category: "test".to_string(),
        description: "Capacity compaction regression".to_string(),
        is_suspicious: false,
        severity: 0,
    })?;

    let mut oversized_capacity_name = String::with_capacity(1_000_000);
    oversized_capacity_name.push_str("duplicate");
    let error = provider
        .add_pattern(PatternDef {
            name: oversized_capacity_name,
            regex: "x".to_string(),
            category: "test".to_string(),
            description: "Capacity compaction regression".to_string(),
            is_suspicious: false,
            severity: 0,
        })
        .unwrap_err();
    let AnalysisError::DuplicateName { name, .. } = error else {
        panic!("expected duplicate-name error");
    };
    assert!(name.capacity() <= 256);
    Ok(())
}

#[test]
fn precompiled_patterns_cannot_bypass_the_regex_source_limit() {
    let oversized_source = format!("(?x){}", " ".repeat(65_536));
    let pattern = Pattern {
        name: "oversized_precompiled".to_string(),
        regex: regex::Regex::new(&oversized_source).unwrap(),
        category: "test".to_string(),
        description: "Direct Pattern validation regression".to_string(),
        is_suspicious: false,
        severity: 0,
    };

    assert!(matches!(
        DefaultStringAnalyzer::new().add_pattern(pattern),
        Err(AnalysisError::InputTooLarge {
            field: "pattern.regex",
            limit: 65_536,
            ..
        })
    ));
}

#[test]
fn retained_precompiled_pattern_strings_are_compacted() -> AnalysisResult<()> {
    let mut name = String::with_capacity(1_000_000);
    name.push_str("compact_pattern");
    let mut category = String::with_capacity(1_000_000);
    category.push_str("test");
    let mut description = String::with_capacity(1_000_000);
    description.push_str("Pattern compaction regression");
    let mut analyzer = DefaultStringAnalyzer::new();
    analyzer.add_pattern(Pattern {
        name,
        regex: regex::Regex::new("x").unwrap(),
        category,
        description,
        is_suspicious: false,
        severity: 0,
    })?;

    let pattern = &analyzer.get_patterns()[0];
    assert_eq!(pattern.name.capacity(), pattern.name.len());
    assert_eq!(pattern.category.capacity(), pattern.category.len());
    assert_eq!(pattern.description.capacity(), pattern.description.len());
    Ok(())
}

#[test]
fn failed_pattern_update_preserves_the_existing_definition() {
    let mut provider = DefaultPatternProvider::empty();
    provider
        .add_pattern(PatternDef {
            name: "atomic".to_string(),
            regex: "old".to_string(),
            category: "test".to_string(),
            description: "Atomic update regression".to_string(),
            is_suspicious: false,
            severity: 0,
        })
        .unwrap();

    let result = provider.update_pattern(PatternDef {
        name: "atomic".to_string(),
        regex: "[".to_string(),
        category: "test".to_string(),
        description: "Invalid replacement".to_string(),
        is_suspicious: false,
        severity: 0,
    });
    assert!(matches!(result, Err(AnalysisError::InvalidRegex { .. })));
    let patterns = provider.get_patterns();
    assert_eq!(patterns.len(), 1);
    assert!(patterns[0].regex.is_match("old"));
}

#[test]
fn pattern_provider_rejects_growth_beyond_its_retention_limit() -> AnalysisResult<()> {
    let mut provider = DefaultPatternProvider::empty();
    for index in 0..4_096 {
        provider.add_pattern(PatternDef {
            name: format!("bounded_{index}"),
            regex: "x".to_string(),
            category: "test".to_string(),
            description: "Pattern-provider capacity regression".to_string(),
            is_suspicious: false,
            severity: 0,
        })?;
    }

    assert!(matches!(
        provider.add_pattern(PatternDef {
            name: "one_too_many".to_string(),
            regex: "x".to_string(),
            category: "test".to_string(),
            description: "Pattern-provider capacity regression".to_string(),
            is_suspicious: false,
            severity: 0,
        }),
        Err(AnalysisError::CapacityExceeded {
            resource: "pattern provider patterns",
            limit: 4_096,
        })
    ));
    Ok(())
}

#[test]
fn categorizer_uses_real_ip_parsing_and_precise_tokens() {
    let categorizer = DefaultCategorizer::new();
    for address in ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"] {
        assert!(
            categorizer
                .categorize(address)
                .iter()
                .any(|category| category.name == "ip_address")
        );
    }
    for value in ["999.999.999.999", "English", "bashful", "BANANA"] {
        let categories = categorizer.categorize(value);
        assert!(categories.iter().all(|category| {
            category.name != "ip_address"
                && category.name != "command"
                && category.name != "api_call"
        }));
    }
    assert!(
        categorizer
            .categorize("/bin/bash")
            .iter()
            .any(|category| category.name == "command")
    );
    assert!(
        categorizer
            .categorize("CreateProcessW")
            .iter()
            .any(|category| category.name == "api_call")
    );
}

#[test]
fn category_rules_validate_names_and_sort_deterministically() -> AnalysisResult<()> {
    let mut categorizer = DefaultCategorizer::empty();
    categorizer.add_rule(test_rule("z_rule", "z", 10))?;
    categorizer.add_rule(test_rule("a_rule", "a", 10))?;
    categorizer.add_rule(test_rule("high", "high", 20))?;

    let names: Vec<_> = categorizer
        .categorize("match")
        .into_iter()
        .map(|category| category.name)
        .collect();
    assert_eq!(names, ["high", "a", "z"]);
    assert!(matches!(
        categorizer.add_rule(test_rule("high", "duplicate", 0)),
        Err(AnalysisError::DuplicateName { .. })
    ));
    assert!(matches!(
        categorizer.remove_rule("missing"),
        Err(AnalysisError::NotFound { .. })
    ));
    Ok(())
}

fn test_rule(name: &str, category: &str, priority: i32) -> CategoryRule {
    CategoryRule {
        name: name.to_string(),
        matcher: Box::new(|value| value == "match"),
        category: StringCategory {
            name: category.to_string(),
            parent: None,
            description: "Test category".to_string(),
        },
        priority,
    }
}
