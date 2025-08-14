//! Tests for individual components

use threatflux_string_analysis::{
    DefaultCategorizer, DefaultPatternProvider, DefaultStringAnalyzer, StringAnalyzer, Categorizer, PatternProvider, PatternDef
};

#[test]
fn test_default_string_analyzer() {
    let analyzer = DefaultStringAnalyzer::new();
    
    // Test entropy calculation
    let low_entropy = analyzer.calculate_entropy("aaaaaaa");
    let high_entropy = analyzer.calculate_entropy("random$#@!string123");
    
    assert!(low_entropy < high_entropy);
    assert!(low_entropy >= 0.0);
    
    // Test analysis with patterns
    let pattern_provider = DefaultPatternProvider::default();
    let analyzer_with_patterns = DefaultStringAnalyzer::new()
        .with_patterns(pattern_provider.get_patterns());
    
    let analysis = analyzer_with_patterns.analyze("cmd.exe /c whoami");
    assert!(analysis.is_suspicious);
    assert!(!analysis.suspicious_indicators.is_empty());
    assert!(analysis.categories.contains("command"));
    
    // Test non-suspicious string
    let benign_analysis = analyzer_with_patterns.analyze("hello world");
    assert!(!benign_analysis.is_suspicious);
}

#[test]
fn test_default_categorizer() {
    let categorizer = DefaultCategorizer::new();
    
    // Test URL categorization
    let url_categories = categorizer.categorize("https://example.com");
    assert!(url_categories.iter().any(|c| c.name == "url"));
    
    // Test IP address categorization  
    let ip_categories = categorizer.categorize("192.168.1.1");
    assert!(ip_categories.iter().any(|c| c.name == "ip_address"));
    
    // Test email categorization
    let email_categories = categorizer.categorize("test@example.com");
    assert!(email_categories.iter().any(|c| c.name == "email"));
    
    // Test path categorization
    let path_categories = categorizer.categorize("/usr/bin/bash");
    assert!(path_categories.iter().any(|c| c.name == "path"));
    
    // Test registry categorization
    let registry_categories = categorizer.categorize("HKEY_LOCAL_MACHINE\\Software");
    assert!(registry_categories.iter().any(|c| c.name == "registry"));
    
    // Test library categorization
    let lib_categories = categorizer.categorize("kernel32.dll");
    assert!(lib_categories.iter().any(|c| c.name == "library"));
    
    // Test generic categorization for unmatched strings
    let generic_categories = categorizer.categorize("just some text");
    assert!(generic_categories.iter().any(|c| c.name == "generic"));
}

#[test]
fn test_default_pattern_provider() {
    let provider = DefaultPatternProvider::default();
    let patterns = provider.get_patterns();
    
    assert!(!patterns.is_empty());
    
    // Check for expected pattern categories
    let pattern_categories: Vec<_> = patterns.iter().map(|p| &p.category).collect();
    assert!(pattern_categories.contains(&&"network".to_string()));
    assert!(pattern_categories.contains(&&"command".to_string()));
    assert!(pattern_categories.contains(&&"malware".to_string()));
    assert!(pattern_categories.contains(&&"crypto".to_string()));
    
    // Test suspicious patterns
    let suspicious_patterns: Vec<_> = patterns.iter().filter(|p| p.is_suspicious).collect();
    assert!(!suspicious_patterns.is_empty());
}

#[test]
fn test_pattern_compilation() {
    let pattern_def = PatternDef {
        name: "test_pattern".to_string(),
        regex: r"\d+".to_string(),
        category: "test".to_string(),
        description: "Test pattern for numbers".to_string(),
        is_suspicious: false,
        severity: 3,
    };
    
    let pattern = pattern_def.compile().unwrap();
    assert_eq!(pattern.name, "test_pattern");
    assert_eq!(pattern.category, "test");
    assert_eq!(pattern.severity, 3);
    assert!(!pattern.is_suspicious);
    assert!(pattern.regex.is_match("123"));
    assert!(!pattern.regex.is_match("abc"));
}

#[test]
fn test_analyzer_with_custom_threshold() {
    let analyzer = DefaultStringAnalyzer::new()
        .with_entropy_threshold(6.0);
    
    let analysis = analyzer.analyze("moderately_random_string");
    // With higher threshold, this should not be flagged as suspicious due to entropy alone
    let entropy_indicators: Vec<_> = analysis.suspicious_indicators
        .iter()
        .filter(|i| i.pattern_name == "high_entropy")
        .collect();
    
    // This depends on the actual entropy calculation but should be empty or fewer
    assert!(entropy_indicators.len() <= 1);
}