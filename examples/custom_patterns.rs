//! Example of using custom patterns for domain-specific analysis

use threatflux_string_analysis::{
    DefaultPatternProvider, DefaultStringAnalyzer, PatternDef, PatternProvider, StringContext,
    StringTracker,
};

fn main() -> anyhow::Result<()> {
    // Create a pattern provider with custom patterns for cryptocurrency analysis
    let mut pattern_provider = DefaultPatternProvider::empty();

    // Add cryptocurrency-related patterns
    pattern_provider.add_pattern(PatternDef {
        name: "bitcoin_address".to_string(),
        regex: r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$".to_string(),
        category: "cryptocurrency".to_string(),
        description: "Bitcoin address pattern".to_string(),
        is_suspicious: true,
        severity: 7,
    })?;

    pattern_provider.add_pattern(PatternDef {
        name: "ethereum_address".to_string(),
        regex: r"^0x[a-fA-F0-9]{40}$".to_string(),
        category: "cryptocurrency".to_string(),
        description: "Ethereum address pattern".to_string(),
        is_suspicious: true,
        severity: 7,
    })?;

    pattern_provider.add_pattern(PatternDef {
        name: "crypto_mining_pool".to_string(),
        regex: r"(?i)(pool\.minexmr|nanopool|2miners|ethermine)".to_string(),
        category: "mining".to_string(),
        description: "Cryptocurrency mining pool".to_string(),
        is_suspicious: true,
        severity: 8,
    })?;

    pattern_provider.add_pattern(PatternDef {
        name: "monero_address".to_string(),
        regex: r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$".to_string(),
        category: "cryptocurrency".to_string(),
        description: "Monero address pattern".to_string(),
        is_suspicious: true,
        severity: 8,
    })?;

    // Add ransomware-specific patterns
    pattern_provider.add_pattern(PatternDef {
        name: "ransomware_extension".to_string(),
        regex: r"(?i)\.(locked|encrypted|crypto|enc|lock|[a-z0-9]{6,8})$".to_string(),
        category: "ransomware".to_string(),
        description: "Common ransomware file extension".to_string(),
        is_suspicious: true,
        severity: 9,
    })?;

    pattern_provider.add_pattern(PatternDef {
        name: "ransom_note_keyword".to_string(),
        regex: r"(?i)(decrypt|restore|bitcoin|payment|ransom|encrypted)".to_string(),
        category: "ransomware".to_string(),
        description: "Keywords commonly found in ransom notes".to_string(),
        is_suspicious: true,
        severity: 8,
    })?;

    // Create analyzer with custom patterns
    let analyzer = DefaultStringAnalyzer::new()
        .with_patterns(pattern_provider.get_patterns())
        .with_entropy_threshold(4.2);

    // Create tracker
    let tracker = StringTracker::with_components(
        Box::new(analyzer),
        Box::new(threatflux_string_analysis::DefaultCategorizer::new()),
    );

    // Simulate analyzing a crypto-mining malware
    println!("Analyzing suspected crypto-mining malware...\n");

    let suspicious_strings = vec![
        "stratum+tcp://pool.minexmr.com:4444",
        "43QVqFAMNDhj3rFvjLqSqMBgkTQXvqCKheFCaWtmgBcE3XzM5vw52fQjcqBW6ixmBFjdMvDn3YSLBK7mfXg3bQTqmqFbPfC",
        "0x742d35Cc6634C0532925a3b844Bc9e7595f7E8E0",
        "config.json",
        "--cuda-threads 4",
        "--cpu-priority 5",
        "YOUR_FILES_ARE_ENCRYPTED.txt",
        "Send 0.5 Bitcoin to decrypt your files",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ];

    for (i, string) in suspicious_strings.iter().enumerate() {
        tracker.track_string(
            string,
            "/tmp/miner.exe",
            "abc123def456",
            "malware_scanner",
            StringContext::FileString {
                offset: Some(i * 100),
            },
        )?;
    }

    // Add some benign strings for comparison
    let benign_strings = vec![
        "Mozilla/5.0",
        "Windows NT 10.0",
        "Content-Type: application/json",
        "Accept-Language: en-US",
    ];

    for string in benign_strings {
        tracker.track_string(
            string,
            "/usr/bin/firefox",
            "xyz789uvw456",
            "file_scanner",
            StringContext::Metadata {
                field: "header".to_string(),
            },
        )?;
    }

    // Analyze results
    let stats = tracker.get_statistics(None);

    println!("=== Analysis Results ===");
    println!("Total strings analyzed: {}", stats.total_unique_strings);

    // Look for cryptocurrency-related strings
    println!("\n=== Cryptocurrency Indicators ===");
    let crypto_filter = threatflux_string_analysis::StringFilter {
        categories: Some(vec!["cryptocurrency".to_string(), "mining".to_string()]),
        suspicious_only: None,
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        file_paths: None,
        file_hashes: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };

    let crypto_stats = tracker.get_statistics(Some(&crypto_filter));
    for (string, _) in crypto_stats.most_common {
        if let Some(details) = tracker.get_string_details(&string) {
            println!("  - {} (categories: {:?})", string, details.categories);
        }
    }

    // Look for ransomware indicators
    println!("\n=== Ransomware Indicators ===");
    let ransomware_filter = threatflux_string_analysis::StringFilter {
        categories: Some(vec!["ransomware".to_string()]),
        suspicious_only: None,
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        file_paths: None,
        file_hashes: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };

    let ransomware_stats = tracker.get_statistics(Some(&ransomware_filter));
    for (string, _) in ransomware_stats.most_common {
        println!("  - {}", string);
    }

    // Summary of threats
    println!("\n=== Threat Summary ===");
    println!(
        "Suspicious strings found: {}",
        stats.suspicious_strings.len()
    );
    println!("\nThreat categories detected:");
    for (category, count) in stats.category_distribution {
        if category == "cryptocurrency" || category == "mining" || category == "ransomware" {
            println!("  - {}: {} indicators", category, count);
        }
    }

    Ok(())
}
