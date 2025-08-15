//! Example of using ThreatFlux String Analysis for security log analysis

use threatflux_string_analysis::{
    Categorizer, CategoryRule, DefaultCategorizer, DefaultStringAnalyzer, StringCategory,
    StringContext, StringFilter, StringTracker,
};

fn main() -> anyhow::Result<()> {
    // Create a custom analyzer for log analysis
    let analyzer = DefaultStringAnalyzer::new().with_entropy_threshold(4.0); // Lower threshold for logs

    // Create a custom categorizer with log-specific rules
    let mut categorizer = DefaultCategorizer::new();

    // Add custom categorization rule for log levels
    categorizer.add_rule(CategoryRule {
        name: "log_level".to_string(),
        matcher: Box::new(|s| {
            s.contains("[ERROR]")
                || s.contains("[WARN]")
                || s.contains("[INFO]")
                || s.contains("[DEBUG]")
        }),
        category: StringCategory {
            name: "log_level".to_string(),
            parent: Some("logging".to_string()),
            description: "Log level indicator".to_string(),
        },
        priority: 100,
    })?;

    // Create tracker with custom components
    let tracker = StringTracker::with_components(Box::new(analyzer), Box::new(categorizer));

    // Simulate processing security logs
    let log_entries = vec![
        (
            "2024-01-15 10:23:45 [ERROR] Failed login attempt from 192.168.1.100",
            "auth.log",
        ),
        (
            "2024-01-15 10:23:46 [ERROR] Failed login attempt from 192.168.1.100",
            "auth.log",
        ),
        (
            "2024-01-15 10:23:47 [ERROR] Failed login attempt from 192.168.1.100",
            "auth.log",
        ),
        (
            "2024-01-15 10:24:01 [WARN] Unusual process spawned: powershell.exe -encodedcommand",
            "system.log",
        ),
        (
            "2024-01-15 10:24:05 [INFO] User admin logged in successfully",
            "auth.log",
        ),
        (
            "2024-01-15 10:25:10 [ERROR] Connection to C2 server at evil.malware.com:443",
            "network.log",
        ),
        (
            "2024-01-15 10:25:15 [WARN] Suspicious registry modification: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "system.log",
        ),
        (
            "2024-01-15 10:26:00 [INFO] Backup completed successfully",
            "backup.log",
        ),
        (
            "2024-01-15 10:27:30 [ERROR] Ransomware signature detected: .locked extension",
            "antivirus.log",
        ),
    ];

    println!("Processing security logs...\n");

    // Track strings from log entries
    for (log_entry, log_file) in log_entries {
        // Extract potential IOCs from the log entry
        let parts: Vec<&str> = log_entry.split_whitespace().collect();

        for part in parts {
            // Skip timestamps and common words
            if part.len() < 4 || part.starts_with("2024-") {
                continue;
            }

            tracker.track_string(
                part,
                log_file,
                &format!("{}_hash", log_file),
                "log_analyzer",
                StringContext::Other {
                    category: "log_entry".to_string(),
                },
            )?;
        }
    }

    // Analyze the results
    let stats = tracker.get_statistics(None);

    println!("=== Log Analysis Summary ===");
    println!("Total unique strings: {}", stats.total_unique_strings);
    println!("Total occurrences: {}", stats.total_occurrences);

    // Find suspicious patterns
    println!("\n=== Suspicious Indicators ===");
    let suspicious_filter = StringFilter {
        suspicious_only: Some(true),
        min_occurrences: None,
        max_occurrences: None,
        min_length: None,
        max_length: None,
        categories: None,
        file_paths: None,
        file_hashes: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };

    let suspicious_stats = tracker.get_statistics(Some(&suspicious_filter));
    for string in &suspicious_stats.suspicious_strings {
        if let Some(details) = tracker.get_string_details(string) {
            println!(
                "  - {} (seen {} times in {} files)",
                string,
                details.total_occurrences,
                details.unique_files.len()
            );
        }
    }

    // Find repeated patterns (potential brute force indicators)
    println!("\n=== Repeated Patterns (Potential Attacks) ===");
    let repeated_filter = StringFilter {
        min_occurrences: Some(3),
        max_occurrences: None,
        min_length: None,
        max_length: None,
        categories: None,
        file_paths: None,
        file_hashes: None,
        suspicious_only: None,
        regex_pattern: None,
        min_entropy: None,
        max_entropy: None,
        date_range: None,
    };

    let repeated_stats = tracker.get_statistics(Some(&repeated_filter));
    for (string, count) in repeated_stats.most_common.iter().take(5) {
        println!("  - {} (appeared {} times)", string, count);
    }

    // Search for specific IOCs
    println!("\n=== Searching for Network IOCs ===");
    let network_results = tracker.search_strings(".com", 10);
    for entry in network_results {
        if entry.is_suspicious {
            println!("  - {} [SUSPICIOUS]", entry.value);
        }
    }

    // Find related strings (useful for clustering attacks)
    println!("\n=== Related Strings Analysis ===");
    if let Some(ip_entry) = tracker.get_string_details("192.168.1.100") {
        println!(
            "Strings related to {} (potential attack source):",
            ip_entry.value
        );
        let related = tracker.get_related_strings(&ip_entry.value, 5);
        for (string, similarity) in related {
            println!("  - {} (similarity: {:.2})", string, similarity);
        }
    }

    Ok(())
}
