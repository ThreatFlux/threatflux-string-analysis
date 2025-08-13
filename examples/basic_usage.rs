//! Basic usage example of the ThreatFlux String Analysis library

use threatflux_string_analysis::{StringContext, StringFilter, StringTracker};

fn main() -> anyhow::Result<()> {
    // Create a new string tracker
    let tracker = StringTracker::new();

    // Simulate analyzing a malicious file
    println!("Tracking strings from a simulated malicious file...\n");

    // Track various suspicious strings
    tracker.track_string(
        "http://malware-c2.evil.com/beacon",
        "/tmp/suspicious.exe",
        "a1b2c3d4e5f6",
        "malware_scanner",
        StringContext::Url {
            protocol: Some("http".to_string()),
        },
    )?;

    tracker.track_string(
        "cmd.exe /c powershell -encodedcommand",
        "/tmp/suspicious.exe",
        "a1b2c3d4e5f6",
        "malware_scanner",
        StringContext::Command {
            command_type: "shell".to_string(),
        },
    )?;

    tracker.track_string(
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "/tmp/suspicious.exe",
        "a1b2c3d4e5f6",
        "malware_scanner",
        StringContext::Registry {
            hive: Some("HKEY_LOCAL_MACHINE".to_string()),
        },
    )?;

    tracker.track_string(
        "VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZw==",
        "/tmp/suspicious.exe",
        "a1b2c3d4e5f6",
        "malware_scanner",
        StringContext::FileString {
            offset: Some(0x1000),
        },
    )?;

    // Track some benign strings from another file
    tracker.track_string(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "/usr/bin/browser",
        "f6e5d4c3b2a1",
        "file_scanner",
        StringContext::Metadata {
            field: "user_agent".to_string(),
        },
    )?;

    // Get overall statistics
    let stats = tracker.get_statistics(None);
    println!("=== Overall Statistics ===");
    println!("Total unique strings: {}", stats.total_unique_strings);
    println!("Total occurrences: {}", stats.total_occurrences);
    println!("Total files analyzed: {}", stats.total_files_analyzed);
    println!("Suspicious strings: {}", stats.suspicious_strings.len());
    println!("\nCategory distribution:");
    for (category, count) in &stats.category_distribution {
        println!("  {}: {}", category, count);
    }

    // Filter for suspicious strings only
    println!("\n=== Suspicious Strings Only ===");
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
    println!(
        "Found {} suspicious strings:",
        suspicious_stats.total_unique_strings
    );
    for (string, _) in suspicious_stats.most_common.iter().take(5) {
        if let Some(details) = tracker.get_string_details(string) {
            println!(
                "  - {} (entropy: {:.2}, categories: {:?})",
                string, details.entropy, details.categories
            );
        }
    }

    // Search for specific patterns
    println!("\n=== Searching for Command-Related Strings ===");
    let command_filter = StringFilter {
        categories: Some(vec!["command".to_string()]),
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

    let command_stats = tracker.get_statistics(Some(&command_filter));
    for (string, count) in command_stats.most_common {
        println!("  - {} (occurrences: {})", string, count);
    }

    // Find strings with high entropy
    println!("\n=== High Entropy Strings ===");
    for (string, entropy) in stats.high_entropy_strings.iter().take(3) {
        println!("  - {} (entropy: {:.2})", string, entropy);
    }

    Ok(())
}
