# ThreatFlux String Analysis

A comprehensive Rust library for advanced string analysis and categorization, designed for security applications including malware analysis, threat hunting, and forensic investigations.

## Features

- **String Tracking**: Track string occurrences across multiple files with full context
- **Automatic Categorization**: Identify URLs, paths, commands, registry keys, and more
- **Entropy Analysis**: Detect potentially encoded or encrypted strings
- **Suspicious Pattern Detection**: Built-in patterns for malware and threat indicators
- **Statistical Analysis**: Generate insights about string distributions and relationships
- **Extensible Architecture**: Add custom patterns and categorization rules
- **High Performance**: Optimized for analyzing large volumes of strings
- **Serialization Support**: Full serde support for all data structures

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
threatflux-string-analysis = "0.1.0"
```

Basic usage:

```rust
use threatflux_string_analysis::{StringTracker, StringContext};

fn main() -> anyhow::Result<()> {
    let tracker = StringTracker::new();
    
    // Track a suspicious string
    tracker.track_string(
        "http://malware.com/beacon",
        "/path/to/file.exe",
        "file_hash_123",
        "my_scanner",
        StringContext::Url { protocol: Some("http".to_string()) }
    )?;
    
    // Get statistics
    let stats = tracker.get_statistics(None);
    println!("Suspicious strings: {}", stats.suspicious_strings.len());
    
    Ok(())
}
```

## Advanced Usage

### Custom Pattern Matching

```rust
use threatflux_string_analysis::{PatternDef, DefaultPatternProvider};

let mut provider = DefaultPatternProvider::empty();

// Add custom pattern for API keys
provider.add_pattern(PatternDef {
    name: "api_key".to_string(),
    regex: r"[A-Za-z0-9]{32,}".to_string(),
    category: "credential".to_string(),
    description: "Potential API key".to_string(),
    is_suspicious: true,
    severity: 7,
})?;
```

### Custom Categorization

```rust
use threatflux_string_analysis::{CategoryRule, StringCategory, DefaultCategorizer};

let mut categorizer = DefaultCategorizer::new();

categorizer.add_rule(CategoryRule {
    name: "custom_rule".to_string(),
    matcher: Box::new(|s| s.contains("custom_pattern")),
    category: StringCategory {
        name: "custom_category".to_string(),
        parent: None,
        description: "Custom category description".to_string(),
    },
    priority: 100,
})?;
```

### Filtering and Searching

```rust
use threatflux_string_analysis::StringFilter;

// Filter for high-entropy suspicious strings
let filter = StringFilter {
    suspicious_only: Some(true),
    min_entropy: Some(4.5),
    categories: Some(vec!["network".to_string(), "command".to_string()]),
    ..Default::default()
};

let filtered_stats = tracker.get_statistics(Some(&filter));
```

## Use Cases

### Malware Analysis
- Extract and categorize strings from binary files
- Identify C2 servers, encryption keys, and malicious commands
- Track string patterns across malware families

### Security Log Analysis
- Process security logs to identify IOCs
- Detect repeated attack patterns
- Correlate suspicious activities

### Threat Hunting
- Search for specific threat indicators
- Analyze string entropy for obfuscation detection
- Track evolution of threats over time

### Forensic Investigations
- Extract and analyze strings from memory dumps
- Categorize artifacts by type
- Build timelines of string occurrences

## Architecture

The library is built with a modular, trait-based architecture:

- **StringAnalyzer**: Core trait for analyzing strings
- **Categorizer**: Trait for categorizing strings
- **PatternProvider**: Trait for managing detection patterns
- **StringTracker**: Main tracking and analysis engine

This design allows for easy extension and customization for specific use cases.

## Examples

See the `examples/` directory for complete examples:

- `basic_usage.rs`: Introduction to the library
- `security_log_analysis.rs`: Analyzing security logs
- `custom_patterns.rs`: Creating domain-specific patterns

## Performance

The library is optimized for high-volume string analysis:

- Efficient string deduplication
- Configurable memory limits
- Fast pattern matching with compiled regexes
- Minimal allocations in hot paths

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT OR Apache-2.0 license.