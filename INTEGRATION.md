# ThreatFlux String Analysis - Integration Guide

## Overview

The `threatflux-string-analysis` library has been successfully extracted from the file-scanner project's `string_tracker.rs` module into a standalone, reusable library for advanced string analysis and categorization.

## Key Features

1. **Modular Architecture**: Trait-based design with pluggable components
2. **Extensible Patterns**: Add custom patterns for domain-specific analysis
3. **Flexible Categorization**: Define custom categorization rules
4. **Advanced Analysis**: Entropy calculation, similarity detection, statistical analysis
5. **Full Compatibility**: Maintains backward compatibility with file-scanner

## Architecture

### Core Traits

- **StringAnalyzer**: Analyzes strings for suspicious patterns and entropy
- **Categorizer**: Categorizes strings into types (URL, path, command, etc.)
- **PatternProvider**: Manages detection patterns

### Main Components

- **StringTracker**: Main tracking and analysis engine
- **DefaultStringAnalyzer**: Built-in analyzer with security patterns
- **DefaultCategorizer**: Built-in categorization rules
- **DefaultPatternProvider**: Built-in security-focused patterns

## Integration with File-Scanner

The integration maintains full backward compatibility through `string_tracker_compat.rs`:

```rust
// In file-scanner/src/string_tracker_compat.rs
pub struct StringTracker {
    inner: threatflux_string_analysis::StringTracker,
}
```

This wrapper ensures all existing code continues to work without modifications.

## Usage Examples

### Basic Usage
```rust
use threatflux_string_analysis::{StringTracker, StringContext};

let tracker = StringTracker::new();
tracker.track_string(
    "http://malware.com",
    "/file.exe",
    "hash123",
    "scanner",
    StringContext::Url { protocol: Some("http".to_string()) }
)?;
```

### Custom Patterns
```rust
use threatflux_string_analysis::{PatternDef, DefaultPatternProvider, PatternProvider};

let mut provider = DefaultPatternProvider::empty();
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
use threatflux_string_analysis::{CategoryRule, StringCategory, Categorizer};

let mut categorizer = DefaultCategorizer::new();
categorizer.add_rule(CategoryRule {
    name: "log_level".to_string(),
    matcher: Box::new(|s| s.contains("[ERROR]") || s.contains("[WARN]")),
    category: StringCategory {
        name: "log_level".to_string(),
        parent: Some("logging".to_string()),
        description: "Log level indicator".to_string(),
    },
    priority: 100,
})?;
```

## Built-in Patterns

The library includes patterns for detecting:

- **Network Indicators**: URLs, IP addresses
- **Command Execution**: Shell commands, code execution functions
- **Cryptography**: Encoding algorithms, Base64 strings
- **File Paths**: Suspicious system paths
- **Credentials**: Password-related keywords
- **Registry Keys**: Windows registry patterns
- **Malware Indicators**: Common malware terminology
- **Surveillance**: Keylogger and spyware patterns

## Use Cases

1. **Malware Analysis**: Extract and categorize IOCs from binaries
2. **Security Log Analysis**: Process logs to identify threats
3. **Threat Hunting**: Search for specific patterns across files
4. **Forensic Investigations**: Analyze memory dumps and artifacts
5. **SIEM Integration**: Build string analysis into security pipelines

## Performance Considerations

- Efficient string deduplication
- Configurable memory limits (max 1000 occurrences per string by default)
- Compiled regex patterns for fast matching
- Minimal allocations in hot paths

## Future Enhancements

- Machine learning-based categorization
- Integration with threat intelligence feeds
- Real-time pattern updates
- Export to STIX/TAXII formats
- Clustering and anomaly detection

## Migration Guide

For existing file-scanner users:

1. No code changes required - the compatibility wrapper handles everything
2. The API remains exactly the same
3. All existing tests continue to pass
4. Performance characteristics are unchanged

For new projects:

1. Add dependency: `threatflux-string-analysis = "0.1.0"`
2. Use the library directly without the compatibility wrapper
3. Take advantage of the extensible architecture
4. Contribute patterns back to the community

## Contributing

We welcome contributions! Areas for contribution:

- New pattern definitions for emerging threats
- Additional categorization rules
- Performance optimizations
- Documentation and examples
- Integration guides for other tools