# ThreatFlux String Analysis

[![Crates.io](https://img.shields.io/crates/v/threatflux-string-analysis.svg)](https://crates.io/crates/threatflux-string-analysis)
[![docs.rs](https://docs.rs/threatflux-string-analysis/badge.svg)](https://docs.rs/threatflux-string-analysis)
[![CI](https://github.com/ThreatFlux/threatflux-string-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-string-analysis/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/threatflux-string-analysis/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/threatflux-string-analysis/actions/workflows/security.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.95.0-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/LICENSE)

An in-memory Rust library for tracking strings across files, enriching them
with context, and applying configurable categorization, retention, and analysis
heuristics.

ThreatFlux String Analysis is designed for binary-analysis, forensic, and
security-pipeline enrichment. Its indicators are evidence for an application to
interpret; they are not malware verdicts, reputation data, or a replacement for
validation by a security analyst.

## Highlights

- Track occurrences, source files, timestamps, and discovery context
- Categorize URLs, paths, registry keys, commands, libraries, and other strings
- Calculate byte-level Shannon entropy
- Apply built-in or application-defined regular-expression patterns
- Filter statistics by occurrence count, length, category, file, hash, time,
  entropy, suspicion, or regular expression
- Search tracked values and rank related strings with a documented heuristic
- Bound retained strings, source identities, occurrence detail, categories,
  indicators, and input byte lengths through `AnalysisConfig`
- Share tracker state safely between clones

## Install

```toml
[dependencies]
threatflux-string-analysis = "0.2.2"
```

Version 0.2.2 requires Rust 1.95.0 or newer.

## Quick start

```rust
use threatflux_string_analysis::{StringContext, StringTracker};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tracker = StringTracker::new();

    tracker.track_string(
        "powershell.exe -EncodedCommand ...",
        "/samples/example.bin",
        "sha256:example",
        "example-scanner",
        StringContext::Command {
            command_type: "PowerShell".to_owned(),
        },
    )?;

    let statistics = tracker.get_statistics(None)?;
    println!("tracked strings: {}", statistics.total_unique_strings);
    println!(
        "heuristic-positive strings: {}",
        statistics.total_suspicious_strings
    );

    Ok(())
}
```

The default tracker applies the built-in categorizer and pattern set. A URL or
IP-address match is informational by default; command, credential, malware, and
other explicitly suspicious patterns may contribute a heuristic signal.

## Configure retention

Configuration is validated when a custom tracker is constructed:

```rust
use threatflux_string_analysis::{AnalysisConfig, StringTracker};

fn configured_tracker() -> Result<StringTracker, Box<dyn std::error::Error>> {
    let config = AnalysisConfig {
        max_occurrences_per_string: 128,
        ..AnalysisConfig::default()
    };

    Ok(StringTracker::with_config(config)?)
}
```

Invalid limits and non-finite thresholds are rejected. At unique-string
capacity, repeated values remain accepted but a new distinct value returns
`CapacityExceeded`; the tracker does not silently evict an existing entry.
Per-string occurrence detail retains the newest ingested records, while the
aggregate count continues to describe every accepted observation. See the
[behavior contract](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/docs/BEHAVIOR.md)
for the complete semantics.

## Filter statistics

```rust
use threatflux_string_analysis::{StringFilter, StringTracker};

fn suspicious_commands(
    tracker: &StringTracker,
) -> Result<u64, Box<dyn std::error::Error>> {
    let filter = StringFilter {
        categories: Some(vec!["command".to_owned()]),
        suspicious_only: Some(true),
        ..StringFilter::default()
    };

    Ok(tracker.get_statistics(Some(&filter))?.total_unique_strings)
}
```

Every populated filter field participates in the query. Malformed regular
expressions return an error instead of silently broadening the result.

## Custom analysis

The crate exposes three extension points:

- `StringAnalyzer` computes entropy and heuristic indicators.
- `Categorizer` assigns one or more descriptive categories.
- `PatternProvider` manages compiled pattern definitions.

Use `StringTracker::with_components` for application-specific defaults or
`StringTracker::with_components_and_config` for custom components and limits.
Read the
[pattern guide](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/docs/PATTERNS.md)
before treating a custom match as security-relevant.

## Behavioral boundaries

- The tracker is in-memory only; it does not persist or transmit observations.
- Cloned trackers share the same retained entries.
- Values are limited to 1 MiB of UTF-8 by default. Each path, hash, tool name,
  and owned context field is limited to 16 KiB by default; oversize input is
  rejected before mutation.
- Count and field limits are independent ceilings, not a single heap-byte
  budget. Choose them together for the deployment's memory envelope; maximum
  values can multiply into a large retained data set.
- Entropy is calculated over UTF-8 bytes, so it is not a language model or a
  reliable encrypted-content detector.
- Categories and indicators are heuristic and can produce false positives and
  false negatives.
- Custom analyzers and categorizers are trusted in-process code. Their panics
  propagate to the caller, although callbacks run outside the tracker lock.
- Related-string scores are ranking hints, not probabilistic confidence values.
- Statistics expose bounded sample lists; category distributions can still
  contain one key per retained category. Use targeted filters or lookup methods
  when an application needs a specific entry.

See the
[behavior contract](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/docs/BEHAVIOR.md)
for filtering, ordering, retention, timestamp, concurrency, and error
semantics.

## Examples and guides

- [Basic usage](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/examples/basic_usage.rs) —
  tracking and statistics
- [Custom patterns](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/examples/custom_patterns.rs) —
  domain-specific patterns
- [Security-log analysis](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/examples/security_log_analysis.rs) —
  extracting and correlating log artifacts
- [Pattern guide](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/docs/PATTERNS.md) —
  pattern and indicator semantics
- [File-scanner integration](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/docs/FILE_SCANNER.md) —
  integration boundaries
- [Migrating to 0.2](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/docs/MIGRATING_TO_0.2.md) —
  0.1 upgrade guide

## Development and security

- [Contributing](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/CONTRIBUTING.md) —
  contribution workflow
- [Development](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/DEVELOPMENT.md) —
  local setup and commands
- [Testing](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/TESTING.md) —
  validation matrix
- [Security policy](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/SECURITY.md) —
  private vulnerability reporting
- [Changelog](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/CHANGELOG.md) —
  release history

## License

Licensed under the
[MIT License](https://github.com/ThreatFlux/threatflux-string-analysis/blob/main/LICENSE).
