# Migrating to 0.2

Version 0.2 makes invalid configuration and query input visible, enforces
deterministic bounded retention, and clarifies the difference between
informational categories and suspicious heuristics.

Because this crate is pre-1.0, the `0.1` to `0.2` minor-version change is a
SemVer compatibility boundary.

## Dependency

```toml
[dependencies]
threatflux-string-analysis = "0.2.0"
```

Version 0.2 requires Rust 1.95.0 or newer.

## Construction

`StringTracker::new()` remains an infallible constructor using validated
defaults. Replace post-construction capacity builders with a complete
`AnalysisConfig` and propagate the result of `StringTracker::with_config`.

Before:

```rust,ignore
let tracker = StringTracker::new().with_max_occurrences(128);
```

Version 0.2:

```rust
use threatflux_string_analysis::{AnalysisConfig, StringTracker};

fn tracker() -> Result<StringTracker, Box<dyn std::error::Error>> {
    let config = AnalysisConfig {
        max_occurrences_per_string: 128,
        ..AnalysisConfig::default()
    };

    Ok(StringTracker::with_config(config)?)
}
```

Review every configured limit. Zero capacities, non-finite or out-of-range
entropy thresholds, and other unusable values are rejected rather than accepted
silently.

The new defaults bound a tracker to 100,000 distinct values, 1,000 occurrence
details per value, 1,024 file identities per value, 64 categories, and 64
indicators. Values are limited to 1 MiB of UTF-8, and each source or owned
context field is limited to 16 KiB. See [`BEHAVIOR.md`](BEHAVIOR.md) for exact
field names and semantics.

## Statistics are fallible

`get_statistics` still accepts `None` for all retained entries or
`Some(&StringFilter)` for a filtered view, but it now returns
`AnalysisResult<StringStatistics>`.

Before:

```rust,ignore
let all = tracker.get_statistics(None);
let filtered = tracker.get_statistics(Some(&filter));
```

Version 0.2:

```rust
use threatflux_string_analysis::{StringFilter, StringTracker};

fn counts(tracker: &StringTracker) -> threatflux_string_analysis::AnalysisResult<(u64, u64)> {
    let all = tracker.get_statistics(None)?;
    let filter = StringFilter {
        suspicious_only: Some(true),
        ..StringFilter::default()
    };
    let filtered = tracker.get_statistics(Some(&filter))?;

    Ok((all.total_unique_strings, filtered.total_unique_strings))
}
```

This change makes malformed regular expressions and invalid filter ranges
observable to callers.

## Typed errors and analyzer builders

`AnalysisResult<T>` now aliases `Result<T, AnalysisError>` instead of
`anyhow::Result<T>`. `AnalysisError` is non-exhaustive; match specific variants
when useful and retain a fallback arm.

Analyzer configuration builders now validate their input and return a result:

```rust
use threatflux_string_analysis::{
    AnalysisResult, DefaultPatternProvider, DefaultStringAnalyzer, PatternProvider,
};

fn analyzer() -> AnalysisResult<DefaultStringAnalyzer> {
    let patterns = DefaultPatternProvider::new()?.get_patterns();
    DefaultStringAnalyzer::new()
        .with_entropy_threshold(4.0)?
        .with_patterns(patterns)
}
```

Propagate errors from `with_entropy_threshold`, `with_max_indicators`, and
`with_patterns` instead of assuming every builder input is valid.

The unused `StringMetadata` alias and `StringAnalysis::metadata` field are
removed, along with `AnalysisConfig::enable_time_analysis` and
`custom_metadata_fields`. Applications that attach domain metadata should keep
it in their own record keyed by the tracked value or source identity.

## Batch ingestion

Use the shorter `track_strings` API for new code. The existing
`track_strings_from_results` name remains as a compatibility alias. Both return
an analysis result, and a batch is not transactional: items accepted before an
error remain tracked.

Use `track_occurrence` with a complete `StringOccurrence` when importing
historical observations. The ordinary `track_string` and `track_strings`
methods use the current UTC time.

Additional observations now aggregate their `StringContext` category onto an
existing entry. A new context category at category capacity returns
`CapacityExceeded` before changing the entry.

## Corrected filters

Version 0.2 enforces every populated filter field:

- `file_paths` matches occurrence paths;
- `file_hashes` matches occurrence digests rather than paths;
- `date_range` applies inclusive UTC bounds to `first_seen`;
- malformed `regex_pattern` values return an error; and
- populated fields combine with logical AND.

Tests that previously passed a path through `file_hashes` were relying on a 0.1
defect and must be corrected.

## Categorization and entropy policy

The built-in categorizer is intentionally narrower and more deterministic in
0.2. It now parses complete IPv4 and IPv6 values, uses token-aware command
matching, recognizes only an explicit system-API allow-list, and requires an
absolute or drive-qualified path. URL, registry, and library matching is ASCII
case-insensitive. Categories are deduplicated and equal-priority custom rules
use the rule name as a stable tie-breaker.

Re-baseline reports that depend on categorizer output. Broad 0.1 substring
matches such as `English`, `bashful`, or an arbitrary capitalized name ending in
`A` no longer receive command or API categories. During batch context inference,
a temporary path's `StringContext::Path::path_type` value changed from `temp` to
`temporary`.

High-entropy boundary behavior also changed:

- the built-in analyzer now emits `high_entropy` for values at least 12 UTF-8
  bytes long whose entropy is greater than or equal to the configured threshold;
- 0.1 used a strict greater-than comparison and accepted 11-byte values; and
- statistics now use that same configured threshold and minimum length instead
  of an independent strict `entropy > 4.0` rule.

Values exactly on a threshold can therefore move into the 0.2 result, while
11-byte values move out. Custom analyzers retain their own private threshold;
configure them from the same `AnalysisConfig` value when analyzer evidence and
high-entropy statistics should agree.

## File identities and query errors

`StringEntry::unique_files` is replaced by the ordered
`unique_file_identities: BTreeSet<FileIdentity>` field. An identity contains both
`file_path` and `file_hash`; two observations with the same path and different
digests are distinct identities. `total_files_analyzed` now counts these
identities rather than paths alone.

`search_strings` and `get_related_strings` now return `AnalysisResult`. Propagate
or handle their errors:

```rust
use threatflux_string_analysis::StringTracker;

fn search(tracker: &StringTracker) -> threatflux_string_analysis::AnalysisResult<usize> {
    let matches = tracker.search_strings("powershell", 10)?;
    let related = tracker.get_related_strings("powershell.exe", 10)?;
    Ok(matches.len() + related.len())
}
```

## Portable counters and ordered data

Public aggregate counters and occurrence filter bounds now use `u64` instead of
`usize`, and `StringContext::FileString::offset` is `Option<u64>`. This makes
serialized reports and source offsets independent of the target pointer width.
Update explicit annotations and conversions rather than using unchecked casts.

For deterministic serialization and iteration, entries now use ordered
collections: file identities and categories are `BTreeSet` values, occurrence
detail is a `VecDeque` in ingestion order, and statistic distributions are
`BTreeMap` values. `StringStatistics` adds `total_suspicious_strings` and
`total_high_entropy_strings` so callers do not mistake bounded samples for full
counts.

## Persisted data is not wire-compatible

Version 0.2 does not deserialize 0.1 JSON or other persisted serde records as a
backward-compatible schema. Among other changes:

- `StringAnalysis` removes `metadata` and adds `indicators_truncated`;
- `SuspiciousIndicator` adds `matched_text_truncated`;
- `StringEntry` replaces `unique_files`, changes occurrences and categories to
  ordered collections, uses `u64` counters, and adds retained evidence fields;
- `StringStatistics` uses portable counters, ordered maps, and explicit total
  fields; and
- `AnalysisConfig` removes inert fields and adds required retention limits.

Version stored records explicitly. Migrate 0.1 data through an application
adapter into freshly constructed 0.2 values; do not point a 0.2 deserializer at
an unversioned 0.1 store and assume defaults preserve its meaning.

## Retention and ordering

Version 0.1 capped occurrence detail but left other collections effectively
unbounded and allowed hash-map iteration order to affect output. Version 0.2
validates collection and byte limits, rejects a new distinct value when unique
capacity is full, and defines deterministic occurrence retention and output
ordering. Repeated values remain accepted at unique capacity.

Review applications that assumed:

- every historical occurrence remained in `StringEntry::occurrences`;
- every distinct input value was retained indefinitely;
- summary-vector ordering was arbitrary; or
- `suspicious_strings.len()` represented the total number of suspicious
  entries.

Aggregate occurrence counts can exceed retained detail counts. Read
[`BEHAVIOR.md`](BEHAVIOR.md) before choosing production limits.

## Pattern interpretation

URLs and IPv4 addresses are informational network categories in the default 0.2
policy. Paths, registry keys, encoding candidates, and algorithm names are also
informational. Their presence alone does not set `is_suspicious`. Consumers
that used that flag as a network-IOC detector must add a reputation source or an
explicit application pattern.

Pattern definitions now validate names, regular expressions, and the documented
severity range. Handle provider mutation errors and test benign near-matches.
Removing a missing pattern or category rule now returns `NotFound`, and adding a
duplicate name returns `DuplicateName`.

Built-in pattern identifiers changed with the narrower policy. Update any
suppression, allow-list, or presentation logic keyed by `pattern_name`:

| 0.1 identifier         | 0.2 identifier               |
| ---------------------- | ---------------------------- |
| `url_pattern`          | `url`                        |
| `ip_address`           | `ipv4_address`               |
| `shell_command`        | `shell_interpreter`          |
| `code_execution`       | `dynamic_execution_call`     |
| `crypto_algorithm`     | `crypto_algorithm`           |
| `base64_string`        | `base64_candidate`           |
| `suspicious_path`      | `temporary_or_system_path`   |
| `credential_keyword`   | `credential_assignment`      |
| `registry_key`         | `registry_key`               |
| `malware_keyword`      | `malware_behavior_term`      |
| `surveillance_keyword` | `surveillance_behavior_term` |
| `non_printable_chars`  | `non_printable_characters`   |

The built-in `high_entropy` identifier is unchanged. Matching semantics also
changed, so an identifier mapping alone is not a compatibility shim.

## Migration checklist

- [ ] Raise the dependency to `0.2.0` and use Rust 1.95.0 or newer.
- [ ] Replace capacity builders with `AnalysisConfig` where applicable.
- [ ] Propagate constructor, ingestion, and statistics errors.
- [ ] Replace `anyhow`-specific analysis error handling and propagate fallible
      analyzer builders.
- [ ] Move any application metadata out of the removed placeholder fields.
- [ ] Migrate or invalidate persisted 0.1 serde records under an explicit schema
      version.
- [ ] Prefer `track_strings`. The `track_strings_from_results` method name remains
      available as an alias, but its typed error and new validation failures
      require the same error-handling review.
- [ ] Correct path/hash filters and handle invalid regular expressions.
- [ ] Replace `unique_files` access with `unique_file_identities` and review
      distinct-file totals.
- [ ] Propagate errors from search and related-string queries.
- [ ] Update `usize` count/offset assumptions to `u64` and consume the new total
      fields instead of sample lengths.
- [ ] Select explicit retention limits for the workload.
- [ ] Handle `InputTooLarge` and `CapacityExceeded` without silently dropping an
      observation.
- [ ] Review code that treats `is_suspicious` or severity as a verdict.
- [ ] Update suppressions and reports keyed by renamed built-in pattern IDs.
- [ ] Re-run integration tests with representative benign and suspicious data.
- [ ] Update wrappers, exported reports, and operational documentation.
