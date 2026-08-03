# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Stage GitHub release assets from the canonical crates.io archive and verify
  its registry checksum instead of assuming `cargo publish` retains a local
  package file.

## [0.2.0] - 2026-08-03

### Added

- Validated `AnalysisConfig` construction with explicit collection and UTF-8
  byte bounds.
- Caller-timestamp ingestion for deterministic imports and boundary tests.
- A concise `track_strings` batch API while retaining
  `track_strings_from_results` as a compatibility alias.
- Behavior, pattern, migration, integration, testing, security, contribution,
  and release documentation.
- Regression coverage for filter correctness, configuration boundaries,
  deterministic retention, and hostile input sizes.

### Changed

- Made statistics generation fallible so invalid regular expressions and filter
  ranges are returned to callers.
- Replaced the `anyhow` result alias with a documented, non-exhaustive
  `AnalysisError` and made configurable analyzer builders fallible.
- Corrected file-path, file-hash, and date filtering and made summary ordering
  deterministic.
- Replaced path-only `StringEntry::unique_files` tracking with ordered
  `(file_path, file_hash)` `FileIdentity` values; total-file statistics now count
  distinct identities.
- Made search and related-string queries fallible so invalid or oversized input
  is reported.
- Changed aggregate counters and file offsets to portable `u64` values, adopted
  ordered public collections, and added full suspicious/high-entropy totals
  alongside bounded samples.
- Changed the persisted serde schema and built-in pattern identifiers; 0.1
  records require an explicit application migration.
- Made URL and IP-address patterns informational rather than suspicious by
  default; heuristic indicators are not threat verdicts.
- Narrowed built-in categorization, renamed inferred temporary path context from
  `temp` to `temporary`, and aligned analyzer/statistics high-entropy boundaries
  to the configured threshold and a 12-byte minimum.
- Replaced unbounded or ambiguous retention behavior with explicit capacity
  rejection and deterministic occurrence retention.
- Hardened CI, documentation, security, and release automation with pinned
  actions, least-privilege permissions, and reproducible package checks.
- Adopted the Rust 2024 edition while preserving Rust 1.95.0 as the MSRV.
- Reworked examples and documentation around the supported 0.2 API.

### Removed

- Removed post-construction occurrence-cap configuration in favor of validated
  `AnalysisConfig` construction.
- Removed the unused `StringMetadata`, `StringAnalysis::metadata`,
  `enable_time_analysis`, and `custom_metadata_fields` surfaces.
- Removed generic repository bootstrap and pre-commit installation scripts.

See [`docs/MIGRATING_TO_0.2.md`](docs/MIGRATING_TO_0.2.md) for upgrade guidance.

## [0.1.1] - 2025-08-14

### Changed

- Declared Rust 1.95.0 as the package's minimum supported Rust version.
- Updated dependencies and compatibility fixes for the initial published API.

## [0.1.0] - 2025-08-14

### Added

- Initial standalone string tracking, categorization, entropy, pattern,
  filtering, search, and related-string APIs extracted for file-scanner use.

[Unreleased]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ThreatFlux/threatflux-string-analysis/releases/tag/v0.1.0
