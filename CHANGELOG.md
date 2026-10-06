# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] - 2026-10-06

No library API or behavior change.

### Changed

- Refreshed the committed `Cargo.lock` to `thiserror` 2.0.21.
- Updated the README install snippet to 0.2.3.

### Release engineering

- Releases are cut by the `threatflux-automation` GitHub App, so the release
  tag starts `release.yml` exactly once.
- Publishing uses crates.io trusted publishing only: the `publish` job
  exchanges its OIDC token for a short-lived crates.io token in the
  `crates-io` environment, and the long-lived registry token fallback is
  removed. A version that is already published is skipped, so a release can be
  re-run.
- Before publishing, the release now builds and tests the crate on six
  targets: Linux (x86_64 glibc and musl, aarch64), macOS (Apple silicon and
  Intel), and Windows.
- The GitHub release attaches a CycloneDX SBOM next to the published crate
  archive, its checksum, and the package listing, carries a build provenance
  attestation for the crate and the SBOM, and uses this changelog section as
  its notes.
- `release.yml` and `auto-release.yml` accept a `dry_run` dispatch input that
  rehearses a release without tagging, releasing, or publishing anything.
- Workflows run with read-only default permissions, and every action is
  pinned to a full commit SHA.

## [0.2.2] - 2026-08-11

### Changed

- Refreshed every dependency requirement to the latest stable release,
  including `regex` 1.13.1, `chrono` 0.4.45, `serde` 1.0.229, and
  `serde_json` 1.0.151. No API change.
- Updated the README install snippet, which still named 0.2.0.

### Fixed

- Dispatch the release workflow after an automated release tag, because a tag
  pushed with the default workflow token starts no workflow.

## [0.2.1] - 2026-08-07

This version was tagged and released on GitHub but was not published to
crates.io. Use 0.2.2 or later.

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

[Unreleased]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/ThreatFlux/threatflux-string-analysis/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ThreatFlux/threatflux-string-analysis/releases/tag/v0.1.0
