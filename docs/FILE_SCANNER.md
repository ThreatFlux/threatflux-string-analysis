# File-scanner integration

ThreatFlux String Analysis originated as string-tracking functionality in
[ThreatFlux file-scanner](https://github.com/ThreatFlux/file-scanner). The
standalone crate lets other applications reuse that functionality without
depending on the scanner.

This document describes the integration boundary; it does not promise that every
version of the two repositories is interchangeable.

## Version compatibility

File-scanner selects an explicit `threatflux-string-analysis` crate version in
its workspace manifest and exposes a small compatibility wrapper. Check that
manifest and wrapper before changing either public API.

| String-analysis line | Integration status                                                   |
| -------------------- | -------------------------------------------------------------------- |
| `0.2.x`              | Fallible statistics and validated bounded configuration              |
| `0.1.x`              | Legacy constructor, batch-ingestion, and statistics call conventions |

Version 0.2 is a compatibility boundary because this crate is still pre-1.0.
Follow [`MIGRATING_TO_0.2.md`](MIGRATING_TO_0.2.md) when updating file-scanner
or another existing consumer.

## Wrapper responsibilities

The file-scanner wrapper should remain intentionally small. It may:

- re-export shared data types required by file-scanner;
- construct a tracker with file-scanner's explicit capacity policy;
- translate scanner extraction results into batch ingestion calls; and
- propagate analysis errors to the scanner's existing error boundary.

It should not duplicate pattern definitions, filtering, retention, or
related-string scoring. Those behaviors belong in this crate and must be tested
here.

## Data mapping

| File-scanner input       | String-analysis field                       |
| ------------------------ | ------------------------------------------- |
| Extracted value          | Tracked string value                        |
| Source path              | `StringOccurrence::file_path`               |
| Content digest           | `StringOccurrence::file_hash`               |
| Extractor or parser name | `StringOccurrence::tool_name`               |
| Extraction location      | Appropriate `StringContext` variant         |
| Extraction timestamp     | `track_occurrence` timestamp or current UTC |

Paths and hashes are different fields and must be tested independently. Do not
place a path in a hash filter or infer a digest from a filename.

File-scanner should handle `InputTooLarge` and `CapacityExceeded` explicitly.
The library validates values and every owned source/context string before
mutation, but file-scanner should apply tighter extraction budgets when its
threat model requires them.

## Integration testing

Changes affecting the wrapper require validation in both repositories:

1. Run this crate's complete matrix from [`../TESTING.md`](../TESTING.md).
2. Point a temporary file-scanner branch at the candidate revision.
3. Run file-scanner unit, integration, and representative extraction tests.
4. Confirm configured limits, filtered statistics, and error propagation.
5. Update the file-scanner dependency only after this crate version is
   published.

Avoid claims of unchanged performance without repeatable benchmarks against the
same corpus and toolchains.

## Security boundary

Extracted strings and their metadata are untrusted. File-scanner remains
responsible for bounding files and extraction output before ingestion, handling
analysis errors, protecting sensitive paths and strings, and deciding how
heuristic signals affect its final report. A pattern match is not a malware
verdict.
