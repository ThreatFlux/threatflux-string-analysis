# Behavior and limits

This document defines the observable behavior of ThreatFlux String Analysis
0.2. The Rust API documentation remains authoritative for individual fields and
methods.

## Data model

`StringTracker` stores one `StringEntry` for each distinct string value. An entry
contains:

- first- and last-seen UTC timestamps;
- an aggregate accepted-occurrence count;
- a bounded, ordered set of `(file_path, file_hash)` `FileIdentity` values;
- bounded occurrence detail with path, digest, tool, timestamp, and context;
- categories from context, categorization rules, and matching patterns;
- byte-level Shannon entropy; and
- whether one or more configured heuristics marked the value suspicious.

Entries and statistics are returned as owned values. Returning them therefore
clones retained strings and collections.

## Construction and configuration

`StringTracker::new` constructs a tracker with validated library defaults and is
infallible. `StringTracker::with_config` validates a caller-provided
`AnalysisConfig` and returns an error for unusable capacity values, invalid
thresholds, and other inconsistent settings.

The 0.2 defaults are:

| Setting                                 |     Default | Meaning                                           |
| --------------------------------------- | ----------: | ------------------------------------------------- |
| `min_suspicious_entropy`                |       `4.5` | Byte-entropy threshold                            |
| `max_occurrences_per_string`            |     `1,000` | Detailed observations retained per value          |
| `max_unique_strings`                    |   `100,000` | Distinct values retained by one tracker           |
| `max_input_bytes`                       | `1,048,576` | UTF-8 bytes in a tracked value                    |
| `max_source_bytes`                      |    `16,384` | UTF-8 bytes in each source or owned context field |
| `max_unique_file_identities_per_string` |     `1,024` | Distinct `(file_path, file_hash)` pairs per value |
| `max_categories_per_string`             |        `64` | Aggregate category names per value                |
| `max_indicators_per_string`             |        `64` | Suspicious indicators per value                   |

Every count and byte limit must be nonzero. The entropy threshold must be
finite and between 0 and 8 inclusive.

These settings are independent ceilings. The crate does not enforce one global
heap-byte budget, and configuring several maxima near their largest useful
values can multiply into a very large retained data set. Select them together
from a measured workload and application memory budget.

Configuration is captured by a tracker instance. Clones share retained entries
but retain the same capacity and analysis policy. Changing a configuration
value requires constructing a new tracker.

`StringTracker::with_config` applies `min_suspicious_entropy` to both the
built-in analyzer and high-entropy statistics. With
`with_components_and_config`, the tracker cannot rewrite a custom analyzer's
private threshold; callers should configure that analyzer from the same value
when they want indicator and statistics thresholds to agree.

## Ingestion and timestamps

`track_string` records an observation with the current UTC time.
`track_occurrence` accepts a complete `StringOccurrence`, including a
caller-provided UTC timestamp, for replayable imports and boundary tests.
Applications should normalize source timestamps before ingestion and reject
values outside their own acceptable time window.

`track_strings` and its `track_strings_from_results` compatibility alias process
a slice in order. Batch ingestion returns an error when an item cannot be
accepted. It is not a transaction: observations accepted before the error
remain tracked. Callers that need all-or-nothing behavior must stage and
validate the batch first.

The tracker analyzes and categorizes a value when its entry is first created.
Additional observations update occurrence, file, timestamp, and context-category
information; they do not reinterpret an existing value under a different
analyzer. Each accepted context category is aggregated onto the existing entry.

## Deterministic bounded retention

Every value and source field is measured in UTF-8 bytes and validated before a
tracking mutation. `max_source_bytes` applies independently to `file_path`,
`file_hash`, `tool_name`, and every owned string inside `StringContext`.
Oversized input returns `InputTooLarge` without creating or updating an entry.

All retained collections governed by `AnalysisConfig` enforce their limits:

- At `max_unique_strings`, an unseen value returns `CapacityExceeded`. Existing
  values remain accepted; the tracker does not silently evict another entry.
- Per-string occurrence detail retains the most recently ingested records and
  discards the oldest ingested record when its detail limit is crossed. Caller
  timestamp does not change that ingestion ordering.
- `first_seen` and `last_seen` remain the minimum and maximum caller timestamps
  across every accepted observation, including discarded detail.
- File identity is the `(file_path, file_hash)` pair. At its per-string limit,
  an already retained identity remains accepted and a new pair returns
  `CapacityExceeded` before mutation.
- Every accepted observation contributes its context category. An existing
  category remains accepted at category capacity; a new category returns
  `CapacityExceeded` before mutation.
- Analyzer and categorizer categories must fit their configured limit before a
  new entry is inserted.
- When suspicious indicators exceed their configured limit, the highest
  severities are retained, equal severities prefer earlier evaluation order,
  the returned subset preserves evaluation order, and `indicators_truncated`
  is set. Matched evidence is limited to 512 UTF-8 bytes and records whether it
  was shortened.
- If a custom analyzer reports `is_suspicious` without returning evidence, the
  tracker preserves that signal and sets `indicators_truncated` to show that no
  explainable indicator was retained.

Retention and summary ordering never depend on randomized map iteration order.
With the built-in components—or custom callbacks that are deterministic for a
given input—the same configuration and operation sequence produce the same
detail and output ordering.

Discarding retained detail does not decrement an entry's aggregate occurrence
count. Statistics can therefore report more occurrences than the number of
`StringOccurrence` records currently stored. The aggregate count saturates at
`u64::MAX` rather than wrapping.

Configuration bounds apply per tracker and per field. Applications must still
limit aggregate tracker count, concurrency, query output, and total workload at
their trust boundary.

## Filtering

`get_statistics(None)` describes every retained entry.
`get_statistics(Some(&filter))` combines every populated `StringFilter` field
with logical AND:

- occurrence, UTF-8 byte-length, and entropy ranges are inclusive;
- category, file-path, and file-hash lists use any-of matching within that
  field;
- different fields still combine with AND;
- `suspicious_only: Some(true)` keeps only heuristic-positive entries, while
  `None` or `Some(false)` does not restrict by that flag;
- a regular expression applies to the tracked value; and
- the date range is inclusive and applies to `first_seen`.

An invalid regular expression returns an error. It is never treated as an empty
filter. Empty allow-lists match no entries. A lower range bound greater than its
upper bound is invalid rather than silently producing misleading statistics.

Filter inputs are bounded before compilation or matching. Category-list length
uses `max_categories_per_string`; path- and hash-list lengths use
`max_unique_file_identities_per_string`; every list item uses
`max_source_bytes`. A filter expression is limited to the smaller of
`max_source_bytes` and 64 KiB.

Path and hash filters are independent. Hash filters inspect occurrence digests,
not the set of source paths.

## Statistics and ordering

`StringStatistics` describes the filtered entry set:

- `total_unique_strings` counts matching retained entries;
- `total_occurrences` sums their aggregate occurrence counts;
- `total_files_analyzed` counts distinct retained `FileIdentity` values;
- `most_common` is ordered by occurrence count descending, then value
  ascending;
- `total_suspicious_strings` counts every matching suspicious entry, while the
  `suspicious_strings` sample is ordered by maximum severity descending,
  occurrence count descending, then value ascending;
- `total_high_entropy_strings` counts every matching entry at least 12 UTF-8
  bytes long and at or above the tracker's configured threshold;
- `high_entropy_strings` is ordered by entropy descending, then value
  ascending; and
- category and length distributions count entries, not observations.

Summary sample lists are intentionally bounded. Their length is not a count of
every matching entry; use the corresponding total or a targeted lookup when the
full set matters. Category distributions are exact and can contain one key per
distinct retained category in the filtered set.

## Search and related strings

`search_strings` performs a case-insensitive substring search over tracked
values. An empty or whitespace-only query returns no results. Results are
ordered by occurrence count descending with a stable value tie-breaker and then
truncated to the requested limit. The method returns `AnalysisResult`, including
for an oversized query.

`get_related_strings` ranks other retained values using a fixed weighted score:
55% Jaccard similarity of file identities, 25% Jaccard similarity of meaningful
categories, 10% entropy proximity, and 10% UTF-8 byte-length proximity. Generic
and file-string context categories do not contribute. Results below `0.30` are
excluded, and ties use value order.

The score is only a relative ranking heuristic. It is not a probability,
confidence interval, threat score, or proof that two artifacts share an origin.
The method is fallible, so callers must handle its `AnalysisResult`.

## Concurrency and failure behavior

Clones of a tracker share the same synchronized store. Individual calls are
serialized where required, but a sequence of calls is not a transaction and can
observe intervening writes from another thread.

Custom analyzer and categorizer callbacks are trusted caller code. They execute
outside the shared-state mutex, so a callback panic propagates without poisoning
the retained store. The tracker validates and bounds returned categories and
analysis evidence before insertion, but it cannot constrain a callback's own
CPU use, allocations, side effects, or internal state.

Public operations that can fail return `AnalysisResult`. Configuration, input,
capacity, pattern, and filter errors are reported rather than ignored. Input and
capacity validation occurs before a tracking mutation, while a sequential batch
can retain earlier successful items. Applications should propagate or handle
these errors; ignoring them can produce incomplete analysis.

## Security interpretation

The crate performs local syntactic and statistical analysis. It does not query
reputation services, validate network ownership, inspect executable behavior,
or establish malicious intent. Benign administration tools, URLs, credentials
documentation, encoded assets, and random identifiers can match heuristics;
malicious content can avoid them.

Treat categories, severities, entropy, relatedness, and `is_suspicious` as
explainable signals to combine with provenance and independent evidence. See
[`PATTERNS.md`](PATTERNS.md) for pattern-specific guidance.
