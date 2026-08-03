# Testing

ThreatFlux String Analysis supports Rust 1.95.0 or newer. The repository pins
Rust 1.97.1 for stable development and CI.

## Fast local loop

Run these while developing:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
```

## Pull-request validation

Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
cargo build --examples --all-features --locked
make markdown
```

Validate the minimum Rust version separately:

```bash
rustup toolchain install 1.95.0 --profile minimal
cargo +1.95.0 check --all-targets --all-features --locked
cargo +1.95.0 test --all-targets --all-features --locked
```

The crate currently has no optional feature flags. Continue using
`--all-features` in shared commands so a future feature cannot bypass routine
checks.

## Security and dependency checks

```bash
cargo audit --deny warnings
cargo deny check
```

These tools use current advisory and index data, so a result can change without
a source change. Investigate failures rather than adding broad ignores.

## Required behavior coverage

| Area              | Required coverage                                                                      |
| ----------------- | -------------------------------------------------------------------------------------- |
| Configuration     | Every zero limit, entropy bounds, non-finite values, and default construction          |
| Input bounds      | Exact byte boundary and one byte over for values and every source/context field        |
| Capacity          | New and repeated values at unique capacity; no eviction or partial rejected mutation   |
| Occurrences       | Retention boundary, total count, caller timestamps, and ingestion-order ties           |
| Source identities | Duplicate and new path/hash pairs at their per-string limit                            |
| Categories        | Context aggregation, deduplication, and category-cap rejection                         |
| Patterns          | Expected matches, benign near-misses, invalid regexes, duplicates, and severity bounds |
| Filters           | Every field independently, cross-field AND behavior, empty lists, and invalid ranges   |
| Statistics        | Exact totals, bounded summaries, deterministic ordering, and overflow handling         |
| Search            | Empty queries, case handling, stable tie-breakers, limits, and Unicode values          |
| Relatedness       | Missing targets, stable ordering, threshold boundaries, and zero-length strings        |
| Concurrency       | Shared clones, simultaneous ingestion/readers, and extension-panic isolation           |

Tests should assert exact outcomes. Avoid tautologies, broad timing thresholds,
or comments such as “if implemented.” A coverage increase is useful only when
the test protects behavior.

## Test data

- Use reserved `.example` or `.invalid` domains.
- Use clearly synthetic hashes, paths, credentials, and pattern names.
- Do not access the network or local production files.
- Do not use customer data, live indicators, malware samples, or private
  signatures.
- Prefer caller-provided timestamps to sleeps and wall-clock assumptions.

## Documentation tests

Rustdoc examples, README snippets, and examples are part of the supported
surface. The `make markdown` target compiles Rust blocks in the README and
guides against the local crate.

When documenting a removed API, mark the historical block `rust,ignore` and
pair it with a compiling current example.

## Coverage

Coverage is a diagnostic, not a release criterion by itself:

```bash
cargo llvm-cov --all-features --workspace --locked --lcov --output-path lcov.info
```

Keep generated reports out of git and the crates.io package.

## Release validation

Release candidates also require package inspection, a crates.io dry run, and
public API comparison from [`docs/RELEASING.md`](docs/RELEASING.md).
