# Development

This guide covers the local workflow for ThreatFlux String Analysis. Read
[`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request and
[`TESTING.md`](TESTING.md) for the complete validation matrix.

## Prerequisites

- Rust 1.95.0 or newer, installed with [rustup](https://rustup.rs/)
- `rustfmt` and Clippy
- Git

The repository pins its stable development toolchain to Rust 1.97.1. The crate
has no required native system libraries.

```bash
rustup toolchain install 1.97.1 --profile minimal --component rustfmt,clippy
cargo check --all-targets --all-features --locked
```

Optional repository checks use the following tools:

```bash
cargo install --locked cargo-audit
cargo install --locked cargo-deny
cargo install --locked cargo-semver-checks
```

No setup script modifies the host or installs system packages. Install optional
tools explicitly and review their upstream installation instructions first.

## Useful commands

```bash
cargo fmt --all
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
cargo build --examples --all-features --locked
```

Run `make help` for concise aliases. Direct Cargo commands are the source of
truth and work on every supported platform.

## Design expectations

- Treat tracked strings, paths, hashes, timestamps, pattern definitions, and
  serialized caller data as untrusted input.
- Validate configuration before allocating or accepting observations.
- Keep every retained collection bounded by documented configuration.
- Make bounded occurrence retention and result ordering deterministic; never use
  map iteration order as a public tie-breaker.
- Keep informational categorization separate from suspicious indicators.
- Return invalid configuration, pattern, filter, and component output as errors
  instead of panicking or silently ignoring them. Keep extension callbacks
  outside the shared-state lock.
- Document public behavior changes and false-positive/false-negative tradeoffs.

The observable contract lives in [`docs/BEHAVIOR.md`](docs/BEHAVIOR.md), and
pattern semantics live in [`docs/PATTERNS.md`](docs/PATTERNS.md).

## Tests

Unit tests live beside their modules and integration tests live in `tests/`.
Examples and public documentation snippets must compile. Add focused regression
tests for fixes rather than coverage-only assertions.

Important boundaries include:

- zero, one, and maximum configured capacities;
- capacity rejection, occurrence retention, and exact-timestamp ties;
- every `StringFilter` field, both independently and in combination;
- malformed regular expressions and out-of-range severity values;
- Unicode strings, empty strings, control characters, and large inputs;
- concurrent clones and extension panics that must not poison shared state; and
- caller-supplied timestamps at inclusive range boundaries.

Tests should not rely on the network, execution order, locale, wall-clock sleeps,
or a developer's home directory. Prefer explicit timestamps where the API
allows them.

## Documentation

Public API changes require rustdoc updates and, when user-visible, corresponding
README, behavior, migration, and changelog changes.

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
cargo test --doc --all-features --locked
make markdown
```

Use `.example` or `.invalid` domains and synthetic hashes in examples. Never add
live indicators, customer data, credentials, malware samples, or private paths.

## Security-sensitive changes

Do not open a public issue for a suspected vulnerability. Follow
[`SECURITY.md`](SECURITY.md). Run dependency and policy checks with:

```bash
cargo audit --deny warnings
cargo deny check
```
