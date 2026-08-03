# Contributing

Thank you for improving ThreatFlux String Analysis. Focused bug reports,
documentation fixes, tests, pattern refinements, and implementation changes are
welcome.

By participating, you agree to follow the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Report suspected vulnerabilities
privately as described in [`SECURITY.md`](SECURITY.md).

## Before opening an issue

- Search existing issues and pull requests.
- Confirm the behavior on the latest release or `main`.
- Reduce bugs to a small reproducible example when possible.
- Include the crate and Rust versions, platform, configuration, filter, and
  relevant pattern names.
- For classification concerns, provide benign and expected-match examples and
  explain the desired semantics.

Do not post credentials, customer data, live private indicators, proprietary
signatures, malware samples, or sensitive file paths in a public report.

## Development workflow

1. Fork the repository and create a branch from `main`.
2. Make one focused change with tests and documentation.
3. Run the checks in [`TESTING.md`](TESTING.md).
4. Review the diff for generated files, sensitive strings, and unrelated edits.
5. Open a pull request describing the problem, approach, compatibility impact,
   heuristic tradeoffs, and validation performed.

Use clear commit messages in the imperative mood. Keep commits small enough to
review independently; maintainers may squash them when merging.

## Pull-request checklist

- [ ] Public behavior and compatibility impact are documented.
- [ ] Tests cover exact boundaries and regressions.
- [ ] Results and retention remain deterministic.
- [ ] New or changed patterns include benign near-miss cases.
- [ ] Formatting, Clippy, tests, rustdoc, audit, and dependency policy pass.
- [ ] Migration and changelog notes cover user-visible changes.
- [ ] No extracted production data, credentials, or generated output is present.

## API and behavior changes

This crate is pre-1.0, but compatibility still matters. Call out removed or
renamed public items, changed defaults or trait bounds, new error paths,
serialized representation changes, and altered filtering or ordering. Run
`cargo-semver-checks` when a release baseline is available.

Capacity and filtering changes require tests for:

- values immediately below, at, and above each limit;
- repeated and distinct values at global capacity;
- deterministic occurrence retention and exact timestamp handling;
- every filter field and cross-field combinations; and
- malformed patterns, ranges, and caller timestamps.

## Pattern contributions

New patterns must explain what they identify and why a match should be
informational or suspicious. Include representative true positives and benign
near-misses. Severity is a local review priority, not probability or CVSS.

Prefer narrow application patterns over broad expressions likely to flag normal
software. Read [`docs/PATTERNS.md`](docs/PATTERNS.md) before proposing a built-in
pattern.

## Review

Maintainers may request changes for correctness, safety, API consistency,
documentation, tests, false-positive risk, or release compatibility. A pull
request may be closed if it becomes inactive or diverges from project scope;
useful work can be reopened as a smaller follow-up.
