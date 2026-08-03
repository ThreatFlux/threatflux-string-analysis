# Patterns and heuristic indicators

Patterns attach categories to matching strings and can optionally contribute a
suspicious indicator. Informational matches add only their category. Each
suspicious match records an identifier, description, severity, and bounded
matched text when available.

Matched evidence is limited to 512 UTF-8 bytes and exposes a truncation flag.
When an analyzer produces more indicators than configured, the entry retains
the highest-severity evidence, prefers earlier evaluation order for equal
severities, preserves evaluation order in the returned subset, and sets
`indicators_truncated`.

Patterns are not signatures of malicious intent. A match says that a string has
a syntactic property selected by the pattern author.

## Built-in policy

The built-in provider covers broad groups such as network references, command
execution, encodings, sensitive paths, credential terminology, registry keys,
and malware-related vocabulary.

The default policy distinguishes information from suspicion:

- URLs and syntactically valid IPv4 values are categorized as network
  information but are not suspicious merely because they exist.
- Paths, registry keys, encoding candidates, and cryptographic algorithm names
  are also informational by default.
- Shell interpreters, credential assignments, dynamic-execution calls, and
  malware-oriented vocabulary may contribute suspicious indicators.
- High byte entropy and unexpected control characters are analyzer heuristics,
  not regular-expression patterns.

Built-in severities prioritize review within this library's output. They are
integers from 0 through 10, not CVSS scores, probabilities, or a stable mapping
to another product's risk levels.

The built-in provider and analyzer emit the following stable identifiers within
the 0.2 release line:

| Identifier                            | Category       | Policy        | Severity |
| ------------------------------------- | -------------- | ------------- | -------: |
| `url`                                 | `network`      | Informational |        — |
| `ipv4_address`                        | `network`      | Informational |        — |
| `crypto_algorithm`                    | `crypto`       | Informational |        — |
| `base64_candidate`                    | `encoding`     | Informational |        — |
| `temporary_or_system_path`            | `path`         | Informational |        — |
| `registry_key`                        | `registry`     | Informational |        — |
| `shell_interpreter`                   | `command`      | Suspicious    |        6 |
| `dynamic_execution_call`              | `execution`    | Suspicious    |        7 |
| `credential_assignment`               | `credential`   | Suspicious    |        8 |
| `malware_behavior_term`               | `malware`      | Suspicious    |        9 |
| `surveillance_behavior_term`          | `surveillance` | Suspicious    |        8 |
| `high_entropy` (analyzer)             | —              | Suspicious    |        6 |
| `non_printable_characters` (analyzer) | —              | Suspicious    |        5 |

The first eleven rows are regular-expression patterns. The final two are
analyzer heuristics and therefore do not attach a pattern category.

Broad patterns will produce false positives. For example, documentation may
contain the words `token` or `powershell`, software can legitimately use
encoding, and administrative tools frequently contain command strings.

## Add a custom pattern

Bring the `PatternProvider` trait into scope when modifying a provider:

```rust
use threatflux_string_analysis::{
    DefaultPatternProvider, PatternDef, PatternProvider,
};

fn application_patterns(
) -> Result<DefaultPatternProvider, Box<dyn std::error::Error>> {
    let mut provider = DefaultPatternProvider::empty();

    provider.add_pattern(PatternDef {
        name: "example_token_name".to_owned(),
        regex: r"(?i)\bexample[_-]?token\b".to_owned(),
        category: "credential".to_owned(),
        description: "Application-specific token field name".to_owned(),
        is_suspicious: true,
        severity: 6,
    })?;

    Ok(provider)
}
```

`DefaultPatternProvider::empty` starts with no built-ins. Use
`DefaultPatternProvider::new` when an application wants the built-in set and
then add its own definitions.

Pattern names should be unique and stable within a compatible release line
because downstream systems may use them for explanation or suppression. The
0.2 built-in rename mapping is documented in
[`MIGRATING_TO_0.2.md`](MIGRATING_TO_0.2.md). Adding a duplicate name is invalid.
Updating a pattern validates the replacement before changing the active set, so
an invalid regular expression cannot silently remove a working definition.

## Regular-expression behavior

Pattern expressions use Rust's [`regex`](https://docs.rs/regex) syntax. Features
such as look-around and backreferences are not supported. Compilation can fail
and is therefore part of the fallible provider API.

Write patterns that are:

- anchored when the entire value must match;
- explicit about case sensitivity;
- narrow enough to explain and test;
- assigned a descriptive category independent of suspicion; and
- tested against representative true positives and benign near-misses.

Do not embed live credentials, private indicators, customer identifiers, or
licensed signature content in source code or tests.

## Entropy

Entropy is calculated over UTF-8 bytes. Values at least 12 bytes long and at or
above the analyzer's configured threshold can produce a `high_entropy`
indicator.

High entropy can arise from encryption, compression, encoding, hashes, random
identifiers, or ordinary non-ASCII text. Low entropy does not demonstrate that
content is benign. Tune the threshold against a representative corpus and keep
entropy as one signal among several.

## Categories and context

Pattern categories, categorizer categories, and the caller-provided
`StringContext` category are combined on an entry. A category is descriptive;
it does not make an entry suspicious by itself.

Categorization rules can return more than one category. Rule priority provides
a deterministic evaluation order, not an automatic first-match-wins policy.

## Operational guidance

- Version and review pattern changes like code.
- Record the rationale, expected matches, and known false positives.
- Test invalid patterns and severity bounds.
- Compare alert volume before and after deployment.
- Prefer a narrow application-specific pattern over making a broad built-in
  pattern more aggressive.
- Preserve the matched pattern name and description when presenting a signal to
  an analyst.
