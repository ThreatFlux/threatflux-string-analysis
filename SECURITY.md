# Security Policy

## Supported versions

Security fixes are provided for the latest published minor release. Users should
upgrade to the newest patch before reporting a problem.

| Version              | Supported |
| -------------------- | :-------: |
| Latest `0.x` release |    Yes    |
| Older releases       |    No     |

## Reporting a vulnerability

Do not open a public issue or discussion for a suspected vulnerability.

Use GitHub's
[private vulnerability reporting](https://github.com/ThreatFlux/threatflux-string-analysis/security/advisories/new).
If that is unavailable, email `security@threatflux.ai` with the repository name
in the subject.

Include, when possible:

- affected crate and Rust versions;
- realistic input, configuration, and attack conditions;
- impact, including confidentiality, integrity, availability, or unsafe policy
  decisions;
- a minimal reproducer or pattern definition;
- suggested mitigations; and
- whether the issue is already public.

Remove credentials, personal information, customer strings, and unrelated
production data. Encrypt especially sensitive material before sending it and
ask for a preferred key or transfer method.

Validation, remediation, disclosure timing, and credit are coordinated
privately. Please allow a reasonable remediation window before public
disclosure.

## Security model

ThreatFlux String Analysis processes caller-provided strings and metadata in the
current process. Its built-in components do not execute tracked strings, access
files named by paths, contact network addresses, persist observations, or query
reputation services. Application-provided components are trusted code and are
outside that guarantee.

The crate is not:

- a malware scanner or threat verdict engine;
- an authorization or data-loss-prevention boundary;
- a secret detector with guaranteed recall;
- a validator for URLs, IP ownership, file hashes, or executable behavior; or
- a substitute for application-level input and memory budgets.

Applications remain responsible for limiting aggregate workload, protecting
sensitive observations, authorizing access to results, handling analysis
errors, and combining heuristic output with independent evidence.

Configuration bounds reduce accidental and adversarial memory growth, but they
are independent count/field ceilings rather than a global heap-byte budget. The
application must select compatible limits and control concurrency, query output,
and total tracker count. See
[`docs/BEHAVIOR.md`](docs/BEHAVIOR.md) and
[`docs/PATTERNS.md`](docs/PATTERNS.md) for detailed boundaries.

Application-provided analyzer and categorizer implementations are trusted
in-process code. The tracker bounds their retained output, but cannot sandbox
their execution, allocations, side effects, or panics.

## Classification reports

A false positive or false negative is not automatically a vulnerability.
Classification issues are still valuable and can normally be reported through a
public issue using synthetic data. Use the private channel when a defect could
cause a security boundary bypass, disclose sensitive data, trigger resource
exhaustion, or affect users before a fix is available.

## Dependency disclosures

Reports that only repeat a dependency advisory should explain whether the
affected code is reachable in this crate. Automated scanner output is useful,
but reachability and realistic impact help maintainers prioritize remediation.
