# Releasing

This checklist is for ThreatFlux String Analysis maintainers. Releases should be
produced from a clean, protected `main` branch through the repository's release
workflow.

## Prepare

1. Choose the version from public API, behavior, MSRV, pattern-policy, and
   serialization compatibility changes. A pre-1.0 minor bump can be breaking.
2. Update README installation snippets and migration guidance. Move release
   notes from `Unreleased` into a dated `## [X.Y.Z] - YYYY-MM-DD` section in
   `CHANGELOG.md` and update its comparison links; that section becomes the
   GitHub release notes. `auto-release.yml` bumps the version in `Cargo.toml`
   and `Cargo.lock`; bump them yourself only when you tag a release by hand.
3. Confirm the package description, license, repository and documentation URLs,
   categories, keywords, and include set.
4. Run the complete matrix in [`../TESTING.md`](../TESTING.md).
5. Compare the public API with the previous release:

   ```bash
   cargo semver-checks check-release --all-features
   ```

6. Inspect exactly what crates.io will receive:

   ```bash
   cargo package --list --locked
   cargo package --locked
   cargo publish --dry-run --locked
   ```

The package must not contain credentials, extracted strings, scan results,
coverage output, generated documentation, workflow files, or repository
bootstrap scripts.

## Pattern and behavior review

Before release, review changes to built-in patterns and thresholds separately
from compilation and unit-test status:

- document why each new suspicious pattern is security-relevant;
- test representative matches and benign near-misses;
- confirm URLs and IP addresses remain informational unless policy explicitly
  changes;
- compare output volume on a representative, non-sensitive corpus; and
- call out retention, ordering, or filter changes in the changelog.

Do not publish private indicators or customer-derived examples as release test
data.

## Rehearse

Run the release workflow as a dry run before cutting a release. It builds and
tests every release target, generates the CycloneDX SBOM, packages the crate,
and runs `cargo publish --dry-run`, without tagging, releasing, or publishing:

```bash
gh workflow run release.yml --ref main -f dry_run=true
gh workflow run auto-release.yml --ref main -f dry_run=true
```

The auto-release dry run reports the version and tag the next release would
use.

## Publish

1. Merge the release change to `main` and wait for every required check.
2. Let `auto-release.yml` cut the release once CI and Security pass on `main`
   (a `feat:` or `fix:` commit since the last tag selects the bump), or create
   an annotated `vX.Y.Z` or `vX.Y.Z-prerelease` tag from the verified `main`
   commit yourself. Release tags with SemVer build metadata (`+...`) are not
   supported.
3. The tag starts `release.yml`, which validates its provenance, builds and
   tests every target, and publishes the crate. A version that is already on
   crates.io is skipped rather than uploaded again, so the workflow can be
   re-run safely.
4. After crates.io publication succeeds, the workflow creates or updates the
   GitHub release, attaches the exact published crate archive, its checksum,
   the package listing, and the SBOM, and records a build provenance
   attestation for the crate and the SBOM. The release notes are the
   `CHANGELOG.md` section for the version; without one, the notes
   auto-release wrote are kept, so add missing compatibility context by hand.

Publishing uses crates.io trusted publishing: the `publish` job in
`release.yml` runs in the `crates-io` environment and exchanges its OIDC token
for a short-lived crates.io token. No registry token is stored in the
repository or its settings. Never place a long-lived registry token in
repository files, workflow arguments, or logs.

## Verify

- Confirm the new version and owners on crates.io.
- Build the published crate in a fresh project with the declared MSRV.
- Confirm docs.rs built the public documentation and examples.
- Re-run a minimal tracking and filtered-statistics program against the
  published package.
- Verify the GitHub release references the immutable source tag.
- Verify the attestation for the downloaded crate archive:

  ```bash
  gh attestation verify threatflux-string-analysis-X.Y.Z.crate \
    --repo ThreatFlux/threatflux-string-analysis \
    --signer-workflow ThreatFlux/threatflux-string-analysis/.github/workflows/release.yml
  ```
- Confirm changelog comparison links point to the correct tags.

If crates.io accepts a version and artifact upload or GitHub Release creation
then fails, do not delete, overwrite, reuse, or republish that version. Recover
the missing release metadata for the same immutable tag:

1. Confirm the crate version and checksum through the crates.io API.
2. Download the canonical published archive from crates.io and compare its
   contents with `cargo package --list` at the release tag.
3. Generate a checksum for that downloaded archive.
4. Have an authorized maintainer create the missing GitHub Release for the
   existing tag, attach the archive and checksum, and record why automation did
   not complete.

Publish a new patch version only when package contents or runtime behavior need
a code fix. A patch release does not repair missing metadata for the version
that was already published.
