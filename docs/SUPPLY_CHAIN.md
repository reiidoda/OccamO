# Supply Chain Hardening

OccamO is built and released with supply-chain defenses enabled.

## Artifacts

- SBOMs generated in CI for releases.
- SHA256 checksums published with release assets.
- Sigstore signing for published Python artifacts.
- Container images signed with cosign.

## Provenance

- Build provenance attestation generated via `actions/attest-build-provenance`.
- Release workflows are pinned to commit SHAs.

## GitHub Actions

- Workflows declare minimal required permissions.
- Action versions are pinned to commit SHAs with the original tag noted.
- Dependabot updates GitHub Actions dependencies weekly.

## Dependency review

A dependency review workflow runs on pull requests to flag risky updates.
