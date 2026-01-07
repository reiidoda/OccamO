# Releasing OccamO

This repo ships multiple deliverables: the Python package, the GitHub Action,
and the VS Code extension. Use this guide to keep releases consistent.

## Python package (PyPI)

- Releases are managed by Release Please (`.github/workflows/release-please.yml`).
- Publish jobs run in `.github/workflows/publish.yml` on GitHub Releases.
- SBOMs, checksums, and Sigstore signatures are attached to the release.
- The publish job is gated by `PUBLISH_PYPI=true` (repo variable) to avoid
  failing releases before PyPI trusted publishing is configured.

## GitHub Action tags

The action is stored under `action/` and referenced as:

```
uses: reiidoda/OccamO/action@v1
```

Recommended versioning:

- `v1` is a moving tag that points to the latest stable action release.
- `v1.x.y` tags are immutable and can be used for pinning.

Suggested steps:

1. Ensure `action-e2e` passes.
2. Tag and push:

```
git tag -a v1.2.3 -m "OccamO Action v1.2.3"
git push origin v1.2.3
git tag -fa v1 -m "OccamO Action v1"
git push origin v1 --force
```

## Marketplace checklist

- `action/action.yml` includes `name`, `description`, and `branding`.
- Root `README.md` describes action usage and inputs/outputs.
- A license file exists at repo root.
- Tags (`v1`, `v1.x.y`) are published and referenced in docs.
- Workflows declare minimal permissions.

If you decide to publish directly from the repo root, you can add a
root-level `action.yml` wrapper that forwards inputs to `action/`.

## VS Code extension (beta)

- Source lives in `vscode/`.
- Build: `npm install` and `npm run compile`.
- Package with `vsce package` when you are ready to publish.
