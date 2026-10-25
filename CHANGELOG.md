# Changelog

## Unreleased

- Add a shared Renovate preset, `default.json`, for repositories to extend.
- The secret scan no longer skips any file by path. gitleaks's default
  config skips lockfiles, `node_modules/`, vendored code, images, fonts
  and binary extensions; the action now ships that config with every
  path skip removed. Its checks for placeholder values stay. A secret in
  a previously skipped file turns the scan red.
- The secret scan fails when the scanned commits add or change a
  compressed archive (gzip, zip, tar, bzip2, xz, zstd or 7z, detected by
  content), since gitleaks cannot see inside one.

## v1.0.0

First release of `actions/security-floor`: a secret scan (gitleaks
8.30.1) and a dependency scan (osv-scanner 2.6.0) with pinned,
checksum-verified tool binaries and no inputs.

Consumer impact, for a repository moving from gitleaks-action and a
separate osv-scanner job:

- Drop the `GITLEAKS_LICENSE` and `GITHUB_TOKEN` environment variables
  and the `pull-requests: read` permission. The workflow needs only
  `contents: read`.
- A repository `osv-scanner.toml` no longer suppresses findings. Ignored
  advisories turn the scan red until the dependency is upgraded.
- Every `Cargo.toml`, `package.json` and `pyproject.toml` needs a tracked
  lockfile in its directory or a parent, Rust libraries included.
- Checkout must use `fetch-depth: 0`. A shallow clone fails the secret
  scan.
