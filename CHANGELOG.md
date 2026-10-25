# Changelog

## v0.1.1

- `default.json`: updates and lock file maintenance run on Saturday,
  10:00-15:59 UTC, instead of early Monday. Vulnerability fixes still
  open at any time.

## v0.1.0

First release:

- `actions/security-floor`: a secret scan (gitleaks 8.30.1) and a
  dependency scan (osv-scanner 2.6.0) with pinned, checksum-verified tool
  binaries and no inputs.
- `default.json`: a shared Renovate preset.

Consumer impact, for a repository moving from gitleaks-action and a
separate osv-scanner job:

- Drop the `GITLEAKS_LICENSE` and `GITHUB_TOKEN` environment variables
  and the `pull-requests: read` permission. The workflow needs only
  `contents: read`.
- Secrets in lockfiles, `node_modules/`, vendored code, images, fonts and
  binary-extension files are scanned; gitleaks's default config skipped
  them. Its checks for placeholder values stay.
- A compressed archive (gzip, zip, tar, bzip2, xz, zstd or 7z, detected
  by content, so `.jar`, `.whl` and `.docx` count) added or changed in
  the scanned commits fails the secret scan.
- A repository `osv-scanner.toml` no longer suppresses findings. Ignored
  advisories turn the scan red until the dependency is upgraded.
- Every `Cargo.toml`, `package.json` and `pyproject.toml` needs a tracked
  lockfile in its directory or a parent, Rust libraries included.
- Checkout must use `fetch-depth: 0`. A shallow clone fails the secret
  scan.
