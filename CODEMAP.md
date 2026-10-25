# Codemap

| Path | What it is |
|---|---|
| `actions/security-floor/action.yml` | Composite action: runs `floor.sh gitleaks`, then `floor.sh osv` |
| `actions/security-floor/floor.sh` | Both scans: tool install and checksum, scan range from the event, preflight refusals, gitleaks and osv-scanner runs, job summary |
| `actions/security-floor/gitleaks.toml` | gitleaks default rules for the pinned version with every path skip removed; pinned by checksum in `floor.sh` |
| `default.json` | Shared Renovate preset |
| `tests/run.sh` | Self-test: one `expect` row per behavior, fixtures generated at runtime |
| `tests/id-hook/` | Accept and reject lines for the `no-internal-ids` pre-commit hook |
| `.github/workflows/self-test.yml` | CI: pre-commit, the self-test, and the action run against this repository with positive and negative controls |
| `.pre-commit-config.yaml` | Hooks for this repository |
