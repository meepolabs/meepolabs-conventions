# meepolabs-conventions

Shared conventions for meepolabs repositories. The first piece is the
security floor: a GitHub Actions step that every repository runs to scan
for committed secrets and for dependencies with known vulnerabilities.

## Security floor

`actions/security-floor` is a composite action with two steps:

1. **Secret scan (gitleaks 8.30.1).** Scans the git history that the
   triggering event introduced (see "What is scanned"). Fails on any
   finding. Findings are redacted in the log.
2. **Dependency scan (osv-scanner 2.6.0).** Scans the dependency
   lockfiles in the checkout against the OSV database. Fails on any known
   vulnerability.

The dependency scan runs even when the secret scan fails, so each step
shows its own verdict. Both steps also write a short report to the job
summary.

Both tools are downloaded from their GitHub releases and checked against
a SHA-256 hash fixed in the action's source. The versions and hashes
change only with a new release of this repository; nothing in the
environment can override them.

The action has no inputs and no outputs. It needs no token, no license
key and no permission beyond `contents: read`.

## Using it

### Pin by commit

The action's path, `actions/security-floor`, never moves. Pin it by the
full 40-character commit SHA of a release tag, with the tag as a comment:

```yaml
uses: meepolabs/meepolabs-conventions/actions/security-floor@<40-hex>  # v1.0.0
```

To get the commit for a tag:

```sh
git ls-remote https://github.com/meepolabs/meepolabs-conventions \
  refs/tags/v1.0.0 'refs/tags/v1.0.0^{}'
```

If the output has a `refs/tags/v1.0.0^{}` line (an annotated tag), use the
SHA on that line. Otherwise use the SHA on the `refs/tags/v1.0.0` line.

### Caller example

Save as `.github/workflows/security.yml` and replace `<40-hex>` with the
commit SHA from the step above.

```yaml
name: security

on:
  pull_request:
  push:
    branches: [main, develop]
  schedule:
    - cron: '0 6 * * 1'

permissions:
  contents: read

# A newer pull request run cancels the superseded one, which scanned an
# older head of the same pull request. Push and schedule runs each get their
# own group: GitHub drops a pending run in a shared group even without
# cancel-in-progress, and a dropped push run leaves that push unscanned.
concurrency:
  group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  security-floor:
    name: Security floor
    runs-on: ${{ vars.CI_RUNNER || 'ubuntu-latest' }}
    timeout-minutes: 20
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Security floor
        uses: meepolabs/meepolabs-conventions/actions/security-floor@<40-hex>  # v1.0.0
```

GitHub registers `push` and `schedule` triggers only from the workflow
file on the default branch. Merge the workflow there, or the weekly scan
never runs.

### What the caller owns

The action decides what to scan and when to fail. Everything around it
is the calling workflow's job:

- **Checkout** with `fetch-depth: 0`, into the workspace root (no
  `path:`). A shallow clone fails the secret scan.
- **Triggers.** The secret scan picks its range from the event, so
  `pull_request`, `push` and a weekly `schedule` together cover new
  commits and the full history.
- **Permissions:** `contents: read` is all the action needs.
- **Timeout:** set `timeout-minutes` on the job.
- **Concurrency.** Never cancel or replace a push run: each push run is
  the only secret scan of that push's commits. A group shared by several
  push runs is not enough, because GitHub replaces a pending run in the
  group with the next one even without `cancel-in-progress`. Cancelling
  superseded pull request runs is fine.

### Runners

The action runs on Linux x64 only; any other platform fails with
`unsupported platform`. It runs on:

- GitHub-hosted ubuntu runners, and
- self-hosted Linux x64 runners that provide:
  - `/bin/bash` and `/usr/bin/env`;
  - git 2.36 or newer, `jq`, `curl`, `tar` and `sha256sum` in `/usr/bin`;
  - a standard GNU userland (coreutils such as `mktemp`, `head` and `od`,
    plus `grep` and `sed`) in `/usr/bin` or `/bin`: the script
    runs with `PATH=/usr/bin:/bin` and nothing else;
  - a readable `/proc`: the script checks its own environment through
    `/proc/<pid>/environ` and fails when it cannot read it.

The runner needs outbound HTTPS to GitHub (tool downloads) and to the
OSV service (advisory lookups). `HTTPS_PROXY` and `NO_PROXY` are honored.

The example job picks its runner from the repository variable
`CI_RUNNER`: set it to a self-hosted runner's label to run there, or
leave it unset for GitHub-hosted runners. Use self-hosted runners for
private repositories only. A changed variable takes effect on the next
push or new run; re-running an old run may keep the previous runner.

### Cost of the weekly run

The weekly scheduled run scans the full history of every branch and tag
and every lockfile. It is the run that catches a vulnerability published
after the last push to a repository nobody is touching, so keep it. It is
also the slowest run, and on private repositories using GitHub-hosted
runners each run is billed Actions minutes: budget one full scan per
repository per week.

## What is scanned

### Secrets

| Event | Commits scanned |
|---|---|
| `pull_request` | the pull request's commits (base..head); full history if either commit is missing from the clone |
| `push` | the pushed commits (before..after) |
| `push` creating a branch or tag | everything reachable from the new commit |
| `push` whose previous commit is not in the clone (usually a force push) | everything reachable from the new commit |
| `push` deleting a branch or tag | nothing; passes with a notice |
| any other event (`schedule`, `workflow_dispatch`, ...) | full history of all refs |

Merge commits are scanned, including content introduced only while
resolving a merge.

gitleaks runs with the rules of its default config, shipped with the
action as `actions/security-floor/gitleaks.toml`. No file is skipped by
path: every file's content is scanned as stored in git, lockfiles,
vendored code, images and binaries included; compressed archives (`.gz`,
`.zip`, ...) are not unpacked. gitleaks's checks for placeholder values
(such as `${{ secrets.NAME }}` or `$VAR`) stay, so a reference to a
secret is not a finding. Nothing in the scanned repository can relax the verdict:

- A repository `.gitleaks.toml` (rules and allowlists) is ignored.
- Inline `gitleaks:allow` comments are ignored.
- A `.gitleaksignore` at the repository root fails the step, because
  gitleaks always reads that file: `repo .gitleaksignore is not honored;
  remove it and rewrite the flagged value`.

A finding is fixed by rewriting the value out of the scanned history, and
rotating it if it was a real secret. This applies to fake secrets too,
such as test fixtures: generate them at test time or write them in a
form the rules do not match.

### Dependencies

osv-scanner scans every dependency file it recognizes in the checkout
(lockfiles, requirements files, SBOMs and similar), including files that
`.gitignore` lists. There is no advisory ignore list: a repository
`osv-scanner.toml` is overridden, so its ignore entries have no effect.
A vulnerability is fixed by upgrading the dependency.

Before scanning, the step checks that every tracked manifest has a
tracked lockfile in its own directory or a parent directory:

| Manifest | Accepted lockfiles |
|---|---|
| `Cargo.toml` | `Cargo.lock` |
| `package.json` | `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, `bun.lock` |
| `pyproject.toml` | `poetry.lock`, `uv.lock` |

- **A manifest without a lockfile fails**, Rust libraries included:
  `lockfile check: N manifest(s) without a tracked lockfile in their
  directory or a parent`. Any `pyproject.toml` counts, even one that only
  configures tools.
- **No manifest is a visible pass.** A repository that tracks none of the
  manifests or lockfiles above, and where osv-scanner finds no package
  sources, passes with the notice `no package manifest or lockfile found;
  nothing to scan`.

## When the step fails

Every failure prints a `security-floor: FAIL:` line. Besides findings,
the step fails closed in these cases.

Tool installation:

- A tool download that still fails after 3 retries: `download failed`.
- A downloaded or cached tool whose hash does not match: `checksum
  mismatch`.

Checkouts and history the secret scan refuses rather than scan
partially:

- A shallow clone: `checkout needs fetch-depth: 0 (the clone is
  shallow)`.
- A partial clone (`--filter`) missing objects in the scan range:
  `checkout is missing N objects in the scan range (a partial clone or a
  damaged repository); fetch the full history without --filter`.
- A merge with 3 or more parents in the scan range: `octopus merge in
  scan range; not scannable`.
- A file name git must quote (a control character, `"` or `\`) anywhere
  in the scan range: `path git would quote; history is not scannable`.
- Any error or warning from git while walking the history: `git log
  reported errors or warnings (exit N); history is not scannable`.
- git older than 2.36: `git 2.36 or newer is required`.
- gitleaks still running after 600 seconds: it is stopped and the step
  fails with `gitleaks error (exit N): tool or config failure`.

Dependency files the dependency scan cannot read:

- A symlinked dependency file, or a submodule entry at a dependency file
  path: `osv-scanner cannot scan symlink: <path>` or `osv-scanner cannot
  scan submodule entry: <path>`.
- One of the lockfiles listed above, tracked under `node_modules/`:
  `osv-scanner cannot scan lockfile under node_modules/: <path>`.
- One of the lockfiles listed above that yields no packages: `osv:
  lockfile produced no packages`.

Any other osv-scanner error, such as a network failure, also fails the
step.

## Threat model

The action runs inside the calling job, so every step before it in the
same job can change what it sees: the environment, the tools on the
runner, and the checked-out files. Those earlier steps are trusted.

Call the action first in its job, right after checkout. Do not install
dependencies, build, or run any other step before it in that job. Put
builds and tests in a separate job.

## What it does not do

It does not upload SARIF results, comment on pull requests, or update
itself. A new version is adopted by changing the pinned SHA.

## Renovate preset

`default.json` is a shared Renovate preset. Extend it pinned to a release
tag, `"extends": ["github>meepolabs/meepolabs-conventions#vX.Y.Z"]`, and
Renovate bumps the tag when a new release is published.
Each repository keeps its stack-specific groups, custom managers and
first-party pins in its own `renovate.json`.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT. See [LICENSE](LICENSE).
