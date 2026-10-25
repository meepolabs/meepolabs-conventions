# meepolabs-conventions

The shared conventions for Meepo Labs repositories, kept in one place so
every repository pulls them from here instead of copying them.

| Piece | Path | What it does |
|---|---|---|
| Security floor | `actions/security-floor` | CI step: secret scan and dependency vulnerability scan |
| Renovate preset | `default.json` | Shared dependency-update policy |

## Versions

Releases are tagged `vX.Y.Z`. Before v1.0.0, a minor version can change
how the pieces are used. A patch version does not, but any release can
make a check stricter, for example by closing a gap in a scan, and turn
a passing repository red.
Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Security floor

A composite action with two steps. Both fail on any finding; the second
runs even when the first fails.

1. **Secret scan** (gitleaks): on `push` and `pull_request`, the commits
   they introduce; on any other event, the full history of all branches
   and tags. Every file is scanned; nothing is skipped by
   path, and the repository cannot allowlist anything (`.gitleaks.toml`
   and `gitleaks:allow` are ignored; a `.gitleaksignore` fails the scan).
2. **Dependency scan** (osv-scanner): every lockfile in the checkout,
   with no ignore list.

The tools are pinned and checked against fixed SHA-256 hashes. The action
has no inputs and needs only `contents: read`.

### Usage

Pin the action by the commit SHA of a release tag, with the tag as a
comment, and run it first in its job, right after checkout. Get the SHA
with `git ls-remote https://github.com/meepolabs/meepolabs-conventions
'refs/tags/vX.Y.Z^{}' refs/tags/vX.Y.Z` (use the `^{}` line when there
is one):

```yaml
name: security

on:
  push:
    branches: [develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '17 13 * * 6'
  workflow_dispatch:

permissions:
  contents: read

# Never cancel a push run: it is the only scan of that push.
concurrency:
  group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  security-floor:
    runs-on: ${{ vars.CI_RUNNER || 'ubuntu-latest' }}
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: meepolabs/meepolabs-conventions/actions/security-floor@<commit-sha>  # vX.Y.Z
```

- `fetch-depth: 0` is required; a shallow clone fails.
- The weekly `schedule` runs early Saturday (13:17 UTC), and only from the
  default branch. `main` gets no push run: it only receives commits that
  already passed on `develop`.
- `CI_RUNNER` is an optional repository variable naming a self-hosted
  runner label (private repositories only); unset means GitHub-hosted.
  A self-hosted runner needs Linux x64, git 2.36 or newer, `jq`, `curl`,
  `tar` and `sha256sum` in `/usr/bin`, and outbound HTTPS.

### When it fails

Every failure prints a `security-floor: FAIL:` line.

- **A leak:** rewrite the value out of history, and rotate it if it was
  real. Fake secrets in tests count too: generate them at test time.
- **A compressed archive** (gzip, zip, tar and similar, by content, so
  `.jar`, `.whl` and `.docx` count) in the scanned commits: the scan
  cannot read inside it. Keep archives out of git.
- **A vulnerable dependency:** see [Vulnerable dependencies](#vulnerable-dependencies).
- **A manifest without a tracked lockfile** (`package.json`,
  `pyproject.toml`, `Cargo.toml`): commit the lockfile.
- **A dependency file the scan cannot read** (a symlink, a submodule
  entry, a lockfile under `node_modules/`, or a lockfile with no
  packages): the message names the path.
- **History the scan cannot read in full** (a shallow or partial clone,
  an octopus merge, a file name git must quote): the message names the
  cause; fix the checkout or the history.

### Vulnerable dependencies

The dependency scan and Dependabot alerts report the same kind of
finding. Handle both the same way; there is no ignore list.

- **A fixed version at least 14 days old:** fix it now, in its own pull
  request to `develop`. Renovate opens that pull request at any time when
  GitHub has a Dependabot alert for the package.
- **A fix younger than 14 days:** it arrives in the weekly update once it
  is 14 days old. Take it earlier only for a high or critical
  vulnerability in code that runs in production; that is a maintainer
  decision.
- **A fix that needs a major upgrade:** plan the upgrade as its own work.
- **No fix yet:** remove the package, or wait.

Until the fix lands, the scan stays red on every pull request in the
repository.

## Renovate preset

Extend it pinned to a release tag; Renovate proposes the next tag when
one is published:

```json
{ "extends": ["github>meepolabs/meepolabs-conventions#vX.Y.Z"] }
```

It sets grouped updates on `develop` once a week (Saturday, 10:00-15:59
UTC), a 14-day wait before a new release is proposed, SHA-pinned
actions, and manual review of majors. Exact version pins apply only to
npm and GitHub Actions; a repository that pins every manager keeps that
rule in its own config. Keep stack-specific groups and repository quirks
in the repository's own `renovate.json`.

Renovate replaces Dependabot's pull requests. Once Renovate is running
in a repository:

- Delete `.github/dependabot.yml`, if there is one.
- Turn off Dependabot security updates:
  `gh api -X DELETE repos/OWNER/REPO/automated-security-fixes`.
- Keep the dependency graph and Dependabot alerts on. Renovate reads the
  alerts to open vulnerability fixes at any time.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE)
