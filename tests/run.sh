#!/usr/bin/env bash
# Self-test for actions/security-floor/floor.sh. Needs network access, git,
# curl, jq and sha256sum. Every fixture is generated at runtime.
#
# Row contract: expect <name> <exit> <grep-text> [--absent <text>] -- cmd...
#   Runs cmd, asserts its exit code AND that its combined output contains
#   <grep-text> (fixed string). --absent fails the row if <text> appears.
#
# Reconciliation: the run passes only if the emitted PASS lines equal the
# number of `expect` call sites in this file (lines starting with `expect`)
# plus rows declared with declare_dynamic_rows. A call site inside a loop
# counts once; the loop declares its extra iterations explicitly.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly ROOT
readonly FLOOR_SH="$ROOT/actions/security-floor/floor.sh"
readonly SELF="$ROOT/tests/run.sh"

WORK=$(mktemp -d)
readonly WORK
trap 'rm -rf -- "$WORK"' EXIT
readonly SHARED_RUNNER_TEMP="$WORK/runner-temp-shared"
readonly FAKE_HOME="$WORK/home"
readonly PASS_LOG="$WORK/pass.log"
readonly FAIL_LOG="$WORK/fail.log"
mkdir -p -- "$SHARED_RUNNER_TEMP" "$FAKE_HOME"
: >"$PASS_LOG"
: >"$FAIL_LOG"
DYNAMIC_ROWS=0
ROW_SEQ=0

# ---------------------------------------------------------------- harness

expect() {
	local name=$1 want_exit=$2 want_text=$3
	shift 3
	local -a absent=()
	while [[ $# -gt 0 && $1 != "--" ]]; do
		case "$1" in
		--absent)
			absent+=("$2")
			shift 2
			;;
		*)
			echo "expect: bad option '$1' in row $name" >&2
			exit 2
			;;
		esac
	done
	[[ $# -gt 0 ]] || {
		echo "expect: missing -- in row $name" >&2
		exit 2
	}
	shift

	ROW_SEQ=$((ROW_SEQ + 1))
	local log="$WORK/row-$ROW_SEQ.log" rc=0 reason="" text
	("$@") >"$log" 2>&1 || rc=$?

	if [[ "$rc" != "$want_exit" ]]; then
		reason="exit $rc, want $want_exit"
	elif ! grep -qF -- "$want_text" "$log"; then
		reason="output lacks '$want_text'"
	else
		for text in "${absent[@]}"; do
			if grep -qF -- "$text" "$log"; then
				reason="output contains a forbidden string"
				break
			fi
		done
	fi

	if [[ -z "$reason" ]]; then
		printf 'PASS %s\n' "$name" | tee -a "$PASS_LOG"
	else
		printf 'FAIL %s: %s\n' "$name" "$reason" | tee -a "$FAIL_LOG"
		sed 's/^/    | /' "$log" | tail -n 30
	fi
}

declare_dynamic_rows() {
	DYNAMIC_ROWS=$((DYNAMIC_ROWS + $1))
}

reconcile() {
	local call_sites emitted failed expected
	# Counts misspelled calls too (expect_row ...), so a row that silently
	# stops running still raises the expected total.
	call_sites=$(grep -cE '^[[:space:]]*expect[A-Za-z0-9_-]*[[:space:]]' "$SELF")
	emitted=$(grep -c '^PASS ' "$PASS_LOG" || true)
	failed=$(grep -c '^FAIL ' "$FAIL_LOG" || true)
	expected=$((call_sites + DYNAMIC_ROWS))
	echo "rows: PASS $emitted, FAIL $failed, expected PASS $expected ($call_sites call sites + $DYNAMIC_ROWS dynamic)"
	if [[ "$failed" -ne 0 || "$emitted" -ne "$expected" ]]; then
		echo "self-test: FAILED"
		return 1
	fi
	echo "self-test: OK"
}

# ---------------------------------------------------------------- fixtures

new_repo() {
	local dir
	dir=$(mktemp -d "$WORK/repo.XXXXXX")
	git -C "$dir" init -q -b main
	printf '%s\n' "$dir"
}

# commit_file <repo> <path> <content> -> prints the new commit sha
commit_file() {
	local repo=$1 path=$2 content=$3
	mkdir -p -- "$(dirname -- "$repo/$path")"
	printf '%s\n' "$content" >"$repo/$path"
	git -C "$repo" add -- "$path"
	git -C "$repo" -c user.name=fixture -c user.email=fixture@example.invalid \
		-c commit.gpgsign=false commit -q -m "add $path"
	git -C "$repo" rev-parse HEAD
}

new_secret() {
	local raw
	raw=$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')
	[[ ${#raw} -ge 36 ]] || {
		echo "new_secret: not enough random bytes" >&2
		return 1
	}
	printf 'ghp_%s\n' "${raw:0:36}"
}

write_event_push() {
	local path=$1 before=$2 after=$3
	jq -n --arg b "$before" --arg a "$after" '{before: $b, after: $a}' >"$path"
}

write_event_pull_request() {
	local path=$1 base=$2 head=$3
	jq -n --arg b "$base" --arg h "$head" \
		'{pull_request: {base: {sha: $b}, head: {sha: $h}}}' >"$path"
}

write_event_other() {
	jq -n '{}' >"$1"
}

clean_npm_lockfile() {
	cat <<'EOF'
{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "fixture",
      "version": "1.0.0",
      "dependencies": {
        "is-number": "7.0.0"
      }
    },
    "node_modules/is-number": {
      "version": "7.0.0",
      "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
      "integrity": "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==",
      "engines": {
        "node": ">=0.12.0"
      }
    }
  }
}
EOF
}

# floor_copy_with <from> <to>: a temp copy of floor.sh with one literal
# replaced; fails if <from> is not present exactly once.
floor_copy_with() {
	local from=$1 to=$2 dir content n
	content=$(<"$FLOOR_SH")
	n=$(grep -cF -- "$from" "$FLOOR_SH" || true)
	[[ "$n" == 1 ]] || {
		echo "floor_copy_with: '$from' found $n times" >&2
		return 1
	}
	dir=$(mktemp -d "$WORK/floor-copy.XXXXXX")
	printf '%s\n' "${content/"$from"/"$to"}" >"$dir/floor.sh"
	chmod 0755 "$dir/floor.sh"
	printf '%s\n' "$dir/floor.sh"
}

# curlrc_home <proxy>: a HOME whose .curlrc routes curl through <proxy>.
curlrc_home() {
	local dir
	dir=$(mktemp -d "$WORK/home.XXXXXX")
	printf 'proxy = "%s"\n' "$1" >"$dir/.curlrc"
	printf '%s\n' "$dir"
}

fresh_runner_temp() {
	mktemp -d "$WORK/runner-temp.XXXXXX"
}

tampered_cache_copy() {
	local dir f
	dir=$(fresh_runner_temp)
	cp -R -- "$SHARED_RUNNER_TEMP/security-floor" "$dir/"
	for f in "$dir"/security-floor/bin/*; do
		printf 'x' >>"$f"
	done
	printf '%s\n' "$dir"
}

closed_port() {
	local port
	for port in 9 47 1023 49151 65000; do
		if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
			printf '%s\n' "$port"
			return 0
		fi
	done
	echo "closed_port: no closed local port found" >&2
	return 1
}

# stub_dir <name=script>...: a directory of executable stubs.
stub_dir() {
	local dir spec
	dir=$(mktemp -d "$WORK/stubs.XXXXXX")
	for spec in "$@"; do
		printf '#!/bin/sh\n%s\n' "${spec#*=}" >"$dir/${spec%%=*}"
		chmod 0755 "$dir/${spec%%=*}"
	done
	printf '%s\n' "$dir"
}

# run_floor_script <script> <repo> <subcommand> [NAME=VALUE...]
# Runs in a scrubbed environment so nothing from the caller's shell (proxies,
# GITHUB_*, tool config) leaks into a row. Later NAME=VALUE pairs win.
run_floor_script() {
	local script=$1 repo=$2 sub=$3
	shift 3
	cd -- "$repo"
	env -i PATH="$PATH" HOME="$FAKE_HOME" RUNNER_TEMP="$SHARED_RUNNER_TEMP" \
		"$@" "$script" "$sub"
}

run_floor() {
	run_floor_script "$FLOOR_SH" "$@"
}

# Runs floor.sh with RUNNER_TEMP unset, then fails unless its private temp
# directory was removed.
run_floor_without_runner_temp() {
	local repo=$1 sub=$2 tmp leftover
	tmp=$(mktemp -d "$WORK/tmpdir.XXXXXX")
	run_floor "$repo" "$sub" RUNNER_TEMP= TMPDIR="$tmp"
	leftover=$(find "$tmp" -mindepth 1 -print -quit)
	[[ -z "$leftover" ]] || {
		echo "temp dir not cleaned: $leftover"
		return 1
	}
}

# check_pins_literal <file>: the tool pins are single readonly literals and
# nothing that looks like a pin is read from the environment.
check_pins_literal() {
	local file=$1 name n bad=0 found
	local -a pins=(GITLEAKS_VERSION GITLEAKS_URL GITLEAKS_SHA256 OSV_VERSION OSV_URL OSV_SHA256)
	for name in "${pins[@]}"; do
		n=$(grep -cE "^readonly ${name}=\"[^\$\`\"]+\"\$" "$file" || true)
		if [[ "$n" != 1 ]]; then
			echo "pin $name is not a single readonly literal"
			bad=1
		fi
		n=$(grep -cE "(^|[^A-Za-z0-9_])${name}=" "$file" || true)
		if [[ "$n" != 1 ]]; then
			echo "pin $name is assigned $n times"
			bad=1
		fi
	done
	if grep -nE '^readonly [A-Za-z_][A-Za-z0-9_]*=.*[$`]' "$file"; then
		echo "a readonly constant is assigned from an expansion"
		bad=1
	fi
	if grep -nE '\$\{[A-Za-z0-9_]*(_VERSION|_URL|_SHA256):?[-=+?]' "$file"; then
		echo "a pin-shaped name is read with a default expansion"
		bad=1
	fi
	if grep -nE 'printenv|\$\{!' "$file"; then
		echo "indirect environment lookup"
		bad=1
	fi
	while IFS= read -r found; do
		case " ${pins[*]} " in
		*" $found "*) ;;
		*)
			echo "unexpected pin-shaped name: $found"
			bad=1
			;;
		esac
	done < <(grep -oE '[A-Z][A-Z0-9_]*_(VERSION|URL|SHA256)' "$file" | sort -u)
	[[ "$bad" == 0 ]] || return 1
	echo "pins are literal"
}

# ---------------------------------------------------------------- rows

gitleaks_sha=$(sed -n 's/^readonly GITLEAKS_SHA256="\([0-9a-f]*\)"$/\1/p' "$FLOOR_SH")
osv_sha=$(sed -n 's/^readonly OSV_SHA256="\([0-9a-f]*\)"$/\1/p' "$FLOOR_SH")
wrong_gitleaks_sha=$(printf '%s' "$gitleaks_sha" | sha256sum | cut -d' ' -f1)
wrong_osv_sha=$(printf '%s' "$osv_sha" | sha256sum | cut -d' ' -f1)

clean_repo=$(new_repo)
clean_head=$(commit_file "$clean_repo" README.md "fixture repository")
other_event="$WORK/event-other.json"
write_event_other "$other_event"
push_event="$WORK/event-push.json"

osv_repo=$(new_repo)
commit_file "$osv_repo" package.json '{"name": "fixture", "version": "1.0.0", "dependencies": {"is-number": "7.0.0"}}' >/dev/null
commit_file "$osv_repo" package-lock.json "$(clean_npm_lockfile)" >/dev/null

secret=$(new_secret)
secret_repo=$(new_repo)
commit_file "$secret_repo" app.env "API_TOKEN=$secret" >/dev/null
secret_head=$(git -C "$secret_repo" rev-parse HEAD)
write_event_push "$push_event" "$clean_head" "$secret_head"

port=$(closed_port)
proxy="http://127.0.0.1:$port"

# Dispatch.
expect usage-unknown-subcommand 2 "usage: floor.sh gitleaks|osv" -- run_floor "$clean_repo" scan
expect usage-no-subcommand 2 "usage: floor.sh gitleaks|osv" -- "$FLOOR_SH"

# Clean greens; these also fill the shared cache for later rows.
expect gitleaks-clean-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$clean_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect osv-clean-lockfile-green 0 "PASS: osv: no known vulnerabilities" -- \
	run_floor "$osv_repo" osv GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect gitleaks-no-runner-temp-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor_without_runner_temp "$clean_repo" gitleaks
expect gitleaks-ignores-env-pins 0 "gitleaks verified: 8.30.1" -- \
	run_floor "$clean_repo" gitleaks GITLEAKS_VERSION=0.0.0 \
	GITLEAKS_URL=https://example.invalid/gitleaks.tar.gz GITLEAKS_SHA256="$wrong_gitleaks_sha"

# Install path: network, checksum, cache, version, platform.
expect gitleaks-network-unreachable-red 1 "download failed" --absent "checksum mismatch" -- \
	run_floor "$clean_repo" gitleaks RUNNER_TEMP="$(fresh_runner_temp)" https_proxy="$proxy" HTTPS_PROXY="$proxy"
expect osv-network-unreachable-red 1 "download failed" --absent "checksum mismatch" -- \
	run_floor "$osv_repo" osv RUNNER_TEMP="$(fresh_runner_temp)" https_proxy="$proxy" HTTPS_PROXY="$proxy"
expect gitleaks-checksum-mismatch-red 1 "checksum mismatch: downloaded gitleaks" -- \
	run_floor_script "$(floor_copy_with "$gitleaks_sha" "$wrong_gitleaks_sha")" "$clean_repo" gitleaks
expect osv-checksum-mismatch-red 1 "checksum mismatch: downloaded osv-scanner" -- \
	run_floor_script "$(floor_copy_with "$osv_sha" "$wrong_osv_sha")" "$osv_repo" osv
expect gitleaks-ignores-curlrc-green 0 "gitleaks verified: 8.30.1" -- \
	run_floor "$clean_repo" gitleaks RUNNER_TEMP="$(fresh_runner_temp)" HOME="$(curlrc_home "$proxy")"
expect gitleaks-tampered-cache-red 1 "checksum mismatch: cached gitleaks" -- \
	run_floor "$clean_repo" gitleaks RUNNER_TEMP="$(tampered_cache_copy)"
expect osv-tampered-cache-red 1 "checksum mismatch: cached osv-scanner" -- \
	run_floor "$osv_repo" osv RUNNER_TEMP="$(tampered_cache_copy)"
expect gitleaks-version-mismatch-red 1 "version mismatch: gitleaks" -- \
	run_floor_script "$(floor_copy_with 'GITLEAKS_VERSION="8.30.1"' 'GITLEAKS_VERSION="8.30.0"')" "$clean_repo" gitleaks
expect osv-version-mismatch-red 1 "version mismatch: osv-scanner" -- \
	run_floor_script "$(floor_copy_with 'OSV_VERSION="2.6.0"' 'OSV_VERSION="2.5.9"')" "$osv_repo" osv
# shellcheck disable=SC2016 # literal stub/source text
expect non-x86_64-red 1 "unsupported platform: Linux aarch64" -- \
	run_floor "$clean_repo" gitleaks \
	PATH="$(stub_dir 'uname=case "$1" in -m) echo aarch64 ;; *) echo Linux ;; esac')":"$PATH"
# shellcheck disable=SC2016 # literal stub/source text
expect non-linux-red 1 "unsupported platform: Darwin x86_64" -- \
	run_floor "$clean_repo" osv \
	PATH="$(stub_dir 'uname=case "$1" in -m) echo x86_64 ;; *) echo Darwin ;; esac')":"$PATH"

# Tools run only by absolute path; output is redacted.
expect gitleaks-path-shadow-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$push_event" \
	PATH="$(stub_dir 'gitleaks=exit 0' 'osv-scanner=exit 0')":"$PATH"
expect gitleaks-secret-redacted 1 "github-pat" --absent "$secret" -- \
	run_floor "$secret_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$push_event"

# Source text: pins are literals, never read from the environment.
expect source-pins-literal 0 "pins are literal" -- check_pins_literal "$FLOOR_SH"
# shellcheck disable=SC2016 # literal stub/source text
expect source-pins-check-catches-env-default 1 "default expansion" -- \
	check_pins_literal "$(floor_copy_with 'GITLEAKS_VERSION="8.30.1"' 'GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"')"

reconcile
