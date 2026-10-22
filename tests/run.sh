#!/usr/bin/env bash
# Self-test for actions/security-floor/floor.sh. Needs network access, git,
# curl, jq and sha256sum. Every fixture is generated at runtime.
#
# Row contract: expect <name> <exit> <grep-text> [--absent <text>] -- cmd...
#   Runs cmd, asserts its exit code AND that its combined output contains
#   <grep-text> (fixed string). --absent fails the row if <text> appears.
#
# Reconciliation: the run passes only if the emitted PASS plus SKIP lines
# equal the number of `expect` call sites in this file (lines starting with
# `expect`) plus rows declared with declare_dynamic_rows. A call site inside a
# loop counts once; the loop declares its extra iterations explicitly. A row
# that cannot run in this environment calls skip_row in place of its expect,
# and the skip is printed in the final count line.
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
readonly SKIP_LOG="$WORK/skip.log"
mkdir -p -- "$SHARED_RUNNER_TEMP" "$FAKE_HOME"
: >"$PASS_LOG"
: >"$FAIL_LOG"
: >"$SKIP_LOG"
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

# skip_row <name> <reason>: stands in for exactly one expect call site.
skip_row() {
	printf 'SKIP %s: %s\n' "$1" "$2" | tee -a "$SKIP_LOG"
}

declare_dynamic_rows() {
	DYNAMIC_ROWS=$((DYNAMIC_ROWS + $1))
}

reconcile() {
	local call_sites emitted failed skipped expected
	# Counts misspelled calls too (expect_row ...), so a row that silently
	# stops running still raises the expected total.
	call_sites=$(grep -cE '^[[:space:]]*expect[A-Za-z0-9_-]*[[:space:]]' "$SELF")
	emitted=$(grep -c '^PASS ' "$PASS_LOG" || true)
	failed=$(grep -c '^FAIL ' "$FAIL_LOG" || true)
	skipped=$(grep -c '^SKIP ' "$SKIP_LOG" || true)
	expected=$((call_sites + DYNAMIC_ROWS))
	echo "rows: PASS $emitted, SKIP $skipped, FAIL $failed, expected PASS+SKIP $expected ($call_sites call sites + $DYNAMIC_ROWS dynamic)"
	if [[ "$failed" -ne 0 || "$((emitted + skipped))" -ne "$expected" ]]; then
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

vulnerable_npm_lockfile() {
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
        "lodash": "4.17.15"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
      "integrity": "sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A=="
    }
  }
}
EOF
}

# osv_ignore_package_toml <name>: an osv-scanner.toml that ignores every
# advisory for one npm package.
osv_ignore_package_toml() {
	printf '[[PackageOverrides]]\nname = "%s"\necosystem = "npm"\nignore = true\nreason = "fixture"\n' "$1"
}

# A gitleaks config that allowlists every path.
gitleaks_allow_all_toml() {
	printf '[allowlist]\npaths = [".*"]\n'
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

# floor_with_stubs_on_path <name=script>...: a floor.sh copy whose fixed PATH
# puts the stubs first. Models a shadowing binary inside a trusted PATH entry,
# which an environment PATH can no longer reach.
floor_with_stubs_on_path() {
	local dir
	dir=$(stub_dir "$@")
	floor_copy_with 'readonly FLOOR_PATH=/usr/bin:/bin' "readonly FLOOR_PATH=$dir:/usr/bin:/bin"
}

# tar_to_command_script: a TAR_OPTIONS --to-command target that, in place of
# extracting, writes a gitleaks that reports the pinned version and finds
# nothing next to the archive.
tar_to_command_script() {
	local file
	file=$(mktemp "$WORK/to-command.XXXXXX")
	cat >"$file" <<'EOF'
#!/bin/sh
cat >/dev/null
dest=$(dirname "$TAR_ARCHIVE")/$TAR_FILENAME
printf '#!/bin/sh\n[ "$1" = version ] && echo 8.30.1\nexit 0\n' >"$dest"
chmod 0700 "$dest"
EOF
	chmod 0755 "$file"
	printf '%s\n' "$file"
}

# run_floor_with_absent_preload <repo> <subcommand> [NAME=VALUE...]
# Runs floor.sh with LD_PRELOAD naming a missing library, so the dynamic
# loader reports every process that inherited it. A calibration run (no
# subcommand, which exits before starting any child) counts the processes
# that necessarily start before the environment is rebuilt; the real run
# must report no more. Returns the floor's exit code, or 3 if any child
# inherited LD_PRELOAD.
run_floor_with_absent_preload() {
	local repo=$1 sub=$2 lib="$WORK/absent-preload.so" log baseline reached rc=0
	shift 2
	log=$(mktemp "$WORK/preload.XXXXXX")
	baseline=$( (cd -- "$repo" && env -i PATH="$PATH" LD_PRELOAD="$lib" "$FLOOR_SH") 2>&1 | grep -cF -- "$lib" || true)
	run_floor "$repo" "$sub" LD_PRELOAD="$lib" "$@" >"$log" 2>&1 || rc=$?
	cat -- "$log"
	reached=$(grep -cF -- "$lib" "$log" || true)
	if [[ "$reached" -gt "$baseline" ]]; then
		echo "LD_PRELOAD reached $((reached - baseline)) processes after sanitization"
		return 3
	fi
	return "$rc"
}

# run_floor_sentinel_preset <script> <repo> <subcommand> [NAME=VALUE...]
# Starts floor.sh the way the re-exec does (bash -p, fixed PATH, LC_ALL=C)
# with the sentinel already set to the PID the script will see, so the
# re-exec is skipped and only the in-script environment check stands.
run_floor_sentinel_preset() {
	local script=$1 repo=$2 sub=$3
	shift 3
	cd -- "$repo"
	# shellcheck disable=SC2016 # $$ expands in the child shell
	env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$FAKE_HOME" RUNNER_TEMP="$SHARED_RUNNER_TEMP" "$@" \
		/bin/bash -c 'SECURITY_FLOOR_REEXEC_PID=$$ exec /bin/bash -p -- "$0" "$1"' "$script" "$sub"
}

# tar_shim_dir: a `tar` that ignores the archive and writes, into the -C
# directory, a gitleaks that reports the pinned version and finds nothing.
tar_shim_dir() {
	local dir
	dir=$(mktemp -d "$WORK/stubs.XXXXXX")
	cat >"$dir/tar" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
	[ "$1" = -C ] && dest=$2
	shift
done
printf '#!/bin/sh\n[ "$1" = version ] && echo 8.30.1\nexit 0\n' >"$dest/gitleaks"
chmod 0700 "$dest/gitleaks"
EOF
	chmod 0755 "$dir/tar"
	printf '%s\n' "$dir"
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

# runner_temp_with_symlink <relative path>: a fresh RUNNER_TEMP in which that
# path is a symlink to a directory elsewhere.
runner_temp_with_symlink() {
	local dir target
	dir=$(fresh_runner_temp)
	target=$(mktemp -d "$WORK/symlink-target.XXXXXX")
	mkdir -p -- "$(dirname -- "$dir/$1")"
	ln -s -- "$target" "$dir/$1"
	printf '%s\n' "$dir"
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

osv_clean_ignore_repo=$(new_repo)
commit_file "$osv_clean_ignore_repo" package-lock.json "$(clean_npm_lockfile)" >/dev/null
commit_file "$osv_clean_ignore_repo" osv-scanner.toml "$(osv_ignore_package_toml is-number)" >/dev/null

osv_vuln_repo=$(new_repo)
commit_file "$osv_vuln_repo" package-lock.json "$(vulnerable_npm_lockfile)" >/dev/null

osv_vuln_ignore_repo=$(new_repo)
commit_file "$osv_vuln_ignore_repo" package-lock.json "$(vulnerable_npm_lockfile)" >/dev/null
commit_file "$osv_vuln_ignore_repo" osv-scanner.toml "$(osv_ignore_package_toml lodash)" >/dev/null

gitleaks_allow_all="$WORK/gitleaks-allow-all.toml"
gitleaks_allow_all_toml >"$gitleaks_allow_all"

secret=$(new_secret)
secret_repo=$(new_repo)
commit_file "$secret_repo" app.env "API_TOKEN=$secret" >/dev/null
secret_head=$(git -C "$secret_repo" rev-parse HEAD)
write_event_push "$push_event" "$clean_head" "$secret_head"

tar_to_command=$(tar_to_command_script)
no_diff_attributes="$WORK/no-diff.attributes"
printf '* -diff\n' >"$no_diff_attributes"
git_config_no_diff=(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.attributesFile GIT_CONFIG_VALUE_0="$no_diff_attributes")

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
	run_floor_script "$(floor_with_stubs_on_path 'uname=case "$1" in -m) echo aarch64 ;; *) echo Linux ;; esac')" \
	"$clean_repo" gitleaks
# shellcheck disable=SC2016 # literal stub/source text
expect non-linux-red 1 "unsupported platform: Darwin x86_64" -- \
	run_floor_script "$(floor_with_stubs_on_path 'uname=case "$1" in -m) echo x86_64 ;; *) echo Darwin ;; esac')" \
	"$osv_repo" osv
expect gitleaks-extract-failure-red 1 "FAIL: extract failed: gitleaks" -- \
	run_floor_script "$(floor_with_stubs_on_path 'tar=exit 2')" "$clean_repo" gitleaks
expect cache-dir-symlink-red 1 "FAIL: unsafe cache directory" -- \
	run_floor "$clean_repo" gitleaks RUNNER_TEMP="$(runner_temp_with_symlink security-floor)"
expect cache-bin-symlink-red 1 "FAIL: unsafe cache directory" -- \
	run_floor "$clean_repo" gitleaks RUNNER_TEMP="$(runner_temp_with_symlink security-floor/bin)"
# A cache directory owned by another user is refused before chmod is tried.
# As root -O always holds, and the copy would chmod /usr/bin.
if [[ "$EUID" -eq 0 ]]; then
	skip_row cache-dir-foreign-owner-red "running as root: ownership cannot differ"
else
	# shellcheck disable=SC2016 # literal source text
	expect cache-dir-foreign-owner-red 1 "FAIL: unsafe cache directory: /usr" -- \
		run_floor_script "$(floor_copy_with 'local floor_dir="$BASE_DIR/security-floor"' 'local floor_dir="$BASE_DIR"')" \
		"$clean_repo" gitleaks RUNNER_TEMP=/usr
fi

# The caller's environment is replaced by an allowlist: none of these reach
# tar, git, gitleaks or the loader.
expect env-path-tar-shim-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks RUNNER_TEMP="$(fresh_runner_temp)" PATH="$(tar_shim_dir):$PATH"
expect env-gitleaks-config-toml-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks GITLEAKS_CONFIG_TOML="$(<"$gitleaks_allow_all")"
expect env-gitleaks-config-file-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks GITLEAKS_CONFIG="$gitleaks_allow_all"
expect env-tar-options-to-command-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks TAR_OPTIONS="--to-command=$tar_to_command"
expect env-ld-preload-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor_with_absent_preload "$secret_repo" gitleaks
expect env-git-dir-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks GIT_DIR="$clean_repo/.git"
expect env-git-config-attributes-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks "${git_config_no_diff[@]}"
expect env-sentinel-wrong-pid-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks SECURITY_FLOOR_REEXEC_PID=1 TAR_OPTIONS="--to-command=$tar_to_command"
expect env-sentinel-preset-secret-red 1 "FAIL: unsanitized environment: unexpected variable TAR_OPTIONS" -- \
	run_floor_sentinel_preset "$FLOOR_SH" "$secret_repo" gitleaks TAR_OPTIONS="--to-command=$tar_to_command"
expect env-sentinel-preset-hidden-name-red 1 "FAIL: unsanitized environment: unexpected variable BASH_FUNC_floor%%" -- \
	run_floor_sentinel_preset "$FLOOR_SH" "$clean_repo" gitleaks 'BASH_FUNC_floor%%=() { :; }'
expect env-sentinel-preset-clean-env-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor_sentinel_preset "$FLOOR_SH" "$clean_repo" gitleaks
expect env-attack-clean-repo-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor_with_absent_preload "$clean_repo" gitleaks RUNNER_TEMP="$(fresh_runner_temp)" PATH="$(tar_shim_dir):$PATH" \
	GITLEAKS_CONFIG_TOML="$(<"$gitleaks_allow_all")" GITLEAKS_CONFIG="$gitleaks_allow_all" \
	TAR_OPTIONS="--to-command=$tar_to_command" GIT_DIR="$clean_repo/.git" "${git_config_no_diff[@]}" \
	SECURITY_FLOOR_REEXEC_PID=1

# An osv-scanner.toml in the scanned tree cannot ignore advisories.
expect osv-vulnerable-lockfile-red 1 "FAIL: osv: scan failed" -- \
	run_floor "$osv_vuln_repo" osv
expect osv-repo-ignore-toml-still-red 1 "FAIL: osv: scan failed" -- \
	run_floor "$osv_vuln_ignore_repo" osv
expect osv-clean-lockfile-with-toml-green 0 "PASS: osv: no known vulnerabilities" -- \
	run_floor "$osv_clean_ignore_repo" osv

# Tools run only by absolute path, even when a trusted PATH entry holds a
# same-named binary; output is redacted.
expect gitleaks-path-shadow-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor_script "$(floor_with_stubs_on_path 'gitleaks=exit 0' 'osv-scanner=exit 0')" \
	"$secret_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$push_event"
expect osv-path-shadow-vulnerable-red 1 "FAIL: osv: scan failed" -- \
	run_floor_script "$(floor_with_stubs_on_path 'gitleaks=exit 0' 'osv-scanner=exit 0')" \
	"$osv_vuln_repo" osv
expect gitleaks-secret-redacted 1 "github-pat" --absent "$secret" -- \
	run_floor "$secret_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$push_event"

# Source text: pins are literals, never read from the environment.
expect source-pins-literal 0 "pins are literal" -- check_pins_literal "$FLOOR_SH"
# shellcheck disable=SC2016 # literal stub/source text
expect source-pins-check-catches-env-default 1 "default expansion" -- \
	check_pins_literal "$(floor_copy_with 'GITLEAKS_VERSION="8.30.1"' 'GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"')"

reconcile
