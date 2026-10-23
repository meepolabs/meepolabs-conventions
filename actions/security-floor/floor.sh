#!/usr/bin/env bash
# Security floor: secret scan (gitleaks) and dependency scan (osv-scanner)
# with pinned, checksum-verified tool binaries.
#
# Usage: floor.sh gitleaks|osv
# Exit:  0 pass, 1 any failure, 2 usage error.
set -euo pipefail

# An earlier step in the job can export variables that change which bytes run
# or what they scan (TAR_OPTIONS, LD_PRELOAD, GIT_DIR, GIT_CONFIG_*, tool
# config, PATH, ...). No denylist of them stays complete, so the script
# re-executes itself once in an environment built only from this allowlist.
# The sentinel carries this process's PID, which exec preserves. It only
# prevents a re-exec loop: a run that finds it set must still pass the check
# below, so a caller presetting it gains nothing.
readonly FLOOR_PATH=/usr/bin:/bin
if [[ "${SECURITY_FLOOR_REEXEC_PID:-}" != "$$" ]]; then
	floor_env=(PATH="$FLOOR_PATH" LC_ALL=C SECURITY_FLOOR_REEXEC_PID="$$")
	# Kept for tools that resolve per-user paths. The secret scan does not
	# read git's user or system config (isolate_git_config).
	[[ -v HOME ]] && floor_env+=("HOME=$HOME")
	# Cache and work directory root; TMPDIR is the fallback when it is unset.
	[[ -v RUNNER_TEMP ]] && floor_env+=("RUNNER_TEMP=$RUNNER_TEMP")
	[[ -v TMPDIR ]] && floor_env+=("TMPDIR=$TMPDIR")
	# Runner-written event context and job summary paths: data, not code.
	[[ -v GITHUB_EVENT_NAME ]] && floor_env+=("GITHUB_EVENT_NAME=$GITHUB_EVENT_NAME")
	[[ -v GITHUB_EVENT_PATH ]] && floor_env+=("GITHUB_EVENT_PATH=$GITHUB_EVENT_PATH")
	[[ -v GITHUB_STEP_SUMMARY ]] && floor_env+=("GITHUB_STEP_SUMMARY=$GITHUB_STEP_SUMMARY")
	# Egress proxies on self-hosted runners, honored by curl and osv-scanner.
	# A proxy only carries bytes; the hash check decides what runs.
	[[ -v https_proxy ]] && floor_env+=("https_proxy=$https_proxy")
	[[ -v HTTPS_PROXY ]] && floor_env+=("HTTPS_PROXY=$HTTPS_PROXY")
	[[ -v no_proxy ]] && floor_env+=("no_proxy=$no_proxy")
	[[ -v NO_PROXY ]] && floor_env+=("NO_PROXY=$NO_PROXY")
	# -p: the new shell ignores BASH_ENV and imported functions.
	exec /usr/bin/env -i "${floor_env[@]}" /bin/bash -p -- "$0" "$@"
fi

# Reached directly (sentinel preset) or after the re-exec: either way the
# environment must look exactly like the re-exec builds it. The process's
# initial environment is read from the kernel, not from `compgen -e`: bash
# hides entries whose names it cannot hold (BASH_FUNC_x%%, A-B) but still
# passes them on to every child.
assert_sanitized_env() {
	local entry name
	[[ $- == *p* && "$PATH" == "$FLOOR_PATH" && "${LC_ALL:-}" == C ]] ||
		{ printf 'security-floor: FAIL: unsanitized environment: shell flags, PATH or LC_ALL\n' >&2; exit 1; }
	[[ -r /proc/$$/environ ]] ||
		{ printf 'security-floor: FAIL: unsanitized environment: cannot read /proc/%s/environ\n' "$$" >&2; exit 1; }
	while IFS= read -r -d '' entry; do
		name=${entry%%=*}
		case "$name" in
		PATH | LC_ALL | SECURITY_FLOOR_REEXEC_PID | PWD | OLDPWD | SHLVL | _) ;;
		HOME | RUNNER_TEMP | TMPDIR | GITHUB_EVENT_NAME | GITHUB_EVENT_PATH | GITHUB_STEP_SUMMARY) ;;
		https_proxy | HTTPS_PROXY | no_proxy | NO_PROXY) ;;
		*)
			printf 'security-floor: FAIL: unsanitized environment: unexpected variable %s\n' "$name" >&2
			exit 1
			;;
		esac
	done <"/proc/$$/environ"
}
assert_sanitized_env
umask 077

# Tool pins. Literals only: a version, URL or hash read from the environment
# would be a bypass that leaves no diff (tests/run.sh enforces this).
readonly GITLEAKS_VERSION="8.30.1"
readonly GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
readonly GITLEAKS_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
readonly OSV_VERSION="2.6.0"
readonly OSV_URL="https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64"
readonly OSV_SHA256="ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108"

# gitleaks passes --log-opts to `git log -p` split on single spaces, and the
# option replaces its default full-history arguments. Plain `git log -p`
# prints no diff for merge commits (--remerge-diff), only "Binary files
# differ" for files git or .gitattributes call binary (--text), and no
# content for a pure rename (--no-renames). Each lowercase filter letter
# excludes one change class; type changes (t, a symlink replaced by a file)
# must stay in.
readonly SCAN_OPTS="--full-history --diff-filter=uxdb --remerge-diff --text --no-renames"
readonly FULL_HISTORY_OPTS="--full-history --all --diff-filter=uxdb --remerge-diff --text --no-renames"
readonly ZERO_SHA="0000000000000000000000000000000000000000"
readonly GIT_MIN_MAJOR=2
readonly GIT_MIN_MINOR=36

# Manifest name -> lockfile names that pin it. A manifest is satisfied by a
# tracked lockfile in its own directory or any parent up to the scan root,
# which covers Cargo, npm, pnpm, yarn and bun workspaces. Any pyproject.toml
# counts as a manifest, including one that only configures tools.
declare -rA MANIFEST_LOCKFILES=(
	[Cargo.toml]="Cargo.lock"
	[package.json]="pnpm-lock.yaml package-lock.json yarn.lock bun.lock"
	[pyproject.toml]="poetry.lock uv.lock"
)

BASE_DIR=""
OWNS_BASE_DIR=false
CACHE_DIR=""
WORK_DIR=""
GIT_ENV=()
SCAN_EVENT=""
SCAN_MODE=""
SCAN_RANGE=""
SCAN_LOG_OPTS=""
SCAN_REVS=()
declare -A TRACKED_LOCKFILES=()
LOCKFILE_PATHS=()
LOCKFILE_CHECK="not run"
OSV_SOURCES_FOUND=false

usage() {
	echo "usage: floor.sh gitleaks|osv" >&2
}

info() {
	printf 'security-floor: %s\n' "$*"
}

pass() {
	printf 'security-floor: PASS: %s\n' "$*"
	exit 0
}

fail() {
	printf 'security-floor: FAIL: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	if [[ "$OWNS_BASE_DIR" == true ]]; then
		rm -rf -- "$BASE_DIR"
	elif [[ -n "$WORK_DIR" ]]; then
		rm -rf -- "$WORK_DIR"
	fi
}

check_platform() {
	local os arch
	os=$(uname -s) || fail "cannot determine platform"
	arch=$(uname -m) || fail "cannot determine platform"
	if [[ "$os" != "Linux" || "$arch" != "x86_64" ]]; then
		fail "unsupported platform: $os $arch (only Linux x86_64 is supported)"
	fi
}

# The cache persists verified assets across steps of one job; WORK_DIR is
# private to this run and holds the bytes that actually execute.
prepare_dirs() {
	local runner_temp="${RUNNER_TEMP:-}"
	if [[ -n "$runner_temp" ]]; then
		[[ "$runner_temp" == /* ]] || fail "RUNNER_TEMP must be an absolute path"
		BASE_DIR="$runner_temp"
	else
		BASE_DIR=$(mktemp -d) || fail "cannot create temp directory"
		OWNS_BASE_DIR=true
	fi
	local floor_dir="$BASE_DIR/security-floor"
	CACHE_DIR="$floor_dir/bin"
	mkdir -p -- "$CACHE_DIR" || fail "cannot create cache directory: $CACHE_DIR"
	require_private_dir "$floor_dir"
	require_private_dir "$CACHE_DIR"
	WORK_DIR=$(mktemp -d "$floor_dir/run.XXXXXX") || fail "cannot create run directory in $floor_dir"
	chmod 0700 -- "$WORK_DIR" || fail "cannot restrict run directory: $WORK_DIR"
}

# A pre-planted symlink or foreign-owned directory would let someone else
# choose the bytes this run caches and executes.
require_private_dir() {
	local dir=$1
	[[ ! -L "$dir" && -d "$dir" && -O "$dir" ]] ||
		fail "unsafe cache directory: $dir (symlink, not a directory, or not owned by the current user)"
	chmod 0700 -- "$dir" || fail "cannot restrict cache directory: $dir"
}

verify_sha256() {
	local file=$1 expected=$2 label=$3 actual
	actual=$(sha256sum -- "$file") || fail "checksum mismatch: cannot hash $label"
	actual=${actual%% *}
	[[ "$actual" == "$expected" ]] || fail "checksum mismatch: $label (expected $expected, got $actual)"
}

download() {
	local url=$1 dest=$2
	# --disable must come first: it stops curl reading a planted ~/.curlrc.
	if ! curl --disable --fail --retry 3 --retry-all-errors --retry-delay 2 \
		--connect-timeout 10 --max-time 120 \
		--proto '=https' --proto-redir '=https' \
		--location --silent --show-error \
		--output "$dest" -- "$url"; then
		fail "download failed: $url"
	fi
}

# Every run hashes the exact bytes it is about to use, whether they came from
# the cache or the network. A cached asset that no longer matches is treated
# as tampering, not refreshed.
fetch_verified() {
	local url=$1 sha=$2 label=$3 dest=$4
	local cached="$CACHE_DIR/$sha"
	if [[ -f "$cached" ]]; then
		cp -- "$cached" "$dest" || fail "cache read failed: $label"
		verify_sha256 "$dest" "$sha" "cached $label"
		return
	fi
	download "$url" "$dest"
	verify_sha256 "$dest" "$sha" "downloaded $label"
	cp -- "$dest" "$cached.tmp.$$" || fail "cache write failed: $label"
	mv -f -- "$cached.tmp.$$" "$cached" || fail "cache write failed: $label"
}

check_version() {
	local label=$1 expected=$2 actual=$3
	[[ "$actual" == "$expected" ]] || fail "version mismatch: $label reports '$actual', expected '$expected'"
	info "$label verified: $actual"
}

install_gitleaks() {
	local asset="$WORK_DIR/gitleaks.tar.gz" bin="$WORK_DIR/gitleaks" out
	fetch_verified "$GITLEAKS_URL" "$GITLEAKS_SHA256" "gitleaks $GITLEAKS_VERSION" "$asset"
	tar -xzf "$asset" -C "$WORK_DIR" --no-same-owner gitleaks || fail "extract failed: gitleaks $GITLEAKS_VERSION"
	chmod 0700 "$bin" || fail "cannot make gitleaks executable"
	out=$("$bin" version) || fail "gitleaks version check failed"
	check_version gitleaks "$GITLEAKS_VERSION" "$out"
}

install_osv() {
	local bin="$WORK_DIR/osv-scanner" out
	fetch_verified "$OSV_URL" "$OSV_SHA256" "osv-scanner $OSV_VERSION" "$bin"
	chmod 0700 "$bin" || fail "cannot make osv-scanner executable"
	out=$("$bin" --version) || fail "osv-scanner version check failed"
	check_version osv-scanner "osv-scanner version: $OSV_VERSION" "${out%%$'\n'*}"
}

# git and gitleaks read no system or user git config: a gitconfig under HOME
# or /etc can hide diffs from `git log -p` (a textconv driver, an attributes
# file). That also drops any global safe.directory, so the workspace is
# trusted here explicitly. Set per command, never exported: the process
# environment stays exactly what assert_sanitized_env checked.
init_git_env() {
	local workspace
	workspace=$(pwd -P) || fail "cannot resolve the workspace path"
	GIT_ENV=(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
		GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory "GIT_CONFIG_VALUE_0=$workspace")
}

git_isolated() {
	env "${GIT_ENV[@]}" git "$@"
}

preflight_git() {
	local shallow version
	shallow=$(git_isolated rev-parse --is-shallow-repository) ||
		scan_fail "not a usable git checkout: $(pwd -P)"
	[[ "$shallow" != true ]] || scan_fail "checkout needs fetch-depth: 0 (the clone is shallow)"
	[[ "$shallow" == false ]] || scan_fail "cannot tell whether the clone is shallow"
	version=$(git_isolated version) || scan_fail "cannot determine the git version"
	[[ "$version" =~ ^git\ version\ ([0-9]+)\.([0-9]+) ]] ||
		scan_fail "cannot parse the git version: $version"
	if ((BASH_REMATCH[1] < GIT_MIN_MAJOR ||
		(BASH_REMATCH[1] == GIT_MIN_MAJOR && BASH_REMATCH[2] < GIT_MIN_MINOR))); then
		scan_fail "git $GIT_MIN_MAJOR.$GIT_MIN_MINOR or newer is required (--remerge-diff); found: $version"
	fi
}

# event_sha <jq path array>: the event field at that path when it is a
# lowercase 40-hex string, else nothing. A missing, unreadable or invalid
# event file yields nothing; callers decide whether that widens or fails.
# The path must be absolute so jq can never read it as an option.
event_sha() {
	local path=${GITHUB_EVENT_PATH:-} value
	[[ "$path" == /* && -f "$path" && -r "$path" ]] || return 0
	value=$(jq -j --argjson p "$1" \
		'try getpath($p) catch null | select(type == "string" and test("\\A[0-9a-f]{40}\\z"))' \
		"$path" 2>/dev/null) || return 0
	[[ "$value" =~ ^[0-9a-f]{40}$ ]] && printf '%s' "$value"
	return 0
}

is_commit() {
	[[ "$1" =~ ^[0-9a-f]{40}$ ]] && git_isolated cat-file -e "$1^{commit}" 2>/dev/null
}

use_full_history() {
	SCAN_MODE=$1
	SCAN_RANGE="all refs"
	SCAN_LOG_OPTS=$FULL_HISTORY_OPTS
	SCAN_REVS=(--all)
}

# use_revs <mode> <rev>: <rev> is built only from SHAs that passed is_commit.
use_revs() {
	SCAN_MODE=$1
	SCAN_RANGE=$2
	SCAN_LOG_OPTS="$SCAN_OPTS $2"
	SCAN_REVS=("$2")
}

select_push_range() {
	local before after
	before=$(event_sha '["before"]')
	after=$(event_sha '["after"]')
	if [[ "$after" == "$ZERO_SHA" ]]; then
		SCAN_MODE="branch deletion"
		return
	fi
	is_commit "$after" ||
		scan_fail "push event: 'after' is missing, malformed or not a commit in the checkout"
	if [[ "$before" == "$ZERO_SHA" ]]; then
		use_revs "new ref, everything reachable from 'after'" "$after"
	elif is_commit "$before"; then
		use_revs "push range" "$before..$after"
	else
		use_revs "fallback, 'before' is not a commit in the checkout; everything reachable from 'after'" "$after"
	fi
}

select_pull_request_range() {
	local base head
	base=$(event_sha '["pull_request","base","sha"]')
	head=$(event_sha '["pull_request","head","sha"]')
	if is_commit "$base" && is_commit "$head"; then
		use_revs "pull request range" "$base..$head"
	else
		use_full_history "fallback, pull request base or head is not a commit in the checkout; full history"
	fi
}

select_scan_range() {
	local event=${GITHUB_EVENT_NAME:-}
	SCAN_EVENT=${event:-none}
	[[ "$SCAN_EVENT" =~ ^[a-z_]{1,64}$ ]] || SCAN_EVENT="unrecognized"
	case "$event" in
	push) select_push_range ;;
	pull_request) select_pull_request_range ;;
	*) use_full_history "full history" ;;
	esac
}

# gitleaks treats an unknown revision in --log-opts as an empty scan and
# exits 0, so the range must resolve before it runs. --remerge-diff remerges
# two-parent merges only: an octopus merge prints no diff of its own, so
# whatever it adds would go unscanned.
preflight_scan_range() {
	local count octopus
	count=$(git_isolated rev-list --count "${SCAN_REVS[@]}" --) ||
		scan_fail "scan range does not resolve: $SCAN_RANGE"
	info "scan: event $SCAN_EVENT; mode $SCAN_MODE; range $SCAN_RANGE; $count commits"
	octopus=$(git_isolated rev-list --min-parents=3 --count "${SCAN_REVS[@]}" --) ||
		scan_fail "scan range does not resolve: $SCAN_RANGE"
	[[ "$octopus" == 0 ]] || scan_fail "octopus merge in scan range; not scannable ($octopus commits)"
}

# gitleaks 8.30.1 reads <source>/.gitleaksignore whatever
# --gitleaks-ignore-path says, following a symlink, so its presence alone
# fails the scan.
refuse_repo_ignore_file() {
	[[ ! -e .gitleaksignore && ! -L .gitleaksignore ]] ||
		scan_fail "repo .gitleaksignore is not honored; remove it and rewrite the flagged value"
}

write_gitleaks_summary() {
	local result=$1
	[[ -n "${GITHUB_STEP_SUMMARY:-}" ]] || return 0
	printf '### security-floor: gitleaks\n\n- gitleaks: %s\n- event: %s\n- mode: %s\n- range: %s\n- result: %s\n\n' \
		"$GITLEAKS_VERSION" "$SCAN_EVENT" "$SCAN_MODE" "${SCAN_RANGE:-none}" "$result" \
		>>"$GITHUB_STEP_SUMMARY" || info "warning: cannot write the job summary"
}

scan_fail() {
	write_gitleaks_summary "FAIL, $*"
	fail "$@"
}

# Only gitleaks's built-in rules apply: nothing the scanned repo supplies
# (.gitleaks.toml, .gitleaksignore, inline gitleaks:allow) changes the result.
# A finding's file path is repo-controlled and can hold a newline followed by
# a workflow command, so the runner ignores commands in the tool's output.
# The resume token is random per run: the output cannot end the fence.
scan_secrets() {
	local config="$WORK_DIR/gitleaks.toml" ignore_dir="$WORK_DIR/gitleaks-ignore" token rc=0
	printf '[extend]\nuseDefault = true\n' >"$config" || scan_fail "cannot write the gitleaks config"
	mkdir -- "$ignore_dir" || scan_fail "cannot create the gitleaks ignore directory"
	token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || scan_fail "cannot generate a stop-commands token"
	[[ "$token" =~ ^[0-9a-f]{32}$ ]] || scan_fail "cannot generate a stop-commands token"
	printf '::stop-commands::%s\n' "$token"
	env "${GIT_ENV[@]}" "$WORK_DIR/gitleaks" git --redact --verbose --exit-code 2 --no-banner \
		--config "$config" --gitleaks-ignore-path "$ignore_dir" --ignore-gitleaks-allow \
		--log-opts "$SCAN_LOG_OPTS" . 2>&1 || rc=$?
	printf '::%s::\n' "$token"
	return "$rc"
}

run_gitleaks() {
	local rc=0
	init_git_env
	preflight_git
	select_scan_range
	if [[ "$SCAN_MODE" == "branch deletion" ]]; then
		printf '::notice title=security-floor::push deletes a ref; nothing to scan\n'
		write_gitleaks_summary "pass (nothing to scan)"
		pass "gitleaks: branch deletion, nothing to scan"
	fi
	preflight_scan_range
	refuse_repo_ignore_file
	install_gitleaks
	scan_secrets || rc=$?
	case "$rc" in
	0)
		write_gitleaks_summary "pass, no leaks found"
		pass "gitleaks: no leaks found"
		;;
	2)
		write_gitleaks_summary "FAIL, leaks found"
		fail "gitleaks: leaks found"
		;;
	*)
		write_gitleaks_summary "FAIL, gitleaks error (exit $rc)"
		fail "gitleaks error (exit $rc): tool or config failure"
		;;
	esac
}

# A tracked path as one printable log line: a name holding a newline or other
# control character is shell-quoted, so it cannot start a workflow command.
printable_path() {
	if [[ "$1" =~ [^[:print:]] ]]; then
		printf '%q' "$1"
	else
		printf '%s' "$1"
	fi
}

# manifest_has_lockfile <manifest path>: a tracked lockfile for that manifest
# kind sits in the manifest's directory or one of its parents.
manifest_has_lockfile() {
	local manifest=$1 dir="" lock
	local -a locks
	read -r -a locks <<<"${MANIFEST_LOCKFILES[${manifest##*/}]}"
	[[ "$manifest" == */* ]] && dir=${manifest%/*}
	while true; do
		for lock in "${locks[@]}"; do
			[[ -n "${TRACKED_LOCKFILES["${dir:+$dir/}$lock"]:-}" ]] && return 0
		done
		[[ -n "$dir" ]] || return 1
		if [[ "$dir" == */* ]]; then
			dir=${dir%/*}
		else
			dir=""
		fi
	done
}

# The lockfile check reads what git tracks, not the working tree: a lockfile
# that exists only on the runner proves nothing about the reviewed change.
# Tracked names are looked up only by plain expansion: `[[ -v map[$key] ]]`
# would evaluate the subscript a second time.
# osv-scanner does not follow a symlink (a package manager does), finds
# nothing in a submodule entry, and skips any lockfile under node_modules/
# even with --no-ignore: each would leave a tracked file unscanned.
check_lockfiles() {
	local listing="$WORK_DIR/tracked" entry mode path name manifest locks lock
	local -a manifests=() lockless=() unscannable=()
	local -A lock_names=()
	for locks in "${MANIFEST_LOCKFILES[@]}"; do
		for lock in $locks; do
			lock_names["$lock"]=1
		done
	done
	git_isolated ls-files -s -z --cached >"$listing" ||
		osv_fail "not a usable git checkout: cannot list tracked files in $(pwd -P)"
	while IFS= read -r -d '' entry; do
		mode=${entry%% *}
		path=${entry#*$'\t'}
		name=${path##*/}
		if [[ -n "${MANIFEST_LOCKFILES["$name"]:-}" ]]; then
			manifests+=("$path")
		elif [[ -n "${lock_names["$name"]:-}" ]]; then
			TRACKED_LOCKFILES["$path"]=1
			LOCKFILE_PATHS+=("$path")
			[[ "/$path" == */node_modules/* ]] && unscannable+=("lockfile under node_modules/: $path")
		else
			continue
		fi
		case "$mode" in
		120000) unscannable+=("symlink: $path") ;;
		160000) unscannable+=("submodule entry: $path") ;;
		esac
	done <"$listing"
	((${#manifests[@]} + ${#TRACKED_LOCKFILES[@]} > 0)) && OSV_SOURCES_FOUND=true
	if [[ "$OSV_SOURCES_FOUND" != true ]]; then
		LOCKFILE_CHECK="no manifest or lockfile tracked"
		info "lockfile check: $LOCKFILE_CHECK"
		return
	fi
	if ((${#unscannable[@]} > 0)); then
		for entry in "${unscannable[@]}"; do
			printf 'security-floor: osv-scanner cannot scan %s\n' "$(printable_path "$entry")" >&2
		done
		LOCKFILE_CHECK="FAIL, ${#unscannable[@]} unscannable manifest or lockfile entries"
		osv_fail "lockfile check: ${#unscannable[@]} manifest or lockfile entries osv-scanner cannot scan"
	fi
	for manifest in "${manifests[@]}"; do
		manifest_has_lockfile "$manifest" || lockless+=("$manifest")
	done
	if ((${#lockless[@]} > 0)); then
		for manifest in "${lockless[@]}"; do
			printf 'security-floor: no tracked lockfile for manifest: %s\n' "$(printable_path "$manifest")" >&2
		done
		LOCKFILE_CHECK="FAIL, ${#lockless[@]} manifest(s) without a tracked lockfile"
		osv_fail "lockfile check: ${#lockless[@]} manifest(s) without a tracked lockfile in their directory or a parent"
	fi
	LOCKFILE_CHECK="ok"
	info "lockfile check: ok"
}

# write_osv_summary <result> [table file]
write_osv_summary() {
	local result=$1 table=${2:-}
	[[ -n "${GITHUB_STEP_SUMMARY:-}" ]] || return 0
	{
		printf '### security-floor: osv\n\n- osv-scanner: %s\n- lockfile check: %s\n- result: %s\n\n' \
			"$OSV_VERSION" "$LOCKFILE_CHECK" "$result"
		if [[ -n "$table" && -s "$table" ]]; then
			cat -- "$table"
			printf '\n'
		fi
	} >>"$GITHUB_STEP_SUMMARY" || info "warning: cannot write the job summary"
}

osv_fail() {
	write_osv_summary "FAIL, $*"
	fail "$@"
}

# osv_scan <config> <root> <format> <output file> [flag...]
# An empty --config replaces every osv-scanner.toml in the scanned tree, so a
# repo cannot ignore its own advisories. --no-ignore scans tracked files that
# .gitignore lists. Call analysis is off because it runs only when `go` is
# installed, and then drops advisories for code it judges uncalled: the
# verdict would depend on the runner image.
osv_scan() {
	local config=$1 root=$2 format=$3 output=$4
	shift 4
	"$WORK_DIR/osv-scanner" scan source --config "$config" --no-ignore --no-call-analysis=all \
		--format "$format" --output-file "$output" "$@" -r "$root"
}

# scanned_sources <osv json> <out>: writes, NUL-separated, every result
# source that holds at least one package. Results that are missing or not in
# the expected shape fail the run.
scanned_sources() {
	local json=$1 out=$2
	jq -j '.results | if type == "array" then .[] else error("no results array") end
		| select((.packages | length) > 0) | .source.path + "\u0000"' -- "$json" >"$out" 2>/dev/null ||
		osv_fail "osv-scanner error: JSON results are missing or unreadable"
}

# require_lockfiles_scanned <sources> <root> <table>: every tracked lockfile
# is a scanned source. osv-scanner names a source <root>/<tracked path> for
# the root it was given, so the root is the physical workspace path.
require_lockfiles_scanned() {
	local sources=$1 root=${2%/} table=$3 path
	local -a missing=()
	local -A scanned=()
	while IFS= read -r -d '' path; do
		scanned["$path"]=1
	done <"$sources"
	for path in "${LOCKFILE_PATHS[@]}"; do
		[[ -n "${scanned["$root/$path"]:-}" ]] || missing+=("$path")
	done
	((${#missing[@]} == 0)) && return 0
	for path in "${missing[@]}"; do
		printf 'security-floor: lockfile produced no packages: %s\n' "$(printable_path "$path")" >&2
	done
	write_osv_summary "FAIL, lockfile produced no packages" "$table"
	fail "osv: lockfile produced no packages: ${#missing[@]} tracked lockfile(s)"
}

# The verdict comes from one JSON scan; a second scan renders the table for
# the log and the job summary only.
run_osv() {
	local rc=0 table_rc root config="$WORK_DIR/osv-scanner.toml" json="$WORK_DIR/osv-results.json"
	local sources="$WORK_DIR/osv-sources" table="$WORK_DIR/osv-results.md"
	init_git_env
	check_lockfiles
	install_osv
	root=$(pwd -P) || osv_fail "cannot resolve the workspace path"
	: >"$config" || osv_fail "cannot write osv-scanner config"
	osv_scan "$config" "$root" json "$json" --all-packages || rc=$?
	case "$rc" in
	0 | 1)
		scanned_sources "$json" "$sources"
		table_rc=0
		osv_scan "$config" "$root" markdown "$table" >/dev/null 2>&1 || table_rc=$?
		((table_rc <= 1)) || info "osv-scanner table scan failed (exit $table_rc); the verdict is from the JSON scan"
		[[ -s "$table" ]] && cat -- "$table"
		;;
	128)
		if [[ "$OSV_SOURCES_FOUND" != true ]]; then
			printf '::notice title=security-floor::no package manifest or lockfile found; nothing to scan\n'
			write_osv_summary "pass (no package sources)"
			pass "osv: no package sources"
		fi
		: >"$sources" || osv_fail "cannot write the osv source list"
		;;
	*)
		write_osv_summary "FAIL, osv-scanner error (exit $rc)"
		fail "osv-scanner error (exit $rc): tool or network failure"
		;;
	esac
	require_lockfiles_scanned "$sources" "$root" "$table"
	case "$rc" in
	0)
		write_osv_summary "pass, no known vulnerabilities" "$table"
		pass "osv: no known vulnerabilities"
		;;
	1)
		write_osv_summary "FAIL, known vulnerabilities found" "$table"
		fail "osv: known vulnerabilities found"
		;;
	*)
		write_osv_summary "FAIL, lockfile produced no packages"
		fail "osv: lockfile produced no packages (exit $rc)"
		;;
	esac
}

main() {
	local cmd
	if [[ $# -ne 1 ]]; then
		usage
		exit 2
	fi
	case "$1" in
	gitleaks) cmd=run_gitleaks ;;
	osv) cmd=run_osv ;;
	*)
		usage
		exit 2
		;;
	esac
	check_platform
	trap cleanup EXIT
	prepare_dirs
	"$cmd"
}

main "$@"
