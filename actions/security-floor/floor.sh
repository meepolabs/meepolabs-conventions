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
	# git reads its global config (safe.directory on runners) from HOME.
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

BASE_DIR=""
OWNS_BASE_DIR=false
CACHE_DIR=""
WORK_DIR=""

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

run_gitleaks() {
	local rc=0
	install_gitleaks
	"$WORK_DIR/gitleaks" git --redact --verbose --exit-code 2 --no-banner . || rc=$?
	case "$rc" in
	0) pass "gitleaks: no leaks found" ;;
	2) fail "gitleaks: leaks found" ;;
	*) fail "gitleaks: scan error (exit $rc)" ;;
	esac
}

# An empty --config replaces any osv-scanner.toml in the scanned tree, so a
# repo cannot ignore its own advisories.
run_osv() {
	local rc=0 config="$WORK_DIR/osv-scanner.toml"
	install_osv
	: >"$config" || fail "cannot write osv-scanner config"
	"$WORK_DIR/osv-scanner" scan source --config "$config" -r . || rc=$?
	case "$rc" in
	0) pass "osv: no known vulnerabilities" ;;
	*) fail "osv: scan failed (exit $rc)" ;;
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
