#!/usr/bin/env bash
# Self-test for actions/security-floor (floor.sh, action.yml) and the
# pre-commit config. Needs network access, git, curl, jq, yq, pre-commit and
# sha256sum. Every fixture is generated at runtime, except the id-hook line
# lists under tests/id-hook/.
#
# Row contract: expect <name> <exit> <grep-text> [--contains <text>]
#                      [--absent <text>] -- cmd...
#   Runs cmd, asserts its exit code AND that its combined output contains
#   <grep-text> and every --contains text (fixed strings). --absent fails the
#   row if <text> appears.
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
readonly ACTIONS_DIR="$ROOT/actions"
readonly ACTION_YML="$ACTIONS_DIR/security-floor/action.yml"
readonly SELF="$ROOT/tests/run.sh"
readonly PRECOMMIT_CONFIG="$ROOT/.pre-commit-config.yaml"
readonly WORKFLOW_DIR="$ROOT/.github/workflows"
readonly ID_HOOK="no-internal-ids"
readonly ID_HOOK_ACCEPT="$ROOT/tests/id-hook/accept.txt"
readonly ID_HOOK_REJECT="$ROOT/tests/id-hook/reject.txt"

WORK=$(mktemp -d)
readonly WORK
trap 'rm -rf -- "$WORK"' EXIT
readonly SHARED_RUNNER_TEMP="$WORK/runner-temp-shared"
readonly FAKE_HOME="$WORK/home"
readonly PASS_LOG="$WORK/pass.log"
readonly FAIL_LOG="$WORK/fail.log"
readonly SKIP_LOG="$WORK/skip.log"
readonly ZERO=0000000000000000000000000000000000000000
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
	local -a absent=() contains=()
	while [[ $# -gt 0 && $1 != "--" ]]; do
		case "$1" in
		--absent)
			absent+=("$2")
			shift 2
			;;
		--contains)
			contains+=("$2")
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
		for text in "${contains[@]}"; do
			if ! grep -qF -- "$text" "$log"; then
				reason="output lacks '$text'"
				break
			fi
		done
		for text in "${absent[@]}"; do
			[[ -z "$reason" ]] || break
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

# git_in <repo> <args...>: git with a fixed identity, for fixture history.
git_in() {
	local repo=$1
	shift
	git -C "$repo" -c user.name=fixture -c user.email=fixture@example.invalid \
		-c commit.gpgsign=false "$@"
}

# write_file <repo> <path> <content>: write and stage, no commit.
write_file() {
	local repo=$1 path=$2 content=$3
	mkdir -p -- "$(dirname -- "$repo/$path")"
	printf '%s\n' "$content" >"$repo/$path"
	git -C "$repo" add -- "$path"
}

# evil_merge_repo <secret>: main and a side branch merge cleanly, and the
# merge commit alone adds the secret. Prints "<repo> <before> <merge>".
evil_merge_repo() {
	local repo before merge
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	git -C "$repo" branch side
	before=$(commit_file "$repo" main.txt "main change")
	git -C "$repo" checkout -q side
	commit_file "$repo" side.txt "side change" >/dev/null
	git -C "$repo" checkout -q main
	git_in "$repo" merge -q --no-ff --no-commit side
	write_file "$repo" app.env "API_TOKEN=$1"
	git_in "$repo" commit -q -m "merge side"
	merge=$(git -C "$repo" rev-parse HEAD)
	printf '%s %s %s\n' "$repo" "$before" "$merge"
}

# conflict_merge_repo <secret>: both branches edit one line; the conflict
# resolution alone introduces the secret. Prints "<repo> <before> <merge>".
conflict_merge_repo() {
	local repo before merge
	repo=$(new_repo)
	commit_file "$repo" app.env "API_TOKEN=unset" >/dev/null
	git -C "$repo" branch side
	before=$(commit_file "$repo" app.env "API_TOKEN=main")
	git -C "$repo" checkout -q side
	commit_file "$repo" app.env "API_TOKEN=side" >/dev/null
	git -C "$repo" checkout -q main
	git_in "$repo" merge -q side >/dev/null 2>&1 && {
		echo "conflict_merge_repo: merge did not conflict" >&2
		return 1
	}
	write_file "$repo" app.env "API_TOKEN=$1"
	git_in "$repo" commit -q --no-edit
	merge=$(git -C "$repo" rev-parse HEAD)
	printf '%s %s %s\n' "$repo" "$before" "$merge"
}

# scoped_pr_repo <secret>: main once held the secret (added, then removed);
# a PR branch from before that merges main back in. Prints
# "<repo> <base> <head>" for a PR whose range holds no secret.
scoped_pr_repo() {
	local repo base head
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	git -C "$repo" branch feature
	commit_file "$repo" app.env "API_TOKEN=$1" >/dev/null
	base=$(commit_file "$repo" app.env "API_TOKEN=unset")
	git -C "$repo" checkout -q feature
	commit_file "$repo" feature.txt "feature change" >/dev/null
	git_in "$repo" merge -q --no-ff --no-edit main
	head=$(git -C "$repo" rev-parse HEAD)
	git -C "$repo" checkout -q main
	printf '%s %s %s\n' "$repo" "$base" "$head"
}

# long_pr_repo <secret> <n>: a PR of <n> commits whose first commit holds the
# secret. Prints "<repo> <base> <head>".
long_pr_repo() {
	local repo base head i
	repo=$(new_repo)
	base=$(commit_file "$repo" README.md "fixture")
	commit_file "$repo" app.env "API_TOKEN=$1" >/dev/null
	for ((i = 2; i <= $2; i++)); do
		head=$(commit_file "$repo" "notes/$i.txt" "change $i")
	done
	printf '%s %s %s\n' "$repo" "$base" "$head"
}

# nul_byte_secret_repo <secret>: the secret sits in a file git calls binary
# only because of a NUL byte. The name keeps a text extension: gitleaks's
# default config skips paths with binary extensions (.bin, ...) by name.
nul_byte_secret_repo() {
	local repo
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	printf 'API_TOKEN=%s\n\000\n' "$1" >"$repo/app.env"
	git -C "$repo" add -- app.env
	git_in "$repo" commit -q -m "add app.env"
	printf '%s\n' "$repo"
}

# attributes_repo [secret]: a tracked .gitattributes marks every file -diff;
# with a secret, a later commit adds it.
attributes_repo() {
	local repo
	repo=$(new_repo)
	commit_file "$repo" .gitattributes "* -diff" >/dev/null
	if [[ $# -gt 0 ]]; then
		commit_file "$repo" app.env "API_TOKEN=$1" >/dev/null
	else
		commit_file "$repo" app.env "API_TOKEN=unset" >/dev/null
	fi
	printf '%s\n' "$repo"
}

# gitconfig_home <attributes line> [gitconfig lines]: a HOME whose
# ~/.gitconfig points core.attributesFile at a file holding <attributes line>.
gitconfig_home() {
	local dir
	dir=$(mktemp -d "$WORK/home.XXXXXX")
	printf '%s\n' "$1" >"$dir/attributes"
	printf '[core]\n\tattributesFile = %s\n%s\n' "$dir/attributes" "${2:-}" >"$dir/.gitconfig"
	printf '%s\n' "$dir"
}

# ignored_secret_repo <secret_repo>: a full clone of <secret_repo> whose
# .gitleaksignore lists the fingerprint of the secret's finding.
ignored_secret_repo() {
	local repo sha
	repo=$(mktemp -d "$WORK/repo.XXXXXX")
	git clone -q -- "file://$1" "$repo"
	sha=$(git -C "$repo" log -n 1 --format=%H -- app.env)
	commit_file "$repo" .gitleaksignore "$sha:app.env:github-pat:1" >/dev/null
	printf '%s\n' "$repo"
}

# typechange_repo <secret>: app.env starts as a symlink, then a regular file
# holding the secret replaces it. Prints "<repo> <before> <after>".
typechange_repo() {
	local repo before after
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	ln -s README.md "$repo/app.env"
	git -C "$repo" add -- app.env
	git_in "$repo" commit -q -m "link app.env"
	before=$(git -C "$repo" rev-parse HEAD)
	rm -- "$repo/app.env"
	after=$(commit_file "$repo" app.env "API_TOKEN=$1")
	[[ "$(git -C "$repo" diff --name-status "$before" "$after")" == $'T\tapp.env' ]] || {
		echo "typechange_repo: not a type change" >&2
		return 1
	}
	printf '%s %s %s\n' "$repo" "$before" "$after"
}

# rename_pr_repo <secret>: a PR adds the secret under node_modules/ (skipped
# by the default rules' path allowlist), then renames it out. Prints
# "<repo> <base> <head>".
rename_pr_repo() {
	local repo base head
	repo=$(new_repo)
	base=$(commit_file "$repo" README.md "fixture")
	commit_file "$repo" node_modules/x/app.env "API_TOKEN=$1" >/dev/null
	git -C "$repo" mv -- node_modules/x/app.env app.env
	git_in "$repo" commit -q -m "move app.env"
	head=$(git -C "$repo" rev-parse HEAD)
	printf '%s %s %s\n' "$repo" "$base" "$head"
}

# octopus_repo <secret>: a three-parent merge whose own change adds the
# secret. Prints "<repo> <before> <merge>".
octopus_repo() {
	local repo before merge parents
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	git -C "$repo" branch one
	git -C "$repo" branch two
	before=$(commit_file "$repo" main.txt "main change")
	git -C "$repo" checkout -q one
	commit_file "$repo" one.txt "one" >/dev/null
	git -C "$repo" checkout -q two
	commit_file "$repo" two.txt "two" >/dev/null
	git -C "$repo" checkout -q main
	git_in "$repo" merge -q --no-ff --no-commit one two >/dev/null
	write_file "$repo" app.env "API_TOKEN=$1"
	git_in "$repo" commit -q -m "merge one and two"
	merge=$(git -C "$repo" rev-parse HEAD)
	parents=$(git -C "$repo" rev-list --parents -n 1 "$merge" | wc -w)
	[[ "$parents" == 4 ]] || {
		echo "octopus_repo: merge has $((parents - 1)) parents, want 3" >&2
		return 1
	}
	printf '%s %s %s\n' "$repo" "$before" "$merge"
}

# check_commands_fenced <log>: the log holds a ::stop-commands:: fence, and
# every ::warning line sits inside it. Fails when no such line exists, so a
# fixture that stops producing one cannot pass.
check_commands_fenced() {
	local log=$1 line token="" inside=false fenced=0 bare=0
	while IFS= read -r line; do
		if [[ "$inside" == false && "$line" =~ ^::stop-commands::([0-9a-f]{32})$ ]]; then
			token=${BASH_REMATCH[1]}
			inside=true
		elif [[ "$inside" == true && "$line" == "::$token::" ]]; then
			inside=false
		elif [[ "$line" == ::warning* ]]; then
			if [[ "$inside" == true ]]; then
				fenced=$((fenced + 1))
			else
				bare=$((bare + 1))
			fi
		fi
	done <"$log"
	echo "workflow commands: $fenced fenced, $bare outside the fence"
	[[ -n "$token" && "$inside" == false && "$fenced" -gt 0 && "$bare" == 0 ]]
}

# run_floor_fenced <repo> <subcommand> [NAME=VALUE...]: runs the subcommand,
# then checks its output with check_commands_fenced. Returns 3 when the check
# fails, else the floor's exit code.
run_floor_fenced() {
	local repo=$1 sub=$2 log rc=0
	shift 2
	log=$(mktemp "$WORK/fenced.XXXXXX")
	run_floor "$repo" "$sub" "$@" >"$log" 2>&1 || rc=$?
	cat -- "$log"
	check_commands_fenced "$log" || return 3
	return "$rc"
}

# run_floor_no_bare_commands <repo> <subcommand> [NAME=VALUE...]: runs the
# subcommand, then returns 3 if any log line other than a stop-commands fence
# line starts a workflow command, else the floor's exit code.
run_floor_no_bare_commands() {
	local repo=$1 sub=$2 log rc=0 bare
	shift 2
	log=$(mktemp "$WORK/bare.XXXXXX")
	run_floor "$repo" "$sub" "$@" >"$log" 2>&1 || rc=$?
	cat -- "$log"
	bare=$(grep -E '^::' -- "$log" | grep -cvE '^::(stop-commands::[0-9a-f]{32}|[0-9a-f]{32}::)$' || true)
	echo "bare workflow commands: $bare"
	[[ "$bare" == 0 ]] || return 3
	return "$rc"
}

# corrupt_history_repo: HEAD exists but its parent commit object is gone.
corrupt_history_repo() {
	local repo parent
	repo=$(new_repo)
	parent=$(commit_file "$repo" README.md "fixture")
	commit_file "$repo" notes.txt "change" >/dev/null
	rm -f -- "$repo/.git/objects/${parent:0:2}/${parent:2}"
	printf '%s\n' "$repo"
}

# bang_attributes_pr_repo <secret>: a PR whose head commit adds a
# .gitattributes line git warns about on stderr, and the secret. Prints
# "<repo> <base> <head>".
bang_attributes_pr_repo() {
	local repo base head
	repo=$(new_repo)
	base=$(commit_file "$repo" README.md "fixture")
	write_file "$repo" .gitattributes '!x text'
	write_file "$repo" app.env "API_TOKEN=$1"
	git_in "$repo" commit -q -m "add app.env"
	head=$(git -C "$repo" rev-parse HEAD)
	printf '%s %s %s\n' "$repo" "$base" "$head"
}

# missing_preimage_repo <secret>: a push range that edits app.env to hold the
# secret, with the pre-push version of app.env deleted from the object store.
# Every object the range itself reaches is present. Prints
# "<repo> <before> <after>".
missing_preimage_repo() {
	local repo before after blob
	repo=$(new_repo)
	before=$(commit_file "$repo" app.env "API_TOKEN=unset")
	blob=$(git -C "$repo" rev-parse "$before:app.env")
	after=$(commit_file "$repo" app.env "API_TOKEN=$1")
	rm -f -- "$repo/.git/objects/${blob:0:2}/${blob:2}"
	git -C "$repo" cat-file -e "$blob" 2>/dev/null && {
		echo "missing_preimage_repo: blob still present" >&2
		return 1
	}
	printf '%s %s %s\n' "$repo" "$before" "$after"
}

# partial_clone_repo: a --filter=blob:none clone whose promisor remote is
# gone, so the blobs of older commits can be neither read nor fetched.
partial_clone_repo() {
	local src dest i
	src=$(new_repo)
	git -C "$src" config uploadpack.allowFilter true
	for i in 1 2 3; do
		commit_file "$src" notes.txt "version $i" >/dev/null
	done
	dest=$(mktemp -d "$WORK/repo.XXXXXX")
	git clone -q --filter=blob:none -- "file://$src" "$dest" 2>/dev/null
	rm -rf -- "$src"
	[[ "$(git -C "$dest" config --get remote.origin.promisor)" == true ]] || {
		echo "partial_clone_repo: clone is not partial" >&2
		return 1
	}
	printf '%s\n' "$dest"
}

# rich_clean_repo: a clean history holding a merge, a rename and a
# .gitattributes, so git log -p walks the paths the scan options change.
rich_clean_repo() {
	local repo
	repo=$(new_repo)
	commit_file "$repo" .gitattributes '*.env text' >/dev/null
	commit_file "$repo" README.md "fixture" >/dev/null
	git -C "$repo" branch side
	commit_file "$repo" main.txt "main change" >/dev/null
	git -C "$repo" checkout -q side
	commit_file "$repo" side.env "API_TOKEN=unset" >/dev/null
	git -C "$repo" checkout -q main
	git_in "$repo" merge -q --no-ff --no-edit side
	git -C "$repo" mv -- side.env renamed.env
	git_in "$repo" commit -q -m "rename side.env"
	printf '%s\n' "$repo"
}

# xdg_attributes_home <attributes line>: a HOME holding git's default
# attributes file, read when core.attributesFile is unset.
xdg_attributes_home() {
	local dir
	dir=$(mktemp -d "$WORK/home.XXXXXX")
	mkdir -p -- "$dir/.config/git"
	printf '%s\n' "$1" >"$dir/.config/git/attributes"
	printf '%s\n' "$dir"
}

# replaced_secret_repo <secret>: main holds the secret, and a refs/replace
# entry swaps that commit for a clean twin.
replaced_secret_repo() {
	local repo base secret_commit twin
	repo=$(new_repo)
	base=$(commit_file "$repo" README.md "fixture")
	secret_commit=$(commit_file "$repo" app.env "API_TOKEN=$1")
	git -C "$repo" checkout -q --detach "$base"
	twin=$(commit_file "$repo" app.env "API_TOKEN=unset")
	git -C "$repo" checkout -q main
	git -C "$repo" replace "$secret_commit" "$twin"
	printf '%s\n' "$repo"
}

# textconv_local_repo <secret>: a tracked .gitattributes routes every file
# through a diff driver whose textconv, set in .git/config, prints nothing.
textconv_local_repo() {
	local repo
	repo=$(files_repo .gitattributes '* diff=t' app.env "API_TOKEN=$1")
	git -C "$repo" config diff.t.textconv true
	printf '%s\n' "$repo"
}

# graft_repo <secret>: a deprecated info/grafts file, which makes git print a
# hint on stderr for every history walk.
graft_repo() {
	local repo head
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	head=$(commit_file "$repo" app.env "API_TOKEN=$1")
	printf '%s\n' "$head" >"$repo/.git/info/grafts"
	printf '%s\n' "$repo"
}

# trailing_backslash_pr_repo <secret>: a plain file holds the secret, then two
# commits add and edit a file named "t\" whose lines, once the parser has
# lost the name, read as diff headers. gitleaks then stops before the older
# commit and passes. Prints "<repo> <base> <head>" for a PR spanning all three.
trailing_backslash_pr_repo() {
	local repo base head
	repo=$(new_repo)
	base=$(commit_file "$repo" README.md "fixture")
	commit_file "$repo" app.env "API_TOKEN=$1" >/dev/null
	commit_file "$repo" "t\\" $'-- /dev/null\na\nb\nc\nold' >/dev/null
	head=$(commit_file "$repo" "t\\" $'++ b/x\na\nb\nc\nnew')
	printf '%s %s %s\n' "$repo" "$base" "$head"
}

# parser_stall_repo: the "t\\" history behind a large diff. Once the parser
# stops reading, git blocks writing to the pipe and gitleaks waits forever.
parser_stall_repo() {
	local repo
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	commit_file "$repo" big.txt "$(seq 1 40000)" >/dev/null
	commit_file "$repo" "t\\" $'-- /dev/null\na\nb\nc\nold' >/dev/null
	commit_file "$repo" "t\\" $'++ b/x\na\nb\nc\nnew' >/dev/null
	printf '%s\n' "$repo"
}

# quoted_name_merge_repo: a clean merge whose resolution alone adds a file
# named "t\", so only the remerge diff of the merge commit shows the name.
quoted_name_merge_repo() {
	local repo
	repo=$(new_repo)
	commit_file "$repo" README.md "fixture" >/dev/null
	git -C "$repo" branch side
	commit_file "$repo" main.txt "main change" >/dev/null
	git -C "$repo" checkout -q side
	commit_file "$repo" side.txt "side change" >/dev/null
	git -C "$repo" checkout -q main
	git_in "$repo" merge -q --no-ff --no-commit side
	write_file "$repo" "t\\" "fixture"
	git_in "$repo" commit -q -m "merge side"
	printf '%s\n' "$repo"
}

# noisy_attributes_repo: a tracked .gitattributes with thousands of lines git
# warns about, so git log prints megabytes on stderr.
noisy_attributes_repo() {
	local repo
	repo=$(new_repo)
	seq -f '!x%g text' 1 10000 >"$repo/.gitattributes"
	git -C "$repo" add -- .gitattributes 2>/dev/null
	git_in "$repo" commit -q -m "add .gitattributes" 2>/dev/null
	commit_file "$repo" README.md "fixture" 2>/dev/null >/dev/null
	printf '%s\n' "$repo"
}

# run_floor_term_in_fence <script> <repo> <marker>: runs the gitleaks
# subcommand in its own process group and, once the script's git stub has
# written <marker> (the history walk started inside the command fence),
# sends SIGTERM to the group, as a runner cancelling the job does. Returns 3
# unless the log holds exactly one stop and one matching resume line, else the
# floor's exit code.
run_floor_term_in_fence() {
	local script=$1 repo=$2 marker=$3 log pid i rc=0 token stops resumes
	log=$(mktemp "$WORK/term.XXXXXX")
	(cd -- "$repo" && exec setsid env -i PATH="$PATH" HOME="$FAKE_HOME" RUNNER_TEMP="$SHARED_RUNNER_TEMP" \
		GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event" "$script" gitleaks) >"$log" 2>&1 &
	pid=$!
	for ((i = 0; i < 600; i++)); do
		[[ -e "$marker" ]] && break
		sleep 0.1
	done
	[[ -e "$marker" ]] || echo "history walk never started"
	kill -TERM -- "-$pid" 2>/dev/null || true
	wait "$pid" || rc=$?
	cat -- "$log"
	token=$(sed -n 's/^::stop-commands::\([0-9a-f]\{32\}\)$/\1/p' -- "$log" | head -n 1)
	stops=$(grep -c '^::stop-commands::' -- "$log" || true)
	resumes=0
	[[ -n "$token" ]] && resumes=$(grep -cxF -- "::$token::" "$log" || true)
	echo "fence: $stops stop, $resumes resume"
	[[ -e "$marker" && "$stops" == 1 && "$resumes" == 1 ]] || return 3
	return "$rc"
}

# run_floor_summary <repo> <subcommand> [NAME=VALUE...]: run_floor with a job
# summary file, then print the summary with each line prefixed "summary: ".
run_floor_summary() {
	local repo=$1 sub=$2 summary rc=0
	shift 2
	summary=$(mktemp "$WORK/summary.XXXXXX")
	run_floor "$repo" "$sub" GITHUB_STEP_SUMMARY="$summary" "$@" || rc=$?
	sed 's/^/summary: /' -- "$summary"
	return "$rc"
}

# run_floor_summary_only <repo> <subcommand> [NAME=VALUE...]: as
# run_floor_summary, but the run's own log is discarded, so a match can only
# come from the summary.
run_floor_summary_only() {
	local rc=0
	run_floor_summary "$@" >"$WORK/summary-only.log" 2>&1 || rc=$?
	grep '^summary: ' -- "$WORK/summary-only.log" || true
	return "$rc"
}

# files_repo <path> <content> [<path> <content>...]: a repo with each file
# committed in order. Content "" writes a zero-byte file.
files_repo() {
	local repo
	repo=$(new_repo)
	while [[ $# -gt 0 ]]; do
		if [[ -z "$2" ]]; then
			mkdir -p -- "$(dirname -- "$repo/$1")"
			: >"$repo/$1"
			git -C "$repo" add -- "$1"
			git_in "$repo" commit -q -m "add $1"
		else
			commit_file "$repo" "$1" "$2" >/dev/null
		fi
		shift 2
	done
	printf '%s\n' "$repo"
}

# gitignored_lockfile_repo <ignored: true|false>: a clean root lockfile and a
# tracked vulnerable sub/package-lock.json, optionally listed in .gitignore.
gitignored_lockfile_repo() {
	local repo
	repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" sub/package-lock.json "$(vulnerable_npm_lockfile)")
	[[ "$1" == true ]] && commit_file "$repo" .gitignore "sub/" >/dev/null
	printf '%s\n' "$repo"
}

# symlinked_lockfile_repo: a clean root lockfile, and sub/package-lock.json
# tracked as a symlink to a vulnerable lockfile stored under another name.
symlinked_lockfile_repo() {
	local repo
	repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" data/lock.json "$(vulnerable_npm_lockfile)")
	mkdir -p -- "$repo/sub"
	ln -s ../data/lock.json "$repo/sub/package-lock.json"
	git -C "$repo" add -- sub/package-lock.json
	git_in "$repo" commit -q -m "link sub/package-lock.json"
	printf '%s\n' "$repo"
}

# gitlink_lockfile_repo: a clean root lockfile, and a submodule entry named
# sub/package-lock.json.
gitlink_lockfile_repo() {
	local repo
	repo=$(files_repo package-lock.json "$(clean_npm_lockfile)")
	git -C "$repo" update-index --add --cacheinfo "160000,$(git -C "$repo" rev-parse HEAD),sub/package-lock.json"
	git_in "$repo" commit -q -m "add sub/package-lock.json submodule entry"
	printf '%s\n' "$repo"
}

# symlinked_go_mod_repo: a clean root lockfile, and sub/go.mod tracked as a
# symlink to a vulnerable go.mod stored under another name. go.mod is not a
# manifest the lockfile map knows.
symlinked_go_mod_repo() {
	local repo
	repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" data/go-mod.txt "$(go_mod_vulnerable)")
	mkdir -p -- "$repo/sub"
	ln -s ../data/go-mod.txt "$repo/sub/go.mod"
	git -C "$repo" add -- sub/go.mod
	git_in "$repo" commit -q -m "link sub/go.mod"
	printf '%s\n' "$repo"
}

# symlinked_plain_files_repo: a clean root lockfile and tracked symlinks whose
# names no osv-scanner extractor reads, the shape of a repo that links hooks
# or docs.
symlinked_plain_files_repo() {
	local repo
	repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" hooks/shared "#!/bin/sh")
	mkdir -p -- "$repo/a/hooks"
	ln -s ../../hooks/shared "$repo/a/hooks/pre-app-boot"
	ln -s ../package-lock.json "$repo/a/lock-link.json"
	git -C "$repo" add -- a/hooks/pre-app-boot a/lock-link.json
	git_in "$repo" commit -q -m "link hooks"
	printf '%s\n' "$repo"
}

# floor_counting_osv <marker>: a floor.sh copy that appends a line to <marker>
# each time it starts osv-scanner.
floor_counting_osv() {
	# shellcheck disable=SC2016 # literal source text
	floor_copy_with '	"$WORK_DIR/osv-scanner" scan source' "	echo osv >>'$1'
	\"\$WORK_DIR/osv-scanner\" scan source"
}

# run_floor_counting_osv <marker> <script> <repo>: runs the osv subcommand,
# then prints how many times osv-scanner started.
run_floor_counting_osv() {
	local marker=$1 rc=0
	run_floor_script "$2" "$3" osv || rc=$?
	echo "osv-scanner invocations: $(grep -c '' -- "$marker" 2>/dev/null || echo 0)"
	return "$rc"
}

# An npm lockfile that parses but lists no packages.
zero_package_npm_lockfile() {
	printf '{"name": "fixture", "lockfileVersion": 3, "packages": {"": {"name": "fixture"}}}\n'
}

# fsmonitor_home: a HOME whose ~/.gitconfig runs a hook, which announces
# itself on stderr, from any git command that reads the index.
fsmonitor_home() {
	local dir
	dir=$(mktemp -d "$WORK/home.XXXXXX")
	printf '#!/bin/sh\necho fsmonitor-hook-ran >&2\nexit 1\n' >"$dir/hook"
	chmod 0755 "$dir/hook"
	printf '[core]\n\tfsmonitor = %s\n' "$dir/hook" >"$dir/.gitconfig"
	printf '%s\n' "$dir"
}

# floor_with_go_stub <marker> [<from> <to>]: a floor.sh copy (optionally with
# one literal replaced) whose fixed PATH holds a `go` that records each call
# in <marker>.
floor_with_go_stub() {
	local marker=$1 script=$FLOOR_SH dir
	if [[ $# -ge 3 ]]; then
		script=$(copy_with "$FLOOR_SH" "$2" "$3")
	fi
	dir=$(stub_dir "go=echo \"\$*\" >>'$marker'; exit 1")
	copy_with "$script" 'readonly FLOOR_PATH=/usr/bin:/bin' "readonly FLOOR_PATH=$dir:/usr/bin:/bin"
}

# run_floor_reporting_go <marker> <script> <repo>: runs the osv subcommand,
# then reports whether the go stub was called.
run_floor_reporting_go() {
	local marker=$1 rc=0
	run_floor_script "$2" "$3" osv || rc=$?
	[[ -s "$marker" ]] && echo "go was invoked: $(head -n 1 -- "$marker")"
	return "$rc"
}

# check_osv_flags <file>: the osv-scanner call carries every flag the
# verdict depends on.
check_osv_flags() {
	local file=$1 flag bad=0 call
	# shellcheck disable=SC2016 # literal source text
	call=$(grep -F '"$WORK_DIR/osv-scanner" scan source' "$file" || true)
	[[ -n "$call" ]] || {
		echo "osv-scanner scan call not found"
		return 1
	}
	# shellcheck disable=SC2016 # literal source text
	for flag in '--config "$config"' --no-ignore --no-call-analysis=all; do
		if ! grep -qF -- "$flag" <<<"$call"; then
			echo "osv-scanner call lacks $flag"
			bad=1
		fi
	done
	[[ "$bad" == 0 ]] || return 1
	echo "osv flags present"
}

go_mod_vulnerable() {
	printf 'module example.com/fixture\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.0\n'
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

# A gitleaks config with one custom rule for a string no default rule flags.
gitleaks_custom_rule_toml() {
	printf '[[rules]]\nid = "fixture-marker"\nregex = %s\n' "'FIXTURE_MARKER_[0-9]{8}'"
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

# copy_with <file> <from> <to>: a temp copy of <file> with one literal
# replaced; fails if <from> is not present exactly once.
copy_with() {
	local file=$1 from=$2 to=$3 dir content n copy
	content=$(<"$file")
	n=$(grep -cF -- "$from" "$file" || true)
	[[ "$n" == 1 ]] || {
		echo "copy_with: '$from' found $n times" >&2
		return 1
	}
	dir=$(mktemp -d "$WORK/floor-copy.XXXXXX")
	copy="$dir/$(basename -- "$file")"
	printf '%s\n' "${content/"$from"/"$to"}" >"$copy"
	chmod 0755 "$copy"
	printf '%s\n' "$copy"
}

floor_copy_with() {
	copy_with "$FLOOR_SH" "$@"
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

# run_floor_script_bounded <seconds> <script> <repo> <subcommand> [NAME=VALUE...]:
# run_floor_script, killed after <seconds> (exit 124) so a hang fails the row.
run_floor_script_bounded() {
	local seconds=$1 script=$2 repo=$3 sub=$4
	shift 4
	cd -- "$repo"
	timeout "$seconds" env -i PATH="$PATH" HOME="$FAKE_HOME" RUNNER_TEMP="$SHARED_RUNNER_TEMP" \
		"$@" "$script" "$sub"
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

# action_json <file>: action.yml as JSON, so the checks below query it with jq.
action_json() {
	yq -o=json '.' "$1"
}

# check_action_interface <file>: no inputs and no outputs, not even empty.
check_action_interface() {
	local declared
	declared=$(action_json "$1" | jq -r '[keys[] | select(. == "inputs" or . == "outputs")] | join(" ")')
	[[ -z "$declared" ]] || {
		echo "action declares: $declared"
		return 1
	}
	echo "no inputs or outputs"
}

# check_action_run_lines <file>: a composite action whose only steps are the
# gitleaks and osv runs of floor.sh, in that order, each in bash.
check_action_run_lines() {
	local got want
	got=$(action_json "$1" | jq -c '{using: .runs.using, steps: [.runs.steps[] | {id, shell, run}]}')
	# shellcheck disable=SC2016 # the action's run text, expanded by the runner
	want=$(jq -cn --arg p '/bin/bash -p "$GITHUB_ACTION_PATH/floor.sh"' \
		'{using: "composite", steps: [
			{id: "gitleaks", shell: "bash", run: ($p + " gitleaks")},
			{id: "osv", shell: "bash", run: ($p + " osv")}]}')
	[[ "$got" == "$want" ]] || {
		printf 'unexpected run lines:\n got %s\nwant %s\n' "$got" "$want"
		return 1
	}
	echo "two run lines: gitleaks, osv"
}

# check_action_privileged_bash <file>: every run starts the script with
# /bin/bash -p, so BASH_ENV and exported functions are not loaded.
check_action_privileged_bash() {
	local bad
	bad=$(action_json "$1" | jq -r '.runs.steps[] | select(.run | startswith("/bin/bash -p ") | not) | .id')
	[[ -z "$bad" ]] || {
		echo "run without /bin/bash -p in step: $bad"
		return 1
	}
	echo "every run uses /bin/bash -p"
}

# check_action_osv_condition <file>: osv runs after a gitleaks failure.
check_action_osv_condition() {
	local cond
	cond=$(action_json "$1" | jq -r '.runs.steps[] | select(.id == "osv") | .["if"] // ""')
	# shellcheck disable=SC2016 # literal expression text
	[[ "$cond" == '${{ !cancelled() }}' ]] || {
		echo "osv step condition is '$cond'"
		return 1
	}
	echo "osv runs unless cancelled"
}

# check_action_no_run_expressions <file>: no workflow expression is spliced
# into shell text.
check_action_no_run_expressions() {
	local bad
	bad=$(action_json "$1" | jq -r '.runs.steps[] | select(.run | contains("${{")) | .id')
	[[ -z "$bad" ]] || {
		echo "expression in run of step: $bad"
		return 1
	}
	echo "no expressions in run"
}

# run_action_step <action.yml> <step id> <repo> [NAME=VALUE...]: runs the
# step's run text the way a composite bash step does (a script file under
# bash --noprofile --norc -eo pipefail) with GITHUB_ACTION_PATH at the real
# action directory and the repo as working directory.
run_action_step() {
	local action=$1 id=$2 repo=$3 script
	shift 3
	script=$(mktemp "$WORK/step.XXXXXX")
	action_json "$action" | jq -r --arg id "$id" '.runs.steps[] | select(.id == $id) | .run' >"$script"
	[[ -s "$script" ]] || {
		echo "run_action_step: no step $id"
		return 2
	}
	cd -- "$repo"
	env -i PATH="$PATH" HOME="$FAKE_HOME" RUNNER_TEMP="$SHARED_RUNNER_TEMP" \
		GITHUB_ACTION_PATH="$(dirname -- "$FLOOR_SH")" "$@" \
		/bin/bash --noprofile --norc -eo pipefail "$script"
}

# A bash function body for chmod that, when bash imports it, replaces any
# gitleaks it is asked to chmod with a stub that reports the pinned version
# and finds nothing.
# shellcheck disable=SC2016 # function source text
readonly CHMOD_DROPS_FAKE_GITLEAKS='() { case "$2" in */gitleaks) printf "#!/bin/sh\n[ \"\$1\" = version ] && echo 8.30.1\nexit 0\n" >"$2" ;; esac; command chmod "$@"; }'

# imported_chmod_drops_fake_gitleaks: plain bash imports the function, and
# a chmod of a gitleaks path leaves the stub behind.
imported_chmod_drops_fake_gitleaks() {
	local target
	target="$(mktemp -d "$WORK/fake-gitleaks.XXXXXX")/gitleaks"
	: >"$target"
	# shellcheck disable=SC2016 # expands in the child shell
	env -i PATH=/usr/bin:/bin "BASH_FUNC_chmod%%=$CHMOD_DROPS_FAKE_GITLEAKS" \
		/bin/bash -c 'chmod 0700 "$1" && "$1" version' bash "$target"
}

# ---------------------------------------------------------------- pre-commit

# id_hook_config <config> <out>: only the id hook, with its exclude dropped so
# fixture files are checked wherever they sit.
id_hook_config() {
	HOOK_ID="$ID_HOOK" yq '
		.repos = [.repos[] | select(.repo == "local")
			| .hooks = [.hooks[] | select(.id == strenv(HOOK_ID)) | del(.exclude)]
			| select(.hooks | length == 1)]' "$1" >"$2"
	[[ "$(yq '.repos | length' "$2")" == 1 ]] || {
		echo "id_hook_config: no local hook $ID_HOOK in $1" >&2
		return 1
	}
}

# id_hook_run <config> <out>: writes each accept line to accept-<n>.txt and
# each reject line to reject-<n>.txt in a fresh repo, runs the derived hook
# once over all of them, and saves its output.
id_hook_run() {
	local config=$1 out=$2 repo kind n line
	local -a files=()
	repo=$(new_repo)
	id_hook_config "$config" "$repo/hook.yaml"
	for kind in accept reject; do
		n=0
		while IFS= read -r line || [[ -n "$line" ]]; do
			n=$((n + 1))
			printf '%s\n' "$line" >"$repo/$kind-$n.txt"
			files+=("$kind-$n.txt")
		done <"$ROOT/tests/id-hook/$kind.txt"
	done
	git -C "$repo" add -- hook.yaml "${files[@]}"
	(cd -- "$repo" && PRE_COMMIT_HOME="$WORK/pre-commit-home" \
		pre-commit run "$ID_HOOK" -c hook.yaml --color never --files "${files[@]}") >"$out" 2>&1 || true
}

# id_hook_verdict <output> <file> <reported|quiet>: the hook ran, and named
# the file or not.
id_hook_verdict() {
	local out=$1 file=$2 want=$3 got=quiet
	grep -q '^no internal ids\.\.\.*\(Passed\|Failed\)$' "$out" || {
		echo "id hook did not run:"
		cat -- "$out"
		return 2
	}
	cut -d: -f1 -- "$out" | grep -qxF -- "$file" && got=reported
	echo "$file: $got"
	[[ "$got" == "$want" ]]
}

# fixture_lines <file>: the line count, failing on an empty list.
fixture_lines() {
	local n
	n=$(grep -c '' "$1" || true)
	echo "$1: $n lines"
	[[ "$n" -gt 0 ]]
}

# check_gitleaks_rev_parity <config> <floor.sh>: the hook rev, without its
# leading v, is the version floor.sh pins.
check_gitleaks_rev_parity() {
	local rev pin
	rev=$(yq '.repos[] | select(.repo == "https://github.com/gitleaks/gitleaks") | .rev' "$1")
	pin=$(sed -n 's/^readonly GITLEAKS_VERSION="\([^"]*\)"$/\1/p' "$2")
	if [[ -n "$pin" && "${rev#v}" == "$pin" ]]; then
		echo "gitleaks rev parity: $pin"
	else
		echo "gitleaks rev mismatch: hook '$rev', floor.sh '$pin'"
		return 1
	fi
}

# ---------------------------------------------------------------- workflows

# Workflow policies as jq programs over one workflow, parsed by yq with
# anchors expanded. Each yields {checked, violations}. A policy whose key
# (`on` or `jobs`) is missing or of the wrong type errors, so the file fails.
# shellcheck disable=SC2016 # jq program text
declare -rA WORKFLOW_POLICIES=(
	[pull-request-target]='
		(.on | if type == "string" then [.] elif type == "array" then .
			elif type == "object" then keys else error("unrecognized on") end) as $t
		| {checked: ($t | length),
			violations: [$t[] | select(. == "pull_request_target") | "trigger pull_request_target"]}'
	[secrets-inherit]='
		[.jobs | to_entries[]] as $j
		| {checked: ($j | length),
			violations: [$j[] | select(.value.secrets == "inherit") | "job \(.key): secrets: inherit"]}'
	[timeout]='
		[.jobs | to_entries[]] as $j
		| {checked: ($j | length),
			violations: [$j[] | select(.value["timeout-minutes"] == null) | "job \(.key): no timeout-minutes"]}'
	[pinned-uses]='
		[.jobs | to_entries[] | .key as $k | .value
			| ((.uses // empty), (.steps // [] | .[] | .uses // empty)) | {job: $k, ref: .}] as $u
		| {checked: ($u | length),
			violations: [$u[] | select((.ref | type) != "string"
				or (.ref | test("\\A(\\./|[^@]+@[0-9a-f]{40}\\z)") | not))
				| "job \(.job): uses \(.ref)"]}'
)

# apply_policy <name> <program> <base> <file>...: runs one jq program over
# each file, parsed by yq with anchors expanded, and prints each violation
# with the file's path under <base>. Fails on a violation, a file that does
# not parse, or nothing to check.
apply_policy() {
	local name=$1 program=$2 base=$3 file result line checked=0 bad=0
	shift 3
	for file in "$@"; do
		if ! result=$(yq -o=json 'explode(.)' "$file" | jq -c "$program"); then
			echo "$name: cannot check ${file#"$base"/}"
			bad=1
			continue
		fi
		checked=$((checked + $(jq -r '.checked' <<<"$result")))
		while IFS= read -r line; do
			echo "${file#"$base"/}: $line"
			bad=1
		done < <(jq -r '.violations[]' <<<"$result")
	done
	[[ "$bad" == 0 && "$checked" -gt 0 ]] || {
		echo "$name: FAIL ($checked checked)"
		return 1
	}
	echo "$name: ok, $checked checked in $# files"
}

# check_workflows <policy> <dir>: applies one policy to every file in <dir>.
check_workflows() {
	local policy=$1 dir=$2
	local -a files
	mapfile -t -d '' files < <(find "$dir" -mindepth 1 -maxdepth 1 -print0 | sort -z)
	((${#files[@]} > 0)) || {
		echo "$policy: no workflow files in $dir"
		return 1
	}
	apply_policy "$policy" "${WORKFLOW_POLICIES[$policy]}" "$dir" "${files[@]}"
}

# Composite action steps: every uses: is local, pinned to a 40-hex commit
# SHA, or a docker:// image pinned by digest. A file without a runs mapping,
# or with steps that are not a list, errors, so the file fails. Every step
# counts as checked, so a composite of run: steps only still checks.
# shellcheck disable=SC2016 # jq program text
readonly ACTION_PINNED_USES='
	(.runs | if type == "object" then . else error("no runs mapping") end
		| .steps // [] | if type == "array" then . else error("steps is not a list") end) as $s
	| {checked: ($s | length),
		violations: [$s | to_entries[] | select(.value | has("uses")) | {n: (.key + 1), ref: .value.uses}
			| select((.ref | type) != "string"
				or (.ref | test("\\A(\\./|(?!docker://)[^@]+@[0-9a-f]{40}\\z|docker://[^@]+@sha256:[0-9a-f]{64}\\z)") | not))
			| "step \(.n): uses \(.ref)"]}'

# check_actions <dir>: the pinning policy over <dir>/*/action.yml and
# action.yaml. Fails when there are none.
check_actions() {
	local dir=$1
	local -a files
	mapfile -t -d '' files < <(find "$dir" -mindepth 2 -maxdepth 2 \
		\( -name action.yml -o -name action.yaml \) -print0 | sort -z)
	((${#files[@]} > 0)) || {
		echo "action-pinned-uses: no action files in $dir"
		return 1
	}
	apply_policy action-pinned-uses "$ACTION_PINNED_USES" "$dir" "${files[@]}"
}

# action_dir <content> [<file name>]: an actions directory holding one
# action with that content, in fixture/action.yml by default.
action_dir() {
	local dir
	dir=$(mktemp -d "$WORK/actions.XXXXXX")
	mkdir -- "$dir/fixture"
	printf '%s\n' "$1" >"$dir/fixture/${2:-action.yml}"
	printf '%s\n' "$dir"
}

# action_copy_with <from> <to>: an actions directory holding a copy of the
# security-floor action.yml with one literal replaced.
action_copy_with() {
	local copy dir
	copy=$(copy_with "$ACTION_YML" "$1" "$2") || return 1
	dir=$(mktemp -d "$WORK/actions.XXXXXX")
	mkdir -- "$dir/security-floor"
	mv -- "$copy" "$dir/security-floor/action.yml"
	printf '%s\n' "$dir"
}

# workflow_dir <content>: a directory holding one workflow with that content.
workflow_dir() {
	local dir
	dir=$(mktemp -d "$WORK/workflows.XXXXXX")
	printf '%s\n' "$1" >"$dir/fixture.yml"
	printf '%s\n' "$dir"
}

# workflow_copy_with <from> <to>: the directory of a self-test.yml copy with
# one literal replaced.
workflow_copy_with() {
	local copy
	copy=$(copy_with "$WORKFLOW_DIR/self-test.yml" "$1" "$2") || return 1
	dirname -- "$copy"
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

# Lockfile check fixtures. A manifest's content does not matter to the check.
pkg_json='{"name": "fixture", "version": "1.0.0"}'
cargo_toml=$(printf '[package]\nname = "fixture"\nversion = "0.1.0"')
pyproject_toml=$(printf '[project]\nname = "fixture"\nversion = "0.1.0"')
osv_workspace_repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" packages/a/package.json "$pkg_json")
osv_lock_in_child_repo=$(files_repo package.json "$pkg_json" sub/package-lock.json "$(clean_npm_lockfile)")
osv_wrong_kind_repo=$(files_repo Cargo.toml "$cargo_toml" package-lock.json "$(clean_npm_lockfile)")
osv_untracked_lock_repo=$(files_repo package.json "$pkg_json")
clean_npm_lockfile >"$osv_untracked_lock_repo/package-lock.json"
osv_lock_only_empty_repo=$(files_repo package-lock.json "")
osv_newline_name_repo=$(files_repo $'dir\n::warning::x/package.json' "$pkg_json")
osv_ignored_sub_repo=$(gitignored_lockfile_repo true)
osv_unignored_sub_repo=$(gitignored_lockfile_repo false)
osv_nested_toml_repo=$(gitignored_lockfile_repo false)
commit_file "$osv_nested_toml_repo" sub/osv-scanner.toml "$(osv_ignore_package_toml lodash)" >/dev/null
osv_go_repo=$(files_repo go.mod "$(go_mod_vulnerable)")
osv_symlink_lock_repo=$(symlinked_lockfile_repo)
osv_symlink_go_mod_repo=$(symlinked_go_mod_repo)
osv_symlink_plain_repo=$(symlinked_plain_files_repo)
osv_command_dir_repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" \
	$'x\n::warning title=injected::y/package-lock.json' '{not json')
osv_count_marker="$WORK/osv-invocations"
osv_gitlink_lock_repo=$(gitlink_lockfile_repo)
osv_zero_package_sibling_repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" \
	sub/package-lock.json "$(zero_package_npm_lockfile)")
osv_node_modules_lock_repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" \
	node_modules/x/package-lock.json "$(vulnerable_npm_lockfile)")
osv_nested_clean_repo=$(files_repo package-lock.json "$(clean_npm_lockfile)" sub/package-lock.json "$(clean_npm_lockfile)")
osv_linked_workspace="$WORK/linked-workspace"
ln -s -- "$osv_nested_clean_repo" "$osv_linked_workspace"
go_marker_flag="$WORK/go-called-with-flag"
go_marker_noflag="$WORK/go-called-without-flag"
fsmon_home=$(fsmonitor_home)

gitleaks_allow_all="$WORK/gitleaks-allow-all.toml"
gitleaks_allow_all_toml >"$gitleaks_allow_all"

secret=$(new_secret)
secret_repo=$(new_repo)
commit_file "$secret_repo" app.env "API_TOKEN=$secret" >/dev/null
secret_head=$(git -C "$secret_repo" rev-parse HEAD)
write_event_push "$push_event" "$clean_head" "$secret_head"

# Scan range fixtures. range_repo: clean root, then the secret, then a clean
# commit on top.
range_repo=$(new_repo)
range_c1=$(commit_file "$range_repo" README.md "fixture repository")
range_c2=$(commit_file "$range_repo" app.env "API_TOKEN=$secret")
range_c3=$(commit_file "$range_repo" notes.txt "later change")
unknown_sha=$(printf '%s' "$secret" | sha1sum | cut -d' ' -f1)
read -r evil_repo evil_before evil_merge < <(evil_merge_repo "$secret")
read -r conflict_repo conflict_before conflict_merge < <(conflict_merge_repo "$secret")
read -r scoped_repo scoped_base scoped_head < <(scoped_pr_repo "$secret")
read -r long_repo long_base long_head < <(long_pr_repo "$secret" 35)
shallow_repo=$(mktemp -d "$WORK/repo.XXXXXX")
git clone -q --depth 1 -- "file://$range_repo" "$shallow_repo"
bad_config_repo=$(new_repo)
commit_file "$bad_config_repo" .gitleaks.toml "[[rules]" >/dev/null
toml_allow_all_repo=$(files_repo .gitleaks.toml "$(gitleaks_allow_all_toml)" app.env "API_TOKEN=$secret")
toml_no_default_repo=$(files_repo .gitleaks.toml $'[extend]\nuseDefault = false' app.env "API_TOKEN=$secret")
toml_custom_rule_repo=$(files_repo .gitleaks.toml "$(gitleaks_custom_rule_toml)" notes.txt "value=FIXTURE_MARKER_12345678")
inline_allow_repo=$(files_repo app.env "API_TOKEN=$secret # gitleaks:allow")
read -r typechange_repo typechange_before typechange_after < <(typechange_repo "$secret")
read -r rename_repo rename_base rename_head < <(rename_pr_repo "$secret")
read -r octopus_repo octopus_before octopus_merge < <(octopus_repo "$secret")
command_path_repo=$(files_repo $'notes\n::warning title=injected::fixture.env' "API_TOKEN=$secret")
nul_repo=$(nul_byte_secret_repo "$secret")
attr_secret_repo=$(attributes_repo "$secret")
attr_clean_repo=$(attributes_repo)
ignored_repo=$(ignored_secret_repo "$secret_repo")
corrupt_repo=$(corrupt_history_repo)
corrupt_head=$(git -C "$corrupt_repo" rev-parse HEAD)
no_diff_home=$(gitconfig_home '* -diff')
textconv_home=$(gitconfig_home '* diff=hide' "$(printf '[diff "hide"]\n\ttextconv = true')")
read -r bang_attr_repo bang_attr_base bang_attr_head < <(bang_attributes_pr_repo "$secret")
read -r preimage_repo preimage_before preimage_after < <(missing_preimage_repo "$secret")
partial_repo=$(partial_clone_repo)
rich_clean=$(rich_clean_repo)
xdg_bang_home=$(xdg_attributes_home '!x text')
replaced_repo=$(replaced_secret_repo "$secret")
textconv_local=$(textconv_local_repo "$secret")
grafted_repo=$(graft_repo "$secret")
backslash_name_repo=$(files_repo "t\\" "API_TOKEN=$secret")
read -r backslash_pr_repo backslash_pr_base backslash_pr_head < <(trailing_backslash_pr_repo "$secret")
backslash_merge_repo=$(quoted_name_merge_repo)
utf8_name=$'caf\xc3\xa9.env'
utf8_secret_repo=$(files_repo "$utf8_name" "API_TOKEN=$secret")
utf8_clean_repo=$(files_repo "$utf8_name" "API_TOKEN=unset")
noisy_repo=$(noisy_attributes_repo)
stall_repo=$(parser_stall_repo)
# shellcheck disable=SC2016 # literal source text
floor_no_path_check=$(floor_copy_with '	refuse_quoted_paths "${log_opts[@]}"' '')
floor_no_path_check_short_timeout=$(copy_with "$floor_no_path_check" \
	'readonly GITLEAKS_TIMEOUT_SECONDS=600' 'readonly GITLEAKS_TIMEOUT_SECONDS=3')
term_marker="$WORK/git-log-started"
# shellcheck disable=SC2016 # literal stub text
slow_git_log_stub='git=case " $* " in *" log -p -U0 "*) : >'"'$term_marker'"'; sleep 60 ;; esac; exec /usr/bin/git "$@"'
# shellcheck disable=SC2016 # literal stub text
old_git_stub='git=[ "$1" = version ] && { echo "git version 2.35.8"; exit 0; }; exec /usr/bin/git "$@"'

# push_event / pr_event <name> <sha> <sha>: write an event file, print its path.
push_event() {
	write_event_push "$WORK/event-$1.json" "$2" "$3"
	printf '%s\n' "$WORK/event-$1.json"
}
pr_event() {
	write_event_pull_request "$WORK/event-$1.json" "$2" "$3"
	printf '%s\n' "$WORK/event-$1.json"
}
ev_push_range=$(push_event push-range "$range_c1" "$range_c3")
ev_push_after_secret=$(push_event push-after-secret "$range_c2" "$range_c3")
ev_first_push=$(push_event first-push "$ZERO" "$secret_head")
ev_force_push=$(push_event force-push "$unknown_sha" "$range_c3")
ev_option_before=$(push_event option-before "--output=$WORK/x" "$range_c3")
ev_delete=$(push_event delete "$range_c3" "$ZERO")
ev_after_missing="$WORK/event-after-missing.json"
jq -n --arg b "$range_c1" '{before: $b}' >"$ev_after_missing"
ev_after_unknown=$(push_event after-unknown "$range_c1" "$unknown_sha")
ev_after_upper=$(push_event after-upper "$range_c1" "${range_c3^^}")
ev_evil=$(push_event evil "$evil_before" "$evil_merge")
ev_conflict=$(push_event conflict "$conflict_before" "$conflict_merge")
ev_corrupt=$(push_event corrupt "$ZERO" "$corrupt_head")
ev_typechange=$(push_event typechange "$typechange_before" "$typechange_after")
ev_octopus=$(push_event octopus "$octopus_before" "$octopus_merge")
ev_pr_rename=$(pr_event pr-rename "$rename_base" "$rename_head")
ev_pr_attributes=$(pr_event pr-attributes "$(git -C "$attr_secret_repo" rev-parse HEAD~1)" \
	"$(git -C "$attr_secret_repo" rev-parse HEAD)")
ev_pr_bang_attr=$(pr_event pr-bang-attr "$bang_attr_base" "$bang_attr_head")
ev_pr_backslash=$(pr_event pr-backslash "$backslash_pr_base" "$backslash_pr_head")
ev_preimage=$(push_event preimage "$preimage_before" "$preimage_after")
ev_pr_long=$(pr_event pr-long "$long_base" "$long_head")
ev_pr_scoped=$(pr_event pr-scoped "$scoped_base" "$scoped_head")
ev_pr_after_secret=$(pr_event pr-after-secret "$range_c2" "$range_c3")
ev_pr_head_newline=$(pr_event pr-head-newline "$range_c2" "$range_c3"$'\n')
ev_pr_missing="$WORK/event-pr-missing.json"
jq -n --arg h "$range_c3" '{pull_request: {head: {sha: $h}}}' >"$ev_pr_missing"

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
expect osv-vulnerable-lockfile-red 1 "FAIL: osv: known vulnerabilities found" -- \
	run_floor "$osv_vuln_repo" osv
expect osv-repo-ignore-toml-still-red 1 "FAIL: osv: known vulnerabilities found" -- \
	run_floor "$osv_vuln_ignore_repo" osv
expect osv-clean-lockfile-with-toml-green 0 "PASS: osv: no known vulnerabilities" -- \
	run_floor "$osv_clean_ignore_repo" osv
expect osv-nested-ignore-toml-still-red 1 "FAIL: osv: known vulnerabilities found" -- \
	run_floor "$osv_nested_toml_repo" osv

# A tracked lockfile is scanned even when .gitignore lists it; the control
# has the same files without the .gitignore.
expect osv-gitignored-tracked-lockfile-red 1 "FAIL: osv: known vulnerabilities found" -- \
	run_floor "$osv_ignored_sub_repo" osv
expect osv-same-lockfile-not-ignored-red 1 "FAIL: osv: known vulnerabilities found" -- \
	run_floor "$osv_unignored_sub_repo" osv

# Exit 128 ("no package sources") passes only when nothing was tracked.
expect osv-no-manifest-notice-green 0 "::notice title=security-floor::no package manifest or lockfile found" \
	--contains "lockfile check: no manifest or lockfile tracked" -- \
	run_floor "$clean_repo" osv
expect osv-empty-lockfile-no-manifest-red 1 "FAIL: osv: lockfile produced no packages" -- \
	run_floor "$osv_lock_only_empty_repo" osv
# The cached binary installs offline; the advisory query then fails.
expect osv-scan-network-error-red 1 "FAIL: osv-scanner error (exit" --absent "PASS:" -- \
	run_floor "$osv_vuln_repo" osv https_proxy="$proxy" HTTPS_PROXY="$proxy"

# Lockfile check: one lockless row per manifest kind, named in the output.
for manifest in Cargo.toml package.json pyproject.toml; do
	case "$manifest" in
	Cargo.toml) content=$cargo_toml ;;
	package.json) content=$pkg_json ;;
	pyproject.toml) content=$pyproject_toml ;;
	esac
	expect "osv-lockless-$manifest-red" 1 "FAIL: lockfile check: 1 manifest(s) without a tracked lockfile" \
		--contains "no tracked lockfile for manifest: svc/$manifest" -- \
		run_floor "$(files_repo "svc/$manifest" "$content")" osv
done
declare_dynamic_rows 2

# One accept row per lockfile name: the manifest plus an empty lockfile of
# that name passes the check, and the empty lockfile then fails the scan.
for pair in Cargo.toml:Cargo.lock package.json:pnpm-lock.yaml package.json:package-lock.json \
	package.json:yarn.lock package.json:bun.lock pyproject.toml:poetry.lock pyproject.toml:uv.lock; do
	manifest=${pair%%:*}
	lockfile=${pair#*:}
	expect "osv-accepts-$lockfile-empty-red" 1 "FAIL: osv: lockfile produced no packages" \
		--contains "security-floor: lockfile check: ok" -- \
		run_floor "$(files_repo "$manifest" "x" "$lockfile" "")" osv
done
declare_dynamic_rows 6

# Every tracked lockfile must be a scanned source with packages. A tracked
# entry osv-scanner cannot read fails the lockfile check by name, before the
# per-lockfile check could also catch it.
expect osv-symlinked-lockfile-red 1 "osv-scanner cannot scan symlink: sub/package-lock.json" \
	--contains "FAIL: lockfile check: 1 dependency file entries osv-scanner cannot scan" -- \
	run_floor "$osv_symlink_lock_repo" osv
# Any tracked symlink at a path osv-scanner would extract, not only the
# lockfile map's names; the control holds symlinks no extractor reads.
expect osv-symlinked-go-mod-red 1 "osv-scanner cannot scan symlink: sub/go.mod" -- \
	run_floor "$osv_symlink_go_mod_repo" osv
expect osv-symlinked-plain-files-green 0 "PASS: osv: no known vulnerabilities" --absent "cannot scan" -- \
	run_floor "$osv_symlink_plain_repo" osv
expect osv-gitlink-lockfile-red 1 "osv-scanner cannot scan submodule entry: sub/package-lock.json" -- \
	run_floor "$osv_gitlink_lock_repo" osv
expect osv-node-modules-lockfile-red 1 \
	"osv-scanner cannot scan lockfile under node_modules/: node_modules/x/package-lock.json" -- \
	run_floor "$osv_node_modules_lock_repo" osv
expect osv-zero-package-sibling-red 1 "FAIL: osv: lockfile produced no packages: 1 tracked lockfile(s)" \
	--contains "lockfile produced no packages: sub/package-lock.json" --absent "package-lock.json, " -- \
	run_floor "$osv_zero_package_sibling_repo" osv
# shellcheck disable=SC2016 # literal source text
expect osv-json-results-missing-red 1 "FAIL: osv-scanner error: JSON results are missing or unreadable" -- \
	run_floor_script "$(floor_copy_with 'osv_scan "$config" "$root" "$json" 2>&1 || rc=$?' \
		'rm -f -- "$json" || rc=$?')" "$osv_repo" osv
# shellcheck disable=SC2016 # literal source text
expect osv-json-results-unreadable-red 1 "FAIL: osv-scanner error: JSON results are missing or unreadable" -- \
	run_floor_script "$(floor_copy_with 'osv_scan "$config" "$root" "$json" 2>&1 || rc=$?' \
		'printf "not json" >"$json" || rc=$?')" "$osv_repo" osv
expect osv-nested-lockfiles-green 0 "PASS: osv: no known vulnerabilities" -- \
	run_floor "$osv_nested_clean_repo" osv
expect osv-workspace-through-symlink-green 0 "PASS: osv: no known vulnerabilities" -- \
	run_floor "$osv_linked_workspace" osv

expect osv-workspace-member-root-lockfile-green 0 "PASS: osv: no known vulnerabilities" \
	--contains "security-floor: lockfile check: ok" -- \
	run_floor "$osv_workspace_repo" osv
expect osv-lockfile-below-manifest-red 1 "no tracked lockfile for manifest: package.json" -- \
	run_floor "$osv_lock_in_child_repo" osv
expect osv-lockfile-of-other-kind-red 1 "no tracked lockfile for manifest: Cargo.toml" -- \
	run_floor "$osv_wrong_kind_repo" osv
expect osv-untracked-lockfile-red 1 "no tracked lockfile for manifest: package.json" -- \
	run_floor "$osv_untracked_lock_repo" osv
# shellcheck disable=SC2016 # literal expected output
expect osv-control-char-path-quoted-red 1 "no tracked lockfile for manifest: \$'dir\\n::warning::x/package.json'" -- \
	run_floor "$osv_newline_name_repo" osv

# The tracked-file listing reads no HOME git config. The control shows the
# fixture's hook runs for a plain git command.
expect home-gitconfig-hook-fixture-runs 0 "fsmonitor-hook-ran" -- \
	env -C "$osv_repo" HOME="$fsmon_home" git ls-files
expect osv-home-gitconfig-hook-not-run-green 0 "PASS: osv: no known vulnerabilities" --absent "fsmonitor-hook-ran" -- \
	run_floor "$osv_repo" osv HOME="$fsmon_home"

# Job summary: the OSV table goes to GITHUB_STEP_SUMMARY.
expect osv-summary-vulnerable-table-red 1 "summary: - result: FAIL, known vulnerabilities found" \
	--contains "| lodash | 4.17.15 |" -- \
	run_floor_summary_only "$osv_vuln_repo" osv
expect osv-summary-clean-green 0 "summary: - result: pass, no known vulnerabilities" \
	--contains "summary: osv-scanner: 1 packages scanned, 0 with known vulnerabilities" --absent "lodash" -- \
	run_floor_summary_only "$osv_repo" osv

# One osv-scanner run gives the verdict, the per-lockfile check and the table.
expect osv-single-invocation-red 1 "osv-scanner invocations: 1" --contains "| lodash | 4.17.15 |" -- \
	run_floor_counting_osv "$osv_count_marker" "$(floor_counting_osv "$osv_count_marker")" "$osv_vuln_repo"

# osv-scanner names a malformed lockfile's path, newline and all, on its
# error line; that reaches the log only inside the command fence. The failed
# extraction makes osv-scanner exit with an error, so the run is red.
expect osv-path-workflow-command-fenced-red 1 "FAIL: osv-scanner error (exit" \
	--contains "fenced, 0 outside the fence" -- \
	run_floor_fenced "$osv_command_dir_repo" osv

# Call analysis stays off: it would run only where `go` is installed and
# drop advisories for code judged uncalled. A `go` stub on the fixed PATH
# records whether osv-scanner probes for it; the control drops the flag.
expect source-osv-flags 0 "osv flags present" -- check_osv_flags "$FLOOR_SH"
expect source-osv-flags-check-catches-missing 1 "lacks --no-call-analysis=all" -- \
	check_osv_flags "$(floor_copy_with ' --no-call-analysis=all' '')"
expect osv-go-on-path-not-invoked-red 1 "FAIL: osv: known vulnerabilities found" --absent "go was invoked" -- \
	run_floor_reporting_go "$go_marker_flag" "$(floor_with_go_stub "$go_marker_flag")" "$osv_go_repo"
expect osv-go-on-path-control-invoked 1 "go was invoked" -- \
	run_floor_reporting_go "$go_marker_noflag" \
	"$(floor_with_go_stub "$go_marker_noflag" ' --no-call-analysis=all' '')" "$osv_go_repo"

# Tools run only by absolute path, even when a trusted PATH entry holds a
# same-named binary; output is redacted.
expect gitleaks-path-shadow-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor_script "$(floor_with_stubs_on_path 'gitleaks=exit 0' 'osv-scanner=exit 0')" \
	"$secret_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$push_event"
expect osv-path-shadow-vulnerable-red 1 "FAIL: osv: known vulnerabilities found" -- \
	run_floor_script "$(floor_with_stubs_on_path 'gitleaks=exit 0' 'osv-scanner=exit 0')" \
	"$osv_vuln_repo" osv
expect gitleaks-secret-redacted 1 "github-pat" --absent "$secret" -- \
	run_floor "$secret_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$push_event"

# Scan range: push.
expect push-range-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_push_range"
expect push-secret-before-before-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_push_after_secret"
expect push-first-push-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_first_push"
expect push-force-fallback-secret-red 1 "summary: - mode: fallback, 'before' is not a commit" -- \
	run_floor_summary "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_force_push"
expect push-force-fallback-leaks-red 1 "summary: - result: FAIL, leaks found" -- \
	run_floor_summary "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_force_push"
expect push-option-shaped-before-fallback-red 1 "mode fallback, 'before' is not a commit" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_option_before"
expect push-branch-delete-notice-green 0 "::notice title=security-floor::push deletes a ref" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_delete"
expect push-after-missing-red 1 "FAIL: push event: 'after' is missing, malformed or not a commit" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_after_missing"
expect push-after-unknown-red 1 "FAIL: push event: 'after' is missing, malformed or not a commit" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_after_unknown"
expect push-after-uppercase-red 1 "FAIL: push event: 'after' is missing, malformed or not a commit" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_after_upper"
expect push-event-file-missing-red 1 "FAIL: push event: 'after' is missing, malformed or not a commit" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$WORK/absent.json"
expect push-evil-merge-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$evil_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_evil"
expect push-conflict-merge-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$conflict_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_conflict"
expect push-range-unresolvable-red 1 "FAIL: scan range does not resolve" -- \
	run_floor "$corrupt_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_corrupt"

# Scan range: pull request.
expect pr-35-commits-secret-in-first-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$long_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_long"
expect pr-merged-base-with-old-secret-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$scoped_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_scoped"
expect pr-merged-base-repo-full-history-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$scoped_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect pr-range-after-secret-green 0 "mode pull request range" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_after_secret"
expect pr-head-malformed-full-history-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_head_newline"
expect pr-base-missing-full-history-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_missing"

# Scan range: other events, preflight, tool errors.
expect schedule-old-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$range_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect no-event-old-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$range_repo" gitleaks
expect shallow-clone-red 1 "FAIL: checkout needs fetch-depth: 0" -- \
	run_floor "$shallow_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect git-too-old-red 1 "FAIL: git 2.36 or newer is required" -- \
	run_floor_script "$(floor_with_stubs_on_path "$old_git_stub")" "$clean_repo" gitleaks

# Nothing the scanned repo supplies changes the verdict: only the built-in
# rules run. The custom-rule control loads the repo config to show its rule
# fires on the fixture.
expect malformed-gitleaks-toml-ignored-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$bad_config_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect repo-toml-allow-all-paths-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$toml_allow_all_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect repo-toml-use-default-false-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$toml_no_default_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect repo-toml-custom-rule-not-loaded-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$toml_custom_rule_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
# shellcheck disable=SC2016 # literal source text
expect repo-toml-custom-rule-control-loaded-red 1 "FAIL: gitleaks: leaks found" --contains "fixture-marker" -- \
	run_floor_script "$(floor_copy_with '--config "$config" --gitleaks-ignore-path' '--gitleaks-ignore-path')" \
	"$toml_custom_rule_repo" gitleaks \
	GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect inline-gitleaks-allow-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$inline_allow_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect gitleaksignore-fingerprint-red 1 "FAIL: repo .gitleaksignore is not honored" -- \
	run_floor "$ignored_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect gitleaksignore-absent-same-history-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"

# Change classes plain `git log -p` hides: a type change, a pure rename, a
# merge seen only by the full-history form, and an octopus merge, which no
# diff option shows and so fails before the scan.
expect push-typechange-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$typechange_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_typechange"
expect schedule-typechange-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$typechange_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect pr-rename-out-of-allowlisted-path-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$rename_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_rename"
expect schedule-evil-merge-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$evil_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect push-octopus-merge-red 1 "FAIL: octopus merge in scan range; not scannable" -- \
	run_floor "$octopus_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_octopus"
expect schedule-octopus-merge-red 1 "FAIL: octopus merge in scan range; not scannable" -- \
	run_floor "$octopus_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"

# A tracked path holding a newline and a workflow command is refused, and
# reaches the log only as git's quoted, single-line form.
expect gitleaks-path-workflow-command-refused-red 1 "FAIL: path git would quote; history is not scannable" \
	--contains '"notes\n::warning title=injected::fixture.env"' --contains "bare workflow commands: 0" -- \
	run_floor_no_bare_commands "$command_path_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"

# Content git would print as "Binary files differ" is still scanned.
expect attributes-no-diff-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$attr_secret_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect nul-byte-file-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$nul_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect pr-attributes-no-diff-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$attr_secret_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_attributes"
expect attributes-no-diff-clean-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$attr_clean_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect home-gitconfig-no-diff-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks HOME="$no_diff_home"
expect home-gitconfig-textconv-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks HOME="$textconv_home"
expect home-gitconfig-textconv-clean-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$clean_repo" gitleaks HOME="$textconv_home"

# gitleaks stops at the first git stderr line and still exits 0, so the same
# git log runs first and any stderr fails the scan. The clean row shows a
# healthy history with merges and renames prints none.
expect pr-bang-attributes-stderr-red 1 "FAIL: git log reported errors or warnings" \
	--contains "security-floor: git: warning: Negative patterns are ignored" -- \
	run_floor "$bang_attr_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_bang_attr"
expect push-missing-preimage-blob-red 1 "FAIL: git log reported errors or warnings" \
	--contains "security-floor: git: fatal: unable to read" -- \
	run_floor "$preimage_repo" gitleaks GITHUB_EVENT_NAME=push GITHUB_EVENT_PATH="$ev_preimage"
expect schedule-graft-hint-red 1 "FAIL: git log reported errors or warnings" \
	--contains "grafts is deprecated" -- \
	run_floor "$grafted_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect git-log-preflight-clean-history-green 0 "PASS: gitleaks: no leaks found" --absent "git log reported" -- \
	run_floor "$rich_clean" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
# gitleaks's diff parser stops, with nothing on git stderr, at a name git
# quotes, so any quoted name in the walk fails the scan. UTF-8 names are not
# quoted (core.quotePath=false) and scan normally.
expect schedule-backslash-name-secret-red 1 'FAIL: path git would quote; history is not scannable: "t\\"' -- \
	run_floor "$backslash_name_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect pr-backslash-name-hides-older-secret-red 1 "FAIL: path git would quote; history is not scannable" -- \
	run_floor "$backslash_pr_repo" gitleaks GITHUB_EVENT_NAME=pull_request GITHUB_EVENT_PATH="$ev_pr_backslash"
expect schedule-backslash-name-in-merge-resolution-red 1 "FAIL: path git would quote; history is not scannable" -- \
	run_floor "$backslash_merge_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect schedule-utf8-name-secret-red 1 "FAIL: gitleaks: leaks found" --absent "path git would quote" -- \
	run_floor "$utf8_secret_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect schedule-utf8-name-clean-green 0 "PASS: gitleaks: no leaks found" -- \
	run_floor "$utf8_clean_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
# Should the parser stall anyway, gitleaks's own timeout ends the scan red
# (exit 1, "partial scan") rather than hanging the job. The path check is
# removed from this copy so the stall can happen at all.
expect schedule-parser-stall-times-out-red 1 "FAIL: gitleaks error (exit 1)" --contains "partial scan" -- \
	run_floor_script_bounded 60 "$floor_no_path_check_short_timeout" "$stall_repo" gitleaks \
	GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect schedule-oversized-git-stderr-bounded-red 1 "FAIL: git log reported errors or warnings" \
	--contains "git stderr kept: 65536 bytes (limit 65536)" -- \
	run_floor "$noisy_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect partial-clone-red 1 "FAIL: checkout is missing 2 objects in the scan range (a partial clone" -- \
	run_floor "$partial_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"

# Repo-local and per-user git state that hides content without printing
# anything: git's default attributes file under HOME, a replace ref, and a
# textconv driver in .git/config.
expect home-xdg-attributes-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$secret_repo" gitleaks HOME="$xdg_bang_home"
expect replace-ref-hidden-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$replaced_repo" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"
expect local-textconv-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor "$textconv_local" gitleaks GITHUB_EVENT_NAME=schedule GITHUB_EVENT_PATH="$other_event"

# A run cancelled inside the command fence still resumes workflow commands.
expect sigterm-in-fence-resumes-once 143 "fence: 1 stop, 1 resume" -- \
	run_floor_term_in_fence "$(floor_with_stubs_on_path "$slow_git_log_stub")" "$clean_repo" "$term_marker"

# The scan trusts the workspace through its own safe.directory, not a HOME
# config. git's test knob models a checkout owned by another user; the
# control points safe.directory elsewhere and must be refused.
# shellcheck disable=SC2016 # literal source text
expect foreign-owner-workspace-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_floor_script "$(floor_copy_with '"GIT_CONFIG_VALUE_0=$workspace"' \
		'GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "GIT_CONFIG_VALUE_0=$workspace"')" "$secret_repo" gitleaks
# shellcheck disable=SC2016 # literal source text
expect foreign-owner-untrusted-path-red 1 "FAIL: not a usable git checkout" -- \
	run_floor_script "$(floor_copy_with '"GIT_CONFIG_VALUE_0=$workspace"' \
		'GIT_TEST_ASSUME_DIFFERENT_OWNER=1 "GIT_CONFIG_VALUE_0=$workspace/elsewhere"')" "$secret_repo" gitleaks

# action.yml: the composite wiring, read through yq. Each check has a
# control on a copy with one literal changed.
expect source-action-no-inputs-outputs 0 "no inputs or outputs" -- check_action_interface "$ACTION_YML"
expect source-action-inputs-check-catches-input 1 "action declares: inputs" -- \
	check_action_interface "$(copy_with "$ACTION_YML" 'runs:' $'inputs: {x: {description: x}}\nruns:')"
expect source-action-outputs-check-catches-output 1 "action declares: outputs" -- \
	check_action_interface "$(copy_with "$ACTION_YML" 'runs:' $'outputs: {x: {description: x, value: x}}\nruns:')"
expect source-action-run-lines 0 "two run lines: gitleaks, osv" -- check_action_run_lines "$ACTION_YML"
expect source-action-run-lines-check-catches-subcommand 1 "unexpected run lines" -- \
	check_action_run_lines "$(copy_with "$ACTION_YML" 'floor.sh" osv' 'floor.sh" gitleaks')"
expect source-action-privileged-bash 0 "every run uses /bin/bash -p" -- check_action_privileged_bash "$ACTION_YML"
# shellcheck disable=SC2016 # literal source text
expect source-action-privileged-check-catches-plain-bash 1 "run without /bin/bash -p in step: osv" -- \
	check_action_privileged_bash "$(copy_with "$ACTION_YML" 'run: /bin/bash -p "$GITHUB_ACTION_PATH/floor.sh" osv' \
		'run: /bin/bash "$GITHUB_ACTION_PATH/floor.sh" osv')"
expect source-action-osv-not-cancelled 0 "osv runs unless cancelled" -- check_action_osv_condition "$ACTION_YML"
# shellcheck disable=SC2016 # literal source text
expect source-action-condition-check-catches-missing-if 1 "osv step condition is ''" -- \
	check_action_osv_condition "$(copy_with "$ACTION_YML" '      if: ${{ !cancelled() }}' '')"
expect source-action-no-run-expressions 0 "no expressions in run" -- check_action_no_run_expressions "$ACTION_YML"
# shellcheck disable=SC2016 # literal source text
expect source-action-expression-check-catches-github-context 1 "expression in run of step: gitleaks" -- \
	check_action_no_run_expressions "$(copy_with "$ACTION_YML" '"$GITHUB_ACTION_PATH/floor.sh" gitleaks' \
		'"${{ github.action_path }}/floor.sh" gitleaks')"

# The action's own run lines, executed from the scanned repo: floor.sh is
# reached by absolute path under bash -p and re-executes itself from $0.
expect action-step-gitleaks-clean-green 0 "PASS: gitleaks: no leaks found" -- \
	run_action_step "$ACTION_YML" gitleaks "$clean_repo"
expect action-step-gitleaks-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_action_step "$ACTION_YML" gitleaks "$secret_repo"
expect action-step-osv-clean-green 0 "PASS: osv: no known vulnerabilities" -- \
	run_action_step "$ACTION_YML" osv "$osv_repo"
expect action-step-osv-vulnerable-red 1 "FAIL: osv: known vulnerabilities found" -- \
	run_action_step "$ACTION_YML" osv "$osv_vuln_repo"

# An exported chmod function would swap the verified gitleaks for a stub.
# The control shows plain bash imports it and the stub then runs. Under the
# action's bash -p it is never imported; without -p, floor.sh's own re-exec
# and environment check still reject it, so no green is asserted for that.
expect bash-func-chmod-fixture-imported-drops-stub 0 "8.30.1" -- imported_chmod_drops_fake_gitleaks
expect action-step-bash-func-chmod-secret-red 1 "FAIL: gitleaks: leaks found" -- \
	run_action_step "$ACTION_YML" gitleaks "$secret_repo" RUNNER_TEMP="$(fresh_runner_temp)" \
	"BASH_FUNC_chmod%%=$CHMOD_DROPS_FAKE_GITLEAKS"

# Source text: pins are literals, never read from the environment.
expect source-pins-literal 0 "pins are literal" -- check_pins_literal "$FLOOR_SH"
# shellcheck disable=SC2016 # literal stub/source text
expect source-pins-check-catches-env-default 1 "default expansion" -- \
	check_pins_literal "$(floor_copy_with 'GITLEAKS_VERSION="8.30.1"' 'GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"')"

# Pre-commit: the id hook over every fixture line, one row per line. The
# fixture-size rows fail the run when a list is empty.
expect id-hook-accept-fixture-nonempty 0 "lines" -- fixture_lines "$ID_HOOK_ACCEPT"
expect id-hook-reject-fixture-nonempty 0 "lines" -- fixture_lines "$ID_HOOK_REJECT"
id_hook_out="$WORK/id-hook.out"
id_hook_run "$PRECOMMIT_CONFIG" "$id_hook_out"
accept_lines=$(grep -c '' "$ID_HOOK_ACCEPT" || true)
reject_lines=$(grep -c '' "$ID_HOOK_REJECT" || true)
for kind in accept reject; do
	if [[ "$kind" == accept ]]; then
		count=$accept_lines verdict=quiet
	else
		count=$reject_lines verdict=reported
	fi
	for ((n = 1; n <= count; n++)); do
		expect "id-hook-$kind-line-$n" 0 "$kind-$n.txt: $verdict" -- \
			id_hook_verdict "$id_hook_out" "$kind-$n.txt" "$verdict"
	done
done
declare_dynamic_rows "$((accept_lines + reject_lines - 1))"

expect precommit-gitleaks-rev-parity 0 "gitleaks rev parity: 8.30.1" -- \
	check_gitleaks_rev_parity "$PRECOMMIT_CONFIG" "$FLOOR_SH"
expect precommit-gitleaks-rev-parity-catches-drift 1 "gitleaks rev mismatch: hook 'v8.30.0', floor.sh '8.30.1'" -- \
	check_gitleaks_rev_parity "$(copy_with "$PRECOMMIT_CONFIG" 'rev: v8.30.1' 'rev: v8.30.0')" "$FLOOR_SH"

# Workflow policy over .github/workflows/, read through yq. Each policy has a
# control on a self-test.yml copy or a small fixture that breaks it.
readonly WF_JOB='jobs: {j: {runs-on: ubuntu-24.04, timeout-minutes: 1, steps: [{run: "true"}]}}'
readonly WF_SHA=3d3c42e5aac5ba805825da76410c181273ba90b1
expect workflow-no-pull-request-target 0 "pull-request-target: ok" -- \
	check_workflows pull-request-target "$WORKFLOW_DIR"
expect workflow-pull-request-target-check-catches-trigger 1 "self-test.yml: trigger pull_request_target" -- \
	check_workflows pull-request-target "$(workflow_copy_with '  workflow_dispatch:' $'  workflow_dispatch:\n  pull_request_target:')"
expect workflow-pull-request-target-check-catches-list-form 1 "fixture.yml: trigger pull_request_target" -- \
	check_workflows pull-request-target "$(workflow_dir "on: [push, pull_request_target]"$'\n'"$WF_JOB")"
expect workflow-pull-request-target-check-ignores-comment 0 "pull-request-target: ok, 1 checked" -- \
	check_workflows pull-request-target "$(workflow_dir "on: push # not pull_request_target"$'\n'"$WF_JOB")"
expect workflow-no-secrets-inherit 0 "secrets-inherit: ok" -- \
	check_workflows secrets-inherit "$WORKFLOW_DIR"
expect workflow-secrets-inherit-check-catches-inherit 1 "fixture.yml: job call: secrets: inherit" -- \
	check_workflows secrets-inherit "$(workflow_dir "on: push
jobs: {call: {uses: \"o/r/.github/workflows/w.yml@$WF_SHA\", secrets: inherit}}")"
expect workflow-every-job-has-timeout 0 "timeout: ok" -- \
	check_workflows timeout "$WORKFLOW_DIR"
expect workflow-timeout-check-catches-missing 1 "self-test.yml: job action: no timeout-minutes" -- \
	check_workflows timeout "$(workflow_copy_with '    timeout-minutes: 10' '')"
expect workflow-uses-pinned 0 "pinned-uses: ok" -- \
	check_workflows pinned-uses "$WORKFLOW_DIR"
expect workflow-pinned-check-catches-tag 1 "self-test.yml: job checks: uses actions/setup-python@v6" -- \
	check_workflows pinned-uses "$(workflow_copy_with '      - name: Install pre-commit' \
		$'      - uses: actions/setup-python@v6\n      - name: Install pre-commit')"
expect workflow-pinned-check-catches-short-sha 1 "fixture.yml: job j: uses actions/checkout@${WF_SHA:0:12}" -- \
	check_workflows pinned-uses "$(workflow_dir "on: push
jobs: {j: {runs-on: x, timeout-minutes: 1, steps: [{uses: \"actions/checkout@${WF_SHA:0:12}\"}]}}")"
expect workflow-pinned-check-catches-sha-in-comment 1 "fixture.yml: job j: uses actions/checkout@v7" -- \
	check_workflows pinned-uses "$(workflow_dir "on: push
jobs:
  j:
    runs-on: x
    timeout-minutes: 1
    steps:
      - uses: actions/checkout@v7 # @$WF_SHA")"
expect workflow-pinned-check-catches-aliased-step 1 "fixture.yml: job j: uses actions/checkout@v7" -- \
	check_workflows pinned-uses "$(workflow_dir "on: push
x-step: &step {uses: actions/checkout@v7}
jobs: {j: {runs-on: x, timeout-minutes: 1, steps: [*step]}}")"
expect workflow-pinned-check-catches-reusable-call 1 "fixture.yml: job call: uses o/r/.github/workflows/w.yml@main" -- \
	check_workflows pinned-uses "$(workflow_dir "on: push
jobs: {call: {uses: o/r/.github/workflows/w.yml@main}}")"
expect workflow-pinned-check-catches-docker 1 "fixture.yml: job j: uses docker://alpine:3" -- \
	check_workflows pinned-uses "$(workflow_dir "on: push
jobs: {j: {runs-on: x, timeout-minutes: 1, steps: [{uses: \"docker://alpine:3\"}]}}")"
expect workflow-check-fails-unparseable 1 "timeout: cannot check fixture.yml" -- \
	check_workflows timeout "$(workflow_dir $'on: push\njobs: [unclosed')"
expect workflow-check-fails-empty-dir 1 "timeout: no workflow files" -- \
	check_workflows timeout "$(mktemp -d "$WORK/workflows.XXXXXX")"

expect workflow-pull-request-target-check-catches-scalar-form 1 "fixture.yml: trigger pull_request_target" -- \
	check_workflows pull-request-target "$(workflow_dir "on: pull_request_target"$'\n'"$WF_JOB")"

# The same pinning policy over composite actions under actions/.
readonly ACTION_RUNS='runs:
  using: composite
  steps:'
expect action-uses-pinned 0 "action-pinned-uses: ok" -- check_actions "$ACTIONS_DIR"
expect action-pinned-check-accepts-sha-local-and-digest 0 "action-pinned-uses: ok, 4 checked in 1 files" -- \
	check_actions "$(action_dir "$ACTION_RUNS
    - uses: actions/checkout@$WF_SHA
    - uses: ./local
    - uses: docker://alpine@sha256:$ZERO${ZERO:0:24}
    - {run: \"true\", shell: bash}")"
expect action-pinned-check-catches-tag 1 "security-floor/action.yml: step 2: uses owner/x@v1" -- \
	check_actions "$(action_copy_with '    - id: osv' $'    - uses: owner/x@v1\n    - id: osv')"
expect action-pinned-check-catches-short-sha 1 "fixture/action.yml: step 1: uses actions/checkout@${WF_SHA:0:12}" -- \
	check_actions "$(action_dir "$ACTION_RUNS
    - uses: actions/checkout@${WF_SHA:0:12}")"
expect action-pinned-check-catches-aliased-step 1 "fixture/action.yml: step 1: uses actions/checkout@v7" -- \
	check_actions "$(action_dir "x-step: &step {uses: actions/checkout@v7}
$ACTION_RUNS
    - *step")"
expect action-pinned-check-catches-docker-tag 1 "fixture/action.yml: step 1: uses docker://alpine:3" -- \
	check_actions "$(action_dir "$ACTION_RUNS
    - uses: docker://alpine:3")"
expect action-pinned-check-catches-docker-commit-sha 1 "fixture/action.yml: step 1: uses docker://alpine@$WF_SHA" -- \
	check_actions "$(action_dir "$ACTION_RUNS
    - uses: docker://alpine@$WF_SHA")"
expect action-check-fails-unparseable 1 "action-pinned-uses: cannot check fixture/action.yml" -- \
	check_actions "$(action_dir $'runs:\n  steps: [unclosed')"
expect action-check-fails-without-runs 1 "action-pinned-uses: cannot check fixture/action.yml" -- \
	check_actions "$(action_dir 'name: no runs')"
expect action-check-fails-empty-dir 1 "action-pinned-uses: no action files" -- \
	check_actions "$(mktemp -d "$WORK/actions.XXXXXX")"
expect action-check-finds-action-yaml 1 "fixture/action.yaml: step 1: uses owner/x@v1" -- \
	check_actions "$(action_dir "$ACTION_RUNS
    - uses: owner/x@v1" action.yaml)"

reconcile
