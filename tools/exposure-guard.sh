#!/bin/sh
# tools/exposure-guard.sh - refuse AWS account ids and organization ids in tracked text.
#
#   tools/exposure-guard.sh            every tracked file, working tree (hand-run audit)
#   tools/exposure-guard.sh --staged   the staged content of the staged files (pre-commit)
#
# Exit 0 clean, 1 a finding (one line each: path:line: kind), 2 the guard could not
# measure (no repository, git grep failed, not one tracked file) - never silently green.
# Two rules:
#   FORM, not file name. An account id is a run of EXACTLY 12 digits bounded by
#     non-digits; the word around the run decides, never the file. The run alone is an
#     id unless it is a placeholder. A run glued to letters (abc123456789012) is an id
#     too, unless the word is a hex digest of 32 or more characters (a
#     .terraform.lock.hcl zh: hash, an OIDC thumbprint, a SHA256SUMS line). That
#     exception is load-bearing for lock-file hashes whose only exactly-12 digit run
#     sits between hex letters; check it with
#       git log --all -p -- '*.terraform.lock.hcl' | grep -oE 'zh:[0-9a-f]{64}' | sort -u
#     and count the hashes with a run of EXACTLY 12 digits, not 12 or more: only those
#     are this exception's business.
#     A run of 13 or more digits is no id: a millisecond timestamp
#     in tasks.meta.json, a 17-digit ami-/vpc- fixture, a longer run inside a hash.
#     A base64 h1: hash needs no rule. No file is skipped by name, so
#     an id planted in a lock file or tasks.meta.json is found there too. Blind spots,
#     named: an id glued to a DIGIT is a 13-digit run, an id inside a 32+ character hex
#     word is a digest - neither can be told from a timestamp or a hash by form. The
#     organization form keeps its non-alphanumeric left boundary: without it, words
#     such as auto-remediation or to-organization read as o- ids. Binary files are
#     skipped (git grep -I).
#   VALUES, not files, are exempt: the documented placeholders in the awk block below
#     (READMEs, tftest mocks, the 99990000NN masks of the versioned audit record, the
#     org mocks). A new placeholder goes there; a real value never - the guard would
#     stop seeing it. The output names path and line, never the id, so it is safe to
#     paste anywhere. `git commit --no-verify` bypasses the hook; this script cannot know.
set -uf
cd "$(git rev-parse --show-toplevel)" || exit 2
mode=tracked; cached=
if [ "${1-}" = "--staged" ]; then
  mode=staged; cached=--cached
  files=$(git diff --cached --name-only --diff-filter=ACMR -z | tr '\0' '\n')
  [ -n "$files" ] || { echo "exposure-guard: OK - nothing staged, 0 files checked"; exit 0; }
else
  files=$(git ls-files -z | tr '\0' '\n')
  [ -n "$files" ] || { echo "exposure-guard: ERROR - no tracked file, nothing measured" >&2; exit 2; }
fi
n=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
hits=$(mktemp) || exit 2; trap 'rm -f "$hits"' EXIT
IFS='
'
# cheap over-inclusive prefilter; the exact bounded form and the placeholder list are in awk
# Pathname expansion off for the two unquoted lists below (semgrep
# unquoted-variable-expansion-in-command): IFS splits them on newlines, but a
# tracked name carrying a glob character would still expand against the working
# directory and could hand git grep a path nobody tracked. Same idiom, and the
# same reason, as tools/live/apply_tiers.sh.
set -f
git grep -n -I -E -e '[0-9]{12}' -e 'o-[a-z0-9]{10}' $cached -- $files >"$hits"; rc=$?
set +f
case $rc in 0|1) ;; *) echo "exposure-guard: ERROR - git grep exit $rc, nothing measured" >&2; exit 2;; esac
awk -F: -v mode="$mode" -v n="$n" '
BEGIN { split("123456789012 210987654321 987654321098 001122334455 111100002222 111122223333" \
  " 232323232323 444455556666 555566667777 666677778888 909090909090 o-xxxxxxxxxx o-maskedorg01" \
  " o-abc123def4 o-abcd1234567 o-abcde12345 o-mockorgid12 o-fakeorg000 o-fabricated0", p, " ")
  for (i in p) allow[p[i]] }
function placeholder(t) { return (t in allow) || t ~ /^(0+|1+|2+|3+|4+|5+|6+|7+|8+|9+)$/ || t ~ /^99990000(000[1-9]|0010)$/ }
# re is a STRING: an awk regex literal passed as argument is evaluated as $0 ~ /re/ first
function scan(s, re, kind,   t) { while (match(s, re) && RLENGTH > 1) {
    t = substr(s, RSTART, RLENGTH); gsub(/^[^[:alnum:]]|[^[:alnum:]]$/, "", t)
    if (!placeholder(t)) { print path ":" line ": " kind; found++ }
    s = substr(s, RSTART + RLENGTH - 1) } }     # keep the closing boundary for the next token
# the alphanumeric word of s around the characters a..b
function word(s, a, b) { while (a > 1 && substr(s, a - 1, 1) ~ /[[:alnum:]]/) a--
  while (b < length(s) && substr(s, b + 1, 1) ~ /[[:alnum:]]/) b++
  return substr(s, a, b - a + 1) }
# the account form: exactly 12 digits, bounded by non-digits; the word around the run
# decides (see FORM above). off = characters of s0 already cut away in front of s.
function scan12(s0,   s, off, a, t, w) { s = s0; off = 0
  while (match(s, "(^|[^0-9])[0-9]{12}([^0-9]|$)") && RLENGTH > 1) {
    a = off + RSTART + ((substr(s, RSTART, 1) ~ /[0-9]/) ? 0 : 1)   # first digit, in s0
    t = substr(s0, a, 12); w = word(s0, a, a + 11)
    if (!placeholder(t) && w !~ /^([0-9a-f]{32,}|[0-9A-F]{32,})$/) {
      print path ":" line ": 12-digit account id" (w == t ? "" : " glued to letters") ", not a documented placeholder"
      found++ }
    off += RSTART + RLENGTH - 2; s = substr(s, RSTART + RLENGTH - 1) } }   # keep the closing boundary
{ path = $1; line = $2; s = substr($0, length(path) + length(line) + 3)
  scan12(s)
  scan(s, "(^|[^[:alnum:]])o-[a-z0-9]{10,32}([^[:alnum:]]|$)", "organization id o-..., not a documented placeholder") }
END { what = (mode == "staged") ? "staged file(s)" : "tracked file(s)"
  if (found) { printf "exposure-guard: REFUSED - %d finding(s) in %d %s; redact the value" \
    " (a documented placeholder such as 123456789012 or o-xxxxxxxxxx passes)\n", found, n, what; exit 1 }
  printf "exposure-guard: OK - %d %s checked, no account or organization id outside the placeholder list\n", n, what }
' "$hits"
