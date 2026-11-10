#!/usr/bin/env bash
# tools/state-clone-guard.sh - bind a local state directory to ONE clone.
#
#   tools/state-clone-guard.sh <state_dir> <repo_root> <state_backend>
#
# Called by stacks/root.hcl through run_cmd() while the configuration is
# parsed, so it runs before any backend is initialised -- on plan, apply and
# render alike. Two clones of this repository that share one local state
# directory (the per-user default ~/.tlz-state, or one TLZ_STATE_DIR exported
# for both) read and write the SAME per-unit state files; this script is the
# half of the guard that leaves a record, root.hcl is the half that refuses.
#
# With state_backend = "local" and a usable (absolute) directory:
#   * no marker yet  -> write <state_dir>/.tlz-clone carrying <repo_root>,
#                       the clone's absolute repository path (get_repo_root()),
#                       creating the directory if needed;
#   * marker present -> leave it exactly as it is.
#   Either way the ONE line printed is the path the marker holds. root.hcl
#   compares it with its own get_repo_root() and refuses on a difference,
#   naming both clones and the two remedies.
# With any other backend: print nothing, touch nothing, exit 0. Terragrunt
# evaluates both branches of a ternary (root.hcl), so the backend check has to
# live HERE -- a run_cmd wrapped in a ternary would still execute.
# With a directory that is not usable (relative, or "/.tlz-state" from an unset
# HOME): print nothing, touch nothing, exit 0 -- root.hcl's _state_dir_guard
# carries that refusal, and a mkdir of a relative path here would land in the
# .terragrunt-cache generation the guard exists to keep state out of.
#
# No network, no AWS, idempotent. The write is first-writer-wins (noclobber):
# two units of one `run --all` parsed in parallel cannot leave a half-written
# marker, and two clones racing for a fresh directory leave exactly one owner.
# Exit 0 in every case above; a non-zero exit (unwritable or unreadable
# directory, or a marker path holding something other than a regular file --
# a directory, a FIFO, a symlink) surfaces as a run_cmd error with this
# script's message.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "state-clone-guard.sh: expected <state_dir> <repo_root> <state_backend>, got $# argument(s)" >&2
  exit 2
fi
state_dir="$1"
repo_root="$2"
backend="$3"

[ "$backend" = "local" ] || exit 0
case "$state_dir" in
  /.tlz-state | "" ) exit 0 ;;
  /*) ;;
  *) exit 0 ;;
esac
if [ -z "$repo_root" ] || [ "${repo_root#/}" = "$repo_root" ]; then
  echo "state-clone-guard.sh: the repository root must be an absolute path, got '$repo_root'" >&2
  exit 2
fi

marker="$state_dir/.tlz-clone"
if [ ! -e "$marker" ]; then
  mkdir -p "$state_dir"
  # noclobber: `>` fails instead of overwriting when another writer got here
  # first; that writer's path is then read back below like any other marker.
  ( set -C; printf '%s\n' "$repo_root" > "$marker" ) 2>/dev/null || true
fi
# Only a plain file is a marker: a FIFO would block the read below forever,
# a directory would fail it; a symlink could point anywhere.
if [ -L "$marker" ] || [ ! -f "$marker" ]; then
  echo "state-clone-guard.sh: $marker exists but is not a regular file (refusing: a state directory marker must be a plain file written by this guard; remove it if the old clone is gone)" >&2
  exit 2
fi
if [ ! -r "$marker" ]; then
  echo "state-clone-guard.sh: $marker exists but cannot be read" >&2
  exit 2
fi
IFS= read -r recorded < "$marker" || true
printf '%s\n' "$recorded"
