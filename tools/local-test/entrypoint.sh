#!/usr/bin/env bash
# Entrypoint for the offline test container.
#
# The working tree is mounted from the host and is owned by the host uid, not
# by root inside the container. Git refuses operations on a tree it considers
# "dubious ownership", which breaks the guards that enumerate tracked files
# (test_live_isolation_guard, test_quality_audit_exposure_guard) via `git`.
# Marking the mount as a safe directory restores them without weakening any
# check. This runs offline (no network, no AWS) like everything else here.
set -euo pipefail

git config --global --add safe.directory /workspace 2>/dev/null || true

exec "$@"
