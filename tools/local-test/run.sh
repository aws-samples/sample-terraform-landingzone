#!/usr/bin/env bash
# Build and run the offline test container for the Terraform Landing Zone.
#
# Runs the offline check chain (make all: fmt / validate / lint / scan / test)
# inside a container with a pinned toolchain. No AWS is reached and no
# credentials are mounted — this is the offline mirror of the check chain, not
# a substitute for the live suite under tests/live/.
#
# Usage (from anywhere; the script locates the repository root itself):
#   tools/local-test/run.sh                 # runs `make all` in the container
#   tools/local-test/run.sh make test       # runs a specific target
#   TLZ_CONTAINER_ENGINE=finch tools/local-test/run.sh   # use Finch
#
# The container runtime defaults to docker; set TLZ_CONTAINER_ENGINE=finch to
# use Finch instead. The image and the check chain are identical between them.

set -euo pipefail

ENGINE="${TLZ_CONTAINER_ENGINE:-docker}"
IMAGE="tlz-offline-test"

# Repository root = two levels up from this script (tools/local-test/).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." &>/dev/null && pwd)"

if ! command -v "${ENGINE}" >/dev/null 2>&1; then
  echo "ERROR: container engine '${ENGINE}' not found on PATH." >&2
  echo "Install Docker (native Linux) or set TLZ_CONTAINER_ENGINE=finch." >&2
  exit 1
fi

echo "=== Building ${IMAGE} with ${ENGINE} ==="
"${ENGINE}" build \
  -f "${REPO_ROOT}/tools/local-test/Containerfile" \
  -t "${IMAGE}" \
  "${REPO_ROOT}"

# Run the check chain. The working tree is mounted read-write so `make`
# can create .terraform/ init artifacts, but:
#   --network none  — the container cannot reach AWS or anything else.
#   no credential mounts — ~/.aws is never passed in.
#   --user <host uid:gid> — everything the chain writes into the mounted tree
#     (.terraform/, __pycache__/, .pytest_cache/, lock-file updates) is owned
#     by the invoking user, not by root. Without this, a host without root
#     access is left with files in its own checkout that it cannot remove.
#     HOME is pointed at a writable scratch path because that uid has no home
#     inside the image; the pre-fetched providers and tflint ruleset live under
#     /opt/tlz and are found through the environment baked into the image.
# The default command is `make all`; any arguments override it.
echo "=== Running offline check chain in ${IMAGE} (network: none) ==="
if [ "$#" -eq 0 ]; then
  set -- make all
fi
"${ENGINE}" run --rm \
  --network none \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "${REPO_ROOT}:/workspace" \
  -w /workspace \
  "${IMAGE}" \
  "$@"
