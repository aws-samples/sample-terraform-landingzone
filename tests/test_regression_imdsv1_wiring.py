"""regression: the operator's IMDSv1 acknowledgement reaches modules/ec2-compute in every stack.

Without the wiring, every stack that owns modules/ec2-compute hands the module
its default ``[]`` for ``imdsv1_acknowledged_launch_templates`` -- correct in
the module, green in every gate, reachable by nobody. This pins the PROPERTY,
not the one case:

  for EVERY stack that owns modules/ec2-compute, a value an operator sets in
  env/common.hcl arrives at the module as that stack's input, and every
  acknowledgement key the operator is offered arrives at some stack.

How it is measured, so that a legitimate rewrite stays green:

* The stacks are DERIVED from the tree: every ``stacks/**/terragrunt.hcl``
  that names ``modules/ec2-compute``, confirmed by what ``terragrunt render``
  reports as the unit's ``terraform.source``. Nothing is listed by hand.
* The operator's keys are DERIVED from env/common.hcl.example -- the file an
  operator copies -- as every assignment named ``*imdsv1_acknowledged_launch_templates``.
* Each key gets its own sentinel list, every ``enable_*`` flag is switched on,
  and each derived stack is rendered by Terragrunt itself. The rendered input
  must equal exactly one sentinel. No stack or loader text is matched, so key
  order, another default, ``try``/``lookup`` spellings or an additional stack
  do not matter; what matters is what Terragrunt hands the module.

The render runs in a staged copy of the tracked tree under ``tmp_path`` with a
stand-in ``aws`` first on PATH that answers ParameterNotFound (the one
legitimate empty answer of the cross-account SSM lookup), so nothing reaches
AWS and no credentials are needed. Without ``terragrunt`` on PATH the test
skips and says so: the CI ``test`` job installs terragrunt itself before it
runs ``make test``, so the pin runs there; it skips only where terragrunt is
absent, for example a bare developer shell.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt/bash with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MODULE = "modules/ec2-compute"
MODULE_INPUT = "imdsv1_acknowledged_launch_templates"
KEY_RE = re.compile(r"^(\s*)(\w*" + MODULE_INPUT + r")\s*=.*$", re.MULTILINE)
ENABLE_RE = re.compile(r"^(\s*enable_\w+\s*=\s*)false\b", re.MULTILINE)
OWNS_RE = re.compile(r"modules/+ec2-compute\b")

# Answers every call the way SSM answers for a parameter that does not exist
# yet; stacks/*/cross_account.hcl classifies that as "no account", never as
# an error, and nothing leaves the host.
STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the IMDSv1 wiring pin renders the stacks with it",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _operator_keys(example_text):
    keys = sorted({m.group(2) for m in KEY_RE.finditer(example_text)})
    assert keys, (
        "env/common.hcl.example offers no *%s key: an operator has nothing to set" % MODULE_INPUT
    )
    return keys


def _sentinel(key):
    return ["pin-" + key.replace("_", "-")]


def _stage(tmp_path):
    """Copy the tracked tree, write the operator's configuration, fence off AWS."""
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue  # a tracked path deleted in the working tree
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    example = (root / "env/common.hcl.example").read_text()
    keys = _operator_keys(example)
    for line in (m.group(0) for m in KEY_RE.finditer(example)):
        assert line.count("[") == line.count("]"), (
            "multi-line assignment in env/common.hcl.example, this pin writes one-line lists: " + line
        )
    common = KEY_RE.sub(
        lambda m: "%s%s = %s" % (m.group(1), m.group(2), json.dumps(_sentinel(m.group(2)))),
        example,
    )
    common = ENABLE_RE.sub(r"\1true", common)
    (root / "env/common.hcl").write_text(common)
    shutil.copy2(root / "env/accounts.hcl.example", root / "env/accounts.hcl")

    subprocess.run(["git", "init", "-q", str(root)], check=True)  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text(STANDIN_AWS)
    aws.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = "%s%s%s" % (bin_dir, os.pathsep, env.get("PATH", ""))
    env["TLZ_STATE_DIR"] = str(tmp_path / "state")
    env["TG_NON_INTERACTIVE"] = "true"
    env["TG_NO_COLOR"] = "true"
    for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(var, None)
    return root, keys, env


def _candidate_units(root):
    return sorted(
        p.parent.relative_to(root).as_posix()
        for p in (root / "stacks").rglob("terragrunt.hcl")
        if ".terragrunt-cache" not in p.parts and OWNS_RE.search(p.read_text())
    )


def _render(root, unit, env):
    proc = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["terragrunt", "render", "--json", "--log-level", "error"],
        cwd=root / unit, env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, "%s: terragrunt render failed (rc=%d):\n%s" % (
        unit, proc.returncode, proc.stderr[-2000:],
    )
    return json.loads(proc.stdout)


def test_regression_imdsv1_acknowledgement_reaches_every_ec2_compute_stack(tmp_path):
    root, keys, env = _stage(tmp_path)
    units = _candidate_units(root)
    assert units, "no stack under stacks/ names %s: nothing to pin" % MODULE

    sentinels = {json.dumps(_sentinel(k)): k for k in keys}
    arrived = {}  # unit -> operator key whose value it received
    problems = []
    for unit in units:
        rendered = _render(root, unit, env)
        source = (rendered.get("terraform") or {}).get("source") or ""
        if not source.rstrip("/").endswith("/" + MODULE):
            problems.append(
                "%s names %s but renders terraform.source=%r: an ownership shape this pin does not read"
                % (unit, MODULE, source)
            )
            continue
        inputs = rendered.get("inputs") or {}
        if MODULE_INPUT not in inputs:
            problems.append("%s: input %s is not passed to the module" % (unit, MODULE_INPUT))
            continue
        got = json.dumps(inputs[MODULE_INPUT])
        if got not in sentinels:
            problems.append(
                "%s: %s = %s, none of the operator's values %s arrived"
                % (unit, MODULE_INPUT, got, sorted(sentinels))
            )
            continue
        arrived[unit] = sentinels[got]

    orphans = sorted(set(keys) - set(arrived.values()))
    if orphans and not problems:
        problems.append(
            "operator key(s) %s reach no stack that owns %s" % (orphans, MODULE)
        )
    print("imdsv1 wiring pin: %s" % ", ".join("%s<-%s" % (u, k) for u, k in sorted(arrived.items())))
    assert not problems, "\n".join(problems)
