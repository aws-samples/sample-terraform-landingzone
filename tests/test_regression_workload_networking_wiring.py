"""regression: the workload compute unit took its security groups and target groups from the management account.

``stacks/workload-dev/workload-compute`` runs modules/ec2-compute in the workload
account but resolved ``security_group_ids`` and ``target_group_arns`` from
``stacks/management/networking``: management-owned security groups on a
participant launch template and a management-owned target group on a workload
auto-scaling group, both of which AWS refuses at apply. The groups and target
groups now come from the workload account's own networking unit,
``stacks/workload-dev/networking`` (modules/workload-networking); only the
shared subnets keep coming from the management stack. This pins the wiring:

* with ``enable_workload_compute = true`` the rendered compute unit takes
  ``security_group_ids`` and ``target_group_arns`` from the dependency whose
  ``config_path`` is the workload networking unit, and ``subnet_ids`` from the
  dependency whose ``config_path`` is the management networking unit;
* the workload networking unit renders with modules/workload-networking as
  its source and reads ``vpc_ids`` and ``subnet_ids`` from management
  networking;
* with the toggle off both units are excluded, so the compute unit never
  depends on an excluded unit.

How it is measured: the harness of tests/test_regression_imdsv1_wiring.py -- a
staged copy of the tracked tree under ``tmp_path``, env/common.hcl from the
example, a stand-in ``aws`` first on PATH that answers every account lookup
with a placeholder id so both units resolve an account and nothing reaches
AWS. Terragrunt renders each unit itself. Because every dependency mock of
the compute unit is an empty map, the staged copy's mocks are rewritten to one
sentinel per dependency NAME before the render; the rendered inputs then say
which dependency each map came from, and the dependency's ``config_path`` in
the same render says which unit that is. Without ``terragrunt`` on PATH the
test skips and says so (the CI ``test`` job installs it before ``make test``).
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
COMPUTE_UNIT = "stacks/workload-dev/workload-compute"
NETWORKING_UNIT = "stacks/workload-dev/networking"
MANAGEMENT_NETWORKING_UNIT = "stacks/management/networking"
TOGGLE_RE = re.compile(r"^(\s*enable_workload_compute\s*=\s*)false\b", re.MULTILINE)
PLACEHOLDER_ID = "111111111111"
MAPS = ("subnet_ids", "security_group_ids", "target_group_arns")

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the workload networking wiring pin renders the stacks with it",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _stage(tmp_path, toggle_on):
    """Copy the tracked tree, write the operator's configuration, fence off AWS."""
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue  # a tracked path deleted in the working tree
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    common = (root / "env/common.hcl.example").read_text()
    if toggle_on:
        common, n = TOGGLE_RE.subn(r"\1true", common)
        assert n == 1, "env/common.hcl.example: no single 'enable_workload_compute = false' line to switch on"
    (root / "env/common.hcl").write_text(common)
    shutil.copy2(root / "env/accounts.hcl.example", root / "env/accounts.hcl")
    subprocess.run(["git", "init", "-q", str(root)], check=True)  # nosec B603 B607 -- literal argv, no shell

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    # Every account lookup answers the placeholder id: both units resolve an
    # account, so only the toggle decides their exclusion.
    aws.write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in *get-parameter*) echo %s; exit 0;; esac\n'
        "exit 254\n" % PLACEHOLDER_ID
    )
    aws.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = "%s%s%s" % (bin_dir, os.pathsep, env.get("PATH", ""))
    env["TLZ_STATE_DIR"] = str(tmp_path / "state")
    env["TG_NON_INTERACTIVE"] = "true"
    env["TG_NO_COLOR"] = "true"
    for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(var, None)
    return root, env


def _render(root, unit, env):
    proc = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["terragrunt", "render", "--json", "--log-level", "error"],
        cwd=root / unit, env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, "%s: terragrunt render failed (rc=%d):\n%s" % (
        unit, proc.returncode, proc.stderr[-2000:],
    )
    return json.loads(proc.stdout)


def _unit_of(root, unit, config_path):
    """The repository path of a dependency's config_path, resolved from the unit."""
    return os.path.normpath(os.path.join(unit, config_path)).replace(os.sep, "/")


def _sentinel_mocks(root, unit, dependencies):
    """Rewrite every empty-map mock of the unit's dependency blocks to {pin = "<dependency name>"}.

    The render says which dependency a rendered input came from only if the
    mocks differ; the sentinel is the dependency's own name, so the assertion
    below reads as 'this map came from that dependency'.
    """
    path = root / unit / "terragrunt.hcl"
    text = path.read_text()
    for name in dependencies:
        block = re.search(r'^dependency "%s" \{\n(.*?)^\}' % re.escape(name), text, re.MULTILINE | re.DOTALL)
        assert block, "%s: no dependency %r block to rewrite" % (unit, name)
        body, n = re.subn(
            r"^(\s*(?:%s)\s*=\s*)\{\}\s*$" % "|".join(MAPS),
            lambda m: '%s{ pin = "%s" }' % (m.group(1), name),
            block.group(1), flags=re.MULTILINE,
        )
        assert n > 0, "%s: dependency %r mocks none of %s as an empty map" % (unit, name, MAPS)
        text = text[: block.start(1)] + body + text[block.end(1):]
    path.write_text(text)


def test_regression_compute_unit_takes_groups_and_target_groups_from_the_workload_account(tmp_path):
    root, env = _stage(tmp_path, toggle_on=True)

    rendered = _render(root, COMPUTE_UNIT, env)
    assert rendered["exclude"]["if"] is False, "with the toggle on the compute unit must run"
    deps = rendered["dependency"]
    by_unit = {_unit_of(root, COMPUTE_UNIT, d["config_path"]): name for name, d in deps.items()}
    assert NETWORKING_UNIT in by_unit, (
        "the compute unit depends on %s, not on the workload account's networking unit %s"
        % (sorted(by_unit), NETWORKING_UNIT)
    )
    assert MANAGEMENT_NETWORKING_UNIT in by_unit, "the shared subnets still come from management networking"

    _sentinel_mocks(root, COMPUTE_UNIT, deps)
    inputs = _render(root, COMPUTE_UNIT, env)["inputs"]
    got = {m: inputs.get(m) for m in MAPS}
    want = {
        "subnet_ids": {"pin": by_unit[MANAGEMENT_NETWORKING_UNIT]},
        "security_group_ids": {"pin": by_unit[NETWORKING_UNIT]},
        "target_group_arns": {"pin": by_unit[NETWORKING_UNIT]},
    }
    assert got == want, (
        "modules/ec2-compute in the workload account receives its maps from the wrong units: %r" % got
    )


def test_regression_workload_networking_unit_reads_vpcs_and_subnets_from_management(tmp_path):
    root, env = _stage(tmp_path, toggle_on=True)
    rendered = _render(root, NETWORKING_UNIT, env)
    assert rendered["exclude"]["if"] is False, "with the toggle on the networking unit must run"
    source = (rendered.get("terraform") or {}).get("source") or ""
    assert source.rstrip("/").endswith("/modules/workload-networking"), source
    deps = rendered["dependency"]
    by_unit = {_unit_of(root, NETWORKING_UNIT, d["config_path"]): name for name, d in deps.items()}
    assert MANAGEMENT_NETWORKING_UNIT in by_unit, sorted(by_unit)
    assert rendered["inputs"]["enable"] is True

    path = root / NETWORKING_UNIT / "terragrunt.hcl"
    name = by_unit[MANAGEMENT_NETWORKING_UNIT]
    block = re.search(r'^dependency "%s" \{\n(.*?)^\}' % re.escape(name), path.read_text(), re.MULTILINE | re.DOTALL)
    assert block, name
    body, n = re.subn(
        r"^(\s*(?:vpc_ids|subnet_ids)\s*=\s*)\{\}\s*$",
        lambda m: '%s{ pin = "%s" }' % (m.group(1), name), block.group(1), flags=re.MULTILINE,
    )
    assert n == 2, "the management networking dependency must mock vpc_ids and subnet_ids as empty maps"
    text = path.read_text()
    path.write_text(text[: block.start(1)] + body + text[block.end(1):])
    inputs = _render(root, NETWORKING_UNIT, env)["inputs"]
    assert inputs["vpc_ids"] == {"pin": name} and inputs["subnet_ids"] == {"pin": name}, inputs


def test_regression_both_workload_units_follow_the_one_toggle(tmp_path):
    root, env = _stage(tmp_path, toggle_on=False)
    excluded = {u: _render(root, u, env)["exclude"]["if"] for u in (NETWORKING_UNIT, COMPUTE_UNIT)}
    assert excluded == {NETWORKING_UNIT: True, COMPUTE_UNIT: True}, (
        "with enable_workload_compute = false both units must be excluded, or the compute unit "
        "depends on an excluded unit and fails with 'detected no outputs': %r" % excluded
    )
