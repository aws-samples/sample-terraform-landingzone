"""regression: four ways the organization-wide plan and apply went wrong.

Each case renders the stacks with Terragrunt itself, the way the IMDSv1 wiring
pin does: a staged copy of the tracked tree under ``tmp_path``, env/common.hcl
and env/accounts.hcl copied from their examples, and a stand-in ``aws`` first
on PATH that records its arguments and answers every ``ssm get-parameter`` with
a placeholder account id. Nothing reaches AWS and no credentials are needed.

1. stacks/audit/security-config ran modules/security through the Audit
   provider with audit_account_id = the Audit id, so the apply asked the Audit
   account for the delegated-administrator registrations that only the
   management account may make.
2. The cross-account sidecars read /tlz/accounts/<name>/id without
   ``--region``; with the operator's CLI in another region the read answered
   ParameterNotFound and the unit silently left the organization run.
3. stacks/management/logging passed an empty Log-Archive id to a module that
   only warns, and the central bucket was named tlz-central-logs--<region>.
4. The warm-account guard of the ou-deployment units passed whenever the set
   of active accounts was empty, which is real data on an apply, not only the
   mock of a first plan.

Without ``terragrunt`` on PATH the test skips and says so (the CI ``test`` job
installs it before ``make test``).
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PLACEHOLDER_ID = "111111111111"
REGION_RE = re.compile(r'^\s*region\s*=\s*"([^"]+)"', re.MULTILINE)
ENABLE_LOGGING_RE = re.compile(r"^(\s*enable_logging\s*=\s*)false\b", re.MULTILINE)
GUARD_RE = re.compile(r"condition = data\.aws_partition\.current\.partition != \"\" && \((true|false) \|\|")

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: these pins render the stacks with it",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _stage(tmp_path, enable_logging=False):
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    common = (root / "env/common.hcl.example").read_text()
    if enable_logging:
        common, n = ENABLE_LOGGING_RE.subn(r"\1true", common)
        assert n == 1, "env/common.hcl.example: no single 'enable_logging = false' line to switch on"
    (root / "env/common.hcl").write_text(common)
    shutil.copy2(root / "env/accounts.hcl.example", root / "env/accounts.hcl")
    subprocess.run(["git", "init", "-q", str(root)], check=True)  # nosec B603 B607 -- literal argv, no shell

    log = tmp_path / "aws-calls.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text(
        "#!/usr/bin/env bash\n"
        'printf "%%s\\n" "$*" >> "%s"\n'
        'case "$*" in *get-parameter*) echo %s; exit 0;; esac\n'
        "exit 254\n" % (log, PLACEHOLDER_ID)
    )
    aws.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = "%s%s%s" % (bin_dir, os.pathsep, env.get("PATH", ""))
    env["TLZ_STATE_DIR"] = str(tmp_path / "state")
    env["TG_NON_INTERACTIVE"] = "true"
    env["TG_NO_COLOR"] = "true"
    # The operator's CLI points at another region than the landing zone's.
    env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = "ap-southeast-2"
    for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(var, None)
    return root, env, log


def _render(root, unit, env, expect_ok=True):
    proc = subprocess.run(  # nosec B603 B607 -- argv list of literals, cwd inside the staged copy, no shell
        ["terragrunt", "render", "--json", "--log-level", "error"],
        cwd=root / unit, env=env, capture_output=True, text=True, timeout=300,
    )
    if not expect_ok:
        return proc
    assert proc.returncode == 0, "%s: terragrunt render failed (rc=%d):\n%s" % (
        unit, proc.returncode, proc.stderr[-2000:],
    )
    return json.loads(proc.stdout)


def _rewrite(path, old, new):
    text = path.read_text()
    assert text.count(old) == 1, "%s: expected exactly one %r to rewrite" % (path, old)
    path.write_text(text.replace(old, new))


def test_regression_audit_security_config_makes_no_management_only_registration(tmp_path):
    root, env, _ = _stage(tmp_path)
    inputs = _render(root, "stacks/audit/security-config", env)["inputs"]
    assert inputs["audit_account_id"] == "", (
        "the Audit-account unit passes audit_account_id=%r: modules/security then makes the "
        "delegated-administrator registrations from the Audit account" % inputs["audit_account_id"]
    )
    assert inputs["enable_guardduty"] is False and inputs["enable_security_hub"] is False, (
        "the Audit account's detector and Security Hub account belong to security-org-config"
    )


def test_regression_every_account_lookup_names_the_home_region(tmp_path):
    root, env, log = _stage(tmp_path)
    region = REGION_RE.search((root / "env/common.hcl").read_text()).group(1)
    units = sorted(p.parent.relative_to(root).as_posix() for p in (root / "stacks").rglob("cross_account.hcl"))
    assert units, "no stacks/**/cross_account.hcl: nothing to pin"
    problems = []
    for unit in units:
        if log.exists():
            log.unlink()
        _render(root, unit, env)
        calls = [c for c in (log.read_text().splitlines() if log.exists() else []) if "ssm get-parameter" in c]
        if not calls:
            problems.append("%s: no SSM account lookup recorded" % unit)
        problems += ["%s: %s" % (unit, c) for c in calls if ("--region %s " % region) not in c + " "]
    assert not problems, "lookups without --region %s:\n%s" % (region, "\n".join(problems))


def test_regression_logging_refuses_an_empty_log_archive_id(tmp_path):
    root, env, _ = _stage(tmp_path, enable_logging=True)
    unit = "stacks/management/logging"
    assert _render(root, unit, env)["inputs"]["log_archive_account_id"] == "000000000000", (
        "the mocked first plan must keep rendering with the placeholder id"
    )
    # An accounts answer without a Log-Archive account, as real outputs can be.
    _rewrite(root / unit / "terragrunt.hcl", 'account_ids = { "Log-Archive" = "000000000000" }', "account_ids = {}")
    proc = _render(root, unit, env, expect_ok=False)
    assert proc.returncode != 0, "an empty Log-Archive id rendered: %s" % proc.stdout[-500:]
    assert "no Log-Archive account id" in proc.stderr and "log_archive_account_id" in proc.stderr, proc.stderr[-2000:]


def test_regression_warm_account_guard_passes_only_the_mock(tmp_path):
    root, env, _ = _stage(tmp_path)
    units = sorted(
        p.parent.relative_to(root).as_posix()
        for p in (root / "stacks/management/ou-deployment").glob("*/terragrunt.hcl")
        if "warm_account_guard" in p.read_text()
    )
    assert units, "no ou-deployment unit carries the warm-account guard: nothing to pin"

    def guard(unit):
        found = [
            m.group(1)
            for block in _render(root, unit, env)["generate"].values()
            for m in GUARD_RE.finditer(block.get("contents") or "")
        ]
        assert len(found) == 1, "%s: expected one warm-account guard, found %d" % (unit, len(found))
        return found[0]

    assert {u: guard(u) for u in units} == {u: "true" for u in units}, "the mocked plan must pass the guard"
    for unit in units:  # outputs without the sentinel: a real, empty set of active accounts
        _rewrite(root / unit / "terragrunt.hcl", '{ "__tlz_mock_outputs__" = "000000000000" }', "{}")
    assert {u: guard(u) for u in units} == {u: "false" for u in units}, (
        "a real empty set of active accounts must not short-circuit the guard"
    )
