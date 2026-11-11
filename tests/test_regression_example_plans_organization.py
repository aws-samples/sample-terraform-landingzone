"""regression: the organization unit rendered from env/common.hcl.example must plan.

A fresh clone copies env/common.hcl.example to env/common.hcl, so the example
is the first configuration the organization module sees. It once shipped two
inputs the module refuses at plan time:

1. ``service_access_principals`` with placeholder account ids
   (``__AUDIT_ACCOUNT_ID__`` and others) for services whose trusted access no
   toggle enables. The module requires a 12-digit id and every delegated
   administrator's service in ``aws_service_access_principals``.
2. A declarative-policy target list naming the accounts ``Network`` and
   ``SharedServices``. A target must be ``Root``, a declared OU name or a
   12-digit account id.

A third case pins the commented delegated-administrator hint of the example:
GuardDuty, Security Hub, Macie and Access Analyzer are registered by the
security stack, so the hint must not name them (a second registration of the
same service fails at apply).

The render runs in a staged copy of the tracked tree under ``tmp_path`` with a
stand-in ``aws`` first on PATH that answers ParameterNotFound, so nothing
reaches AWS and no credentials are needed. Without ``terragrunt`` on PATH the
render cases skip and say so.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
UNIT = "stacks/management/organization"
ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
SECURITY_STACK_SERVICES = ("guardduty", "securityhub", "macie", "access-analyzer")
HINT_PRINCIPAL_RE = re.compile(r'service_principal\s*=\s*"([^".$]+)\.')

STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

needs_terragrunt = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: this pin renders the organization unit with it",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


@pytest.fixture(scope="module")
def inputs(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("example-organization")
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    shutil.copy2(root / "env/common.hcl.example", root / "env/common.hcl")
    shutil.copy2(root / "env/accounts.hcl.example", root / "env/accounts.hcl")
    subprocess.run(["git", "init", "-q", str(root)], check=True)  # nosec B603 B607 -- literal argv, no shell

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

    proc = subprocess.run(  # nosec B603 B607 -- argv list of literals, cwd inside the staged copy, no shell
        ["terragrunt", "render", "--json", "--log-level", "error"],
        cwd=root / UNIT, env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, "%s: terragrunt render failed (rc=%d):\n%s" % (
        UNIT, proc.returncode, proc.stderr[-2000:],
    )
    return json.loads(proc.stdout)["inputs"]


@needs_terragrunt
def test_regression_example_delegated_admins_are_real_and_trusted(inputs):
    trusted = inputs["aws_service_access_principals"]
    problems = []
    for entry in inputs["service_access_principals"]:
        if not ACCOUNT_ID_RE.match(entry["account_id"]):
            problems.append("%s: account_id %r is not a 12-digit account id" % (
                entry["service_principal"], entry["account_id"]))
        if entry["service_principal"] not in trusted:
            problems.append("%s: not in aws_service_access_principals %r" % (entry["service_principal"], trusted))
    assert not problems, "the example's delegated administrators are refused by the module:\n" + "\n".join(problems)


@needs_terragrunt
def test_regression_example_policy_targets_resolve(inputs):
    known = {"Root"} | {ou["name"] for ou in inputs["organizational_units"]}
    lists = sorted(
        k for k, v in inputs.items()
        if k.endswith("_policies") and isinstance(v, list) and all(isinstance(p, dict) for p in v)
    )
    assert "declarative_policies" in lists, "the organization unit passes no declarative_policies: nothing to pin"
    targets = [(k, p["name"], t) for k in lists for p in inputs[k] for t in p.get("targets") or []]
    if inputs.get("enable_quarantine_scp"):
        targets += [("quarantine_scp_targets", "-", t) for t in inputs.get("quarantine_scp_targets") or []]
    bad = ["%s %s: %r" % (k, name, t) for k, name, t in targets if t not in known and not ACCOUNT_ID_RE.match(t)]
    assert not bad, "targets that are neither Root, a declared OU nor a 12-digit id (known: %s):\n%s" % (
        sorted(known), "\n".join(bad))


def test_regression_example_hint_names_no_security_stack_service():
    text = (REPO / "env/common.hcl.example").read_text()
    start = text.index("# Delegated Admin")
    end = text.index("\n  additional_aws_service_access_principals", start)
    named = HINT_PRINCIPAL_RE.findall(text[start:end])
    assert named, "the example names no delegated-administrator service_principal: nothing to pin"
    clash = sorted(set(named) & set(SECURITY_STACK_SERVICES))
    assert not clash, (
        "env/common.hcl.example suggests %s as delegated administrators; the security stack registers "
        "them already, and a second registration fails at apply" % clash
    )
