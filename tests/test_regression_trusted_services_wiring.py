"""regression: the operator's additional trusted-access principals reach the organization module.

``stacks/management/organization`` computes ``aws_service_access_principals``
from the module toggles. The organization resource owns the COMPLETE
trusted-access list and the module refuses ``[]``, so a toggle combination
that renders nothing had no repair path from a ``stacks/`` deployment, and an
organization adopted with more trusted services than the toggles know could
not keep them. The repair is an operator key,
``additional_aws_service_access_principals``: env/common.hcl.example offers
it, configurations/loader.hcl merges it (base.tfvars + env/common.hcl +
frameworks) and the stack concatenates the result onto the toggle list.

This pins the PROPERTY in both directions, the way
tests/test_regression_operator_kms_key_wiring.py pins the KMS key wiring:

  * an operator value set in env/common.hcl arrives as the module input of
    the organization stack (the key is offered AND wired);
  * the loader's merged key is what the stack consumes -- a value that only
    the loader can see (set in base.tfvars) arrives too, so a raw
    env/common.hcl read in the stack would not pass;
  * on aws-eusc the loader strips ``sso.<suffix>`` from the additional list,
    in step with the delegated-admin filter, and leaves the rest alone;
  * a blank entry the operator typed ARRIVES at the module input instead of
    vanishing on the way, so the module's validation refuses it by name. A
    ``compact()`` around the concatenated list drops ``""`` in silence and
    the plan succeeds with the intended service simply absent; the module
    cannot refuse what it never sees, so this is pinned at the stack render;
  * on aws-eusc a ``null`` entry SURVIVES the loader's ``sso.`` strip and
    arrives at the module input too. ``startswith(null, "sso.")`` aborts the
    whole loader evaluation, so the render fails inside the loader and the
    module's own blank diagnostic never speaks; the strip must tolerate a
    null so the module is the one that refuses it.

How it is measured. A legitimate rewrite that keeps the key names stays
green; a rename of the operator or loader key is caught, by design, because
the keys are derived by name suffix: a name that no longer ends in
``_aws_service_access_principals``, or an operator key the loader does not
carry under the same name, reddens the pin even when the rename is consistent
across env/common.hcl.example, configurations/loader.hcl and the stack.

  * The module input is the variable ``aws_service_access_principals`` of
    modules/organization; the stack is DERIVED as every
    ``stacks/**/terragrunt.hcl`` that names that module, confirmed by what
    ``terragrunt render`` reports as the unit's ``terraform.source``.
  * The operator key is DERIVED from env/common.hcl.example as the
    assignment whose name ends in the module input and is not the module
    input itself; the loader key is DERIVED from configurations/loader.hcl
    the same way. Nothing is listed by hand.
  * Every ``enable_*`` flag stays as the example ships it, so the toggle
    list stays small and the sentinels are visibly additions.

The render runs in a staged copy of the tracked tree under ``tmp_path`` with a
stand-in ``aws`` first on PATH that answers ParameterNotFound, so nothing
reaches AWS and no credentials are needed. Without ``terragrunt`` on PATH the
test skips and says so.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt/bash with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MODULE = "organization"
MODULE_INPUT = "aws_service_access_principals"
KEY_RE = re.compile(r"^(\s*)(\w+_%s)\s*=.*$" % MODULE_INPUT, re.MULTILINE)
REGION_RE = re.compile(r'^(\s*region\s*=\s*)"[^"]*"', re.MULTILINE)

# Principals no toggle of the stack produces, one per path under test.
OPERATOR_SENTINELS = ["ram.amazonaws.com", "servicequotas.amazonaws.com"]
LOADER_SENTINEL = "backup.amazonaws.com"

STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the trusted-services wiring pin renders the stack with it",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _keys(text, where):
    keys = sorted({m.group(2) for m in KEY_RE.finditer(text)})
    assert keys, "%s offers no key ending in _%s" % (where, MODULE_INPUT)
    return keys


def _stage(tmp_path, operator_values, suffix="amazonaws.com", region=None):
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    example = (root / "env/common.hcl.example").read_text()
    operator_keys = _keys(example, "env/common.hcl.example")
    assert len(operator_keys) == 1, "expected one operator key, found %s" % operator_keys
    (operator_key,) = operator_keys
    common = KEY_RE.sub(
        lambda m: "%s%s = %s" % (m.group(1), m.group(2), json.dumps(operator_values)),
        example,
    )
    if region is not None:
        common, n = REGION_RE.subn(r'\1"%s"' % region, common, count=1)
        assert n == 1, "env/common.hcl.example has no region assignment to switch"
    (root / "env/common.hcl").write_text(common)
    shutil.copy2(root / "env/accounts.hcl.example", root / "env/accounts.hcl")

    # The loader reads base.tfvars itself; the stack cannot see this file.
    loader_keys = _keys((root / "configurations/loader.hcl").read_text(), "configurations/loader.hcl")
    assert operator_key in loader_keys, (
        "the operator key %s is not a loader local (loader offers %s)" % (operator_key, loader_keys)
    )
    base = root / "configurations/base/base.tfvars"
    base.write_text(base.read_text().rstrip("\n") + "\n%s = %s\n" % (
        operator_key, json.dumps([LOADER_SENTINEL.replace("amazonaws.com", suffix)]),
    ))

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
    return root, operator_key, env


def _organization_units(root):
    owns = re.compile(r"modules/+%s\b" % re.escape(MODULE))
    return sorted(
        p.parent.relative_to(root).as_posix()
        for p in (root / "stacks").rglob("terragrunt.hcl")
        if ".terragrunt-cache" not in p.parts and owns.search(p.read_text())
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


def _rendered_inputs(root, env):
    """unit -> rendered aws_service_access_principals, for every organization unit."""
    units = _organization_units(root)
    assert units, "no stack under stacks/ names modules/%s: nothing to pin" % MODULE
    got = {}
    for unit in units:
        rendered = _render(root, unit, env)
        source = ((rendered.get("terraform") or {}).get("source") or "").rstrip("/")
        if not source.endswith("/modules/" + MODULE):
            continue  # names the module in text but deploys another one
        inputs = rendered.get("inputs") or {}
        assert MODULE_INPUT in inputs, "%s: input %s is not passed to modules/%s" % (unit, MODULE_INPUT, MODULE)
        got[unit] = inputs[MODULE_INPUT]
    assert got, "no stack deploys modules/%s" % MODULE
    return got


def test_regression_operator_trusted_services_reach_the_organization_stack(tmp_path):
    root, key, env = _stage(tmp_path, OPERATOR_SENTINELS)
    problems = []
    for unit, principals in _rendered_inputs(root, env).items():
        for sentinel in OPERATOR_SENTINELS:
            if sentinel not in principals:
                problems.append("%s: operator value %s of %s did not arrive in %s = %r" % (
                    unit, sentinel, key, MODULE_INPUT, principals))
        if LOADER_SENTINEL not in principals:
            problems.append("%s: the loader's merged %s is not consumed -- base.tfvars value %s missing from %r" % (
                unit, key, LOADER_SENTINEL, principals))
        if len(set(principals)) != len(principals):
            problems.append("%s: %s carries duplicates: %r" % (unit, MODULE_INPUT, principals))
        print("trusted services pin: %s.%s <- %s: %s" % (unit, MODULE_INPUT, key, principals))
    assert not problems, "\n".join(problems)


def test_regression_operator_trusted_services_strip_sso_on_aws_eusc(tmp_path):
    kept = "ram.amazonaws.eu"
    stripped = "sso.amazonaws.eu"
    root, key, env = _stage(tmp_path, [kept, stripped], suffix="amazonaws.eu", region="eusc-de-east-1")
    problems = []
    for unit, principals in _rendered_inputs(root, env).items():
        if kept not in principals:
            problems.append("%s: operator value %s of %s did not arrive on aws-eusc: %r" % (unit, kept, key, principals))
        if stripped in principals:
            problems.append("%s: %s of %s reached %s on aws-eusc, where Identity Center does not exist: %r" % (
                unit, stripped, key, MODULE_INPUT, principals))
        print("trusted services pin (aws-eusc): %s.%s <- %s: %s" % (unit, MODULE_INPUT, key, principals))
    assert not problems, "\n".join(problems)


def test_regression_operator_blank_trusted_service_arrives_for_the_module_to_refuse(tmp_path):
    """regression: a blank operator entry was compact()ed away before the module could refuse it.

    The stack once wrapped compact() around the WHOLE concatenated list, so an
    "" in additional_aws_service_access_principals vanished on the way: the
    plan succeeded and the service the operator meant to name was simply
    absent. The blank must arrive at the module input, where the variable's
    validation refuses it by name before any apply.
    """
    blank = ""
    root, key, env = _stage(tmp_path, [blank, OPERATOR_SENTINELS[0]])
    problems = []
    for unit, principals in _rendered_inputs(root, env).items():
        if blank not in principals:
            problems.append(
                "%s: the blank entry %r of %s vanished before reaching %s = %r -- the module "
                "cannot refuse what it never sees, and the plan succeeds with the intended "
                "service absent" % (unit, blank, key, MODULE_INPUT, principals))
        if OPERATOR_SENTINELS[0] not in principals:
            problems.append("%s: operator value %s of %s did not arrive beside the blank: %r" % (
                unit, OPERATOR_SENTINELS[0], key, principals))
        print("trusted services pin (blank entry): %s.%s <- %s: %s" % (unit, MODULE_INPUT, key, principals))
    assert not problems, "\n".join(problems)


def test_regression_operator_null_trusted_service_survives_the_aws_eusc_strip(tmp_path):
    """regression: a null operator entry aborted the loader on aws-eusc before the module could refuse it.

    The aws-eusc branch of the loader strips ``sso.<suffix>`` from the
    operator's additional list with ``startswith(principal, "sso.")``. That
    call fails on a null element and aborts evaluation of the whole loader,
    so ``terragrunt render`` died with ``argument must not be null`` at
    configurations/loader.hcl instead of the module refusing the entry by
    name. The null must survive the strip and arrive at the module input,
    where the blank validation of ``aws_service_access_principals`` is the
    one that refuses it. On the commercial partition the strip is never
    entered, so only aws-eusc is pinned here.
    """
    kept = "ram.amazonaws.eu"
    root, key, env = _stage(tmp_path, [None, kept], suffix="amazonaws.eu", region="eusc-de-east-1")
    problems = []
    for unit, principals in _rendered_inputs(root, env).items():
        if None not in principals:
            problems.append(
                "%s: the null entry of %s vanished before reaching %s = %r on aws-eusc -- the module "
                "cannot refuse what it never sees" % (unit, key, MODULE_INPUT, principals))
        if kept not in principals:
            problems.append("%s: operator value %s of %s did not arrive beside the null: %r" % (
                unit, kept, key, principals))
        print("trusted services pin (aws-eusc, null entry): %s.%s <- %s: %s" % (unit, MODULE_INPUT, key, principals))
    assert not problems, "\n".join(problems)
