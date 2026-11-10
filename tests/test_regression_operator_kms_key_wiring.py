"""regression: the operator's KMS keys for Lambda environments and CodeBuild reach their modules.

v0.5.8 offers three customer-managed key ARNs in env/common.hcl.example --
``logging_lambda_environment_kms_key_arn``,
``monitoring_lambda_environment_kms_key_arn`` and
``codebuild_encryption_kms_key_arn`` -- which configurations/loader.hcl passes
through and three stacks hand to their modules. Without this test the
stack lines could be deleted while ``make test`` stays green: the modules
validate the input, nothing checks that it arrives. This pins the PROPERTY,
the way tests/test_regression_imdsv1_wiring.py pins the IMDSv1 lists:

  for EVERY stack whose module declares one of the key inputs, a value the
  operator sets in env/common.hcl arrives there as that stack's input, every
  key the operator is offered arrives at some stack, and a key named after a
  stack (``logging_…``, ``monitoring_…``) arrives at THAT stack.

How it is measured, so that a legitimate rewrite stays green:

* The module inputs are the variables named ``lambda_environment_kms_key_arn``
  or ``codebuild_encryption_kms_key_arn``; the modules are DERIVED as every
  modules/*/ that declares one of them.
* The stacks are DERIVED from the tree: every ``stacks/**/terragrunt.hcl``
  that names such a module, confirmed by what ``terragrunt render`` reports
  as the unit's ``terraform.source``. Nothing is listed by hand.
* The operator's keys are DERIVED from env/common.hcl.example as every
  assignment whose name ends in one of the module inputs.
* Each key gets its own sentinel key ARN (placeholder account), every
  ``enable_*`` flag is switched on, and each derived stack is rendered by
  Terragrunt itself. The rendered input must equal exactly one sentinel.

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
MODULE_INPUTS = ("lambda_environment_kms_key_arn", "codebuild_encryption_kms_key_arn")
KEY_RE = re.compile(
    r"^(\s*)(\w*(?:%s))\s*=.*$" % "|".join(MODULE_INPUTS), re.MULTILINE,
)
ENABLE_RE = re.compile(r"^(\s*enable_\w+\s*=\s*)false\b", re.MULTILINE)
ACCOUNT = "111111111111"  # documented placeholder

STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the operator KMS key wiring pin renders the stacks with it",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _sentinel(index):
    # A key ARN of the shape the modules validate, one distinct key id per key.
    return "arn:aws:kms:eu-central-1:%s:key/00000000-0000-0000-0000-%012d" % (ACCOUNT, index + 1)


def _input_of(key):
    return next(i for i in MODULE_INPUTS if key.endswith(i))


def _modules(root):
    """module dir name -> the key inputs it declares."""
    found = {}
    for tf in sorted((root / "modules").glob("*/*.tf")):
        text = tf.read_text()
        for name in MODULE_INPUTS:
            if re.search(r'^variable\s+"%s"' % name, text, re.MULTILINE):
                found.setdefault(tf.parent.name, set()).add(name)
    assert found, "no module declares any of %s: nothing to pin" % (MODULE_INPUTS,)
    return found


def _stage(tmp_path):
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    example = (root / "env/common.hcl.example").read_text()
    keys = sorted({m.group(2) for m in KEY_RE.finditer(example)})
    assert keys, "env/common.hcl.example offers no key ending in %s" % (MODULE_INPUTS,)
    sentinels = {k: _sentinel(i) for i, k in enumerate(keys)}
    common = KEY_RE.sub(
        lambda m: "%s%s = %s" % (m.group(1), m.group(2), json.dumps(sentinels[m.group(2)])),
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
    return root, sentinels, env


def _candidate_units(root, modules):
    owns = re.compile(r"modules/+(%s)\b" % "|".join(re.escape(m) for m in modules))
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


def test_regression_operator_kms_keys_reach_every_stack(tmp_path):
    root, sentinels, env = _stage(tmp_path)
    modules = _modules(root)
    units = _candidate_units(root, modules)
    assert units, "no stack under stacks/ names any of %s: nothing to pin" % sorted(modules)

    by_value = {v: k for k, v in sentinels.items()}
    arrived = {}  # (unit, input) -> operator key whose value it received
    problems = []
    for unit in units:
        rendered = _render(root, unit, env)
        source = ((rendered.get("terraform") or {}).get("source") or "").rstrip("/")
        module = next((m for m in modules if source.endswith("/modules/" + m)), None)
        if module is None:
            continue  # names such a module in text but deploys another one
        inputs = rendered.get("inputs") or {}
        for name in sorted(modules[module]):
            if name not in inputs:
                problems.append("%s: input %s is not passed to modules/%s" % (unit, name, module))
                continue
            got = inputs[name]
            if got not in by_value:
                problems.append(
                    "%s: %s = %r, none of the operator's values arrived" % (unit, name, got)
                )
                continue
            key = by_value[got]
            prefix = key[: -len(_input_of(key))].rstrip("_")
            if _input_of(key) != name:
                problems.append("%s: %s received %s, a key for %s" % (unit, name, key, _input_of(key)))
            elif prefix and Path(unit).name != prefix:
                problems.append("%s: %s received %s, the key of the %s stack" % (unit, name, key, prefix))
            arrived[(unit, name)] = key

    orphans = sorted(set(sentinels) - set(arrived.values()))
    if orphans:
        problems.append("operator key(s) %s reach no stack" % orphans)
    print("operator kms key pin: %s" % ", ".join(
        "%s.%s<-%s" % (u, n, k) for (u, n), k in sorted(arrived.items())
    ))
    assert not problems, "\n".join(problems)
