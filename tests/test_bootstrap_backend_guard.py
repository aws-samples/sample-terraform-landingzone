"""regression: the bootstrap backend guard aborted run --all discovery on the shipped local backend; a direct call with state_backend != "s3" created a lock table.

The bootstrap unit creates the S3 state bucket and the DynamoDB lock table.
Its ``exclude`` block skips it under ``run --all`` when env/common.hcl sets a
backend other than ``"s3"``, but a direct ``terragrunt plan``/``apply`` inside
the unit ignores ``exclude``: such a call creates ``terraform-locks`` and
fails on the bucket only because the placeholder name
``your-terraform-state-bucket`` is taken. The unit therefore refuses a direct
call in a ``before_hook``, before Terraform initialises anything. A
``file()``-abort local would not do: terragrunt evaluates it while discovering
``run --all`` -- before ``exclude`` applies -- so the whole all-mode run would
fail on the shipped default backend; the hook runs only when the unit itself
executes.

How it is measured: the tracked tree is staged under ``tmp_path``, an
env/common.hcl is written from env/common.hcl.example with the chosen backend,
a stand-in ``aws`` first on PATH answers ParameterNotFound and logs every call
(nothing reaches AWS), HOME points into ``tmp_path``, and a direct
``terragrunt plan``/``init`` in the bootstrap unit or ``terragrunt render
--all`` from ``stacks/`` is the verdict. Without ``terragrunt`` on PATH the
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
UNIT = "stacks/management/bootstrap"
GUARD_WORDS = "creates the S3 bucket and the DynamoDB lock table"

STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "printf '%s\\n' \"$*\" >> \"$TLZ_TEST_AWS_LOG\"\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the bootstrap backend guard is measured by terragrunt",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _sub_one(pattern, repl, text):
    new, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    assert n == 1, "env/common.hcl.example has no line matching %r" % pattern
    return new


def _stage(tmp_path, backend):
    """A staged copy of the tracked tree with env/common.hcl set to `backend`."""
    root = tmp_path / "repo"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    common = (root / "env/common.hcl.example").read_text()
    common = _sub_one(r'^(\s*state_backend\s*=\s*)"local"', r'\g<1>"%s"' % backend, common)
    (root / "env/common.hcl").write_text(common)
    shutil.copy2(root / "env/accounts.hcl.example", root / "env/accounts.hcl")
    subprocess.run(["git", "init", "-q", str(root)], check=True)  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
    return root


def _env(tmp_path):
    """Stand-in aws first on PATH, HOME inside tmp_path, no AWS credentials, non-interactive."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text(STANDIN_AWS)
    aws.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    aws_log = tmp_path / "aws-calls.log"
    aws_log.touch()
    env = dict(os.environ)
    env["PATH"] = "%s%s%s" % (bin_dir, os.pathsep, env.get("PATH", ""))
    env["HOME"] = str(home)
    env["TLZ_TEST_AWS_LOG"] = str(aws_log)
    env.pop("TLZ_STATE_DIR", None)
    env["TG_NON_INTERACTIVE"] = "true"
    env["TG_NO_COLOR"] = "true"
    for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(var, None)
    return env


def _terragrunt(args, cwd, env):
    return subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["terragrunt", *args, "--log-level", "error"],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=600,
    )


def _json_objects(text):
    """Every top-level JSON object on `text` (render --all prints one per unit)."""
    dec = json.JSONDecoder()
    objs, i = [], 0
    while True:
        start = text.find("{", i)
        if start < 0:
            return objs
        try:
            obj, end = dec.raw_decode(text, start)
        except ValueError:
            i = start + 1
            continue
        objs.append(obj)
        i = end


@pytest.mark.parametrize("command", ["plan", "init"])
def test_a_direct_call_with_a_local_backend_is_refused(tmp_path, command):
    """regression: the bootstrap backend guard aborted run --all discovery on the shipped local backend; a direct call with state_backend != "s3" created a lock table.

    `exclude` protects `run --all` only; the direct call must be refused by the
    hook before Terraform initialises the backend or reaches AWS.
    """
    root = _stage(tmp_path, "local")
    env = _env(tmp_path)

    proc = _terragrunt([command], root / UNIT, env)

    assert proc.returncode != 0, (
        "a direct `terragrunt %s` in the bootstrap unit ran with state_backend = \"local\": "
        "an apply would create the DynamoDB lock table and try the placeholder bucket" % command
    )
    msg = " ".join(proc.stderr.split())
    assert GUARD_WORDS in msg, "the refusal does not carry the guard's message:\n%s" % proc.stderr[-3000:]
    combined = proc.stdout + proc.stderr
    assert "Initializing the backend" not in combined, (
        "Terraform initialised the backend before the refusal:\n%s" % combined[-3000:]
    )
    calls = Path(env["TLZ_TEST_AWS_LOG"]).read_text()
    assert not re.search(r"^(s3|s3api|dynamodb)\b.*\bcreate", calls, re.MULTILINE), (
        "the refused call reached a create on the stand-in aws:\n%s" % calls
    )


def test_s3_init_passes_then_test_is_refused_after_switch_to_local(tmp_path):
    """regression: the bootstrap backend guard aborted run --all discovery on the shipped local backend; a direct call with state_backend != "s3" created a lock table.

    (second reading: `test --no-auto-init` on a warm cache)

    The hook refuses only other backends: with "s3" a direct init passes it
    (and initialises the unit's own local state backend). That warm cache
    then lets `terragrunt test --no-auto-init` skip the init hook, so after
    env/common.hcl is switched to "local" the hook must refuse `test` itself
    before Terraform runs the module's tests.
    """
    root = _stage(tmp_path, "s3")
    env = _env(tmp_path)

    proc = _terragrunt(["init"], root / UNIT, env)

    assert GUARD_WORDS not in " ".join(proc.stderr.split()), (
        "the backend guard fired with state_backend = \"s3\":\n%s" % proc.stderr[-3000:]
    )
    assert proc.returncode == 0, "terragrunt init failed (rc=%d):\n%s" % (
        proc.returncode, proc.stderr[-3000:],
    )

    # Same staged root, same initialised cache: only the backend value changes
    # (the value alone is replaced, so the file keeps its alignment).
    common_path = root / "env/common.hcl"
    common_path.write_text(
        _sub_one(r'^(\s*state_backend\s*=\s*)"s3"', r'\g<1>"local"', common_path.read_text())
    )

    proc = _terragrunt(["test", "--no-auto-init"], root / UNIT, env)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, (
        "`terragrunt test --no-auto-init` on a warm cache ran with state_backend = \"local\":\n%s"
        % combined[-3000:]
    )
    msg = " ".join(proc.stderr.split())
    assert GUARD_WORDS in msg, "the refusal does not carry the guard's message:\n%s" % proc.stderr[-3000:]
    for word in ("Initializing", "Success!", "bootstrap.tftest.hcl"):
        assert word not in combined, (
            "Terraform ran before the refusal (%r in the output):\n%s" % (word, combined[-3000:])
        )


def test_render_all_on_the_local_backend_excludes_bootstrap(tmp_path):
    """regression: the bootstrap backend guard aborted run --all discovery on the shipped local backend; a direct call with state_backend != "s3" created a lock table.

    With the shipped default backend `render --all` must succeed and emit the
    bootstrap unit as excluded, not abort on it.
    """
    root = _stage(tmp_path, "local")

    proc = _terragrunt(["render", "--all", "--json"], root / "stacks", _env(tmp_path))

    assert proc.returncode == 0, "terragrunt render --all failed (rc=%d):\n%s" % (
        proc.returncode, proc.stderr[-3000:],
    )
    objs = _json_objects(proc.stdout)
    # render JSON carries no unit path; the unit's own state path names it
    # (<state_dir>/management/bootstrap/terraform.tfstate).
    boot = [
        o for o in objs
        if str(((o.get("remote_state") or {}).get("config") or {}).get("path", "")).endswith(
            "/%s/terraform.tfstate" % UNIT.split("/", 1)[1]
        )
    ]
    assert boot, "render --all emitted no object for %s among %d:\n%s" % (
        UNIT, len(objs), proc.stdout[:3000],
    )
    for o in boot:
        assert (o.get("exclude") or {}).get("if") is True, (
            "the bootstrap unit is not excluded on the local backend: %r" % o.get("exclude")
        )
