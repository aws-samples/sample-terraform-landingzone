"""regression: the networking stack refuses an authenticated edge whose client secret would land in local state.

An authenticated edge hands its OIDC client
secret to ``aws_lb_listener.default_action.authenticate_oidc.client_secret``,
so the value is written into the Terraform STATE whichever way it arrives
(``client_secret_arn`` is read from Secrets Manager into the same attribute).
With ``state_backend = "local"`` that state is a plain JSON file on the
operator's disk. The networking unit therefore refuses, at Terragrunt config
time and before any module runs or any secret is read:

  * any listener with an ``authenticated_edge`` while the backend is not "s3";
  * any listener whose ``authenticated_edge`` carries a literal
    ``client_secret``, whatever the backend -- the stack's only input path is
    env/common.hcl, a file, so ``client_secret_arn`` is the only stack path.

How it is measured: the tracked tree is staged under ``tmp_path``, an
env/common.hcl is written from env/common.hcl.example with networking on, the
chosen backend and one load balancer, a stand-in ``aws`` first on PATH answers
ParameterNotFound (nothing reaches AWS), and ``terragrunt render`` of the
networking unit is the verdict. Without ``terragrunt`` on PATH the test skips
and says so.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt/bash with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
UNIT = "stacks/management/networking"
GUARD_PREFIX = "_edge_"
FENCE_RE = re.compile(
    r"^[ \t]*# --- authenticated edge guard \(begin\).*?^[ \t]*# --- authenticated edge guard \(end\)[^\n]*\n",
    re.MULTILINE | re.DOTALL,
)
LB_NAME = "d-s1-edge-alb"
# A stand-in for the listener's literal client secret: a placeholder, never a
# credential. The guard must refuse the SHAPE (a non-null client_secret).
LITERAL = "placeholder-not-a-credential"

STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the authenticated-edge state guard is measured by terragrunt render",
)


def _lb_hcl(scheme="internet-facing", edge=True, literal_secret=False):
    """One load balancer entry as HCL, in the shape of modules/networking load_balancers."""
    secret = (
        'client_secret = "%s"' % LITERAL
        if literal_secret
        else 'client_secret_arn = "arn:aws:secretsmanager:us-east-1:111111111111:secret:d-s1-edge-oidc"'
    )
    edge_block = (
        """
          authenticated_edge = {
            issuer                 = "https://idp.example.com"
            authorization_endpoint = "https://idp.example.com/authorize"
            token_endpoint         = "https://idp.example.com/token"
            user_info_endpoint     = "https://idp.example.com/userinfo"
            client_id              = "d-s1-edge"
            %s
          }"""
        % secret
        if edge
        else ""
    )
    return """[
    {
      name         = "%s"
      type         = "application"
      vpc_name     = "d-s1-edge-vpc"
      subnet_names = ["d-s1-edge-a"]
      scheme       = "%s"
      listeners = [
        {
          port     = 443
          protocol = "HTTPS"%s
        }
      ]
    }
  ]""" % (LB_NAME, scheme, edge_block)


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


def _stage(tmp_path, backend, load_balancers):
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    common = (root / "env/common.hcl.example").read_text()
    common = _sub_one(r"^(\s*enable_networking\s*=\s*)false\b", r"\g<1>true", common)
    common = _sub_one(r'^(\s*state_backend\s*=\s*)"local"', r'\g<1>"%s"' % backend, common)
    common = _sub_one(
        r"^(\s*load_balancers\s*=\s*)\[\]", lambda m: m.group(1) + load_balancers, common
    )
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
    return root, env


def _render(root, env):
    return subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["terragrunt", "render", "--json", "--log-level", "error"],
        cwd=root / UNIT, env=env, capture_output=True, text=True, timeout=300,
    )


def _render_ok(root, env):
    proc = _render(root, env)
    assert proc.returncode == 0, "terragrunt render failed (rc=%d):\n%s" % (
        proc.returncode, proc.stderr[-2000:],
    )
    return json.loads(proc.stdout)


def test_s1_local_backend_with_authenticated_edge_is_refused(tmp_path):
    root, env = _stage(tmp_path, "local", _lb_hcl())
    proc = _render(root, env)
    assert proc.returncode != 0, (
        "an authenticated edge rendered with state_backend = \"local\": its client "
        "secret would be written to a plain state file on disk"
    )
    msg = " ".join(proc.stderr.split())
    for needle in (LB_NAME, "state_backend", '"s3"', "internal"):
        assert needle in msg, "refusal does not name %r:\n%s" % (needle, proc.stderr[-2000:])


def test_s1_s3_backend_with_authenticated_edge_renders(tmp_path):
    root, env = _stage(tmp_path, "s3", _lb_hcl())
    rendered = _render_ok(root, env)
    lbs = rendered["inputs"]["load_balancers"]
    assert [lb["name"] for lb in lbs] == [LB_NAME]
    assert lbs[0]["listeners"][0]["authenticated_edge"]["client_id"] == "d-s1-edge"


def test_s1_literal_client_secret_is_refused_on_any_backend(tmp_path):
    root, env = _stage(tmp_path, "s3", _lb_hcl(literal_secret=True))
    proc = _render(root, env)
    assert proc.returncode != 0, (
        "a literal client_secret in env/common.hcl rendered: the stack's only "
        "input is a file, so client_secret_arn is the only stack path"
    )
    msg = " ".join(proc.stderr.split())
    for needle in (LB_NAME, "client_secret_arn"):
        assert needle in msg, "refusal does not name %r:\n%s" % (needle, proc.stderr[-2000:])
    assert LITERAL not in msg, "the refusal repeats the secret value"


def test_s1_local_backend_without_edge_renders_unchanged(tmp_path):
    """No authenticated edge: the unit renders exactly as without the guard."""
    root, env = _stage(tmp_path, "local", _lb_hcl(scheme="internal", edge=False))
    guarded = _render_ok(root, env)

    unit_file = root / UNIT / "terragrunt.hcl"
    text = unit_file.read_text()
    unit_file.write_text(FENCE_RE.sub("", text))
    unguarded = _render_ok(root, env)

    guarded["locals"] = {
        k: v for k, v in guarded["locals"].items() if not k.startswith(GUARD_PREFIX)
    }
    assert json.dumps(guarded, sort_keys=True) == json.dumps(unguarded, sort_keys=True), (
        "the authenticated-edge guard changed the rendered unit although no listener has an edge"
    )
