"""regression: an unknown compliance framework name is refused with a message that names it.

configurations/loader.hcl carries a guard (``_framework_guard``):
a name in ``compliance_frameworks`` that is not one of ``valid_frameworks``
aborts the load with ``compliance_frameworks names the unknown framework(s)
'<name>'``. Without the guard the first reader of the name was
read_tfvars_file, whose error names a missing .tfvars path instead of the
operator's typo. This test notices the guard going.

How it is measured: the tracked tree is staged under ``tmp_path``, the
operator's env/common.hcl is written from env/common.hcl.example with one
known and one unknown framework, and a stack that reads the loader is
rendered by Terragrunt itself. The stack is DERIVED -- the first
``stacks/**/terragrunt.hcl`` (sorted) that reads configurations/loader.hcl --
so no stack is named here. A control render with the known framework alone
must succeed, so the refusal is the name's doing and not the staging's. The
refusal must also be the ONLY failure: Terragrunt reports every local that
fails, so a guard left unwired (nothing consuming ``_framework_guard``) still
prints its line NEXT TO the read_tfvars_file error -- measured on a mutant of
loader.hcl for this test. The pin therefore also asserts that no read of the
unknown name's .tfvars file was attempted.
Nothing reaches AWS: a stand-in ``aws`` first on PATH answers
ParameterNotFound. Without ``terragrunt`` on PATH the test skips and says so.
"""

import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt/bash with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KNOWN = "nist-800-53"
UNKNOWN = "tlz-no-such-framework"
FRAMEWORKS_RE = re.compile(r"^(\s*compliance_frameworks\s*=\s*)\[[^\]\n]*\]", re.MULTILINE)
READS_LOADER_RE = re.compile(r"configurations/loader\.hcl")

STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the unknown-framework pin renders a stack with it",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _stage(tmp_path):
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
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


def _write_common(root, frameworks):
    example = (root / "env/common.hcl.example").read_text()
    assert len(FRAMEWORKS_RE.findall(example)) == 1, (
        "env/common.hcl.example has no single one-line compliance_frameworks assignment to set"
    )
    value = "[%s]" % ", ".join('"%s"' % f for f in frameworks)
    (root / "env/common.hcl").write_text(FRAMEWORKS_RE.sub(lambda m: m.group(1) + value, example))


def _loader_unit(root):
    units = sorted(
        p.parent.relative_to(root).as_posix()
        for p in (root / "stacks").rglob("terragrunt.hcl")
        if ".terragrunt-cache" not in p.parts and READS_LOADER_RE.search(p.read_text())
    )
    assert units, "no stack under stacks/ reads configurations/loader.hcl: nothing to pin"
    return units[0]


def _render(root, unit, env):
    return subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["terragrunt", "render", "--json", "--log-level", "error"],
        cwd=root / unit, env=env, capture_output=True, text=True, timeout=300,
    )


def test_regression_unknown_framework_refused_naming_it(tmp_path):
    root, env = _stage(tmp_path)
    unit = _loader_unit(root)

    _write_common(root, [KNOWN])
    control = _render(root, unit, env)
    assert control.returncode == 0, "%s: control render with %r failed (rc=%d):\n%s" % (
        unit, [KNOWN], control.returncode, control.stderr[-2000:],
    )

    _write_common(root, [KNOWN, UNKNOWN])
    proc = _render(root, unit, env)
    output = proc.stdout + proc.stderr
    print("unknown-framework pin: %s rc=%d" % (unit, proc.returncode))
    assert proc.returncode != 0, "%s: compliance_frameworks = [%r, %r] rendered without error" % (
        unit, KNOWN, UNKNOWN,
    )
    assert "unknown framework(s) '%s'" % UNKNOWN in output, (
        "%s: the refusal does not name the unknown framework %r:\n%s" % (unit, UNKNOWN, output[-2000:])
    )
    # The guard must STOP the load, not merely add a line: the framework files
    # are read only from the guarded list, so no read of <name>.tfvars may be
    # attempted (that read's error names a path, not the typo).
    assert "%s.tfvars" % UNKNOWN not in output, (
        "%s: the load went on to read %s.tfvars; the guard did not stop it:\n%s"
        % (unit, UNKNOWN, output[-2000:])
    )
    assert "'%s'" % KNOWN not in output.split("unknown framework(s)", 1)[1].split(";", 1)[0], (
        "%s: the refusal names the known framework %r as unknown" % (unit, KNOWN)
    )
