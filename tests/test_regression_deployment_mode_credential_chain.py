"""regression: with the deployment account switched on, no unit could reach its state or its provider.

``enable_deployment_account = true`` in env/common.hcl places the state bucket
and the pipeline in a second, deployment account. Rendered with Terragrunt on a
staged copy of the tree (the harness of test_regression_org_apply_paths.py:
every account id set in env/accounts.hcl so no account lookup runs, a stand-in
``aws`` first on PATH that refuses every call, HOME inside ``tmp_path``), the
mode failed in four places before any credential was even tried:

1. stacks/management/deployment-role, the unit that CREATES TLZDeploymentRole,
   was rendered a provider that assumes TLZDeploymentRole -- a role that does
   not exist until this very unit has applied. Every management-account unit
   got that provider, so an operator's named profile was never used.
2. The S3 backend of every unit carried a top-level ``role_arn`` and no
   ``profile``. Terraform 1.14+ has no top-level ``role_arn`` on the s3 backend
   (it takes ``assume_role { role_arn = ... }``) and refused the generated
   backend.tf at ``init`` with "Unsupported argument" -- so every unit in the
   mode failed before the first AWS call.
3. stacks/deployment/pipeline had no cross-account sidecar, so the pipeline's
   own resources would have landed in the management account instead of the
   deployment account the module assumes (its bucket and roles are named after
   the account it runs in).
4. stacks/management/bootstrap was not excluded in the mode and would have
   created a second bucket of the same global name as
   stacks/deployment/bootstrap.

The operator's path is now: provider = the profile (management account; a
cross-account unit adds its member role as before), backend = the profile plus
``assume_role`` into the deployment account's access role. With the mode OFF,
provider.tf and the backend configuration are rendered from unchanged text --
pinned here against the exact strings of the previous release, so an
organization that does not use the mode plans no change.

Without ``terragrunt`` on PATH the tests skip and say so; the ``init`` case
also needs ``terraform``.
"""

import json
import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

MANAGEMENT_ID = "111111111111"
DEPLOYMENT_ID = "123456789012"
ACCOUNT_IDS = {
    "management_account_id": MANAGEMENT_ID,
    "deployment_account_id": DEPLOYMENT_ID,
    "audit_account_id": "444455556666",
    "log_archive_account_id": "111122223333",
}
WORKLOAD_DEV_ID = "210987654321"

# Values of env/common.hcl.example that reach provider.tf and backend.tf.
PROFILE = "your-aws-profile"
REGION = "eu-central-1"
ACCESS_ROLE = "AWSControlTowerExecution"
BUCKET = "your-terraform-state-bucket"
LOCK_TABLE = "terraform-locks"
TAGS = '{"Environment":"production","ManagedBy":"Terraform","Project":"TerraformLandingZone"}'
STATE_ROLE_ARN = "arn:aws:iam::%s:role/%s" % (DEPLOYMENT_ID, ACCESS_ROLE)

MANAGEMENT_UNITS = [
    "stacks/management/deployment-role",
    "stacks/management/accounts",
    "stacks/management/organization",
]
PIPELINE_UNIT = "stacks/deployment/pipeline"
CROSS_ACCOUNT_UNIT = "stacks/audit/security-config"  # the Audit account, through its sidecar

# The provider of a management-account unit, exactly as the previous release
# rendered it (the operator's profile, no role).
PROVIDER_DIRECT = (
    'provider "aws" {\n'
    '  region  = "%s"\n'
    '  profile = "%s" != "" ? "%s" : null\n'
    "\n"
    "  default_tags {\n"
    "    tags = %s\n"
    "  }\n"
    "}\n" % (REGION, PROFILE, PROFILE, TAGS)
)


def _provider_cross_account(role_arn):
    """The provider of a unit with a cross_account.hcl sidecar, exactly as rendered."""
    return (
        'provider "aws" {\n'
        '  region  = "%s"\n'
        '  profile = "%s" != "" ? "%s" : null\n'
        "\n"
        "  default_tags {\n"
        "    tags = %s\n"
        "  }\n"
        "\n"
        "  assume_role {\n"
        '    role_arn = "%s"\n'
        "  }\n"
        "}\n" % (REGION, PROFILE, PROFILE, TAGS, role_arn)
    )


def _backend_default(unit):
    """remote_state.config of the s3 backend with the mode off (render --json prints encrypt as a string)."""
    return {
        "bucket": BUCKET,
        "key": "%s/terraform.tfstate" % unit.split("/", 1)[1],
        "region": REGION,
        "encrypt": "true",
        "dynamodb_table": LOCK_TABLE,
        "profile": PROFILE,
    }


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


def _sub_one(pattern, repl, text, where):
    new, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    assert n == 1, "%s has no single line matching %r" % (where, pattern)
    return new


def _stage(tmp_path, mode_on, backend, pipeline_on=False, deployment_id=DEPLOYMENT_ID):
    """A staged copy of the tracked tree: env/common.hcl from the example with the
    chosen backend and switches, env/accounts.hcl with every account id set."""
    root = tmp_path / "tree"
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    where = "env/common.hcl.example"
    common = (root / where).read_text()
    common = _sub_one(r'^(\s*state_backend\s*=\s*)"local"', r'\g<1>"%s"' % backend, common, where)
    if mode_on:
        common = _sub_one(r"^(\s*enable_deployment_account\s*=\s*)false\b", r"\g<1>true", common, where)
    if pipeline_on:
        common = _sub_one(r"^(\s*enable_pipeline\s*=\s*)false\b", r"\g<1>true", common, where)
    (root / "env/common.hcl").write_text(common)

    where = "env/accounts.hcl.example"
    accounts = (root / where).read_text()
    for key, value in dict(ACCOUNT_IDS, deployment_account_id=deployment_id).items():
        accounts = _sub_one(r'^(\s*%s\s*=\s*)""' % key, r'\g<1>"%s"' % value, accounts, where)
    accounts = _sub_one(
        r"^(\s*workload_accounts\s*=\s*)\{\}", r'\g<1>{ "Workload-Dev" = "%s" }' % WORKLOAD_DEV_ID, accounts, where,
    )
    (root / "env/accounts.hcl").write_text(accounts)
    subprocess.run(["git", "init", "-q", str(root)], check=True)  # nosec B603 B607 -- literal argv, no shell

    # Every account id is configured, so no lookup may run: the stand-in
    # refuses every call and records it.
    log = tmp_path / "cli-calls.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    standin = bin_dir / "aws"
    standin.write_text(
        "#!/usr/bin/env bash\n"
        "printf '%%s\\n' \"$*\" >> \"%s\"\n"
        "echo 'stand-in: no CLI call is expected while the configuration is parsed' >&2\n"
        "exit 254\n" % log
    )
    standin.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    env = dict(os.environ)
    env["PATH"] = "%s%s%s" % (bin_dir, os.pathsep, env.get("PATH", ""))
    env["HOME"] = str(home)  # no ~/.aws of the host: the example's profile must not resolve
    env["TLZ_STATE_DIR"] = str(tmp_path / "state")
    env["TG_NON_INTERACTIVE"] = "true"
    env["TG_NO_COLOR"] = "true"
    for var in [v for v in env if v.startswith("AWS_")]:
        env.pop(var, None)
    return root, env, log


def _terragrunt(args, cwd, env, timeout=300):
    return subprocess.run(  # nosec B603 B607 -- argv list of literals, cwd inside the staged copy, no shell
        ["terragrunt", *args, "--log-level", "error"],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
    )


def _render(root, unit, env):
    proc = _terragrunt(["render", "--json"], root / unit, env)
    assert proc.returncode == 0, "%s: terragrunt render failed (rc=%d):\n%s" % (
        unit, proc.returncode, proc.stderr[-2000:],
    )
    return json.loads(proc.stdout)


def _json_objects(text):
    """Every top-level JSON object in `text` (render --all prints one per unit)."""
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


def _render_all(root, env):
    proc = _terragrunt(["render", "--all", "--json"], root / "stacks", env, timeout=900)
    assert proc.returncode == 0, "terragrunt render --all failed (rc=%d):\n%s" % (proc.returncode, proc.stderr[-3000:])
    objs = _json_objects(proc.stdout)
    assert len(objs) > 10, "render --all emitted %d objects:\n%s" % (len(objs), proc.stdout[:2000])
    return objs


def _provider(rendered):
    return rendered["generate"]["provider"]["contents"]


def _state_path(obj):
    return str(((obj.get("remote_state") or {}).get("config") or {}).get("path", ""))


# --- the mode on: the operator's chain ---------------------------------------


def test_management_units_run_as_the_operator_in_the_mode(tmp_path):
    root, env, _ = _stage(tmp_path, mode_on=True, backend="s3")
    providers = {u: _provider(_render(root, u, env)) for u in MANAGEMENT_UNITS}
    wrong = {u: p for u, p in providers.items() if p != PROVIDER_DIRECT}
    assert not wrong, (
        "with the deployment account on, a management-account unit must run as the operator's profile "
        "(deployment-role creates TLZDeploymentRole and cannot assume it), got:\n%s"
        % "\n".join("--- %s\n%s" % (u, p) for u, p in wrong.items())
    )
    assert _render(root, MANAGEMENT_UNITS[0], env)["exclude"]["if"] is False, "deployment-role runs in the mode"


def test_pipeline_unit_runs_in_the_deployment_account(tmp_path):
    root, env, _ = _stage(tmp_path, mode_on=True, backend="s3", pipeline_on=True)
    rendered = _render(root, PIPELINE_UNIT, env)
    assert rendered["exclude"]["if"] is False, "enable_pipeline = true must include the pipeline unit"
    assert _provider(rendered) == _provider_cross_account(STATE_ROLE_ARN), (
        "the pipeline unit must assume the deployment account's access role, or its bucket and roles "
        "land in the management account:\n%s" % _provider(rendered)
    )

    # Pipeline off: the sidecar yields no role and the unit stays out of the run.
    root, env, _ = _stage(tmp_path / "pipeline-off", mode_on=True, backend="s3")
    rendered = _render(root, PIPELINE_UNIT, env)
    assert rendered["exclude"]["if"] is True
    assert _provider(rendered) == PROVIDER_DIRECT


def test_every_s3_backend_assumes_the_deployment_accounts_access_role(tmp_path):
    root, env, log = _stage(tmp_path, mode_on=True, backend="s3", pipeline_on=True)
    objs = _render_all(root, env)

    s3_units = {o["remote_state"]["config"]["key"]: o["remote_state"]["config"] for o in objs
                if (o.get("remote_state") or {}).get("backend") == "s3"}
    assert len(s3_units) > 10, "render --all found %d units on the s3 backend" % len(s3_units)
    expected = {
        key: dict(_backend_default("stacks/" + key.rsplit("/", 1)[0]),
                  assume_role={"role_arn": STATE_ROLE_ARN, "session_name": "tlz-state"})
        for key in s3_units
    }
    wrong = {k: c for k, c in s3_units.items() if c != expected[k]}
    assert not wrong, (
        "every s3 backend must carry the profile and assume_role { role_arn, session_name } into the "
        "deployment account's access role and no top-level role_arn (Terraform refuses it at init):\n%s"
        % json.dumps(wrong, indent=2, sort_keys=True)
    )

    # One bucket per deployment: in the mode it is the deployment account's.
    boot = {name: [o for o in objs if _state_path(o).endswith("/%s/bootstrap/terraform.tfstate" % name)]
            for name in ("management", "deployment")}
    assert boot["management"] and boot["deployment"], "render --all emitted no object for a bootstrap unit"
    assert all(o["exclude"]["if"] is True for o in boot["management"]), (
        "stacks/management/bootstrap must be excluded in the mode: it would create a second bucket of the same name"
    )
    assert all(o["exclude"]["if"] is False for o in boot["deployment"]), "stacks/deployment/bootstrap runs in the mode"

    # No parse-time CLI call: a pipeline container has no aws binary, and every id is configured.
    calls = log.read_text() if log.exists() else ""
    assert calls == "", "the stand-in aws was called while the configuration was parsed:\n%s" % calls


def test_init_in_the_mode_fails_on_the_missing_profile_not_on_the_backend_shape(tmp_path):
    if shutil.which("terraform") is None:
        pytest.skip("terraform not on PATH: init is what refuses or accepts the generated backend.tf")
    root, env, _ = _stage(tmp_path, mode_on=True, backend="s3")
    proc = _terragrunt(["init"], root / MANAGEMENT_UNITS[0], env, timeout=600)
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, "init with a profile that does not exist must fail:\n%s" % combined[-2000:]
    assert "Unsupported argument" not in combined, (
        "Terraform refused the generated backend.tf (the s3 backend has no top-level role_arn):\n%s" % combined[-3000:]
    )
    assert "failed to get shared config profile" in combined, (
        "the first failure must be the missing profile %r, not the backend shape:\n%s" % (PROFILE, combined[-3000:])
    )


def test_mode_on_without_the_deployment_account_id_is_refused_when_parsed(tmp_path):
    root, env, _ = _stage(tmp_path, mode_on=True, backend="s3", deployment_id="")
    proc = _terragrunt(["render", "--json"], root / MANAGEMENT_UNITS[2], env)
    assert proc.returncode != 0, "an empty deployment_account_id rendered a backend with an empty account in its role ARN"
    assert "deployment_account_id in env/accounts.hcl is empty" in proc.stderr, proc.stderr[-2000:]


# --- the mode off: nothing changes --------------------------------------------


@pytest.mark.parametrize("backend", ["local", "s3"])
def test_mode_off_renders_the_previous_releases_provider_and_backend(tmp_path, backend):
    root, env, log = _stage(tmp_path, mode_on=False, backend=backend)
    unit = "stacks/management/organization"
    rendered = _render(root, unit, env)
    assert _provider(rendered) == PROVIDER_DIRECT, "provider.tf of a management unit changed:\n%s" % _provider(rendered)
    config = rendered["remote_state"]["config"]
    if backend == "s3":
        assert config == _backend_default(unit), "the s3 backend of the default path changed: %r" % config
    else:
        assert config == {"path": "%s/management/organization/terraform.tfstate" % env["TLZ_STATE_DIR"]}, config

    cross = _render(root, CROSS_ACCOUNT_UNIT, env)
    assert _provider(cross) == _provider_cross_account(
        "arn:aws:iam::%s:role/%s" % (ACCOUNT_IDS["audit_account_id"], ACCESS_ROLE)
    ), "provider.tf of a cross-account unit changed:\n%s" % _provider(cross)
    pipeline = _render(root, PIPELINE_UNIT, env)
    assert pipeline["exclude"]["if"] is True and _provider(pipeline) == PROVIDER_DIRECT, (
        "with the pipeline off its unit must stay excluded and keep the default provider"
    )
    assert not log.exists() or log.read_text() == "", "a CLI call ran while the configuration was parsed"
