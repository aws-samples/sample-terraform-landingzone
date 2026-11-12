"""regression: eight ways the organization-wide plan and apply went wrong.

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
5. stacks/management/accounts could not plan before the organization unit had
   applied: its mock handed an empty OU map, so no account's OU resolved, and
   the module's deployment_account provider had no profile, so an operator
   who works through aws_profile alone had no credentials for it.
6. Units whose dependency was switched off stayed in the first apply:
   management/cur read the outputs of the excluded logging unit, the
   config-recorder sidecars those of logging, audit/security-org-config those
   of security, and each failed with "detected no outputs". The units now
   follow the toggle of their dependency (cur no longer reads logging at all),
   and security-org-config reads the merged Macie switch, so an operator file
   without ``enable_macie`` still renders.
7. stacks/management/networking waited for config-rules although it reads
   none of its outputs, which put networking, iam and every unit after them
   two levels later in the organization run.
8. The finding consumers (GuardDuty export, Macie export, Security Hub
   aggregator and automation rules) ran in the management account, where they
   see that account's findings only. With ``security_finding_consumers_in_audit``
   (default true) and a resolved Audit account, management/security creates
   none of them, audit/security-org-config carries the rules, the export and
   the member list without the Audit account, and audit/monitoring alerts on
   them after it; with the switch off every Audit input is empty, the Audit
   monitoring unit is excluded and the management unit keeps today's layout.

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
    # The pipeline's sidecar builds its role from env/accounts.hcl alone and makes no lookup.
    units = sorted(
        p.parent.relative_to(root).as_posix()
        for p in (root / "stacks").rglob("cross_account.hcl")
        if "ssm get-parameter" in p.read_text()
    )
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


def test_regression_accounts_unit_plans_before_the_organization_exists(tmp_path):
    root, env, _ = _stage(tmp_path)
    rendered = _render(root, "stacks/management/accounts", env)
    common = rendered["locals"]["common"]["locals"]
    inputs = rendered["inputs"]
    assert common["aws_profile"] and inputs.get("aws_profile") == common["aws_profile"], (
        "the accounts unit must hand aws_profile to the module's deployment_account provider"
    )
    assert "deployment_provider" not in rendered["generate"], "the unused 'deployment' provider alias is generated again"
    mock = rendered["dependency"]["organization"]["mock_outputs"]["ou_name_to_id"]
    assert sorted(mock) == sorted(ou["name"] for ou in common["organizational_units"]), (
        "the first plan's mock must name every declared OU, or the accounts' OUs do not resolve: %r" % mock
    )
    assert all(re.fullmatch(r"ou-[a-z0-9]+-[a-z0-9]+", v) for v in mock.values()), mock


# Units that read the outputs of a toggled unit, with the toggle of that unit.
TOGGLED_DEPENDENCY_UNITS = {
    "stacks/audit/config-recorder": "enable_logging",
    "stacks/log-archive/config-recorder": "enable_logging",
    "stacks/workload-dev/config-recorder": "enable_logging",
    "stacks/audit/security-org-config": "enable_security",
}


def _switch_on(root, toggle):
    path = root / "env/common.hcl"
    text, n = re.subn(r"^(\s*%s\s*=\s*)false\b" % toggle, r"\1true", path.read_text(), flags=re.MULTILINE)
    assert n == 1, "env/common.hcl: no single '%s = false' line to switch on" % toggle
    path.write_text(text)


def test_regression_first_apply_skips_units_whose_dependency_is_off(tmp_path):
    # The stand-in aws resolves every account id: the state of the second pass.
    root, env, _ = _stage(tmp_path)
    excluded = {u: _render(root, u, env)["exclude"]["if"] for u in TOGGLED_DEPENDENCY_UNITS}
    assert excluded == {u: True for u in TOGGLED_DEPENDENCY_UNITS}, (
        "with the dependency's toggle off these units still run and fail with 'detected no outputs': %r"
        % sorted(u for u, off in excluded.items() if not off)
    )
    cur = _render(root, "stacks/management/cur", env)
    assert cur["exclude"]["if"] is False, "the example ships the Cost and Usage Report on"
    assert not cur.get("dependency"), (
        "management/cur reads outputs of %s; with the dedicated bucket it needs none, and an "
        "excluded dependency has no outputs to read on apply" % sorted(cur["dependency"])
    )
    for toggle in sorted(set(TOGGLED_DEPENDENCY_UNITS.values())):
        _switch_on(root, toggle)
    included = {u: _render(root, u, env)["exclude"]["if"] for u in TOGGLED_DEPENDENCY_UNITS}
    assert included == {u: False for u in TOGGLED_DEPENDENCY_UNITS}, (
        "with the toggles on and the account ids resolved every unit must run: %r" % included
    )


def test_regression_security_org_config_reads_the_merged_macie_switch(tmp_path):
    root, env, _ = _stage(tmp_path)
    _rewrite(root / "env/common.hcl", "  enable_macie           = false\n", "")
    inputs = _render(root, "stacks/audit/security-org-config", env)["inputs"]
    assert inputs["enable_macie"] is True, (
        "without enable_macie in env/common.hcl the base value (true) applies, as in "
        "management/security; got %r" % inputs["enable_macie"]
    )


def test_regression_networking_does_not_wait_on_config_rules(tmp_path):
    root, env, _ = _stage(tmp_path)
    proc = subprocess.run(  # nosec B603 B607 -- argv list of literals, cwd inside the staged copy, no shell
        ["terragrunt", "find", "--dependencies", "--json", "--log-level", "error"],
        cwd=root / "stacks", env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, "terragrunt find failed (rc=%d):\n%s" % (proc.returncode, proc.stderr[-2000:])
    deps = {u["path"]: set(u.get("dependencies") or []) for u in json.loads(proc.stdout)}
    assert "management/config-rules" not in deps["management/networking"], (
        "networking waits on config-rules again: %s" % sorted(deps["management/networking"])
    )
    # The edges that stay: networking's real inputs, and the two ordering edges kept on purpose.
    assert {"management/accounts", "management/logging", "management/security"} <= deps["management/networking"]
    assert "management/security" in deps["management/iam"]
    assert "audit/security-config" in deps["management/config-rules"]


def _dependencies(root, env):
    proc = subprocess.run(  # nosec B603 B607 -- argv list of literals, cwd inside the staged copy, no shell
        ["terragrunt", "find", "--dependencies", "--json", "--log-level", "error"],
        cwd=root / "stacks", env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, "terragrunt find failed (rc=%d):\n%s" % (proc.returncode, proc.stderr[-2000:])
    return {u["path"]: set(u.get("dependencies") or []) for u in json.loads(proc.stdout)}


def test_regression_finding_consumers_follow_the_switch(tmp_path):
    root, env, _ = _stage(tmp_path)
    for toggle in ("enable_logging", "enable_security", "enable_monitoring"):
        _switch_on(root, toggle)
    # The Audit account resolves on both sides with the same placeholder: env/accounts.hcl
    # for the management units, the stand-in SSM answer for the Audit units. The management
    # account and one more active account give the member list something to carry.
    accounts = root / "env/accounts.hcl"
    _rewrite(accounts, 'audit_account_id       = ""', 'audit_account_id       = "%s"' % PLACEHOLDER_ID)
    _rewrite(accounts, 'management_account_id  = ""', 'management_account_id  = "123456789012"')
    org_unit = root / "stacks/audit/security-org-config/terragrunt.hcl"
    _rewrite(org_unit, "active_account_ids = {}", 'active_account_ids = { Audit = "%s", Workload = "444455556666" }' % PLACEHOLDER_ID)

    security = _render(root, "stacks/management/security", env)["inputs"]
    assert security["manage_finding_consumers"] is False, (
        "with the switch on and the Audit account resolved, management/security still creates the consumers"
    )
    org = _render(root, "stacks/audit/security-org-config", env)["inputs"]
    assert org["security_hub_automation_rules"] and org["security_hub_automation_rules"] == security["security_hub_automation_rules"], (
        "audit/security-org-config must carry the same automation rules the management unit reads from the loader"
    )
    assert org["guardduty_export_frequency"] == security["guardduty_export_frequency"] != None  # noqa: E711 -- rendered JSON null
    assert sorted(org["security_hub_member_account_ids"]) == ["123456789012", "444455556666"], (
        "the member list must carry every active account and the management account, never the Audit account: %r"
        % org["security_hub_member_account_ids"]
    )
    monitoring = _render(root, "stacks/audit/monitoring", env)
    assert monitoring["exclude"]["if"] is False, "audit/monitoring must run with the switch on"
    assert monitoring["inputs"]["dashboard_name"] != "TLZ-Landing-Zone-Health", "the Audit dashboard must not adopt the management one"
    deps = _dependencies(root, env)
    assert "audit/security-org-config" in deps["audit/monitoring"], (
        "audit/monitoring must run after audit/security-org-config: %s" % sorted(deps["audit/monitoring"])
    )

    _rewrite(root / "env/common.hcl", "security_finding_consumers_in_audit = true", "security_finding_consumers_in_audit = false")
    security = _render(root, "stacks/management/security", env)["inputs"]
    assert security["manage_finding_consumers"] is True, "with the switch off the consumers must stay in management/security"
    org = _render(root, "stacks/audit/security-org-config", env)["inputs"]
    empty = {
        "security_hub_automation_rules": [], "security_hub_disabled_controls": [], "security_hub_member_account_ids": [],
        "security_hub_aggregation_regions": [], "enable_security_hub_region_aggregation": False,
        "macie_publish_sensitive_data_findings": False, "guardduty_export_frequency": None,
        "central_log_bucket_name": "", "guardduty_export_kms_key_arn": "",
    }
    assert {k: org[k] for k in empty} == empty, "with the switch off every consumer input of audit/security-org-config must be empty"
    assert _render(root, "stacks/audit/monitoring", env)["exclude"]["if"] is True, "audit/monitoring must be excluded with the switch off"


def test_regression_management_account_is_a_member_without_accounts_hcl(tmp_path):
    """The guide leaves management_account_id empty; the member list reads the organization unit."""
    root, env, _ = _stage(tmp_path)
    for toggle in ("enable_logging", "enable_security"):
        _switch_on(root, toggle)
    accounts = root / "env/accounts.hcl"
    _rewrite(accounts, 'audit_account_id       = ""', 'audit_account_id       = "%s"' % PLACEHOLDER_ID)
    org_unit = root / "stacks/audit/security-org-config/terragrunt.hcl"
    # The organization unit's output after its apply, in place of the empty first-plan mock.
    _rewrite(org_unit, 'master_account_id = ""', 'master_account_id = "123456789012"')
    _rewrite(org_unit, "active_account_ids = {}", 'active_account_ids = { Audit = "%s", Workload = "444455556666" }' % PLACEHOLDER_ID)

    org = _render(root, "stacks/audit/security-org-config", env)["inputs"]
    assert sorted(org["security_hub_member_account_ids"]) == ["123456789012", "444455556666"], (
        "with env/accounts.hcl as the guide leaves it, the member list must carry the management account "
        "from the organization unit and never the Audit account: %r" % org["security_hub_member_account_ids"]
    )

    # Without the organization unit nothing supplies the id. A configuration that planned
    # before still renders: the dependency is off, the management account is not enrolled,
    # and env/accounts.hcl fills it.
    _rewrite(root / "env/common.hcl", "enable_organization            = true", "enable_organization            = false")
    rendered = _render(root, "stacks/audit/security-org-config", env)
    assert rendered["exclude"]["if"] is False, "the unit must still run with the organization unit excluded"
    assert rendered["inputs"]["security_hub_member_account_ids"] == ["444455556666"], rendered["inputs"]["security_hub_member_account_ids"]
    _rewrite(accounts, 'management_account_id  = ""', 'management_account_id  = "123456789012"')
    org = _render(root, "stacks/audit/security-org-config", env)["inputs"]
    assert sorted(org["security_hub_member_account_ids"]) == ["123456789012", "444455556666"], org["security_hub_member_account_ids"]
