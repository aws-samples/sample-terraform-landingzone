"""regression: an account declared in the Suspended OU stayed a deployment target.

The example attaches the deny-all ``suspended-guardrails`` policy to the
Suspended OU and marks the OU ``ignore = true``, but nothing read the flag:
configurations/ou-membership.hcl joined every recorded account id into the
OU memberships, and the per-account sidecars (``stacks/*/*/cross_account.hcl``)
resolved every declared account. Every unit then assumed the access role in
the suspended account and every call was denied.

Pinned here, rendered with Terragrunt from a staged copy of the tree (harness
of test_regression_org_apply_paths.py; nothing reaches AWS):

* an account declared in ``Suspended`` with an id recorded in
  ``workload_accounts`` is absent from ``resolved_accounts`` of every
  ou-deployment unit, although the entry names the Suspended OU, and the unit
  is excluded;
* the per-account units of that account resolve ``account_id = ""`` and are
  excluded -- the directory-derived name of ``workload-dev/*`` (the networking
  unit of the workload account among them) and the literal name of
  ``audit/config-recorder`` alike;
* the undeclared-OU abort of the membership file still fires through a sidecar.

A control pass with the same account in ``Workloads`` shows the harness sees
the account at all.
"""

from test_regression_org_apply_paths import PLACEHOLDER_ID, _render, _rewrite, _stage
from test_regression_org_apply_paths import pytestmark as needs_terragrunt  # noqa: F401

pytestmark = needs_terragrunt

OU_DEPLOYMENT_ENTRIES = (
    "  ou_deployments = {\n"
    "    backup_vaults = {\n"
    '      organizational_units = ["Workloads", "Suspended"]\n'
    "      accounts             = []\n"
    "      excluded_accounts    = []\n"
    '      inputs               = { vaults = [{ name = "pin-vault" }] }\n'
    "    }\n"
    "    event_bus_policy = {\n"
    '      organizational_units = ["Workloads", "Suspended"]\n'
    "      accounts             = []\n"
    "      excluded_accounts    = []\n"
    '      inputs               = { policy = "{\\"Version\\":\\"2012-10-17\\",\\"Statement\\":[]}" }\n'
    "    }\n"
    "    service_quotas = {\n"
    '      organizational_units = ["Workloads", "Suspended"]\n'
    "      accounts             = []\n"
    "      excluded_accounts    = []\n"
    '      inputs               = { quota_increases = [{ service_code = "vpc", quota_code = "L-F678F1CE", desired_value = 10 }] }\n'
    "    }\n"
    "    ssm_parameters = {\n"
    '      organizational_units = ["Workloads", "Suspended"]\n'
    "      accounts             = []\n"
    "      excluded_accounts    = []\n"
    '      inputs               = { parameters = [{ name = "/tlz/example", type = "String", value = "x" }] }\n'
    "    }\n"
    "  }\n"
)

WORKLOAD_DEV_TAGS = '\n      tags                     = { AccountType = "Workload", Environment = "dev" }'
AUDIT_TAGS = '\n      tags                     = { AccountType = "Audit" }'


def _declared_in(tags, ou):
    return 'organizational_unit_name = "%s"%s' % (ou, tags)


def _stage_with_memberships(tmp_path):
    root, env, _ = _stage(tmp_path)
    common = root / "env/common.hcl"
    _rewrite(common, "  ou_deployments = {}\n", OU_DEPLOYMENT_ENTRIES)
    for key in ("backup_vaults", "event_bus_policy", "service_quotas", "ssm_parameters"):
        text = common.read_text()
        old = [l for l in text.splitlines() if l.lstrip().startswith("enable_ou_deployment_%s " % key)]
        assert len(old) == 1, "env/common.hcl: no single enable_ou_deployment_%s line" % key
        _rewrite(common, old[0], old[0].replace("= false", "= true", 1))
    _rewrite(root / "env/accounts.hcl", "workload_accounts = {}", 'workload_accounts = { "Workload-Dev" = "%s" }' % PLACEHOLDER_ID)
    return root, env


def _ou_deployment_units(root):
    units = sorted(p.parent.relative_to(root).as_posix() for p in (root / "stacks/management/ou-deployment").glob("*/terragrunt.hcl"))
    assert units, "no ou-deployment unit under stacks/management/ou-deployment: nothing to pin"
    return units


def _sidecar_units(root, account_dir):
    units = sorted(p.parent.relative_to(root).as_posix() for p in (root / "stacks" / account_dir).glob("*/cross_account.hcl"))
    assert units, "no stacks/%s/*/cross_account.hcl: nothing to pin" % account_dir
    return units


def test_regression_suspended_account_leaves_every_deployment_target(tmp_path):
    root, env = _stage_with_memberships(tmp_path)
    common = root / "env/common.hcl"
    ou_units = _ou_deployment_units(root)
    sidecar_units = _sidecar_units(root, "workload-dev") + ["stacks/audit/config-recorder"]
    # The networking unit arrived with its own copy of the sidecar; the glob
    # must see it, so a drift between the copies is caught below by name.
    assert "stacks/workload-dev/networking" in sidecar_units, sidecar_units

    # Control: declared in working OUs, the accounts are targets.
    resolved = {u: _render(root, u, env)["locals"]["resolved_accounts"] for u in ou_units}
    assert resolved == {u: [PLACEHOLDER_ID] for u in ou_units}, "control: the recorded account must join the memberships: %r" % resolved
    account_ids = {u: _render(root, u, env)["locals"]["account_id"] for u in sidecar_units}
    assert account_ids == {u: PLACEHOLDER_ID for u in sidecar_units}, "control: every sidecar must resolve the account: %r" % account_ids

    # The pin: the same accounts declared in the Suspended OU.
    _rewrite(common, _declared_in(WORKLOAD_DEV_TAGS, "Workloads"), _declared_in(WORKLOAD_DEV_TAGS, "Suspended"))
    _rewrite(common, _declared_in(AUDIT_TAGS, "Security"), _declared_in(AUDIT_TAGS, "Suspended"))
    problems = []
    for unit in ou_units:
        rendered = _render(root, unit, env)
        if rendered["locals"]["resolved_accounts"]:
            problems.append("%s: a suspended account is still a target: %r" % (unit, rendered["locals"]["resolved_accounts"]))
        if rendered["exclude"]["if"] is not True:
            problems.append("%s: not excluded although no account is left" % unit)
    for unit in sidecar_units:
        rendered = _render(root, unit, env)
        if rendered["locals"]["account_id"] != "":
            problems.append("%s: the sidecar resolves the suspended account %r" % (unit, rendered["locals"]["account_id"]))
        if rendered["exclude"]["if"] is not True:
            problems.append("%s: not excluded although its account is suspended" % unit)
    assert not problems, "\n".join(problems)

    # The membership file's undeclared-OU abort reaches the sidecars too.
    _rewrite(common, _declared_in(WORKLOAD_DEV_TAGS, "Suspended"), _declared_in(WORKLOAD_DEV_TAGS, "Nowhere"))
    proc = _render(root, "stacks/workload-dev/budgets", env, expect_ok=False)
    assert proc.returncode != 0, "an account in an undeclared OU rendered: %s" % proc.stdout[-500:]
    assert "missing from organizational_units" in proc.stderr and "Workload-Dev -> Nowhere" in proc.stderr, proc.stderr[-2000:]
