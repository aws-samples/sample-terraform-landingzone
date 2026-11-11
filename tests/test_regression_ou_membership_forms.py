"""regression: two account-entry forms the accounts module accepts broke every OU-deployment unit.

configurations/ou-membership.hcl read ``organizational_unit_name`` of every
account entry as a plain OU name. A path such as ``"Workloads/Dev"`` (the form
docs/operations.md shows) was rejected as an undeclared OU, and an entry that
names only ``organizational_unit_id`` had no such attribute at all. Both
failures happen while the file is parsed, so ``terragrunt run --all`` stopped
before any unit ran. The module resolves a path through its last segment and
places an id-form entry by its id; the membership now follows the same rules.

The stack is rendered with Terragrunt from a staged copy of the tree (see
test_regression_org_apply_paths.py); nothing reaches AWS.
"""

from test_regression_org_apply_paths import PLACEHOLDER_ID, _render, _rewrite, _stage
from test_regression_org_apply_paths import pytestmark as needs_terragrunt  # noqa: F401

pytestmark = needs_terragrunt

UNIT = "stacks/management/ou-deployment/ssm-parameters"


def test_regression_ou_membership_accepts_path_and_id_forms(tmp_path):
    root, env, _ = _stage(tmp_path)
    common = root / "env/common.hcl"
    # Path form: the account lives in the nested OU Dev below Workloads.
    _rewrite(
        common,
        'organizational_unit_name = "Workloads"\n      tags                     = { AccountType = "Workload", Environment = "dev" }',
        'organizational_unit_name = "Workloads/Dev"\n      tags                     = { AccountType = "Workload", Environment = "dev" }',
    )
    # Id form: an entry placed by OU id, without an OU name.
    _rewrite(
        common,
        "  accounts = [\n",
        '  accounts = [\n    {\n      name                   = "Placed-By-Id"\n'
        '      email                  = "org+placed-by-id@example.com"\n'
        '      organizational_unit_id = "ou-abcd-12345678"\n    },\n',
    )
    _rewrite(common, "enable_ou_deployment_ssm_parameters   = false", "enable_ou_deployment_ssm_parameters   = true")
    _rewrite(
        common,
        "  ou_deployments = {}\n",
        '  ou_deployments = {\n    ssm_parameters = {\n      organizational_units = ["Dev"]\n'
        "      accounts             = []\n      excluded_accounts    = []\n"
        '      inputs               = { parameters = [{ name = "/tlz/example", type = "String", value = "x" }] }\n'
        "    }\n  }\n",
    )
    _rewrite(root / "env/accounts.hcl", "workload_accounts = {}", 'workload_accounts = { "Workload-Dev" = "%s" }' % PLACEHOLDER_ID)

    rendered = _render(root, UNIT, env)
    assert rendered["locals"]["resolved_accounts"] == [PLACEHOLDER_ID], (
        "the path-form account must join the membership of its leaf OU Dev: %r" % rendered["locals"]["resolved_accounts"]
    )
