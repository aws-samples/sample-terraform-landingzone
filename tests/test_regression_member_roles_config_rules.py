"""regression: three gaps between the organization's policies and what the
stacks deploy, rendered offline with Terragrunt.

1. The organization backup policy runs every backup selection as
   ``Backup-Role`` in the member account, and no stack created that role in a
   member account. stacks/management/member-roles now calls
   modules/member-roles once per active account with the role list.
2. stacks/management/config-rules excluded every member account unless
   ``audit_account_id`` was typed into env/accounts.hcl; it now resolves the
   Audit account like the Audit recorder stack (accounts.hcl, else the SSM
   parameter /tlz/accounts/Audit/id).
3. The example env/common.hcl stripped the default security group of every
   account that turns networking on.

Staging, the stand-in ``aws`` and the render come from
tests/test_regression_org_apply_paths.py. No credentials, no AWS call.
"""

import re

import pytest

from test_regression_org_apply_paths import PLACEHOLDER_ID, REPO, _render, _rewrite, _stage
from test_regression_org_apply_paths import pytestmark as needs_terragrunt

ACCOUNT = "2222" + "22222222"
EXAMPLE_ACCOUNTS = 'active_account_ids    = {}'


def _hcl_list(text, key):
    """The first `key = [...]` list after the start of text."""
    match = re.search(r"\b%s\s*=\s*\[([^\]]*)\]" % re.escape(key), text)
    assert match, key
    return re.findall(r'"([^"]+)"', match.group(1))


def test_regression_example_keeps_the_default_security_group():
    common = (REPO / "env/common.hcl.example").read_text()
    assert re.search(r"^\s*delete_default_vpc\s*=\s*false\b", common, re.MULTILINE), (
        "env/common.hcl.example must ship delete_default_vpc = false"
    )


def test_regression_backup_role_targets_cover_the_backup_policy_targets():
    common = (REPO / "env/common.hcl.example").read_text()
    assert re.search(r"^\s*enable_member_roles\s*=\s*true\b", common, re.MULTILINE)
    role = common[common.index('name               = "Backup-Role"'):]
    role_targets = set(_hcl_list(role, "deployment_targets"))
    policy = common[common.index('name        = "primary-backup-plan"'):]
    policy_targets = set(_hcl_list(policy, "targets"))
    assert policy_targets and policy_targets <= role_targets, (
        "the backup policy is attached to %s but Backup-Role is deployed to %s"
        % (sorted(policy_targets), sorted(role_targets))
    )


@needs_terragrunt
def test_regression_member_roles_unit_calls_the_module_per_account(tmp_path):
    root, env, _ = _stage(tmp_path)
    unit = "stacks/management/member-roles"
    _rewrite(root / unit / "terragrunt.hcl", EXAMPLE_ACCOUNTS,
             'active_account_ids    = { "Workload-Dev" = "%s" }' % ACCOUNT)
    rendered = _render(root, unit, env)
    calls = rendered["generate"]["member_roles"]["contents"]
    assert 'module "acct_%s"' % ACCOUNT in calls
    assert re.search(r'source\s*=\s*"[^"]*/modules/member-roles"', calls)
    assert "providers = { aws = aws.acct_%s }" % ACCOUNT in calls
    providers = rendered["generate"]["providers"]["contents"]
    assert ":iam::%s:role/" % ACCOUNT in providers
    roles = {role["name"]: role for role in rendered["inputs"]["roles"]}
    assert "Infrastructure" in roles["Backup-Role"]["deployment_targets"]


@needs_terragrunt
@pytest.mark.parametrize(("ssm_answer", "excluded"), [(PLACEHOLDER_ID, []), (None, [ACCOUNT])])
def test_regression_config_rules_reads_the_audit_account_from_ssm(tmp_path, ssm_answer, excluded):
    root, env, _ = _stage(tmp_path)
    if ssm_answer is None:
        aws = tmp_path / "bin" / "aws"
        aws.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation'\n"
            "exit 254\n"
        )
    unit = "stacks/management/config-rules"
    _rewrite(root / unit / "terragrunt.hcl", "    account_ids        = {}",
             '    account_ids        = { "Workload-Dev" = "%s" }' % ACCOUNT)
    inputs = _render(root, unit, env)["inputs"]
    assert inputs["global_excluded_accounts"] == excluded
