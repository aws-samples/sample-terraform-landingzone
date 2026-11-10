# Security baseline of the Audit account (password policy, EBS default
# encryption, S3 public access block and the other account-level settings of
# modules/security), applied through the cross-account provider.
#
# This unit makes no delegated-administrator registration and manages neither
# the GuardDuty detector nor the Security Hub account of the Audit account:
#   - RegisterDelegatedAdministrator and the services' EnableOrganizationAdminAccount
#     are accepted only from the management account. stacks/management/security
#     makes them; with audit_account_id set here the same calls would go out
#     from the Audit account and the apply would fail there.
#   - The Audit account's detector, Security Hub account and standards
#     subscriptions belong to stacks/audit/security-org-config (same toggles,
#     same account). Two states owning one account singleton collide.
# Every GuardDuty and Security Hub resource of modules/security waits on the
# delegated-administrator registration (depends_on chain in guardduty.tf and
# securityhub.tf), so this unit's state holds none of them: switching them off
# here destroys nothing.
# The module's check "audit_account_configured" warns on this unit's plan; the
# warning is expected here, the registration lives in the management unit.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Cross-account access parameters, shared with stacks/root.hcl. The unit
  # declares no `generate "provider"` block of its own — two blocks of the
  # same name abort the configuration load for every command. The
  # account resolution sits in cross_account.hcl so that root.hcl and this file
  # read the same value.
  cross_account = read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl")
  account_id    = local.cross_account.locals.account_id
}

exclude {
  if      = local.account_id == ""
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/security"
}

dependency "accounts" {
  config_path  = "../../management/accounts"
  skip_outputs = true
}

# Ordering only: the delegated-administrator registrations of the management
# unit come first.
dependency "security" {
  config_path  = "../../management/security"
  skip_outputs = true
}

inputs = {
  # Empty on purpose: audit_account_id is the only gate of the
  # delegated-administrator resources of modules/security (see the header).
  audit_account_id = ""
  # The Audit account's detector and Security Hub account are owned by
  # stacks/audit/security-org-config (see the header).
  enable_guardduty       = false
  enable_security_hub    = false
  enable_macie           = false
  enable_access_analyzer = false
  is_eusc                = local.common.locals.partition == "aws-eusc"

  password_policy = local.compliance.locals.password_policy
}
