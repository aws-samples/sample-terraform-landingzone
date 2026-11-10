# Security Org Config from Audit Account — org-wide GuardDuty/SecurityHub/Macie/Detective
# Cross-account provider to Audit Account as Delegated Admin
#
# This stack configures org-wide security service enablement from the Audit
# account (delegated admin). It depends on management/security which registers
# the delegated admin for each service.

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

  partition = local.common.locals.partition
}

# Skip execution when audit account ID is not available
exclude {
  if      = local.account_id == ""
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/security-org-config"
}

dependency "security" {
  config_path = "../../management/security"

  mock_outputs = {
    guardduty_detector_id = ""
    security_hub_arn      = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  # Service toggles — derived from management/security outputs
  enable_guardduty    = dependency.security.outputs.guardduty_detector_id != ""
  enable_security_hub = dependency.security.outputs.security_hub_arn != ""
  enable_macie        = local.common.locals.enable_macie
  enable_detective    = try(local.common.locals.enable_detective, false)

  # Partition awareness
  is_eusc = local.partition == "aws-eusc"

  # GuardDuty feature toggles (module defaults apply when not set in common.hcl)
  guardduty_features = try(local.common.locals.guardduty_features, {})

  # GuardDuty target selection. Same loader local that
  # stacks/management/security reads for modules/security, so both modules take
  # exactly one path for the same target selection.
  guardduty_deployment_targets = local.compliance.locals.guardduty_deployment_targets

  # Security Hub standards from compliance loader
  security_hub_standards = local.compliance.locals.filtered_security_hub_standards
}
