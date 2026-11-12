# Security Org Config from Audit Account — org-wide GuardDuty/SecurityHub/Macie/Detective
# Cross-account provider to Audit Account as Delegated Admin
#
# This stack configures org-wide security service enablement from the Audit
# account (delegated admin). It depends on management/security which registers
# the delegated admin for each service.
#
# With security_finding_consumers_in_audit (env/common.hcl, default true) this
# unit also runs the finding consumers of the administrator: the GuardDuty
# findings export and the Macie classification export into the central log
# bucket of management/logging, the Security Hub finding aggregator, the
# automation rules, the disabled controls and the enrolment of the existing
# accounts as Security Hub members. management/security then creates none of
# its own. With the switch false every consumer input below is empty and the
# consumers stay in the management account.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Cross-account access parameters, shared with stacks/root.hcl. The unit
  # declares no `generate "provider"` block of its own — two blocks of the
  # same name abort the configuration load for every command. The
  # account resolution sits in cross_account.hcl so that root.hcl and this file
  # read the same value.
  cross_account = read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl")
  account_id    = local.cross_account.locals.account_id

  partition = local.common.locals.partition

  # Where the finding consumers run: here, while the switch is on and the Audit
  # account resolves. Same expression as in stacks/management/security, which
  # creates its own consumers exactly when this is false.
  consumers_in_audit = try(local.common.locals.security_finding_consumers_in_audit, true) && local.account_id != ""

  # The management account becomes a Security Hub member of this administrator.
  # Its id comes from env/accounts.hcl when set there, otherwise from the
  # organization unit while it is included. With enable_organization = false
  # and the key empty nothing supplies it: the management account is not
  # enrolled (check security_hub_members_enrolled of the module warns when no
  # member is left at all).
  management_account_id_override = try(local.accounts.locals.management_account_id, "")
  read_organization              = local.consumers_in_audit && local.management_account_id_override == "" && local.common.locals.enable_organization
}

# Skip execution when the audit account ID is not available, and while
# management/security is switched off: that unit then has no outputs to read.
exclude {
  if      = local.account_id == "" || !local.common.locals.enable_security
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

# The central log bucket and its key: the export destinations of the finding
# consumers. Same mocks as in stacks/management/security — an empty bucket
# name creates no export on a plan before the logging unit exists.
dependency "logging" {
  config_path = "../../management/logging"

  mock_outputs = {
    central_log_bucket_name = ""
    kms_key_arn             = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# The accounts to enrol as Security Hub members. Warm accounts are no
# deployment targets, so the active set is read.
dependency "accounts" {
  config_path = "../../management/accounts"

  mock_outputs = {
    active_account_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# The management account id, read only while env/accounts.hcl leaves it empty.
# The accounts unit already depends on the organization unit, so the run
# order stays the same. Before its first apply the mock enrols no management
# account.
dependency "organization" {
  config_path = "../../management/organization"
  enabled     = local.read_organization

  mock_outputs = {
    master_account_id = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  # Service toggles — derived from management/security outputs
  enable_guardduty    = dependency.security.outputs.guardduty_detector_id != ""
  enable_security_hub = dependency.security.outputs.security_hub_arn != ""
  enable_macie        = local.compliance.locals.filtered_enable_macie
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

  # ---------------------------------------------------------------------------
  # Finding consumers of the administrator (see the header). The same loader
  # locals stacks/management/security reads; every value is empty while the
  # consumers stay in the management account.
  # ---------------------------------------------------------------------------
  central_log_bucket_name               = local.consumers_in_audit ? dependency.logging.outputs.central_log_bucket_name : ""
  guardduty_export_kms_key_arn          = local.consumers_in_audit ? dependency.logging.outputs.kms_key_arn : ""
  guardduty_export_frequency            = local.consumers_in_audit ? local.compliance.locals.guardduty_export_frequency : null
  guardduty_export_prefix               = local.consumers_in_audit ? local.compliance.locals.guardduty_export_prefix : "guardduty/"
  macie_publish_sensitive_data_findings = local.consumers_in_audit ? local.compliance.locals.filtered_macie_publish_sensitive_data_findings : false

  enable_security_hub_region_aggregation = local.consumers_in_audit ? local.compliance.locals.enable_security_hub_region_aggregation : false
  security_hub_aggregation_regions       = local.consumers_in_audit ? local.compliance.locals.security_hub_aggregation_regions : []
  security_hub_automation_rules          = local.consumers_in_audit ? local.compliance.locals.security_hub_automation_rules : []
  security_hub_disabled_controls         = local.consumers_in_audit ? local.compliance.locals.security_hub_disabled_controls : []

  # Every active account and the management account become Security Hub
  # members of this administrator; the Audit account itself never does (the
  # module refuses it). The management account id comes from env/accounts.hcl,
  # or from the organization unit while that file leaves it empty (see locals).
  security_hub_member_account_ids = local.consumers_in_audit ? [
    for id in concat(
      values(dependency.accounts.outputs.active_account_ids),
      compact([
        local.management_account_id_override != "" ? local.management_account_id_override
        : local.read_organization ? dependency.organization.outputs.master_account_id : ""
      ]),
    ) : id if id != local.account_id
  ] : []
}
