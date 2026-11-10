# Control Tower — optional Landing Zone (30-60 min on first apply)

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

exclude {
  if      = !local.common.locals.enable_control_tower
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/control-tower"
}

# Organization: supplies the OU IDs the control targets are built from. The
# dependency must not carry skip_outputs = true: ou_name_to_arn would stay empty
# and every control would get an OU *name* as target_identifier — a value
# Control Tower rejects.
dependency "organization" {
  config_path = "../organization"

  mock_outputs = {
    ou_name_to_id     = {}
    organization_id   = "o-mockorgid12"
    master_account_id = "000000000000"
    partition         = "aws"
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  audit_account_id       = local.accounts.locals.audit_account_id
  log_archive_account_id = local.accounts.locals.log_archive_account_id
  landing_zone_version   = local.common.locals.control_tower_version
  governed_regions       = local.common.locals.enabled_regions
  enable_identity_center = local.common.locals.enable_sso_assignment

  control_tower_controls = try(local.common.locals.control_tower_controls, [])
  # Organization-wide CloudTrail of the landing zone (manifest field
  # centralizedLogging.enabled). true — the value the manifest always carried.
  enable_organization_trail = try(local.common.locals.enable_organization_trail, true)
  auto_enroll_ous           = try(local.common.locals.auto_enroll_ous, [])

  # Without these three inputs Control Tower would keep the two module defaults
  # of 365 days while the rest of the landing zone follows the merged log
  # retention — a contradiction in the compliance view.
  #
  # The two loader locals follow log_retention_days, so Control Tower never
  # holds a shorter period than the rest; env/common.hcl can raise them further
  # with the two keys of the same name (0 = no override).
  #
  # Boundary worth knowing: modules/control-tower validates 1 to 5475 days. The
  # longest framework retention is 2555, so the frameworks are safe — but a
  # value above 5475 in env/common.hcl wins the max() and is then rejected by
  # the module.
  logging_retention_days        = local.compliance.locals.control_tower_logging_retention_days
  access_logging_retention_days = local.compliance.locals.control_tower_access_logging_retention_days

  # The management account ID comes from env/accounts.hcl, not from the
  # configuration layer. Empty means "resolve via aws_caller_identity", which is
  # what the module did on its own before.
  management_account_id = local.accounts.locals.management_account_id

  # OU ARNs, assembled from the outputs of the organization module. The ARN of an
  # organizational unit is
  # arn:<partition>:organizations::<management-account>:ou/<org-id>/<ou-id>;
  # partition and account come from the module's own data sources, so no
  # partition is written here by hand.
  ou_name_to_arn = {
    for name, id in dependency.organization.outputs.ou_name_to_id :
    name => "arn:${dependency.organization.outputs.partition}:organizations::${dependency.organization.outputs.master_account_id}:ou/${dependency.organization.outputs.organization_id}/${id}"
  }
}
