# Accounts — Account creation with OU resolution and SSO

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Accounts that already exist and that this module does not create, keyed by
  # account name — see the comment at inputs.account_ids below. Entries without
  # an ID are dropped: an empty ID would satisfy check "ic_accounts_exist" for a
  # name that resolves to nothing.
  external_account_ids = {
    for name, id in local.accounts.locals.workload_accounts : name => id
    if id != ""
  }
}

exclude {
  if      = !local.common.locals.enable_accounts
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/accounts"

  # AWS Organizations allows max 5 concurrent CreateAccount requests.
  extra_arguments "parallelism" {
    commands  = ["apply", "destroy"]
    arguments = ["-parallelism=5"]
  }
}

# The accounts module requires aws.deployment provider alias (for SSM params in Deployment Account).
# When deployment account is disabled, this alias points to the same account as the default provider.
generate "deployment_provider" {
  path      = "deployment-provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<-EOF
    provider "aws" {
      alias   = "deployment"
      region  = "${local.common.locals.region}"
      profile = "${local.common.locals.aws_profile}" != "" ? "${local.common.locals.aws_profile}" : null

      default_tags {
        tags = ${jsonencode(local.common.locals.default_tags)}
      }
    }
  EOF
}

dependency "organization" {
  config_path = "../organization"

  mock_outputs = {
    ou_name_to_id = {}
    scp_ids       = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "control_tower" {
  config_path  = "../control-tower"
  skip_outputs = true
  # CT is optional — when skipped, this dependency is ignored
}

inputs = {
  organization_root_id = "" # the module falls back to a data source
  ou_name_to_id        = dependency.organization.outputs.ou_name_to_id
  accounts             = local.common.locals.accounts
  # Two roles: account_access_role_name is the role the stacks and
  # the module's deployment-account provider ASSUME to reach existing accounts;
  # created_account_role_name is the role CreateAccount makes INSIDE a new
  # member account. Optional key -- absent (null) means the same name as
  # account_access_role_name.
  account_access_role_name  = local.common.locals.account_access_role_name
  created_account_role_name = try(local.common.locals.created_account_role_name, null)
  close_on_deletion         = local.common.locals.close_on_deletion
  # Sign-in alias of the management account (the account this stack runs in).
  management_account_alias        = try(local.common.locals.management_account_alias, "")
  default_tags                    = local.common.locals.default_tags
  enable_sso_assignment           = local.common.locals.enable_sso_assignment
  sso_permission_set_name         = local.common.locals.sso_permission_set_name
  sso_principal_type              = local.common.locals.sso_principal_type
  sso_principal_name              = local.common.locals.sso_principal_name
  enable_deployment_account       = local.common.locals.enable_deployment_account
  deployment_account_id           = local.accounts.locals.deployment_account_id
  region                          = local.common.locals.region
  enable_control_tower_enrollment = try(local.common.locals.enable_control_tower_enrollment, false)
  enable_account_warming          = try(local.common.locals.enable_account_warming, false)

  # Identity Center permission sets and assignments. The module implements the
  # whole feature (modules/accounts/sso.tf); these two collections are the only
  # input path to aws_ssoadmin_permission_set.ic and
  # aws_ssoadmin_account_assignment.ic.
  identity_center_permission_sets = local.compliance.locals.identity_center_permission_sets
  identity_center_assignments     = local.compliance.locals.identity_center_assignments

  # Name resolution for the assignment targets. This must NOT be
  # dependency.accounts.outputs.account_ids: this unit *is* the accounts unit,
  # so that would be a dependency on itself. It would also be redundant —
  # local.ic_account_ids in modules/accounts/sso.tf already merges
  # aws_organizations_account.this by name, which is exactly what the
  # account_ids output exposes. What the module cannot know is the accounts it
  # does not create; those come from env/accounts.hcl.
  #
  # Limit worth knowing: env/accounts.hcl records the four core accounts
  # (management, audit, log-archive, deployment) by ID only, without an account
  # name, and var.account_ids is keyed by name. Only workload_accounts is
  # name-keyed, so only it can be passed here.
  account_ids = local.external_account_ids
}

# Resource adoption: declarative import blocks rendered from the adoption
# list (configurations/base/resource-adoptions.json, loader local
# adoption_imports_by_stack). One import block per entry of this stack; an
# empty adoption list renders no blocks and leaves the plan unchanged. An
# existing account is invited by hand once (docs/resource-adoption.md) and
# then adopted here into aws_organizations_account.this["<name>"].
generate "imports" {
  path      = "adoption-imports.tf"
  if_exists = "overwrite_terragrunt"
  contents = lookup(
    local.compliance.locals.adoption_imports_by_stack,
    "management/accounts",
    "# No adoption entries for this stack (configurations/base/resource-adoptions.json).\n",
  )
}
