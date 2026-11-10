# Deployment Role — creates TLZDeploymentRole in the Management Account
# Excluded when enable_deployment_account = false

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

exclude {
  if      = !local.common.locals.enable_deployment_account
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/deployment-role"
}

dependency "accounts" {
  config_path  = "../accounts"
  skip_outputs = true
}

inputs = {
  deployment_account_id = local.accounts.locals.deployment_account_id

  # The role name is a name given to this installation — there is nothing to
  # merge, so it comes straight from env/common.hcl.
  role_name = local.common.locals.deployment_role_name

  # Without this input the deployment role was created without a permissions
  # boundary, although the module offers the option. Empty means "no boundary",
  # which keeps the value effect-neutral until one is configured.
  permissions_boundary_arn = local.compliance.locals.deployment_role_permissions_boundary_arn

  # The narrow inline policy document (enumerated security-service
  # and Identity Center actions instead of `service:*`). The key is commented
  # out in env/common.hcl.example, so try() keeps the broad document for every
  # configuration that does not set it.
  narrow_grants = try(local.common.locals.deployment_role_narrow_grants, false)
}
