# Customizations — User-Defined CloudFormation Stacks and StackSets
#
# Deploys the cloudformation_stacks and cloudformation_stack_sets entries of
# env/common.hcl through customizations/cloudformation. Each entry carries its
# template either inline (template_body) or as a repo-relative file path
# (template); the path form is read here, so the module always receives the
# template as a string.
include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

exclude {
  if      = !try(local.common.locals.enable_cloudformation_customizations, false)
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}/customizations/cloudformation"
}

dependency "accounts" {
  config_path = "../../accounts"
  mock_outputs = {
    active_account_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# Organization: supplies the OU name map so a stack set may name its
# deployment targets by OU name instead of raw ou- ID. Empty map as mock
# output — the module default, so validate and plan behave before the first
# apply exactly as they would without the wiring.
dependency "organization" {
  config_path = "../../organization"
  mock_outputs = {
    ou_name_to_id = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  region        = local.common.locals.region
  default_tags  = local.common.locals.default_tags
  account_ids   = dependency.accounts.outputs.active_account_ids
  ou_name_to_id = dependency.organization.outputs.ou_name_to_id

  cloudformation_stacks = [
    for s in try(local.common.locals.cloudformation_stacks, []) : merge(s, {
      template_body = try(s.template_body, file("${get_repo_root()}/${s.template}"))
    })
  ]

  cloudformation_stack_sets = [
    for s in try(local.common.locals.cloudformation_stack_sets, []) : merge(s, {
      template_body = try(s.template_body, file("${get_repo_root()}/${s.template}"))
    })
  ]
}
