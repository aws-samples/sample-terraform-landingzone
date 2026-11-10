# Budgets in the Workload-Dev account (cross-account)
# Template for additional accounts: copy this directory together with
# cross_account.hcl — the account name is derived from the directory name.
#
# The unit selects itself: it runs only when at least one budget of the
# configuration (budget_config or an additional_budgets entry) lists this
# account's directory name in its deployment_targets. The module then creates
# exactly the budgets that list this account.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))

  # Cross-account access parameters, shared with stacks/root.hcl (same
  # sidecar contract as the config-recorder units): root.hcl reads
  # cross_account.hcl and generates the provider with the assume-role ARN.
  cross_account = read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl")
  account_id    = local.cross_account.locals.account_id

  # Budget deployment_targets and the module input deployment_account_name
  # carry the stack DIRECTORY name ("workload-dev") — modules/budgets
  # validates exactly this lowercase form. This is deliberately distinct
  # from the account-NAME contract ("Workload-Dev") that cross_account.hcl
  # derives for SSM discovery and workload_accounts override keys.
  dir_name = local.cross_account.locals.dir_name

  # Every deployment target named anywhere in the budget configuration. The
  # unit is excluded unless its own directory name appears here.
  budget_deployment_targets = distinct(concat(
    try(local.common.locals.budget_config.deployment_targets, []),
    flatten([
      for budget in try(local.common.locals.additional_budgets, []) :
      try(budget.deployment_targets, [])
    ]),
  ))
}

exclude {
  if = (
    local.account_id == ""
    || !try(local.common.locals.enable_budgets, false)
    || !contains(local.budget_deployment_targets, local.dir_name)
  )
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/budgets"
}

dependency "accounts" {
  config_path  = "../../management/accounts"
  skip_outputs = true
}

inputs = {
  enable_budgets     = try(local.common.locals.enable_budgets, false)
  budget_config      = try(local.common.locals.budget_config, {})
  additional_budgets = try(local.common.locals.additional_budgets, [])
  # The module filters the budget set down to the entries whose
  # deployment_targets list this account.
  deployment_account_name = local.dir_name
  default_tags            = local.common.locals.default_tags
}
