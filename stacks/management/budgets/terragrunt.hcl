# Budgets — AWS Budget for cost monitoring

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

exclude {
  if      = !local.common.locals.enable_budgets
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/budgets"
}

inputs = {
  enable_budgets = local.common.locals.enable_budgets
  budget_config  = local.common.locals.budget_config
  # Further budgets beside the primary one; entries with deployment_targets
  # are created by the per-account budgets units (stacks/<account>/budgets).
  additional_budgets = try(local.common.locals.additional_budgets, [])
  default_tags       = local.common.locals.default_tags
}
