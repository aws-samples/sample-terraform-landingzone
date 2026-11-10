include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

# ← Add your own toggle in env/common.hcl (e.g. enable_my_custom_module)
exclude {
  if      = !try(local.common.locals.enable_my_custom_module, false)
  actions = ["all"]
}

terraform {
  # ← Point to your own module under customizations/
  source = "${get_repo_root()}/customizations/_template"
}

dependency "networking" {
  config_path  = "../../networking"
  skip_outputs = true
  # ← Adjust dependency: which stack must run before yours?
}

dependency "accounts" {
  config_path = "../../accounts"
  mock_outputs = {
    active_account_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  region       = local.common.locals.region
  default_tags = local.common.locals.default_tags
  account_ids  = dependency.accounts.outputs.active_account_ids
}
