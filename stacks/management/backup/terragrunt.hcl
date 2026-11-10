# Backup — AWS Backup Vaults

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

exclude {
  if      = length(local.common.locals.backup_vaults) == 0
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/backup"
}

dependency "accounts" {
  config_path = "../accounts"

  mock_outputs = {
    active_account_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  backup_vaults = local.common.locals.backup_vaults
  account_ids   = dependency.accounts.outputs.active_account_ids
}
