# Service Catalog — Portfolios, Products, Sharing, Principal Associations

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

exclude {
  if      = !local.common.locals.enable_service_catalog
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/service-catalog"
}

dependency "accounts" {
  config_path  = "../accounts"
  skip_outputs = true
  # Service Catalog does not need outputs from Accounts — ordering dependency only
}

inputs = {
  portfolios = try(local.common.locals.service_catalog_portfolios, [])
}
