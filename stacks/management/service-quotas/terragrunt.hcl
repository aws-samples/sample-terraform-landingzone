# Service Quotas — Automated service quota increase requests

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

exclude {
  if      = length(try(local.common.locals.service_quota_increases, [])) == 0
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/service-quotas"
}

inputs = {
  service_quota_increases = local.common.locals.service_quota_increases
}
