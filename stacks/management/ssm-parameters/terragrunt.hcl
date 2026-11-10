# SSM Parameters — AWS Systems Manager Parameter Store

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

exclude {
  if      = length(local.common.locals.ssm_parameters) == 0
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/ssm-parameters"
}

inputs = {
  ssm_parameters = local.common.locals.ssm_parameters
  default_tags   = local.common.locals.default_tags
}
