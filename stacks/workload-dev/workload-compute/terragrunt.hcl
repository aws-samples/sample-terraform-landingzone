# Workload compute in the Workload-Dev account (cross-account) — launch
# templates and auto-scaling groups for workloads (modules/ec2-compute)
# Template for additional accounts: copy this directory together with
# cross_account.hcl — the account name is derived from the directory name.
#
# The management networking stack supplies the resolution maps (subnets,
# security groups, target groups of the application and network load
# balancers). User-data templates travel as strings through the loader
# (user_data_template inline or user_data_template_file resolved there).

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Cross-account access parameters, shared with stacks/root.hcl (same
  # sidecar contract as the config-recorder units).
  cross_account = read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl")
  account_id    = local.cross_account.locals.account_id
}

exclude {
  if = (
    local.account_id == ""
    || !try(local.common.locals.enable_workload_compute, false)
  )
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/ec2-compute"
}

dependency "networking" {
  config_path = "../../management/networking"

  mock_outputs = {
    subnet_ids         = {}
    security_group_ids = {}
    target_group_arns  = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  enable_ec2_compute = try(local.common.locals.enable_workload_compute, false)

  # Launch templates from the loader: user_data_template_file entries are
  # resolved to their content there, so the module receives strings only.
  launch_templates                     = local.compliance.locals.workload_launch_templates
  imdsv1_acknowledged_launch_templates = local.compliance.locals.workload_imdsv1_acknowledged_launch_templates
  autoscaling_groups                   = try(local.common.locals.workload_autoscaling_groups, {})

  # Resolution maps from the management networking stack: entries reference
  # subnets, security groups and target groups by these names.
  subnet_ids         = dependency.networking.outputs.subnet_ids
  security_group_ids = dependency.networking.outputs.security_group_ids
  target_group_arns  = dependency.networking.outputs.target_group_arns

  default_tags = local.common.locals.default_tags
}
