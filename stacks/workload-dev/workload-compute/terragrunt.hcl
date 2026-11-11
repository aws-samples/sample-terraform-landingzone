# Workload compute in the Workload-Dev account (cross-account) — launch
# templates and auto-scaling groups for workloads (modules/ec2-compute)
# Template for additional accounts: copy this directory together with
# cross_account.hcl — the account name is derived from the directory name.
#
# Two stacks supply the resolution maps. The workload networking unit of this
# account (../networking) supplies the security groups and target groups: an
# auto-scaling group attaches only to a target group of its own account, and a
# participant of a shared VPC launches instances only with groups it owns. The
# management networking stack supplies the subnets, which stay management-owned
# and shared. User-data templates travel as strings through the loader
# (user_data_template inline or user_data_template_file resolved there).
#
# One toggle gates both units, enable_workload_compute, so the networking
# dependency is never an excluded unit.

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
    subnet_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "workload_networking" {
  config_path = "../networking"

  mock_outputs = {
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

  # Resolution maps: the shared subnets from the management networking stack
  # (keys vpc_name.subnet_name); the security groups (keys vpc_name.sg_name)
  # and target groups (names) from the workload networking unit of this
  # account.
  subnet_ids         = dependency.networking.outputs.subnet_ids
  security_group_ids = dependency.workload_networking.outputs.security_group_ids
  target_group_arns  = dependency.workload_networking.outputs.target_group_arns

  default_tags = local.common.locals.default_tags
}
