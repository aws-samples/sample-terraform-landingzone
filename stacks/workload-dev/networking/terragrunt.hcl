# Workload networking in the Workload-Dev account (cross-account) — the security
# groups, target groups and internal load balancers the workload account owns in
# the VPCs the management account shares with it (modules/workload-networking)
# Template for additional accounts: copy this directory together with
# cross_account.hcl — the account name is derived from the directory name.
#
# AWS fixes the split: an auto-scaling group, its target group and the load
# balancer in front of it must be in one account, and a participant of a shared
# VPC launches instances only with security groups it owns. The management
# networking stack keeps the VPC, the shared subnets and the share, and supplies
# their IDs here; the compute unit of this account (../workload-compute)
# resolves security groups and target groups by the names this unit publishes.
#
# One toggle gates both units, enable_workload_compute: the compute unit depends
# on this one, so it never reads an excluded dependency.

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
  source = "${get_repo_root()}//modules/workload-networking"
}

dependency "networking" {
  config_path = "../../management/networking"

  mock_outputs = {
    vpc_ids    = {}
    subnet_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "logging" {
  config_path = "../../management/logging"

  mock_outputs = {
    elb_log_bucket_name = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  enable = try(local.common.locals.enable_workload_compute, false)

  # Resolution maps from the management networking stack: the VPCs and the
  # subnets shared with this account, referenced by name in the entries.
  vpc_ids    = dependency.networking.outputs.vpc_ids
  subnet_ids = dependency.networking.outputs.subnet_ids

  # The collections of this account from the loader (env/common.hcl).
  security_groups = local.compliance.locals.workload_security_groups
  target_groups   = local.compliance.locals.workload_target_groups

  # Load balancers without an explicit access_logs block write their access
  # logs into the central ELB log bucket of the logging stack, as the
  # management networking stack does. An empty bucket name (enable_elb_log_bucket
  # off) leaves access logging to the per-LB configuration. Delivery from this
  # account depends on the bucket policy admitting it.
  load_balancers = [
    for lb in local.compliance.locals.workload_load_balancers :
    merge(lb, {
      access_logs = try(lb.access_logs, null) != null ? lb.access_logs : (
        dependency.logging.outputs.elb_log_bucket_name != "" ? {
          bucket  = dependency.logging.outputs.elb_log_bucket_name
          prefix  = lb.name
          enabled = true
        } : null
      )
    })
  ]

  default_tags = local.common.locals.default_tags
}
