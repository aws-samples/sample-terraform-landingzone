# Firewall appliances — third-party firewall instances, manager nodes and
# auto-scaling fleets behind the gateway load balancer (modules/ec2-compute)
#
# The networking dependency supplies the resolution maps (subnets, security
# groups, target groups of the gateway load balancer); the security dependency
# supplies the firewall configuration bucket, which every user-data template
# can reference through the built-in placeholders config_bucket and
# config_bucket_arn. User-data templates travel as strings through the loader
# (user_data_template inline or user_data_template_file resolved there).

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

exclude {
  if      = !try(local.common.locals.enable_firewall_appliances, false)
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/ec2-compute"
}

dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    subnet_ids             = {}
    security_group_ids     = {}
    target_group_arns      = {}
    gwlb_target_group_arns = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "security" {
  config_path = "../security"

  mock_outputs = {
    firewall_config_bucket_name = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  enable_ec2_compute = try(local.common.locals.enable_firewall_appliances, false)

  # Launch templates from the loader: user_data_template_file entries are
  # resolved to their content there, so the module receives strings only.
  launch_templates                     = local.compliance.locals.firewall_launch_templates
  imdsv1_acknowledged_launch_templates = local.compliance.locals.firewall_imdsv1_acknowledged_launch_templates
  autoscaling_groups                   = try(local.common.locals.firewall_autoscaling_groups, {})
  instances                            = try(local.common.locals.firewall_instances, {})

  # SSM building blocks: appliance configuration documents (content as
  # configuration strings) and their associations, targeted at the instances
  # of this stack by key or by tag.
  ssm_documents    = try(local.common.locals.firewall_ssm_documents, {})
  ssm_associations = try(local.common.locals.firewall_ssm_associations, {})

  # Resolution maps from the networking stack: entries reference subnets,
  # security groups and target groups by these names. The GWLB target groups
  # carry the appliance fleet; the generic target groups stay available for
  # manager fleets behind an NLB/ALB.
  subnet_ids         = dependency.networking.outputs.subnet_ids
  security_group_ids = dependency.networking.outputs.security_group_ids
  target_group_arns = merge(
    dependency.networking.outputs.target_group_arns,
    dependency.networking.outputs.gwlb_target_group_arns,
  )

  # Firewall configuration bucket (modules/security): reachable in every
  # user-data template as config_bucket / config_bucket_arn.
  config_bucket_name = dependency.security.outputs.firewall_config_bucket_name

  default_tags = local.common.locals.default_tags
}
