# Directory configuration instance — declarative first-fill of an AWS Managed
# Microsoft AD (modules/ec2-compute)
#
# A single Windows instance joins the managed directory through the
# AWS-managed SSM document AWS-JoinDirectoryServiceDomain; the directory
# setup itself (users, groups, password policy) runs as aws_ssm_document
# entries whose PowerShell content is a configuration string, associated to
# the instance — no local-exec, no shell script in the repository, no
# external data source.
#
# Directory data (directory ID, domain name, DNS addresses) comes from the
# iam stack outputs (dependency "iam"), keyed by the directory name of the
# managed_active_directories entry. During validate/plan the mock outputs
# leave the lookups empty; at apply an empty directoryId fails visibly at the
# association — there is no silent fallback into a different directory.
#
# Operational boundary (docs/directory-config.md): Terraform manages the
# instance, the documents and the associations — not the objects that the
# setup scripts create inside the directory. Manual directory changes create
# no plan diff.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Key of the managed_active_directories entry (modules/iam) this instance
  # configures; resolves against the iam outputs below.
  directory_name = try(local.common.locals.directory_config_directory_name, "")

  instances     = try(local.common.locals.directory_config_instances, {})
  instance_keys = sort(keys(local.instances))
}

exclude {
  if      = !try(local.common.locals.enable_directory_config, false)
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/ec2-compute"
}

dependency "iam" {
  config_path = "../iam"

  mock_outputs = {
    managed_ad_ids           = {}
    managed_ad_dns_addresses = {}
    managed_ad_domain_names  = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    subnet_ids         = {}
    security_group_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  enable_ec2_compute = try(local.common.locals.enable_directory_config, false)

  # Launch template of the configuration instance (Windows AMI per entry);
  # user-data templates travel as strings through the loader.
  launch_templates                     = local.compliance.locals.directory_config_launch_templates
  imdsv1_acknowledged_launch_templates = local.compliance.locals.directory_config_imdsv1_acknowledged_launch_templates
  instances                            = local.instances

  # Directory setup as configuration strings: PowerShell documents plus their
  # associations (requirement: declarative, no script files).
  ssm_documents = try(local.common.locals.directory_config_ssm_documents, {})
  ssm_associations = merge(
    # Domain join through the AWS-managed document, fed from the iam outputs.
    local.directory_name != "" && length(local.instance_keys) > 0 ? {
      directory-domain-join = {
        document_name = "AWS-JoinDirectoryServiceDomain"
        parameters = {
          directoryId   = lookup(dependency.iam.outputs.managed_ad_ids, local.directory_name, "")
          directoryName = lookup(dependency.iam.outputs.managed_ad_domain_names, local.directory_name, "")
          dnsIpAddresses = join(",", sort(tolist(
            lookup(dependency.iam.outputs.managed_ad_dns_addresses, local.directory_name, [])
          )))
        }
        instance_keys = local.instance_keys
      }
    } : {},
    try(local.common.locals.directory_config_ssm_associations, {}),
  )

  # Resolution maps for the launch template's network interfaces.
  subnet_ids         = dependency.networking.outputs.subnet_ids
  security_group_ids = dependency.networking.outputs.security_group_ids

  default_tags = local.common.locals.default_tags
}
