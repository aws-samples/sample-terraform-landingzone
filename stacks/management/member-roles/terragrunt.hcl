# Member Roles — the IAM roles and customer-managed policies of env/common.hcl
# whose deployment_targets name member accounts (by OU name, account name or
# account ID), created in those accounts from the Management Account.
# Backup-Role is the role the organization backup policy runs every backup
# selection as; EC2-Default-SSM-Role is the default instance role.
#
# Same shape as config-recorder-members: one generated provider per active
# account, assuming account_access_role_name there (a role the guardrail SCPs
# exempt), and one call of modules/member-roles per account. There is no
# terraform source block, so terragrunt copies only this directory into its
# cache; the generated module calls name the module by its path under the
# repository root. The role and policy lists reach the module as root
# variables, never as generated text.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  partition    = local.common.locals.partition
  region       = local.common.locals.region
  role_name    = local.common.locals.account_access_role_name
  default_tags = local.common.locals.default_tags
  aws_profile  = local.common.locals.aws_profile
}

exclude {
  if      = !try(local.common.locals.enable_member_roles, false)
  actions = ["all"]
}

dependency "accounts" {
  config_path = "../accounts"

  mock_outputs = {
    active_account_ids    = {}
    active_account_ou_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "organization" {
  config_path = "../organization"

  mock_outputs = {
    ou_name_to_id = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

generate "providers" {
  path      = "providers.tf"
  if_exists = "overwrite_terragrunt"

  contents = join("\n\n", [for name, id in dependency.accounts.outputs.active_account_ids :
    <<-EOF
    # ${name}
    provider "aws" {
      alias   = "acct_${id}"
      region  = "${local.region}"
      profile = "${local.aws_profile}" != "" ? "${local.aws_profile}" : null

      default_tags {
        tags = ${jsonencode(local.default_tags)}
      }

      assume_role {
        role_arn = "arn:${local.partition}:iam::${id}:role/${local.role_name}"
      }
    }
    EOF
  ])
}

generate "member_roles" {
  path      = "member_roles.tf"
  if_exists = "overwrite_terragrunt"

  contents = join("\n\n", concat(
    # Typed like the module's variables: Terraform reads a TF_VAR_ value of a
    # variable typed `any` as a plain string.
    [<<-EOF
    variable "roles" {
      type = list(object({
        name                          = string
        assume_role_policy            = string
        path                          = optional(string, "/")
        max_session_duration          = optional(number, 3600)
        managed_policy_arns           = optional(list(string), [])
        customer_managed_policy_names = optional(list(string), [])
        permissions_boundary          = optional(string, null)
        instance_profile              = optional(bool, false)
        inline_policies = optional(list(object({
          name   = string
          policy = string
        })), [])
        deployment_targets = optional(list(string), [])
      }))
      default = []
    }

    variable "customer_managed_policies" {
      type = list(object({
        name               = string
        policy             = string
        deployment_targets = optional(list(string), [])
      }))
      default = []
    }

    variable "ou_name_to_id" {
      type    = map(string)
      default = {}
    }

    variable "account_ou_ids" {
      type    = map(string)
      default = {}
    }
    EOF
    ],
    [for name, id in dependency.accounts.outputs.active_account_ids :
      <<-EOF
      # ${name}
      module "acct_${id}" {
        source    = "${get_repo_root()}/modules/member-roles"
        providers = { aws = aws.acct_${id} }

        account_name              = "${name}"
        account_id                = "${id}"
        account_ou_id             = lookup(var.account_ou_ids, "${name}", "")
        ou_name_to_id             = var.ou_name_to_id
        partition                 = "${local.partition}"
        roles                     = var.roles
        customer_managed_policies = var.customer_managed_policies
      }
      EOF
    ],
  ))
}

generate "outputs" {
  path      = "outputs.tf"
  if_exists = "overwrite_terragrunt"

  contents = <<-EOF
  output "role_arns" {
    description = "Map of account name to the roles created there (role name to ARN)"
    value = {
      ${join("\n    ", [for name, id in dependency.accounts.outputs.active_account_ids : "\"${name}\" = module.acct_${id}.role_arns"])}
    }
  }
  EOF
}

inputs = {
  # The same lists the iam stack creates in the management account: roles
  # from env/common.hcl, customer-managed policies from the loader (which
  # resolves __LOADER_INJECT__ documents). Entries without deployment_targets
  # stay in the management account only.
  roles                     = local.common.locals.roles
  customer_managed_policies = local.compliance.locals.customer_managed_policies
  ou_name_to_id             = dependency.organization.outputs.ou_name_to_id
  account_ou_ids            = dependency.accounts.outputs.active_account_ou_ids
}
