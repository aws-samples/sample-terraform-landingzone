# OU Deployment — Backup Vaults
# Deploys the backup module into every account resolved from the
# ou_deployments["backup_vaults"] entry of env/common.hcl. Resolution
# (configurations/ou-membership.hcl): union of OU members (nested OUs roll
# up) and explicit accounts, minus excluded_accounts, deduplicated — at
# generate time, from the configured mapping (see docs/ou-deployment.md).
# Per resolved account this unit generates a provider alias (assume_role,
# pattern stacks/management/config-recorder-members) and one instantiation
# of modules/backup with a static provider assignment.
#
# inputs schema (ou_deployments["backup_vaults"].inputs):
#   vaults — list of vault definitions per modules/backup:backup_vaults

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  ou     = read_terragrunt_config(find_in_parent_folders("configurations/ou-membership.hcl"))

  partition    = local.common.locals.partition
  region       = local.common.locals.region
  role_name    = local.common.locals.account_access_role_name
  default_tags = local.common.locals.default_tags
  aws_profile  = local.common.locals.aws_profile

  enabled           = try(local.common.locals.enable_ou_deployment_backup_vaults, false)
  resolved_accounts = try(local.ou.locals.effective_accounts["backup_vaults"], [])
  vaults            = try(local.common.locals.ou_deployments["backup_vaults"].inputs.vaults, [])
}

# Switch off or an empty effective account set -> zero resources.
exclude {
  if      = !local.enabled || length(local.resolved_accounts) == 0
  actions = ["all"]
}

# Double-slash source: Terragrunt copies the repo tree into
# .terragrunt-cache and runs in this unit's directory inside the copy,
# so repo-relative module sources and their file() reads resolve.
terraform {
  source = "${get_repo_root()}//stacks/management/ou-deployment/backup-vaults"
}

# Ordering and plausibility only: the effective account set comes from the
# static resolution above, not from these outputs.
dependency "accounts" {
  config_path = "../../accounts"

  # The sentinel key marks these outputs as mocked for the warm-account
  # guard below; no account the accounts unit creates carries that name.
  mock_outputs = {
    active_account_ids = { "__tlz_mock_outputs__" = "000000000000" }
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

generate "providers" {
  path      = "providers.tf"
  if_exists = "overwrite_terragrunt"

  contents = join("\n\n", [for id in local.resolved_accounts :
    <<-EOF
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

generate "backup_vaults" {
  path      = "backup_vaults.tf"
  if_exists = "overwrite_terragrunt"

  contents = join("\n\n", concat(
    [for id in local.resolved_accounts :
      <<-EOF
      module "backup_${id}" {
        # Repo-relative source: the unit's double-slash terraform source
        # makes the copied repo tree the working root, so this path and
        # the module's repo-relative file() reads resolve inside the copy.
        source = "${get_path_to_repo_root()}/modules/backup"

        providers = {
          aws = aws.acct_${id}
        }

        backup_vaults = ${jsonencode(local.vaults)}
      }
      EOF
    ],
    [
      <<-EOF
      data "aws_partition" "current" {}

      # Blocking guard (warm-account exclusion): the lifecycle
      # precondition aborts plan and apply hard where a check block only
      # warned, so a warm account listed in env/accounts.hcl cannot be
      # deployed to past a warning. The partition clause anchors the
      # condition to an object in the configuration (Terraform rejects
      # all-literal preconditions; the lists are baked in at generate
      # time). Only the mocked outputs of a plan before the first
      # accounts apply pass unchecked, recognised by the sentinel key of
      # the mock above. A real empty active set (every account warm, or
      # targets the accounts unit does not create) is refused.
      resource "terraform_data" "warm_account_guard" {
        lifecycle {
          precondition {
            condition = data.aws_partition.current.partition != "" && (${jsonencode(contains(keys(dependency.accounts.outputs.active_account_ids), "__tlz_mock_outputs__"))} || alltrue([
              for id in ${jsonencode(local.resolved_accounts)} :
              contains(${jsonencode(sort(values(dependency.accounts.outputs.active_account_ids)))}, id)
            ]))
            error_message = "At least one resolved target account is not among the active account IDs of the accounts unit — warm or suspended accounts are excluded from deployment targets. Check env/accounts.hcl, warm flags, the OU of each account and the ou_deployments entry 'backup_vaults'."
          }
        }
      }
      EOF
    ],
  ))
}
