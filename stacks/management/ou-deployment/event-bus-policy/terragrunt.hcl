# OU Deployment — Default Event Bus Policy
# Applies a resource policy to the default EventBridge event bus of every
# account resolved from the ou_deployments["event_bus_policy"] entry of
# env/common.hcl. Resolution (configurations/ou-membership.hcl): union of
# OU members (nested OUs roll up) and explicit accounts, minus
# excluded_accounts, deduplicated — at generate time, from the configured
# mapping (see docs/ou-deployment.md).
# No module carries this single resource; like
# stacks/management/config-recorder-members, this unit generates the
# resources directly: per resolved account a provider alias (assume_role)
# and one aws_cloudwatch_event_bus_policy with a static provider assignment.
#
# inputs schema (ou_deployments["event_bus_policy"].inputs):
#   policy — JSON policy document (string) for the default event bus;
#            must be non-empty when this unit is enabled

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

  enabled           = try(local.common.locals.enable_ou_deployment_event_bus_policy, false)
  resolved_accounts = try(local.ou.locals.effective_accounts["event_bus_policy"], [])
  policy            = try(local.common.locals.ou_deployments["event_bus_policy"].inputs.policy, "")

  # An enabled unit with targets but no policy document is a configuration
  # error — abort naming the missing input instead of planning an invalid
  # resource. file() fails on the non-existent path; the "path" carries the
  # diagnostic text.
  _policy_guard = (!local.enabled || length(local.resolved_accounts) == 0 || local.policy != "") ? "ok" : file(
    "ERROR: enable_ou_deployment_event_bus_policy is on and accounts are resolved, but ou_deployments['event_bus_policy'].inputs.policy is empty."
  )
}

# Switch off or an empty effective account set -> zero resources.
exclude {
  if      = !local.enabled || length(local.resolved_accounts) == 0
  actions = ["all"]
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

generate "event_bus_policies" {
  path      = "event_bus_policies.tf"
  if_exists = "overwrite_terragrunt"

  contents = join("\n\n", concat(
    [for id in local.resolved_accounts :
      <<-EOF
      resource "aws_cloudwatch_event_bus_policy" "acct_${id}" {
        provider       = aws.acct_${id}
        event_bus_name = "default"
        policy         = ${jsonencode(local.policy)}
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
            error_message = "At least one resolved target account is not among the active account IDs of the accounts unit — warm accounts are excluded from deployment targets. Check env/accounts.hcl, warm flags and the ou_deployments entry 'event_bus_policy'."
          }
        }
      }
      EOF
    ],
  ))
}
