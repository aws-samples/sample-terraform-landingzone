# IAM — Baseline Roles, SAML Provider, Customer-Managed Policies

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

exclude {
  if      = !local.common.locals.enable_iam
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/iam"
}

dependency "security" {
  config_path  = "../security"
  skip_outputs = true
  # IAM does not need outputs from Security — ordering dependency only
}

dependency "accounts" {
  config_path = "../accounts"

  mock_outputs = {
    active_account_ids    = {}
    active_account_ou_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# Organization: supplies the OU name map for the directory share-target
# resolution (share_targets.organizational_units of managed_active_directories).
# Empty map as mock output — the module default, so validate and plan work
# before the first apply of the organization stack.
dependency "organization" {
  config_path = "../organization"

  mock_outputs = {
    ou_name_to_id = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# Networking: supplies the VPC and subnet identifiers that Managed Microsoft AD
# and the AD Connector are placed in. Empty maps as mock outputs — that is the
# module default of both variables, so validate and plan work before the first
# apply of the networking stack.
dependency "networking" {
  config_path = "../networking"

  mock_outputs = {
    vpc_ids               = {}
    subnet_ids            = {}
    resolver_endpoint_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  roles          = local.common.locals.roles
  saml_providers = local.common.locals.saml_providers
  # The loader merges all three layers (base + common + frameworks) and
  # resolves __LOADER_INJECT__ entries through its injection table with
  # jsonencode(jsondecode(...)) normalization — a syntax error or an unknown
  # name fails at plan time. _loader_inject_map stays loader-private.
  customer_managed_policies = local.compliance.locals.customer_managed_policies
  account_ids               = dependency.accounts.outputs.active_account_ids

  # IAM users and groups
  iam_users  = local.compliance.locals.iam_users
  iam_groups = local.compliance.locals.iam_groups

  # AWS Managed Microsoft AD and AD Connector.
  #
  # vpc_ids and subnet_ids come from the networking stack — modules/networking is
  # the only place the identifiers exist. An ordering edge config-rules -> iam
  # would close a cycle (networking -> config-rules -> iam -> networking), which
  # terragrunt answers by dropping units from the run queue. config-rules
  # therefore does not depend on iam (the reasons are written down in
  # stacks/management/config-rules/terragrunt.hcl), and iam runs after
  # networking.
  managed_active_directories = local.compliance.locals.managed_active_directories
  vpc_ids                    = dependency.networking.outputs.vpc_ids
  subnet_ids                 = dependency.networking.outputs.subnet_ids
  # Outbound Resolver endpoints for the Managed AD FORWARD rules — Route 53
  # Resolver accepts FORWARD rules only with an outbound endpoint.
  resolver_endpoint_ids = dependency.networking.outputs.resolver_endpoint_ids

  # Account and OU maps for the directory share-target resolution (the
  # module resolves share_targets.organizational_units to the accounts the
  # OU contains) and the role the module assumes to place an admin secret in
  # the account named by secret_config.account.
  ou_name_to_id = dependency.organization.outputs.ou_name_to_id

  # The active pendant — warm accounts are no deployment targets.
  account_ou_ids              = dependency.accounts.outputs.active_account_ou_ids
  mad_secret_access_role_name = try(local.common.locals.account_access_role_name, "AWSControlTowerExecution")

  # Service Catalog propagation role
  enable_service_catalog = local.common.locals.enable_service_catalog

  # Management account ID. Read by the trust policy of the StackSet execution
  # role (modules/iam/main.tf) — without it the role would trust a principal
  # ARN with an empty account field.
  management_account_id = local.accounts.locals.management_account_id

  # StackSet roles — loader merge (base + common + frameworks)
  enable_stackset_roles = local.compliance.locals.enable_stackset_roles
  is_management_account = try(local.common.locals.is_management_account, false)

  # Optional customer-managed key for the Secrets Manager secrets that hold
  # auto-generated IAM user passwords. Empty default keeps the Secrets Manager
  # service key (aws/secretsmanager); no key is created anywhere for this.
  secrets_kms_key_arn = try(local.common.locals.secrets_kms_key_arn, "")
  # Break-glass access package: numbered emergency users with mandatory
  # permissions boundary; the usage alarm lives in the monitoring stack
  # (enable_break_glass_alarm). Off by default; null keeps the module default.
  enable_break_glass = try(local.common.locals.enable_break_glass, false)
  break_glass_config = try(local.common.locals.break_glass_config, null)
}
