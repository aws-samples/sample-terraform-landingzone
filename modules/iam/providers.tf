# Provider configuration for directory admin secrets placed outside the
# management account or the home region.
#
# secret_config.account and secret_config.region of a managed_active_directories
# entry choose where the module stores the generated admin secret. Terraform
# cannot create provider configurations per entry, so the placement runs over
# ONE static, role-assuming alias — the variable validation therefore requires
# all placing entries to name the same account and the same region. The module
# owns the configuration itself so that the module directory resolves as a root
# module (terraform validate, terraform test) — the same reasoning as the
# deployment_account alias of modules/accounts.
#
# When no entry places its secret, assume_role and region are omitted: the
# alias then resolves to the ambient credentials and the secrets stay in the
# management account, in the provider region.

locals {
  # The (validated-uniform) placement targets across all entries.
  mad_secret_declared_accounts = distinct([
    for ad in var.managed_active_directories : ad.secret_config.account
    if ad.secret_config.account != null
  ])
  mad_secret_declared_regions = distinct([
    for ad in var.managed_active_directories : ad.secret_config.region
    if ad.secret_config.region != null
  ])

  # Account entries name either a 12-digit ID or a key of account_ids.
  mad_secret_account_id = length(local.mad_secret_declared_accounts) == 0 ? "" : (
    can(regex("^[0-9]{12}$", local.mad_secret_declared_accounts[0]))
    ? local.mad_secret_declared_accounts[0]
    : lookup(var.account_ids, local.mad_secret_declared_accounts[0], "")
  )
  mad_secret_region = length(local.mad_secret_declared_regions) == 0 ? "" : local.mad_secret_declared_regions[0]

  # Effective admin secret name per Managed Microsoft AD: the configured
  # admin_secret_name, or the module's fixed tlz/mad/<directory>/admin-password
  # form — the name aws_iam_role_policy.mad_secret_access grants read access to.
  mad_admin_secret_names = {
    for name, ad in local.microsoft_ad_map :
    name => coalesce(ad.secret_config.admin_secret_name, "tlz/mad/${name}/admin-password")
  }
}

provider "aws" {
  alias  = "mad_secret"
  region = local.mad_secret_region != "" ? local.mad_secret_region : null

  dynamic "assume_role" {
    for_each = local.mad_secret_account_id != "" ? [1] : []

    content {
      role_arn = "arn:${data.aws_partition.current.partition}:iam::${local.mad_secret_account_id}:role/${var.mad_secret_access_role_name}"
    }
  }
}
