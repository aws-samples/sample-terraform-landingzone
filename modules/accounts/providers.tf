# Provider configuration for the account-metadata parameters written outside
# the management account.
#
# The module creates AWS Organizations accounts through the default provider
# (management account) and mirrors the resulting account metadata into SSM
# Parameter Store. When var.enable_deployment_account is set, those parameters
# belong in the Deployment Account, which requires a second, role-assuming
# provider configuration. The module owns that configuration itself so that the
# module directory resolves as a root module (terraform validate, terraform
# test) — a configuration_aliases entry would only be satisfiable through a
# calling module and leaves the module unvalidatable on its own.
#
# When var.enable_deployment_account is false the assume_role block is omitted:
# the alias then resolves to the ambient credentials and stays unused, because
# aws_ssm_parameter.account_id_deployment has an empty for_each in that case.

provider "aws" {
  alias  = "deployment_account"
  region = var.region != "" ? var.region : null

  dynamic "assume_role" {
    for_each = var.enable_deployment_account && var.deployment_account_id != "" ? [1] : []

    content {
      role_arn = "arn:${data.aws_partition.current.partition}:iam::${var.deployment_account_id}:role/${var.account_access_role_name}"
    }
  }

  default_tags {
    tags = var.default_tags
  }
}
