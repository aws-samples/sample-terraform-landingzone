# =============================================================================
# Detective — Conditional (skip in aws-eusc partition)
# =============================================================================
# Detective is not available in the aws-eusc partition (AWS Services by Region,
# eusc-de-east-1), so all three resources are
# gated on !local.is_eusc, following the Macie pattern in macie.tf.

resource "aws_detective_graph" "this" {
  count = var.enable_detective && !local.is_eusc ? 1 : 0
}

resource "aws_organizations_delegated_administrator" "detective" {
  count = var.enable_detective && !local.is_eusc && var.audit_account_id != "" ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "detective.${local.dns_suffix}"
}

# Detective reads its administrator from its own designation API, not from the
# Organizations registration above (same class as GuardDuty and
# Security Hub): detective:EnableOrganizationAdminAccount "can only be called
# by the organization management account", and where a delegated administrator
# is registered in Organizations the designated account must be that account
# (API reference). From the Audit account the call is refused, and without the
# designation the Audit account's aws_detective_organization_configuration
# (UpdateOrganizationConfiguration, administrator account only) has no
# administrator to run as. Same audit_account_id guard as every registration in
# this module; ordered after the registration so the designated account is the
# registered one. The designation enables Detective in the Audit account and
# creates its behavior graph if none exists; the Audit stack's
# aws_detective_graph adopts an existing graph with
#   terraform import 'aws_detective_graph.this[0]' <graph-arn>
# A designation made out-of-band is adopted with
#   terraform import 'aws_detective_organization_admin_account.this[0]' <audit-account-id>
resource "aws_detective_organization_admin_account" "this" {
  count = var.enable_detective && !local.is_eusc && var.audit_account_id != "" ? 1 : 0

  account_id = var.audit_account_id

  depends_on = [aws_organizations_delegated_administrator.detective, aws_detective_graph.this]
}

# Without this check the skip would be silent: enable_detective = true would
# look like it took effect. The check warns instead of failing, because
# skipping an unavailable service is the intended behaviour and must not block
# the plan (same convention as macie_partition_availability).
check "detective_partition_availability" {
  assert {
    condition     = !(var.enable_detective && local.is_eusc)
    error_message = "enable_detective is true but Detective is not available in the aws-eusc partition. All Detective resources are skipped in this deployment. Set enable_detective = false to suppress this warning."
  }
}
