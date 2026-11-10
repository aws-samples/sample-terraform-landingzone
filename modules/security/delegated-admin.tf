# =============================================================================
# Delegated Administrator — one per enabled service → Audit account
# =============================================================================

resource "aws_organizations_delegated_administrator" "guardduty" {
  count = var.enable_guardduty && var.audit_account_id != "" ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "guardduty.${local.dns_suffix}"
}

resource "aws_organizations_delegated_administrator" "securityhub" {
  count = var.enable_security_hub && var.audit_account_id != "" ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "securityhub.${local.dns_suffix}"
}

resource "aws_organizations_delegated_administrator" "macie" {
  count = var.enable_macie && !local.is_eusc && var.audit_account_id != "" ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "macie.${local.dns_suffix}"
}

resource "aws_organizations_delegated_administrator" "access_analyzer" {
  count = var.enable_access_analyzer && var.audit_account_id != "" ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "access-analyzer.${local.dns_suffix}"
}
