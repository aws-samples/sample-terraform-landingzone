# Security module: GuardDuty, Security Hub, Macie, IAM Access Analyzer, Password Policy
#
# IMPORTANT: Org-wide configurations (GuardDuty Org Config, Security Hub Org Config)
# are managed from the Delegated Admin account (Audit), not from the Management
# Account. The Management Account only registers the Delegated Admin and
# enables the services locally. The org configuration is applied by
# modules/security-org-config through a cross-account provider in the Audit account.
#
# The finding consumers (GuardDuty findings export, Macie classification
# export, Security Hub finding aggregator and automation rules) reach the
# member accounts' findings only in the delegated administrator, so
# modules/security-org-config creates them in the Audit account and the
# management stack passes manage_finding_consumers = false here. With the
# default true this module creates them in the account of the provider passed
# in — the Management Account in the shipped stacks — where they see that
# account's own findings only.

# --- Partition Detection ---
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  dns_suffix = data.aws_partition.current.dns_suffix
  arn_prefix = "arn:${local.partition}"
  region     = data.aws_region.current.region
  account_id = data.aws_caller_identity.current.account_id

  # EU Sovereign Cloud detection — one derivation for every module of the
  # landing zone. docs/multi-partition.md promises the decision is
  # made automatically from the detected partition; var.is_eusc stays in the
  # expression so an explicit input and the existing test runs keep working and
  # so a caller can force the EUSC behaviour outside that partition.
  is_eusc = var.is_eusc || local.partition == "aws-eusc"
  # --- Configurable lifecycle rule sets ---
  # One derivation per bucket, in the same shape modules/logging uses. A rule
  # set of length zero is a deliberate "no rules" and stays distinguishable from
  # null, which means "keep the rule the module derives" — that is why the flag
  # tests for null and not for emptiness.
  explicit_guardduty_export_lifecycle = var.guardduty_export_lifecycle_rules != null
  explicit_audit_manager_lifecycle    = var.audit_manager_bucket_lifecycle_rules != null
  guardduty_export_lifecycle_rules    = coalesce(var.guardduty_export_lifecycle_rules, [])
  audit_manager_lifecycle_rules       = coalesce(var.audit_manager_bucket_lifecycle_rules, [])
  macie_export_lifecycle_rules        = coalesce(var.macie_export_lifecycle_rules, [])
  session_manager_lifecycle_rules     = coalesce(var.session_manager_lifecycle_rules, [])
}

# --- Precondition: audit_account_id should be set for real deployments ---

check "audit_account_configured" {
  assert {
    condition     = var.audit_account_id != ""
    error_message = "audit_account_id is empty. Security delegation will be skipped. Set the account ID in env/accounts.hcl or ensure the accounts module has created the Audit account."
  }
}

# --- Check: features that write to the central log bucket need its name ---
# Four resources of this module multiply their count by
# central_log_bucket_name != "" (guardduty.tf: publishing destination and the
# export lifecycle rules; macie.tf: classification export; ssm-documents.tf:
# resource data sync). With the name empty — the logging stack's output not
# yet wired, a partial env — a feature the operator explicitly switched on
# becomes zero resources, and the plan looks complete. The check names what is
# being skipped. A warning like audit_account_configured, not a precondition:
# the stack's mock output for central_log_bucket_name is "" on a first plan
# before the logging stack exists, and that plan must stay possible. The two
# exports leave the list with manage_finding_consumers = false: they are then
# the administrator's, not this account's.
locals {
  central_log_bucket_consumers = compact([
    var.manage_finding_consumers && var.enable_guardduty && var.guardduty_export_frequency != null ? "GuardDuty findings export (guardduty_export_frequency)" : "",
    var.enable_guardduty && var.guardduty_export_frequency != null && (var.guardduty_lifecycle_rules != null || local.explicit_guardduty_export_lifecycle) ? "GuardDuty export lifecycle rules (guardduty_lifecycle_rules / guardduty_export_lifecycle_rules)" : "",
    var.manage_finding_consumers && var.enable_macie && !local.is_eusc && var.macie_publish_sensitive_data_findings ? "Macie classification export (macie_publish_sensitive_data_findings)" : "",
    var.enable_macie && !local.is_eusc && length(local.macie_export_lifecycle_rules) > 0 ? "Macie export lifecycle rules (macie_export_lifecycle_rules)" : "",
    var.enable_ssm_resource_data_sync ? "SSM resource data sync (enable_ssm_resource_data_sync)" : "",
  ])
}

check "central_log_bucket_configured" {
  assert {
    condition     = var.central_log_bucket_name != "" || length(local.central_log_bucket_consumers) == 0
    error_message = "central_log_bucket_name is empty, but features that write to the central log bucket are enabled and are SKIPPED in this plan — no resource is created for: ${join("; ", local.central_log_bucket_consumers)}. Wire the logging stack output (dependency.logging.outputs.central_log_bucket_name) or disable the features; a green apply without the bucket name archives nothing."
  }
}

# --- Check: finding consumers kept here while an administrator is designated ---
# The export of this account reaches this account's findings only; the
# administrator's export (modules/security-org-config) reaches every member's.
# A warning, not a failure: an operator may defer the move with
# security_finding_consumers_in_audit = false, and a deployment without an
# Audit account has no administrator to move them to.
check "finding_consumers_in_administrator" {
  assert {
    condition     = !(var.manage_finding_consumers && var.audit_account_id != "" && var.enable_guardduty && var.guardduty_export_frequency != null && var.central_log_bucket_name != "")
    error_message = "The GuardDuty findings export is created in this account while audit_account_id names a delegated administrator: it exports this account's findings only, the member accounts' findings reach no export. Leave security_finding_consumers_in_audit at its default so stacks/audit/security-org-config creates the export, the aggregator and the automation rules in the administrator."
  }
}

# =============================================================================
# Central Root User Management
# =============================================================================
# The organization stack registers trusted access for the IAM service
# principal (modules/organization, aws_service_access_principals). No resource
# and no toggle exist for root management in the security module — see the
# README section "Provider Limits".

# =============================================================================
# Root Management Capability Placeholders
# =============================================================================
# Nothing in this repository turns these two features on. The organization
# stack registers trusted access for iam.<dns_suffix> (behind
# enable_central_root_management); that is the prerequisite only, the
# RootCredentialsManagement and RootSessions features stay off until they are
# enabled with `aws iam enable-organizations-root-credentials-management` and
# `aws iam enable-organizations-root-sessions` in the management account. The
# provider the lock file pins (hashicorp/aws 6.62.0) has a resource for them,
# aws_iam_organizations_features; this tree does not declare it. The two
# inputs only feed the warning below, so a true value claims nothing and
# switches nothing.

check "root_credentials_management_provider_limitation" {
  assert {
    condition     = !var.root_credentials_management && !var.allow_root_sessions
    error_message = "root_credentials_management or allow_root_sessions is true, but this module enables neither feature: no resource reads the two inputs, and the trusted access for the IAM service principal that the organization stack registers does not enable them. Enable them in the management account with `aws iam enable-organizations-root-credentials-management` and `aws iam enable-organizations-root-sessions`, or set both inputs to false."
  }
}
