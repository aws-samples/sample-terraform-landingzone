# Security Org Config module — runs in the Audit account (delegated admin)
#
# Configures org-wide security service enablement:
# - GuardDuty org config + detector with all features
# - Security Hub org config
# - Macie session (conditional on !is_eusc)
# - Detective graph with member auto-enable (conditional on !is_eusc)
# - The finding consumers of the administrator (consumers.tf): GuardDuty
#   findings export, Macie classification export, Security Hub finding
#   aggregator, automation rules, member enrolment and disabled controls.
#   AWS ties each of them to the administrator account — only there do they
#   reach the members' findings.
#
# The delegated-admin DESIGNATIONS (GuardDuty, Security Hub, Macie, Detective)
# are made by modules/security from the management account — the only account
# whose EnableOrganizationAdminAccount calls AWS accepts.

# --- Partition Detection ---
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  arn_prefix = "arn:${local.partition}"
  account_id = data.aws_caller_identity.current.account_id

  # EU Sovereign Cloud detection — the same derivation modules/security uses:
  # the detected partition decides on its own, so a stack that does not pass
  # the boolean still gets the EUSC behaviour (docs/multi-partition.md).
  # var.is_eusc stays in the expression so an explicit input keeps working.
  is_eusc = var.is_eusc || local.partition == "aws-eusc"
}

# =============================================================================
# GuardDuty — Detector + Org Configuration
# =============================================================================

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable = true

  # The administrator's frequency is the one AWS applies to the members'
  # EventBridge notifications and to the export; null keeps the provider
  # default (SIX_HOURS), so a deployment without an export plans no change.
  finding_publishing_frequency = var.guardduty_export_frequency
}

resource "aws_guardduty_detector_feature" "s3_protection" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "S3_DATA_EVENTS"
  status      = var.guardduty_features.s3_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "EKS_AUDIT_LOGS"
  status      = var.guardduty_features.eks_audit_logs ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "EKS_RUNTIME_MONITORING"
  status      = var.guardduty_features.eks_runtime_monitoring ? "ENABLED" : "DISABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = var.guardduty_features.eks_manage_agent ? "ENABLED" : "DISABLED"
  }
}

resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "EBS_MALWARE_PROTECTION"
  status      = var.guardduty_features.ebs_malware_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "rds_protection" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "RDS_LOGIN_EVENTS"
  status      = var.guardduty_features.rds_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "lambda_protection" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = var.guardduty_features.lambda_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_organization_configuration" "this" {
  count = var.enable_guardduty ? 1 : 0

  auto_enable_organization_members = "ALL"
  detector_id                      = aws_guardduty_detector.this[0].id

  # No datasources block: the detector above is configured through
  # the FEATURES API (aws_guardduty_detector_feature), and the legacy
  # dataSources parameter of UpdateOrganizationConfiguration is deprecated —
  # on a feature-based organization the call is rejected or the block is
  # ignored, and it only ever covered three of the six features (S3, EKS audit
  # logs, EBS malware), so members never got RDS, Lambda or EKS runtime
  # auto-enabled. The per-feature resources below carry every toggle of
  # var.guardduty_features to the members. The attribute stays computed in the
  # provider, so dropping the block changes nothing on this resource.

  depends_on = [
    aws_guardduty_detector_feature.s3_protection,
    aws_guardduty_detector_feature.eks_audit_logs,
    aws_guardduty_detector_feature.eks_runtime_monitoring,
    aws_guardduty_detector_feature.ebs_malware_protection,
    aws_guardduty_detector_feature.rds_protection,
    aws_guardduty_detector_feature.lambda_protection,
  ]
}

# --- Org-wide feature auto-enablement, one resource per detector feature ---
# auto_enable follows auto_enable_organization_members = "ALL" above: a feature
# the configuration switches on is enabled for every member, a switched-off
# feature for none. NONE (not a missing resource) so that turning a feature
# off also reaches the members instead of leaving the last setting in place.

locals {
  guardduty_org_features = {
    S3_DATA_EVENTS         = var.guardduty_features.s3_protection
    EKS_AUDIT_LOGS         = var.guardduty_features.eks_audit_logs
    EBS_MALWARE_PROTECTION = var.guardduty_features.ebs_malware_protection
    RDS_LOGIN_EVENTS       = var.guardduty_features.rds_protection
    LAMBDA_NETWORK_LOGS    = var.guardduty_features.lambda_protection
  }
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = var.enable_guardduty ? local.guardduty_org_features : {}

  detector_id = aws_guardduty_detector.this[0].id
  name        = each.key
  auto_enable = each.value ? "ALL" : "NONE"

  depends_on = [aws_guardduty_organization_configuration.this]
}

# EKS runtime monitoring carries the agent-management add-on as additional
# configuration, mirroring aws_guardduty_detector_feature.eks_runtime_monitoring.
resource "aws_guardduty_organization_configuration_feature" "eks_runtime_monitoring" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "EKS_RUNTIME_MONITORING"
  auto_enable = var.guardduty_features.eks_runtime_monitoring ? "ALL" : "NONE"

  additional_configuration {
    name        = "EKS_ADDON_MANAGEMENT"
    auto_enable = var.guardduty_features.eks_manage_agent ? "ALL" : "NONE"
  }

  depends_on = [aws_guardduty_organization_configuration.this]
}

# =============================================================================
# Security Hub — Org Configuration
# =============================================================================

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards = false
}

resource "aws_securityhub_organization_configuration" "this" {
  count = var.enable_security_hub ? 1 : 0

  auto_enable = true

  depends_on = [aws_securityhub_account.this]
}

# --- Security Hub Standards in the delegated admin account ---
# Subscribes the standards the configuration selects. The form follows the
# sister implementation in modules/security/securityhub.tf: entries may be plain
# ARN suffix strings or objects with arn_suffix and enabled, and a disabled
# entry is documentation only.

locals {
  normalized_security_hub_standards = [
    for s in var.security_hub_standards : {
      arn_suffix = can(s.arn_suffix) ? tostring(s.arn_suffix) : tostring(s)
      enabled    = can(s.enabled) ? tobool(s.enabled) : true
    }
  ]

  # Keyed by arn_suffix for for_each (same form as
  # modules/security/securityhub.tf): removing or disabling one standard does
  # not shift the remaining org-wide subscriptions, as a count index would
  # (destroy/create with a coverage gap in between) — with the delegated admin
  # scope the gap would span every member account.
  enabled_security_hub_standards = var.enable_security_hub ? {
    for s in local.normalized_security_hub_standards : s.arn_suffix => s if s.enabled
  } : {}
}

resource "aws_securityhub_standards_subscription" "this" {
  for_each = local.enabled_security_hub_standards

  standards_arn = "${local.arn_prefix}:securityhub:${local.region}::standards/${each.key}"

  depends_on = [aws_securityhub_account.this]
}

# The switch from count to for_each moves the resource addresses. The moved
# blocks map the count indices of the DEFAULT DELIVERY ORDER — all four
# standards enabled, sorted lexicographically by arn_suffix — onto the new
# keys. Deployments whose enabled-standard list orders differently (for
# example compliance_frameworks = ["nist-800-53"] without a cis-3.0
# framework puts nist at index 2) do NOT migrate cleanly: a moved target
# absent from for_each is destroyed and recreated, exactly as it would be
# without the block, so the blocks cannot make it worse — but such
# deployments need `terraform state mv` BEFORE upgrading. See the
# "Security Hub standards subscriptions" migration section in
# docs/operations.md. Both modules subscribe the same loader-merged list,
# so the index order matches modules/security/securityhub.tf. An index a
# deployment never had is ignored by Terraform.
moved {
  from = aws_securityhub_standards_subscription.this[0]
  to   = aws_securityhub_standards_subscription.this["aws-foundational-security-best-practices/v/1.0.0"]
}

moved {
  from = aws_securityhub_standards_subscription.this[1]
  to   = aws_securityhub_standards_subscription.this["cis-aws-foundations-benchmark/v/1.4.0"]
}

moved {
  from = aws_securityhub_standards_subscription.this[2]
  to   = aws_securityhub_standards_subscription.this["cis-aws-foundations-benchmark/v/3.0.0"]
}

moved {
  from = aws_securityhub_standards_subscription.this[3]
  to   = aws_securityhub_standards_subscription.this["nist-800-53/v/5.0.0"]
}

# =============================================================================
# Macie — session in the Audit account (conditional on !is_eusc)
# =============================================================================
# The org-admin DESIGNATION is not made here: Macie's
# EnableOrganizationAdminAccount may only be called by the organization
# management account, and the management account may not designate itself —
# from the Audit account the call is refused, from the management account it
# would name the wrong account. modules/security (macie.tf,
# aws_macie2_organization_admin_account) designates the Audit account from the
# management stack; this module owns what the delegated admin configures. The
# removed block drops a stale state entry without calling the API — a
# DisableOrganizationAdminAccount from this account would be refused the same
# way, and from the wrong account it would strip the org's designation.

resource "aws_macie2_account" "this" {
  count = var.enable_macie && !local.is_eusc ? 1 : 0
}

removed {
  from = aws_macie2_organization_admin_account.this

  lifecycle {
    destroy = false
  }
}

# =============================================================================
# Detective — graph and member auto-enable (conditional on !is_eusc)
# =============================================================================
# Detective is not available in the aws-eusc partition (AWS Services by Region,
# eusc-de-east-1). Same gate as the Macie resources above; the check below
# reports the skip for deployments that run only this module (the sister check
# in modules/security covers that stack).
#
# As for Macie, the org-admin designation is NOT made here: Detective's
# EnableOrganizationAdminAccount "can only be called by the organization
# management account" (API reference), and the management account cannot be
# the delegated administrator. modules/security (detective.tf,
# aws_detective_organization_admin_account) designates the Audit account; this
# module manages the graph and the member auto-enable of the designated admin.

resource "aws_detective_graph" "this" {
  count = var.enable_detective && !local.is_eusc ? 1 : 0
}

removed {
  from = aws_detective_organization_admin_account.this

  lifecycle {
    destroy = false
  }
}

resource "aws_detective_organization_configuration" "this" {
  count = var.enable_detective && !local.is_eusc ? 1 : 0

  auto_enable = true
  graph_arn   = aws_detective_graph.this[0].graph_arn
}

# Without this check the skip would be silent for a deployment that enables
# Detective only through this module: enable_detective = true would look like
# it took effect. The check warns instead of failing, because skipping an
# unavailable service is the intended behaviour and must not block the plan
# (same convention as modules/security).
check "detective_partition_availability" {
  assert {
    condition     = !(var.enable_detective && local.is_eusc)
    error_message = "enable_detective is true but Detective is not available in the aws-eusc partition. All Detective resources are skipped in this deployment. Set enable_detective = false to suppress this warning."
  }
}

# =============================================================================
# Cross-account deployment_targets warning
# =============================================================================

check "guardduty_deployment_targets_warning" {
  assert {
    condition     = length(var.guardduty_deployment_targets) == 0
    error_message = "guardduty_deployment_targets is non-empty [${join(", ", var.guardduty_deployment_targets)}]. deployment_targets is accepted for configuration compatibility, but Terraform cannot dynamically create cross-account providers. Use Terragrunt per-account stacks for cross-account deployment."
  }
}
