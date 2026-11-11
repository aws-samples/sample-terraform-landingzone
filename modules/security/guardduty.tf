# =============================================================================
# GuardDuty — Detector in Management Account
# Org config is managed from the Audit account (modules/security-org-config)
# =============================================================================

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable = true

  depends_on = [aws_organizations_delegated_administrator.guardduty]
}

# GuardDuty keeps its own notion of the delegated administrator, set only
# through guardduty:EnableOrganizationAdminAccount from the management account
# (AWS Organizations, "Amazon GuardDuty and AWS Organizations": trusted access
# first, then EnableOrganizationAdminAccount; the Organizations registration
# in delegated-admin.tf alone leaves the service without an administrator).
# Without this resource the Audit account is registered in Organizations but
# GuardDuty does not recognise it, and modules/security-org-config's
# aws_guardduty_organization_configuration fails there with "the current
# account is not the administrator account". Same pairing as
# Macie (macie.tf: aws_organizations_delegated_administrator.macie plus
# aws_macie2_organization_admin_account), same audit_account_id guard as every
# delegated-admin registration of this module. A deployment whose designation
# was made out-of-band adopts it with
#   terraform import 'aws_guardduty_organization_admin_account.this[0]' <audit-account-id>
resource "aws_guardduty_organization_admin_account" "this" {
  count = var.enable_guardduty && var.audit_account_id != "" ? 1 : 0

  admin_account_id = var.audit_account_id

  depends_on = [aws_organizations_delegated_administrator.guardduty, aws_guardduty_detector.this]
}

resource "aws_guardduty_detector_feature" "s3_logs" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "S3_DATA_EVENTS"
  status      = var.guardduty_s3_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "EKS_AUDIT_LOGS"
  status      = var.guardduty_eks_protection ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "ebs_malware" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "EBS_MALWARE_PROTECTION"
  status      = var.guardduty_malware_protection ? "ENABLED" : "DISABLED"
}

# --- GuardDuty Lambda Protection (G1) ---

resource "aws_guardduty_detector_feature" "lambda_protection" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = var.guardduty_lambda_protection ? "ENABLED" : "DISABLED"
}

# --- GuardDuty RDS Protection (G2) ---

resource "aws_guardduty_detector_feature" "rds_protection" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "RDS_LOGIN_EVENTS"
  status      = var.guardduty_rds_protection ? "ENABLED" : "DISABLED"
}

# --- GuardDuty EKS Runtime Monitoring ---

resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "EKS_RUNTIME_MONITORING"
  status      = var.guardduty_eks_runtime_monitoring ? "ENABLED" : "DISABLED"

  # Agent management is a sub-configuration of the runtime monitoring feature,
  # not a feature of its own: EKS_ADDON_MANAGEMENT is the additional
  # configuration the pinned provider (6.39.0) accepts here, and it carries
  # var.guardduty_eks_manage_agent, so choosing manual agent deployment takes
  # effect. The block is
  # only emitted while runtime monitoring itself is on — AWS has nothing to
  # manage for a disabled feature, and the sub-configuration would otherwise
  # appear in every plan that leaves the feature off.
  dynamic "additional_configuration" {
    for_each = var.guardduty_eks_runtime_monitoring ? [1] : []
    content {
      name   = "EKS_ADDON_MANAGEMENT"
      status = var.guardduty_eks_manage_agent ? "ENABLED" : "DISABLED"
    }
  }
}

# --- GuardDuty Deployment Targets ---
# NOTE: Terraform cannot dynamically create providers for cross-account GuardDuty
# configuration. GuardDuty is configured in the management account and the delegated
# admin account only. For member account configuration, use the delegated admin pattern
# via the security-org-config module (modules/security-org-config/).

check "guardduty_deployment_targets_warning" {
  assert {
    condition     = length(var.guardduty_deployment_targets) == 0
    error_message = "guardduty_deployment_targets is set but Terraform cannot dynamically create providers for cross-account GuardDuty configuration. GuardDuty is configured in the management account and the delegated admin account. Use the delegated admin pattern via the security-org-config module for member account configuration."
  }
}

# =============================================================================
# GuardDuty — Publishing Destination / Export
# =============================================================================

# Wait for S3 bucket policy and KMS key policy to propagate before GuardDuty validates permissions
resource "time_sleep" "guardduty_export_wait" {
  count = var.manage_finding_consumers && var.enable_guardduty && var.guardduty_export_frequency != null && var.central_log_bucket_name != "" ? 1 : 0

  create_duration = "30s"

  depends_on = [aws_guardduty_detector.this]
}

locals {
  # One normalised prefix feeds both the export destination and the lifecycle
  # rule, so the location GuardDuty writes to and the location the retention
  # rule filters on cannot drift apart.
  guardduty_export_prefix_normalized = trim(var.guardduty_export_prefix, "/")

  guardduty_export_destination_arn = join("", [
    "${local.arn_prefix}:s3:::${var.central_log_bucket_name}",
    local.guardduty_export_prefix_normalized != "" ? "/${local.guardduty_export_prefix_normalized}" : "",
  ])

  guardduty_export_lifecycle_prefix = (
    local.guardduty_export_prefix_normalized != ""
    ? "${local.guardduty_export_prefix_normalized}/"
    : ""
  )
}

# The export of this account. With manage_finding_consumers = false the
# administrator's export (modules/security-org-config) carries every account's
# findings, this one included, and nothing is created here.
resource "aws_guardduty_publishing_destination" "this" {
  count = var.manage_finding_consumers && var.enable_guardduty && var.guardduty_export_frequency != null && var.central_log_bucket_name != "" ? 1 : 0

  detector_id      = aws_guardduty_detector.this[0].id
  destination_arn  = local.guardduty_export_destination_arn
  destination_type = "S3"
  kms_key_arn      = var.guardduty_export_kms_key_arn

  # Second line of defence behind the cross-variable validation of
  # guardduty_export_kms_key_arn: it keeps the requirement attached to the
  # resource even if the creation condition above ever changes.
  lifecycle {
    precondition {
      condition     = var.guardduty_export_kms_key_arn != ""
      error_message = "guardduty_export_kms_key_arn must be set when guardduty_export_frequency and central_log_bucket_name are configured. kms_key_arn is a required argument of aws_guardduty_publishing_destination and AWS rejects an empty value."
    }
  }

  depends_on = [aws_guardduty_detector.this, time_sleep.guardduty_export_wait]
}

# =============================================================================
# GuardDuty — S3 Malware Protection
# =============================================================================

locals {
  guardduty_s3_malware_enabled = var.enable_guardduty_s3_malware_protection && length(var.guardduty_s3_malware_configs) > 0

  guardduty_s3_malware_configs_map = {
    for cfg in var.guardduty_s3_malware_configs : cfg.bucket_name => cfg
  }

  guardduty_s3_malware_kms_arns = [
    for cfg in var.guardduty_s3_malware_configs : cfg.kms_key_arn
    if cfg.kms_key_arn != null
  ]
}

resource "aws_guardduty_malware_protection_plan" "this" {
  for_each = local.guardduty_s3_malware_enabled ? local.guardduty_s3_malware_configs_map : {}

  role = aws_iam_role.guardduty_malware_scan[0].arn

  tags = length(each.value.tags) > 0 ? each.value.tags : null

  protected_resource {
    s3_bucket {
      bucket_name     = each.value.bucket_name
      object_prefixes = length(each.value.object_prefixes) > 0 ? each.value.object_prefixes : null
    }
  }

  actions {
    tagging {
      status = each.value.enable_malware_protection_tags ? "ENABLED" : "DISABLED"
    }
  }

  lifecycle {
    precondition {
      condition     = var.enable_guardduty
      error_message = "enable_guardduty must be true when enable_guardduty_s3_malware_protection is enabled. GuardDuty S3 Malware Protection requires an active GuardDuty detector."
    }
  }

  depends_on = [aws_guardduty_detector.this]
}

# --- IAM Role for GuardDuty S3 Malware Scanning ---

resource "aws_iam_role" "guardduty_malware_scan" {
  count = local.guardduty_s3_malware_enabled ? 1 : 0

  name = "tlz-guardduty-malware-scan"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/guardduty-malware-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

# --- S3 Policy for GuardDuty Malware Scanning ---

resource "aws_iam_role_policy" "guardduty_malware_scan_s3" {
  count = local.guardduty_s3_malware_enabled ? 1 : 0

  name = "guardduty-malware-scan-s3"
  role = aws_iam_role.guardduty_malware_scan[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/guardduty-malware-s3-policy.json", {
    bucket_arns_json = jsonencode(flatten([
      for cfg in var.guardduty_s3_malware_configs : [
        "arn:${local.partition}:s3:::${cfg.bucket_name}",
        "arn:${local.partition}:s3:::${cfg.bucket_name}/*",
      ]
    ]))
  })))
}

# --- Conditional KMS Policy for GuardDuty Malware Scanning ---

resource "aws_iam_role_policy" "guardduty_malware_scan_kms" {
  count = local.guardduty_s3_malware_enabled && length(local.guardduty_s3_malware_kms_arns) > 0 ? 1 : 0

  name = "guardduty-malware-scan-kms"
  role = aws_iam_role.guardduty_malware_scan[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/guardduty-malware-kms-policy.json", {
    kms_arns_json = jsonencode(local.guardduty_s3_malware_kms_arns)
  })))
}

# =============================================================================
# GuardDuty S3 Export Lifecycle Rules
# =============================================================================


# S3 keeps exactly one lifecycle configuration per bucket, so every rule this
# module declares for the central log bucket has to live in this one resource —
# a second aws_s3_bucket_lifecycle_configuration on the same bucket would
# overwrite the first. That is why the Macie export rules are here and not in
# macie.tf, and why the resource keeps its name: the address is what existing
# state is stored under, and renaming it would require a state move for a
# deployment that changes nothing.
#
# Every rule stays scoped to its own export prefix. The bucket belongs to the
# logging module; a rule covering the whole bucket may not be declared here.
#
# The logging module writes the lifecycle configuration of the same bucket
# (modules/logging/s3-central.tf, aws_s3_bucket_lifecycle_configuration
# .central_logs). Whichever of the two applies last replaces the other's rules,
# and a destroy of this resource deletes every rule of the bucket. The resource
# is therefore only planned with replace_central_log_bucket_lifecycle = true;
# without it, a rule input that would write it is refused in the plan
# (variables.tf), and the export rules belong in the logging module's
# central_log_bucket_lifecycle_rules.
resource "aws_s3_bucket_lifecycle_configuration" "guardduty_export" {
  count = (
    var.replace_central_log_bucket_lifecycle &&
    var.central_log_bucket_name != "" && (
      (var.enable_guardduty && var.guardduty_export_frequency != null && (var.guardduty_lifecycle_rules != null || local.explicit_guardduty_export_lifecycle)) ||
      (var.enable_macie && length(local.macie_export_lifecycle_rules) > 0)
    )
  ) ? 1 : 0

  bucket = var.central_log_bucket_name

  dynamic "rule" {
    for_each = local.macie_export_lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      filter {
        prefix = rule.value.prefix
      }

      dynamic "expiration" {
        for_each = rule.value.expiration_days != null || rule.value.expired_object_delete_marker != null ? [rule.value] : []
        content {
          days                         = expiration.value.expiration_days
          expired_object_delete_marker = expiration.value.expired_object_delete_marker
        }
      }

      dynamic "transition" {
        for_each = rule.value.transitions
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.noncurrent_version_expiration_days != null ? [rule.value.noncurrent_version_expiration_days] : []
        content {
          noncurrent_days = noncurrent_version_expiration.value
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = rule.value.noncurrent_version_transitions
        content {
          noncurrent_days = noncurrent_version_transition.value.days
          storage_class   = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "abort_incomplete_multipart_upload" {
        for_each = rule.value.abort_incomplete_multipart_upload_days != null ? [rule.value.abort_incomplete_multipart_upload_days] : []
        content {
          days_after_initiation = abort_incomplete_multipart_upload.value
        }
      }
    }
  }

  dynamic "rule" {
    for_each = local.guardduty_export_lifecycle_rules
    content {
      id     = rule.value.id
      status = rule.value.enabled ? "Enabled" : "Disabled"

      filter {
        prefix = rule.value.prefix
      }

      dynamic "expiration" {
        for_each = rule.value.expiration_days != null || rule.value.expired_object_delete_marker != null ? [rule.value] : []
        content {
          days                         = expiration.value.expiration_days
          expired_object_delete_marker = expiration.value.expired_object_delete_marker
        }
      }

      dynamic "transition" {
        for_each = rule.value.transitions
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = rule.value.noncurrent_version_expiration_days != null ? [rule.value.noncurrent_version_expiration_days] : []
        content {
          noncurrent_days = noncurrent_version_expiration.value
        }
      }

      dynamic "noncurrent_version_transition" {
        for_each = rule.value.noncurrent_version_transitions
        content {
          noncurrent_days = noncurrent_version_transition.value.days
          storage_class   = noncurrent_version_transition.value.storage_class
        }
      }

      dynamic "abort_incomplete_multipart_upload" {
        for_each = rule.value.abort_incomplete_multipart_upload_days != null ? [rule.value.abort_incomplete_multipart_upload_days] : []
        content {
          days_after_initiation = abort_incomplete_multipart_upload.value
        }
      }
    }
  }

  # The derived rule set. It is dropped as soon as an explicit rule set
  # describes the lifecycle of the bucket -- with the default input the plan
  # stays exactly the same.
  #
  # The condition also names guardduty_lifecycle_rules: the resource can exist
  # without a GuardDuty retention period (the Macie rules create it too), and
  # without this term the derived rule would read an attribute of null.
  dynamic "rule" {
    for_each = (local.explicit_guardduty_export_lifecycle || var.guardduty_lifecycle_rules == null) ? [] : [1]
    content {

      id     = "guardduty-export-lifecycle"
      status = "Enabled"

      filter {
        prefix = local.guardduty_export_lifecycle_prefix
      }

      expiration {
        days = var.guardduty_lifecycle_rules.retention_days
      }

      # Scoped to the export prefix, like the rest of this rule: the bucket
      # belongs to the logging module, so a rule covering the whole bucket may
      # not be declared here.
      abort_incomplete_multipart_upload {
        days_after_initiation = 7
      }
    }
  }

}

check "guardduty_excluded_region_check" {
  assert {
    condition     = !contains(var.guardduty_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in guardduty_excluded_regions. GuardDuty resources are still created in this deployment but the region should be excluded from multi-region configuration."
  }
}

check "guardduty_s3_protection_excluded_region_check" {
  assert {
    condition     = !contains(var.guardduty_s3_protection_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in guardduty_s3_protection_excluded_regions. GuardDuty S3 protection is still created in this deployment but the region should be excluded from S3 protection configuration."
  }
}

check "guardduty_ec2_protection_excluded_region_check" {
  assert {
    condition     = !contains(var.guardduty_ec2_protection_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in guardduty_ec2_protection_excluded_regions. GuardDuty EC2 malware protection is still created in this deployment but the region should be excluded from EC2 protection configuration."
  }
}

check "guardduty_eks_protection_excluded_region_check" {
  assert {
    condition     = !contains(var.guardduty_eks_protection_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in guardduty_eks_protection_excluded_regions. GuardDuty EKS protection is still created in this deployment but the region should be excluded from EKS protection configuration."
  }
}

check "guardduty_lambda_protection_excluded_region_check" {
  assert {
    condition     = !contains(var.guardduty_lambda_protection_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in guardduty_lambda_protection_excluded_regions. GuardDuty Lambda protection is still created in this deployment but the region should be excluded from Lambda protection configuration."
  }
}

check "guardduty_rds_protection_excluded_region_check" {
  assert {
    condition     = !contains(var.guardduty_rds_protection_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in guardduty_rds_protection_excluded_regions. GuardDuty RDS protection is still created in this deployment but the region should be excluded from RDS protection configuration."
  }
}

# =============================================================================
# GuardDuty — Malware Scan Settings (EBS snapshot preservation)
# =============================================================================
# The malware scan settings API has no resource in the provider; the
# comparison base drives it through a deploy-time function as well. The
# function below is invoked by Terraform itself (aws_lambda_invocation,
# lifecycle_scope CRUD): it applies the retention setting when the switch is
# turned on or the detector changes, and reverts the setting to the service
# default when the switch leaves the configuration. With the default false
# nothing is created and the plan of existing deployments stays unchanged.

data "archive_file" "guardduty_scan_settings" {
  count = var.enable_guardduty && var.guardduty_keep_malware_snapshots ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/guardduty_malware_scan_settings.py"
  output_path = "${path.module}/lambda/guardduty_malware_scan_settings.zip"
}

resource "aws_iam_role" "guardduty_scan_settings" {
  count = var.enable_guardduty && var.guardduty_keep_malware_snapshots ? 1 : 0

  name = "tlz-guardduty-scan-settings"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "guardduty_scan_settings" {
  count = var.enable_guardduty && var.guardduty_keep_malware_snapshots ? 1 : 0

  name = "guardduty-scan-settings"
  role = aws_iam_role.guardduty_scan_settings[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/guardduty-scan-settings-lambda-policy.json", {
    detector_arn  = "${local.arn_prefix}:guardduty:${local.region}:${local.account_id}:detector/${aws_guardduty_detector.this[0].id}"
    log_group_arn = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/tlz-guardduty-scan-settings:*"
  })))
}

resource "aws_lambda_function" "guardduty_scan_settings" {
  count = var.enable_guardduty && var.guardduty_keep_malware_snapshots ? 1 : 0

  function_name    = "tlz-guardduty-scan-settings"
  description      = "Applies the GuardDuty malware scan snapshot retention setting at deployment time"
  runtime          = "python3.12"
  handler          = "guardduty_malware_scan_settings.lambda_handler"
  role             = aws_iam_role.guardduty_scan_settings[0].arn
  filename         = data.archive_file.guardduty_scan_settings[0].output_path
  source_code_hash = data.archive_file.guardduty_scan_settings[0].output_base64sha256
  timeout          = 30

  # The function is only ever invoked synchronously by Terraform, one call
  # per apply — a single reserved execution is all it can use.
  reserved_concurrent_executions = 1

  depends_on = [aws_iam_role_policy.guardduty_scan_settings]
}

# The function's own execution log group. Lambda creates /aws/lambda/<function
# name> implicitly on the first invocation when nothing has declared it: the
# group then sits outside the state, carries no retention and is never
# destroyed with the stack. Same class as the monitoring module's two functions
# (modules/monitoring/README.md, "Lambda execution log groups"). The name
# derives from the function so the two cannot drift apart. The invocation below
# depends on it — Terraform invokes this function during the apply, so without
# the edge the same apply that declares the group could let Lambda create it
# first. CreateLogGroup is create-only: an account where the function has
# already run must import the group (README, "Lambda execution log groups").
resource "aws_cloudwatch_log_group" "guardduty_scan_settings" {
  count = var.enable_guardduty && var.guardduty_keep_malware_snapshots ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.guardduty_scan_settings[0].function_name}"
  retention_in_days = var.guardduty_scan_settings_log_retention_days
  kms_key_id        = aws_kms_key.security_lambda_logs[0].arn
}

resource "aws_lambda_invocation" "guardduty_scan_settings" {
  count = var.enable_guardduty && var.guardduty_keep_malware_snapshots ? 1 : 0

  function_name   = aws_lambda_function.guardduty_scan_settings[0].function_name
  lifecycle_scope = "CRUD"

  input = jsonencode({
    detector_id  = aws_guardduty_detector.this[0].id
    preservation = "RETENTION_WITH_FINDING"
  })

  depends_on = [aws_cloudwatch_log_group.guardduty_scan_settings]
}
