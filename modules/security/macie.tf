# =============================================================================
# Macie — Conditional (skip in aws-eusc partition)
# =============================================================================

# Macie knows exactly one activation per account and region, so exactly one
# resource block manages it. finding_publishing_frequency is an optional
# argument of that same activation; null keeps the AWS default.
resource "aws_macie2_account" "this" {
  count = var.enable_macie && !local.is_eusc ? 1 : 0

  finding_publishing_frequency = var.macie_publishing_frequency

  # A region listed in macie_disabled_regions keeps its activation managed but
  # suspended: analysis and billing stop, configuration and findings remain,
  # removing the region resumes the session. ENABLED is the provider default,
  # so deployments without the list keep their plan.
  status = contains(var.macie_disabled_regions, local.region) ? "PAUSED" : "ENABLED"

  depends_on = [aws_organizations_delegated_administrator.macie]
}

# Same audit_account_id guard as every other delegated-admin registration in
# this module (delegated-admin.tf, detective.tf, audit-manager.tf): without it
# an empty Audit account passes the plan (the audit_account_configured check
# only warns) and the API rejects admin_account_id = "" at apply time.
resource "aws_macie2_organization_admin_account" "this" {
  count = var.enable_macie && !local.is_eusc && var.audit_account_id != "" ? 1 : 0

  admin_account_id = var.audit_account_id

  depends_on = [aws_macie2_account.this]
}

# =============================================================================
# Macie Sensitive Data Findings
# =============================================================================

resource "aws_macie2_classification_export_configuration" "this" {
  count = var.enable_macie && !local.is_eusc && var.macie_publish_sensitive_data_findings == true && var.central_log_bucket_name != "" ? 1 : 0

  s3_destination {
    bucket_name = var.central_log_bucket_name
    key_prefix  = "macie/classification-results/"
    kms_key_arn = var.guardduty_export_kms_key_arn != "" ? var.guardduty_export_kms_key_arn : null
  }

  # Same defence as the GuardDuty export (aws_guardduty_publishing_destination):
  # the Macie API requires a KMS key for the S3 destination and rejects a null
  # kms_key_arn at apply time — the precondition turns that into a plan error.
  lifecycle {
    precondition {
      condition     = var.guardduty_export_kms_key_arn != ""
      error_message = "guardduty_export_kms_key_arn must be set when macie_publish_sensitive_data_findings and central_log_bucket_name are configured. The Macie classification export requires a KMS key for its S3 destination and AWS rejects an empty value."
    }
  }

  depends_on = [aws_macie2_account.this]
}

check "macie_excluded_region_check" {
  assert {
    condition     = !contains(var.macie_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in macie_excluded_regions. Macie resources are still created in this deployment but the region should be excluded from multi-region configuration."
  }
}

# Macie does not exist in the aws-eusc partition, so every resource above is
# gated on !local.is_eusc and the module creates nothing. Without this check the
# skip is silent: enable_macie = true would look like it took effect. The check
# warns instead of failing, because skipping an unavailable service is the
# intended behaviour and must not block the plan.
check "macie_partition_availability" {
  assert {
    condition     = !(var.enable_macie && local.is_eusc)
    error_message = "enable_macie is true but Macie is not available in the aws-eusc partition. All Macie resources are skipped in this deployment. Set enable_macie = false to suppress this warning."
  }
}

# =============================================================================
# Macie Session Settings (automated discovery, classification scope,
# policy findings publication)
# =============================================================================
# Three Macie session APIs have no resource in the provider
# (UpdateAutomatedDiscoveryConfiguration, UpdateClassificationScope,
# PutFindingsPublicationConfiguration); the comparison base drives them
# through deploy-time functions as well. The function below is invoked by
# Terraform itself (aws_lambda_invocation, lifecycle_scope CRUD), one
# invocation per setting: it applies the declared state on create and update
# and restores the service default when the switch leaves the configuration
# (automated discovery off, no scope exclusions, policy findings published).
# With the defaults (null/empty) nothing is created and the plan of existing
# deployments stays unchanged.

locals {
  # Which of the three settings are managed in this deployment.
  macie_settings_managed = var.enable_macie && !local.is_eusc && (
    var.macie_automated_discovery != null ||
    length(var.macie_classification_scope_excluded_buckets) > 0 ||
    var.macie_publish_policy_findings != null
  )

  # The classification scope API is regional: only the bucket names declared
  # for the current region are applied here — the entries of other regions
  # belong to the deployments of those regions.
  macie_scope_excluded_names = flatten([
    for entry in var.macie_classification_scope_excluded_buckets :
    entry.names if entry.region == local.region
  ])
}

data "archive_file" "macie_session_settings" {
  count = local.macie_settings_managed ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/macie_session_settings.py"
  output_path = "${path.module}/lambda/macie_session_settings.zip"
}

resource "aws_iam_role" "macie_session_settings" {
  count = local.macie_settings_managed ? 1 : 0

  name = "tlz-macie-session-settings"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "macie_session_settings" {
  count = local.macie_settings_managed ? 1 : 0

  name = "macie-session-settings"
  role = aws_iam_role.macie_session_settings[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/macie-session-settings-lambda-policy.json", {
    log_group_arn = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/tlz-macie-session-settings:*"
  })))
}

resource "aws_lambda_function" "macie_session_settings" {
  count = local.macie_settings_managed ? 1 : 0

  function_name    = "tlz-macie-session-settings"
  description      = "Applies the Macie session settings (automated discovery, classification scope, findings publication) at deployment time"
  runtime          = "python3.12"
  handler          = "macie_session_settings.lambda_handler"
  role             = aws_iam_role.macie_session_settings[0].arn
  filename         = data.archive_file.macie_session_settings[0].output_path
  source_code_hash = data.archive_file.macie_session_settings[0].output_base64sha256
  timeout          = 30

  # The function is only ever invoked synchronously by Terraform, up to three
  # calls per apply — a single reserved execution is all it can use.
  reserved_concurrent_executions = 1

  depends_on = [aws_iam_role_policy.macie_session_settings]
}

# The function's own execution log group — same class and same reasoning as
# aws_cloudwatch_log_group.guardduty_scan_settings in this module. All three
# invocations below depend on it: which of them runs first depends on the
# toggles, so each carries the edge rather than relying on the chain between
# them. CreateLogGroup is create-only: an account where the function has already
# run must import the group (README, "Lambda execution log groups").
resource "aws_cloudwatch_log_group" "macie_session_settings" {
  count = local.macie_settings_managed ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.macie_session_settings[0].function_name}"
  retention_in_days = var.macie_session_settings_log_retention_days
  kms_key_id        = aws_kms_key.security_lambda_logs[0].arn
}

resource "aws_lambda_invocation" "macie_automated_discovery" {
  count = var.enable_macie && !local.is_eusc && var.macie_automated_discovery != null ? 1 : 0

  function_name   = aws_lambda_function.macie_session_settings[0].function_name
  lifecycle_scope = "CRUD"

  input = jsonencode({
    setting = "automated-discovery"
    status  = var.macie_automated_discovery ? "ENABLED" : "DISABLED"
  })

  depends_on = [
    aws_macie2_account.this,
    aws_cloudwatch_log_group.macie_session_settings,
  ]
}

resource "aws_lambda_invocation" "macie_classification_scope" {
  count = var.enable_macie && !local.is_eusc && length(var.macie_classification_scope_excluded_buckets) > 0 ? 1 : 0

  function_name   = aws_lambda_function.macie_session_settings[0].function_name
  lifecycle_scope = "CRUD"

  # The declared names replace the previous exclusion state of this region —
  # an empty region-local list is the explicit statement "no exclusions here".
  input = jsonencode({
    setting               = "classification-scope"
    excluded_bucket_names = local.macie_scope_excluded_names
  })

  depends_on = [
    aws_lambda_invocation.macie_automated_discovery,
    aws_cloudwatch_log_group.macie_session_settings,
  ]
}

resource "aws_lambda_invocation" "macie_publish_policy_findings" {
  count = var.enable_macie && !local.is_eusc && var.macie_publish_policy_findings != null ? 1 : 0

  function_name   = aws_lambda_function.macie_session_settings[0].function_name
  lifecycle_scope = "CRUD"

  input = jsonencode({
    setting = "publish-policy-findings"
    publish = var.macie_publish_policy_findings
  })

  depends_on = [
    aws_macie2_account.this,
    aws_cloudwatch_log_group.macie_session_settings,
  ]
}
