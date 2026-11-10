# =============================================================================
# KMS Keys
# =============================================================================

# --- KMS Key for S3 Bucket Encryption ---

resource "aws_kms_key" "log_bucket" {
  description             = "KMS key for central logging S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # An override replaces the generated key policy entirely; it is normalized
  # like every other policy document of the repository. Without one, the
  # generated policy applies, including any kms_attachments statements merged
  # in main.tf. The confirmation switch is read here too: the validation
  # already rejects an unconfirmed override in the plan, and the expression
  # keeps the confirmation authoritative at the one place that acts on it.
  policy = (
    var.central_log_bucket_policies.kms_override != null && var.allow_bucket_policy_overrides
    ? jsonencode(jsondecode(var.central_log_bucket_policies.kms_override))
    : jsonencode(local.log_bucket_kms_policy)
  )
}

resource "aws_kms_alias" "log_bucket" {
  name          = "alias/${var.log_bucket_kms_alias}"
  target_key_id = aws_kms_key.log_bucket.key_id
}

# --- Dedicated Management Account KMS Key ---

resource "aws_kms_key" "management" {
  description             = "Dedicated management account KMS key for DynamoDB and SSM encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode(local.management_kms_policy)
}

resource "aws_kms_alias" "management" {
  name          = "alias/${var.management_kms_alias}"
  target_key_id = aws_kms_key.management.key_id
}

# --- Dedicated CloudWatch Logs KMS Key ---

resource "aws_kms_key" "cloudwatch" {
  description             = "Dedicated KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode(local.cloudwatch_kms_policy)
}

resource "aws_kms_alias" "cloudwatch" {
  name          = "alias/${var.cloudwatch_kms_alias}"
  target_key_id = aws_kms_key.cloudwatch.key_id
}

# =============================================================================
# Per-Account S3 KMS Key
# =============================================================================

resource "aws_kms_key" "per_account_s3" {
  count = var.enable_per_account_kms_keys ? 1 : 0

  description             = "Per-account KMS key for S3 bucket encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-per-account-s3-key-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "per_account_s3" {
  count = var.enable_per_account_kms_keys ? 1 : 0

  name          = "alias/${var.per_account_s3_kms_alias}"
  target_key_id = aws_kms_key.per_account_s3[0].key_id
}
