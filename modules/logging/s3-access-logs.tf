# =============================================================================
# Separate Access Logs Bucket
# =============================================================================

resource "aws_s3_bucket" "access_logs" {
  count = var.enable_separate_access_logs_bucket ? 1 : 0

  # An adopted bucket keeps its name (docs/resource-adoption.md); empty
  # derives the conventional name — bucket_name_prefix (default tlz-) plus
  # the family suffix — and keeps the existing plan.
  bucket = (
    var.adopted_access_logs_bucket_name != ""
    ? var.adopted_access_logs_bucket_name
    : "${var.bucket_name_prefix}access-logs-${var.log_archive_account_id}-${local.region}"
  )
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "access_logs" {
  count  = var.enable_separate_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3, not the log bucket key: S3 server access logging does not support a
# target bucket with SSE-KMS default encryption (S3 user guide, "Enabling
# Amazon S3 server access logging").
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  count  = var.enable_separate_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  count  = var.enable_separate_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  count  = var.enable_separate_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  dynamic "rule" {
    for_each = local.access_logs_lifecycle_rules
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
  dynamic "rule" {
    for_each = local.explicit_access_logs_lifecycle ? [] : [1]
    content {

      id     = "access-log-retention"
      status = "Enabled"

      expiration {
        days = var.log_retention_days
      }

      noncurrent_version_expiration {
        noncurrent_days = var.log_retention_days
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = 7
      }
    }
  }

}

locals {
  # The generated bucket policy plus any user-supplied statements, appended in
  # list order — same deterministic merge as on the central log bucket. The
  # one() keeps the expression valid while the bucket toggle is off; the
  # variable validation ties non-empty documents to the toggle.
  access_logs_bucket_base_policy = var.enable_separate_access_logs_bucket ? jsondecode(templatefile("${path.module}/../../configurations/policies/logging/s3-access-logs-bucket-policy.json", {
    dns_suffix = local.dns_suffix
    bucket_arn = one(aws_s3_bucket.access_logs[*].arn)
    account_id = local.account_id
  })) : null

  access_logs_bucket_policy = var.enable_separate_access_logs_bucket ? merge(local.access_logs_bucket_base_policy, {
    Statement = concat(
      local.access_logs_bucket_base_policy.Statement,
      flatten([
        for doc in var.access_logs_bucket_policies.s3_attachments :
        jsondecode(doc).Statement
      ]),
    )
  }) : null
}

resource "aws_s3_bucket_policy" "access_logs" {
  count  = var.enable_separate_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  # An override replaces the generated policy entirely and is normalized like
  # every other policy document of the repository. The confirmation switch is
  # read here too: the validation already rejects an unconfirmed override in
  # the plan, and the expression keeps the confirmation authoritative at the
  # one place that acts on it.
  policy = (
    var.access_logs_bucket_policies.s3_override != null && var.allow_bucket_policy_overrides
    ? jsonencode(jsondecode(var.access_logs_bucket_policies.s3_override))
    : jsonencode(local.access_logs_bucket_policy)
  )

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}
