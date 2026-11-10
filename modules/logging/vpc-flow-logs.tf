# =============================================================================
# VPC Flow Logs Dedicated S3 Bucket
# =============================================================================

resource "aws_s3_bucket" "vpc_flow_logs" {
  count = var.enable_vpc_flow_logs_bucket ? 1 : 0

  # An adopted bucket keeps its name (docs/resource-adoption.md); empty
  # derives the conventional name — bucket_name_prefix (default tlz-) plus
  # the family suffix — and keeps the existing plan.
  bucket = (
    var.adopted_vpc_flow_logs_bucket_name != ""
    ? var.adopted_vpc_flow_logs_bucket_name
    : "${var.bucket_name_prefix}vpc-flow-logs-${local.account_id}-${local.region}"
  )
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "vpc_flow_logs" {
  count  = var.enable_vpc_flow_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.vpc_flow_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "vpc_flow_logs" {
  count  = var.enable_vpc_flow_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.vpc_flow_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vpc_flow_logs" {
  count  = var.enable_vpc_flow_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.vpc_flow_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_bucket.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vpc_flow_logs" {
  count  = var.enable_vpc_flow_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.vpc_flow_logs[0].id

  dynamic "rule" {
    for_each = local.vpc_flow_logs_lifecycle_rules
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
    for_each = local.explicit_vpc_flow_logs_lifecycle ? [] : [1]
    content {

      id     = "vpc-flow-logs-retention"
      status = "Enabled"

      expiration {
        days = var.vpc_flow_logs_bucket_config.retention_days
      }

      noncurrent_version_expiration {
        noncurrent_days = var.vpc_flow_logs_bucket_config.retention_days
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = 7
      }
    }
  }

}

resource "aws_s3_bucket_policy" "vpc_flow_logs" {
  count  = var.enable_vpc_flow_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.vpc_flow_logs[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/s3-vpc-flow-logs-bucket-policy.json", {
    dns_suffix = local.dns_suffix
    bucket_arn = aws_s3_bucket.vpc_flow_logs[0].arn
    account_id = local.account_id
  })))

  depends_on = [aws_s3_bucket_public_access_block.vpc_flow_logs]
}

# --- VPC Flow Logs Replication to Central Logs Bucket ---

resource "aws_iam_role" "vpc_flow_logs_replication" {
  count = var.enable_vpc_flow_logs_bucket ? 1 : 0
  name  = "tlz-vpc-flow-logs-replication"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/vpc-flow-logs-replication-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "vpc_flow_logs_replication" {
  count = var.enable_vpc_flow_logs_bucket ? 1 : 0
  name  = "tlz-vpc-flow-logs-replication-policy"
  role  = aws_iam_role.vpc_flow_logs_replication[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/vpc-flow-logs-replication-policy.json", {
    source_bucket_arn       = aws_s3_bucket.vpc_flow_logs[0].arn
    destination_bucket_arn  = aws_s3_bucket.central_logs.arn
    source_kms_key_arn      = aws_kms_key.log_bucket.arn
    destination_kms_key_arn = aws_kms_key.log_bucket.arn
  })))
}

resource "aws_s3_bucket_replication_configuration" "vpc_flow_logs" {
  count  = var.enable_vpc_flow_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.vpc_flow_logs[0].id
  role   = aws_iam_role.vpc_flow_logs_replication[0].arn

  rule {
    id     = "replicate-to-central"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.central_logs.arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.log_bucket.arn
      }
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.vpc_flow_logs,
    aws_s3_bucket_versioning.central_logs,
  ]
}
