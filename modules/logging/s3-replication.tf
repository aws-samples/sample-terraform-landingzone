# =============================================================================
# S3 Cross-Region Replication
# =============================================================================

# --- IAM Role for S3 Replication ---

resource "aws_iam_role" "replication" {
  count = local.replication_enabled ? 1 : 0

  name = "tlz-s3-replication-role"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/s3-replication-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "replication" {
  count = local.replication_enabled ? 1 : 0

  name = "tlz-s3-replication-policy"
  role = aws_iam_role.replication[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/s3-replication-policy.json", {
    source_bucket_arn       = aws_s3_bucket.central_logs.arn
    destination_bucket_arn  = local.replication_dest_bucket_arn
    source_kms_key_arn      = aws_kms_key.log_bucket.arn
    destination_kms_key_arn = local.replication_dest_kms_key_arn
  })))
}

# --- Destination KMS Key (auto-created when no destination_kms_key_arn provided) ---
#
# Every auto-created destination resource below — the replica key, its alias,
# the bucket and each bucket-configuration sibling — is pinned to
# destination_region. Without the argument the provider (~> 6.0, per-resource
# region) created them in the deployment's own region: the bucket NAME carried
# the destination region, the replication rule pointed at that name, S3
# same-region replication is legal, so the apply was green and the "cross-
# region" replica sat next to its source. A replica KMS key must live in the
# bucket's region, so the key and alias move with it.
# Migration: a replica that was already deployed in the source region is
# REPLACED by the next plan (region forces a new resource). Its bucket has to be
# empty for the destroy (force_destroy stays the operator's call), and the
# global bucket name is unavailable for a while after deletion — see the
# module README, "S3 Cross-Region Replication", before applying.

resource "aws_kms_key" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region

  description             = "KMS key for S3 replication destination bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-replication-dest-key-policy.json", {
    arn_prefix           = local.arn_prefix
    account_id           = local.account_id
    replication_role_arn = aws_iam_role.replication[0].arn
    dns_suffix           = local.dns_suffix
  })))
}

resource "aws_kms_alias" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region

  name          = "alias/tlz-central-logs-replica"
  target_key_id = aws_kms_key.replication_dest[0].key_id
}

# --- Destination S3 Bucket (auto-created when no destination_bucket_arn provided) ---

resource "aws_s3_bucket" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region

  bucket        = local.replication_dest_bucket_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region
  bucket = aws_s3_bucket.replication_dest[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region
  bucket = aws_s3_bucket.replication_dest[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replication_dest[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region
  bucket = aws_s3_bucket.replication_dest[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region
  bucket = aws_s3_bucket.replication_dest[0].id

  rule {
    id     = "replica-retention"
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

resource "aws_s3_bucket_policy" "replication_dest" {
  count  = local.create_replication_dest_bucket ? 1 : 0
  region = var.s3_replication_config.destination_region
  bucket = aws_s3_bucket.replication_dest[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/s3-replication-dest-bucket-policy.json", {
    replication_role_arn = aws_iam_role.replication[0].arn
    bucket_arn           = aws_s3_bucket.replication_dest[0].arn
  })))

  depends_on = [aws_s3_bucket_public_access_block.replication_dest]
}

# --- S3 Replication Configuration on Source Bucket ---

# destination_region equal to the deployment region turns the "cross-region"
# replica into a same-region copy: legal for S3, invisible in the plan, and no
# disaster-recovery value. variables.tf cannot compare against the region (it
# is only known through the provider), so the comparison lives here. A warning
# rather than a precondition: same-region replication is a supported AWS
# feature, and a deployment that chose it deliberately keeps its plan — the
# convention of audit_manager_maintenance_mode in modules/security, not of the
# hard CUR us-east-1 precondition, whose region mismatch AWS would reject.
check "replication_destination_is_cross_region" {
  assert {
    condition     = !local.replication_enabled || var.s3_replication_config.destination_region != local.region
    error_message = "s3_replication_config.destination_region ('${var.s3_replication_config.destination_region}') is the region of this deployment ('${local.region}'). The replica bucket is created in the same region as the central log bucket — a same-region copy, not cross-region disaster recovery. Choose a different destination_region, or keep this value if same-region replication is intended."
  }
}

resource "aws_s3_bucket_replication_configuration" "central_logs" {
  count = local.replication_enabled ? 1 : 0

  role   = aws_iam_role.replication[0].arn
  bucket = aws_s3_bucket.central_logs.id

  dynamic "rule" {
    for_each = { for r in local.replication_rules : r.id => r }
    content {
      id       = rule.value.id
      priority = rule.value.priority
      status   = rule.value.status

      filter {
        prefix = rule.value.prefix
      }

      destination {
        bucket        = local.replication_dest_bucket_arn
        storage_class = "STANDARD"

        encryption_configuration {
          replica_kms_key_id = local.replication_dest_kms_key_arn
        }
      }

      source_selection_criteria {
        sse_kms_encrypted_objects {
          status = "Enabled"
        }
      }

      delete_marker_replication {
        status = "Enabled"
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.central_logs,
    aws_s3_bucket_versioning.replication_dest,
  ]
}
