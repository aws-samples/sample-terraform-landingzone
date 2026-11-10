# Bootstrap module: S3 State Bucket, DynamoDB Lock Table, optional KMS Key

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  arn_prefix = "arn:${local.partition}"
  account_id = data.aws_caller_identity.current.account_id
  create_kms = var.kms_key_alias != ""
}

# --- Optional KMS Key for SSE-KMS ---

resource "aws_kms_key" "state" {
  count = local.create_kms ? 1 : 0

  description             = "KMS key for Terraform state bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/bootstrap/kms-key-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
  })))
}

resource "aws_kms_alias" "state" {
  count = local.create_kms ? 1 : 0

  name          = "alias/${var.kms_key_alias}"
  target_key_id = aws_kms_key.state[0].key_id
}

# --- S3 State Bucket ---

resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket_name
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  #checkov:skip=CKV2_AWS_67:the only CMK here is aws_kms_key.state, created with enable_key_rotation = true when kms_key_alias is set; without it the bucket uses SSE-S3 (AES256) and no CMK exists to rotate
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.create_kms ? "aws:kms" : "AES256"
      kms_master_key_id = local.create_kms ? aws_kms_key.state[0].arn : null
    }
    bucket_key_enabled = local.create_kms
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --- DynamoDB Lock Table ---

resource "aws_dynamodb_table" "lock" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  # The lock table follows the module's optional state KMS key: with
  # kms_key_alias set, lock metadata is encrypted with the same customer-managed
  # key as the state bucket (one trust domain, no additional key); without an
  # alias the DynamoDB service default (AWS-owned key) applies. The table holds
  # only lock metadata (LockID, digest) — no state content, no secrets.
  dynamic "server_side_encryption" {
    for_each = local.create_kms ? [1] : []
    content {
      enabled     = true
      kms_key_arn = aws_kms_key.state[0].arn
    }
  }
}
