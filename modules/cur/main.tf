# modules/cur — AWS Cost and Usage Report
# NOTE: CUR is only available in us-east-1.

# --- Partition Detection ---
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  dns_suffix = data.aws_partition.current.dns_suffix
  arn_prefix = "arn:${local.partition}"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region

  # Supported partitions are aws and aws-eusc. The report definition requires
  # the us-east-1 billing region, which does not exist in aws-eusc, and the
  # availability of the service there is not confirmed. The module therefore
  # skips creation in aws-eusc and surfaces the skip through the check block
  # below instead of silently planning a resource that cannot be applied.
  is_eusc        = local.partition == "aws-eusc"
  cur_enabled    = var.enable_cost_and_usage_report && !local.is_eusc
  bucket_enabled = local.cur_enabled && var.enable_dedicated_bucket

  cur_bucket_name  = "tlz-cur-${local.account_id}-${local.region}"
  effective_bucket = local.bucket_enabled ? aws_s3_bucket.cur[0].id : var.s3_bucket_name

  # Full lifecycle rule set of the dedicated CUR bucket. The flag tests for
  # null, not for emptiness: null means "keep the derived rule", the empty
  # list is the explicit statement "no rules".
  explicit_cur_lifecycle     = var.cur_bucket_lifecycle_rules != null
  cur_bucket_lifecycle_rules = coalesce(var.cur_bucket_lifecycle_rules, [])

  # KMS policy object (externalized concat wrapper)
  cur_kms_policy = {
    Version = "2012-10-17"
    Statement = concat(
      jsondecode(templatefile("${path.module}/../../configurations/policies/cur/kms-key-policy.json", {
        arn_prefix = local.arn_prefix
        account_id = local.account_id
        dns_suffix = local.dns_suffix
      })).Statement,
      length(var.kms_key_administrators) > 0 ? [
        jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-key-administrators-statement.json", {
          kms_key_administrators_json = jsonencode(var.kms_key_administrators)
        })),
      ] : [],
    )
  }
}

# --- Partition Guard Warning ---
check "cur_eusc_warning" {
  assert {
    condition     = !local.is_eusc || !var.enable_cost_and_usage_report
    error_message = "Cost and Usage Report availability is not confirmed in the aws-eusc partition, and the report definition requires the us-east-1 billing region, which does not exist there. CUR resources will be skipped."
  }
}

# =============================================================================
# Dedicated CUR S3 Bucket
# =============================================================================

resource "aws_kms_key" "cur" {
  count = local.bucket_enabled ? 1 : 0

  description             = "KMS key for CUR S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode(local.cur_kms_policy)
}

resource "aws_kms_alias" "cur" {
  count = local.bucket_enabled ? 1 : 0

  name          = "alias/tlz/cur/kms"
  target_key_id = aws_kms_key.cur[0].key_id
}

resource "aws_s3_bucket" "cur" {
  count = local.bucket_enabled ? 1 : 0

  bucket        = local.cur_bucket_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "cur" {
  count  = local.bucket_enabled ? 1 : 0
  bucket = aws_s3_bucket.cur[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cur" {
  count  = local.bucket_enabled ? 1 : 0
  bucket = aws_s3_bucket.cur[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cur[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cur" {
  count  = local.bucket_enabled ? 1 : 0
  bucket = aws_s3_bucket.cur[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cur" {
  count  = local.bucket_enabled ? 1 : 0
  bucket = aws_s3_bucket.cur[0].id

  # Two forms describe this bucket: cur_bucket_lifecycle_rules — the full rule
  # set — and, when it stays null, the single rule the module
  # derives from the 365-day expiration, noncurrent_version_expiration_days
  # and abort_incomplete_multipart_upload_days. The derived rule keeps its
  # exact plan; local.explicit_cur_lifecycle is what switches it off, so a
  # deployment that sets nothing keeps the derived configuration.

  dynamic "rule" {
    for_each = local.cur_bucket_lifecycle_rules
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

  # Derived single-rule behavior when no rule set is provided
  dynamic "rule" {
    for_each = local.explicit_cur_lifecycle ? [] : [1]
    content {
      id     = "cur-lifecycle"
      status = "Enabled"

      expiration {
        days = 365
      }

      noncurrent_version_expiration {
        noncurrent_days = var.noncurrent_version_expiration_days
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = var.abort_incomplete_multipart_upload_days
      }
    }
  }
}

resource "aws_s3_bucket_policy" "cur" {
  count  = local.bucket_enabled ? 1 : 0
  bucket = aws_s3_bucket.cur[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/cur/s3-bucket-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
    bucket_arn = aws_s3_bucket.cur[0].arn
  })))

  depends_on = [aws_s3_bucket_public_access_block.cur]
}

# =============================================================================
# CUR Report Definition
# =============================================================================

resource "aws_cur_report_definition" "this" {
  for_each = local.cur_enabled ? toset(["this"]) : toset([])

  report_name                = var.cur_config.report_name
  time_unit                  = var.cur_config.time_unit
  format                     = var.cur_config.format
  compression                = var.cur_config.compression
  additional_schema_elements = var.cur_config.additional_schema_elements
  report_versioning          = var.cur_config.report_versioning

  # null leaves both arguments unset: no manifests are requested and the API
  # default for refreshing closed reports stays untouched — the state every
  # deployment had before the two attributes existed.
  additional_artifacts   = var.cur_config.additional_artifacts
  refresh_closed_reports = var.cur_config.refresh_closed_reports

  s3_bucket = local.effective_bucket
  s3_prefix = var.cur_config.s3_prefix
  s3_region = var.s3_bucket_region != "" ? var.s3_bucket_region : local.region

  # PutReportDefinition verifies AT CALL TIME that the destination bucket's
  # policy grants billingreports.amazonaws.com the reads and writes it needs.
  # Terraform orders the report after the bucket itself (through
  # local.effective_bucket) but knew nothing of the policy, so a first apply
  # could reach the API before the policy was attached and fail with
  # "Failed to verify customer bucket permission" — intermittently, depending
  # on graph order. Same pattern as the trail in modules/logging/cloudtrail.tf,
  # which waits on aws_s3_bucket_policy.central_logs for the same reason.
  # Harmless when count is 0 (external bucket, policy managed elsewhere).
  depends_on = [aws_s3_bucket_policy.cur]

  lifecycle {
    # The note at the top of this file was always true and never asserted:
    # the CUR API lives only in us-east-1, and PutReportDefinition from any
    # other provider region fails at apply — after the dedicated bucket group
    # may already have been created in the wrong region. This is a hard
    # precondition, deliberately not a check-block warning like
    # cur_eusc_warning above: in aws-eusc the module can only skip (the
    # service does not exist in the partition, the warning documents the
    # skip), while a wrong region in the aws partition is a caller error with
    # a caller-side fix — configure the provider for us-east-1, as
    # stacks/management/cur does via its provider override. Skipping silently
    # would drop a report that was explicitly requested, and a warning in a
    # run-all plan is easy to miss; a failed plan is not.
    precondition {
      condition     = local.region == "us-east-1"
      error_message = "Cost and Usage Report definitions can only be created in us-east-1 — the provider is configured for another region. Configure the CUR provider for us-east-1 (see the provider override in stacks/management/cur/terragrunt.hcl)."
    }

    # With an external bucket the s3_region fallback above is a guess: after
    # the us-east-1 precondition it always names us-east-1, which is the
    # external bucket's region only by coincidence, and CUR rejects a region
    # that does not match the bucket's real location. The region is required
    # explicitly instead of derived via data.aws_s3_bucket because a fresh
    # install plans against Terragrunt mock outputs — a bucket name that does
    # not exist yet — and the data source would fail exactly there. Only the
    # dedicated bucket may fall back: the module creates it in the provider
    # region, so the fallback is its real location by construction.
    precondition {
      condition     = var.enable_dedicated_bucket || var.s3_bucket_region != ""
      error_message = "s3_bucket_region is required when the report is delivered to an external bucket (enable_dedicated_bucket = false) — the provider-region fallback would only match the bucket's real location by coincidence, and CUR rejects a mismatch."
    }
  }
}
