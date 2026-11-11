# =============================================================================
# Central S3 Bucket
# =============================================================================
# Created in the account of the provider the caller passes in. The
# management/logging stack runs with the management account's provider (it
# has no cross_account.hcl), so the bucket lives in the management account;
# log_archive_account_id only appears in its name.

resource "aws_s3_bucket" "central_logs" {
  bucket              = local.bucket_name
  force_destroy       = var.force_destroy
  object_lock_enabled = var.enable_s3_object_lock
}

# --- S3 Object Lock Configuration ---

resource "aws_s3_bucket_object_lock_configuration" "central_logs" {
  count  = var.enable_s3_object_lock ? 1 : 0
  bucket = aws_s3_bucket.central_logs.id

  rule {
    default_retention {
      mode = var.s3_object_lock_config.retention_mode
      days = var.s3_object_lock_config.retention_days
    }
  }
}

check "s3_object_lock_creation_warning" {
  assert {
    condition     = !var.enable_s3_object_lock || var.force_destroy
    error_message = "S3 Object Lock is enabled. Object Lock must be set at bucket creation time and cannot be added to existing buckets. If enabling on an existing deployment, the bucket must be re-created. Set force_destroy = true in test environments to allow bucket replacement."
  }
}

resource "aws_s3_bucket_versioning" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.log_bucket.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  # Three forms describe this bucket, in this order of precedence:
  #
  #   1. central_log_bucket_lifecycle_rules — the full rule set. When it is
  #      given, it is the whole lifecycle of the bucket and the two derived
  #      forms below fall away.
  #   2. s3_lifecycle_rules — one rule per known prefix, derived from a
  #      retention per prefix.
  #   3. neither — one rule for the whole bucket from log_retention_days.
  #
  # The two derived forms keep their exact plan; local.explicit_lifecycle is
  # what switches them off, so a deployment that sets none of the rule-set
  # inputs keeps the derived configuration.

  dynamic "rule" {
    for_each = local.central_log_lifecycle_rules
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

  # Default single-rule behavior when s3_lifecycle_rules is not provided
  dynamic "rule" {
    for_each = local.explicit_central_log_lifecycle || var.s3_lifecycle_rules != null ? [] : [1]
    content {
      id     = "log-retention"
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

  # Per-prefix rules when s3_lifecycle_rules is provided
  dynamic "rule" {
    for_each = local.explicit_central_log_lifecycle || var.s3_lifecycle_rules == null ? {} : local.lifecycle_rules
    content {
      id     = rule.key
      status = "Enabled"

      filter {
        prefix = rule.value.prefix
      }

      expiration {
        days = coalesce(rule.value.retention_days, var.log_retention_days)
      }

      noncurrent_version_expiration {
        noncurrent_days = coalesce(rule.value.retention_days, var.log_retention_days)
      }

      dynamic "transition" {
        for_each = rule.value.glacier_transition_days != null ? [rule.value.glacier_transition_days] : []
        content {
          days          = transition.value
          storage_class = "GLACIER"
        }
      }

      dynamic "transition" {
        for_each = rule.value.deep_archive_transition_days != null ? [rule.value.deep_archive_transition_days] : []
        content {
          days          = transition.value
          storage_class = "DEEP_ARCHIVE"
        }
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = 7
      }
    }
  }

  # --- GuardDuty root-export remediation ---
  # While the GuardDuty export was broken, a workaround pointed the publishing
  # destination at the bare bucket, so findings were written to the bucket root
  # as AWSLogs/<account-id>/GuardDuty/... instead of under guardduty/. Those
  # objects sit outside every prefixed rule above and would otherwise be
  # retained forever. One rule per detector account expires them — current
  # versions via expiration, the noncurrent versions the versioned bucket then
  # holds via noncurrent_version_expiration, so the storage is actually
  # reclaimed and not just hidden behind delete markers.
  #
  # The /GuardDuty/ path segment is pinned in the literal prefix, so the rule
  # cannot match any other writer of this bucket: the org trail and Config
  # write under cloudtrail/ and config/, Macie under macie/, CUR under cur/,
  # access logs under s3-access-logs/ — and an account trail configured
  # without a key prefix writes AWSLogs/<account>/CloudTrail/..., whose third
  # segment differs. A bare AWSLogs/ rule would catch exactly that trail data,
  # which is why the prefix carries the account id and service segment.
  #
  # The rules are additive in every lifecycle form of this bucket, including
  # the explicit central_log_bucket_lifecycle_rules set: they remediate a
  # historical mistake and are driven by their own opt-in variable — remove
  # guardduty_root_export_cleanup once the root objects are gone and the rules
  # disappear with it.
  dynamic "rule" {
    for_each = local.guardduty_root_cleanup_rules
    content {
      id     = "guardduty-root-export-cleanup-${rule.key}"
      status = "Enabled"

      filter {
        prefix = rule.value
      }

      expiration {
        days = var.guardduty_root_export_cleanup.retention_days
      }

      noncurrent_version_expiration {
        noncurrent_days = var.guardduty_root_export_cleanup.retention_days
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = 7
      }
    }
  }
}

# --- S3 Access Logging ---
# Only into the separate access logs bucket. The central bucket cannot log
# into itself: its policy has no grant for the logging service, its SSE-KMS
# default encryption is not a supported target, and a bucket that logs into
# itself writes logs about its own logs. Without the separate bucket, object
# access to the central bucket is recorded by the S3 data events of the
# organization trail (cloudtrail_s3_data_events).

resource "aws_s3_bucket_logging" "central_logs" {
  count  = var.enable_separate_access_logs_bucket ? 1 : 0
  bucket = aws_s3_bucket.central_logs.id

  target_bucket = aws_s3_bucket.access_logs[0].id
  target_prefix = "s3-access-logs/"
}

# --- S3 Bucket Policy for CloudTrail and Config Delivery ---

locals {
  # The GuardDuty grant of the bucket policy must track the configured export
  # prefix, or overriding the prefix breaks the export. Normalised the same
  # way the security module derives its destination path: trimmed slashes,
  # then one trailing slash — an empty prefix grants the bucket root.
  guardduty_export_policy_prefix = (
    trim(var.guardduty_export_prefix, "/") != ""
    ? "${trim(var.guardduty_export_prefix, "/")}/"
    : ""
  )

  # The generated bucket policy plus any user-supplied statements, appended in
  # list order — the merge is deterministic and keeps every other top-level
  # field of the document. The documents themselves come as strings from the
  # configuration layer; the module reads no file beyond its own template.
  central_log_bucket_base_policy = jsondecode(templatefile("${path.module}/../../configurations/policies/logging/s3-central-logs-bucket-policy.json", {
    dns_suffix              = local.dns_suffix
    bucket_arn              = aws_s3_bucket.central_logs.arn
    arn_prefix              = local.arn_prefix
    region                  = local.region
    account_id              = local.account_id
    organization_id         = var.organization_id
    guardduty_export_prefix = local.guardduty_export_policy_prefix
    # The GuardDuty and Macie grants admit every account whose export writes
    # here (main.tf, export_source_accounts): a string for one account, a JSON
    # array for more.
    export_source_accounts_json = local.export_source_accounts_json
    # The CloudTrail grants are scoped to the organization trail by
    # aws:SourceArn; CreateTrail validates them synchronously, so the name in
    # the policy must be the name of the trail — a renamed trail without this
    # fails with InsufficientS3BucketPolicyException.
    org_trail_name = var.cloudtrail_org_trail_name
  }))

  central_log_bucket_policy = merge(local.central_log_bucket_base_policy, {
    Statement = concat(
      local.central_log_bucket_base_policy.Statement,
      flatten([
        for doc in var.central_log_bucket_policies.s3_attachments :
        jsondecode(doc).Statement
      ]),
    )
  })
}

resource "aws_s3_bucket_policy" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  # An override replaces the generated policy entirely and is normalized like
  # every other policy document of the repository. The confirmation switch is
  # read here too: the validation already rejects an unconfirmed override in
  # the plan, and the expression keeps the confirmation authoritative at the
  # one place that acts on it.
  policy = (
    var.central_log_bucket_policies.s3_override != null && var.allow_bucket_policy_overrides
    ? jsonencode(jsondecode(var.central_log_bucket_policies.s3_override))
    : jsonencode(local.central_log_bucket_policy)
  )

  depends_on = [aws_s3_bucket_public_access_block.central_logs]
}

# --- GuardDuty export folder marker ---
# CreatePublishingDestination validates that the "folder" named by
# destinationArn exists. S3 has no folders — the check is satisfied by a
# zero-byte object whose key is the prefix with a trailing slash. Without it
# AWS answers 400 "The request failed because the resource folder specified in
# the destinationArn parameter does not exist" and the export cannot be created
# on a fresh bucket at all. The key comes from the same derivation as the
# PutObject grant, so marker, grant and destination cannot drift apart.
#
# Object-lock caveat: with enable_s3_object_lock and COMPLIANCE retention this
# marker cannot be deleted until retention lapses, so a destroy of the logging
# unit fails on it even with force_destroy. Known and accepted — do not "fix"
# it here.
resource "aws_s3_object" "guardduty_export_marker" {
  count = local.guardduty_export_policy_prefix != "" ? 1 : 0

  bucket  = aws_s3_bucket.central_logs.id
  key     = local.guardduty_export_policy_prefix
  content = ""

  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.log_bucket.arn

  # The marker must never be written before the bucket's default encryption and
  # its policy exist: Terraform is otherwise free to order the object first.
  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.central_logs,
    aws_s3_bucket_policy.central_logs,
  ]
}
