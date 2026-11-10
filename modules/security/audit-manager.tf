# =============================================================================
# Audit Manager — Conditional (skip in aws-eusc partition)
# =============================================================================
# Audit Manager is not available in the aws-eusc partition (AWS Services by
# Region, eusc-de-east-1). Every resource of
# the service block below — including the reports bucket, which exists only to
# serve the service — is gated on !local.is_eusc, following the Macie pattern.

locals {
  # One derivation for every Audit Manager resource of this file.
  audit_manager_active = var.enable_audit_manager && !local.is_eusc
}

# Audit Manager knows exactly one registration per account and region, so
# exactly one resource block manages it. delegated_admin_account and kms_key are
# optional arguments of that same registration.
resource "aws_auditmanager_account_registration" "this" {
  count = local.audit_manager_active ? 1 : 0

  delegated_admin_account = var.audit_account_id != "" ? var.audit_account_id : null
  kms_key                 = var.audit_manager_reports_destination != null ? var.audit_manager_reports_destination.kms_key_arn : null
}

resource "aws_organizations_delegated_administrator" "audit_manager" {
  count = local.audit_manager_active && var.audit_account_id != "" ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "auditmanager.${local.dns_suffix}"
}

# Without this check the skip would be silent: enable_audit_manager = true
# would look like it took effect. The check warns instead of failing (same
# convention as macie_partition_availability).
check "audit_manager_partition_availability" {
  assert {
    condition     = !(var.enable_audit_manager && local.is_eusc)
    error_message = "enable_audit_manager is true but Audit Manager is not available in the aws-eusc partition. All Audit Manager resources (including the reports bucket) are skipped in this deployment. Set enable_audit_manager = false to suppress this warning."
  }
}

# AWS put Audit Manager into maintenance mode: as of April 30, 2026 the API
# refuses NEW account registrations (and registrations in new regions) with a
# ValidationException at apply time. Accounts registered BEFORE the cutoff
# keep working, and the registration resource above must keep managing them —
# which is why this is a warning and not a failing precondition: a hard fail
# would break every pre-cutoff deployment that legitimately keeps
# enable_audit_manager = true, and plan time cannot distinguish an existing
# registration from a new one. Same convention as the two checks around it:
# surface the documented service limitation before the AWS 400 does.
check "audit_manager_maintenance_mode" {
  assert {
    condition     = !var.enable_audit_manager
    error_message = "enable_audit_manager is true, but AWS Audit Manager is in maintenance mode: as of April 30, 2026 AWS refuses NEW account registrations (and new regions) with a ValidationException at apply time. An account that registered before the cutoff keeps working and stays managed — this warning is expected there. If this account never registered Audit Manager, set enable_audit_manager = false; the apply will fail otherwise."
  }
}

# =============================================================================
# Audit Manager Reports Destination — partially supported by the provider
# =============================================================================
# Of var.audit_manager_reports_destination only kms_key_arn reaches AWS: it is
# applied above as the Audit Manager account KMS key. The account registration
# has no argument for an assessment reports destination — the provider exposes
# that destination per assessment (aws_auditmanager_assessment), which needs a
# framework, roles and a scope and is therefore not part of this module.
# s3_bucket_name and s3_prefix are consequently recorded but not applied.

check "audit_manager_reports_destination_provider_limitation" {
  assert {
    condition     = var.audit_manager_reports_destination == null
    error_message = "audit_manager_reports_destination is set. Only its kms_key_arn is applied (as the Audit Manager account KMS key); s3_bucket_name and s3_prefix are not, because aws_auditmanager_account_registration has no reports destination argument — the destination belongs to an assessment (aws_auditmanager_assessment). Use enable_audit_manager_bucket for a module-managed reports bucket, or set the destination on the assessment."
  }
}

# =============================================================================
# Audit Manager S3 Reports Bucket
# =============================================================================

resource "aws_s3_bucket" "audit_manager_reports" {
  count = local.audit_manager_active && var.enable_audit_manager_bucket ? 1 : 0

  bucket_prefix = "tlz-audit-manager-reports-"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "audit_manager_reports" {
  count = local.audit_manager_active && var.enable_audit_manager_bucket ? 1 : 0

  bucket = aws_s3_bucket.audit_manager_reports[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_manager_reports" {
  #checkov:skip=CKV2_AWS_67:default is SSE-S3 (AES256) with no CMK; audit_manager_bucket_kms_key_arn is a caller-owned key whose rotation is set where that key is defined, not here
  count = local.audit_manager_active && var.enable_audit_manager_bucket ? 1 : 0

  bucket = aws_s3_bucket.audit_manager_reports[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.audit_manager_bucket_kms_key_arn != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.audit_manager_bucket_kms_key_arn != "" ? var.audit_manager_bucket_kms_key_arn : null
    }
    bucket_key_enabled = var.audit_manager_bucket_kms_key_arn != "" ? true : false
  }
}

resource "aws_s3_bucket_public_access_block" "audit_manager_reports" {
  count = local.audit_manager_active && var.enable_audit_manager_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.audit_manager_reports[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_manager_reports" {
  # OR-form after the GuardDuty pattern (guardduty.tf): explicit rules apply
  # independently of the derived rule's day count, so audit_manager_bucket_
  # lifecycle_rules are not dropped silently when lifecycle_days = 0.
  # The derived rule below stays bound to days > 0: without explicit rules the
  # count still requires it, and with explicit rules the dynamic block skips
  # the derived rule entirely.
  count = local.audit_manager_active && var.enable_audit_manager_bucket && (var.audit_manager_bucket_lifecycle_days > 0 || local.explicit_audit_manager_lifecycle) ? 1 : 0

  bucket = aws_s3_bucket.audit_manager_reports[0].id

  dynamic "rule" {
    for_each = local.audit_manager_lifecycle_rules
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

  # The derived rule set. It drops out as soon as an explicit rule set
  # describes the bucket's lifecycle — with default input the plan stays
  # literally the same.
  dynamic "rule" {
    for_each = local.explicit_audit_manager_lifecycle ? [] : [1]
    content {

      id     = "audit-manager-reports-lifecycle"
      status = "Enabled"

      expiration {
        days = var.audit_manager_bucket_lifecycle_days
      }

      noncurrent_version_expiration {
        noncurrent_days = var.audit_manager_bucket_lifecycle_days
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = 7
      }
    }
  }

}
