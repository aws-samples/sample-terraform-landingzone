# =============================================================================
# Session Manager IAM Policy and Attachment
# =============================================================================

resource "aws_iam_policy" "session_manager_ec2" {
  count = length(var.session_manager_attach_policy_to_roles) > 0 ? 1 : 0

  name        = "tlz-SessionManagerEC2Policy"
  description = "IAM policy for Session Manager access with S3 logging, CloudWatch logging, and KMS encryption"

  # This policy attaches to instance/workload roles. The instance side of
  # Session Manager needs only the logging path (S3/CloudWatch/KMS) and
  # ssm:GetDocument; the session channel itself runs over ssmmessages, covered
  # by AmazonSSMManagedInstanceCore. ssm:StartSession/TerminateSession/
  # ResumeSession are operator-side actions and were removed from the template:
  # on "*" they allowed lateral movement (open sessions to any instance) and
  # terminating other operators' sessions from a compromised instance.
  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/session-manager-ec2-policy.json", {
    arn_prefix           = local.arn_prefix
    account_id           = local.account_id
    s3_bucket_name       = var.session_manager_s3_bucket_name
    cloudwatch_log_group = var.session_manager_cloudwatch_log_group
    kms_key_id           = var.session_manager_kms_key_id
  })))
}

resource "aws_iam_role_policy_attachment" "session_manager_ec2" {
  for_each = toset(var.session_manager_attach_policy_to_roles)

  role       = each.value
  policy_arn = aws_iam_policy.session_manager_ec2[0].arn
}

# =============================================================================
# Session Manager Logging
# =============================================================================

resource "aws_ssm_document" "session_manager" {
  count         = var.enable_session_manager_logging ? 1 : 0
  name          = "SSM-SessionManagerRunShell"
  document_type = "Session"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Session Manager configuration with S3 and CloudWatch logging"
    sessionType   = "Standard_Stream"
    inputs = merge(
      {
        s3BucketName                = var.enable_session_manager_s3_logging ? var.session_manager_s3_bucket_name : ""
        s3KeyPrefix                 = var.enable_session_manager_s3_logging ? var.session_manager_s3_key_prefix : ""
        s3EncryptionEnabled         = var.enable_session_manager_s3_logging && var.session_manager_s3_bucket_name != "" ? true : false
        cloudWatchLogGroupName      = var.session_manager_cloudwatch_log_group
        cloudWatchEncryptionEnabled = var.session_manager_cloudwatch_log_group != "" ? true : false
      },
      var.session_manager_kms_key_id != "" ? {
        kmsEncryptionEnabled = true
        kmsKeyId             = var.session_manager_kms_key_id
      } : {}
    )
  })
}

check "session_manager_s3_logging_no_bucket" {
  assert {
    condition     = !var.enable_session_manager_s3_logging || var.session_manager_s3_bucket_name != ""
    error_message = "enable_session_manager_s3_logging is true but session_manager_s3_bucket_name is empty. S3 logging will not function without a bucket name."
  }
}

# The SSM Document API accepts any string as a logging target, so a log group
# or bucket that nothing creates applies cleanly and fails only when an
# operator opens a session ("Failed to upload session logs", or sessions
# refused outright when logging is enforced). The two checks below look the
# named targets up at plan time and WARN when they do not exist. Listing data
# sources are used deliberately: a missing target is an EMPTY result, so the
# assert fires with this curated message instead of a raw provider error. A
# failing lookup (e.g. the plan role lacks logs:DescribeLogGroups or
# s3:ListAllMyBuckets) is masked to a warning by the check block itself —
# "If a nested data source's provider raises errors, they are masked as
# warnings and do not prevent the Terraform operation from continuing"
# (Terraform check block reference; verified against Terraform v1.16.1) — so
# neither shape can break a plan in an account where the target legitimately
# does not exist yet. The sentinel names keep the disabled-path lookups cheap
# and matching nothing.

check "session_manager_cloudwatch_log_group_exists" {
  data "aws_cloudwatch_log_groups" "session_manager" {
    log_group_name_prefix = (
      var.enable_session_manager_logging && var.session_manager_cloudwatch_log_group != ""
      ? var.session_manager_cloudwatch_log_group
      : "/tlz/session-manager-check-disabled"
    )
  }

  assert {
    condition = (
      !var.enable_session_manager_logging ||
      var.session_manager_cloudwatch_log_group == "" ||
      contains(data.aws_cloudwatch_log_groups.session_manager.log_group_names, var.session_manager_cloudwatch_log_group)
    )
    error_message = "session_manager_cloudwatch_log_group names '${var.session_manager_cloudwatch_log_group}', but no such log group exists in this account/region. The SSM document accepts the name and the apply stays green — sessions fail at runtime ('Failed to upload session logs', or refused when logging is enforced). Create the log group or fix the name."
  }
}

check "session_manager_s3_bucket_exists" {
  data "aws_s3_buckets" "session_manager" {
    prefix = (
      var.enable_session_manager_logging && var.enable_session_manager_s3_logging && var.session_manager_s3_bucket_name != ""
      ? var.session_manager_s3_bucket_name
      : "tlz-session-manager-check-disabled-no-such-bucket"
    )
  }

  assert {
    condition = (
      !var.enable_session_manager_logging ||
      !var.enable_session_manager_s3_logging ||
      var.session_manager_s3_bucket_name == "" ||
      contains([for b in data.aws_s3_buckets.session_manager.buckets : b.name], var.session_manager_s3_bucket_name)
    )
    error_message = "session_manager_s3_bucket_name names '${var.session_manager_s3_bucket_name}', but no such bucket is visible to this account. The SSM document accepts the name and the apply stays green — sessions fail at runtime when logs cannot be uploaded. Create the bucket, fix the name, or check cross-account visibility (a bucket owned by another account does not appear in ListBuckets and will keep this warning firing even when the name is correct)."
  }
}

# The module configures exactly one account — which accounts receive this stack
# is decided in the deployment layer. The exclusion list documents that
# decision next to the configuration it excludes from, and the check warns when
# a plan runs against an account the list names. Unlike the two account
# exclusion checks of this module that guard unconditional resources, this one
# is bound to enable_session_manager_logging: without the session document
# there is nothing the account could be excluded from.
check "session_manager_excluded_account_check" {
  assert {
    condition     = !var.enable_session_manager_logging || !contains(var.session_manager_excluded_accounts, local.account_id)
    error_message = "The current account '${local.account_id}' is in session_manager_excluded_accounts. The Session Manager configuration is still created but this account should be excluded."
  }
}

# =============================================================================
# Session Manager Log Lifecycle
# =============================================================================
# The session logs go to var.session_manager_s3_bucket_name under
# var.session_manager_s3_key_prefix. That bucket is not the central log bucket,
# so its lifecycle is a resource of its own rather than a further rule set in
# guardduty.tf.
#
# Without session_manager_lifecycle_rules nothing is created — the module has
# never written a lifecycle for these logs, and the default keeps it that way.
# The bucket belongs to whoever passes its name in. S3 keeps one lifecycle
# configuration per bucket, so this resource is the WHOLE lifecycle of that
# bucket: setting session_manager_lifecycle_rules replaces every rule the
# bucket already has, including rules outside the log prefix, and a destroy
# deletes them all. Setting the input is the operator's explicit opt-in to
# that; the variable description says so. Scope each rule to the log prefix,
# and carry over any other rule the bucket needs into the same rule set.

resource "aws_s3_bucket_lifecycle_configuration" "session_manager_logs" {
  count = (
    var.enable_session_manager_s3_logging &&
    var.session_manager_s3_bucket_name != "" &&
    length(local.session_manager_lifecycle_rules) > 0
  ) ? 1 : 0

  bucket = var.session_manager_s3_bucket_name

  dynamic "rule" {
    for_each = local.session_manager_lifecycle_rules
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
}
