# =============================================================================
# EBS Default Encryption
# =============================================================================

resource "aws_ebs_encryption_by_default" "this" {
  count   = var.enable_ebs_default_encryption ? 1 : 0
  enabled = true
}

# Registers the account-wide EBS default encryption key. It has to run in both
# cases: with an externally supplied ARN and with the module-managed key below —
# otherwise the module-managed key is created but never used and EBS keeps
# encrypting against the AWS-managed aws/ebs key.
resource "aws_ebs_default_kms_key" "this" {
  count   = var.enable_ebs_default_encryption ? 1 : 0
  key_arn = var.ebs_default_kms_key_arn != "" ? var.ebs_default_kms_key_arn : aws_kms_key.ebs_default[0].arn
}

# --- Module-Managed EBS KMS Key (when no external key ARN is provided) ---

resource "aws_kms_key" "ebs_default" {
  count = var.enable_ebs_default_encryption && var.ebs_default_kms_key_arn == "" ? 1 : 0

  description             = "Module-managed KMS key for EBS default encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = data.aws_iam_policy_document.ebs_default_key_policy[0].json
}

resource "aws_kms_alias" "ebs_default" {
  count = var.enable_ebs_default_encryption && var.ebs_default_kms_key_arn == "" ? 1 : 0

  name          = "alias/tlz/ebs/kms"
  target_key_id = aws_kms_key.ebs_default[0].key_id
}

# EC2 Auto Scaling launches encrypted volumes through its service-linked role,
# which needs the key policy of a customer managed default key to name it
# (EC2 Auto Scaling user guide, "Required AWS KMS key policy for use with
# encrypted volumes"). KMS refuses a key policy that names a role that does not
# exist, and the role appears only with the account's first Auto Scaling
# group, so the grant is added only when the lookup finds the role.
# shortcut: a role created after this apply gets its grant at the next apply
# of this stack; declare aws_iam_service_linked_role here once every account
# that runs this module is known to have or want the role.
data "aws_iam_roles" "autoscaling_service_linked" {
  count = var.enable_ebs_default_encryption && var.ebs_default_kms_key_arn == "" ? 1 : 0

  # Role names are unique in an account; the name alone selects the role in
  # every partition.
  name_regex = "^AWSServiceRoleForAutoScaling$"
}

data "aws_iam_policy_document" "ebs_default_key_policy" {
  count = var.enable_ebs_default_encryption && var.ebs_default_kms_key_arn == "" ? 1 : 0

  # Root account full access
  statement {
    sid    = "EnableRootAccountAccess"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(data.aws_iam_roles.autoscaling_service_linked[0].arns) > 0 ? [sort(tolist(data.aws_iam_roles.autoscaling_service_linked[0].arns))] : []
    content {
      sid    = "AllowAutoScalingServiceLinkedRoleUse"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = statement.value
      }
      actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = length(data.aws_iam_roles.autoscaling_service_linked[0].arns) > 0 ? [sort(tolist(data.aws_iam_roles.autoscaling_service_linked[0].arns))] : []
    content {
      sid    = "AllowAutoScalingServiceLinkedRoleGrants"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = statement.value
      }
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }
}

check "ebs_encryption_excluded_region_check" {
  assert {
    condition     = !contains(var.ebs_encryption_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in ebs_encryption_excluded_regions. EBS encryption resources are still created in this deployment but the region should be excluded from multi-region configuration."
  }
}

# =============================================================================
# S3 Account Public Access Block
# =============================================================================

resource "aws_s3_account_public_access_block" "this" {
  count                   = var.enable_s3_public_access_block ? 1 : 0
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

check "s3_pab_excluded_account_check" {
  assert {
    condition     = !contains(var.s3_public_access_block_excluded_accounts, local.account_id)
    error_message = "The current account '${local.account_id}' is in s3_public_access_block_excluded_accounts. S3 public access block is still created but this account should be excluded from enforcement."
  }
}
