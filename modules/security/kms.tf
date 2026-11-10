# =============================================================================
# KMS Customer-Managed Keys
# =============================================================================

locals {
  kms_keys_with_targets = [
    for k in var.kms_keys : k.alias
    if length(k.deployment_targets) > 0
  ]

  # removal_policy = "retain" protects the key at the API instead of at the
  # plan: the statement below denies kms:ScheduleKeyDeletion for every
  # principal, so a destroy (or a removal from the configuration) fails with
  # AccessDenied until a prior apply sets the policy back to destroy. This
  # covers console and CLI deletion attempts as well, not only Terraform runs.
  # PutKeyPolicy stays allowed on purpose — flipping removal_policy back to
  # destroy must remain possible without state surgery.
  kms_retain_deny_statement = {
    Sid       = "DenyScheduleKeyDeletion"
    Effect    = "Deny"
    Principal = "*"
    Action    = "kms:ScheduleKeyDeletion"
    Resource  = "*"
  }

  # Base document the deny statement is composed into: the user-supplied
  # policy when given, otherwise the rendered equivalent of the AWS default
  # key policy (root account access) — appending to the implicit default is
  # not possible, so the default becomes explicit for retained keys.
  kms_key_base_policy = {
    for k in var.kms_keys : k.alias => jsondecode(
      # The condition selects between two strings and the result is decoded
      # once — a conditional over the decoded documents would demand that the
      # user document and the template unify their object types.
      k.policy != null ? k.policy : templatefile("${path.module}/../../configurations/policies/security/kms-default-key-policy.json", {
        arn_prefix = local.arn_prefix
        account_id = local.account_id
      })
    ) if k.removal_policy == "retain"
  }

  # Composed policy per key: destroy passes the user policy through unchanged
  # (null keeps the AWS default), retain appends the deny statement. flatten
  # normalises a Statement that is a single object instead of an array — a
  # conditional would demand that both branches unify their types.
  kms_key_policy = {
    for k in var.kms_keys : k.alias => (
      k.removal_policy == "retain" ? jsonencode(merge(
        local.kms_key_base_policy[k.alias],
        {
          Statement = concat(
            flatten([local.kms_key_base_policy[k.alias].Statement]),
            [local.kms_retain_deny_statement],
          )
        }
      )) : k.policy
    )
  }
}

check "kms_keys_deployment_targets_warning" {
  assert {
    condition     = length(local.kms_keys_with_targets) == 0
    error_message = "kms_keys with deployment_targets detected [${join(", ", local.kms_keys_with_targets)}]. Terraform cannot dynamically create providers for cross-account KMS key deployment. Keys will only be created in the Management Account."
  }
}

resource "aws_kms_key" "custom" {
  for_each = { for k in var.kms_keys : k.alias => k }

  description             = each.value.description
  policy                  = local.kms_key_policy[each.key]
  enable_key_rotation     = each.value.enable_key_rotation
  deletion_window_in_days = each.value.deletion_window_in_days
  is_enabled              = each.value.is_enabled
}

resource "aws_kms_alias" "custom" {
  for_each = { for k in var.kms_keys : k.alias => k }

  name          = "alias/${each.value.alias}"
  target_key_id = aws_kms_key.custom[each.key].key_id
}

# =============================================================================
# Lambda Encryption KMS Key
# =============================================================================

resource "aws_kms_key" "lambda_encryption" {
  count = var.enable_lambda_encryption && var.lambda_encryption_kms_key_arn == "" ? 1 : 0

  description             = "KMS key for Lambda function encryption at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/lambda-encryption-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "lambda_encryption" {
  count = var.enable_lambda_encryption && var.lambda_encryption_kms_key_arn == "" ? 1 : 0

  name          = "alias/tlz-lambda-encryption"
  target_key_id = aws_kms_key.lambda_encryption[0].key_id
}

# =============================================================================
# Per-Account CloudWatch KMS Key
# =============================================================================

resource "aws_kms_key" "per_account_cloudwatch" {
  count = var.enable_per_account_kms_keys ? 1 : 0

  description             = "Per-account KMS key for CloudWatch Logs encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/per-account-cloudwatch-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    region     = local.region
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "per_account_cloudwatch" {
  count = var.enable_per_account_kms_keys ? 1 : 0

  name          = "alias/tlz/cloudwatch/kms"
  target_key_id = aws_kms_key.per_account_cloudwatch[0].key_id
}

# =============================================================================
# Per-Account Lambda KMS Key
# =============================================================================

resource "aws_kms_key" "per_account_lambda" {
  count = var.enable_per_account_kms_keys ? 1 : 0

  description             = "Per-account KMS key for Lambda function encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/per-account-lambda-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "per_account_lambda" {
  count = var.enable_per_account_kms_keys ? 1 : 0

  name          = "alias/tlz/lambda/kms"
  target_key_id = aws_kms_key.per_account_lambda[0].key_id
}

# =============================================================================
# Security Module Lambda Execution Log Group KMS Key
# =============================================================================

resource "aws_kms_key" "security_lambda_logs" {
  count = local.macie_settings_managed || (var.enable_guardduty && var.guardduty_keep_malware_snapshots) ? 1 : 0

  description             = "KMS key for this module's own Lambda execution log groups"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/per-account-cloudwatch-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    region     = local.region
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "security_lambda_logs" {
  count = local.macie_settings_managed || (var.enable_guardduty && var.guardduty_keep_malware_snapshots) ? 1 : 0

  name          = "alias/tlz/security/lambda-logs/kms"
  target_key_id = aws_kms_key.security_lambda_logs[0].key_id
}

# =============================================================================
# SQS KMS Key
# =============================================================================

resource "aws_kms_key" "sqs" {
  count = var.enable_sqs_kms_key ? 1 : 0

  description             = "Per-account KMS key for SQS queue encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/sqs-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "sqs" {
  count = var.enable_sqs_kms_key ? 1 : 0

  name          = "alias/tlz/sqs/kms"
  target_key_id = aws_kms_key.sqs[0].key_id
}
