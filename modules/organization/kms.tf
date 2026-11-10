# =============================================================================
# CloudWatch Logs KMS Key — this module's Lambda execution log groups
# =============================================================================
# The three automation Lambdas of this module (quarantine auto-detach, SCP
# auto-revert, account move) each own their execution log group. A
# customer-managed key is a per-key monthly charge; this key encrypts those
# groups without imposing that charge on a default deployment — the count gate means the key exists only when at least one of
# the three functions is actually deployed, so a landing zone that enables
# none of them still pays nothing and creates no key.
#
# The key is deliberately shared by the three groups rather than one key per
# group: they are the same trust domain (this account's own Lambda execution
# output, one service principal) and three keys would triple the standing
# charge for no separation anyone reads.

locals {
  # Any of the three execution log groups this module can create. Each term is
  # the same condition its own log group resource counts on, so the key comes
  # into existence exactly when the first group does.
  enable_cloudwatch_logs_kms = (
    local.enable_quarantine_auto_detach ||
    local.enable_scp_auto_revert ||
    var.enable_account_move_automation
  )
}

resource "aws_kms_key" "cloudwatch_logs" {
  count = local.enable_cloudwatch_logs_kms ? 1 : 0

  description             = "KMS key for the organization module's Lambda execution log groups"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/cloudwatch-logs-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    region     = local.region
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "cloudwatch_logs" {
  count = local.enable_cloudwatch_logs_kms ? 1 : 0

  name          = "alias/tlz/organization/lambda-logs/kms"
  target_key_id = aws_kms_key.cloudwatch_logs[0].key_id
}

# =============================================================================
# SNS KMS Key — this module's EventBridge-fed notification topics
# =============================================================================
# The SCP-change topic and the quarantine-detach topic receive their messages
# from EventBridge. EventBridge cannot publish to a topic encrypted with the
# AWS managed key alias/aws/sns: that key's policy cannot be changed to grant
# events.<dns_suffix>, so every event would be dropped. This customer-managed
# key grants EventBridge exactly GenerateDataKey* and Decrypt. AWS does not
# support aws:SourceAccount / aws:SourceArn in the key policy for
# EventBridge-to-encrypted-topic delivery (SNS developer guide, "Enable
# compatibility between event sources from AWS services and encrypted
# topics"); the topic policies keep the publish grant itself. Count-gated like
# the logs key above: no key exists while neither topic does.

locals {
  enable_sns_topics_kms = var.enable_scp_revert_detection || local.enable_quarantine_auto_detach
}

resource "aws_kms_key" "sns_topics" {
  count = local.enable_sns_topics_kms ? 1 : 0

  description             = "KMS key for the organization module's EventBridge-fed SNS topics"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/sns-eventbridge-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}
