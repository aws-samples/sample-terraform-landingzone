# =============================================================================
# CloudWatch Logs KMS Key — this module's Lambda execution log groups
# =============================================================================
# The two automation Lambdas of this module that own a log group here (SCP
# auto-revert, account move) encrypt it with a customer-managed key. A
# customer-managed key is a per-key monthly charge; the key exists only in a
# region where at least one of those functions is deployed, so a landing zone
# that enables neither pays nothing and creates no key.
#
# A log group's key must be in the log group's region. Both functions run in
# the region Organizations delivers its events to (local.scp_revert_region,
# scp-revert.tf; us-east-1 in the aws partition), so one key serves both
# groups, keyed "stack" only when that region is the stack's own.
#
# Instance keys: "stack" is the key in the stack's own region, the address an
# earlier single-key release used as [0] (see the moved blocks below), so a
# deployed key keeps its identity. A key in another region is keyed by that
# region's name.

locals {
  # Instance key of the keys in the region of the Organizations events.
  scp_revert_kms_key = local.scp_revert_region == local.region ? "stack" : local.scp_revert_region

  cloudwatch_logs_kms_regions = merge(
    var.enable_account_move_automation ? { (local.scp_revert_kms_key) = local.scp_revert_region } : {},
    local.enable_scp_auto_revert ? { (local.scp_revert_kms_key) = local.scp_revert_region } : {},
  )
}

resource "aws_kms_key" "cloudwatch_logs" {
  for_each = local.cloudwatch_logs_kms_regions

  region                  = each.value
  description             = "KMS key for the organization module's Lambda execution log groups"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/cloudwatch-logs-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    region     = each.value
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "cloudwatch_logs" {
  for_each = local.cloudwatch_logs_kms_regions

  region        = each.value
  name          = "alias/tlz/organization/lambda-logs/kms"
  target_key_id = aws_kms_key.cloudwatch_logs[each.key].key_id
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
# topics"); the topic policies keep the publish grant itself. One key per
# region a topic lives in: the SCP-change topic in local.scp_revert_region,
# the quarantine-detach topic in the stack's region.

locals {
  sns_topics_kms_regions = merge(
    local.enable_quarantine_auto_detach ? { stack = local.region } : {},
    var.enable_scp_revert_detection ? { (local.scp_revert_kms_key) = local.scp_revert_region } : {},
  )
}

resource "aws_kms_key" "sns_topics" {
  for_each = local.sns_topics_kms_regions

  region                  = each.value
  description             = "KMS key for the organization module's EventBridge-fed SNS topics"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/sns-eventbridge-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}

# Upgrade path: a release with one key per resource addressed it as [0], in
# the stack's region. The key in the stack's region keeps that key; a key
# that is no longer needed in the stack's region (the SCP change and account
# move resources now in us-east-1, nothing else there) is scheduled for
# deletion.
moved {
  from = aws_kms_key.cloudwatch_logs[0]
  to   = aws_kms_key.cloudwatch_logs["stack"]
}

moved {
  from = aws_kms_alias.cloudwatch_logs[0]
  to   = aws_kms_alias.cloudwatch_logs["stack"]
}

moved {
  from = aws_kms_key.sns_topics[0]
  to   = aws_kms_key.sns_topics["stack"]
}
