# =============================================================================
# SNS Forwarder Lambda Execution Log Group KMS Key
# =============================================================================
# The forwarder's execution log group (aws_cloudwatch_log_group.sns_forwarder,
# see main.tf) carried an accepted #checkov:skip=CKV_AWS_158: a customer-
# managed key is a per-key monthly charge and the module declared none. This
# key removes that trade-off without imposing it on a default deployment —
# count is gated on the same toggle the log group's is, so a landing zone
# that leaves the forwarder disabled still pays nothing and creates no key.
#
# The policy document duplicates the security module's
# per-account-cloudwatch-kms-policy.json (same trust: logs.<region>.<dns_suffix>
# encrypting this account's own log data) rather than reaching across module
# boundaries for it — no module in this tree references another module's
# configurations/policies/ directory, and the organization module's own
# cloudwatch-logs-kms-policy.json is the same statement kept as its own copy.

resource "aws_kms_key" "sns_forwarder_logs" {
  count = var.enable_sns_forwarder ? 1 : 0

  description             = "KMS key for the SNS forwarder Lambda's execution log group"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/sns-forwarder-logs-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    region     = local.region
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "sns_forwarder_logs" {
  count = var.enable_sns_forwarder ? 1 : 0

  name          = "alias/tlz/monitoring/sns-forwarder-logs/kms"
  target_key_id = aws_kms_key.sns_forwarder_logs[0].key_id
}
