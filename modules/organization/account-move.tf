# =============================================================================
# Account Move Automation (EventBridge + Lambda)
# Logs the CreateAccount and MoveAccount events of Organizations; the function
# moves no account.
# =============================================================================

# Organizations delivers CreateAccount and MoveAccount to EventBridge in the
# same single region as the SCP change events, so every regional resource of
# this function (rule, target, permission, function, log group and its key)
# names local.scp_revert_region (scp-revert.tf): us-east-1 in the aws
# partition, the stack's region in the others.

data "archive_file" "account_move" {
  count       = var.enable_account_move_automation ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/lambda/account_move.zip"

  source {
    content  = file("${path.module}/lambda/account_move.py")
    filename = "index.py"
  }
}

resource "aws_cloudwatch_log_group" "account_move" {
  count             = var.enable_account_move_automation ? 1 : 0
  region            = local.scp_revert_region
  name              = "/aws/lambda/tlz-account-move"
  retention_in_days = var.account_move_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs[local.scp_revert_kms_key].arn
}

resource "aws_iam_role" "account_move_lambda" {
  count = var.enable_account_move_automation ? 1 : 0
  name  = "tlz-account-move-lambda"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "account_move_orgs" {
  count = var.enable_account_move_automation ? 1 : 0
  name  = "account-move-organizations"
  role  = aws_iam_role.account_move_lambda[0].id

  policy = jsonencode(jsondecode(file("${path.module}/../../configurations/policies/organization/account-move-orgs-policy.json")))
}

resource "aws_iam_role_policy" "account_move_logs" {
  count = var.enable_account_move_automation ? 1 : 0
  name  = "account-move-cloudwatch-logs"
  role  = aws_iam_role.account_move_lambda[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/account-move-logs-policy.json", {
    arn_prefix        = local.arn_prefix
    master_account_id = local.master_account_id
  })))
}

resource "aws_lambda_function" "account_move" {
  count         = var.enable_account_move_automation ? 1 : 0
  region        = local.scp_revert_region
  function_name = "tlz-account-move"
  role          = aws_iam_role.account_move_lambda[0].arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 60

  # Cap on parallel executions — same reasoning as on the auto-detach Lambda:
  # the function reacts to rare Organizations control-plane events
  # (CreateAccount, MoveAccount), so a small reserved pool is ample and bounds
  # a runaway invocation storm instead of letting it drain the account's
  # concurrency pool. Not 1 as on policy_strategy_detach: that function is
  # called synchronously by Terraform one call at a time, while this one is
  # invoked asynchronously by EventBridge and a burst of account moves can
  # legitimately overlap.
  reserved_concurrent_executions = 10

  filename         = data.archive_file.account_move[0].output_path
  source_code_hash = data.archive_file.account_move[0].output_base64sha256

  depends_on = [aws_cloudwatch_log_group.account_move]
}

resource "aws_cloudwatch_event_rule" "account_move" {
  count  = var.enable_account_move_automation ? 1 : 0
  region = local.scp_revert_region
  # EventBridge PutRule is an upsert — see var.account_move_rule_name for why
  # an apply-test must scope this.
  name        = var.account_move_rule_name
  description = "Triggers account move Lambda on Organizations CreateAccount and MoveAccount events"

  event_pattern = jsonencode({
    source      = ["aws.organizations"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["organizations.${local.dns_suffix}"]
      eventName   = ["CreateAccount", "MoveAccount"]
    }
  })
}

resource "aws_cloudwatch_event_target" "account_move" {
  count     = var.enable_account_move_automation ? 1 : 0
  region    = local.scp_revert_region
  rule      = aws_cloudwatch_event_rule.account_move[0].name
  target_id = "account-move-lambda"
  arn       = aws_lambda_function.account_move[0].arn
}

resource "aws_lambda_permission" "account_move_eventbridge" {
  count         = var.enable_account_move_automation ? 1 : 0
  region        = local.scp_revert_region
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.account_move[0].function_name
  principal     = "events.${local.dns_suffix}"
  source_arn    = aws_cloudwatch_event_rule.account_move[0].arn
}
