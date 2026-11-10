# --- Quarantine SCP ---
# Denies all actions for new accounts except those performed via the
# provisioning roles (AWSControlTowerExecution, tlz-*).
# Mirrors the AttachQuarantineScp behavior for newly-enrolled accounts.
# The fallback reads the same document the loader injects
# (tlz-quarantine-guardrails.json) so both paths carry one policy source.

resource "aws_organizations_policy" "quarantine" {
  count = var.enable_quarantine_scp ? 1 : 0

  name        = "TLZQuarantinePolicy"
  description = "Quarantine SCP for new accounts"
  type        = "SERVICE_CONTROL_POLICY"
  content     = var.quarantine_scp_content != "" ? var.quarantine_scp_content : jsonencode(jsondecode(file("${path.module}/../../configurations/policies/organization/tlz-quarantine-guardrails.json")))

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "quarantine" {
  for_each = var.enable_quarantine_scp ? toset(var.quarantine_scp_targets) : toset([])

  policy_id = aws_organizations_policy.quarantine[0].id
  target_id = lookup(local.target_name_to_id, each.value, each.value)

  lifecycle {
    # Hard quota: at most 5 SCPs directly attached per target (scp-quota.tf).
    # The quarantine SCP counts toward the quota of each of its targets.
    precondition {
      condition     = local.scp_attachment_count_by_target[each.value] <= local.scp_attachments_per_target_quota
      error_message = local.scp_quota_error
    }
  }
}

# =============================================================================
# Quarantine SCP Auto-Detach Notification
# =============================================================================
# When both enable_quarantine_scp and enable_quarantine_auto_detach are true,
# creates an EventBridge rule that detects CodePipeline SUCCEEDED events of
# the pipelines in var.quarantine_detach_pipeline_names and sends an SNS
# notification. When the auto-detach Lambda is deployed, it
# automatically detaches the quarantine SCP from all targets on pipeline
# completion. The SNS notification path remains active regardless.

locals {
  enable_quarantine_auto_detach = var.enable_quarantine_scp && var.enable_quarantine_auto_detach
}

resource "aws_sns_topic" "quarantine_detach" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  # SNS CreateTopic is an upsert (adopts an existing topic of this name) — see
  # var.quarantine_detach_topic_name for why an apply-test must scope this.
  name = var.quarantine_detach_topic_name
  # EventBridge cannot publish to a topic under the AWS managed key
  # alias/aws/sns; this module's SNS key grants it (kms.tf).
  kms_master_key_id = aws_kms_key.sns_topics[0].arn
}

resource "aws_sns_topic_policy" "quarantine_detach" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  arn = aws_sns_topic.quarantine_detach[0].arn
  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/sns-eventbridge-policy.json", {
    dns_suffix = local.dns_suffix
    topic_arn  = aws_sns_topic.quarantine_detach[0].arn
  })))
}

resource "aws_sns_topic_subscription" "quarantine_detach" {
  for_each = local.enable_quarantine_auto_detach ? toset(var.scp_revert_notification_emails) : toset([])

  topic_arn = aws_sns_topic.quarantine_detach[0].arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_event_rule" "quarantine_detach" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  # EventBridge PutRule is an upsert — see var.quarantine_detach_rule_name.
  name        = var.quarantine_detach_rule_name
  description = "Detects CodePipeline SUCCEEDED events to notify for quarantine SCP detachment"

  # Scoped to the named pipelines: the Lambda target detaches the quarantine
  # SCP from every target, so a SUCCEEDED of any other pipeline in this
  # account and region must not reach it.
  event_pattern = jsonencode({
    source      = ["aws.codepipeline"]
    detail-type = ["CodePipeline Pipeline Execution State Change"]
    detail = {
      pipeline = var.quarantine_detach_pipeline_names
      state    = ["SUCCEEDED"]
    }
  })
}

resource "aws_cloudwatch_event_target" "quarantine_detach" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  rule      = aws_cloudwatch_event_rule.quarantine_detach[0].name
  target_id = "quarantine-detach-sns"
  arn       = aws_sns_topic.quarantine_detach[0].arn

  input_transformer {
    input_paths = {
      pipeline = "$.detail.pipeline"
      state    = "$.detail.state"
    }
    input_template = "\"TLZ Pipeline <pipeline> completed with state <state>. Please manually detach the Quarantine SCP from new accounts. Quarantine SCP ID: ${var.enable_quarantine_scp ? aws_organizations_policy.quarantine[0].id : "N/A"}\""
  }
}

# =============================================================================
# Quarantine Auto-Detach Lambda
# =============================================================================
# When both enable_quarantine_scp and enable_quarantine_auto_detach are true,
# deploys a Lambda function that automatically detaches the quarantine SCP
# from all targets after the deployment pipeline completes. The existing
# EventBridge → SNS notification path remains active regardless.

locals {
  quarantine_auto_detach_lambda_code = <<-PYTHON
import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

organizations = boto3.client("organizations")


def lambda_handler(event, context):
    """Handle CodePipeline SUCCEEDED events via EventBridge.

    Reads the quarantine SCP policy ID from the QUARANTINE_SCP_POLICY_ID
    environment variable, lists all targets the policy is attached to,
    and detaches it from each one.
    """
    logger.info("Received event: %s", json.dumps(event))

    policy_id = os.environ.get("QUARANTINE_SCP_POLICY_ID", "")
    if not policy_id:
        logger.error("QUARANTINE_SCP_POLICY_ID environment variable is not set.")
        return {"statusCode": 400, "body": "Missing QUARANTINE_SCP_POLICY_ID"}

    try:
        # List all targets the quarantine SCP is attached to
        targets = []
        paginator = organizations.get_paginator("list_targets_for_policy")
        for page in paginator.paginate(PolicyId=policy_id):
            targets.extend(page.get("Targets", []))

        logger.info(
            "Found %d targets for quarantine SCP %s", len(targets), policy_id
        )

        # Detach the quarantine SCP from each target
        for target in targets:
            target_id = target["TargetId"]
            target_name = target.get("Name", target_id)
            try:
                organizations.detach_policy(
                    PolicyId=policy_id, TargetId=target_id
                )
                logger.info(
                    "Successfully detached quarantine SCP %s from %s (%s)",
                    policy_id,
                    target_name,
                    target_id,
                )
            except organizations.exceptions.PolicyNotAttachedException:
                logger.info(
                    "Quarantine SCP %s already detached from %s (%s) — skipping.",
                    policy_id,
                    target_name,
                    target_id,
                )
            except Exception:
                logger.exception(
                    "Error detaching quarantine SCP %s from %s (%s)",
                    policy_id,
                    target_name,
                    target_id,
                )

    except Exception:
        logger.exception(
            "Error listing targets for quarantine SCP %s", policy_id
        )
        return {"statusCode": 500, "body": "Detach failed"}

    return {"statusCode": 200, "body": "Detach completed"}
PYTHON
}

data "archive_file" "quarantine_auto_detach" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/.archive/quarantine_auto_detach.zip"

  source {
    content  = local.quarantine_auto_detach_lambda_code
    filename = "index.py"
  }
}

resource "aws_iam_role" "quarantine_auto_detach_lambda" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  name = "tlz-quarantine-auto-detach-lambda"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "quarantine_auto_detach_lambda" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  name = "quarantine-auto-detach-permissions"
  role = aws_iam_role.quarantine_auto_detach_lambda[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/quarantine-auto-detach-policy.json", {
    arn_prefix = local.arn_prefix
    # The sqs:SendMessage grant must name the queue the Lambda's
    # dead_letter_config points at — Lambda validates that at create.
    dlq_name = var.quarantine_auto_detach_dlq_name
  })))
}

# Dead-letter queue for the auto-detach Lambda. EventBridge invokes the
# function asynchronously; without a DLQ an event that still fails after the
# two automatic retries is dropped without a trace. SQS-managed encryption
# (SSE-SQS) and 14 days retention — the queue is idle unless invocations fail.
# SQS CreateQueue is idempotent for an existing queue with identical
# attributes — see var.quarantine_auto_detach_dlq_name for why an apply-test
# must scope this.
resource "aws_sqs_queue" "quarantine_auto_detach_dlq" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  name                      = var.quarantine_auto_detach_dlq_name
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_lambda_function" "quarantine_auto_detach" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  function_name = "tlz-quarantine-auto-detach"
  description   = "Automatically detaches quarantine SCP from accounts after pipeline completion"
  role          = aws_iam_role.quarantine_auto_detach_lambda[0].arn
  handler       = "index.lambda_handler"
  runtime       = "python3.12"
  timeout       = 60

  # Cap on parallel executions: the function reacts to rare control-plane
  # events, so a small reserved pool is ample and bounds a runaway invocation
  # storm instead of letting it drain the account's concurrency pool.
  reserved_concurrent_executions = 10

  filename         = data.archive_file.quarantine_auto_detach[0].output_path
  source_code_hash = data.archive_file.quarantine_auto_detach[0].output_base64sha256

  dead_letter_config {
    target_arn = aws_sqs_queue.quarantine_auto_detach_dlq[0].arn
  }

  environment {
    variables = {
      QUARANTINE_SCP_POLICY_ID = aws_organizations_policy.quarantine[0].id
    }
  }

  lifecycle {
    precondition {
      condition     = var.enable_quarantine_scp
      error_message = "enable_quarantine_auto_detach requires enable_quarantine_scp to be true."
    }
  }
}

# EventBridge target: route pipeline completion events to the auto-detach Lambda
# (second target on the existing quarantine_detach rule — SNS target remains active)
resource "aws_cloudwatch_event_target" "quarantine_auto_detach_lambda" {
  count     = local.enable_quarantine_auto_detach ? 1 : 0
  rule      = aws_cloudwatch_event_rule.quarantine_detach[0].name
  target_id = "quarantine-auto-detach-lambda"
  arn       = aws_lambda_function.quarantine_auto_detach[0].arn

  # The target is what lets EventBridge invoke the function; the function's
  # log group must exist before the first invocation can create it implicitly.
  depends_on = [aws_cloudwatch_log_group.quarantine_auto_detach]
}

# The function's own execution log group — the same gap the monitoring module's
# functions carried (modules/monitoring/README.md, "Lambda execution log
# groups"): implicitly created by Lambda on the first invocation, outside the
# state, without retention and never destroyed. The name derives from the
# function so the two cannot drift apart. CreateLogGroup is create-only: an
# account where the function has already run must import the group (README,
# "Lambda execution log groups").
resource "aws_cloudwatch_log_group" "quarantine_auto_detach" {
  count = local.enable_quarantine_auto_detach ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.quarantine_auto_detach[0].function_name}"
  retention_in_days = var.quarantine_auto_detach_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs[0].arn
}

resource "aws_lambda_permission" "quarantine_auto_detach" {
  count         = local.enable_quarantine_auto_detach ? 1 : 0
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.quarantine_auto_detach[0].function_name
  principal     = "events.${local.dns_suffix}"
  source_arn    = aws_cloudwatch_event_rule.quarantine_detach[0].arn
}
