# =============================================================================
# SCP Revert Detection (G4)
# =============================================================================

# AWS Organizations is a global service: its CloudTrail events reach
# EventBridge in us-east-1 only (Organizations user guide, "Monitoring your
# organization with EventBridge"). A rule in another region is valid and
# silent, so every regional resource of the detection and of the auto-revert
# function (rule, targets, topic, its key, function, queue, log group and its
# key) names this region, whatever region the stack runs in.
# shortcut: only the aws partition is mapped; other partitions keep the
# stack's region. Add the home region of aws-us-gov / aws-cn / aws-eusc once
# one of them is deployed with detection.
locals {
  scp_revert_region = local.partition == "aws" ? "us-east-1" : local.region
}

resource "aws_sns_topic" "scp_revert" {
  count = var.enable_scp_revert_detection ? 1 : 0

  region = local.scp_revert_region
  # Overridable: SNS CreateTopic is an upsert on an existing name — see
  # var.scp_revert_topic_name for why an apply-test must scope this.
  name = var.scp_revert_topic_name
  # EventBridge cannot publish to a topic under the AWS managed key
  # alias/aws/sns; this module's SNS key grants it (kms.tf).
  kms_master_key_id = aws_kms_key.sns_topics[local.scp_revert_kms_key].arn
}

resource "aws_sns_topic_policy" "scp_revert" {
  count = var.enable_scp_revert_detection ? 1 : 0

  region = local.scp_revert_region
  arn    = aws_sns_topic.scp_revert[0].arn
  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/sns-eventbridge-policy.json", {
    dns_suffix = local.dns_suffix
    topic_arn  = aws_sns_topic.scp_revert[0].arn
  })))
}

resource "aws_sns_topic_subscription" "scp_revert" {
  for_each = var.enable_scp_revert_detection ? toset(var.scp_revert_notification_emails) : toset([])

  region    = local.scp_revert_region
  topic_arn = aws_sns_topic.scp_revert[0].arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_event_rule" "scp_revert" {
  count = var.enable_scp_revert_detection ? 1 : 0

  region = local.scp_revert_region
  # Overridable: EventBridge PutRule is an upsert on an existing name — see
  # var.scp_revert_rule_name for why an apply-test must scope this.
  name        = var.scp_revert_rule_name
  description = "Detects SCP modifications outside Terraform (UpdatePolicy, DeletePolicy, DetachPolicy)"

  event_pattern = jsonencode({
    source      = ["aws.organizations"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["organizations.${local.dns_suffix}"]
      eventName   = ["UpdatePolicy", "DeletePolicy", "DetachPolicy"]
    }
  })
}

resource "aws_cloudwatch_event_target" "scp_revert" {
  count = var.enable_scp_revert_detection ? 1 : 0

  region    = local.scp_revert_region
  rule      = aws_cloudwatch_event_rule.scp_revert[0].name
  target_id = "scp-revert-sns"
  arn       = aws_sns_topic.scp_revert[0].arn
}

# =============================================================================
# SCP Auto-Revert Lambda (G4)
# =============================================================================
# When both enable_scp_revert_detection and enable_scp_auto_revert are true,
# deploys a Lambda function that automatically reverts unauthorized SCP
# modifications. The existing EventBridge → SNS notification path remains
# active regardless of the auto-revert toggle.

locals {
  enable_scp_auto_revert = var.enable_scp_revert_detection && var.enable_scp_auto_revert

  # The content this module deployed, by policy ID: what an UpdatePolicy
  # revert restores. Packaged next to the code as known_good_policies.json,
  # so the function always carries the content of the last apply.
  scp_auto_revert_known_good = merge(
    { for p in aws_organizations_policy.scp : p.id => p.content },
    { for p in aws_organizations_policy.rcp : p.id => p.content },
    { for p in aws_organizations_policy.quarantine : p.id => p.content },
    { for p in aws_organizations_policy.pipeline_scp : p.id => p.content },
  )

  # tests/test_regression_org_lambda_handlers.py runs this code offline.
  scp_auto_revert_lambda_code = <<-PYTHON
import json
import logging
import os
import re

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Role name patterns for Terraform-managed / trusted automation roles.
# Changes made by these principals are intentional and should NOT be reverted.
EXCLUSION_PATTERNS = [
    r".*-Deployment.*",
    r".*OrganizationAccountAccessRole.*",
    r".*AWSControlTowerExecution.*",
    # The landing zone's Terraform role: no hyphen before "Deployment", so
    # the first pattern does not match it.
    r":role/(?:.*/)?TLZDeploymentRole$",
    # This function's own role: its UpdatePolicy and AttachPolicy calls are
    # CloudTrail events too and must not trigger it again.
    r":role/(?:.*/)?tlz-scp-auto-revert-lambda$",
    # The sibling function of this module that detaches policies on purpose
    # (policy-strategy.tf): re-attaching after it would give an allow-list
    # target FullAWSAccess back.
    r":role/(?:.*/)?tlz-policy-strategy-detach-lambda$",
]

KNOWN_GOOD_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "known_good_policies.json"
)

organizations = boto3.client("organizations")


def _known_good():
    with open(KNOWN_GOOD_FILE, encoding="utf-8") as handle:
        return json.load(handle)


def _not_reverted(reason):
    logger.error("NOT REVERTED: %s", reason)
    return {"statusCode": 409, "body": "Not reverted: " + reason}


def lambda_handler(event, context):
    """Handle CloudTrail events for SCP modifications via EventBridge.

    Inspects the caller principal and reverts the change if it was not
    made by a trusted automation role.
    """
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")
    user_identity = detail.get("userIdentity", {})

    # Extract the caller principal ARN (works for assumed-role and IAM user)
    principal_arn = user_identity.get("arn", "")
    session_issuer_arn = (
        user_identity.get("sessionContext", {})
        .get("sessionIssuer", {})
        .get("arn", "")
    )
    caller_arn = session_issuer_arn if session_issuer_arn else principal_arn

    logger.info("Event: %s, Caller ARN: %s", event_name, caller_arn)

    # Check if the caller matches any exclusion pattern
    for pattern in EXCLUSION_PATTERNS:
        if re.search(pattern, caller_arn):
            logger.info(
                "Caller %s matches exclusion pattern %s — skipping revert.",
                caller_arn,
                pattern,
            )
            return {"statusCode": 200, "body": "Skipped: trusted automation role"}

    # Unauthorized change detected — attempt revert
    request_params = detail.get("requestParameters", {})
    policy_id = request_params.get("policyId", "")

    if not policy_id:
        logger.warning("No policyId found in event — cannot revert.")
        return {"statusCode": 400, "body": "No policyId in event"}

    try:
        if event_name == "UpdatePolicy":
            # Restore the content this module deployed. The CURRENT content
            # is the tampered one; writing it back would restore nothing.
            known_good = _known_good().get(policy_id)
            if known_good is None:
                return _not_reverted(
                    "policy %s is not managed by this landing zone; "
                    "review the change by hand." % policy_id
                )
            current = organizations.describe_policy(PolicyId=policy_id)
            if json.loads(current["Policy"]["Content"]) == json.loads(known_good):
                logger.info("Policy %s already matches the deployed content.", policy_id)
                return {"statusCode": 200, "body": "Nothing to revert"}
            organizations.update_policy(PolicyId=policy_id, Content=known_good)
            logger.info("Restored the deployed content of policy %s", policy_id)
            return {"statusCode": 200, "body": "Revert completed: content restored"}

        if event_name == "DeletePolicy":
            return _not_reverted(
                "policy %s was deleted; a deleted policy cannot be restored "
                "automatically. Re-apply the organization stack." % policy_id
            )

        if event_name == "DetachPolicy":
            target_id = request_params.get("targetId", "")
            if not target_id:
                return _not_reverted(
                    "DetachPolicy for %s carries no targetId." % policy_id
                )
            logger.info(
                "Re-attaching policy %s to target %s", policy_id, target_id
            )
            organizations.attach_policy(PolicyId=policy_id, TargetId=target_id)
            logger.info("Re-attached policy %s to %s", policy_id, target_id)
            return {"statusCode": 200, "body": "Revert completed: policy re-attached"}

    except Exception:
        logger.exception("Error reverting SCP modification for %s", policy_id)
        return {"statusCode": 500, "body": "Revert failed"}

    return _not_reverted("event %s is not handled." % event_name)
PYTHON
}

data "archive_file" "scp_auto_revert" {
  count = local.enable_scp_auto_revert ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/.archive/scp_auto_revert.zip"

  source {
    content  = local.scp_auto_revert_lambda_code
    filename = "index.py"
  }

  source {
    content  = jsonencode(local.scp_auto_revert_known_good)
    filename = "known_good_policies.json"
  }
}

resource "aws_iam_role" "scp_auto_revert_lambda" {
  count = local.enable_scp_auto_revert ? 1 : 0

  name = "tlz-scp-auto-revert-lambda"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "scp_auto_revert_lambda" {
  count = local.enable_scp_auto_revert ? 1 : 0

  name = "scp-auto-revert-permissions"
  role = aws_iam_role.scp_auto_revert_lambda[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/scp-auto-revert-policy.json", {
    arn_prefix = local.arn_prefix
    # The sqs:SendMessage grant must name the queue the Lambda's
    # dead_letter_config points at — Lambda validates that at create.
    dlq_name = var.scp_auto_revert_dlq_name
  })))
}

# Dead-letter queue for the auto-revert Lambda. EventBridge invokes the
# function asynchronously; without a DLQ an unauthorized SCP change whose
# revert still fails after the two automatic retries would vanish silently —
# for a security guard function that loss must be observable and replayable.
# SQS CreateQueue is idempotent for an existing queue with identical
# attributes — see var.scp_auto_revert_dlq_name for why an apply-test must
# scope this.
resource "aws_sqs_queue" "scp_auto_revert_dlq" {
  count = local.enable_scp_auto_revert ? 1 : 0

  # Lambda requires its dead-letter queue in the function's region.
  region                    = local.scp_revert_region
  name                      = var.scp_auto_revert_dlq_name
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_lambda_function" "scp_auto_revert" {
  count = local.enable_scp_auto_revert ? 1 : 0

  region        = local.scp_revert_region
  function_name = "tlz-scp-auto-revert"
  description   = "Automatically reverts unauthorized SCP modifications detected via CloudTrail"
  role          = aws_iam_role.scp_auto_revert_lambda[0].arn
  handler       = "index.lambda_handler"
  runtime       = "python3.12"
  timeout       = 60

  # Cap on parallel executions — same reasoning as on the auto-detach Lambda.
  reserved_concurrent_executions = 10

  filename         = data.archive_file.scp_auto_revert[0].output_path
  source_code_hash = data.archive_file.scp_auto_revert[0].output_base64sha256

  dead_letter_config {
    target_arn = aws_sqs_queue.scp_auto_revert_dlq[0].arn
  }

  lifecycle {
    precondition {
      condition     = var.enable_scp_revert_detection
      error_message = "enable_scp_auto_revert requires enable_scp_revert_detection to be true."
    }
  }
}

# EventBridge target: route SCP modification events to the auto-revert Lambda
# (second target on the existing scp_revert rule — SNS target remains active)
resource "aws_cloudwatch_event_target" "scp_auto_revert_lambda" {
  count     = local.enable_scp_auto_revert ? 1 : 0
  region    = local.scp_revert_region
  rule      = aws_cloudwatch_event_rule.scp_revert[0].name
  target_id = "scp-auto-revert-lambda"
  arn       = aws_lambda_function.scp_auto_revert[0].arn

  # The target is what lets EventBridge invoke the function; the function's
  # log group must exist before the first invocation can create it implicitly.
  depends_on = [aws_cloudwatch_log_group.scp_auto_revert]
}

# The function's own execution log group. Without it Lambda creates
# /aws/lambda/<function name> implicitly on the first invocation, outside the
# state, without retention and never destroyed; the name derives from the
# function so the two cannot drift apart. CreateLogGroup is create-only: an
# account where the function has already run must import the group (README,
# "Lambda execution log groups").
resource "aws_cloudwatch_log_group" "scp_auto_revert" {
  count = local.enable_scp_auto_revert ? 1 : 0

  region            = local.scp_revert_region
  name              = "/aws/lambda/${aws_lambda_function.scp_auto_revert[0].function_name}"
  retention_in_days = var.scp_auto_revert_log_retention_days
  kms_key_id        = aws_kms_key.cloudwatch_logs[local.scp_revert_kms_key].arn
}

resource "aws_lambda_permission" "scp_auto_revert" {
  count         = local.enable_scp_auto_revert ? 1 : 0
  region        = local.scp_revert_region
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scp_auto_revert[0].function_name
  principal     = "events.${local.dns_suffix}"
  source_arn    = aws_cloudwatch_event_rule.scp_revert[0].arn
}
