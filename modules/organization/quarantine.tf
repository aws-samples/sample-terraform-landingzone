# --- Quarantine SCP ---
# Denies all actions for new accounts except those performed via the
# provisioning roles (AWSControlTowerExecution, tlz-*).
# Mirrors the AttachQuarantineScp behavior for newly-enrolled accounts.
# The fallback reads the same document the loader injects
# (tlz-quarantine-guardrails.json) so both paths carry one policy source.

locals {
  # Targets of the quarantine SCP: the listed OUs and accounts plus the
  # quarantine OU, whose attachment exists before any account is created
  # inside it. One list feeds the attachment, the SCP quota count
  # (scp-quota.tf) and the target-resolution check (main.tf).
  quarantine_scp_attachment_targets = distinct(concat(
    var.quarantine_scp_targets,
    var.quarantine_ou_name != "" ? [var.quarantine_ou_name] : [],
  ))
}

resource "aws_organizations_policy" "quarantine" {
  count = var.enable_quarantine_scp ? 1 : 0

  name        = "TLZQuarantinePolicy"
  description = "Quarantine SCP for new accounts"
  type        = "SERVICE_CONTROL_POLICY"
  content     = var.quarantine_scp_content != "" ? var.quarantine_scp_content : jsonencode(jsondecode(file("${path.module}/../../configurations/policies/organization/tlz-quarantine-guardrails.json")))

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "quarantine" {
  for_each = var.enable_quarantine_scp ? toset(local.quarantine_scp_attachment_targets) : toset([])

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
# Quarantine SCP Release Notification
# =============================================================================
# When both enable_quarantine_scp and enable_quarantine_auto_detach are true,
# an EventBridge rule detects CodePipeline SUCCEEDED events of the pipelines
# in var.quarantine_detach_pipeline_names and sends an SNS notification. The
# release itself is manual: an operator moves the accounts that run configured
# out of the quarantine OU by setting quarantined = false on their entries and
# applying the accounts unit. No function releases them, because a pipeline
# event does not name the accounts a run configured, and releasing every
# target would free accounts that run never touched.

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
  kms_master_key_id = aws_kms_key.sns_topics["stack"].arn
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

  # Scoped to the named pipelines: a SUCCEEDED of any other pipeline in this
  # account and region must not ask for a release.
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
    input_template = "\"TLZ Pipeline <pipeline> completed with state <state>. Move the configured accounts out of the quarantine OU: set quarantined = false on their entries in env/common.hcl and apply stacks/management/accounts. Quarantine SCP ID: ${var.enable_quarantine_scp ? aws_organizations_policy.quarantine[0].id : "N/A"}\""
  }
}
