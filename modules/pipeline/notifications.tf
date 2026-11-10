# Pipeline Module — State-change notifications (CodePipeline variant)
#
# Behind enable_pipeline_notifications (default false), one EventBridge rule
# per selected execution state matches "CodePipeline Pipeline Execution State
# Change" events of THIS pipeline and publishes them to the existing approval
# topic (aws_sns_topic.approval, already carrying the e-mail subscription).
# The pipeline is addressed by its resource ARN, so the event pattern is
# partition-correct without constructing an ARN by hand.
#
# The rules exist only for the CodePipeline variant: the ECS and external
# variants have no aws_codepipeline resource whose states could be matched.

locals {
  pipeline_notifications_enabled = local.codepipeline_enabled && var.enable_pipeline_notifications

  pipeline_notification_states = local.pipeline_notifications_enabled ? toset(var.pipeline_notification_states) : toset([])
}

resource "aws_cloudwatch_event_rule" "pipeline_state" {
  for_each = local.pipeline_notification_states

  # EventBridge PutRule is an upsert — see var.pipeline_state_rule_name_prefix
  # for why an apply-test must scope this.
  name        = "${var.pipeline_state_rule_name_prefix}-${lower(each.value)}"
  description = "Reports the ${each.value} state of the TLZ deployment pipeline to the approval topic"

  event_pattern = jsonencode({
    source      = ["aws.codepipeline"]
    detail-type = ["CodePipeline Pipeline Execution State Change"]
    resources   = [aws_codepipeline.this[0].arn]
    detail = {
      state = [each.value]
    }
  })
}

# EventBridge cannot publish to a topic encrypted with the AWS managed key
# alias/aws/sns (its policy cannot grant events.<dns_suffix>), so the rules
# above would deliver nothing. While notifications are on, the approval topic
# moves to this customer-managed key, which grants EventBridge only
# GenerateDataKey* and Decrypt. AWS does not support aws:SourceAccount /
# aws:SourceArn in the key policy for this delivery path (SNS developer guide,
# "Enable compatibility between event sources from AWS services and encrypted
# topics"); the topic policy below keeps the SourceArn scope. CodePipeline
# publishes approval requests with its service role, which gets its grant on
# this key in codepipeline.tf. Notifications off: no key, alias/aws/sns stays.
resource "aws_kms_key" "approval_topic" {
  count = local.pipeline_notifications_enabled ? 1 : 0

  description             = "KMS key for the TLZ pipeline approval topic (EventBridge state notifications)"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/sns-eventbridge-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_cloudwatch_event_target" "pipeline_state" {
  for_each = local.pipeline_notification_states

  rule      = aws_cloudwatch_event_rule.pipeline_state[each.value].name
  target_id = "tlz-pipeline-approval-topic"
  arn       = aws_sns_topic.approval[0].arn
}

# EventBridge delivers to SNS through the topic's access policy — without this
# statement the events would be dropped silently. The policy exists only while
# notifications are on and is scoped to exactly the state rules above. The
# document lives in configurations/policies/ (repository convention for IAM
# and resource policies).
resource "aws_sns_topic_policy" "pipeline_state_events" {
  count = local.pipeline_notifications_enabled ? 1 : 0

  arn = aws_sns_topic.approval[0].arn

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/pipeline/state-events-topic-policy.json", {
    # Derived, not hardcoded: the EventBridge service principal carries the
    # DNS suffix of the partition.
    events_principal = "events.${data.aws_partition.current.dns_suffix}"
    sns_topic_arn    = aws_sns_topic.approval[0].arn
    rule_arns_json = jsonencode([
      for rule in aws_cloudwatch_event_rule.pipeline_state : rule.arn
    ])
  })))
}
