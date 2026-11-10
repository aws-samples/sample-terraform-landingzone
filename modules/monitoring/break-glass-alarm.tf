# =============================================================================
# Break-glass usage alarm
# =============================================================================
# The alerting half of the break-glass package (users: modules/iam,
# break-glass.tf). A metric filter on the CloudTrail log group counts every
# API event whose caller is an IAM user with the break-glass prefix, and an
# alarm notifies the configured targets on the first event — an emergency
# sign-in must never go unnoticed. Everything hangs on
# enable_break_glass_alarm (default false); an active switch without an alarm
# target is rejected at plan, because a silent break-glass alarm defeats its
# purpose.

resource "aws_cloudwatch_log_metric_filter" "break_glass" {
  count = var.enable_break_glass_alarm ? 1 : 0

  name = var.break_glass_alarm_config.metric_filter_name
  # Resolved like every other filter target (main.tf): a module-managed
  # group through its resource, any other name through a plan-time read, so a
  # break-glass alarm on a log group that does not exist fails the plan instead
  # of installing nothing behind a green apply — a security control that
  # silently failed to install.
  log_group_name = local.metric_filter_log_group_name[var.break_glass_alarm_config.log_group_name]
  pattern        = "{ ($.userIdentity.type = \"IAMUser\") && ($.userIdentity.userName = \"${var.break_glass_alarm_config.user_prefix}*\") }"

  metric_transformation {
    name      = var.break_glass_alarm_config.metric_name
    namespace = var.break_glass_alarm_config.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "break_glass" {
  count = var.enable_break_glass_alarm ? 1 : 0

  alarm_name          = var.break_glass_alarm_config.alarm_name
  metric_name         = var.break_glass_alarm_config.metric_name
  namespace           = var.break_glass_alarm_config.metric_namespace
  statistic           = "Sum"
  period              = 300
  threshold           = var.break_glass_alarm_config.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = var.break_glass_alarm_config.alarm_actions
  treat_missing_data  = "notBreaching"
  alarm_description   = "A break-glass user was used. Verify the emergency, then rotate the credentials (see modules/iam README, Break-glass access)."
}
