# =============================================================================
# Monitoring Module Tests (modules/monitoring)
# =============================================================================
# Coverage (four mandatory scenarios):
#   1. Toggle-Off      — all enable_*/feature toggles false -> zero resources
#   2. Default         — minimal valid input, default values
#   3. Custom          — user-defined configuration with realistic values
#   4. Validation      — invalid input rejected via expect_failures
#
# The module has no single module-level toggle. The Toggle-Off scenario covers
# all boolean toggles: sns_kms_encryption, enable_securityhub_cloudwatch_-
# forwarding, enable_sns_forwarder. The value-driven feature switches
# (sns_topics, cloudwatch_metric_filters, cloudwatch_alarms,
# cloudwatch_log_groups, securityhub_eventbridge_rules,
# eventbridge_default_bus_policy) are covered as well.
#
# The module uses a single unaliased AWS provider (no configuration_aliases)
# plus the archive provider for the forwarder Lambda package. Both are mocked
# so that no credentials and no local zip artifacts are required.

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111111111111"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }
}

mock_provider "archive" {}

# -----------------------------------------------------------------------------
# 1. Toggle-Off — every optional feature disabled
# -----------------------------------------------------------------------------

run "monitoring_all_toggles_off" {
  command = plan

  variables {
    sns_kms_encryption                       = false
    enable_securityhub_cloudwatch_forwarding = false
    enable_sns_forwarder                     = false
    enable_log_group_onboarding              = false
    sns_topics                               = []
    sns_email_targets                        = []
    sns_lambda_targets                       = []
    cloudwatch_metric_filters                = []
    cloudwatch_alarms                        = []
    cloudwatch_log_groups                    = []
    securityhub_eventbridge_rules            = []
    eventbridge_default_bus_policy           = null
  }

  assert {
    condition = (
      length(aws_cloudwatch_event_rule.log_group_onboarding) == 0 &&
      length(aws_lambda_function.log_group_onboarding) == 0 &&
      length(aws_iam_role.log_group_onboarding) == 0 &&
      length(aws_sqs_queue.log_group_onboarding_dlq) == 0 &&
      length(aws_cloudwatch_log_group.log_group_onboarding) == 0
    )
    error_message = "No onboarding resource must be created when enable_log_group_onboarding is false."
  }

  assert {
    condition     = length(aws_kms_key.sns) == 0 && length(aws_kms_alias.sns) == 0
    error_message = "No SNS KMS key must be created when sns_kms_encryption is false."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.securityhub_findings) == 0
    error_message = "No SecurityHub findings log group must be created when forwarding is disabled."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.securityhub_findings) == 0
    error_message = "No SecurityHub forwarding rule must be created when forwarding is disabled."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.securityhub_to_cloudwatch) == 0
    error_message = "No SecurityHub forwarding target must be created when forwarding is disabled."
  }

  assert {
    condition     = length(aws_cloudwatch_log_resource_policy.securityhub_eventbridge) == 0
    error_message = "No SecurityHub log resource policy must be created when forwarding is disabled."
  }

  assert {
    condition     = length(aws_lambda_function.sns_forwarder) == 0 && length(aws_cloudwatch_log_group.sns_forwarder) == 0
    error_message = "No forwarder Lambda and no forwarder log group must be created when enable_sns_forwarder is false."
  }

  assert {
    condition     = length(aws_iam_role.sns_forwarder) == 0 && length(aws_iam_role_policy.sns_forwarder) == 0
    error_message = "No forwarder IAM resources must be created when enable_sns_forwarder is false."
  }

  assert {
    condition     = length(data.archive_file.sns_forwarder) == 0
    error_message = "No Lambda package must be built when enable_sns_forwarder is false."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.sns_forwarder) == 0 && length(aws_lambda_permission.sns_forwarder) == 0
    error_message = "No forwarder subscriptions or permissions must be created when enable_sns_forwarder is false."
  }

  assert {
    condition     = length(aws_sns_topic.severity) == 0
    error_message = "No severity topics must be created when sns_topics is empty."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.email) == 0 && length(aws_sns_topic_subscription.lambda) == 0
    error_message = "No subscriptions must be created without email or lambda targets."
  }

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 0
    error_message = "No metric filters must be created when cloudwatch_metric_filters is empty."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.this) == 0
    error_message = "No alarms must be created when cloudwatch_alarms is empty."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.this) == 0
    error_message = "No log groups must be created when cloudwatch_log_groups is empty."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.securityhub) == 0
    error_message = "No custom SecurityHub rules must be created when securityhub_eventbridge_rules is empty."
  }

  assert {
    condition     = length(aws_cloudwatch_event_bus_policy.default) == 0
    error_message = "No event bus policy must be created when eventbridge_default_bus_policy is null."
  }

  assert {
    condition     = output.sns_kms_key_arn == "" && output.sns_forwarder_lambda_arn == ""
    error_message = "Optional feature outputs must be empty when the corresponding toggles are off."
  }

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 0 && length(aws_cloudwatch_metric_alarm.this) == 0 && length(aws_cloudwatch_log_group.this) == 0
    error_message = "No metric filters, alarms or log groups must be created when no collections are configured."
  }

  assert {
    condition     = output.securityhub_findings_log_group_arn == null
    error_message = "SecurityHub findings log group output must be null when forwarding is disabled."
  }
}

# -----------------------------------------------------------------------------
# 2. Default configuration — single-topic fallback with default values
# -----------------------------------------------------------------------------

run "monitoring_default_config" {
  command = plan

  assert {
    condition     = aws_cloudwatch_dashboard.landing_zone.dashboard_name == "TLZ-Landing-Zone-Health"
    error_message = "Dashboard name must match the module convention."
  }

  assert {
    condition     = length(aws_sns_topic.alerts) == 1
    error_message = "The fallback alert topic must be created when no severity topics are configured."
  }

  assert {
    condition     = aws_sns_topic.alerts[0].name == "tlz-landing-zone-alerts"
    error_message = "Fallback topic name must match the module convention."
  }

  assert {
    condition     = length(aws_kms_key.sns) == 1 && length(aws_kms_alias.sns) == 1
    error_message = "SNS KMS key and alias must be created when sns_kms_encryption defaults to true."
  }

  assert {
    condition     = length(aws_sns_topic_policy.alerts) == 1
    error_message = "The fallback topic policy must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.guardduty_findings) == 1
    error_message = "The fallback GuardDuty routing rule must be created."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.guardduty_findings[0].name == "tlz-guardduty-findings-alert"
    error_message = "Fallback GuardDuty rule name must match the module convention."
  }

  # jsonencode escapes ">" as \u003e, hence the u003e fragment in the pattern.
  assert {
    condition     = can(regex("u003e=\",7", aws_cloudwatch_event_rule.guardduty_findings[0].event_pattern))
    error_message = "Default alert_on_severity HIGH must map to the numeric threshold 7."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.guardduty_to_sns) == 1
    error_message = "The fallback GuardDuty target must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.guardduty_severity) == 0
    error_message = "No per-severity rules must be created in the single-topic fallback."
  }

  assert {
    condition     = length(output.severity_topic_arns) == 0
    error_message = "severity_topic_arns must be empty in the single-topic fallback."
  }
}

# -----------------------------------------------------------------------------
# 3. Custom configuration — severity topics and optional features enabled
# -----------------------------------------------------------------------------

run "monitoring_custom_config" {
  command = plan

  variables {
    sns_kms_encryption = true
    alert_on_severity  = "MEDIUM"
    organization_id    = "o-abcd1234567"

    sns_topics = [
      {
        severity      = "CRITICAL"
        email_targets = ["security@example.com", "oncall@example.com"]
      },
      {
        severity       = "HIGH"
        email_targets  = ["security@example.com"]
        lambda_targets = ["arn:aws:lambda:eu-central-1:111111111111:function:triage"]
      },
    ]

    cloudwatch_metric_filters = [
      {
        name             = "root-account-usage"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ $.userIdentity.type = \"Root\" }"
        metric_namespace = "TLZ/Security"
        metric_name      = "RootAccountUsage"
      }
    ]

    cloudwatch_alarms = [
      {
        name                = "root-account-usage-alarm"
        metric_name         = "RootAccountUsage"
        namespace           = "TLZ/Security"
        statistic           = "Sum"
        period              = 300
        threshold           = 1
        comparison_operator = "GreaterThanOrEqualToThreshold"
        evaluation_periods  = 1
        alarm_actions       = ["arn:aws:sns:eu-central-1:111111111111:tlz-alerts-high"]
        alarm_description   = "Root account usage detected"
      }
    ]

    cloudwatch_log_groups = [
      {
        name              = "/aws/securityhub/findings"
        retention_in_days = 365
      }
    ]

    enable_securityhub_cloudwatch_forwarding = true
    securityhub_severity_filter              = ["CRITICAL", "HIGH"]
    securityhub_findings_log_retention       = 731

    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
      source_topic_arns = ["arn:aws:sns:eu-central-1:111111111111:member-alerts"]
    }

    eventbridge_default_bus_policy = "enabled"
  }

  assert {
    condition     = length(aws_kms_key.sns) == 1 && length(aws_kms_alias.sns) == 1
    error_message = "SNS KMS key and alias must be created when sns_kms_encryption is true."
  }

  assert {
    condition     = aws_kms_alias.sns[0].name == "alias/tlz-sns-encryption"
    error_message = "SNS KMS alias must match the module convention."
  }

  assert {
    condition     = length(aws_sns_topic.alerts) == 0
    error_message = "The fallback topic must not be created when severity topics are configured."
  }

  assert {
    condition     = length(aws_sns_topic.severity) == 2
    error_message = "One SNS topic must be created per configured severity."
  }

  assert {
    condition     = aws_sns_topic.severity["CRITICAL"].name == "tlz-alerts-critical"
    error_message = "Severity topic names must be lower-cased and prefixed with tlz-alerts-."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.severity_email) == 3
    error_message = "All email targets across severities must be subscribed."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.severity_lambda) == 1
    error_message = "All lambda targets across severities must be subscribed."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.guardduty_severity) == 2
    error_message = "One GuardDuty routing rule must be created per severity topic."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.guardduty_findings) == 0
    error_message = "The fallback GuardDuty rule must not be created when severity topics are used."
  }

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 1
    error_message = "One metric filter must be created."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.this["root-account-usage"].log_group_name == "/aws/cloudtrail/tlz-org-trail"
    error_message = "Metric filter must target the configured log group."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.this) == 1
    error_message = "One metric alarm must be created."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.this["root-account-usage-alarm"].threshold == 1
    error_message = "Alarm threshold must match the configuration."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.this) == 1
    error_message = "One CloudWatch Log Group must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.securityhub_findings) == 1
    error_message = "SecurityHub findings log group must be created when forwarding is enabled."
  }

  assert {
    condition     = aws_cloudwatch_log_group.securityhub_findings[0].retention_in_days == 731
    error_message = "SecurityHub findings log retention must match the configuration."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.securityhub_findings) == 1
    error_message = "SecurityHub forwarding rule must be created when forwarding is enabled."
  }

  assert {
    condition     = can(regex("CRITICAL", aws_cloudwatch_event_rule.securityhub_findings[0].event_pattern))
    error_message = "SecurityHub forwarding rule must filter on the configured severities."
  }

  assert {
    condition     = length(aws_cloudwatch_log_resource_policy.securityhub_eventbridge) == 1
    error_message = "SecurityHub log resource policy must be created when forwarding is enabled."
  }

  assert {
    condition     = length(aws_lambda_function.sns_forwarder) == 1
    error_message = "Forwarder Lambda must be created when enable_sns_forwarder is true."
  }

  assert {
    condition     = aws_lambda_function.sns_forwarder[0].function_name == "tlz-sns-forwarder"
    error_message = "Forwarder Lambda name must match the module convention."
  }

  assert {
    condition     = aws_lambda_function.sns_forwarder[0].runtime == "python3.12"
    error_message = "Forwarder Lambda runtime must be python3.12."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.sns_forwarder) == 1 && length(aws_lambda_permission.sns_forwarder) == 1
    error_message = "One forwarder subscription and permission must be created per source topic."
  }

  assert {
    condition     = length(aws_cloudwatch_event_bus_policy.default) == 1
    error_message = "Event bus policy must be created when eventbridge_default_bus_policy is set."
  }

  assert {
    condition     = can(regex("o-abcd1234567", aws_cloudwatch_event_bus_policy.default[0].policy))
    error_message = "Event bus policy must contain the organization ID condition."
  }

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 1 && length(aws_cloudwatch_metric_alarm.this) == 1 && length(aws_cloudwatch_log_group.this) == 1
    error_message = "One metric filter, one alarm and one log group must be created for the configured collections."
  }

  assert {
    condition     = output.sns_topic_arn == ""
    error_message = "The single-topic output must be empty when severity topics are used."
  }

  assert {
    condition     = length(output.severity_topic_arns) == 2
    error_message = "severity_topic_arns must contain one entry per severity topic."
  }
}

# -----------------------------------------------------------------------------
# 3b. Cross-account deployment_targets warning (check block)
# -----------------------------------------------------------------------------

run "monitoring_deployment_targets_warning" {
  command = plan

  variables {
    sns_topics = [
      {
        severity           = "HIGH"
        email_targets      = ["security@example.com"]
        deployment_targets = ["222222222222"]
      }
    ]

    cloudwatch_metric_filters = [
      {
        name               = "cross-account-filter"
        log_group_name     = "/aws/cloudtrail/tlz-org-trail"
        pattern            = "{ $.eventName = \"ConsoleLogin\" }"
        metric_namespace   = "TLZ/Security"
        metric_name        = "ConsoleLogin"
        deployment_targets = ["222222222222"]
      }
    ]

    cloudwatch_alarms = [
      {
        name               = "cross-account-alarm"
        metric_name        = "ConsoleLogin"
        namespace          = "TLZ/Security"
        threshold          = 1
        deployment_targets = ["222222222222"]
      }
    ]
  }

  # Cross-account deployment is not possible with static providers — the module
  # surfaces this via check blocks instead of failing silently. The alarm also
  # carries no alarm_actions, so the notify-nobody check fires too.
  expect_failures = [
    check.sns_topics_deployment_targets_warning,
    check.cloudwatch_metric_filters_deployment_targets_warning,
    check.cloudwatch_alarms_deployment_targets_warning,
    check.cloudwatch_alarms_notify_nobody,
  ]

  assert {
    condition     = length(aws_sns_topic.severity) == 1
    error_message = "Resources must still be created in the management account despite deployment_targets."
  }
}

# -----------------------------------------------------------------------------
# 3c. Custom configuration — SecurityHub EventBridge custom rules
# -----------------------------------------------------------------------------
# A non-empty rule list must plan (a substring check applied to a string would
# abort it), and the __CW_LOG_GROUP_ARN__ placeholder must resolve instead of
# reaching EventBridge unresolved.

run "monitoring_custom_securityhub_eventbridge_rules" {
  command = plan

  # The log group ARN is mocked during the plan so that the target resolution
  # and the derived log resource policy are observable.
  override_resource {
    target          = aws_cloudwatch_log_group.this
    override_during = plan
    values = {
      arn = "arn:aws:logs:eu-central-1:111111111111:log-group:/aws/securityhub/findings"
    }
  }

  variables {
    cloudwatch_log_groups = [
      {
        name              = "/aws/securityhub/findings"
        retention_in_days = 365
      }
    ]

    securityhub_eventbridge_rules = [
      {
        name          = "securityhub-findings-to-logs"
        description   = "Forward SecurityHub findings to the findings log group"
        event_pattern = "{\"source\":[\"aws.securityhub\"]}"
        target_arn    = "__CW_LOG_GROUP_ARN__"
      },
      {
        name          = "securityhub-findings-to-topic"
        event_pattern = "{\"source\":[\"aws.securityhub\"]}"
        target_arn    = "arn:aws:sns:eu-central-1:111111111111:tlz-security-findings"
      },
    ]
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.securityhub) == 2 && length(aws_cloudwatch_event_target.securityhub) == 2
    error_message = "Each configured SecurityHub rule must create one EventBridge rule and one target."
  }

  assert {
    condition     = aws_cloudwatch_event_target.securityhub["securityhub-findings-to-logs"].arn == "arn:aws:logs:eu-central-1:111111111111:log-group:/aws/securityhub/findings"
    error_message = "The __CW_LOG_GROUP_ARN__ placeholder must resolve to the log group ARN instead of being passed through."
  }

  assert {
    condition     = aws_cloudwatch_event_target.securityhub["securityhub-findings-to-topic"].arn == "arn:aws:sns:eu-central-1:111111111111:tlz-security-findings"
    error_message = "A literal target ARN must be passed through unchanged."
  }

  assert {
    condition     = length(aws_cloudwatch_log_resource_policy.securityhub_custom_rules_eventbridge) == 1
    error_message = "A rule targeting a log group must create the EventBridge log resource policy."
  }

  assert {
    condition     = can(regex("/aws/securityhub/findings", aws_cloudwatch_log_resource_policy.securityhub_custom_rules_eventbridge[0].policy_document))
    error_message = "The log resource policy must name the resolved log group of the rule target."
  }
}

# -----------------------------------------------------------------------------
# 4. Validation failures — invalid input must be rejected
# -----------------------------------------------------------------------------

run "monitoring_invalid_alert_severity" {
  command = plan

  variables {
    alert_on_severity = "EXTREME"
  }

  expect_failures = [
    var.alert_on_severity,
  ]
}

run "monitoring_invalid_sns_topic_severity" {
  command = plan

  variables {
    sns_topics = [
      {
        severity = "URGENT"
      }
    ]
  }

  expect_failures = [
    var.sns_topics,
  ]
}

run "monitoring_invalid_alarm_statistic" {
  command = plan

  variables {
    cloudwatch_alarms = [
      {
        name        = "bad-statistic"
        metric_name = "SomeMetric"
        namespace   = "TLZ/Test"
        statistic   = "Median"
        threshold   = 1
      }
    ]
  }

  expect_failures = [
    var.cloudwatch_alarms,
  ]
}

run "monitoring_invalid_log_group_retention" {
  command = plan

  variables {
    cloudwatch_log_groups = [
      {
        name              = "/aws/test/invalid-retention"
        retention_in_days = 42
      }
    ]
  }

  expect_failures = [
    var.cloudwatch_log_groups,
  ]
}

run "monitoring_invalid_organization_id" {
  command = plan

  variables {
    organization_id = "org-12345"
  }

  expect_failures = [
    var.organization_id,
  ]
}

run "monitoring_invalid_forwarder_topic_arn" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "not-an-arn"
    }
  }

  expect_failures = [
    var.sns_forwarder_config,
  ]
}

# SNS invokes the forwarder asynchronously; the
# Lambda must carry a dead-letter queue and a concurrency cap so a failed
# forward is captured instead of silently dropping the alert.
run "monitoring_sns_forwarder_dlq_defaults" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
    }
  }

  assert {
    condition     = length(aws_sqs_queue.sns_forwarder_dlq) == 1
    error_message = "The module-managed dead-letter queue must be created when no external dlq_arn is configured."
  }

  assert {
    condition     = aws_sqs_queue.sns_forwarder_dlq[0].name == "tlz-sns-forwarder-dlq" && aws_sqs_queue.sns_forwarder_dlq[0].sqs_managed_sse_enabled == true
    error_message = "The dead-letter queue must follow the module naming convention and be SSE-encrypted."
  }

  assert {
    condition     = length(aws_lambda_function.sns_forwarder[0].dead_letter_config) == 1
    error_message = "The forwarder Lambda must carry a dead_letter_config."
  }

  assert {
    condition     = aws_lambda_function.sns_forwarder[0].reserved_concurrent_executions == 10
    error_message = "The forwarder Lambda must default to a reserved concurrency of 10."
  }

  # The function's own execution log group is a managed resource, not an
  # implicit creation of the Lambda service: derived from the function name,
  # bounded by the default retention.
  assert {
    condition     = length(aws_cloudwatch_log_group.sns_forwarder) == 1 && aws_cloudwatch_log_group.sns_forwarder[0].name == "/aws/lambda/tlz-sns-forwarder"
    error_message = "The forwarder's own log group /aws/lambda/tlz-sns-forwarder must be declared when the forwarder is enabled."
  }

  assert {
    condition     = aws_cloudwatch_log_group.sns_forwarder[0].retention_in_days == 365
    error_message = "The forwarder log group must default to 365 days of retention."
  }
}

# Reach and rejection of sns_forwarder_config.log_retention_in_days: the value
# reaches the forwarder's own log group; a number outside the CloudWatch
# retention set is refused at plan time instead of at apply.
run "sns_forwarder_log_retention_reaches_the_log_group" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn     = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
      log_retention_in_days = 30
    }
  }

  assert {
    condition     = aws_cloudwatch_log_group.sns_forwarder[0].retention_in_days == 30
    error_message = "log_retention_in_days must reach the forwarder's own log group."
  }
}

run "sns_forwarder_invalid_log_retention_rejected" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn     = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
      log_retention_in_days = 42
    }
  }

  expect_failures = [
    var.sns_forwarder_config,
  ]
}

run "monitoring_sns_forwarder_external_dlq" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn              = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
      dlq_arn                        = "arn:aws:sqs:eu-central-1:210987654321:existing-dlq"
      reserved_concurrent_executions = 5
    }
  }

  assert {
    condition     = length(aws_sqs_queue.sns_forwarder_dlq) == 0
    error_message = "No module-managed queue must be created when an external dlq_arn is configured."
  }

  assert {
    condition     = aws_lambda_function.sns_forwarder[0].dead_letter_config[0].target_arn == "arn:aws:sqs:eu-central-1:210987654321:existing-dlq"
    error_message = "The dead_letter_config must point at the caller-provided queue."
  }

  assert {
    condition     = aws_lambda_function.sns_forwarder[0].reserved_concurrent_executions == 5
    error_message = "The configured reserved concurrency must be applied."
  }
}

run "monitoring_invalid_forwarder_dlq_arn" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
      dlq_arn           = "not-an-arn"
    }
  }

  expect_failures = [
    var.sns_forwarder_config,
  ]
}

# reserved_concurrent_executions = 0 would disable the function and silently
# drop every alert — the validation rejects it.
run "monitoring_invalid_forwarder_zero_concurrency" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn              = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
      reserved_concurrent_executions = 0
    }
  }

  expect_failures = [
    var.sns_forwarder_config,
  ]
}

# The target placeholder must be rejected when the log group it resolves to is
# not configured.
run "monitoring_invalid_securityhub_target_placeholder_without_log_group" {
  command = plan

  variables {
    cloudwatch_log_groups = []

    securityhub_eventbridge_rules = [
      {
        name          = "securityhub-findings-to-logs"
        event_pattern = "{\"source\":[\"aws.securityhub\"]}"
        target_arn    = "__CW_LOG_GROUP_ARN__"
      }
    ]
  }

  expect_failures = [
    var.securityhub_eventbridge_rules,
  ]
}

# -----------------------------------------------------------------------------
# 5. Landing Zone Health dashboard — diagnostic widgets and their identifiers
# -----------------------------------------------------------------------------
# The toggle enable_diagnostics_dashboard and the four identifiers
# guardduty_detector_id, config_aggregator_name, cloudtrail_arn and
# central_log_bucket_name must each reach the dashboard body.

# 5a. Diagnostics on (module default) with every identifier injected — as the
#     monitoring stack passes them from dependency.logging and dependency.security.
run "monitoring_diagnostics_dashboard_with_identifiers" {
  command = plan

  variables {
    guardduty_detector_id   = "12abc34d567e8fa901bc2d34e56789f0"
    config_aggregator_name  = "tlz-org-config-aggregator"
    cloudtrail_arn          = "arn:aws:cloudtrail:eu-central-1:111111111111:trail/tlz-org-trail"
    central_log_bucket_name = "tlz-central-logs-111111111111-eu-central-1"
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "12abc34d567e8fa901bc2d34e56789f0")
    error_message = "guardduty_detector_id must reach the dashboard as the DetectorId dimension."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "\"DetectorId\",\"12abc34d567e8fa901bc2d34e56789f0\"")
    error_message = "The detector ID must be rendered as a dimension pair, not as free text."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "tlz-org-config-aggregator")
    error_message = "config_aggregator_name must reach the dashboard."
  }

  # The widget title carries the trail name, not the full ARN — neither
  # AWS/CloudTrail nor AWS/Config offers a matching CloudWatch dimension.
  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "tlz-org-trail")
    error_message = "cloudtrail_arn must reach the dashboard as the trail name."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "\"BucketName\",\"tlz-central-logs-111111111111-eu-central-1\"")
    error_message = "central_log_bucket_name must reach the dashboard as the BucketName dimension."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "BucketSizeBytes")
    error_message = "The diagnostics dashboard must show the S3 storage metrics of the central log bucket."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "AWS/SecurityHub")
    error_message = "The diagnostic widgets must be part of the dashboard while enable_diagnostics_dashboard is true."
  }

  assert {
    condition     = length(local.dashboard_widgets) == 9
    error_message = "With diagnostics on and all identifiers set the dashboard must hold four base and five diagnostic widgets."
  }
}

# 5b. Diagnostics on, no identifiers — the pre-injection state. The metrics stay
#     undimensioned and the storage widget is omitted instead of carrying an
#     empty BucketName dimension.
run "monitoring_diagnostics_dashboard_without_identifiers" {
  command = plan

  variables {
    guardduty_detector_id   = ""
    config_aggregator_name  = ""
    cloudtrail_arn          = ""
    central_log_bucket_name = ""
  }

  assert {
    condition     = !strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "DetectorId")
    error_message = "Without a detector ID the GuardDuty metric must stay undimensioned."
  }

  assert {
    condition     = !strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "BucketName")
    error_message = "Without a bucket name the S3 storage widget must be omitted."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "\"title\":\"Config Compliance\"")
    error_message = "Without an aggregator name the Config widget must keep its plain title."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "\"title\":\"CloudTrail Events\"")
    error_message = "Without a trail ARN the CloudTrail widget must keep its plain title."
  }

  assert {
    condition     = length(local.dashboard_widgets) == 8
    error_message = "Without identifiers the dashboard must hold four base and four diagnostic widgets (the S3 storage widget is omitted)."
  }
}

# 5c. Diagnostics off — the diagnostic half disappears, the base widgets remain.
run "monitoring_diagnostics_dashboard_disabled" {
  command = plan

  variables {
    enable_diagnostics_dashboard = false
    guardduty_detector_id        = "12abc34d567e8fa901bc2d34e56789f0"
    config_aggregator_name       = "tlz-org-config-aggregator"
    cloudtrail_arn               = "arn:aws:cloudtrail:eu-central-1:111111111111:trail/tlz-org-trail"
    central_log_bucket_name      = "tlz-central-logs-111111111111-eu-central-1"
  }

  assert {
    condition     = length(local.dashboard_widgets) == 4
    error_message = "With enable_diagnostics_dashboard = false only the four base widgets may remain."
  }

  assert {
    condition     = !strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "AWS/SecurityHub")
    error_message = "The Security Hub diagnostic widget must disappear when the toggle is off."
  }

  assert {
    condition     = !strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "BucketSizeBytes")
    error_message = "The S3 storage diagnostic widget must disappear when the toggle is off."
  }

  # The base widgets keep their identifiers — the toggle only governs the
  # diagnostic half.
  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "\"DetectorId\",\"12abc34d567e8fa901bc2d34e56789f0\"")
    error_message = "The base GuardDuty widget must keep its detector dimension when diagnostics are off."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_dashboard.landing_zone.dashboard_body, "tlz-org-config-aggregator")
    error_message = "The base Config widget must keep the aggregator name when diagnostics are off."
  }
}

# -----------------------------------------------------------------------------
# 6. Metric filters, alarms and severity topics reach a resource
# -----------------------------------------------------------------------------
# The three collections the module does its actual work from. This scenario nails the effect of a filled collection down to the resource and
# to the outputs; the neighbouring scenario nails the empty case down to zero.

run "monitoring_collections_create_resources" {
  command = plan

  variables {
    sns_topics = [
      { severity = "CRITICAL", email_targets = ["soc@example.com"] },
    ]

    cloudwatch_metric_filters = [
      {
        name             = "root-account-usage"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ $.userIdentity.type = \"Root\" }"
        metric_namespace = "TLZ/Security"
        metric_name      = "RootAccountUsage"
      },
      {
        name             = "unauthorized-api-calls"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
        metric_namespace = "TLZ/Security"
        metric_name      = "UnauthorizedApiCalls"
        metric_value     = "1"
      },
    ]

    cloudwatch_alarms = [
      {
        name              = "root-account-usage"
        metric_name       = "RootAccountUsage"
        namespace         = "TLZ/Security"
        threshold         = 1
        alarm_description = "Root account was used"
      },
      {
        name               = "unauthorized-api-calls"
        metric_name        = "UnauthorizedApiCalls"
        namespace          = "TLZ/Security"
        statistic          = "Sum"
        period             = 300
        threshold          = 5
        evaluation_periods = 1
      },
    ]
  }

  # The two alarms mirror configurations/base/base.tfvars, whose alarms ship
  # without alarm_actions until env/common.hcl names the recipients (its OPEN
  # EDGE note) — exactly the state the notify-nobody check reports.
  expect_failures = [
    check.cloudwatch_alarms_notify_nobody,
  ]

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 2
    error_message = "Each configured metric filter must create one aws_cloudwatch_log_metric_filter."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.this["unauthorized-api-calls"].name == "unauthorized-api-calls"
    error_message = "The metric filter must carry the configured name."
  }

  assert {
    condition     = one(aws_cloudwatch_log_metric_filter.this["unauthorized-api-calls"].metric_transformation).namespace == "TLZ/Security"
    error_message = "The metric transformation must carry the configured namespace."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.this) == 2
    error_message = "Each configured alarm must create one aws_cloudwatch_metric_alarm."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.this["unauthorized-api-calls"].threshold == 5
    error_message = "The alarm must carry the configured threshold."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.this["root-account-usage"].comparison_operator == "GreaterThanOrEqualToThreshold"
    error_message = "An alarm without an explicit comparison operator must use the documented default."
  }

  assert {
    condition     = length(aws_sns_topic.severity) == 1 && length(aws_sns_topic.alerts) == 0
    error_message = "A configured severity topic must replace the single-topic fallback."
  }

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.this) == 2 && length(aws_cloudwatch_metric_alarm.this) == 2
    error_message = "Two metric filters and two alarms must be created once the collections are wired."
  }

  assert {
    condition     = length(output.metric_filter_names) == 2 && length(output.alarm_arns) == 2
    error_message = "metric_filter_names and alarm_arns must carry a value once the collections are wired."
  }

  assert {
    condition     = length(output.severity_topic_arns) == 1
    error_message = "severity_topic_arns must carry a value once sns_topics is wired."
  }
}

# -----------------------------------------------------------------------------
# SNS topic names — defaults, reach and rejection
# -----------------------------------------------------------------------------

# Entries without a name keep the derived topic names.
run "regression_topic_names_stay_derived" {
  command = plan

  variables {
    organization_id = "o-abcd1234567"
    sns_topics = [
      { severity = "HIGH" },
      { severity = "LOW" },
    ]
  }

  assert {
    condition     = aws_sns_topic.severity["HIGH"].name == "tlz-alerts-high"
    error_message = "A topic without a name must keep the derived tlz-alerts-<severity> name."
  }

  assert {
    condition     = aws_sns_topic.severity["LOW"].name == "tlz-alerts-low"
    error_message = "Every unnamed topic must keep its derived name."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.guardduty_severity["HIGH"].name == "tlz-guardduty-high-findings" && aws_cloudwatch_event_rule.guardduty_severity["LOW"].name == "tlz-guardduty-low-findings"
    error_message = "An entry without rule_name must keep the derived tlz-guardduty-<severity>-findings rule name — a live plan must stay empty."
  }
}

# Reach: a configured name wins over the derivation, per entry.
run "monitoring_topic_name_override_reaches_the_topic" {
  command = plan

  variables {
    organization_id = "o-abcd1234567"
    sns_topics = [
      { severity = "HIGH", name = "security-alerts-prod", rule_name = "tlz-l4test-guardduty-high-findings" },
      { severity = "LOW" },
    ]
  }

  assert {
    condition     = aws_sns_topic.severity["HIGH"].name == "security-alerts-prod"
    error_message = "The configured topic name must reach the topic."
  }

  assert {
    condition     = aws_sns_topic.severity["LOW"].name == "tlz-alerts-low"
    error_message = "An unnamed entry beside a named one must keep its derived name."
  }

  # The routing rule is upsert-prone (PutRule); its target must follow the
  # renamed rule or the apply leaves a target pointing at a rule that does
  # not exist.
  assert {
    condition     = aws_cloudwatch_event_rule.guardduty_severity["HIGH"].name == "tlz-l4test-guardduty-high-findings" && aws_cloudwatch_event_target.guardduty_severity_to_sns["HIGH"].rule == "tlz-l4test-guardduty-high-findings"
    error_message = "A configured rule_name must reach the per-severity GuardDuty rule and its target must follow it."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.guardduty_severity["LOW"].name == "tlz-guardduty-low-findings"
    error_message = "An entry without rule_name beside one with must keep its derived rule name."
  }
}

# Rejection: the per-severity rule is a guardrail class (only
# arn:*:events:*:*:rule/tlz-* is protected), so a rule_name outside the
# namespace is refused at plan time like every other rule name of the module.
run "monitoring_rule_name_outside_namespace_rejected" {
  command = plan

  variables {
    organization_id = "o-abcd1234567"
    sns_topics = [
      { severity = "HIGH", rule_name = "guardduty-high-findings" },
    ]
  }

  expect_failures = [var.sns_topics]
}

# Two entries resolving to one rule name would share a single upserted rule.
run "monitoring_duplicate_rule_name_rejected" {
  command = plan

  variables {
    organization_id = "o-abcd1234567"
    sns_topics = [
      { severity = "HIGH", rule_name = "tlz-guardduty-low-findings" },
      { severity = "LOW" },
    ]
  }

  expect_failures = [var.sns_topics]
}

run "monitoring_invalid_topic_name_rejected" {
  command = plan

  variables {
    organization_id = "o-abcd1234567"
    sns_topics = [
      { severity = "HIGH", name = "no spaces allowed" },
    ]
  }

  expect_failures = [var.sns_topics]
}

run "monitoring_duplicate_topic_name_rejected" {
  command = plan

  variables {
    organization_id = "o-abcd1234567"
    sns_topics = [
      { severity = "HIGH", name = "same-name" },
      { severity = "LOW", name = "same-name" },
    ]
  }

  expect_failures = [var.sns_topics]
}

# -----------------------------------------------------------------------------
# Log group onboarding — toggle, reach and rejection
# -----------------------------------------------------------------------------

# Toggle-Off: the onboarding automation is opt-in; without the toggle no rule,
# no Lambda, no role, no queue exists.
run "regression_onboarding_disabled_creates_nothing" {
  command = plan

  variables {
    organization_id = "o-abcd1234567"
  }

  assert {
    condition = (
      length(aws_cloudwatch_event_rule.log_group_onboarding) == 0 &&
      length(aws_lambda_function.log_group_onboarding) == 0 &&
      length(aws_iam_role.log_group_onboarding) == 0 &&
      length(aws_sqs_queue.log_group_onboarding_dlq) == 0 &&
      length(aws_cloudwatch_log_group.log_group_onboarding) == 0
    )
    error_message = "No onboarding resource may exist while enable_log_group_onboarding is false."
  }
}

# Reach: the toggle builds the chain and every default reaches the Lambda
# environment; the rule listens for successful CreateLogGroup calls.
run "monitoring_onboarding_reaches_the_lambda" {
  command = plan

  variables {
    organization_id             = "o-abcd1234567"
    enable_log_group_onboarding = true
    log_group_onboarding = {
      retention_in_days           = 90
      kms_key_arn                 = "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
      destination_arn             = "arn:aws:logs:eu-central-1:111111111111:destination:central-logs"
      subscription_role_arn       = "arn:aws:iam::111111111111:role/tlz-cw-to-kinesis-role"
      excluded_log_group_patterns = ["/aws/lambda/*"]
    }
  }

  assert {
    condition = (
      length(aws_cloudwatch_event_rule.log_group_onboarding) == 1 &&
      length(aws_cloudwatch_event_target.log_group_onboarding) == 1 &&
      length(aws_lambda_permission.log_group_onboarding) == 1 &&
      length(aws_lambda_function.log_group_onboarding) == 1
    )
    error_message = "Enabling the onboarding must create the rule, target, permission and Lambda."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_event_rule.log_group_onboarding[0].event_pattern, "CreateLogGroup")
    error_message = "The rule must listen for CreateLogGroup API calls."
  }

  assert {
    condition     = aws_lambda_function.log_group_onboarding[0].environment[0].variables["LOG_RETENTION_DAYS"] == "90"
    error_message = "The retention default must reach the Lambda environment."
  }

  assert {
    condition     = aws_lambda_function.log_group_onboarding[0].environment[0].variables["LOG_KMS_KEY_ARN"] == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
    error_message = "The KMS key must reach the Lambda environment."
  }

  assert {
    condition     = aws_lambda_function.log_group_onboarding[0].environment[0].variables["LOG_DESTINATION_ARN"] == "arn:aws:logs:eu-central-1:111111111111:destination:central-logs"
    error_message = "The destination must reach the Lambda environment."
  }

  assert {
    condition     = aws_lambda_function.log_group_onboarding[0].environment[0].variables["LOG_EXCLUDED_PATTERNS"] == jsonencode(["/aws/lambda/*"])
    error_message = "The exclusion patterns must reach the Lambda environment."
  }

  # The function's own execution log group is declared by the module, named
  # from the function so the two cannot disagree, and carries the same
  # retention and key the automation applies to every other group. The
  # exclusion pattern /aws/lambda/* governs what the automation touches, not
  # this module-owned resource — it is bounded regardless.
  assert {
    condition     = length(aws_cloudwatch_log_group.log_group_onboarding) == 1 && aws_cloudwatch_log_group.log_group_onboarding[0].name == "/aws/lambda/tlz-log-group-onboarding"
    error_message = "The onboarding function's own log group /aws/lambda/tlz-log-group-onboarding must be declared when the onboarding is enabled."
  }

  assert {
    condition     = aws_cloudwatch_log_group.log_group_onboarding[0].retention_in_days == 90
    error_message = "log_group_onboarding.retention_in_days must reach the function's own log group, exclusion patterns notwithstanding."
  }

  assert {
    condition     = aws_cloudwatch_log_group.log_group_onboarding[0].kms_key_id == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
    error_message = "log_group_onboarding.kms_key_arn must reach the function's own log group."
  }
}

# Default: without a configured key the function's own log group keeps the
# CloudWatch service encryption (kms_key_id null, not an empty string, which
# the provider would reject) and the 365-day default retention.
run "monitoring_onboarding_own_log_group_defaults" {
  command = plan

  variables {
    organization_id             = "o-abcd1234567"
    enable_log_group_onboarding = true
  }

  assert {
    condition     = aws_cloudwatch_log_group.log_group_onboarding[0].retention_in_days == 365
    error_message = "The onboarding function's own log group must default to 365 days of retention."
  }

  assert {
    condition     = aws_cloudwatch_log_group.log_group_onboarding[0].kms_key_id == null
    error_message = "Without log_group_onboarding.kms_key_arn the function's own log group must carry no kms_key_id."
  }
}

run "monitoring_onboarding_invalid_retention_rejected" {
  command = plan

  variables {
    organization_id             = "o-abcd1234567"
    enable_log_group_onboarding = true
    log_group_onboarding = {
      retention_in_days = 42
    }
  }

  expect_failures = [var.log_group_onboarding]
}

run "monitoring_onboarding_destination_without_role_rejected" {
  command = plan

  variables {
    organization_id             = "o-abcd1234567"
    enable_log_group_onboarding = true
    log_group_onboarding = {
      destination_arn = "arn:aws:logs:eu-central-1:111111111111:destination:central-logs"
    }
  }

  expect_failures = [var.log_group_onboarding]
}

run "monitoring_onboarding_empty_exclusion_rejected" {
  command = plan

  variables {
    organization_id             = "o-abcd1234567"
    enable_log_group_onboarding = true
    log_group_onboarding = {
      excluded_log_group_patterns = ["  "]
    }
  }

  expect_failures = [var.log_group_onboarding]
}

# -----------------------------------------------------------------------------
# Scenario: SecurityHub findings log group name
# -----------------------------------------------------------------------------
# The default is the derived production name, so a deployment without the
# setting keeps its plan.
run "regression_securityhub_log_group_name_stays_derived" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
  }

  assert {
    condition     = aws_cloudwatch_log_group.securityhub_findings[0].name == "/aws/events/securityhub-findings"
    error_message = "Without securityhub_findings_log_group_name the log group must keep its default name."
  }
}

run "securityhub_log_group_name_override_reaches_the_resource" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
    securityhub_findings_log_group_name      = "/org/security/findings"
  }

  assert {
    condition     = aws_cloudwatch_log_group.securityhub_findings[0].name == "/org/security/findings"
    error_message = "securityhub_findings_log_group_name must reach the log group name."
  }
}

run "securityhub_log_group_name_invalid_rejected" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
    securityhub_findings_log_group_name      = "spaces are invalid"
  }

  expect_failures = [var.securityhub_findings_log_group_name]
}

# The name is either a path form or inside the tlz- namespace — the two shapes
# the static prefix guard can classify (ProtectCloudWatchLogGroups covers only
# log-group:tlz-* and /aws/lambda/tlz-*; a path form is deliberately outside).
# A well-formed bare name with neither shape must be refused; the tlz- form is
# what the live apply-test uses (tlz-l4test-…) and must pass.
run "securityhub_log_group_name_tlz_form_accepted" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
    securityhub_findings_log_group_name      = "tlz-securityhub-findings"
  }

  assert {
    condition     = aws_cloudwatch_log_group.securityhub_findings[0].name == "tlz-securityhub-findings"
    error_message = "A tlz- log group name must be accepted and reach the resource."
  }
}

run "securityhub_log_group_name_bare_outside_namespace_rejected" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
    securityhub_findings_log_group_name      = "securityhub-findings"
  }

  expect_failures = [var.securityhub_findings_log_group_name]
}

# Without the setting the log group falls back to the CloudWatch Logs service
# key; with it the declared KMS key must reach the resource.
run "securityhub_findings_log_kms_key_reaches_the_log_group" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
    securityhub_findings_log_kms_key_id      = "arn:aws:kms:eu-central-1:111111111111:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = aws_cloudwatch_log_group.securityhub_findings[0].kms_key_id == "arn:aws:kms:eu-central-1:111111111111:key/11111111-2222-3333-4444-555555555555"
    error_message = "securityhub_findings_log_kms_key_id must reach the findings log group's kms_key_id."
  }
}

run "securityhub_findings_log_kms_key_invalid_rejected" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
    securityhub_findings_log_kms_key_id      = "not-a-kms-reference"
  }

  expect_failures = [var.securityhub_findings_log_kms_key_id]
}
# -----------------------------------------------------------------------------
# Scenario: CloudWatch defaults and deletion protection — defaults
# -----------------------------------------------------------------------------
# Entries without default_value and skip_destroy plan with no default value on
# the transformation and a deletable group.
run "regression_cloudwatch_entries_keep_the_plan" {
  command = plan
  variables {
    cloudwatch_metric_filters = [
      {
        name             = "root-account-usage"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ $.userIdentity.type = \"Root\" }"
        metric_namespace = "TLZ/Security"
        metric_name      = "RootAccountUsage"
      },
    ]
    cloudwatch_log_groups = [
      { name = "/tlz/security/audit" },
    ]
  }
  assert {
    condition     = aws_cloudwatch_log_metric_filter.this["root-account-usage"].metric_transformation[0].default_value == null
    error_message = "Without default_value the metric transformation must carry none — the default."
  }
  assert {
    condition     = aws_cloudwatch_log_group.this["/tlz/security/audit"].skip_destroy == false
    error_message = "Without skip_destroy a log group must stay deletable — the default."
  }
}
# -----------------------------------------------------------------------------
# Scenario: CloudWatch defaults and deletion protection — values reach the
# resources
# -----------------------------------------------------------------------------
run "cloudwatch_default_value_and_skip_destroy_reach_the_resources" {
  command = plan
  variables {
    cloudwatch_metric_filters = [
      {
        name             = "unauthorized-api-calls"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ ($.errorCode = \"*UnauthorizedOperation\") }"
        metric_namespace = "TLZ/Security"
        metric_name      = "UnauthorizedApiCalls"
        default_value    = 0
      },
    ]
    cloudwatch_log_groups = [
      {
        name              = "/tlz/security/audit"
        retention_in_days = 365
        skip_destroy      = true
      },
    ]
  }
  assert {
    condition     = aws_cloudwatch_log_metric_filter.this["unauthorized-api-calls"].metric_transformation[0].default_value == "0"
    error_message = "default_value must reach the metric transformation (as the provider's string form)."
  }
  assert {
    condition     = aws_cloudwatch_log_group.this["/tlz/security/audit"].skip_destroy == true
    error_message = "skip_destroy must reach the log group resource."
  }
  assert {
    condition     = aws_cloudwatch_log_group.this["/tlz/security/audit"].retention_in_days == 365
    error_message = "The existing attributes must keep working next to the new one."
  }
}

# -----------------------------------------------------------------------------
# Break-glass usage alarm
# -----------------------------------------------------------------------------

run "break_glass_alarm_off_no_resources" {
  command = plan

  variables {
    enable_break_glass_alarm = false
  }

  assert {
    condition     = length(aws_cloudwatch_log_metric_filter.break_glass) == 0 && length(aws_cloudwatch_metric_alarm.break_glass) == 0
    error_message = "Without enable_break_glass_alarm no break-glass metric filter or alarm may be planned."
  }
}

run "break_glass_alarm_reaches_filter_and_alarm" {
  command = plan

  variables {
    enable_break_glass_alarm = true
    break_glass_alarm_config = {
      alarm_actions = ["arn:aws:sns:eu-central-1:111111111111:tlz-alerts"]
    }
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.break_glass[0].pattern == "{ ($.userIdentity.type = \"IAMUser\") && ($.userIdentity.userName = \"tlz-break-glass*\") }"
    error_message = "The metric filter must match every API event of IAM users with the break-glass prefix."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.break_glass[0].log_group_name == "/aws/cloudtrail/tlz-org-trail"
    error_message = "The filter must read the organization trail's log group by default."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.break_glass[0].threshold == 1 && aws_cloudwatch_metric_alarm.break_glass[0].comparison_operator == "GreaterThanOrEqualToThreshold"
    error_message = "The alarm must fire on the first break-glass event (threshold 1, >=)."
  }

  assert {
    condition     = contains(aws_cloudwatch_metric_alarm.break_glass[0].alarm_actions, "arn:aws:sns:eu-central-1:111111111111:tlz-alerts")
    error_message = "The alarm must notify the configured target."
  }
}

run "break_glass_alarm_without_target_rejected" {
  command = plan

  variables {
    enable_break_glass_alarm = true
    break_glass_alarm_config = {
      alarm_actions = []
    }
  }

  expect_failures = [var.break_glass_alarm_config]
}

run "break_glass_alarm_without_config_rejected" {
  command = plan

  variables {
    enable_break_glass_alarm = true
  }

  expect_failures = [var.break_glass_alarm_config]
}

# -----------------------------------------------------------------------------
# Topic policy admits both module-side publishers (EventBridge + CloudWatch)
# -----------------------------------------------------------------------------
# Attaching aws_sns_topic_policy replaces the SNS default policy, so CloudWatch
# alarm delivery (alarm_actions) needs its own statement. The policy documents
# interpolate the topic ARN, which is unknown in a plan — the override pins it
# so the rendered document is observable.

run "topic_policy_admits_cloudwatch_alarms" {
  command = plan

  override_resource {
    target          = aws_sns_topic.alerts
    override_during = plan
    values = {
      arn = "arn:aws:sns:eu-central-1:111111111111:tlz-landing-zone-alerts"
    }
  }

  variables {
    sns_kms_encryption = true
  }

  assert {
    condition     = strcontains(aws_sns_topic_policy.alerts[0].policy, "\"AllowCloudWatchAlarmsPublish\"")
    error_message = "The fallback topic policy must carry the CloudWatch alarms publish statement."
  }

  assert {
    condition     = strcontains(aws_sns_topic_policy.alerts[0].policy, "cloudwatch.amazonaws.com")
    error_message = "The CloudWatch service principal must be rendered from the partition dns_suffix."
  }

  assert {
    condition     = strcontains(aws_sns_topic_policy.alerts[0].policy, "\"AllowEventBridgePublish\"")
    error_message = "The EventBridge publish statement must survive next to the CloudWatch statement."
  }

  assert {
    condition     = strcontains(aws_sns_topic_policy.alerts[0].policy, "\"AllowBudgetsPublish\"") && strcontains(aws_sns_topic_policy.alerts[0].policy, "budgets.amazonaws.com")
    error_message = "The topic policy must admit budgets.amazonaws.com — without it a budget notification subscribed to this topic is silently never delivered."
  }

  assert {
    condition     = strcontains(aws_kms_key.sns[0].policy, "\"AllowTopicPublishersKeyUse\"")
    error_message = "The SNS CMK policy must grant the topic's publishers key use — without it CloudWatch cannot deliver to encrypted topics."
  }

  assert {
    condition     = strcontains(aws_kms_key.sns[0].policy, "cloudwatch.amazonaws.com") && strcontains(aws_kms_key.sns[0].policy, "events.amazonaws.com")
    error_message = "Both publishing service principals (cloudwatch, events) must be able to use the CMK."
  }

  assert {
    condition     = strcontains(aws_kms_key.sns[0].policy, "budgets.amazonaws.com")
    error_message = "The budgets principal must be able to use the CMK — sns:Publish alone still fails on kms:GenerateDataKey for an encrypted topic."
  }
}

run "severity_topic_policy_admits_cloudwatch_alarms" {
  command = plan

  override_resource {
    target          = aws_sns_topic.severity
    override_during = plan
    values = {
      arn = "arn:aws:sns:eu-central-1:111111111111:tlz-alerts-high"
    }
  }

  variables {
    organization_id = "o-abcd1234567"
    sns_topics = [
      { severity = "HIGH" },
    ]
  }

  assert {
    condition     = strcontains(aws_sns_topic_policy.severity["HIGH"].policy, "\"AllowCloudWatchAlarmsPublish\"")
    error_message = "Severity topic policies must carry the CloudWatch alarms publish statement as well."
  }

  assert {
    condition     = strcontains(aws_sns_topic_policy.severity["HIGH"].policy, "\"AllowBudgetsPublish\"")
    error_message = "Severity topic policies must carry the budgets publish statement as well — both topic variants render the same policy document."
  }
}

# -----------------------------------------------------------------------------
# Upsert-safe resource names — defaults stay put, overrides reach, rejections
# -----------------------------------------------------------------------------
# SNS CreateTopic, EventBridge PutRule, CloudWatch PutDashboard /
# PutMetricAlarm / PutMetricFilter and Logs PutResourcePolicy are UPSERTs, and
# SQS CreateQueue is IDEMPOTENT for identical attributes — all return the
# existing resource of the same name instead of failing, so a live apply-test
# using the fixed account-wide name adopts the live resource and its teardown
# deletes it. Every such name is therefore a variable
# defaulting to the production name (README, "Upsert-safe resource names").
# KMS CreateAlias is create-only, but a fixed alias would make
# sns_kms_encryption untestable live for the same reason. These runs pin all
# three halves of the contract: the default keeps the production name (a live
# plan stays empty), a non-default value reaches the resource (a test can scope
# itself), and a name outside the guardrail-protected tlz- namespace is refused
# at plan time (the static prefix guard only reads quoted literals, so for a
# var.* name this validation is what keeps the invariant).

# Every default is the production name. The single-topic names (topic, GuardDuty rule, dashboard) are pinned
# by monitoring_default_config above; this run covers the toggled resources.
run "regression_upsert_safe_names_keep_their_defaults" {
  command = plan

  variables {
    sns_kms_encryption                       = true
    enable_log_group_onboarding              = true
    enable_securityhub_cloudwatch_forwarding = true
  }

  assert {
    condition     = aws_kms_alias.sns[0].name == "alias/tlz-sns-encryption"
    error_message = "Without sns_kms_alias_name the SNS key alias must keep its default name."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.log_group_onboarding[0].name == "tlz-log-group-onboarding"
    error_message = "Without log_group_onboarding_rule_name the onboarding rule must keep its default name."
  }

  assert {
    condition     = aws_sqs_queue.log_group_onboarding_dlq[0].name == "tlz-log-group-onboarding-dlq"
    error_message = "Without log_group_onboarding_dlq_name the onboarding dead-letter queue must keep its default name."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.log_group_onboarding[0].policy, ":sqs:*:*:tlz-log-group-onboarding-dlq\"")
    error_message = "Without log_group_onboarding_dlq_name the Lambda policy's sqs:SendMessage grant must keep naming the default queue."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.securityhub_findings[0].name == "tlz-securityhub-findings-to-cloudwatch"
    error_message = "Without securityhub_findings_rule_name the forwarding rule must keep its default name."
  }

  assert {
    condition     = aws_cloudwatch_log_resource_policy.securityhub_eventbridge[0].policy_name == "tlz-securityhub-eventbridge-log-policy"
    error_message = "Without securityhub_eventbridge_log_policy_name the forwarding log policy must keep its default name."
  }
}

# Reach: a test-scoped name for every upsert-prone resource arrives at the
# resource attribute the API keys on. Mirrors what a live apply-test under
# tests/live/modules/monitoring/ has to set to leave the live account alone.
run "upsert_safe_name_overrides_reach_the_resources" {
  command = plan

  variables {
    sns_kms_encryption                       = true
    enable_log_group_onboarding              = true
    enable_securityhub_cloudwatch_forwarding = true
    enable_break_glass_alarm                 = true
    cloudwatch_log_groups                    = [{ name = "/aws/securityhub/findings" }]
    securityhub_eventbridge_rules = [
      {
        name          = "tlz-l4test-securityhub-to-cw"
        event_pattern = "{\"source\":[\"aws.securityhub\"]}"
        target_arn    = "__CW_LOG_GROUP_ARN__"
      },
    ]
    break_glass_alarm_config = {
      alarm_actions      = ["arn:aws:sns:eu-central-1:111111111111:tlz-l4test-alerts"]
      alarm_name         = "tlz-l4test-break-glass-usage"
      metric_filter_name = "tlz-l4test-break-glass-usage-filter"
    }

    alerts_topic_name                        = "tlz-l4test-landing-zone-alerts"
    sns_kms_alias_name                       = "alias/tlz-l4test-sns-encryption"
    guardduty_findings_rule_name             = "tlz-l4test-guardduty-findings-alert"
    securityhub_findings_rule_name           = "tlz-l4test-securityhub-findings-to-cw"
    log_group_onboarding_rule_name           = "tlz-l4test-log-group-onboarding"
    log_group_onboarding_dlq_name            = "tlz-l4test-log-group-onboarding-dlq"
    dashboard_name                           = "tlz-l4test-landing-zone-health"
    securityhub_eventbridge_log_policy_name  = "tlz-l4test-securityhub-eventbridge-log-policy"
    securityhub_custom_rules_log_policy_name = "tlz-l4test-securityhub-custom-rules-to-cw"
  }

  assert {
    condition     = aws_sns_topic.alerts[0].name == "tlz-l4test-landing-zone-alerts"
    error_message = "alerts_topic_name must reach the single-topic alerts topic."
  }

  assert {
    condition     = aws_kms_alias.sns[0].name == "alias/tlz-l4test-sns-encryption"
    error_message = "sns_kms_alias_name must reach the SNS key alias."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.guardduty_findings[0].name == "tlz-l4test-guardduty-findings-alert"
    error_message = "guardduty_findings_rule_name must reach the single-topic GuardDuty rule."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.securityhub_findings[0].name == "tlz-l4test-securityhub-findings-to-cw"
    error_message = "securityhub_findings_rule_name must reach the Security Hub forwarding rule."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.log_group_onboarding[0].name == "tlz-l4test-log-group-onboarding"
    error_message = "log_group_onboarding_rule_name must reach the onboarding rule."
  }

  assert {
    condition     = aws_cloudwatch_dashboard.landing_zone.dashboard_name == "tlz-l4test-landing-zone-health"
    error_message = "dashboard_name must reach the dashboard."
  }

  assert {
    condition     = aws_cloudwatch_log_resource_policy.securityhub_eventbridge[0].policy_name == "tlz-l4test-securityhub-eventbridge-log-policy"
    error_message = "securityhub_eventbridge_log_policy_name must reach the forwarding log resource policy."
  }

  assert {
    condition     = aws_cloudwatch_log_resource_policy.securityhub_custom_rules_eventbridge[0].policy_name == "tlz-l4test-securityhub-custom-rules-to-cw"
    error_message = "securityhub_custom_rules_log_policy_name must reach the custom-rules log resource policy."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.break_glass[0].alarm_name == "tlz-l4test-break-glass-usage"
    error_message = "break_glass_alarm_config.alarm_name must reach the alarm."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.break_glass[0].name == "tlz-l4test-break-glass-usage-filter"
    error_message = "break_glass_alarm_config.metric_filter_name must reach the metric filter."
  }

  # The rule's target and the Lambda permission follow the renamed rule — a
  # renamed rule with a target still pointing at the old name would be an
  # orphan at apply.
  assert {
    condition     = aws_cloudwatch_event_target.log_group_onboarding[0].rule == "tlz-l4test-log-group-onboarding"
    error_message = "The onboarding target must follow the overridden rule name."
  }

  # The DLQ name reaches the queue, and the Lambda's sqs:SendMessage grant
  # follows it — a policy still naming the literal would leave a renamed
  # queue unreachable for dead-lettering, the silent drop the DLQ exists to
  # prevent. (dead_letter_config.target_arn is the queue's ARN, unknown at
  # plan; the live apply-test pins that half.)
  assert {
    condition     = aws_sqs_queue.log_group_onboarding_dlq[0].name == "tlz-l4test-log-group-onboarding-dlq"
    error_message = "log_group_onboarding_dlq_name must reach the onboarding dead-letter queue."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.log_group_onboarding[0].policy, ":sqs:*:*:tlz-l4test-log-group-onboarding-dlq\"") && !strcontains(aws_iam_role_policy.log_group_onboarding[0].policy, "tlz-log-group-onboarding-dlq")
    error_message = "The Lambda policy's sqs:SendMessage grant must follow log_group_onboarding_dlq_name and stop naming the default literal."
  }
}

# Rejection: the DLQ name is not a guardrail class (no organization SCP names
# an SQS ARN), so it carries only the SQS naming rule — 1-80 characters of
# letters, digits, underscore or hyphen.
run "log_group_onboarding_dlq_name_breaking_the_sqs_rule_rejected" {
  command = plan

  variables {
    enable_log_group_onboarding   = true
    log_group_onboarding_dlq_name = "tlz-log-group-onboarding.dlq"
  }

  expect_failures = [var.log_group_onboarding_dlq_name]
}

# Reach: the forwarder DLQ name lands on the queue AND on the sqs:SendMessage
# grant of the forwarder policy (plan-time-known by static name). The default
# is pinned by monitoring_sns_forwarder_dlq_defaults above.
run "sns_forwarder_dlq_name_reaches_queue_and_grant" {
  command = plan

  variables {
    enable_sns_forwarder   = true
    sns_forwarder_dlq_name = "tlz-l4test-sns-forwarder-dlq"
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
    }
  }

  assert {
    condition     = aws_sqs_queue.sns_forwarder_dlq[0].name == "tlz-l4test-sns-forwarder-dlq"
    error_message = "sns_forwarder_dlq_name must reach the forwarder DLQ."
  }

  assert {
    condition     = strcontains(jsonencode(local.sns_forwarder_policy), ":sqs:eu-central-1:111111111111:tlz-l4test-sns-forwarder-dlq\"") && !strcontains(jsonencode(local.sns_forwarder_policy), "tlz-sns-forwarder-dlq")
    error_message = "The forwarder policy's DLQ grant must follow the overridden queue name and drop the default name."
  }
}

# The forwarder role's sqs:SendMessage grant on the module-managed DLQ must
# name the one queue this module creates, not arn:aws:sqs:*:*:<name> (any
# region, any account). The grant must name exactly the mocked account
# (111111111111) and region (eu-central-1).
run "d09_sns_forwarder_dlq_grant_names_this_account_and_region" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
    }
  }

  assert {
    condition = one([
      for s in jsondecode(aws_iam_role_policy.sns_forwarder[0].policy).Statement : s.Resource
      if try(s.Sid, "") == "DeadLetterQueueAccess"
    ]) == "arn:aws:sqs:eu-central-1:111111111111:tlz-sns-forwarder-dlq"
    error_message = "The forwarder DLQ grant must name this account and region (arn:aws:sqs:eu-central-1:111111111111:tlz-sns-forwarder-dlq), never a wildcard."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.sns_forwarder[0].policy, ":sqs:*:")
    error_message = "The forwarder policy must not carry a wildcarded SQS region or account."
  }
}

# The other half: a caller-provided dlq_arn reaches the grant unchanged — the
# scoping applies only to the module-managed queue.
run "d09_sns_forwarder_external_dlq_grant_unchanged" {
  command = plan

  variables {
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
      dlq_arn           = "arn:aws:sqs:eu-west-1:210987654321:existing-dlq"
    }
  }

  assert {
    condition = one([
      for s in jsondecode(aws_iam_role_policy.sns_forwarder[0].policy).Statement : s.Resource
      if try(s.Sid, "") == "DeadLetterQueueAccess"
    ]) == "arn:aws:sqs:eu-west-1:210987654321:existing-dlq"
    error_message = "A caller-provided dlq_arn must reach the forwarder DLQ grant unchanged."
  }
}

run "sns_forwarder_dlq_name_breaking_the_sqs_rule_rejected" {
  command = plan

  variables {
    enable_sns_forwarder   = true
    sns_forwarder_dlq_name = "tlz-sns-forwarder.dlq"
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
    }
  }

  expect_failures = [var.sns_forwarder_dlq_name]
}

# Rejection: the five names are guardrail classes — the organization SCPs
# protect only tlz-* topics and rules — so a name outside the namespace is
# refused before the plan can create an unprotected resource.
run "alerts_topic_name_outside_namespace_rejected" {
  command = plan

  variables {
    alerts_topic_name = "landing-zone-alerts"
  }

  expect_failures = [var.alerts_topic_name]
}

run "sns_kms_alias_name_outside_namespace_rejected" {
  command = plan

  variables {
    sns_kms_encryption = true
    sns_kms_alias_name = "alias/sns-encryption"
  }

  expect_failures = [var.sns_kms_alias_name]
}

run "guardduty_findings_rule_name_invalid_rejected" {
  command = plan

  variables {
    # Inside the namespace but over the 64-character EventBridge limit.
    guardduty_findings_rule_name = "tlz-${join("", [for i in range(70) : "x"])}"
  }

  expect_failures = [var.guardduty_findings_rule_name]
}

run "securityhub_findings_rule_name_invalid_rejected" {
  command = plan

  variables {
    enable_securityhub_cloudwatch_forwarding = true
    securityhub_findings_rule_name           = "tlz-no spaces allowed"
  }

  expect_failures = [var.securityhub_findings_rule_name]
}

run "log_group_onboarding_rule_name_outside_namespace_rejected" {
  command = plan

  variables {
    enable_log_group_onboarding    = true
    log_group_onboarding_rule_name = "log-group-onboarding"
  }

  expect_failures = [var.log_group_onboarding_rule_name]
}

# The DLQ is NOT a guardrail class — no organization policy protects an SQS
# namespace (the RCPs' sqs:* statements are Resource: "*", name-independent),
# so its validation is the SQS standard-queue naming rule alone, like
# dashboard_name's. A dot is refused because a standard queue whose name ends
# in .fifo fails CreateQueue at apply, not at plan.
run "log_group_onboarding_dlq_name_invalid_rejected" {
  command = plan

  variables {
    enable_log_group_onboarding   = true
    log_group_onboarding_dlq_name = "tlz-log-group-onboarding-dlq.fifo"
  }

  expect_failures = [var.log_group_onboarding_dlq_name]
}

# -----------------------------------------------------------------------------
# Metric-filter log groups are resolved at plan time
# -----------------------------------------------------------------------------
# A filter on a group this module creates takes the name from the resource (and
# with it the ordering); every other name is read through
# data.aws_cloudwatch_log_group so a missing group fails the plan. The mock
# provider answers every read, so what is pinned here is the wiring: which
# names are read, which are not, and that both paths reach the filter. The
# negative case — a group that does not exist — is a provider error and
# cannot be shown offline; the data source's failure IS the guard.
run "metric_filter_log_groups_are_resolved_not_passed_raw" {
  command = plan

  variables {
    cloudwatch_log_groups = [
      { name = "/tlz/security/audit" },
    ]
    cloudwatch_metric_filters = [
      {
        name             = "on-external-group"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ $.userIdentity.type = \"Root\" }"
        metric_namespace = "TLZ/Security"
        metric_name      = "RootAccountUsage"
      },
      {
        name             = "on-managed-group"
        log_group_name   = "/tlz/security/audit"
        pattern          = "{ $.eventName = \"ConsoleLogin\" }"
        metric_namespace = "TLZ/Security"
        metric_name      = "ConsoleLogin"
      },
    ]
  }

  assert {
    condition     = keys(data.aws_cloudwatch_log_group.metric_filter_targets) == ["/aws/cloudtrail/tlz-org-trail"]
    error_message = "Exactly the log groups this module does not create must be read at plan time — the external CloudTrail group yes, the managed /tlz/security/audit no."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.this["on-external-group"].log_group_name == "/aws/cloudtrail/tlz-org-trail"
    error_message = "The filter on an external group must still carry that group's name (taken from the plan-time read)."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.this["on-managed-group"].log_group_name == aws_cloudwatch_log_group.this["/tlz/security/audit"].name
    error_message = "The filter on a module-managed group must reference the log group resource, not the raw string."
  }
}

run "break_glass_filter_log_group_is_read_at_plan_time" {
  command = plan

  variables {
    enable_break_glass_alarm = true
    break_glass_alarm_config = {
      alarm_actions  = ["arn:aws:sns:eu-central-1:111111111111:tlz-alerts"]
      log_group_name = "/aws/cloudtrail/tlz-custom-trail"
    }
  }

  assert {
    condition     = contains(keys(data.aws_cloudwatch_log_group.metric_filter_targets), "/aws/cloudtrail/tlz-custom-trail")
    error_message = "The break-glass filter's log group must be among the plan-time reads — a break-glass alarm on a missing group would install nothing behind a green apply."
  }

  assert {
    condition     = aws_cloudwatch_log_metric_filter.break_glass[0].log_group_name == "/aws/cloudtrail/tlz-custom-trail"
    error_message = "The configured break-glass log group must reach the filter through the resolution."
  }
}

# -----------------------------------------------------------------------------
# Alarms that watch nothing are reported
# -----------------------------------------------------------------------------
# An alarm whose custom metric no filter
# emits sits in INSUFFICIENT_DATA forever; treat_missing_data = notBreaching
# paints it green. A warning: another emitter may publish the metric.
run "alarm_without_a_metric_source_is_reported" {
  command = plan

  variables {
    cloudwatch_metric_filters = [
      {
        name             = "root-account-usage"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ $.userIdentity.type = \"Root\" }"
        metric_namespace = "TLZ/Security"
        metric_name      = "RootAccountUsage"
      },
    ]
    cloudwatch_alarms = [
      {
        name          = "root-account-usage"
        metric_name   = "RootAcountUsage" # typo: no filter emits this name
        namespace     = "TLZ/Security"
        threshold     = 1
        alarm_actions = ["arn:aws:sns:eu-central-1:111111111111:tlz-alerts"]
      },
      {
        name          = "billing"
        metric_name   = "EstimatedCharges"
        namespace     = "AWS/Billing" # an AWS namespace needs no filter
        threshold     = 100
        alarm_actions = ["arn:aws:sns:eu-central-1:111111111111:tlz-alerts"]
      },
    ]
  }

  assert {
    condition     = local.cloudwatch_alarms_without_source == ["root-account-usage (TLZ/Security/RootAcountUsage)"]
    error_message = "Exactly the custom-metric alarm without an emitting filter must be reported; the AWS/ namespace alarm must not."
  }

  expect_failures = [
    check.cloudwatch_alarms_have_a_metric_source,
  ]
}

# The matching pair — filter emits the metric, alarm has an action — raises no
# check: both guards are about the gap, not about alarms as such.
run "alarm_with_source_and_action_stays_silent" {
  command = plan

  variables {
    cloudwatch_metric_filters = [
      {
        name             = "root-account-usage"
        log_group_name   = "/aws/cloudtrail/tlz-org-trail"
        pattern          = "{ $.userIdentity.type = \"Root\" }"
        metric_namespace = "TLZ/Security"
        metric_name      = "RootAccountUsage"
      },
    ]
    cloudwatch_alarms = [
      {
        name          = "root-account-usage"
        metric_name   = "RootAccountUsage"
        namespace     = "TLZ/Security"
        threshold     = 1
        alarm_actions = ["arn:aws:sns:eu-central-1:111111111111:tlz-alerts"]
      },
    ]
  }

  assert {
    condition     = length(local.cloudwatch_alarms_without_actions) == 0 && length(local.cloudwatch_alarms_without_source) == 0
    error_message = "An alarm with an emitting filter and an action must trip neither alarm check."
  }
}

# A non-ARN action is rejected by
# PutMetricAlarm at apply; the validation moves that to the plan.
run "alarm_action_that_is_not_an_arn_rejected" {
  command = plan

  variables {
    cloudwatch_alarms = [
      {
        name          = "root-account-usage"
        metric_name   = "RootAccountUsage"
        namespace     = "TLZ/Security"
        threshold     = 1
        alarm_actions = ["tlz-alerts"]
      },
    ]
  }

  expect_failures = [
    var.cloudwatch_alarms,
  ]
}

# -----------------------------------------------------------------------------
# Alarms inherit the alerting topic (single-topic mode)
# -----------------------------------------------------------------------------
# base.tfvars ships its CIS alarms without alarm_actions because the topic ARN
# is unknown until apply and the base layer is shipped content. In single-topic
# mode the module therefore wires empty alarm_actions to its own alerting
# topic; explicit alarm_actions stay exactly as given; with severity topics
# configured no single topic exists, the value degrades to [] and the
# notify-nobody check reports it. The topic ARN is unknown in a plan — the
# override pins it so the wired action is observable.

run "alarm_without_actions_inherits_the_alerting_topic" {
  command = plan

  override_resource {
    target          = aws_sns_topic.alerts
    override_during = plan
    values = {
      arn = "arn:aws:sns:eu-central-1:111111111111:tlz-landing-zone-alerts"
    }
  }

  variables {
    cloudwatch_alarms = [
      {
        name        = "root-account-usage"
        metric_name = "RootAccountUsage"
        namespace   = "AWS/CloudTrailMetrics"
        threshold   = 1
      },
      {
        name          = "unauthorized-api-calls"
        metric_name   = "UnauthorizedApiCalls"
        namespace     = "AWS/CloudTrailMetrics"
        threshold     = 5
        alarm_actions = ["arn:aws:sns:eu-central-1:111111111111:tlz-soc-escalation"]
      },
    ]
  }

  # No expect_failures: the inherited action satisfies the notify-nobody check.

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.this["root-account-usage"].alarm_actions) == 1 &&
      contains(aws_cloudwatch_metric_alarm.this["root-account-usage"].alarm_actions, "arn:aws:sns:eu-central-1:111111111111:tlz-landing-zone-alerts")
    )
    error_message = "An alarm without alarm_actions must inherit the module's alerting topic ARN in single-topic mode."
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.this["unauthorized-api-calls"].alarm_actions) == 1 &&
      contains(aws_cloudwatch_metric_alarm.this["unauthorized-api-calls"].alarm_actions, "arn:aws:sns:eu-central-1:111111111111:tlz-soc-escalation")
    )
    error_message = "Explicit alarm_actions must be used exactly as given — the inheritance only fills empty lists."
  }

  assert {
    condition     = !contains(aws_cloudwatch_metric_alarm.this["unauthorized-api-calls"].alarm_actions, "arn:aws:sns:eu-central-1:111111111111:tlz-landing-zone-alerts")
    error_message = "The alerting topic must not be appended to explicit alarm_actions."
  }
}

run "alarm_without_actions_stays_empty_with_severity_topics" {
  command = plan

  variables {
    sns_topics = [
      { severity = "HIGH", email_targets = ["security@example.com"] },
    ]

    cloudwatch_alarms = [
      {
        name        = "root-account-usage"
        metric_name = "RootAccountUsage"
        namespace   = "AWS/CloudTrailMetrics"
        threshold   = 1
      },
    ]
  }

  # With severity topics there is no single alerting topic to inherit: the
  # alarm keeps empty actions and the notify-nobody check must still report it.
  expect_failures = [
    check.cloudwatch_alarms_notify_nobody,
  ]

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.this["root-account-usage"].alarm_actions) == 0
    error_message = "Without a single alerting topic an empty alarm_actions must stay empty — the module cannot pick a severity."
  }
}

# -----------------------------------------------------------------------------
# lambda_environment_kms_key_arn — reaches BOTH Lambda functions' environment,
# grants each exactly kms:Decrypt on exactly that key, and stays inert when empty
# -----------------------------------------------------------------------------

# Empty case: a deployment that does not set the variable keeps its plan — no
# extra policy resource for either function, kms_key_arn left null (not the
# empty string, which the provider would reject) on both.
run "monitoring_lambda_env_kms_empty_leaves_plan_unchanged" {
  command = plan

  variables {
    organization_id             = "o-abcd1234567"
    enable_log_group_onboarding = true
    log_group_onboarding = {
      retention_in_days           = 90
      kms_key_arn                 = ""
      destination_arn             = ""
      subscription_role_arn       = ""
      excluded_log_group_patterns = []
    }
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
    }
    lambda_environment_kms_key_arn = ""
  }

  assert {
    condition     = length(aws_iam_role_policy.log_group_onboarding_env_kms) == 0 && length(aws_iam_role_policy.sns_forwarder_env_kms) == 0
    error_message = "An empty lambda_environment_kms_key_arn must create no extra IAM policy resource for either function."
  }

  assert {
    condition     = aws_lambda_function.log_group_onboarding[0].kms_key_arn == null
    error_message = "An empty lambda_environment_kms_key_arn must leave kms_key_arn null on the onboarding Lambda, keeping the AWS-managed key — not the empty string, which the provider rejects."
  }

  assert {
    condition     = aws_lambda_function.sns_forwarder[0].kms_key_arn == null
    error_message = "An empty lambda_environment_kms_key_arn must leave kms_key_arn null on the forwarder Lambda, keeping the AWS-managed key — not the empty string, which the provider rejects."
  }
}

# Named case: the key reaches both functions' environment encryption AND both
# execution roles are granted exactly kms:Decrypt on exactly that key's ARN —
# one grant per function, never a shared or wider one.
run "monitoring_lambda_env_kms_named_reaches_both_functions_and_grants_decrypt_only" {
  command = plan

  variables {
    organization_id             = "o-abcd1234567"
    enable_log_group_onboarding = true
    log_group_onboarding = {
      retention_in_days           = 90
      kms_key_arn                 = ""
      destination_arn             = ""
      subscription_role_arn       = ""
      excluded_log_group_patterns = []
    }
    enable_sns_forwarder = true
    sns_forwarder_config = {
      central_topic_arn = "arn:aws:sns:eu-central-1:210987654321:tlz-central-alerts"
    }
    lambda_environment_kms_key_arn = "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
  }

  assert {
    condition     = aws_lambda_function.log_group_onboarding[0].kms_key_arn == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
    error_message = "A named lambda_environment_kms_key_arn must reach the onboarding Lambda's kms_key_arn."
  }

  assert {
    condition     = aws_lambda_function.sns_forwarder[0].kms_key_arn == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
    error_message = "A named lambda_environment_kms_key_arn must reach the forwarder Lambda's kms_key_arn."
  }

  assert {
    condition     = length(aws_iam_role_policy.log_group_onboarding_env_kms) == 1 && length(aws_iam_role_policy.sns_forwarder_env_kms) == 1
    error_message = "A named lambda_environment_kms_key_arn must create exactly one env-kms grant per function."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.log_group_onboarding_env_kms[0].policy).Statement[0].Action == "kms:Decrypt" &&
      jsondecode(aws_iam_role_policy.log_group_onboarding_env_kms[0].policy).Statement[0].Resource == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb" &&
      jsondecode(aws_iam_role_policy.log_group_onboarding_env_kms[0].policy).Statement[0].Effect == "Allow"
    )
    error_message = "The onboarding function's grant must allow ONLY kms:Decrypt, and only on the named key's exact ARN."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.sns_forwarder_env_kms[0].policy).Statement[0].Action == "kms:Decrypt" &&
      jsondecode(aws_iam_role_policy.sns_forwarder_env_kms[0].policy).Statement[0].Resource == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb" &&
      jsondecode(aws_iam_role_policy.sns_forwarder_env_kms[0].policy).Statement[0].Effect == "Allow"
    )
    error_message = "The forwarder function's grant must allow ONLY kms:Decrypt, and only on the named key's exact ARN."
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role_policy.log_group_onboarding_env_kms[0].policy).Statement) == 1 &&
      length(jsondecode(aws_iam_role_policy.sns_forwarder_env_kms[0].policy).Statement) == 1
    )
    error_message = "Each grant must carry exactly one statement."
  }
}
