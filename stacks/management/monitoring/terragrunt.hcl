# Monitoring — CloudWatch Dashboards, SNS Alerting

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

exclude {
  if      = !local.common.locals.enable_monitoring
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/monitoring"
}

dependency "organization" {
  config_path = "../organization"

  mock_outputs = {
    organization_id = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "logging" {
  config_path = "../logging"

  mock_outputs = {
    cloudtrail_arn          = ""
    config_aggregator_name  = ""
    central_log_bucket_name = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "security" {
  config_path = "../security"

  mock_outputs = {
    guardduty_detector_id = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  organization_id        = dependency.organization.outputs.organization_id
  guardduty_detector_id  = dependency.security.outputs.guardduty_detector_id
  config_aggregator_name = dependency.logging.outputs.config_aggregator_name
  cloudtrail_arn         = dependency.logging.outputs.cloudtrail_arn
  sns_email_targets      = local.common.locals.sns_email_targets
  sns_lambda_targets     = local.common.locals.sns_lambda_targets
  alert_on_severity      = local.common.locals.alert_on_severity

  eventbridge_default_bus_policy = try(local.common.locals.eventbridge_default_bus_policy, "")
  central_log_bucket_name        = dependency.logging.outputs.central_log_bucket_name
  cloudwatch_log_groups          = try(local.common.locals.cloudwatch_log_groups, [])
  securityhub_eventbridge_rules  = try(local.common.locals.securityhub_eventbridge_rules, [])

  # SNS KMS encryption for monitoring topics
  sns_kms_encryption = local.compliance.locals.sns_kms_encryption

  # Customer-managed key for the environment variables of the onboarding and
  # SNS-forwarder Lambdas. Empty (the loader default) keeps the AWS-managed key.
  lambda_environment_kms_key_arn = local.compliance.locals.monitoring_lambda_environment_kms_key_arn

  # SecurityHub → CloudWatch Forwarding — loader merge (base + common + frameworks)
  enable_securityhub_cloudwatch_forwarding = local.compliance.locals.enable_securityhub_cloudwatch_forwarding
  securityhub_severity_filter              = local.compliance.locals.securityhub_severity_filter
  securityhub_findings_log_group_name      = try(local.common.locals.securityhub_findings_log_group_name, "/aws/events/securityhub-findings")
  securityhub_findings_log_retention       = try(local.common.locals.securityhub_findings_log_retention, 365)
  securityhub_findings_log_kms_key_id      = try(local.common.locals.securityhub_findings_log_kms_key_id, null)

  # SNS Cross-Account Forwarder Lambda
  enable_sns_forwarder = try(local.common.locals.enable_sns_forwarder, false)
  sns_forwarder_config = try(local.common.locals.sns_forwarder_config, { central_topic_arn = "" })

  # Onboarding of newly created CloudWatch log groups: EventBridge rule plus
  # Lambda applying retention, key and forwarding defaults. Off by default;
  # {} keeps the module defaults of the automation.
  enable_log_group_onboarding = try(local.common.locals.enable_log_group_onboarding, false)
  log_group_onboarding        = try(local.common.locals.log_group_onboarding, {})

  # The three collections the module does its actual work from: without them no
  # deployment produces a metric filter or an alarm. All three are
  # merged with concat() in the loader, so a compliance framework contributes to
  # the baseline instead of replacing it.
  sns_topics                = local.compliance.locals.sns_topics
  cloudwatch_metric_filters = local.compliance.locals.cloudwatch_metric_filters
  cloudwatch_alarms         = local.compliance.locals.cloudwatch_alarms
  # Break-glass usage alarm: metric filter on the CloudTrail log group plus
  # alarm with a mandatory target. The users live in the iam stack
  # (enable_break_glass). Off by default; null keeps the module default.
  enable_break_glass_alarm = try(local.common.locals.enable_break_glass_alarm, false)
  break_glass_alarm_config = try(local.common.locals.break_glass_alarm_config, null)
}
