# Monitoring in the Audit account — alerting on the findings of the whole
# organization.
#
# The Audit account is the delegated administrator of GuardDuty and Security
# Hub, so its EventBridge bus carries every member account's findings; the
# management account's bus carries only its own. This unit runs
# modules/monitoring through the cross-account provider with the alerting part
# only: the GuardDuty → SNS rules, the Security Hub → CloudWatch forwarding,
# the custom Security Hub rules, the SNS topics with their key, the configured
# log groups and the findings dashboard. Metric filters, alarms, the
# break-glass alarm, the log group onboarding and the SNS forwarder stay in
# stacks/management/monitoring, which keeps its own GuardDuty and Security Hub
# rules for the management account's findings.
#
# Runs while security_finding_consumers_in_audit (env/common.hcl, default true)
# is on, after stacks/audit/security-org-config — the unit that makes this
# account the administrator whose bus sees the members.

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Cross-account access parameters, shared with stacks/root.hcl. The unit
  # declares no `generate "provider"` block of its own — two blocks of the
  # same name abort the configuration load for every command. The
  # account resolution sits in cross_account.hcl so that root.hcl and this file
  # read the same value.
  cross_account = read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl")
  account_id    = local.cross_account.locals.account_id

  # Same expression as in stacks/audit/security-org-config and, negated, in
  # stacks/management/security.
  consumers_in_audit = try(local.common.locals.security_finding_consumers_in_audit, true) && local.account_id != ""
}

# Skipped without an Audit account, while monitoring or security is switched
# off (audit/security-org-config then has no outputs to read), and while the
# finding consumers stay in the management account.
exclude {
  if      = local.account_id == "" || !local.common.locals.enable_monitoring || !local.common.locals.enable_security || !local.consumers_in_audit
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/monitoring"
}

dependency "security_org_config" {
  config_path = "../security-org-config"

  mock_outputs = {
    guardduty_detector_id = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  guardduty_detector_id = dependency.security_org_config.outputs.guardduty_detector_id

  # Alerting targets of this account. Absent in env/common.hcl, the management
  # lists apply — every address then confirms two subscriptions, one per
  # account.
  sns_email_targets  = try(local.common.locals.audit_sns_email_targets, local.common.locals.sns_email_targets)
  sns_lambda_targets = local.common.locals.sns_lambda_targets
  alert_on_severity  = local.common.locals.alert_on_severity
  sns_topics         = try(local.common.locals.audit_sns_topics, local.compliance.locals.sns_topics)
  sns_kms_encryption = local.compliance.locals.sns_kms_encryption

  # Security Hub → CloudWatch forwarding and the custom Security Hub rules, with
  # the same configuration the management unit reads. A rule target that names
  # the __CW_LOG_GROUP_ARN__ placeholder needs its log group in this unit.
  enable_securityhub_cloudwatch_forwarding = local.compliance.locals.enable_securityhub_cloudwatch_forwarding
  securityhub_severity_filter              = local.compliance.locals.securityhub_severity_filter
  securityhub_findings_log_group_name      = try(local.common.locals.securityhub_findings_log_group_name, "/aws/events/securityhub-findings")
  securityhub_findings_log_retention       = try(local.common.locals.securityhub_findings_log_retention, 365)
  securityhub_findings_log_kms_key_id      = try(local.common.locals.securityhub_findings_log_kms_key_id, null)
  securityhub_eventbridge_rules            = try(local.common.locals.securityhub_eventbridge_rules, [])
  cloudwatch_log_groups                    = try(local.common.locals.cloudwatch_log_groups, [])
  lambda_environment_kms_key_arn           = local.compliance.locals.monitoring_lambda_environment_kms_key_arn

  # Not in this account: the organization's trail, aggregator and central
  # bucket live in the management account, and metric filters, alarms, the
  # break-glass alarm, the log group onboarding and the SNS forwarder stay in
  # stacks/management/monitoring. The dashboard carries the findings widgets
  # under its own name — PutDashboard is an upsert, and the management name
  # belongs to the management account.
  organization_id                = ""
  eventbridge_default_bus_policy = ""
  config_aggregator_name         = ""
  cloudtrail_arn                 = ""
  central_log_bucket_name        = ""
  cloudwatch_metric_filters      = []
  cloudwatch_alarms              = []
  enable_log_group_onboarding    = false
  enable_sns_forwarder           = false
  enable_break_glass_alarm       = false
  dashboard_name                 = "TLZ-Audit-Findings"
}
