# Monitoring module: CloudWatch Dashboard, SNS Alerting, EventBridge Rules

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  dns_suffix = data.aws_partition.current.dns_suffix
  arn_prefix = "arn:${local.partition}"
  region     = data.aws_region.current.region
  account_id = data.aws_caller_identity.current.account_id

  # Whether severity-based topics are configured
  use_severity_topics = length(var.sns_topics) > 0

  # Severity mapping for EventBridge filters (numeric thresholds)
  severity_map = {
    LOW      = 1
    MEDIUM   = 4
    HIGH     = 7
    CRITICAL = 9
  }
  severity_threshold = local.severity_map[var.alert_on_severity]

  # Severity ranges for EventBridge pattern matching
  # LOW: 1-3.9, MEDIUM: 4-6.9, HIGH: 7-8.9, CRITICAL: 9-10
  severity_ranges = {
    LOW      = { lower = 1, upper = 3.9 }
    MEDIUM   = { lower = 4, upper = 6.9 }
    HIGH     = { lower = 7, upper = 8.9 }
    CRITICAL = { lower = 9, upper = 10 }
  }

  # Email subscriptions as map (fallback single-topic)
  email_subscriptions = {
    for idx, email in var.sns_email_targets : "email-${idx}" => email
  }

  # Lambda subscriptions as map (fallback single-topic)
  lambda_subscriptions = {
    for idx, arn in var.sns_lambda_targets : "lambda-${idx}" => arn
  }

  # Severity topics as map keyed by severity
  severity_topics = {
    for t in var.sns_topics : t.severity => t
  }

  # Flatten severity email subscriptions
  severity_email_subs = flatten([
    for t in var.sns_topics : [
      for idx, email in t.email_targets : {
        key      = "${t.severity}-email-${idx}"
        severity = t.severity
        endpoint = email
      }
    ]
  ])

  # Flatten severity lambda subscriptions
  severity_lambda_subs = flatten([
    for t in var.sns_topics : [
      for idx, arn in t.lambda_targets : {
        key      = "${t.severity}-lambda-${idx}"
        severity = t.severity
        endpoint = arn
      }
    ]
  ])

  # --- Landing Zone Health dashboard ---
  #
  # Every widget of the dashboard is built here instead of inline in the
  # resource, because the diagnostic half of the dashboard is switchable
  # (var.enable_diagnostics_dashboard) and the identifiers of the observed
  # services arrive as module inputs.

  # Trail name of var.cloudtrail_arn
  # (arn:<partition>:cloudtrail:<region>:<account>:trail/<name>). Empty when no
  # ARN is injected — the widget then shows the account-wide event volume.
  cloudtrail_trail_name = (
    var.cloudtrail_arn != ""
    ? element(reverse(split("/", var.cloudtrail_arn)), 0)
    : ""
  )

  # AWS/GuardDuty FindingsCount, dimensioned by detector as soon as the ID is
  # known. Without the dimension the metric aggregates every detector of the
  # account, which is the pre-injection behaviour.
  guardduty_findings_metric = concat(
    ["AWS/GuardDuty", "FindingsCount"],
    var.guardduty_detector_id != "" ? ["DetectorId", var.guardduty_detector_id] : [],
    [{ stat = "Sum", period = 86400 }],
  )

  # The identifiers of the Config aggregator and of the org trail are no
  # CloudWatch dimensions — neither AWS/Config nor AWS/CloudTrail offers one.
  # They name the source of the displayed figures in the widget title, so that
  # the operator can see which aggregator and which trail the dashboard reports
  # on.
  config_compliance_widget_title = (
    var.config_aggregator_name != ""
    ? "Config Compliance (aggregator ${var.config_aggregator_name})"
    : "Config Compliance"
  )

  config_diagnostics_widget_title = (
    var.config_aggregator_name != ""
    ? "Config Non-Compliant Rules (aggregator ${var.config_aggregator_name})"
    : "Config Non-Compliant Rules"
  )

  cloudtrail_events_widget_title = (
    local.cloudtrail_trail_name != ""
    ? "CloudTrail Events (trail ${local.cloudtrail_trail_name})"
    : "CloudTrail Events"
  )

  cloudtrail_diagnostics_widget_title = (
    local.cloudtrail_trail_name != ""
    ? "CloudTrail Management Events per day (trail ${local.cloudtrail_trail_name})"
    : "CloudTrail Management Events (per day)"
  )

  # Base widgets — always part of the dashboard.
  dashboard_base_widgets = [
    {
      type   = "text"
      x      = 0
      y      = 0
      width  = 24
      height = 1
      properties = {
        markdown = "# Landing Zone Health Dashboard"
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 1
      width  = 12
      height = 6
      properties = {
        title   = "GuardDuty Findings"
        region  = local.region
        metrics = [local.guardduty_findings_metric]
        view    = "timeSeries"
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 1
      width  = 12
      height = 6
      properties = {
        title  = local.cloudtrail_events_widget_title
        region = local.region
        metrics = [
          ["AWS/CloudTrail", "EventCount", { stat = "Sum", period = 86400 }],
        ]
        view = "timeSeries"
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 7
      width  = 24
      height = 6
      properties = {
        title  = local.config_compliance_widget_title
        region = local.region
        metrics = [
          ["AWS/Config", "ComplianceByConfigRule", "ComplianceType", "COMPLIANT", { stat = "Sum", period = 86400 }],
          ["AWS/Config", "ComplianceByConfigRule", "ComplianceType", "NON_COMPLIANT", { stat = "Sum", period = 86400 }],
        ]
        view = "timeSeries"
      }
    },
  ]

  # Diagnostic widgets — switchable via var.enable_diagnostics_dashboard.
  # The S3 storage widget requires a bucket name; without it the widget would
  # carry an empty BucketName dimension and stay blank, so it is omitted.
  dashboard_storage_widgets = var.central_log_bucket_name != "" ? [
    {
      type   = "metric"
      x      = 12
      y      = 19
      width  = 12
      height = 6
      properties = {
        title  = "Central Log Bucket Storage (${var.central_log_bucket_name})"
        region = local.region
        metrics = [
          ["AWS/S3", "BucketSizeBytes", "BucketName", var.central_log_bucket_name, "StorageType", "StandardStorage", { stat = "Average", period = 86400 }],
          ["AWS/S3", "NumberOfObjects", "BucketName", var.central_log_bucket_name, "StorageType", "AllStorageTypes", { stat = "Average", period = 86400 }],
        ]
        view = "timeSeries"
      }
    },
  ] : []

  # The five subject areas of the toggle description: Config compliance,
  # Security Hub findings, GuardDuty trend, CloudTrail volume, S3 storage.
  dashboard_diagnostic_widgets = concat(
    [
      {
        type   = "metric"
        x      = 0
        y      = 13
        width  = 8
        height = 6
        properties = {
          title  = local.config_diagnostics_widget_title
          region = local.region
          metrics = [
            ["AWS/Config", "ComplianceByConfigRule", "ComplianceType", "NON_COMPLIANT", { stat = "Sum", period = 86400 }],
          ]
          view = "singleValue"
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 13
        width  = 8
        height = 6
        properties = {
          title  = "Security Hub Findings by Severity"
          region = local.region
          metrics = [
            ["AWS/SecurityHub", "FindingsCount", "SeverityLabel", "CRITICAL", { stat = "Sum", period = 86400 }],
            ["AWS/SecurityHub", "FindingsCount", "SeverityLabel", "HIGH", { stat = "Sum", period = 86400 }],
            ["AWS/SecurityHub", "FindingsCount", "SeverityLabel", "MEDIUM", { stat = "Sum", period = 86400 }],
            ["AWS/SecurityHub", "FindingsCount", "SeverityLabel", "LOW", { stat = "Sum", period = 86400 }],
          ]
          view = "bar"
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 13
        width  = 8
        height = 6
        properties = {
          title   = "GuardDuty Findings Trend (7 days)"
          region  = local.region
          metrics = [local.guardduty_findings_metric]
          view    = "timeSeries"
          period  = 604800
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 19
        width  = 12
        height = 6
        properties = {
          title  = local.cloudtrail_diagnostics_widget_title
          region = local.region
          metrics = [
            ["AWS/CloudTrail", "EventCount", { stat = "Sum", period = 86400 }],
          ]
          view = "timeSeries"
        }
      },
    ],
    local.dashboard_storage_widgets,
  )

  # The for-expression with an if clause is deliberate: a conditional
  # (`var.x ? local.diagnostics : []`) would force the heterogeneous widget
  # objects into one common type and abort the plan.
  dashboard_widgets = concat(
    local.dashboard_base_widgets,
    [for widget in local.dashboard_diagnostic_widgets : widget if var.enable_diagnostics_dashboard],
  )

  # SNS forwarder policy object (externalized concat wrapper)
  sns_forwarder_policy = {
    Version = "2012-10-17"
    Statement = concat(
      jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/sns-forwarder-policy.json", {
        central_topic_arn = var.sns_forwarder_config.central_topic_arn
        arn_prefix        = local.arn_prefix
        region            = local.region
        account_id        = local.account_id
        # Caller-provided queue, or the module-managed one by its static name in
        # this account and region — exactly the ARN aws_sqs_queue.sns_forwarder_dlq
        # gets, but plan-time-known instead of depending on a computed ARN. Never
        # wildcard region or account: that would grant SendMessage on a
        # same-named queue anywhere.
        dlq_arn = var.sns_forwarder_config.dlq_arn != null ? var.sns_forwarder_config.dlq_arn : "${local.arn_prefix}:sqs:${local.region}:${local.account_id}:${var.sns_forwarder_dlq_name}"
      })).Statement,
      var.sns_forwarder_config.kms_key_arn != null ? [
        jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/sns-forwarder-kms-statement.json", {
          kms_key_arn = var.sns_forwarder_config.kms_key_arn
        })),
      ] : []
    )
  }
}

# --- Dedicated SNS KMS Key (when sns_kms_encryption is enabled) ---

resource "aws_kms_key" "sns" {
  count = var.sns_kms_encryption ? 1 : 0

  description             = "KMS key for SNS topic encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/sns-kms-key-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "sns" {
  count = var.sns_kms_encryption ? 1 : 0

  name          = var.sns_kms_alias_name
  target_key_id = aws_kms_key.sns[0].key_id
}

# --- SNS Topic for central alerting (fallback single-topic) ---

resource "aws_sns_topic" "alerts" {
  count             = local.use_severity_topics ? 0 : 1
  name              = var.alerts_topic_name
  kms_master_key_id = var.sns_kms_encryption ? aws_kms_key.sns[0].arn : null
}

# SNS Topic Policy: allows EventBridge delivery (fallback). aws:SourceAccount
# uses StringEqualsIfExists: EventBridge is not documented to transmit the key
# on sns:Publish, so a hard StringEquals could silently reject every delivery;
# IfExists enforces the account pin whenever the key is present and never
# blocks delivery when it is absent.
resource "aws_sns_topic_policy" "alerts" {
  count = local.use_severity_topics ? 0 : 1
  arn   = aws_sns_topic.alerts[0].arn

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/sns-topic-policy.json", {
    dns_suffix    = local.dns_suffix
    sns_topic_arn = aws_sns_topic.alerts[0].arn
    account_id    = local.account_id
  })))
}

# --- SNS Subscriptions: Email (fallback) ---

resource "aws_sns_topic_subscription" "email" {
  for_each = local.use_severity_topics ? {} : local.email_subscriptions

  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# --- SNS Subscriptions: Lambda (fallback) ---

resource "aws_sns_topic_subscription" "lambda" {
  for_each = local.use_severity_topics ? {} : local.lambda_subscriptions

  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "lambda"
  endpoint  = each.value
}

# --- Per-Severity SNS Topics ---

resource "aws_sns_topic" "severity" {
  for_each = local.severity_topics
  # A configured name wins; unset keeps the derived name.
  name              = coalesce(each.value.name, "tlz-alerts-${lower(each.key)}")
  kms_master_key_id = var.sns_kms_encryption ? aws_kms_key.sns[0].arn : null
}

resource "aws_sns_topic_policy" "severity" {
  for_each = local.severity_topics
  arn      = aws_sns_topic.severity[each.key].arn

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/sns-topic-policy.json", {
    dns_suffix    = local.dns_suffix
    sns_topic_arn = aws_sns_topic.severity[each.key].arn
    account_id    = local.account_id
  })))
}

# --- Per-Severity SNS Subscriptions: Email ---

resource "aws_sns_topic_subscription" "severity_email" {
  for_each = { for s in local.severity_email_subs : s.key => s }

  topic_arn = aws_sns_topic.severity[each.value.severity].arn
  protocol  = "email"
  endpoint  = each.value.endpoint
}

# --- Per-Severity SNS Subscriptions: Lambda ---

resource "aws_sns_topic_subscription" "severity_lambda" {
  for_each = { for s in local.severity_lambda_subs : s.key => s }

  topic_arn = aws_sns_topic.severity[each.value.severity].arn
  protocol  = "lambda"
  endpoint  = each.value.endpoint
}

# --- CloudWatch Dashboard ---

resource "aws_cloudwatch_dashboard" "landing_zone" {
  dashboard_name = var.dashboard_name

  # Widgets are assembled in locals: the diagnostic half is switchable and the
  # identifiers of the observed services arrive as module inputs.
  dashboard_body = jsonencode({
    widgets = local.dashboard_widgets
  })
}

# --- EventBridge Rule: GuardDuty Findings → SNS (fallback single-topic) ---

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count       = local.use_severity_topics ? 0 : 1
  name        = var.guardduty_findings_rule_name
  description = "Routes GuardDuty findings at severity ${var.alert_on_severity} and above to SNS"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", local.severity_threshold] }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  count     = local.use_severity_topics ? 0 : 1
  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "guardduty-sns-target"
  arn       = aws_sns_topic.alerts[0].arn
}

# --- EventBridge Rules: Per-Severity GuardDuty Routing ---

resource "aws_cloudwatch_event_rule" "guardduty_severity" {
  for_each = local.severity_topics
  # A configured rule_name wins; unset keeps the derived name. PutRule is an upsert, so a live apply-test sets a
  # tlz-l4test- rule_name rather than adopting a live per-severity rule.
  name        = coalesce(each.value.rule_name, "tlz-guardduty-${lower(each.key)}-findings")
  description = "Routes GuardDuty findings with ${each.key} severity to the ${each.key} SNS topic"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", local.severity_ranges[each.key].lower, "<=", local.severity_ranges[each.key].upper] }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_severity_to_sns" {
  for_each  = local.severity_topics
  rule      = aws_cloudwatch_event_rule.guardduty_severity[each.key].name
  target_id = "guardduty-${lower(each.key)}-sns-target"
  arn       = aws_sns_topic.severity[each.key].arn
}

# --- EventBridge Default Bus Policy ---
# Constructed dynamically to avoid hardcoded ARNs and partition issues.
# When eventbridge_default_bus_policy is a non-empty string (sentinel),
# the policy is built using the current partition, region, and account.

resource "aws_cloudwatch_event_bus_policy" "default" {
  count = var.eventbridge_default_bus_policy != null && var.eventbridge_default_bus_policy != "" ? 1 : 0

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/eventbridge-default-bus-policy.json", {
    arn_prefix      = local.arn_prefix
    region          = local.region
    account_id      = local.account_id
    organization_id = var.organization_id
  })))
  event_bus_name = "default"
}

# --- CloudWatch Metric Filters / Alarms deployment_targets checks ---

locals {
  cw_filters_with_targets = [
    for f in var.cloudwatch_metric_filters : f.name
    if length(f.deployment_targets) > 0
  ]

  cw_alarms_with_targets = [
    for a in var.cloudwatch_alarms : a.name
    if length(a.deployment_targets) > 0
  ]

  sns_topics_with_targets = [
    for t in var.sns_topics : t.severity
    if length(t.deployment_targets) > 0
  ]
}

check "cloudwatch_metric_filters_deployment_targets_warning" {
  assert {
    condition     = length(local.cw_filters_with_targets) == 0
    error_message = "cloudwatch_metric_filters with deployment_targets detected [${join(", ", local.cw_filters_with_targets)}]. Terraform cannot dynamically create providers for cross-account metric filter deployment. Filters will only be created in the Management Account."
  }
}

check "cloudwatch_alarms_deployment_targets_warning" {
  assert {
    condition     = length(local.cw_alarms_with_targets) == 0
    error_message = "cloudwatch_alarms with deployment_targets detected [${join(", ", local.cw_alarms_with_targets)}]. Terraform cannot dynamically create providers for cross-account alarm deployment. Alarms will only be created in the Management Account."
  }
}

check "sns_topics_deployment_targets_warning" {
  assert {
    condition     = length(local.sns_topics_with_targets) == 0
    error_message = "sns_topics with deployment_targets detected [${join(", ", local.sns_topics_with_targets)}]. deployment_targets is accepted for configuration compatibility, but Terraform cannot dynamically create cross-account providers. Use Terragrunt per-account stacks for cross-account deployment."
  }
}

# --- CloudWatch Log Metric Filters ---

# Log-group names referenced by metric filters, resolved at plan time.
# PutMetricFilter rejects a log group that does not exist, and a raw name
# reaches AWS unverified — a filter that names a CloudTrail log group nothing
# has created would only fail at apply, one apply per stale name. Two cases:
#   - a name this module creates itself (cloudwatch_log_groups, the Security Hub
#     findings group) is taken from the resource, which also orders the filter
#     after the group on a first apply — a raw string expresses no dependency;
#   - every other name is read through data.aws_cloudwatch_log_group, so a
#     missing group fails the PLAN with the group's name instead of the apply.
# A hard plan error and not a check: a scoped data source cannot use for_each
# (one check per name is impossible for a free list), and an existing
# deployment whose filters applied has the groups, so nothing legitimate
# breaks. The stack plans monitoring after the logging stack that creates the
# CloudTrail group (docs/getting-started.md, Phase 2 before Phase 3).
locals {
  monitoring_managed_log_group_names = toset(concat(
    [for lg in var.cloudwatch_log_groups : lg.name],
    var.enable_securityhub_cloudwatch_forwarding ? [var.securityhub_findings_log_group_name] : [],
  ))

  metric_filter_log_group_names = toset(concat(
    [for f in var.cloudwatch_metric_filters : f.log_group_name],
    var.enable_break_glass_alarm ? [var.break_glass_alarm_config.log_group_name] : [],
  ))

  external_metric_filter_log_group_names = toset([
    for name in local.metric_filter_log_group_names : name
    if !contains(local.monitoring_managed_log_group_names, name)
  ])

  # name → the value the filter resources use for log_group_name.
  metric_filter_log_group_name = {
    for name in local.metric_filter_log_group_names : name => (
      contains([for lg in var.cloudwatch_log_groups : lg.name], name)
      ? aws_cloudwatch_log_group.this[name].name
      : (
        var.enable_securityhub_cloudwatch_forwarding && name == var.securityhub_findings_log_group_name
        ? aws_cloudwatch_log_group.securityhub_findings[0].name
        : data.aws_cloudwatch_log_group.metric_filter_targets[name].name
      )
    )
  }
}

data "aws_cloudwatch_log_group" "metric_filter_targets" {
  for_each = local.external_metric_filter_log_group_names

  name = each.value
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each = { for f in var.cloudwatch_metric_filters : f.name => f }

  name           = each.value.name
  log_group_name = local.metric_filter_log_group_name[each.value.log_group_name]
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = each.value.metric_namespace
    value     = each.value.metric_value
    # The provider takes the default value as a string; the variable keeps the
    # number type so a non-numeric input fails at the type check, not here.
    default_value = each.value.default_value == null ? null : tostring(each.value.default_value)
  }
}

# --- CloudWatch Metric Alarms ---

# An entry with empty alarm_actions inherits the module's own alerting topic
# when that topic exists (single-topic mode): base.tfvars ships its CIS alarms
# without actions because the topic ARN is unknown until apply and the base
# layer is shipped content — without the inheritance those alarms change state
# and notify nobody. With severity topics configured no single topic exists and
# the module cannot know which severity an alarm belongs to, so the value
# degrades to [] and the notify-nobody check below reports it. Non-empty
# alarm_actions are used exactly as given.
locals {
  alarm_default_actions = length(aws_sns_topic.alerts) > 0 ? [aws_sns_topic.alerts[0].arn] : []
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each = { for a in var.cloudwatch_alarms : a.name => a }

  alarm_name          = each.value.name
  metric_name         = each.value.metric_name
  namespace           = each.value.namespace
  statistic           = each.value.statistic
  period              = each.value.period
  threshold           = each.value.threshold
  comparison_operator = each.value.comparison_operator
  evaluation_periods  = each.value.evaluation_periods
  alarm_actions       = length(each.value.alarm_actions) > 0 ? each.value.alarm_actions : local.alarm_default_actions
  treat_missing_data  = each.value.treat_missing_data
  alarm_description   = each.value.alarm_description
}

# Two ways an alarm applies green and watches nothing. Both are
# warnings, not validations: with severity topics configured no single alerting
# topic exists for empty alarm_actions to inherit (and the module cannot pick a
# severity), and a custom-namespace metric may be emitted by something other
# than this module's filters — a hard failure would break both. The ARN shape
# of a given action IS validated (variables.tf). In single-topic mode an empty
# alarm_actions inherits aws_sns_topic.alerts (see the alarm resource), so the
# notify-nobody list only carries alarms that stay without any action after
# the inheritance.
locals {
  cloudwatch_alarms_without_actions = [
    for a in var.cloudwatch_alarms : a.name
    if length(a.alarm_actions) == 0 && length(local.alarm_default_actions) == 0
  ]

  # namespace/metric pairs this module's filters (and the break-glass filter)
  # emit; an alarm outside the AWS/ namespaces that matches none of them sits in
  # INSUFFICIENT_DATA forever, which treat_missing_data = notBreaching (the
  # default) paints green.
  cloudwatch_filter_metrics = toset(concat(
    [for f in var.cloudwatch_metric_filters : "${f.metric_namespace}/${f.metric_name}"],
    var.enable_break_glass_alarm ? ["${var.break_glass_alarm_config.metric_namespace}/${var.break_glass_alarm_config.metric_name}"] : [],
  ))

  cloudwatch_alarms_without_source = [
    for a in var.cloudwatch_alarms : "${a.name} (${a.namespace}/${a.metric_name})"
    if !startswith(a.namespace, "AWS/") && !contains(local.cloudwatch_filter_metrics, "${a.namespace}/${a.metric_name}")
  ]
}

check "cloudwatch_alarms_notify_nobody" {
  assert {
    condition     = length(local.cloudwatch_alarms_without_actions) == 0
    error_message = "${length(local.cloudwatch_alarms_without_actions)} cloudwatch_alarms entries have no alarm_actions and notify nobody when they fire: ${join(", ", local.cloudwatch_alarms_without_actions)}. The alarms change state in the console and send nothing. Severity topics are configured, so there is no single alerting topic for these alarms to inherit — add alarm_actions with the ARN of the intended severity topic (output severity_topic_arns) to each entry in env/common.hcl, or accept metrics-only alarms knowingly."
  }
}

check "cloudwatch_alarms_have_a_metric_source" {
  assert {
    condition     = length(local.cloudwatch_alarms_without_source) == 0
    error_message = "cloudwatch_alarms entries watch a custom metric that no cloudwatch_metric_filters entry emits: ${join(", ", local.cloudwatch_alarms_without_source)}. Unless another emitter publishes that namespace/metric_name, the alarm stays in INSUFFICIENT_DATA forever and treat_missing_data = notBreaching shows it green. Check metric_name/namespace against the filter's metric_transformation."
  }
}

# --- CloudWatch Log Groups ---

resource "aws_cloudwatch_log_group" "this" {
  for_each = { for lg in var.cloudwatch_log_groups : lg.name => lg }

  name              = each.value.name
  retention_in_days = each.value.retention_in_days
  kms_key_id        = each.value.kms_key_id
  skip_destroy      = each.value.skip_destroy
}

# --- CloudWatch Log Group Onboarding ---
# cloudwatch_log_groups manages the declared groups; services create further
# groups on their own, and those carried neither retention nor key nor
# forwarding until someone noticed them. When enabled, an EventBridge rule
# catches every successful CreateLogGroup call (recorded by CloudTrail) and a
# Lambda applies the configured defaults to the new group. The function code
# ships with the module (lambda/log_group_onboarding.py, packaged via
# archive_file) — no local-exec, no shell script, no external data source.

resource "aws_cloudwatch_event_rule" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  name        = var.log_group_onboarding_rule_name
  description = "Catches newly created CloudWatch log groups so the onboarding Lambda can apply retention, key and forwarding defaults"

  event_pattern = jsonencode({
    source      = ["aws.logs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["logs.${local.dns_suffix}"]
      eventName   = ["CreateLogGroup"]
      errorCode   = [{ exists = false }]
    }
  })
}

data "archive_file" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/log_group_onboarding.py"
  output_path = "${path.module}/lambda/log_group_onboarding.zip"
}

resource "aws_iam_role" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  name = "tlz-log-group-onboarding"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  name = "tlz-log-group-onboarding-policy"
  role = aws_iam_role.log_group_onboarding[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/log-group-onboarding-lambda-policy.json", {
    arn_prefix            = local.arn_prefix
    region                = local.region
    account_id            = local.account_id
    dns_suffix            = local.dns_suffix
    dlq_name              = var.log_group_onboarding_dlq_name
    kms_key_arn           = var.log_group_onboarding.kms_key_arn
    destination_arn       = var.log_group_onboarding.destination_arn
    subscription_role_arn = var.log_group_onboarding.subscription_role_arn
  })))
}

# The grant that makes lambda_environment_kms_key_arn usable for this function.
# Lambda decrypts a function's environment variables with the FUNCTION's role at
# cold start, so a customer-managed key without this statement produces a
# function that plans and applies cleanly and then fails every invocation. Its
# own resource rather than a statement in the document above, because that
# document is a static file and this statement exists only while a key is named.
resource "aws_iam_role_policy" "log_group_onboarding_env_kms" {
  count = var.enable_log_group_onboarding && var.lambda_environment_kms_key_arn != "" ? 1 : 0

  name = "tlz-log-group-onboarding-env-kms"
  role = aws_iam_role.log_group_onboarding[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DecryptOwnEnvironment"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.lambda_environment_kms_key_arn
      },
    ]
  })
}

# Dead-letter queue for the onboarding Lambda. EventBridge invokes the
# function asynchronously; without a DLQ an event that still fails after the
# two automatic retries is dropped without a trace — and the log group it
# carried stays unonboarded, silently. The name is a variable because SQS
# CreateQueue is idempotent for identical attributes: a fixed name would let
# a live apply-test adopt-and-delete the live queue the day the onboarding
# is switched on (see variables.tf, log_group_onboarding_dlq_name).
resource "aws_sqs_queue" "log_group_onboarding_dlq" {
  count = var.enable_log_group_onboarding ? 1 : 0

  name                      = var.log_group_onboarding_dlq_name
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_lambda_function" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  function_name = "tlz-log-group-onboarding"
  description   = "Applies retention, key and forwarding defaults to newly created CloudWatch log groups"
  role          = aws_iam_role.log_group_onboarding[0].arn
  handler       = "log_group_onboarding.lambda_handler"
  runtime       = "python3.12"
  timeout       = 60

  # Cap on parallel executions: the function reacts to control-plane events,
  # so a small reserved pool is ample and bounds a runaway invocation storm
  # instead of letting it drain the account's concurrency pool.
  reserved_concurrent_executions = 10

  filename         = data.archive_file.log_group_onboarding[0].output_path
  source_code_hash = data.archive_file.log_group_onboarding[0].output_base64sha256

  # Empty means the AWS-managed Lambda key keeps encrypting the variables
  # below. A key named here is also
  # granted to the execution role (aws_iam_role_policy.log_group_onboarding_env_kms),
  # without which the function cannot read its own variables at cold start.
  kms_key_arn = var.lambda_environment_kms_key_arn != "" ? var.lambda_environment_kms_key_arn : null

  dead_letter_config {
    target_arn = aws_sqs_queue.log_group_onboarding_dlq[0].arn
  }

  environment {
    variables = {
      LOG_RETENTION_DAYS        = tostring(var.log_group_onboarding.retention_in_days)
      LOG_KMS_KEY_ARN           = var.log_group_onboarding.kms_key_arn
      LOG_DESTINATION_ARN       = var.log_group_onboarding.destination_arn
      LOG_SUBSCRIPTION_ROLE_ARN = var.log_group_onboarding.subscription_role_arn
      LOG_FILTER_PATTERN        = var.log_group_onboarding.filter_pattern
      LOG_EXCLUDED_PATTERNS     = jsonencode(var.log_group_onboarding.excluded_log_group_patterns)
    }
  }
}

# The function's own execution log group. Lambda creates /aws/lambda/<function
# name> implicitly on the first invocation when nothing has declared it, and
# that group then sits outside the state: no retention, no key, never
# destroyed — in every deployment, not only in a test — and its CreateLogGroup
# call is itself an event of the rule above, so the function onboarded its own
# group. Declared here with the defaults the automation applies to every other
# group (retention and, when configured, the key; the exclusion patterns
# govern only what the automation touches, not this module-owned resource).
# The name derives from the function so the two cannot disagree. The event
# target below depends on this group: no invocation, and so no implicit
# creation, can happen before it exists. CreateLogGroup is create-only — in an
# account where the function has already run, the group exists outside the
# state and the apply fails with ResourceAlreadyExistsException until the
# group is imported (README, "Lambda execution log groups").
resource "aws_cloudwatch_log_group" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.log_group_onboarding[0].function_name}"
  retention_in_days = var.log_group_onboarding.retention_in_days
  kms_key_id        = var.log_group_onboarding.kms_key_arn != "" ? var.log_group_onboarding.kms_key_arn : null
}

resource "aws_cloudwatch_event_target" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  rule      = aws_cloudwatch_event_rule.log_group_onboarding[0].name
  target_id = "log-group-onboarding-lambda"
  arn       = aws_lambda_function.log_group_onboarding[0].arn

  # The target is what lets EventBridge invoke the function; the function's
  # log group must exist before the first invocation can create it implicitly.
  depends_on = [aws_cloudwatch_log_group.log_group_onboarding]
}

resource "aws_lambda_permission" "log_group_onboarding" {
  count = var.enable_log_group_onboarding ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_group_onboarding[0].function_name
  principal     = "events.${local.dns_suffix}"
  source_arn    = aws_cloudwatch_event_rule.log_group_onboarding[0].arn
}

# --- SecurityHub Findings → CloudWatch Forwarding via EventBridge ---

resource "aws_cloudwatch_log_group" "securityhub_findings" {
  count = var.enable_securityhub_cloudwatch_forwarding ? 1 : 0

  name              = var.securityhub_findings_log_group_name
  retention_in_days = var.securityhub_findings_log_retention
  kms_key_id        = var.securityhub_findings_log_kms_key_id
}

resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  count       = var.enable_securityhub_cloudwatch_forwarding ? 1 : 0
  name        = var.securityhub_findings_rule_name
  description = "Routes SecurityHub findings to CloudWatch Logs for centralized monitoring and retention"

  event_pattern = jsonencode(merge(
    {
      source      = ["aws.securityhub"]
      detail-type = ["Security Hub Findings - Imported"]
    },
    length(var.securityhub_severity_filter) > 0 ? {
      detail = {
        findings = {
          Severity = {
            Label = var.securityhub_severity_filter
          }
        }
      }
    } : {}
  ))
}

resource "aws_cloudwatch_event_target" "securityhub_to_cloudwatch" {
  count     = var.enable_securityhub_cloudwatch_forwarding ? 1 : 0
  rule      = aws_cloudwatch_event_rule.securityhub_findings[0].name
  target_id = "securityhub-cloudwatch-target"
  # The log group ARN deliberately carries no ":*" suffix: an EventBridge
  # target identifies the resource (the CloudWatch Logs API's logGroupArn
  # form, also what AWS's own reference implementations pass). The ":*" form
  # is reserved for IAM/resource policies -- the accompanying
  # aws_cloudwatch_log_resource_policy appends it.
  arn = aws_cloudwatch_log_group.securityhub_findings[0].arn
}

resource "aws_cloudwatch_log_resource_policy" "securityhub_eventbridge" {
  count = var.enable_securityhub_cloudwatch_forwarding ? 1 : 0

  policy_name = var.securityhub_eventbridge_log_policy_name
  policy_document = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/securityhub-eventbridge-log-policy.json", {
    dns_suffix    = local.dns_suffix
    log_group_arn = aws_cloudwatch_log_group.securityhub_findings[0].arn
  })))
}

# --- SNS Cross-Account Forwarder Lambda ---

data "archive_file" "sns_forwarder" {
  count       = var.enable_sns_forwarder ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/sns_forwarder.py"
  output_path = "${path.module}/lambda/sns_forwarder.zip"
}

# Dead-letter queue for the forwarder Lambda. SNS invokes the function
# asynchronously; without a DLQ a forward that still fails after the two
# automatic retries is dropped without a trace — and the alert it carried
# never reaches the central topic, silently. Skipped when the caller brings
# an existing queue via sns_forwarder_config.dlq_arn.
resource "aws_sqs_queue" "sns_forwarder_dlq" {
  count = var.enable_sns_forwarder && var.sns_forwarder_config.dlq_arn == null ? 1 : 0

  # Overridable: SQS CreateQueue adopts an existing queue with identical
  # attributes — see var.sns_forwarder_dlq_name for why an apply-test must
  # scope this. The forwarder policy's DLQ grant follows the same name.
  name                      = var.sns_forwarder_dlq_name
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_lambda_function" "sns_forwarder" {
  count = var.enable_sns_forwarder ? 1 : 0

  function_name    = "tlz-sns-forwarder"
  description      = "Forwards SNS messages from member account topics to a central SNS topic"
  runtime          = "python3.12"
  handler          = "sns_forwarder.handler"
  role             = aws_iam_role.sns_forwarder[0].arn
  filename         = data.archive_file.sns_forwarder[0].output_path
  source_code_hash = data.archive_file.sns_forwarder[0].output_base64sha256
  timeout          = 30

  # Cap on parallel executions: the function relays alert notifications, so a
  # small reserved pool is ample and bounds a runaway invocation storm instead
  # of letting it drain the account's concurrency pool.
  reserved_concurrent_executions = var.sns_forwarder_config.reserved_concurrent_executions

  dead_letter_config {
    target_arn = var.sns_forwarder_config.dlq_arn != null ? var.sns_forwarder_config.dlq_arn : aws_sqs_queue.sns_forwarder_dlq[0].arn
  }

  # Empty means the AWS-managed Lambda key keeps encrypting the variable
  # below. A key named here is also
  # granted to the execution role (aws_iam_role_policy.sns_forwarder_env_kms),
  # without which the function cannot read its own variables at cold start.
  kms_key_arn = var.lambda_environment_kms_key_arn != "" ? var.lambda_environment_kms_key_arn : null

  environment {
    variables = {
      CENTRAL_TOPIC_ARN = var.sns_forwarder_config.central_topic_arn
    }
  }

  # Lambda validates sqs:SendMessage on the dead_letter_config target at
  # create/update time. Without this edge the function can be created before
  # the role policy granting that permission exists, and the apply fails with
  # a permission error that a retry then masks. Same IAM-propagation class as
  # the module's other explicit orderings.
  depends_on = [aws_iam_role_policy.sns_forwarder]

  lifecycle {
    precondition {
      condition     = var.sns_forwarder_config.central_topic_arn != ""
      error_message = "central_topic_arn must be non-empty when enable_sns_forwarder is true."
    }
  }
}

resource "aws_iam_role" "sns_forwarder" {
  count = var.enable_sns_forwarder ? 1 : 0
  name  = "tlz-sns-forwarder"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/sns-forwarder-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "sns_forwarder" {
  count = var.enable_sns_forwarder ? 1 : 0
  name  = "tlz-sns-forwarder-policy"
  role  = aws_iam_role.sns_forwarder[0].id

  policy = jsonencode(local.sns_forwarder_policy)
}

# Same grant, same reason, for the forwarder: without kms:Decrypt on the named
# key the function cannot read CENTRAL_TOPIC_ARN at cold start and no alert is
# ever relayed. Only present while a key is named.
resource "aws_iam_role_policy" "sns_forwarder_env_kms" {
  count = var.enable_sns_forwarder && var.lambda_environment_kms_key_arn != "" ? 1 : 0

  name = "tlz-sns-forwarder-env-kms"
  role = aws_iam_role.sns_forwarder[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DecryptOwnEnvironment"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.lambda_environment_kms_key_arn
      },
    ]
  })
}

# The forwarder's own execution log group — the same gap as the onboarding
# function's (see aws_cloudwatch_log_group.log_group_onboarding): implicitly
# created by Lambda on the first invocation, untracked and unbounded otherwise.
# The subscriptions below depend on it, so no delivery can invoke the function
# before the group exists. Create-only as well: an account where the forwarder
# has already run must import the group (README, "Lambda execution log groups").
resource "aws_cloudwatch_log_group" "sns_forwarder" {
  count = var.enable_sns_forwarder ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.sns_forwarder[0].function_name}"
  retention_in_days = var.sns_forwarder_config.log_retention_in_days
  kms_key_id        = aws_kms_key.sns_forwarder_logs[0].arn
}

# --- SNS Forwarder Subscriptions and Lambda Permissions ---

resource "aws_sns_topic_subscription" "sns_forwarder" {
  for_each = var.enable_sns_forwarder ? toset(var.sns_forwarder_config.source_topic_arns) : toset([])

  topic_arn = each.value
  protocol  = "lambda"
  endpoint  = aws_lambda_function.sns_forwarder[0].arn

  # The subscription is what lets SNS invoke the function; the function's log
  # group must exist before the first invocation can create it implicitly.
  depends_on = [aws_cloudwatch_log_group.sns_forwarder]
}

resource "aws_lambda_permission" "sns_forwarder" {
  for_each = var.enable_sns_forwarder ? toset(var.sns_forwarder_config.source_topic_arns) : toset([])

  statement_id  = "AllowSNSInvoke-${md5(each.value)}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_forwarder[0].function_name
  principal     = "sns.${local.dns_suffix}"
  source_arn    = each.value
}

# --- SecurityHub EventBridge Custom Rules ---

locals {
  # Placeholder a rule target can use instead of a literal ARN, and the log group
  # it resolves to. Both values are mirrored in the validation of
  # var.securityhub_eventbridge_rules, which cannot reference locals.
  securityhub_findings_log_group_placeholder = "__CW_LOG_GROUP_ARN__"
  securityhub_findings_log_group_name        = "/aws/securityhub/findings"

  # Resolve the __CW_LOG_GROUP_ARN__ placeholder in SecurityHub EventBridge rule
  # targets. The log group is addressed directly: without it the placeholder
  # would reach EventBridge as a literal string and AWS would reject the target.
  # variables.tf requires the log group whenever the placeholder is used.
  securityhub_rules = {
    for rule in var.securityhub_eventbridge_rules : rule.name => merge(rule, {
      resolved_target_arn = (
        rule.target_arn == local.securityhub_findings_log_group_placeholder
        ? aws_cloudwatch_log_group.this[local.securityhub_findings_log_group_name].arn
        : rule.target_arn
      )
    })
  }

  # Determine which rules target CW Log Groups (need resource policy). The
  # decision reads the configured target, not the resolved one: the ARN of a
  # module-managed log group is only known after apply and must not decide how
  # many resources are planned.
  securityhub_rules_targeting_cw = {
    for name, rule in local.securityhub_rules : name => rule
    if rule.target_arn == local.securityhub_findings_log_group_placeholder || (
      startswith(rule.target_arn, "arn:") && strcontains(rule.target_arn, ":log-group:")
    )
  }
}

resource "aws_cloudwatch_event_rule" "securityhub" {
  for_each = local.securityhub_rules

  name          = each.value.name
  description   = each.value.description
  event_pattern = each.value.event_pattern
}

resource "aws_cloudwatch_event_target" "securityhub" {
  for_each = local.securityhub_rules

  rule      = aws_cloudwatch_event_rule.securityhub[each.key].name
  target_id = "${each.key}-target"
  # For log group targets the resolved ARN carries no ":*" suffix: an
  # EventBridge target identifies the resource (the CloudWatch Logs API's
  # logGroupArn form). The ":*" form is reserved for IAM/resource policies --
  # aws_cloudwatch_log_resource_policy.securityhub_custom_rules_eventbridge
  # appends it below.
  arn = each.value.resolved_target_arn
}

resource "aws_cloudwatch_log_resource_policy" "securityhub_custom_rules_eventbridge" {
  count = length(local.securityhub_rules_targeting_cw) > 0 ? 1 : 0

  policy_name = var.securityhub_custom_rules_log_policy_name
  policy_document = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/monitoring/securityhub-custom-rules-eventbridge-log-policy.json", {
    dns_suffix          = local.dns_suffix
    log_group_arns_json = jsonencode([for name, rule in local.securityhub_rules_targeting_cw : "${rule.resolved_target_arn}:*"])
  })))
}
