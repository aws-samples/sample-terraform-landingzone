# Monitoring module variables

variable "sns_kms_encryption" {
  description = "When true (the default), creates a dedicated customer-managed KMS key and encrypts every SNS topic of this module with it (the fallback alerts topic and the per-severity topics alike). When false the topics carry NO server-side encryption at all: kms_master_key_id stays unset, which is not the same as falling back to the AWS-managed aws/sns key. A customer-managed key is the only option that keeps the CloudWatch, EventBridge and Budgets publishers working (AWS SNS Developer Guide, \"Enable compatibility between event sources from AWS services and encrypted topics\": step 1 is use a customer managed key), so the AWS-managed key is not an available middle ground. The key policy (configurations/policies/monitoring/sns-kms-key-policy.json) already grants kms:Decrypt and kms:GenerateDataKey* to cloudwatch, events and budgets — the same publishers the topic policy admits — so turning this on does not silently drop alarm delivery. CKV_AWS_26 flags the false case as an open finding; the owner decided the default is true."
  type        = bool
  default     = true
}

variable "sns_kms_alias_name" {
  description = "Alias of the dedicated SNS KMS key (created when sns_kms_encryption is true). The default is the account-wide production alias. KMS CreateAlias is create-only — an existing alias fails the apply with AlreadyExistsException instead of being adopted — so with the live alias in place a live apply-test that enables sns_kms_encryption cannot run at all under the default: it must override this with a test-scoped alias (alias/tlz-l4test-...). The alias must stay inside the alias/tlz- namespace the repository's name guard covers. A changed default is a destroy/create of the live alias, so leave it at the literal below in production."
  type        = string
  default     = "alias/tlz-sns-encryption"

  validation {
    condition     = can(regex("^alias/tlz[-/][a-zA-Z0-9:/_-]{1,245}$", var.sns_kms_alias_name))
    error_message = "sns_kms_alias_name must start with alias/tlz- (or alias/tlz/) and continue with 1-245 characters of letters, digits, colon, slash, underscore or hyphen — the KMS alias naming rule inside the tlz namespace."
  }
}

variable "guardduty_detector_id" {
  description = "GuardDuty detector ID for dashboard metrics"
  type        = string
  default     = ""

  validation {
    condition     = var.guardduty_detector_id == "" || can(regex("^[0-9a-f]{32}$", var.guardduty_detector_id))
    error_message = "guardduty_detector_id must be empty or a 32-character hexadecimal GuardDuty detector ID."
  }
}

variable "config_aggregator_name" {
  description = "Config aggregator name for compliance status in dashboard"
  type        = string
  default     = ""

  validation {
    condition     = var.config_aggregator_name == "" || can(regex("^[a-zA-Z0-9_.-]{1,256}$", var.config_aggregator_name))
    error_message = "config_aggregator_name must be empty or 1-256 characters of letters, digits, dot, underscore or hyphen."
  }
}

variable "cloudtrail_arn" {
  description = "CloudTrail ARN for event volume in dashboard"
  type        = string
  default     = ""

  validation {
    condition     = var.cloudtrail_arn == "" || can(regex("^arn:[a-z0-9-]+:cloudtrail:", var.cloudtrail_arn))
    error_message = "cloudtrail_arn must be empty or a CloudTrail ARN (arn:<partition>:cloudtrail:<region>:<account-id>:trail/<name>)."
  }
}

variable "sns_email_targets" {
  description = "Email addresses for SNS alerting"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for address in var.sns_email_targets :
      can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[a-zA-Z]{2,}$", address))
    ])
    error_message = "Each sns_email_targets entry must be an email address. A malformed address is accepted by SNS as a pending subscription that never confirms, so the alert path stays silently broken."
  }

  validation {
    condition     = length(distinct(var.sns_email_targets)) == length(var.sns_email_targets)
    error_message = "sns_email_targets must not contain duplicates — SNS would create two subscriptions for the same address."
  }
}

variable "sns_lambda_targets" {
  description = "Lambda ARNs for SNS alerting"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.sns_lambda_targets :
      can(regex("^arn:[a-z0-9-]+:lambda:[a-z0-9-]+:[0-9]{12}:function:", arn))
    ])
    error_message = "Each sns_lambda_targets entry must be a Lambda function ARN (arn:<partition>:lambda:<region>:<account-id>:function:<name>)."
  }
}

variable "alert_on_severity" {
  description = "Severity threshold for GuardDuty findings alerting (LOW, MEDIUM, HIGH, CRITICAL)"
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH", "CRITICAL"], var.alert_on_severity)
    error_message = "alert_on_severity must be LOW, MEDIUM, HIGH, or CRITICAL."
  }
}

variable "alerts_topic_name" {
  description = "Name of the central alerts SNS topic of the single-topic form (created while sns_topics is empty). The default is the account-wide production name. SNS CreateTopic is an UPSERT: a live account already carrying this name is silently adopted rather than failing, so a live apply-test that exercises the single-topic form must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live alerting topic every alarm and EventBridge rule of the account delivers to. The name must stay inside the tlz- namespace: the organization guardrails protect only arn:*:sns:*:*:tlz-* from tampering. A changed default is a destroy/create of the live topic (subscriptions included), so leave it at the literal below in production."
  type        = string
  default     = "tlz-landing-zone-alerts"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9_-]{1,252}$", var.alerts_topic_name))
    error_message = "alerts_topic_name must start with tlz- and be 1-256 characters of letters, digits, underscore or hyphen in total — the AWS SNS topic naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "guardduty_findings_rule_name" {
  description = "Name of the EventBridge rule that routes GuardDuty findings to the central alerts topic in the single-topic form (created while sns_topics is empty). The default is the account-wide production name. EventBridge PutRule is an UPSERT: a live account already carrying this name is silently adopted rather than failing, so a live apply-test that exercises the single-topic form must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rule. The name must stay inside the tlz- namespace: the organization guardrails protect only arn:*:events:*:*:rule/tlz-* from tampering. A changed default is a destroy/create of the live rule, so leave it at the literal below in production."
  type        = string
  default     = "tlz-guardduty-findings-alert"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", var.guardduty_findings_rule_name))
    error_message = "guardduty_findings_rule_name must start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

# --- SNS Severity Topics ---

variable "sns_topics" {
  description = "List of SNS topic definitions with severity-based routing. When provided, separate topics are created per severity level with EventBridge rules routing GuardDuty findings. When empty, falls back to single-topic behavior via sns_email_targets. name overrides the derived topic name tlz-alerts-<severity>; unset keeps the derivation. SNS CreateTopic is an UPSERT, so a derived or set name that an existing topic in the account already carries is silently adopted (and a live apply-test's teardown deletes it) — a live apply-test that configures sns_topics must set a test-scoped name (tlz-l4test-). rule_name overrides the derived name of the entry's GuardDuty routing rule, tlz-guardduty-<severity>-findings; unset keeps the derivation. EventBridge PutRule is an UPSERT, so a live apply-test that configures sns_topics must set a test-scoped rule_name (tlz-l4test-) — under the derived name it adopts a live per-severity rule the day the live stack switches to severity topics, and terraform test's teardown deletes it. A set rule_name must stay inside tlz-: the organization guardrails protect only arn:*:events:*:*:rule/tlz-*, and the static prefix guard reads only literal names, so this validation carries the invariant. deployment_targets is accepted for configuration compatibility but triggers a check block warning since Terraform cannot dynamically create cross-account providers."
  type = list(object({
    severity           = string
    name               = optional(string)
    rule_name          = optional(string)
    email_targets      = optional(list(string), [])
    lambda_targets     = optional(list(string), [])
    deployment_targets = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for t in var.sns_topics :
      contains(["HIGH", "MEDIUM", "LOW", "CRITICAL"], t.severity)
    ])
    error_message = "Each sns_topics entry must have a severity of HIGH, MEDIUM, LOW, or CRITICAL."
  }

  # The SNS naming rule, checked at plan time: an invalid name would only
  # fail at apply, after the rest of the monitoring stack is built.
  validation {
    condition = alltrue([
      for t in var.sns_topics :
      t.name == null || can(regex("^[a-zA-Z0-9_-]{1,256}$", t.name))
    ])
    error_message = "Each sns_topics name must be unset (derived name) or 1-256 characters of letters, digits, underscore or hyphen — the AWS SNS topic naming rule."
  }

  # The effective names key nothing, but two topics of the same name would
  # collide at the API; the derived names cannot collide because severities
  # are distinct per entry.
  validation {
    condition = length(distinct([
      for t in var.sns_topics : coalesce(t.name, "tlz-alerts-${lower(t.severity)}")
    ])) == length(var.sns_topics)
    error_message = "sns_topics names must be unique after applying the derived default tlz-alerts-<severity> — duplicate topic names collide at the SNS API."
  }

  # The routing rule is a guardrail class (arn:*:events:*:*:rule/tlz-*), so a
  # configured rule_name is pinned to the namespace like every other rule
  # name of this module; the derived default already lives inside it.
  validation {
    condition = alltrue([
      for t in var.sns_topics :
      t.rule_name == null || can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", t.rule_name))
    ])
    error_message = "Each sns_topics rule_name must be unset (derived name tlz-guardduty-<severity>-findings) or start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }

  validation {
    condition = length(distinct([
      for t in var.sns_topics : coalesce(t.rule_name, "tlz-guardduty-${lower(t.severity)}-findings")
    ])) == length(var.sns_topics)
    error_message = "sns_topics rule_names must be unique after applying the derived default tlz-guardduty-<severity>-findings — PutRule is an upsert, so two entries with one rule name would silently share (and fight over) a single rule."
  }
}

# --- CloudWatch Metric Filters ---

variable "cloudwatch_metric_filters" {
  description = "List of CloudWatch Log Metric Filter definitions. Each filter creates an aws_cloudwatch_log_metric_filter resource. default_value is the value reported for periods in which logs are ingested but no matching events are found; null (the default) keeps the metric silent in those periods. deployment_targets is accepted for configuration compatibility but triggers a check block warning."
  type = list(object({
    name               = string
    log_group_name     = string
    pattern            = string
    metric_namespace   = string
    metric_name        = string
    metric_value       = optional(string, "1")
    default_value      = optional(number, null)
    deployment_targets = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for f in var.cloudwatch_metric_filters :
      length(f.name) > 0 && length(f.log_group_name) > 0 && length(f.metric_namespace) > 0 && length(f.metric_name) > 0
    ])
    error_message = "Each cloudwatch_metric_filters entry must have non-empty name, log_group_name, metric_namespace, and metric_name."
  }
}

# --- CloudWatch Alarms ---

variable "cloudwatch_alarms" {
  description = "List of CloudWatch Metric Alarm definitions. Each alarm creates an aws_cloudwatch_metric_alarm resource. deployment_targets is accepted for configuration compatibility but triggers a check block warning."
  type = list(object({
    name                = string
    metric_name         = string
    namespace           = string
    statistic           = optional(string, "Sum")
    period              = optional(number, 300)
    threshold           = number
    comparison_operator = optional(string, "GreaterThanOrEqualToThreshold")
    evaluation_periods  = optional(number, 1)
    alarm_actions       = optional(list(string), [])
    treat_missing_data  = optional(string, "notBreaching")
    alarm_description   = optional(string, "")
    deployment_targets  = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for a in var.cloudwatch_alarms :
      length(a.name) > 0 && length(a.metric_name) > 0 && length(a.namespace) > 0
    ])
    error_message = "Each cloudwatch_alarms entry must have non-empty name, metric_name, and namespace."
  }

  validation {
    condition = alltrue([
      for a in var.cloudwatch_alarms :
      contains(["SampleCount", "Average", "Sum", "Minimum", "Maximum"], a.statistic)
    ])
    error_message = "Each cloudwatch_alarms statistic must be one of: SampleCount, Average, Sum, Minimum, Maximum."
  }

  validation {
    condition = alltrue([
      for a in var.cloudwatch_alarms :
      contains(["GreaterThanOrEqualToThreshold", "GreaterThanThreshold", "LessThanThreshold", "LessThanOrEqualToThreshold"], a.comparison_operator)
    ])
    error_message = "Each cloudwatch_alarms comparison_operator must be one of: GreaterThanOrEqualToThreshold, GreaterThanThreshold, LessThanThreshold, LessThanOrEqualToThreshold."
  }

  # PutMetricAlarm accepts any ARN-shaped string and reports a bad target only
  # as a delivery failure when the alarm first fires; a non-ARN it rejects at
  # apply. Same shape rule as break_glass_alarm_config.alarm_actions. Whether
  # the alarm has any action at all is a check (main.tf,
  # cloudwatch_alarms_notify_nobody), because base.tfvars ships its alarms
  # without actions on purpose.
  validation {
    condition = alltrue([
      for a in var.cloudwatch_alarms : alltrue([
        for target in a.alarm_actions : can(regex("^arn:", target))
      ])
    ])
    error_message = "Each cloudwatch_alarms alarm_actions entry must be an ARN (for example an SNS topic ARN) — CloudWatch rejects other values at apply."
  }
}

# --- EventBridge Default Bus Policy ---

variable "eventbridge_default_bus_policy" {
  description = "JSON policy document for the default EventBridge event bus. Set to null to skip creating a bus policy."
  type        = string
  default     = null

  # The value is a sentinel, not the policy body: any non-empty string switches
  # the bus policy on, and the document itself is rendered from
  # configurations/policies/monitoring/eventbridge-default-bus-policy.json so
  # that partition, region and account stay dynamic. Rejecting a JSON document
  # here catches the natural misreading of the variable name, which would
  # otherwise be discarded without a word.
  validation {
    condition     = var.eventbridge_default_bus_policy == null || !can(regex("[{}]", var.eventbridge_default_bus_policy))
    error_message = "eventbridge_default_bus_policy is a switch, not a policy body: any non-empty name enables the bus policy, which the module renders from the versioned template. Pass a name (or an empty string to disable), not a JSON document."
  }
}

# --- CloudWatch Log Groups ---

# --- Diagnostics Dashboard ---

variable "dashboard_name" {
  description = "Name of the Landing Zone Health CloudWatch dashboard. The default is the account-wide production name. CloudWatch PutDashboard is an UPSERT: a live account already carrying this name is silently adopted rather than failing, so a live apply-test must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the real dashboard. A changed default would destroy/create the live dashboard, so leave it at the literal below in production."
  type        = string
  default     = "TLZ-Landing-Zone-Health"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,255}$", var.dashboard_name))
    error_message = "dashboard_name must be 1-255 characters of letters, digits, underscore or hyphen — the CloudWatch dashboard naming rule."
  }
}

variable "enable_diagnostics_dashboard" {
  description = "Extend the Landing Zone Health dashboard with diagnostic widgets for Config compliance, Security Hub findings, GuardDuty trends, CloudTrail volume, and S3 storage metrics."
  type        = bool
  default     = true
}

variable "central_log_bucket_name" {
  description = "Name of the central S3 log bucket for storage metrics in the diagnostics dashboard."
  type        = string
  default     = ""

  validation {
    condition     = var.central_log_bucket_name == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.central_log_bucket_name))
    error_message = "central_log_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

# --- CloudWatch Log Groups ---

variable "cloudwatch_log_groups" {
  description = "List of CloudWatch Log Group definitions. Each entry creates an aws_cloudwatch_log_group resource. skip_destroy protects a log group and its log data from deletion through this configuration: on removal the group is only dropped from management and stays in the account. With the default false a removal deletes the group."
  type = list(object({
    name              = string
    retention_in_days = optional(number, null)
    kms_key_id        = optional(string, null)
    skip_destroy      = optional(bool, false)
  }))
  default = []

  validation {
    condition = alltrue([
      for lg in var.cloudwatch_log_groups :
      lg.retention_in_days == null || contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], lg.retention_in_days)
    ])
    error_message = "Each cloudwatch_log_groups retention_in_days must be null or a valid CloudWatch retention value (0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653)."
  }

  validation {
    condition = alltrue([
      for lg in var.cloudwatch_log_groups :
      length(lg.name) > 0
    ])
    error_message = "Each cloudwatch_log_groups entry must have a non-empty name."
  }
}

# --- CloudWatch Log Group Onboarding ---

variable "enable_log_group_onboarding" {
  description = "When true, an EventBridge rule catches every successful CreateLogGroup call (via CloudTrail) and a Lambda applies the landing zone defaults to the new log group: retention, optionally a KMS key and optionally a subscription filter toward the central log destination. cloudwatch_log_groups manages declared groups; this automation covers the groups services create on their own."
  type        = bool
  default     = false
}

variable "log_group_onboarding" {
  description = "Defaults the onboarding automation applies to newly created log groups. Read only while enable_log_group_onboarding is set. destination_arn and subscription_role_arn come as a pair: the filter cannot be attached without the role CloudWatch Logs assumes. retention_in_days and kms_key_arn also shape the function's own execution log group /aws/lambda/tlz-log-group-onboarding, which the module declares as a managed resource; excluded_log_group_patterns governs only what the automation touches, not that module-owned group."
  type = object({
    retention_in_days           = optional(number, 365)
    kms_key_arn                 = optional(string, "")
    destination_arn             = optional(string, "")
    subscription_role_arn       = optional(string, "")
    filter_pattern              = optional(string, "")
    excluded_log_group_patterns = optional(list(string), [])
  })
  default = {}

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.log_group_onboarding.retention_in_days
    )
    error_message = "log_group_onboarding.retention_in_days must be one of the CloudWatch retention values (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653) — 0 (never expire) is not offered, the automation exists to bound retention."
  }

  validation {
    condition = (
      var.log_group_onboarding.kms_key_arn == "" ||
      can(regex("^arn:[a-z0-9-]+:kms:", var.log_group_onboarding.kms_key_arn))
    )
    error_message = "log_group_onboarding.kms_key_arn must be empty (no key association) or a KMS key ARN."
  }

  validation {
    condition = (
      var.log_group_onboarding.destination_arn == "" ||
      can(regex("^arn:[a-z0-9-]+:", var.log_group_onboarding.destination_arn))
    )
    error_message = "log_group_onboarding.destination_arn must be empty (no subscription filter) or a valid ARN."
  }

  # The pair in both directions: a destination without the role cannot be
  # attached (PutSubscriptionFilter requires roleArn for cross-service
  # destinations), and a role without a destination would silently do nothing.
  validation {
    condition     = (var.log_group_onboarding.destination_arn == "") == (var.log_group_onboarding.subscription_role_arn == "")
    error_message = "log_group_onboarding.destination_arn and subscription_role_arn come as a pair — set both (attach a subscription filter) or neither."
  }

  validation {
    condition = (
      var.log_group_onboarding.subscription_role_arn == "" ||
      can(regex("^arn:[a-z0-9-]+:iam::[0-9]{12}:role/", var.log_group_onboarding.subscription_role_arn))
    )
    error_message = "log_group_onboarding.subscription_role_arn must be empty or an IAM role ARN."
  }

  # A pattern without content matches nothing visible and hides a
  # configuration mistake.
  validation {
    condition = alltrue([
      for pattern in var.log_group_onboarding.excluded_log_group_patterns :
      trimspace(pattern) != ""
    ])
    error_message = "log_group_onboarding.excluded_log_group_patterns must not contain empty entries."
  }
}

variable "log_group_onboarding_rule_name" {
  description = "Name of the EventBridge rule that catches CreateLogGroup calls for the onboarding automation (created when enable_log_group_onboarding is true). The default is the account-wide production name. EventBridge PutRule is an UPSERT: a live account already carrying this name is silently adopted rather than failing, so a live apply-test that enables the onboarding must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rule. The name must stay inside the tlz- namespace: the organization guardrails protect only arn:*:events:*:*:rule/tlz-* from tampering. A changed default is a destroy/create of the live rule, so leave it at the literal below in production."
  type        = string
  default     = "tlz-log-group-onboarding"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", var.log_group_onboarding_rule_name))
    error_message = "log_group_onboarding_rule_name must start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "log_group_onboarding_dlq_name" {
  description = "Name of the SQS dead-letter queue that receives onboarding events the Lambda still fails after its automatic retries (created when enable_log_group_onboarding is true). The default is the account-wide production name. SQS CreateQueue is IDEMPOTENT for an existing queue with identical attributes: it returns the existing queue instead of failing, so a live apply-test that enables the onboarding must override this with a test-scoped name (tlz-l4test-) — otherwise the test silently adopts the live DLQ and `terraform test`'s automatic teardown deletes it, together with every failed onboarding event it holds. That the queue is not live today is NOT a safety property: enabling enable_log_group_onboarding in production creates it under this default overnight, and a test asserting the default name becomes the deletion. The Lambda's execution policy (sqs:SendMessage on the DLQ) follows this name. No organization guardrail pins an SQS namespace (the RCPs' sqs:* statements are name-independent), so unlike the topic and rule names this one is not confined to tlz-; keep the prefix anyway for legibility. A changed default is a destroy/create of the live queue (its messages included), so leave it at the literal below in production."
  type        = string
  default     = "tlz-log-group-onboarding-dlq"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,80}$", var.log_group_onboarding_dlq_name))
    error_message = "log_group_onboarding_dlq_name must be 1-80 characters of letters, digits, underscore or hyphen — the SQS standard-queue naming rule (no dot, so no accidental .fifo suffix on a standard queue)."
  }
}

variable "sns_forwarder_dlq_name" {
  description = "Name of the module-managed dead-letter queue of the SNS cross-account forwarder Lambda (created when enable_sns_forwarder is true and sns_forwarder_config.dlq_arn is null). The default is the account-wide production name. SQS CreateQueue is IDEMPOTENT for identical attributes: an account already carrying this queue is silently adopted rather than failing, so a live apply-test that enables the forwarder must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live queue and every dead-lettered alert in it. Deliberately NOT pinned to the tlz- namespace: no organization guardrail names an SQS queue ARN. The forwarder role's sqs:SendMessage grant follows this name. A changed default is a destroy/create of the live queue, so leave it at the literal below in production."
  type        = string
  default     = "tlz-sns-forwarder-dlq"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,80}$", var.sns_forwarder_dlq_name))
    error_message = "sns_forwarder_dlq_name must be 1-80 characters of letters, digits, underscore or hyphen — the SQS standard-queue naming rule."
  }
}

# --- SecurityHub CloudWatch Forwarding ---

variable "enable_securityhub_cloudwatch_forwarding" {
  description = "When true, creates an EventBridge rule to forward SecurityHub findings to a CloudWatch Log Group."
  type        = bool
  default     = false
}

variable "securityhub_severity_filter" {
  description = "List of severity labels to filter SecurityHub findings. Empty list matches all severities."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for s in var.securityhub_severity_filter :
      contains(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], s)
    ])
    error_message = "Each severity must be CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL."
  }
}

variable "securityhub_findings_log_group_name" {
  description = "Name of the CloudWatch Log Group receiving the forwarded SecurityHub findings. The default is the derived production name. The name must be either a path form (leading slash, like the default /aws/events/securityhub-findings) or inside the tlz- namespace: ProtectCloudWatchLogGroups in tlz-core-guardrails-1.json protects only log-group:tlz-* and log-group:/aws/lambda/tlz-*, and the static prefix guard classifies a log group name as either guardrail-covered (tlz-) or a path form it deliberately does not judge — a bare name with neither shape would be unprotected and unclassifiable, so this validation refuses it at plan time."
  type        = string
  default     = "/aws/events/securityhub-findings"

  validation {
    condition     = can(regex("^[A-Za-z0-9_/.#-]{1,512}$", var.securityhub_findings_log_group_name))
    error_message = "securityhub_findings_log_group_name must be 1-512 characters of letters, digits, underscore, slash, dot, hash or hyphen — the CloudWatch log group naming rule."
  }

  validation {
    condition     = startswith(var.securityhub_findings_log_group_name, "/") || startswith(var.securityhub_findings_log_group_name, "tlz-")
    error_message = "securityhub_findings_log_group_name must either start with a slash (a path-form log group such as /aws/events/securityhub-findings) or start with tlz- (the guardrail-protected namespace) — a bare name with neither shape lies outside every Deny statement and outside what the prefix guard can classify."
  }
}

variable "securityhub_findings_log_retention" {
  description = "Retention in days for the SecurityHub findings CloudWatch Log Group."
  type        = number
  default     = 365

  # CloudWatch accepts only this fixed set of retention values; 0 means never
  # expire. Any other number is rejected at apply time.
  validation {
    condition = contains(
      [0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.securityhub_findings_log_retention
    )
    error_message = "securityhub_findings_log_retention must be one of the CloudWatch retention values: 0 (never expire), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

variable "securityhub_findings_log_kms_key_id" {
  description = "Optional KMS key ID for encrypting the SecurityHub findings CloudWatch Log Group."
  type        = string
  default     = null

  validation {
    condition = (
      var.securityhub_findings_log_kms_key_id == null
      || var.securityhub_findings_log_kms_key_id == ""
      || can(regex("^(arn:[a-z0-9-]+:kms:|alias/|[0-9a-f-]{36}$)", var.securityhub_findings_log_kms_key_id))
    )
    error_message = "securityhub_findings_log_kms_key_id must be null, empty, a KMS key ARN, an alias/<name> or a key UUID."
  }
}

variable "securityhub_findings_rule_name" {
  description = "Name of the EventBridge rule that forwards Security Hub findings to the findings log group (created when enable_securityhub_cloudwatch_forwarding is true). The default is the account-wide production name. EventBridge PutRule is an UPSERT: a live account already carrying this name is silently adopted rather than failing, so a live apply-test that enables the forwarding must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rule. The name must stay inside the tlz- namespace: the organization guardrails protect only arn:*:events:*:*:rule/tlz-* from tampering. A changed default is a destroy/create of the live rule, so leave it at the literal below in production."
  type        = string
  default     = "tlz-securityhub-findings-to-cloudwatch"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", var.securityhub_findings_rule_name))
    error_message = "securityhub_findings_rule_name must start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "securityhub_eventbridge_log_policy_name" {
  description = "Name of the CloudWatch Logs resource policy that lets EventBridge deliver forwarded SecurityHub findings to the findings log group (created when enable_securityhub_cloudwatch_forwarding is true). The default is the account-wide production name. CloudWatch Logs PutResourcePolicy is an UPSERT keyed by this name: a live apply-test that enables the forwarding must override this with a test-scoped name (tlz-l4test-), or `terraform test`'s teardown deletes the live resource policy."
  type        = string
  default     = "tlz-securityhub-eventbridge-log-policy"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,512}$", var.securityhub_eventbridge_log_policy_name))
    error_message = "securityhub_eventbridge_log_policy_name must be 1-512 characters of letters, digits, underscore or hyphen — the CloudWatch Logs resource policy naming rule."
  }
}

variable "securityhub_custom_rules_log_policy_name" {
  description = "Name of the CloudWatch Logs resource policy that lets the securityhub_eventbridge_rules EventBridge rules deliver to their log group targets (created only when at least one rule targets a CloudWatch log group). The default is the account-wide production name. CloudWatch Logs PutResourcePolicy is an UPSERT keyed by this name: a live apply-test that exercises a CW-targeting rule must override this with a test-scoped name (tlz-l4test-), or `terraform test`'s teardown deletes the live resource policy."
  type        = string
  default     = "tlz-securityhub-custom-rules-eventbridge-to-cw"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,512}$", var.securityhub_custom_rules_log_policy_name))
    error_message = "securityhub_custom_rules_log_policy_name must be 1-512 characters of letters, digits, underscore or hyphen — the CloudWatch Logs resource policy naming rule."
  }
}

# --- Organization ID ---

variable "organization_id" {
  description = "AWS Organizations ID for EventBridge bus policy org condition. Empty string disables the org condition."
  type        = string
  default     = ""

  validation {
    condition     = var.organization_id == "" || can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must be empty or a valid AWS Organizations ID in the format o-xxxxxxxxxx."
  }
}

# --- SNS Cross-Account Forwarder Lambda ---

variable "enable_sns_forwarder" {
  description = "Enable cross-account SNS forwarder Lambda that forwards messages from member account topics to a central topic."
  type        = bool
  default     = false
}

variable "sns_forwarder_config" {
  description = "Configuration for the SNS cross-account forwarder Lambda. Only used when enable_sns_forwarder is true. dlq_arn replaces the module-managed dead-letter queue with an existing SQS queue; reserved_concurrent_executions caps parallel invocations (-1 removes the cap); log_retention_in_days is the retention of the function's own execution log group /aws/lambda/tlz-sns-forwarder, which the module declares (0 = never expire)."
  type = object({
    central_topic_arn              = string
    kms_key_arn                    = optional(string, null)
    source_topic_arns              = optional(list(string), [])
    dlq_arn                        = optional(string, null)
    reserved_concurrent_executions = optional(number, 10)
    log_retention_in_days          = optional(number, 365)
  })
  default = {
    central_topic_arn = ""
  }

  validation {
    condition     = var.sns_forwarder_config.central_topic_arn == "" || can(regex("^arn:", var.sns_forwarder_config.central_topic_arn))
    error_message = "sns_forwarder_config.central_topic_arn must be empty or a valid SNS topic ARN (starting with 'arn:') for cross-account alert forwarding."
  }

  validation {
    condition     = var.sns_forwarder_config.dlq_arn == null || can(regex("^arn:", var.sns_forwarder_config.dlq_arn))
    error_message = "sns_forwarder_config.dlq_arn must be null (module-managed queue) or a valid SQS queue ARN (starting with 'arn:')."
  }

  validation {
    condition     = var.sns_forwarder_config.reserved_concurrent_executions == -1 || var.sns_forwarder_config.reserved_concurrent_executions >= 1
    error_message = "sns_forwarder_config.reserved_concurrent_executions must be -1 (no cap) or >= 1. A value of 0 would disable the forwarder entirely and silently drop every alert."
  }

  # CloudWatch accepts only this fixed set of retention values; 0 means never
  # expire. Any other number is rejected at apply time.
  validation {
    condition = contains(
      [0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.sns_forwarder_config.log_retention_in_days
    )
    error_message = "sns_forwarder_config.log_retention_in_days must be one of the CloudWatch retention values: 0 (never expire), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

# --- SecurityHub EventBridge Custom Rules ---

variable "securityhub_eventbridge_rules" {
  description = "List of SecurityHub EventBridge rule definitions. Each rule creates an EventBridge rule and target. Use __CW_LOG_GROUP_ARN__ in target_arn to reference the log group /aws/securityhub/findings, which must then be declared in cloudwatch_log_groups."
  type = list(object({
    name          = string
    description   = optional(string, "")
    event_pattern = string
    target_arn    = string
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.securityhub_eventbridge_rules :
      length(r.name) > 0 && length(r.event_pattern) > 0
    ])
    error_message = "Each securityhub_eventbridge_rules entry must have a non-empty name and event_pattern."
  }

  # The placeholder resolves to a log group of this module. Without that log
  # group the placeholder would reach EventBridge unresolved, and AWS would
  # reject the target.
  validation {
    condition = (
      length([
        for r in var.securityhub_eventbridge_rules :
        r.name if r.target_arn == "__CW_LOG_GROUP_ARN__"
      ]) == 0 ||
      contains([for lg in var.cloudwatch_log_groups : lg.name], "/aws/securityhub/findings")
    )
    error_message = "A securityhub_eventbridge_rules target_arn of __CW_LOG_GROUP_ARN__ requires an entry named /aws/securityhub/findings in cloudwatch_log_groups."
  }

  # An EventBridge target identifies the log group WITHOUT the ":*" suffix;
  # the module appends ":*" itself where the resource policy needs it. A
  # user-supplied ARN already carrying the suffix would produce ":*:*" in the
  # policy and an invalid target ARN — reject it at plan time.
  validation {
    condition = alltrue([
      for r in var.securityhub_eventbridge_rules :
      !endswith(r.target_arn, ":*")
    ])
    error_message = "A securityhub_eventbridge_rules target_arn must not end in \":*\" — supply the plain resource ARN; the module appends \":*\" where the CloudWatch Logs resource policy requires it."
  }
}

# --- Break-Glass Usage Alarm ---

variable "enable_break_glass_alarm" {
  description = "Create the break-glass usage alarm: a metric filter on the CloudTrail log group counting API events of IAM users with the break-glass prefix, and an alarm that notifies the configured targets on the first event. The users themselves live in modules/iam (enable_break_glass)."
  type        = bool
  default     = false
}

variable "break_glass_alarm_config" {
  description = "Break-glass alarm wiring (required when enable_break_glass_alarm is true). alarm_actions must name at least one target — a silent break-glass alarm defeats its purpose. user_prefix must match break_glass_config.user_prefix of modules/iam. alarm_name and metric_filter_name default to the account-wide production name break-glass-usage: CloudWatch PutMetricAlarm and PutMetricFilter are UPSERTs keyed by name, so a live apply-test that enables this alarm must override both with test-scoped names (tlz-l4test-), or `terraform test`'s teardown deletes the live alarm/filter."
  type = object({
    alarm_actions      = list(string)
    log_group_name     = optional(string, "/aws/cloudtrail/tlz-org-trail")
    user_prefix        = optional(string, "tlz-break-glass")
    metric_namespace   = optional(string, "TLZ/Security")
    metric_name        = optional(string, "BreakGlassUsage")
    threshold          = optional(number, 1)
    alarm_name         = optional(string, "break-glass-usage")
    metric_filter_name = optional(string, "break-glass-usage")
  })
  default = null

  validation {
    condition     = !var.enable_break_glass_alarm || var.break_glass_alarm_config != null
    error_message = "enable_break_glass_alarm requires break_glass_alarm_config (at least one alarm_actions target)."
  }

  validation {
    condition = (
      var.break_glass_alarm_config == null
      || try(length(var.break_glass_alarm_config.alarm_actions) > 0, false)
    )
    error_message = "break_glass_alarm_config.alarm_actions must name at least one target when the alarm is enabled — a break-glass sign-in that notifies nobody defeats the alarm's purpose."
  }

  validation {
    condition = (
      var.break_glass_alarm_config == null
      || alltrue([
        for target in var.break_glass_alarm_config.alarm_actions :
        can(regex("^arn:", target))
      ])
    )
    error_message = "Each break_glass_alarm_config.alarm_actions entry must be an ARN (for example an SNS topic ARN)."
  }

  validation {
    condition = (
      var.break_glass_alarm_config == null
      || can(regex("^[a-zA-Z0-9+=,.@_-]+$", var.break_glass_alarm_config.user_prefix))
    )
    error_message = "break_glass_alarm_config.user_prefix must contain only alphanumeric characters and +=,.@_- characters (IAM user name character set)."
  }
}

variable "lambda_environment_kms_key_arn" {
  type        = string
  default     = ""
  description = "Customer-managed KMS key that encrypts the environment variables of this module's two Lambda functions (the log-group onboarding automation and the SNS forwarder). Empty — the default — leaves the variables encrypted with the AWS-managed Lambda key, the module default: the plan is unchanged for anyone who does not set it. When set, the key ARN reaches both functions AND the module grants each function's execution role kms:Decrypt on exactly that key, because without it a function cannot read its own variables at cold start and every invocation fails. A customer-managed key carries a monthly charge; the AWS-managed key does not. The deploying identity additionally needs kms:Encrypt on the key at apply time — that grant lives in the key policy, outside this module."

  validation {
    condition     = var.lambda_environment_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.lambda_environment_kms_key_arn))
    error_message = "lambda_environment_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}
