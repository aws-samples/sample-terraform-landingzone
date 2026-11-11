# Monitoring Module

CloudWatch Dashboards, SNS Alerting, and EventBridge rules for landing zone observability.

The alerts topic's policy and its CMK admit `budgets.amazonaws.com`, so an
AWS Budgets notification can be subscribed to the topic — an operator opt-in:
the shipped example wires budget notifications by e-mail, not SNS.

The module runs twice in the shipped stacks: in the management account
(`stacks/management/monitoring`, everything) and — with
`security_finding_consumers_in_audit` in `env/common.hcl`, default true — in
the Audit account (`stacks/audit/monitoring`, the alerting part only: GuardDuty
and Security Hub EventBridge rules, SNS topics and key, the configured log
groups and the findings dashboard). The Audit account is the delegated
administrator of GuardDuty and Security Hub, so its EventBridge bus carries
every member account's findings; the management bus carries only the
management account's own. The EventBridge rules of this module are
account-local and need no further input for that.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `sns_kms_encryption` | Encrypt every SNS topic of this module (the fallback `alerts` topic and the per-severity topics alike) with a dedicated customer-managed KMS key. `true` is the default; `false` leaves the topics with **no** server-side encryption — not with the AWS-managed `aws/sns` key, which cannot carry the CloudWatch/EventBridge/Budgets publisher grants these topics need. The key policy (`configurations/policies/monitoring/sns-kms-key-policy.json`) already grants `kms:Decrypt`/`kms:GenerateDataKey*` to those same three publishers, so the default does not block alarm delivery | `bool` | `true` | no |
| `sns_kms_alias_name` | Alias of that dedicated key. The default is the production alias; a live apply-test that enables `sns_kms_encryption` overrides it with an `alias/tlz-l4test-` value, because `CreateAlias` fails on an existing alias — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"alias/tlz-sns-encryption"` | no |
| `guardduty_detector_id` | GuardDuty detector ID for dashboard | `string` | `""` | no |
| `config_aggregator_name` | Config aggregator name for dashboard | `string` | `""` | no |
| `cloudtrail_arn` | CloudTrail ARN for dashboard | `string` | `""` | no |
| `sns_email_targets` | Email addresses for alerting | `list(string)` | `[]` | no |
| `sns_lambda_targets` | Lambda ARNs for alerting | `list(string)` | `[]` | no |
| `alert_on_severity` | Severity threshold for GuardDuty findings | `string` | `"HIGH"` | no |
| `alerts_topic_name` | Name of the central alerts topic of the single-topic form (while `sns_topics` is empty). The default is the production name; because `CreateTopic` is an upsert, a live apply-test overrides it with a `tlz-l4test-` name so teardown cannot delete the live alerting topic. Must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-landing-zone-alerts"` | no |
| `guardduty_findings_rule_name` | Name of the EventBridge rule routing GuardDuty findings to that topic (single-topic form). The default is the production name; because `PutRule` is an upsert, a live apply-test overrides it with a `tlz-l4test-` name. Must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-guardduty-findings-alert"` | no |
| `sns_topics` | SNS topics with severity-based routing. One topic per severity level is created together with the EventBridge rules that route GuardDuty findings to it; when empty, `sns_email_targets` drives the single-topic form instead. An optional `name` per entry overrides the derived topic name `tlz-alerts-<severity>`; an optional `rule_name` overrides the derived routing-rule name `tlz-guardduty-<severity>-findings` and must stay inside `tlz-` — because `PutRule` is an upsert, a live apply-test sets a `tlz-l4test-` `rule_name` (see [Upsert-safe resource names](#upsert-safe-resource-names)). A `deployment_targets` entry is accepted but reported by a `check` block, because the module cannot create providers for other accounts | `list(object)` | `[]` | no |
| `cloudwatch_metric_filters` | Log metric filters to create. `default_value` optionally names the value reported for periods in which logs are ingested but nothing matches (see [Metric filter defaults and log group protection](#metric-filter-defaults-and-log-group-protection)). A `deployment_targets` entry is accepted but reported by a `check` block | `list(object)` | `[]` | no |
| `cloudwatch_alarms` | Metric alarms to create. An entry with empty `alarm_actions` inherits the module's alerting topic when that topic exists (see [Alarms inherit the alerting topic](#alarms-inherit-the-alerting-topic)). A `deployment_targets` entry is accepted but reported by a `check` block | `list(object)` | `[]` | no |
| `eventbridge_default_bus_policy` | Resource policy for the default EventBridge bus, as a JSON document. `null` leaves the bus without a policy | `string` | `null` | no |
| `dashboard_name` | Name of the Landing Zone Health CloudWatch dashboard. The default is the production name; because `PutDashboard` is an upsert, a live apply-test overrides it with a `tlz-l4test-` name so teardown cannot delete the real dashboard (see [Upsert-safe resource names](#upsert-safe-resource-names)) | `string` | `"TLZ-Landing-Zone-Health"` | no |
| `enable_diagnostics_dashboard` | Extend the health dashboard with the diagnostic widgets described under [Landing Zone Health Dashboard](#landing-zone-health-dashboard) | `bool` | `true` | no |
| `central_log_bucket_name` | Name of the central log bucket whose storage metrics the diagnostic widgets show. Empty omits that widget | `string` | `""` | no |
| `cloudwatch_log_groups` | Log groups to create. `skip_destroy` optionally protects a group and its data from deletion through this configuration (see [Metric filter defaults and log group protection](#metric-filter-defaults-and-log-group-protection)) | `list(object)` | `[]` | no |
| `enable_log_group_onboarding` | Catch every successful `CreateLogGroup` call (via CloudTrail) with an EventBridge rule and apply the landing zone defaults to the new log group through a Lambda | `bool` | `false` | no |
| `log_group_onboarding` | Defaults the onboarding applies: retention, optionally a KMS key, optionally a subscription filter (`destination_arn` and `subscription_role_arn` as a pair) and exclusion patterns. `retention_in_days` and `kms_key_arn` also shape the function's own declared log group (see [Lambda execution log groups](#lambda-execution-log-groups)) | `object` | `{}` | no |
| `log_group_onboarding_rule_name` | Name of the EventBridge rule that catches `CreateLogGroup` calls for the onboarding. The default is the production name; because `PutRule` is an upsert, a live apply-test overrides it with a `tlz-l4test-` name. Must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-log-group-onboarding"` | no |
| `log_group_onboarding_dlq_name` | Name of the SQS dead-letter queue for onboarding events the Lambda still fails after its retries. The default is the production name; because SQS `CreateQueue` is idempotent for identical attributes (it returns an existing queue instead of failing), a live apply-test overrides it with a `tlz-l4test-` name. The Lambda's `sqs:SendMessage` grant follows the name. Not confined to `tlz-` — no guardrail covers an SQS namespace — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-log-group-onboarding-dlq"` | no |
| `sns_forwarder_dlq_name` | Name of the forwarder Lambda's module-managed dead-letter queue (while `sns_forwarder_config.dlq_arn` is null). Same contract as `log_group_onboarding_dlq_name`: SQS `CreateQueue` adopts an identical existing queue, so a live apply-test overrides it with a `tlz-l4test-` name; the forwarder policy's `sqs:SendMessage` grant follows it. Not pinned to `tlz-` | `string` | `"tlz-sns-forwarder-dlq"` | no |
| `enable_securityhub_cloudwatch_forwarding` | Forward Security Hub findings to a CloudWatch log group through an EventBridge rule | `bool` | `false` | no |
| `securityhub_severity_filter` | Severity labels the forwarding rule accepts. An empty list forwards every severity | `list(string)` | `[]` | no |
| `securityhub_findings_log_group_name` | Name of the Security Hub findings log group. The default is the production name | `string` | `"/aws/events/securityhub-findings"` | no |
| `securityhub_findings_log_retention` | Retention in days of the Security Hub findings log group | `number` | `365` | no |
| `securityhub_findings_log_kms_key_id` | KMS key that encrypts the Security Hub findings log group. `null` uses the CloudWatch Logs default encryption | `string` | `null` | no |
| `securityhub_findings_rule_name` | Name of the EventBridge rule that forwards Security Hub findings to that log group (created with `enable_securityhub_cloudwatch_forwarding`). The default is the production name; because `PutRule` is an upsert, a live apply-test overrides it with a `tlz-l4test-` name. Must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-securityhub-findings-to-cloudwatch"` | no |
| `securityhub_eventbridge_log_policy_name` | Name of the CloudWatch Logs resource policy that lets EventBridge deliver forwarded Security Hub findings (created with `enable_securityhub_cloudwatch_forwarding`). Overridable because `PutResourcePolicy` is an upsert — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-securityhub-eventbridge-log-policy"` | no |
| `securityhub_custom_rules_log_policy_name` | Name of the CloudWatch Logs resource policy for `securityhub_eventbridge_rules` targeting a log group (created only when a rule targets CloudWatch). Overridable because `PutResourcePolicy` is an upsert — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-securityhub-custom-rules-eventbridge-to-cw"` | no |
| `organization_id` | Organization ID that restricts the EventBridge bus policy to the own organization. Empty drops that condition | `string` | `""` | no |
| `enable_sns_forwarder` | Create the forwarder Lambda that relays messages from member account topics to a central topic | `bool` | `false` | no |
| `sns_forwarder_config` | Central topic the forwarder Lambda writes to, plus optional `dlq_arn` (existing SQS queue instead of the module-managed dead-letter queue), `reserved_concurrent_executions` (default `10`, `-1` removes the cap) and `log_retention_in_days` (default `365`) for the function's own declared log group (see [Lambda execution log groups](#lambda-execution-log-groups)). Read only when `enable_sns_forwarder` is set | `object` | `{ central_topic_arn = "" }` | no |
| `securityhub_eventbridge_rules` | Security Hub EventBridge rules with their targets. The placeholder `__CW_LOG_GROUP_ARN__` in `target_arn` refers to the log group `/aws/securityhub/findings`, which then has to be declared in `cloudwatch_log_groups` | `list(object)` | `[]` | no |
| `enable_break_glass_alarm` | Create the break-glass usage alarm described under [Break-glass usage alarm](#break-glass-usage-alarm) | `bool` | `false` | no |
| `break_glass_alarm_config` | Wiring of that alarm: at least one `alarm_actions` target (mandatory), the CloudTrail log group (default `/aws/cloudtrail/tlz-org-trail`), the user prefix matching `break_glass_config.user_prefix` of modules/iam (default `tlz-break-glass`), metric namespace/name and threshold, and `alarm_name`/`metric_filter_name` (both default `break-glass-usage`, overridable because the alarm and metric filter upsert by name — see [Upsert-safe resource names](#upsert-safe-resource-names)) | `object` | `null` | no |

## Break-glass usage alarm

The alerting half of the break-glass package (users: modules/iam,
[Break-glass access](../iam/README.md#break-glass-access)). Behind
`enable_break_glass_alarm` (default `false`) a metric filter on the
CloudTrail log group counts every API event whose caller is an IAM user with
the break-glass prefix — `{ ($.userIdentity.type = "IAMUser") &&
($.userIdentity.userName = "<user_prefix>*") }` — and an alarm notifies the
configured targets on the first event. `alarm_actions` is mandatory when the
switch is on: a break-glass sign-in that notifies nobody defeats the alarm's
purpose. The filter reads the organization trail's log group, which exists as
long as `cloudwatch_log_group_retention` of the logging module is not null.

```hcl
enable_break_glass_alarm = true
break_glass_alarm_config = {
  alarm_actions = ["arn:aws:sns:eu-central-1:111111111111:tlz-alerts"]
  # log_group_name, user_prefix, namespace, name, threshold: defaults
}
```

## Upsert-safe resource names

Several APIs this module calls are **upserts**, not create-only: SNS
`CreateTopic`, EventBridge `PutRule`, CloudWatch `PutDashboard`,
`PutMetricAlarm`, `PutMetricFilter` and CloudWatch Logs `PutResourcePolicy`
all succeed against an existing resource of the same name, adopting it rather
than failing. SQS `CreateQueue` behaves the same way in effect: it is
**idempotent** for an existing queue with identical attributes and returns
that queue instead of an error. That is fine in production, but dangerous for
a live `terraform test`: an apply-test that used a fixed account-wide name
would silently adopt the real resource, and the test's automatic teardown
would then **delete the live one** — for the alerts topic, the resource every
alarm and rule of the account delivers to. To keep a live plan empty in
production while letting a test scope its own resources, the account-wide
name of each upsert-prone resource is a variable with the production name as
its default:

| Variable | Default | Resource |
|---|---|---|
| `alerts_topic_name` | `tlz-landing-zone-alerts` | `aws_sns_topic.alerts` |
| `guardduty_findings_rule_name` | `tlz-guardduty-findings-alert` | `aws_cloudwatch_event_rule.guardduty_findings` |
| `securityhub_findings_rule_name` | `tlz-securityhub-findings-to-cloudwatch` | `aws_cloudwatch_event_rule.securityhub_findings` |
| `log_group_onboarding_rule_name` | `tlz-log-group-onboarding` | `aws_cloudwatch_event_rule.log_group_onboarding` |
| `log_group_onboarding_dlq_name` | `tlz-log-group-onboarding-dlq` | `aws_sqs_queue.log_group_onboarding_dlq` (and the Lambda policy's `sqs:SendMessage` grant) |
| `sns_topics[*].rule_name` | derived `tlz-guardduty-<severity>-findings` | `aws_cloudwatch_event_rule.guardduty_severity[<severity>]` |
| `sns_forwarder_dlq_name` | `tlz-sns-forwarder-dlq` | `aws_sqs_queue.sns_forwarder_dlq` (same SQS semantics; the forwarder policy's grant follows the name) |
| `sns_kms_alias_name` | `alias/tlz-sns-encryption` | `aws_kms_alias.sns` |
| `dashboard_name` | `TLZ-Landing-Zone-Health` | `aws_cloudwatch_dashboard.landing_zone` |
| `securityhub_eventbridge_log_policy_name` | `tlz-securityhub-eventbridge-log-policy` | `aws_cloudwatch_log_resource_policy.securityhub_eventbridge` |
| `securityhub_custom_rules_log_policy_name` | `tlz-securityhub-custom-rules-eventbridge-to-cw` | `aws_cloudwatch_log_resource_policy.securityhub_custom_rules_eventbridge` |
| `break_glass_alarm_config.alarm_name` | `break-glass-usage` | `aws_cloudwatch_metric_alarm.break_glass` |
| `break_glass_alarm_config.metric_filter_name` | `break-glass-usage` | `aws_cloudwatch_log_metric_filter.break_glass` |

The KMS alias is the one create-only entry: `CreateAlias` fails with
`AlreadyExistsException` instead of adopting, so the live alias is never
deleted by a test — but under a fixed name a live apply-test could not
enable `sns_kms_encryption` at all. The topic, the four rule names (the three
fixed ones and `sns_topics[*].rule_name`) and the alias
must keep the `tlz-` prefix (`alias/tlz-` for the alias): the organization
guardrails protect only `arn:*:sns:*:*:tlz-*` and `arn:*:events:*:*:rule/tlz-*`
from tampering, and the module's validation refuses a name outside that
namespace. The DLQ is the exception: no organization policy protects an SQS
namespace (the resource control policies' `sqs:*` statements apply to every
queue regardless of name), so `log_group_onboarding_dlq_name` is validated
against the SQS naming rule only, like `dashboard_name`. The two CloudWatch
Logs resource policies are account-scoped with a limit of ten per account, so
a leaked test policy would also consume a scarce slot.

**Leave these at their defaults in production** — a changed default is a
destroy/create of the live resource (for the topic, subscriptions included).
A live apply-test sets a `tlz-l4test-`
value instead — for **every** name in the table, including the ones whose
resource is not deployed in the account. "Not deployed" is not a safety
property: a deployment can invalidate it overnight (the onboarding DLQ exists the day
`enable_log_group_onboarding` is set), and a test that asserts a resource
under its default name becomes that resource's deletion the moment it does.

Naming cannot make every resource test-safe. `aws_cloudwatch_event_bus_policy`
on the `default` bus is an account singleton — one policy per bus, no name of
its own — so a live apply-test with `eventbridge_default_bus_policy` set would
always overwrite the account's policy and its teardown would remove it. That
setting stays untestable against a live account whatever the test calls it.
The per-severity rules `tlz-guardduty-<severity>-findings` derive their names
from the severity, not from `sns_topics[*].name`; a live test that sets
`sns_topics` collides with a live per-severity deployment of the same
severity (a deployment that uses the single-topic form has no such rules).

## Landing Zone Health Dashboard

The dashboard `TLZ-Landing-Zone-Health` consists of two halves.

The **base widgets** are always created: heading, GuardDuty findings, CloudTrail
events and Config compliance.

The **diagnostic widgets** are governed by `enable_diagnostics_dashboard`
(default `true`): non-compliant Config rules, Security Hub findings by severity,
GuardDuty trend over seven days, CloudTrail management event volume and — as soon
as `central_log_bucket_name` is set — the storage metrics of the central log
bucket. With `enable_diagnostics_dashboard = false` only the base widgets remain.

The four identifiers `guardduty_detector_id`, `config_aggregator_name`,
`cloudtrail_arn` and `central_log_bucket_name` name the source of the displayed
figures. Where CloudWatch offers a matching dimension the value becomes a
dimension (`DetectorId` for GuardDuty, `BucketName` for S3); `AWS/Config` and
`AWS/CloudTrail` have none, so the aggregator name and the trail name derived
from the ARN appear in the widget title. An empty identifier leaves the metric
undimensioned — the widget then shows the account-wide aggregate instead of an
unresolvable dimension value, and the S3 storage widget is omitted entirely.

### Diagnostic Dashboard Widgets (enable_diagnostics_dashboard)

`enable_diagnostics_dashboard` defaults to `true` and is meant to stay that way.
That is a deliberate, permanent exception to the project convention that an
`enable_*` toggle defaults to `false`.

The convention exists so that nothing with a cost or a security consequence
appears in an account without somebody asking for it. Neither applies here. The
toggle adds widgets to a dashboard that is created either way — it creates no
resource of its own, `aws_cloudwatch_dashboard.landing_zone` is a single resource
in both positions, dashboard widgets carry no charge, and no widget grants or
weakens an access path. What the toggle changes is how much of the landing zone's
own state an operator sees at a glance, and the useful default for that is "all
of it".

Switching the default to `false` would therefore buy no safety and cost
visibility: the diagnostic half would disappear from every installation that does
not set the value explicitly. Switching it off per installation stays possible and
is covered by the scenario `monitoring_diagnostics_dashboard_disabled` in
`tests/monitoring.tftest.hcl`.

## Outputs

| Name | Description |
|------|-------------|
| `dashboard_arn` | CloudWatch Dashboard ARN |
| `sns_topic_arn` | SNS Topic ARN for alerts |
| `metric_filter_names` | Map of metric filter name → filter name |
| `alarm_arns` | Map of alarm name → alarm ARN |
| `severity_topic_arns` | Map of severity level → SNS topic ARN (empty when the single-topic fallback is used) |
| `sns_kms_key_arn` | ARN of the dedicated SNS KMS key (empty when `sns_kms_encryption` is false) |
| `sns_forwarder_lambda_arn` | ARN of the SNS forwarder Lambda function (empty when disabled) |
| `sns_forwarder_logs_kms_key_arn` | ARN of the KMS key encrypting the SNS forwarder Lambda's execution log group (empty when disabled) |
| `securityhub_findings_log_group_arn` | ARN of the SecurityHub findings CloudWatch Log Group |

## Resources

The module creates the resource types below, all of them in `main.tf` (the
break-glass usage alarm in `break-glass-alarm.tf`). Which of them a run
actually creates depends on the inputs — the `enable_*` toggles and the
collections that are filled.

- `aws_kms_key`
- `aws_kms_alias`
- `aws_sns_topic`
- `aws_sns_topic_policy`
- `aws_sns_topic_subscription`
- `aws_cloudwatch_dashboard`
- `aws_cloudwatch_event_rule`
- `aws_cloudwatch_event_target`
- `aws_cloudwatch_event_bus_policy`
- `aws_cloudwatch_log_metric_filter`
- `aws_cloudwatch_metric_alarm`
- `aws_cloudwatch_log_group`
- `aws_cloudwatch_log_resource_policy`
- `aws_lambda_function`
- `aws_iam_role`
- `aws_iam_role_policy`
- `aws_lambda_permission`
- `aws_sqs_queue`

## Metric filter defaults and log group protection

Per entry of `cloudwatch_metric_filters`, `default_value` (a number, default
`null`) is reported to the metric during periods in which the log group
ingests events but none matches the filter pattern. Setting it to `0` turns
"no hits" into an explicit zero data point, so alarms with strict
missing-data handling can distinguish "nothing matched" from "no logs at
all". Without it the metric stays silent in such periods.

Per entry of `cloudwatch_log_groups`, `skip_destroy` (default `false`)
protects the group and its log data from deletion through this
configuration: when the entry is removed (or the deployment destroyed), the
group is only dropped from management and stays in the account, including
all stored events. Use it for audit-relevant groups whose retention must
outlive the configuration entry.

```hcl
cloudwatch_metric_filters = [
  {
    name             = "unauthorized-api-calls"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.errorCode = \"*UnauthorizedOperation\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "UnauthorizedApiCalls"
    default_value    = 0
  }
]

cloudwatch_log_groups = [
  {
    name              = "/tlz/security/audit"
    retention_in_days = 365
    skip_destroy      = true
  }
]
```

## Alarms inherit the alerting topic

Per entry of `cloudwatch_alarms`, an empty `alarm_actions` inherits the ARN
of the module's own alerting topic (`aws_sns_topic.alerts`, name
`alerts_topic_name`) whenever that topic exists — the topic is created
exactly when `sns_topics` is empty. The shipped CIS alarms in
`configurations/base/base.tfvars` deliberately carry no `alarm_actions`,
because the topic ARN is unknown until apply and the base layer is shipped
content; without the inheritance they would change state and notify nobody.
The topic's resource policy already admits CloudWatch alarm delivery
(`AllowCloudWatchAlarmsPublish`), none of the shipped alarms watches the
topic itself (all observe `TLZ/Security` filter metrics, so no delivery
loop), and an alarm action fires once per state transition in any case.
Non-empty `alarm_actions` are used exactly as given. With severity topics
configured (`sns_topics` non-empty) no single alerting topic exists, the
module cannot know which severity an alarm belongs to, and `alarm_actions`
stays empty — the `cloudwatch_alarms_notify_nobody` check then reports each
such alarm and names the remedy.

## Log group onboarding

`cloudwatch_log_groups` manages the groups the landing zone declares.
Services create further log groups on their own, and those carry neither
retention nor key nor forwarding until someone notices them.
`enable_log_group_onboarding` closes that gap: an EventBridge rule catches
every successful `CreateLogGroup` call (recorded by CloudTrail) and a Lambda
(`lambda/log_group_onboarding.py`, packaged via `archive_file`) applies the
defaults from `log_group_onboarding` to the new group:

- `retention_in_days` — always applied (default 365).
- `kms_key_arn` — associated when set. The key policy must allow CloudWatch
  Logs to use the key.
- `destination_arn` + `subscription_role_arn` — attached as a subscription
  filter when set; the two come as a pair. `filter_pattern` narrows what the
  filter forwards.
- `excluded_log_group_patterns` — groups the automation leaves untouched:
  exact names or prefixes with a trailing `*`.

Failed onboarding events land in a dead-letter queue
(`log_group_onboarding_dlq_name`, default `tlz-log-group-onboarding-dlq`)
after the automatic retries, so an unonboarded group never disappears
silently. The function's own execution log group is declared by the module
and carries the same `retention_in_days` and `kms_key_arn` — see
[Lambda execution log groups](#lambda-execution-log-groups), including the
import step an installation whose function has already run must take.

```hcl
enable_log_group_onboarding = true
log_group_onboarding = {
  retention_in_days           = 90
  excluded_log_group_patterns = ["/aws/lambda/*"]
}
```

## Lambda execution log groups

Lambda creates a function's execution log group, `/aws/lambda/<function
name>`, implicitly on the first invocation when nothing has declared it. Such
an implicit group sits outside the Terraform state, carries no retention and
no key, and is never destroyed with the stack — and, for the onboarding
function, its own `CreateLogGroup` call is an event of the very rule the
function serves, so the function would onboard itself. Both groups are
therefore managed resources, each created behind the toggle of its function:

| Log group | Resource | Retention | Key |
|---|---|---|---|
| `/aws/lambda/tlz-log-group-onboarding` | `aws_cloudwatch_log_group.log_group_onboarding` | `log_group_onboarding.retention_in_days` (default `365`) | `log_group_onboarding.kms_key_arn` when set |
| `/aws/lambda/tlz-sns-forwarder` | `aws_cloudwatch_log_group.sns_forwarder` | `sns_forwarder_config.log_retention_in_days` (default `365`) | `aws_kms_key.sns_forwarder_logs` (created when `enable_sns_forwarder` is set) |

The names derive from the functions, so a group can never disagree with its
function. The resources that let anything invoke a function — the EventBridge
target of the onboarding rule, the SNS subscriptions of the forwarder — depend
on the group, so no invocation can precede it and create the group
implicitly. For the onboarding function the values are the ones the automation
applies to every other group — and the ones a self-onboarding would apply to
this group wherever no exclusion pattern keeps it off;
`excluded_log_group_patterns` governs what the automation touches and does
not exempt this module-owned resource — the README example above excludes
`/aws/lambda/*` and the function's group is bounded regardless. Neither group sets `skip_destroy`: a destroy of the stack
(or a live test's teardown) removes them with their function. The functions'
execution roles keep their `logs:CreateLogGroup` grant; Lambda does not need
it while the group exists, and removing it belongs to the policy templates.
What the declaration does not change is the rule's reach: Terraform's own
`CreateLogGroup` of the onboarding function's group is itself an event of the
rule, so on a first apply the automation may still onboard that group once —
with the retention and key it already carries (no drift in the plan) and,
when a destination is configured, the subscription filter the module does not
manage on this group. Narrowing what the rule matches is the event pattern's
concern, not this resource's.

**A group that already exists outside the state must be imported before the
apply.** In any account where a function was invoked before its group was
declared, the log group exists outside the state. CloudWatch Logs
`CreateLogGroup` is create-only, so the first apply that declares it fails with
`ResourceAlreadyExistsException` for that group — loudly, before anything is
adopted or deleted, and not until the function has actually run: an account
where the toggle was on but the function was never invoked has no group and
needs nothing. Import the existing group into the monitoring stack (the module
is the stack's root module, so the address carries no `module.` prefix), then
apply:

```sh
cd stacks/management/monitoring
terragrunt import 'aws_cloudwatch_log_group.log_group_onboarding[0]' /aws/lambda/tlz-log-group-onboarding
terragrunt import 'aws_cloudwatch_log_group.sns_forwarder[0]' /aws/lambda/tlz-sns-forwarder
```

Import only the groups of the functions that have run — an import of a group
that does not exist fails with the Terraform error message, as it should. The
plan after the import shows the declared retention (and key) being applied to
the imported group: for a group the onboarding had already onboarded with the
same values, that is no change. The adoption list of
[Resource Adoption](../../docs/resource-adoption.md) cannot carry these
imports, because the monitoring stack emits no `adoption-imports.tf`;
the CLI import above is the path. A fresh deployment that enables a toggle for
the first time needs no import.

## Usage Example

```hcl
module "monitoring" {
  source = "./modules/monitoring"

  guardduty_detector_id  = module.security.guardduty_detector_id
  config_aggregator_name = module.logging.config_aggregator_name
  cloudtrail_arn         = module.logging.cloudtrail_arn

  sns_email_targets = ["ops-team@example.com"]
  alert_on_severity = "HIGH"
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
