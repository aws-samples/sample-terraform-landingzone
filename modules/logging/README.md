# Logging Module

Centralized logging infrastructure for the Landing Zone: org-wide CloudTrail, AWS Config recorder/aggregator, and a KMS-encrypted central S3 log bucket.

Every resource, the central log bucket included, is created in the account of the provider the caller passes in. The `management/logging` stack of this repository has no `cross_account.hcl`, so it runs with the management account's provider and the central log bucket lives in the **management account**. `log_archive_account_id` names the bucket (`tlz-central-logs-<log-archive-account>-<region>`); it does not place it in the Log-Archive account. The central bucket and the log bucket key grant `delivery.logs` (VPC flow logs and other vended logs) for the deploying account only, scoped by `aws:SourceAccount` and `aws:SourceArn`.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `log_archive_account_id` | Account ID for centralized logging | `string` | — | yes |
| `organization_id` | AWS Organizations ID | `string` | — | yes |
| `log_retention_days` | S3 lifecycle retention in days | `number` | `365` | no |
| `cloudwatch_log_group_retention` | CloudWatch Log Group retention in days (null = no log group) | `number` | `null` | no |
| `kms_key_administrators` | ARNs for KMS key administration | `list(string)` | `[]` | no |
| `force_destroy` | Allow the log buckets to be destroyed while they still hold objects. For throw-away environments | `bool` | `false` | no |
| `cloudtrail_management_events` | Record management events in the organization trail | `bool` | `true` | no |
| `cloudtrail_s3_data_events` | Record S3 data events in the organization trail. Switching it off lowers cost and loses object-level history | `bool` | `true` | no |
| `cloudtrail_lambda_data_events` | Record Lambda data events in the organization trail | `bool` | `true` | no |
| `cloudtrail_insights` | Insight types to enable on the trail: `ApiCallRateInsight`, `ApiErrorRateInsight` | `list(string)` | `[]` | no |
| `s3_lifecycle_rules` | Retention per prefix (`cloudtrail/`, `config/`, `s3-access-logs/`) on the central bucket. `null` applies the single `log_retention_days` value to every object | `object` | `null` | no |
| `s3_replication_config` | Cross-region replication of the central log bucket, including re-encryption at the destination. `{}` leaves the bucket unreplicated | `object` | `{}` | no |
| `cloudtrail_account_trails` | Further account-level trails alongside the organization trail, each with region scope, management event scope, Insight types and optional CloudWatch delivery | `list(object)` | `[]` | no |
| `cloudtrail_org_trail_settings` | Region scope of the organization trail: multi-region recording and global service events. `{}` keeps both switched on | `object` | `{}` | no |
| `cloudwatch_log_subscriptions` | Subscription filters on log groups. An empty `destination_arn` routes to the module's own Kinesis stream | `list(object)` | `[]` | no |
| `cloudwatch_log_exclusions` | Log group names or patterns that no subscription filter is attached to | `list(string)` | `[]` | no |
| `cloudwatch_log_exclusion_rules` | Structured exclusions beside the flat list: scope by account, organizational unit and region, exclude by name, prefix or entirely | `list(object)` | `[]` | no |
| `deployment_organizational_unit` | Organizational unit of the account this module deploys into. Read by the `organizational_units` selector of the exclusion rules | `string` | `""` | no |
| `cloudwatch_log_account_subscription` | Account-wide subscription filter policy covering every log group, minus what `selection_criteria` excludes | `object` | `{}` | no |
| `kinesis_pipeline_config` | Tuning of the CloudWatch-to-S3 archive pipeline: stream retention and capacity, delivery buffering, compression, file extension, error prefix and the optional record-processor Lambda. `{}` keeps the production values | `object` | `{}` | no |
| `cloudtrail_sns_topic_name` | Name of an SNS topic that the organization trail notifies. Empty creates no topic | `string` | `""` | no |
| `cloudtrail_org_trail_name` | Name of the organization trail. The default is the production name of the trail; its CloudWatch log group derives from it as `/aws/cloudtrail/<name>` and the central bucket policy scopes its CloudTrail grants to it. Overridable so a live apply-test can scope its own trail — see [Fixed resource names](#fixed-resource-names) | `string` | `"tlz-org-trail"` | no |
| `cloudtrail_cloudwatch_role_name` | Name of the IAM role the organization trail assumes to deliver into its CloudWatch log group (created with `cloudwatch_log_group_retention`). The default is the production name of the role | `string` | `"tlz-cloudtrail-cloudwatch-role"` | no |
| `config_aggregator_name` | Name of the organization-wide AWS Config aggregator. The default is the production name of the aggregator. `PutConfigurationAggregator` is an **upsert**: a live account carrying this name is silently adopted, so a live apply-test must override it with a test-scoped name — see [Fixed resource names](#fixed-resource-names) | `string` | `"tlz-org-config-aggregator"` | no |
| `config_aggregator_role_name` | Name of the IAM role the aggregator assumes to read the member accounts' recorders. The default is the production name of the role; the validation pins the `tlz-` namespace (the guardrail `ProtectIAMRoles` covers only `role/tlz-*`) | `string` | `"tlz-config-aggregator-role"` | no |
| `cloudtrail_cloudwatch_policy_name` | Name of the inline policy on that delivery role. The default is the production name of the policy | `string` | `"tlz-cloudtrail-cloudwatch-policy"` | no |
| `kinesis_stream_name` | Name of the Kinesis data stream of the CloudWatch-to-S3 pipeline. The default is the production name of the stream; must start with `tlz-` — see [Fixed resource names](#fixed-resource-names) | `string` | `"tlz-cw-to-s3-stream"` | no |
| `firehose_delivery_stream_name` | Name of the Firehose delivery stream that drains the Kinesis stream into the central log bucket. The default is the production name; must start with `tlz-` | `string` | `"tlz-cw-to-s3-delivery"` | no |
| `cw_to_kinesis_role_name` | Name of the IAM role CloudWatch Logs assumes to put subscription records onto the stream. The default is the production name of the role; must start with `tlz-` | `string` | `"tlz-cw-to-kinesis-role"` | no |
| `cw_to_kinesis_policy_name` | Name of the inline policy on that role. The default is the production name of the policy | `string` | `"tlz-cw-to-kinesis-policy"` | no |
| `firehose_delivery_role_name` | Name of the IAM role the delivery stream assumes to read the stream, write the bucket and invoke the optional processor. The default is the production name of the role; must start with `tlz-` | `string` | `"tlz-firehose-delivery-role"` | no |
| `firehose_delivery_policy_name` | Name of the inline policy on the delivery role. The default is the production name of the policy | `string` | `"tlz-firehose-delivery-policy"` | no |
| `firehose_processor_function_name` | Name of the optional record-processor Lambda (created with `kinesis_pipeline_config.lambda_processor.enabled`); its log group derives as `/aws/lambda/<name>` and its policy's logs grant follows it. The default is the production name of the function; must start with `tlz-` | `string` | `"tlz-cw-log-processor"` | no |
| `firehose_processor_role_name` | Name of the IAM role the processor Lambda runs as. The default is the production name of the role; must start with `tlz-` | `string` | `"tlz-cw-log-processor-role"` | no |
| `firehose_processor_policy_name` | Name of the inline policy on the processor role. The default is the production name of the policy | `string` | `"tlz-cw-log-processor-policy"` | no |
| `firehose_processor_log_retention_days` | Retention of the processor Lambda's own execution log group `/aws/lambda/<firehose_processor_function_name>`, which the module declares (`0` = never expire). See [Lambda execution log groups](#lambda-execution-log-groups) | `number` | `365` | no |
| `enable_elb_log_bucket` | Create a dedicated bucket for load balancer access logs, encrypted with Amazon S3-managed keys (SSE-S3): Application Load Balancer access logs support no other server-side encryption on the target bucket | `bool` | `false` | no |
| `bucket_name_prefix` | Leading segment, hyphen included, of every bucket name this module derives — the central log bucket, its replica, the access-logs, ELB-log and VPC-flow-log buckets. The default reproduces the production bucket names; must start with `tlz-`, end with a hyphen and stay within 15 characters. A live apply-test sets `tlz-l4test-` — see [Fixed resource names](#fixed-resource-names) | `string` | `"tlz-"` | no |
| `adopted_central_log_bucket_name` | Name of an existing bucket to run as the central log bucket. Empty derives tlz-central-logs-<log-archive-account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket | `string` | `""` | no |
| `adopted_access_logs_bucket_name` | Name of an existing bucket to run as the separate access logs bucket. Empty derives tlz-access-logs-<log-archive-account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket | `string` | `""` | no |
| `adopted_elb_log_bucket_name` | Name of an existing bucket to run as the ELB log bucket. Empty derives tlz-elb-logs-<account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket | `string` | `""` | no |
| `adopted_vpc_flow_logs_bucket_name` | Name of an existing bucket to run as the VPC flow logs bucket. Empty derives tlz-vpc-flow-logs-<account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket | `string` | `""` | no |
| `elb_log_bucket_lifecycle` | Expiration and archive transitions of the load balancer log bucket | `object` | `{}` | no |
| `enable_separate_access_logs_bucket` | Keep the access logs in a bucket of their own instead of in the central log bucket | `bool` | `false` | no |
| `enable_per_account_kms_keys` | Create an S3 key per account. Needed when the module is applied into member accounts | `bool` | `false` | no |
| `manage_config_recorder` | Create the Config recorder, delivery channel and recorder status. `false` leaves the account's single recorder slot to its current owner and applies the rest of the module beside it — see [Config recorder ownership](#config-recorder-ownership) | `bool` | `true` | no |
| `log_bucket_kms_alias` | Alias of the KMS key that encrypts the central log bucket, without the `alias/` prefix. The default is the production alias of the key — see [Fixed resource names](#fixed-resource-names) | `string` | `"tlz-central-logs"` | no |
| `management_kms_alias` | Alias of the dedicated management account KMS key (DynamoDB and SSM encryption), without the `alias/` prefix | `string` | `"tlz/management/kms"` | no |
| `cloudwatch_kms_alias` | Alias of the dedicated CloudWatch Logs KMS key, without the `alias/` prefix | `string` | `"tlz/cloudwatch/kms"` | no |
| `per_account_s3_kms_alias` | Alias of the per-account S3 KMS key (created with `enable_per_account_kms_keys`), without the `alias/` prefix | `string` | `"tlz/s3/kms"` | no |
| `use_config_service_linked_role` | Let the Config recorder use the service-linked role. When unset, `config_recorder_custom_role_arn` is used | `bool` | `true` | no |
| `config_recorder_custom_role_arn` | Role the Config recorder assumes. Required when `use_config_service_linked_role` is unset | `string` | `""` | no |
| `enable_cloudwatch_log_data_protection` | Mask sensitive data in log groups | `bool` | `false` | no |
| `cloudwatch_log_data_protection_log_groups` | Further log groups the masking covers. The trail's log group is always covered | `list(string)` | `[]` | no |
| `cloudwatch_log_data_protection_identifiers` | Data identifiers the masking looks for, by short name — the module builds the full ARN for the active partition. Region-bound identifiers carry a country suffix, for example `DriversLicense-DE` | `list(string)` | `["CreditCardNumber", "CreditCardExpiration", "CreditCardSecurityCode", "EmailAddress", "IpAddress", "AwsSecretKey", "OpenSshPrivateKey", "PgpPrivateKey", "PkcsPrivateKey", ]` | no |
| `ssm_associations` | State Manager associations, for inventory collection or any other document | `list(object)` | `[]` | no |
| `enable_s3_object_lock` | Protect the central log bucket against deletion and overwriting. Only possible while the bucket is created, never afterwards | `bool` | `false` | no |
| `s3_object_lock_config` | Mode and duration of the write protection. Read only when `enable_s3_object_lock` is set | `object` | `{}` | no |
| `enable_cloudtrail_lake` | Create an event data store that the trail's events can be queried in. Closed to new customers since 2026-05-31 — leave `false` unless this account onboarded CloudTrail Lake before the cutoff (a `check` warns when it is on) | `bool` | `false` | no |
| `cloudtrail_lake_config` | Settings of the event data store. `retention_days` accepts 7 to 2555 days | `object` | `{}` | no |
| `enable_vpc_flow_logs_bucket` | Create a dedicated bucket for VPC flow logs that replicates into the central log bucket | `bool` | `false` | no |
| `vpc_flow_logs_bucket_config` | Settings of the flow log bucket. Read only when `enable_vpc_flow_logs_bucket` is set | `object` | `{}` | no |
| `central_log_bucket_lifecycle_rules` | Full lifecycle rule set of the central log bucket. `null` keeps the rules derived from `log_retention_days` and `s3_lifecycle_rules` | `list(object)` | `null` | no |
| `access_logs_bucket_lifecycle_rules` | Full lifecycle rule set of the separate access logs bucket. `null` keeps the rule derived from `log_retention_days` | `list(object)` | `null` | no |
| `elb_log_bucket_lifecycle_rules` | Full lifecycle rule set of the load balancer log bucket. `null` keeps the rule derived from `elb_log_bucket_lifecycle` | `list(object)` | `null` | no |
| `vpc_flow_logs_bucket_lifecycle_rules` | Full lifecycle rule set of the flow log bucket. `null` keeps the rule derived from `vpc_flow_logs_bucket_config` | `list(object)` | `null` | no |
| `guardduty_export_prefix` | S3 prefix of the GuardDuty PutObject grant in the central log bucket policy. Carries the same value as the security module's `guardduty_export_prefix` — the publishing destination writes where this grant allows | `string` | `"guardduty/"` | no |
| `guardduty_root_export_cleanup` | Remediation of GuardDuty findings a broken-export workaround wrote to the bucket root. One lifecycle rule per detector account expires the objects under `AWSLogs/<account-id>/GuardDuty/`; empty `account_ids` reads the deploying account. `null` sets no rule | `object` | `null` | no |
| `central_log_bucket_policies` | Additional and overriding policies of the central log bucket and its KMS key. `{}` keeps the generated documents | `object` | `{}` | no |
| `access_logs_bucket_policies` | Additional and overriding policy of the separate access logs bucket. Requires `enable_separate_access_logs_bucket` | `object` | `{}` | no |
| `elb_log_bucket_policies` | Additional and overriding policy of the load balancer log bucket. Requires `enable_elb_log_bucket` | `object` | `{}` | no |
| `allow_bucket_policy_overrides` | Explicit confirmation that the `*_override` documents are intended — an override replaces an entire generated policy | `bool` | `false` | no |

## Fixed resource names

Several resources of this module carry an account-wide name that is
**create-only** at the API: `CreateTrail`, `CreateRole`, `CreateAlias` and
`CreateBucket` fail with an `AlreadyExists` error when a resource of the same
name exists. In production that is harmless — the names are stable. For a live
`terraform test` it is not: an apply-test applies the whole module, so every
unconditional resource must be creatable, and a fixed name collides with the
deployed stack before the test reaches its first assertion. Each such name is
therefore a variable with the production name as its default:

| Variable | Default | Resource |
|---|---|---|
| `cloudtrail_org_trail_name` | `tlz-org-trail` | `aws_cloudtrail.org_trail`; its log group derives as `/aws/cloudtrail/<name>`, and the three CloudTrail grants of the central bucket policy scope `aws:SourceArn` to it |
| `cloudtrail_cloudwatch_role_name` | `tlz-cloudtrail-cloudwatch-role` | `aws_iam_role.cloudtrail_cloudwatch` |
| `cloudtrail_cloudwatch_policy_name` | `tlz-cloudtrail-cloudwatch-policy` | `aws_iam_role_policy.cloudtrail_cloudwatch` |
| `config_aggregator_role_name` | `tlz-config-aggregator-role` | `aws_iam_role.config_aggregator` and its `AWSConfigRoleForOrganizations` attachment |
| `kinesis_stream_name` | `tlz-cw-to-s3-stream` | `aws_kinesis_stream.cw_to_s3` (name and `Name` tag) |
| `firehose_delivery_stream_name` | `tlz-cw-to-s3-delivery` | `aws_kinesis_firehose_delivery_stream.cw_to_s3` |
| `cw_to_kinesis_role_name` | `tlz-cw-to-kinesis-role` | `aws_iam_role.cw_to_kinesis` |
| `cw_to_kinesis_policy_name` | `tlz-cw-to-kinesis-policy` | `aws_iam_role_policy.cw_to_kinesis` |
| `firehose_delivery_role_name` | `tlz-firehose-delivery-role` | `aws_iam_role.firehose_delivery` |
| `firehose_delivery_policy_name` | `tlz-firehose-delivery-policy` | `aws_iam_role_policy.firehose_delivery` |
| `firehose_processor_function_name` | `tlz-cw-log-processor` | `aws_lambda_function.firehose_processor`; its log group derives as `/aws/lambda/<name>`, and the `CloudWatchLogsAccess` grant of its inline policy scopes to that group |
| `firehose_processor_role_name` | `tlz-cw-log-processor-role` | `aws_iam_role.firehose_processor` |
| `firehose_processor_policy_name` | `tlz-cw-log-processor-policy` | `aws_iam_role_policy.firehose_processor` |
| `log_bucket_kms_alias` | `tlz-central-logs` | `aws_kms_alias.log_bucket` (`alias/` is prepended) |
| `management_kms_alias` | `tlz/management/kms` | `aws_kms_alias.management` |
| `cloudwatch_kms_alias` | `tlz/cloudwatch/kms` | `aws_kms_alias.cloudwatch` |
| `per_account_s3_kms_alias` | `tlz/s3/kms` | `aws_kms_alias.per_account_s3` |
| `bucket_name_prefix` | `tlz-` | the five derived bucket names: `aws_s3_bucket.central_logs` (`<prefix>central-logs-<log-archive>-<region>`), `.replication_dest` (`<prefix>central-logs-replica-<log-archive>-<destination-region>`), `.access_logs` (`<prefix>access-logs-<log-archive>-<region>`), `.elb_logs` (`<prefix>elb-logs-<account>-<region>`), `.vpc_flow_logs` (`<prefix>vpc-flow-logs-<account>-<region>`) — see [The derived bucket family](#the-derived-bucket-family) |
| `adopted_vpc_flow_logs_bucket_name` | `""` → `<prefix>vpc-flow-logs-<account>-<region>` | `aws_s3_bucket.vpc_flow_logs` — the same empty-derives shape as the three `adopted_*` bucket names; a non-empty value wins over prefix and derivation |

### The upsert-named aggregator

One fixed name of this module is worse than a loud collision.
`PutConfigurationAggregator` is an **upsert**: it creates the aggregator of
that name or updates the existing one, and never fails on a name that exists.
Under the literal `tlz-org-config-aggregator` a live apply-test would report a
clean "create" while silently *adopting* the live organization-wide aggregator
— the resource the whole organization's compliance view hangs on — and
`terraform test`'s automatic teardown would then **delete** it, with the
test's own teardown proof listing that name as removed. The name is therefore
a variable as well:

| Variable | Default | Resource |
|---|---|---|
| `config_aggregator_name` | `tlz-org-config-aggregator` | `aws_config_configuration_aggregator.org` |

Naming genuinely fixes this one: aggregators are not an account singleton (the
live management account carries a legacy aggregator beside the `tlz-` one), so
a test-scoped name creates a second, disjoint aggregator that the teardown
removes alone. Contrast the recorder and delivery channel, whose `Put*` calls
are upserts too but whose slot is one per account and region — a different
name cannot coexist there, which is why those are count-gated by
[`manage_config_recorder`](#config-recorder-ownership) instead of named.

Of the two aggregator names only the **role** is pinned to the `tlz-`
namespace by its validation, for the reason spelled out in its error message:
the `ProtectIAMRoles` statement of
`configurations/policies/organization/tlz-core-guardrails-2.json` denies
modification and deletion only for `arn:*:iam::*:role/tlz-*`, and no offline
check reads a name that is a variable — the validation is the only
enforcement of the pin, and `tests/logging.tftest.hcl` exercises it with
`expect_failures`. The
aggregator name is deliberately **not** pinned: no organization guardrail
names a Config aggregator ARN (`ProtectConfigRules` denies on `Resource "*"`
and lists no aggregator action), so the prefix carries no protection a
validation would have to preserve.

**Leave these at their defaults in production** — a changed default is a
destroy/create of the live resource, and for the trail also of its log group.
The `/aws/cloudtrail/tlz-org-trail` default is what the metric filters in
`configurations/base/base.tfvars` and the monitoring module's
`break_glass_alarm_config.log_group_name` reference; a deployment that renames
the trail must point those at the new group. Live apply-tests set a
`tlz-l4test-` value instead — that exact prefix, because several of these
names refuse a value outside the `tlz-` namespace (next paragraph).

**Namespace pin.** The organization guardrails protect resources only by
`tlz-*` ARN pattern: `ProtectIAMRoles` in `tlz-core-guardrails-2.json` for
`arn:*:iam::*:role/tlz-*`, and in `tlz-core-guardrails-1.json`
`ProtectKinesisStreams` for `arn:*:kinesis:*:*:stream/tlz-*` and
`arn:*:firehose:*:*:deliverystream/tlz-*`, `ProtectLambdaFunctions` for
`arn:*:lambda:*:*:function:tlz-*` and `ProtectCloudWatchLogGroups` for
`/aws/lambda/tlz-*`. A name outside that namespace silently loses its
protection, and no offline check reads names.
The validation of every name of a guardrail class therefore requires the
`tlz-` prefix: `cloudtrail_cloudwatch_role_name`, `kinesis_stream_name`,
`firehose_delivery_stream_name`, `cw_to_kinesis_role_name`,
`firehose_delivery_role_name`, `firehose_processor_function_name`,
`firehose_processor_role_name` — and `bucket_name_prefix`, because
`ProtectS3Buckets` in `tlz-core-guardrails-2.json` denies `DeleteBucket`,
`PutBucketPolicy`, `PutBucketVersioning`, `PutEncryptionConfiguration`,
`PutLifecycleConfiguration` and the other bucket mutations only for
`arn:*:s3:::tlz-*`. The inline policy names, the trail name and the KMS
aliases carry only their service naming rule — no guardrail statement names
those classes by prefix. The four `adopted_*_bucket_name` inputs are the
deliberate exception on the S3 class: they name an existing, possibly legacy
(`lza-*`) bucket, and a pin would defeat their purpose.

### The derived bucket family

The five buckets are the one place where "a variable with the production name
as its default" cannot work as written: their names are **derived** from
account and region (`tlz-central-logs-<log-archive>-<region>` and so on), and a
default cannot interpolate either. What *can* carry the production value is
the leading segment. `bucket_name_prefix` defaults to `tlz-` and reproduces
every derived name byte for byte, so no existing plan changes; a live
apply-test sets `tlz-l4test-` once and every bucket of the family — including
the four it switches off — lands outside the deployed names. One knob for the
family rather than five names, for three reasons: only the prefix has a
static default that equals the live names; a single setting cannot forget a
bucket the way five settings can (a test that later enables the ELB or
replica bucket is scoped already); and one value is one thing to assert —
`startswith(<bucket>, "tlz-l4test-")` for every bucket the run creates.

Why the family needed it at all: `CreateBucket` is create-only outside
`us-east-1`, but in `us-east-1` the S3 API answers a request for a bucket the
account already owns with success (the loud `BucketAlreadyExists` there is a
pre-check inside the Terraform provider, not a service guarantee), and S3
names are global. Without the prefix a test bucket would differ from the live
one only because the caller is not the log-archive account and the region is
not `us-east-1` — two facts about the environment that nothing asserts. With
the prefix, the name itself keeps the test's buckets disjoint.

The prefix composes with adoption rather than competing with it: an
`adopted_*_bucket_name` names an existing bucket and wins over prefix and
derivation for that one bucket; every other bucket still takes the prefix.
The validation pins `tlz-`, requires the trailing hyphen (so `tlz-l4test`
cannot yield `tlz-l4testcentral-logs-…`) and caps the length at 15 characters
— the 63-character S3 limit minus the longest derived remainder,
`central-logs-replica-<12-digit account>-<14-character region>`.

Companion resources of the switched-off features keep fixed literal names
that a live test enabling them would still collide on:
`aws_iam_role.vpc_flow_logs_replication` (`tlz-vpc-flow-logs-replication`),
`aws_iam_role.replication` (`tlz-s3-replication-role`) and
`aws_kms_alias.replication_dest` (`alias/tlz-central-logs-replica`). All three
are create-only (`CreateRole`, `CreateAlias`), so a collision fails loudly
rather than adopting; they are not bucket names and are not covered by the
prefix.

### The upsert-named account subscription policy

`aws_cloudwatch_log_account_policy.subscription` is the module's other upsert:
`PutAccountPolicy` creates or updates the policy of the given name, and an
account holds **one** `SUBSCRIPTION_FILTER_POLICY` per region. No name makes
that slot collision-*safe*, but the name decides how a collision *fails*.
Under the literal `tlz-account-log-subscription` a live apply-test that
enables the policy while the deployed stack has one silently adopts the live
policy and deletes it at teardown; under a different name the same collision
fails loudly with `LimitExceededException` before anything is touched. The
name is therefore a field of the input object:

| Variable | Default | Resource |
|---|---|---|
| `cloudwatch_log_account_subscription.policy_name` | `tlz-account-log-subscription` | `aws_cloudwatch_log_account_policy.subscription` |

It is not pinned to the `tlz-` namespace — no organization guardrail names a
Logs account-policy ARN. The live apply-test sets `tlz-l4test-account-log-subscription`;
while the deployed stack subscribes per log group and leaves the account
policy disabled, the test's policy creates fresh, and once the stack enables
one the test fails loudly instead of deleting it.

One account singleton stays outside naming altogether: the Config recorder
trio (one recorder per region — see
[Config recorder ownership](#config-recorder-ownership); the live test sets
`manage_config_recorder = false`).

## Lifecycle rule set

The four `*_lifecycle_rules` inputs share one shape, so a rule reads the same
wherever it is written. Each entry is one S3 lifecycle rule:

| Attribute | Type | Default | Meaning |
|---|---|---|---|
| `id` | `string` | — | Names the rule in the plan and in the bucket configuration. Unique within a rule set |
| `enabled` | `bool` | `true` | `false` writes the rule with status `Disabled` — it stays declared and does not act |
| `prefix` | `string` | `null` | Selects objects under a key prefix. Unset selects the whole bucket |
| `tags` | `map(string)` | `null` | Selects objects by tag. Set either `prefix` or `tags`, never both |
| `expiration_days` | `number` | `null` | Days after which a current object is deleted |
| `expired_object_delete_marker` | `bool` | `null` | Cleans up delete markers whose object is gone. Excludes `expiration_days` |
| `transitions` | `list(object)` | `[]` | Moves into a colder storage class: `storage_class` and `days`, ordered by ascending `days` |
| `noncurrent_version_expiration_days` | `number` | `null` | Days after which a noncurrent version is deleted |
| `noncurrent_version_transitions` | `list(object)` | `[]` | Same two attributes, applied to noncurrent versions |
| `abort_incomplete_multipart_upload_days` | `number` | `null` | Days after which an unfinished multipart upload is cleaned up |

Storage classes: `STANDARD_IA`, `ONEZONE_IA`, `INTELLIGENT_TIERING`,
`GLACIER_IR`, `GLACIER`, `DEEP_ARCHIVE`.

Three points decide the behaviour:

- **`null` keeps the derived rules.** Leaving an input unset changes nothing —
  the bucket keeps exactly the lifecycle the module derives for it.
- **An empty list removes every rule.** `[]` is the deliberate "no lifecycle at
  all" and is distinct from `null`.
- **A rule set replaces, it does not join.** Once given, it is the whole
  lifecycle of that bucket; the derived rules fall away.

Every expiration must be at least `log_retention_days`. A shorter one would
delete log objects before the retention period ends, and no plan would report
the gap.

## Account trails

Beyond the organization trail, `cloudtrail_account_trails` creates further
trails in the account the module deploys into. Each entry controls its trail
alone; every attribute is optional, and the defaults are the resource's
production values:

| Attribute | Default | Meaning |
|---|---|---|
| `name` | — | Trail name, 3-128 characters |
| `s3_bucket_name` | `""` | Destination bucket. Empty names the central log bucket, whose policy does not admit an account trail, see below |
| `s3_key_prefix` | `""` | Key prefix under which the trail writes |
| `enable_log_file_validation` | `true` | Integrity validation of the delivered files |
| `multi_region` | `true` | Record all regions or only the current one |
| `include_global_service_events` | `true` | Include events of global services |
| `management_events` | `null` | `All`, `ReadOnly` or `WriteOnly` adds a management event selector; `null` records none |
| `insights` | `[]` | Insight types: `ApiCallRateInsight`, `ApiErrorRateInsight` |
| `send_to_cloudwatch_logs` | `false` | Deliver into an own log group `/aws/cloudtrail/<name>` |
| `cloudwatch_logs_retention` | `null` | Retention of that log group. Required with the delivery, rejected without it |
| `advanced_event_selectors` | `[]` | Free-form selectors for data events |

**The central log bucket does not accept an account trail as generated.** Every
CloudTrail grant of its policy (`s3-central-logs-bucket-policy.json`) requires
`aws:SourceArn` to be the organization trail and admits writes only under
`cloudtrail/AWSLogs/`. `CreateTrail` checks the bucket policy and refuses an
account trail with an empty `s3_bucket_name` (`InsufficientS3BucketPolicyException`).
Name a bucket whose policy grants the trail, or add the grant to the central
bucket through `central_log_bucket_policies.s3_attachments` (statements for
`cloudtrail.<dns_suffix>` with `aws:SourceArn` of the account trail on the
bucket and on the trail's key prefix).

A delivering trail gets its own log group (encrypted with the module's
CloudWatch KMS key) and its own delivery role `tlz-cloudtrail-cw-<name>` —
which is why such a trail's name is capped at 46 characters: the role name
may not exceed the 64-character IAM limit.

```hcl
cloudtrail_account_trails = [
  {
    name                      = "audit-trail"
    s3_bucket_name            = "audit-trail-logs" # its policy grants this trail
    s3_key_prefix             = "audit"
    management_events         = "WriteOnly"
    insights                  = ["ApiCallRateInsight"]
    send_to_cloudwatch_logs   = true
    cloudwatch_logs_retention = 90
  },
]
```

## Log forwarding: exclusions and the account-wide subscription

`cloudwatch_log_subscriptions` attaches one filter per named log group.
Each entry names its target log group explicitly — there is no implicit
fallback to the org-trail log group. An empty `log_group_name` is rejected
at plan time (variable validation, backed by a resource precondition);
the earlier behaviour silently substituted an empty string when the
org-trail log group did not exist and failed only at apply with
`InvalidParameterException`.
Which of those filters actually get created is governed by two exclusion
inputs, and an account-wide alternative exists beside them:

- **`cloudwatch_log_exclusions`** — the flat list: log group names that no
  filter is attached to.
- **`cloudwatch_log_exclusion_rules`** — structured rules. Each entry scopes
  by `accounts` (12-digit IDs), `organizational_units` and `regions`; an
  unset scope matches. A rule applies when every given scope matches the
  deployment — the account and region the module runs in, and the unit named
  by `deployment_organizational_unit`, which the deployment layer takes from
  the configuration's account list. An applicable rule drops log groups it
  names exactly, by prefix with a trailing `*`, or all of them
  (`exclude_all`). Every entry must name groups or set `exclude_all`, never
  both.
- **`cloudwatch_log_account_subscription`** — one subscription filter policy
  for the whole account instead of per-group filters. `selection_criteria`
  carves out log groups (`LogGroupName NOT IN ["a", "b"]`); an empty
  `destination_arn` targets the module-managed Kinesis stream, like the
  per-group filters. `policy_name` defaults to `tlz-account-log-subscription`
  and exists for live apply-tests — see
  [The upsert-named account subscription policy](#the-upsert-named-account-subscription-policy).

```hcl
cloudwatch_log_exclusion_rules = [
  # Drop Lambda log groups in the workload accounts.
  {
    accounts        = ["333333333333", "444444444444"]
    log_group_names = ["/aws/lambda/*"]
  },
  # Forward nothing from the Sandbox unit.
  {
    organizational_units = ["Sandbox"]
    exclude_all          = true
  },
]

cloudwatch_log_account_subscription = {
  enabled            = true
  selection_criteria = "LogGroupName NOT IN [\"/aws/lambda/noisy\"]"
}
```

## Archive pipeline tuning

Subscribed logs flow through a module-managed pipeline into the central log
bucket: a Kinesis Data Stream, a Firehose delivery stream and dynamic
partitioning by account, region and log group. The pipeline exists whenever a
subscription input targets it; `kinesis_pipeline_config` tunes its values,
and `{}` keeps the production values (24 h retention, on-demand
capacity, 64 MiB/60 s delivery buffer, no compression, no file extension,
the default error prefix, native decompression).

CloudWatch Logs delivers subscription records as gzip-compressed envelopes.
By default the delivery stream decompresses them with the native Firehose
`Decompression` processor and derives the partition keys directly from the
envelope fields, so records land under
`cloudwatch-logs/<account>/<region>/<log_group>/` without any further
configuration. The region segment of that prefix is the deployment region,
pinned at plan time — the envelope carries no region field.

On this default path the error prefix is expected to hold occasional
`CONTROL_MESSAGE` records: CloudWatch Logs emits them when a subscription is
created and for destination health checks, their envelope carries an empty
`logGroup`, and the native processor chain has no way to filter them — the
empty partition key fails partitioning and diverts the record. This is
cosmetic; log data is not affected. The optional `lambda_processor` drops
these records instead.

- **Stream** — `kinesis_retention_hours` (24-8760), `kinesis_stream_mode`
  (`ON_DEMAND` or `PROVISIONED`) and `kinesis_shard_count` (provisioned
  streams only; defaults to one shard).
- **Delivery** — `firehose_buffering_size_mb` (1-128),
  `firehose_buffering_interval_seconds` (60-900),
  `firehose_compression_format` (`UNCOMPRESSED`, `GZIP`, `ZIP`, `Snappy`,
  `HADOOP_SNAPPY`), `firehose_file_extension` (e.g. `.json.gz`) and
  `firehose_error_output_prefix`.
- **Record processor** — `lambda_processor` replaces the native
  decompression with a small Lambda in front of the partitioning step. The
  function decompresses each record and re-emits it as a reshaped JSON
  document carrying `account_id`, `region` and `log_group`; the archived
  objects then hold these documents instead of the raw envelopes, and the
  region partition key comes from the record. `buffer_size_mb` (0.2-3),
  `buffer_interval_seconds` (60-900) and `retries` (0-512) tune the
  processor invocation.

```hcl
kinesis_pipeline_config = {
  kinesis_retention_hours     = 168
  firehose_compression_format = "GZIP"
  firehose_file_extension     = ".json.gz"
  lambda_processor = {
    enabled = true
  }
}
```

## Bucket and KMS policies

Each log bucket carries a policy the module generates: delivery permissions
for the log-writing services and the transport encryption requirement. The
three `*_bucket_policies` inputs extend or replace those documents; the
central log bucket additionally takes statements for the KMS key that
encrypts it. Every document is a JSON string — read it from a file with
`file()` in the configuration layer, the same way the other policies under
`configurations/policies/` are kept.

- **Attachments append.** The statements of every `*_attachments` document
  land behind the generated statements, in list order — the merge is
  deterministic, and the generated statements keep their positions.
- **An override replaces.** A `*_override` document becomes the whole policy;
  the generated statements fall away. Because that can remove the delivery
  permissions and the encryption requirement of a log bucket, every override
  additionally requires `allow_bucket_policy_overrides = true`.
- **Documents are checked in the plan.** Each one must decode as JSON and
  carry `Version` and a `Statement` list. Documents for a bucket whose toggle
  is off are rejected — they would silently do nothing.

The GuardDuty grant of the central log bucket policy tracks
`guardduty_export_prefix`, and the module also writes a zero-byte folder
marker object at that prefix (`aws_s3_object.guardduty_export_marker`):
GuardDuty's `CreatePublishingDestination` validates that the export "folder"
exists and answers 400 on a fresh bucket without it. Grant, marker and the
security module's publishing destination all derive from the same prefix
value, so they cannot drift apart; with an empty prefix the destination is
the bucket root and no marker is created.

While the export was broken, a workaround pointed the destination at the bare
bucket, so findings were written to the bucket **root** as
`AWSLogs/<account-id>/GuardDuty/...` — outside every `guardduty/`-prefixed
lifecycle rule, retained forever. `guardduty_root_export_cleanup` remediates
that: one expiration rule per detector account, each pinning the
`/GuardDuty/` path segment in its literal prefix so keys of any other writer
cannot match — an account trail without a key prefix writes
`AWSLogs/<account>/CloudTrail/...`, which a bare `AWSLogs/` rule would catch
and this one cannot. The rules also expire noncurrent versions (the bucket is
versioned; expiration alone only hides objects behind delete markers), count
from object creation (a retention below the objects' age expires them at the
next lifecycle evaluation), stay additive in every lifecycle form of the
bucket, and disappear when the variable is removed — which is the intended
end state once the root objects are gone.

```hcl
guardduty_root_export_cleanup = {
  retention_days = 1
  # account_ids = ["222222222222"]  # empty: the deploying account
}
```

```hcl
central_log_bucket_policies = {
  s3_attachments = [file("policies/central-logs-extra-statements.json")]
}

elb_log_bucket_policies = {
  s3_attachments = [file("policies/elb-logs-extra-statements.json")]
}
```

```hcl
central_log_bucket_lifecycle_rules = [
  {
    id              = "cloudtrail-archive"
    prefix          = "cloudtrail/"
    expiration_days = 2555
    transitions = [
      { storage_class = "STANDARD_IA", days = 30 },
      { storage_class = "GLACIER", days = 90 },
      { storage_class = "DEEP_ARCHIVE", days = 365 },
    ]
    noncurrent_version_expiration_days     = 400
    abort_incomplete_multipart_upload_days = 7
  },
]
```

## Config recorder ownership

An AWS account allows exactly one Config recorder per region. `PutConfigurationRecorder` for a second one fails with `MaxNumberOfConfigurationRecordersExceeded`, and because a module apply is all-or-nothing, an account whose slot is held by another owner — a legacy recorder from an earlier framework, a Control Tower baseline — could not apply this module at all. `manage_config_recorder` addresses that:

| Value | `aws_config_configuration_recorder.this`, `aws_config_delivery_channel.this`, `aws_config_configuration_recorder_status.this` | `aws_config_configuration_aggregator.org` and its role | Everything else |
|-------|------|------|------|
| `true` (default) | created — the module's default plan | created | created |
| `false` | not created; the existing recorder keeps recording | created | created |

The aggregator is not gated: it collects from the member accounts' recorders through `aws_iam_role.config_aggregator` and needs no recorder in this account.

What the flag does **not** buy: `use_config_service_linked_role` and `config_recorder_custom_role_arn` configure exactly the three resources being skipped, so with `manage_config_recorder = false` they have no effect (the `config_custom_role_required` check is silent then as well), and they cannot be exercised against an account whose slot is taken. A module output that reads the recorder does not exist, so no output changes shape with the flag.

Switching a live deployment from `true` to `false` **destroys** the module's recorder, delivery channel and status — do that only when another recorder is meant to take over. To hand an existing recorder to this module instead, keep the default and import it (docs/resource-adoption.md).

## Outputs

| Name | Description |
|------|-------------|
| `cloudtrail_arn` | ARN of the org-wide CloudTrail trail |
| `central_log_bucket_arn` | ARN of the central S3 log bucket |
| `central_log_bucket_name` | Name of the central S3 log bucket |
| `config_aggregator_name` | Name of the org-wide Config aggregator |
| `log_retention_days` | Retention in days that the central log bucket applies |
| `cloudwatch_log_group_retention` | Retention in days of the trail's log group (`null` when no log group exists) |
| `kms_key_arn` | ARN of the KMS key that encrypts the log buckets |
| `cloudtrail_s3_data_events` | Whether the trail records S3 data events |
| `cloudtrail_lambda_data_events` | Whether the trail records Lambda data events |
| `cloudtrail_insights` | Insight types active on the trail |
| `s3_lifecycle_rules` | Retention per prefix in force on the central bucket (`null` when the single retention value applies) |
| `access_logs_bucket_name` | Name of the separate access logs bucket (empty when `enable_separate_access_logs_bucket` is false) |
| `vpc_flow_logs_bucket_arn` | ARN of the dedicated VPC flow logs bucket (empty when disabled) |
| `cloudtrail_lake_event_data_store_arn` | ARN of the CloudTrail Lake event data store (empty when disabled) |
| `kinesis_stream_arn` | ARN of the Kinesis Data Stream of the CloudWatch-to-S3 pipeline (empty when the pipeline is disabled) |
| `elb_log_bucket_name` | Name of the load balancer log bucket (empty when disabled) |
| `per_account_s3_kms_key_arn` | ARN of the per-account S3 KMS key (empty when `enable_per_account_kms_keys` is false) |
| `replication_dest_bucket_arn` | ARN of the replication destination bucket (empty when replication is disabled) |
| `replication_dest_kms_key_arn` | ARN of the KMS key encrypting the replication destination (empty when replication is disabled) |

## Resources

The module creates the resource types below. They are grouped by the file that declares them, so the grouping doubles as a map of the module. A type appears in more than one row when several files create it for their own purpose. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

| File | Resource types |
|---|---|
| `cloudtrail-lake.tf` | `aws_cloudtrail_event_data_store` |
| `cloudtrail.tf` | `aws_cloudwatch_log_group`, `aws_iam_role`, `aws_iam_role_policy`, `aws_cloudtrail`, `aws_sns_topic`, `aws_sns_topic_policy`, `aws_cloudwatch_log_subscription_filter` |
| `cloudwatch-data-protection.tf` | `aws_cloudwatch_log_data_protection_policy` |
| `config-recorder.tf` | `aws_config_configuration_recorder`, `aws_config_delivery_channel`, `aws_config_configuration_recorder_status`, `aws_config_configuration_aggregator`, `aws_iam_role`, `aws_iam_role_policy_attachment` |
| `kinesis-pipeline.tf` | `aws_kinesis_stream`, `aws_iam_role`, `aws_iam_role_policy`, `aws_kinesis_firehose_delivery_stream`, `aws_lambda_function` (optional record processor, packaged via `archive_file`) |
| `kms.tf` | `aws_kms_key`, `aws_kms_alias` |
| `s3-access-logs.tf` | `aws_s3_bucket`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_lifecycle_configuration`, `aws_s3_bucket_policy` |
| `s3-central.tf` | `aws_s3_bucket`, `aws_s3_bucket_object_lock_configuration`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_lifecycle_configuration`, `aws_s3_bucket_logging`, `aws_s3_bucket_policy`, `aws_s3_object` (GuardDuty export folder marker) |
| `s3-elb-logs.tf` | `aws_s3_bucket`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_policy`, `aws_s3_bucket_lifecycle_configuration` |
| `s3-replication.tf` | `aws_iam_role`, `aws_iam_role_policy`, `aws_kms_key`, `aws_kms_alias`, `aws_s3_bucket`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_lifecycle_configuration`, `aws_s3_bucket_policy`, `aws_s3_bucket_replication_configuration` |
| `ssm-associations.tf` | `aws_ssm_association` |
| `vpc-flow-logs.tf` | `aws_s3_bucket`, `aws_s3_bucket_versioning`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_lifecycle_configuration`, `aws_s3_bucket_policy`, `aws_iam_role`, `aws_iam_role_policy`, `aws_s3_bucket_replication_configuration` |

## Usage Example

```hcl
module "logging" {
  source = "./modules/logging"

  log_archive_account_id         = "123456789012"
  organization_id                = "o-abc123def4"
  log_retention_days             = 365
  cloudwatch_log_group_retention = 90
  kms_key_administrators         = ["arn:aws:iam::123456789012:role/Admin"]
}
```

## Lambda execution log groups

Lambda creates a function's execution log group, `/aws/lambda/<function name>`,
implicitly on the first invocation when nothing has declared it. Such a group
sits outside the Terraform state, carries no retention — its logs never expire —
and no `destroy` and no test teardown removes it, in every deployment and not
only in a test. The monitoring module declares the groups of its two
functions for the same reason
([Lambda execution log groups](../monitoring/README.md#lambda-execution-log-groups));
the record-processor function of the archive pipeline owns its group as well:

| Log group | Resource | Retention |
|---|---|---|
| `/aws/lambda/<firehose_processor_function_name>` (default `/aws/lambda/tlz-cw-log-processor`) | `aws_cloudwatch_log_group.firehose_processor` | `firehose_processor_log_retention_days` (default `365`) |

Each name derives from its function rather than being spelled out again, so a
group can never disagree with the function it belongs to. That matters here in particular:
`firehose_processor_function_name` is operator-settable, so a group built
independently from the same variable would agree with the function only by
convention. The function's inline policy already scopes its logs grant to this
exact group. The delivery stream — the resource that invokes the processor —
depends on the group, so no invocation can precede it.

**Existing installations must import the group before the next apply.** In any
account where one of these functions has already been invoked, its log group
already exists outside the state. CloudWatch Logs `CreateLogGroup` is
create-only, so the apply that first carries this change fails with
`ResourceAlreadyExistsException` for that group — loudly, before anything is
adopted or deleted, and only where the function actually ran: an account where
the feature was enabled but the function never fired has no group and needs
nothing. Import the existing group into this module's stack (the module is the
stack's root module, so the address carries no `module.` prefix), then apply:

```sh
terragrunt import 'aws_cloudwatch_log_group.firehose_processor[0]' /aws/lambda/tlz-cw-log-processor
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
