# Organization Module

Manages Organizational Units (OUs), Service Control Policies (SCPs), Tag Policies, Backup Policies, and Delegated Administrator in AWS Organizations.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `import_organization_id` | ID of an existing organization (`o-…`) to adopt instead of creating one. Empty creates a new organization | `string` | `""` | no |
| `organization_root_id` | Organization Root ID (`r-xxxx`). Empty resolves the root from the organization resource | `string` | `""` | no |
| `aws_service_access_principals` | COMPLETE list of service principals with trusted access in the organization, for example `cloudtrail.amazonaws.com`. A principal missing here has its trusted access disabled on apply; an empty list is refused at plan time (read today's list with `aws organizations list-aws-service-access-for-organization`) | `list(string)` | `[]` (refused) | yes |
| `feature_set` | Feature set of the organization: `ALL` or `CONSOLIDATED_BILLING` | `string` | `"ALL"` | no |
| `organizational_units` | List of OU definitions | `list(object)` | `[]` | no |
| `service_control_policies` | List of SCP definitions. `type` selects between `customer-managed` (the default) and `aws-managed` (attach an AWS-managed policy such as `FullAWSAccess` by its well-known ID); `strategy` selects between `deny-list` (the default) and `allow-list`. See [Policy Strategy](#policy-strategy) | `list(object)` | `[]` | no |
| `enable_allow_list_detach` | Allow `strategy = "allow-list"` entries to detach the AWS default policy from their targets. See [Policy Strategy](#policy-strategy) | `bool` | `false` | no |
| `tag_policies` | List of tag policy definitions | `list(object)` | `[]` | no |
| `backup_policies` | List of backup policy definitions | `list(object)` | `[]` | no |
| `service_access_principals` | Delegated admin service principals | `list(object)` | `[]` | no |
| `enable_pipeline_scp` | Attach an SCP that protects the deployment and pipeline roles from being modified | `bool` | `false` | no |
| `pipeline_scp_config` | Roles and targets of the pipeline SCP. Required when `enable_pipeline_scp` is set | `object` | `null` | no |
| `enable_quarantine_scp` | Attach an SCP that denies every action in a new account to every principal except the roles `AWSControlTowerExecution`, `TLZDeploymentRole`, `tlz-*` and `OrganizationAccountAccessRole`. Those roles keep every action, not only `sts:AssumeRole` | `bool` | `false` | no |
| `quarantine_scp_content` | Policy document of the quarantine SCP. Empty uses the built-in document (`tlz-quarantine-guardrails.json`, with the exemptions named on `enable_quarantine_scp`) | `string` | `""` | no |
| `quarantine_scp_targets` | OU names or account IDs the quarantine SCP is attached to | `list(string)` | `[]` | no |
| `resource_control_policies` | Resource control policies with their target OUs and accounts. `strategy` selects between `deny-list` (the default) and `allow-list` — see [Policy Strategy](#policy-strategy) | `list(object)` | `[]` | no |
| `unresolved_resource_control_policies` | Names of resource control policies the caller left out because their document still carries an unresolved `@@marker@@`. None of them is created; a non-empty list makes the check `rcp_documents_unresolved` warn on plan and apply | `list(string)` | `[]` | no |
| `declarative_policies` | Declarative EC2 policies with their target OUs and accounts | `list(object)` | `[]` | no |
| `chatbot_policies` | Chatbot policies with their target OUs and accounts | `list(object)` | `[]` | no |
| `additional_enabled_policy_types` | Policy types to keep enabled in addition to the ones the policy lists above derive, for example `AISERVICES_OPT_OUT_POLICY`. The organization resource owns the complete list of enabled policy types, so a type an adopted organization has enabled and nothing here names is disabled on apply (read today's types with `aws organizations list-roots`) | `list(string)` | `[]` | no |
| `opt_in_regions` | Opt-in regions to enable organization-wide, for example `eu-south-1`. An empty list leaves region opt-in untouched | `list(string)` | `[]` | no |
| `enable_quarantine_auto_detach` | Notify `scp_revert_notification_emails` when a named pipeline succeeds, so an operator releases the quarantine SCP from the accounts that run configured. The release is manual; nothing detaches the SCP automatically, see [Quarantine release](#quarantine-release). Requires `enable_quarantine_scp` | `bool` | `false` | no |
| `quarantine_detach_pipeline_names` | CodePipeline names whose `SUCCEEDED` state triggers the quarantine release notification; the rule matches no other pipeline. The rule sees pipelines of this account and region only | `list(string)` | `["tlz-deployment-pipeline"]` | no |
| `quarantine_detach_topic_name` | Name of the quarantine-SCP detach notification topic (created with `enable_quarantine_auto_detach`). Same contract as `scp_revert_topic_name` (`CreateTopic` is an upsert; the default is the module's standard name, dormant while the toggle is off); must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-quarantine-scp-detach-notification"` | no |
| `quarantine_detach_rule_name` | Name of the EventBridge rule that detects pipeline completion for the quarantine detach. Same contract as `scp_revert_rule_name` (`PutRule` is an upsert); must stay inside `tlz-` | `string` | `"tlz-quarantine-scp-pipeline-completion"` | no |
| `enable_account_move_automation` | Move accounts between OUs in response to Organizations API events. The rule, the function and its log group are created in `us-east-1`, where Organizations delivers its events, whatever region the stack runs in | `bool` | `false` | no |
| `account_move_log_retention_days` | Log retention in days for the account move automation | `number` | `90` | no |
| `policy_strategy_detach_log_retention_days` | Retention of the policy-strategy detach Lambda's own execution log group `/aws/lambda/tlz-policy-strategy-detach` (`0` = never expire). See [Lambda execution log groups](#lambda-execution-log-groups) | `number` | `365` | no |
| `policy_strategy_detach_log_kms_key_arn` | Optional KMS key ARN for encrypting that log group. Empty keeps the CloudWatch service default encryption; the module creates no key | `string` | `""` | no |
| `scp_auto_revert_log_retention_days` | Retention of the SCP auto-revert Lambda's own execution log group `/aws/lambda/tlz-scp-auto-revert` (`0` = never expire). See [Lambda execution log groups](#lambda-execution-log-groups) | `number` | `365` | no |
| `account_move_rule_name` | Name of the EventBridge rule that triggers the account-move Lambda. Same contract as `scp_revert_rule_name` (`PutRule` is an upsert; the default is the module's standard name, dormant while the toggle is off); must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-account-move"` | no |
| `enable_scp_revert_detection` | Detect SCP changes that were made outside this configuration. The detection is created in `us-east-1`, where Organizations delivers its events, whatever region the stack runs in, see [SCP change detection](#scp-change-detection) | `bool` | `false` | no |
| `scp_revert_notification_emails` | Addresses notified when an SCP change is detected | `list(string)` | `[]` | no |
| `scp_revert_topic_name` | Name of the SCP change notification topic. The default is the module's standard name and may already exist in a deployed management account; because `CreateTopic` is an upsert, an apply-test against a live account overrides it with a `tlz-l4test-` name so teardown cannot delete the live topic. Must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-scp-revert-detection"` | no |
| `scp_revert_rule_name` | Name of the EventBridge rule that detects SCP changes. Same contract as `scp_revert_topic_name` (`PutRule` is an upsert); must stay inside `tlz-` | `string` | `"tlz-scp-modification-detection"` | no |
| `enable_scp_auto_revert` | Revert a detected SCP change automatically. Requires `enable_scp_revert_detection`. What is and is not reverted: [SCP change detection](#scp-change-detection) | `bool` | `false` | no |
| `scp_auto_revert_dlq_name` | Name of the SCP auto-revert Lambda's SQS dead-letter queue (created with `enable_scp_auto_revert`). `CreateQueue` is idempotent on identical attributes, so the same apply-test contract applies; the Lambda policy's `sqs:SendMessage` grant follows the name. Not confined to `tlz-` (no guardrail names an SQS queue) — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-scp-auto-revert-dlq"` | no |

## Policy Strategy

Both policy lists attach purely additively by default (`strategy =
"deny-list"`): the AWS default policy — `FullAWSAccess` for SCPs,
`RCPFullAWSAccess` for RCPs — stays on every target and the entries only
subtract from it. With `strategy = "allow-list"` an entry inverts that model:
its own policy names what remains allowed, and the module detaches the AWS
default policy from the entry's targets so nothing else grants access
alongside it.

Those default attachments were created by AWS, not by this configuration, so
no attachment resource can manage them. A module-owned function (packaged
from an inline template, like the SCP auto-revert function) detaches them at
deployment time, once per policy type over the deduplicated union of all
allow-list targets, and re-attaches them when the configuration is removed —
a target is never left without any policy, because the invocation runs after
the entry's own attachment and the re-attach runs before it is destroyed.
A target that leaves the allow-list targets on a later apply gets the AWS
default policy back in that apply's update of the invocation.
Everything hangs on `enable_allow_list_detach` (default `false`); an
allow-list entry behind the disabled switch is rejected at plan, and an
allow-list entry must name at least one target.

Detaching `FullAWSAccess` can lock an OU out of every service the remaining
policies do not grant. Review the entry's policy against the workloads of
every target before enabling the switch; the deny-list default is the safe
direction.

`type = "aws-managed"` attaches an AWS-managed policy by its well-known ID
(`FullAWSAccess` → `p-FullAWSAccess`) instead of creating one: the entry
carries no `content`, and combining it with `strategy = "allow-list"` is
rejected — `FullAWSAccess` is the policy that strategy detaches.

### SCP attachment quota

AWS Organizations attaches at most **5** SCPs directly to a single target
(root, OU, or account); the quota is fixed. The module counts every SCP
attachment it manages per declared target — the `service_control_policies`
entries plus the quarantine SCP and the pipeline SCP — and rejects the plan
when a target exceeds the quota, before any attachment is attempted
(`scp-quota.tf`). Two boundaries of that count, stated plainly: targets are
grouped by their declared spelling (the same OU addressed once by name and
once by raw `ou-` ID counts as two targets), and attachments created outside
this configuration — the AWS default `FullAWSAccess` that stays attached
under the deny-list strategy, Control Tower guardrails, manual attachments —
occupy quota slots a plan cannot see.

```hcl
enable_allow_list_detach = true

service_control_policies = [
  {
    name     = "workload-allow-list"
    content  = file("policies/allowed-services.json") # what stays allowed
    targets  = ["Workloads"]
    strategy = "allow-list"
  },
  {
    name    = "FullAWSAccess" # keep the default explicitly on Sandbox
    type    = "aws-managed"
    targets = ["Sandbox"]
  }
]
```

## SCP change detection

`enable_scp_revert_detection` creates an EventBridge rule for `UpdatePolicy`,
`DeletePolicy` and `DetachPolicy` and an SNS topic for the alerts. AWS
Organizations delivers these CloudTrail events to EventBridge in `us-east-1`
only, so in the `aws` partition the rule, its targets, the topic and the
auto-revert function with its queue and log group are created in `us-east-1`,
whatever region the stack runs in (the resource-level `region` argument of the
AWS provider; no second provider is needed). Other partitions keep the stack's
region. The topic, like the quarantine-detach topic, is encrypted with a
customer-managed key of this module (`aws_kms_key.sns_topics`) that grants
EventBridge `GenerateDataKey*` and `Decrypt`: EventBridge cannot publish to a
topic under `alias/aws/sns`. A key must sit in the region of what it
encrypts, so `aws_kms_key.sns_topics` and `aws_kms_key.cloudwatch_logs` hold
one key per region in use. The key in the stack's own region is keyed
`"stack"`, a key in another region by that region's name; a stack in
`us-east-1` keeps one key of each, keyed `"stack"`. See
[Upgrading](#upgrading) for a deployment of an earlier release.

## Quarantine release

`enable_quarantine_auto_detach` creates an EventBridge rule for `SUCCEEDED`
of the pipelines in `quarantine_detach_pipeline_names` and an SNS topic that
asks the subscribed addresses to release the quarantine SCP. The release is
manual: detach the quarantine SCP from the accounts the run configured. No
function detaches it, because the pipeline event does not name those
accounts, and detaching from every target would release accounts the run
never touched. The rule sees pipelines of the management account and its
region only.

`enable_scp_auto_revert` adds a Lambda function. An `UpdatePolicy` on an SCP or
RCP this module manages (the quarantine and pipeline SCPs included) is
reverted to the content of the last apply, which the function carries in its
package. An `UpdatePolicy` on any other policy and a `DeletePolicy` are
reported as not reverted; review those changes by hand. A `DetachPolicy` is
undone by attaching the policy again. Changes by `TLZDeploymentRole`, by the
function's own role and by the existing exemption patterns are not reverted.

## Outputs

| Name | Description |
|------|-------------|
| `organization_id` | ID of the organization |
| `ou_name_to_id` | Map of OU name → OU ID (all levels) |
| `scp_ids` | Map of SCP name → SCP ID |
| `rcp_documents_unresolved` | Resource control policies left out for an unresolved `@@marker@@` and therefore not created; empty once `import_organization_id` and `log_archive_account_id` are set |
| `org_root_id` | Root ID of the AWS Organization |
| `partition` | Partition the configuration runs in |
| `dns_suffix` | DNS suffix of the current partition |
| `master_account_id` | Account ID of the organization's management account |
| `ignored_ou_ids` | OU IDs marked `ignore = true` and therefore excluded from policy attachments |
| `chatbot_policy_ids` | Map of Chatbot policy name → policy ID |
| `quarantine_scp_id` | ID of the Quarantine SCP (empty when disabled) |
| `scp_revert_sns_topic_arn` | ARN of the SNS topic for SCP revert notifications (empty when disabled) |
| `scp_auto_revert_lambda_arn` | ARN of the SCP auto-revert Lambda function |
| `account_move_lambda_arn` | ARN of the account move Lambda function (empty when disabled) |

## Resources

The module creates the resource types below. They are grouped by the file that declares them, so the grouping doubles as a map of the module. A type appears in more than one row when several files create it for their own purpose. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

| File | Resource types |
|---|---|
| `account-move.tf` | `aws_cloudwatch_log_group`, `aws_iam_role`, `aws_iam_role_policy`, `aws_lambda_function`, `aws_cloudwatch_event_rule`, `aws_cloudwatch_event_target`, `aws_lambda_permission` |
| `backup-policies.tf` | `aws_organizations_policy`, `aws_organizations_policy_attachment` |
| `chatbot-policies.tf` | `aws_organizations_policy`, `aws_organizations_policy_attachment` |
| `declarative-policies.tf` | `aws_organizations_policy`, `aws_organizations_policy_attachment` |
| `organization.tf` | `aws_organizations_organization`, `aws_organizations_organizational_unit`, `aws_account_region`, `aws_organizations_delegated_administrator` |
| `quarantine.tf` | `aws_organizations_policy`, `aws_organizations_policy_attachment`, `aws_sns_topic`, `aws_sns_topic_policy`, `aws_sns_topic_subscription`, `aws_cloudwatch_event_rule`, `aws_cloudwatch_event_target` |
| `policy-strategy.tf` | `aws_iam_role`, `aws_iam_role_policy`, `aws_lambda_function`, `aws_lambda_invocation` |
| `rcps.tf` | `aws_organizations_policy`, `aws_organizations_policy_attachment` |
| `scp-revert.tf` | `aws_sns_topic`, `aws_sns_topic_policy`, `aws_sns_topic_subscription`, `aws_cloudwatch_event_rule`, `aws_cloudwatch_event_target`, `aws_iam_role`, `aws_iam_role_policy`, `aws_sqs_queue`, `aws_lambda_function`, `aws_lambda_permission` |
| `scp-quota.tf` | (no resources — plan-time SCP quota count, read by the attachment preconditions) |
| `scps.tf` | `aws_organizations_policy`, `aws_organizations_policy_attachment` |
| `tag-policies.tf` | `aws_organizations_policy`, `aws_organizations_policy_attachment` |

## Upsert-safe resource names

Three APIs this module calls are **upserts** or idempotent creates, not
create-only: SNS `CreateTopic` returns an existing topic of the same name,
EventBridge `PutRule` updates an existing rule of the same name, and SQS
`CreateQueue` returns an existing queue when the attributes are identical
(the module's own attributes always are). That is fine in production, but
dangerous for a live `terraform test`: an apply-test that used a fixed
account-wide name would silently adopt the real resource, and the test's
automatic teardown would then **delete the live one**. Every such name is
therefore a variable defaulting to the module's standard name, so a production plan
stays empty while a test can scope its own resources:

| Variable | Default | Resource | Created when | `tlz-` pinned |
|---|---|---|---|---|
| `scp_revert_topic_name` | `tlz-scp-revert-detection` | `aws_sns_topic.scp_revert` | `enable_scp_revert_detection` | yes |
| `scp_revert_rule_name` | `tlz-scp-modification-detection` | `aws_cloudwatch_event_rule.scp_revert` | `enable_scp_revert_detection` | yes |
| `quarantine_detach_topic_name` | `tlz-quarantine-scp-detach-notification` | `aws_sns_topic.quarantine_detach` | `enable_quarantine_scp` and `enable_quarantine_auto_detach` | yes |
| `quarantine_detach_rule_name` | `tlz-quarantine-scp-pipeline-completion` | `aws_cloudwatch_event_rule.quarantine_detach` (target follows) | `enable_quarantine_scp` and `enable_quarantine_auto_detach` | yes |
| `scp_auto_revert_dlq_name` | `tlz-scp-auto-revert-dlq` | `aws_sqs_queue.scp_auto_revert_dlq` (and the Lambda policy's `sqs:SendMessage` grant) | `enable_scp_revert_detection` and `enable_scp_auto_revert` | **no** |
| `account_move_rule_name` | `tlz-account-move` | `aws_cloudwatch_event_rule.account_move` (target follows) | `enable_account_move_automation` | yes |

A toggle that is off is a fact about one configuration, **not a safety property** of a
test: the day a toggle is enabled in production the resource exists under
the default, and an apply-test asserting that default becomes its deletion —
which is why the dormant names are overridable too. Enabling a toggle needs
no name change; the defaults keep the module's standard names.

The pin is a judgement per class, not a reflex. The topic and the three rule
names pin the `tlz-` namespace because the organization guardrails
(`ProtectSNSTopics`, `ProtectEventBridgeRules` in `tlz-core-guardrails-1.json`)
deny tampering only for `arn:*:sns:*:*:tlz-*` and `arn:*:events:*:*:rule/tlz-*`,
and a name that is a variable would otherwise leave the namespace silently —
the validations are the only enforcement of the pin, exercised with `expect_failures` in the module's
`terraform test`. The SQS queue name is deliberately **not**
pinned: no guardrail statement names an SQS queue ARN (the resource control
policies' `sqs:*` statements are `Resource: "*"`, name-independent), so there
is no protection for a
validation to preserve — it carries the SQS standard-queue naming rule only
(no dot, so no accidental `.fifo` suffix). The DLQ grant in
`configurations/policies/organization/scp-auto-revert-policy.json` takes the queue name as a
template parameter (`dlq_name`), because Lambda validates the
`sqs:SendMessage` grant against `dead_letter_config` at create — a renamed
queue with a policy still naming the literal would fail the function's
creation.

**Fixed, deliberately** (create-only APIs — a collision fails loudly
instead of adopting, so a test cannot delete a live one): the Lambda functions
`tlz-scp-auto-revert`, `tlz-account-move`, their
IAM roles, and the log group `/aws/lambda/tlz-account-move`. A live apply-test
of an enabled chain would fail on these before its first assertion, which is
the harmless failure mode.

**Not fixable by naming:** `aws_account_region` (`EnableRegion`) and
`aws_organizations_delegated_administrator` act on account-level singletons
with no name. `RegisterDelegatedAdministrator` fails on a duplicate, but
`EnableRegion` succeeds against an already-enabled region and teardown then
**disables it**. There is no live apply-test for this module, and there must
not be one against the management account.

## Usage Example

```hcl
module "organization" {
  source = "./modules/organization"

  organization_root_id      = data.aws_organizations_organization.current.roots[0].id
  organizational_units      = var.organizational_units
  service_control_policies  = var.service_control_policies
  tag_policies              = var.tag_policies
  backup_policies           = var.backup_policies
  service_access_principals = var.service_access_principals
}
```

## Lambda execution log groups

Lambda creates a function's execution log group, `/aws/lambda/<function name>`,
implicitly on the first invocation when nothing has declared it. Such a group
sits outside the Terraform state, carries no retention — its logs never expire —
and no `destroy` and no test teardown removes it, in every deployment and not
only in a test. The monitoring module declares the groups of its two
functions the same way
([Lambda execution log groups](../monitoring/README.md#lambda-execution-log-groups));
this module declares the group of each of its three automation functions:

| Log group | Resource | Retention |
|---|---|---|
| `/aws/lambda/tlz-account-move` | `aws_cloudwatch_log_group.account_move` | `account_move_log_retention_days` (default `90`) |
| `/aws/lambda/tlz-policy-strategy-detach` | `aws_cloudwatch_log_group.policy_strategy_detach` | `policy_strategy_detach_log_retention_days` (default `365`) |
| `/aws/lambda/tlz-scp-auto-revert` | `aws_cloudwatch_log_group.scp_auto_revert` | `scp_auto_revert_log_retention_days` (default `365`) |

Each name derives from its function rather than being spelled out again, so a
group can never disagree with the function it belongs to. Whatever can invoke a function depends on
its group: the EventBridge targets for the account-move and SCP-revert functions,
and both `aws_lambda_invocation` resources for the policy-strategy function,
which Terraform invokes synchronously during the apply.

**Existing installations must import the group before the next apply.** In any
account where one of these functions has already been invoked, its log group
already exists outside the state. CloudWatch Logs `CreateLogGroup` is
create-only, so the first apply that declares the group fails with
`ResourceAlreadyExistsException` for that group — loudly, before anything is
adopted or deleted, and only where the function actually ran: an account where
the feature was enabled but the function never fired has no group and needs
nothing. Import the existing group into this module's stack (the module is the
stack's root module, so the address carries no `module.` prefix), then apply:

```sh
terragrunt import 'aws_cloudwatch_log_group.policy_strategy_detach[0]' /aws/lambda/tlz-policy-strategy-detach
terragrunt import 'aws_cloudwatch_log_group.scp_auto_revert[0]' /aws/lambda/tlz-scp-auto-revert@us-east-1
```

## Upgrading

A release before this one created each key of this module as `[0]` and ran
the SCP change detection and the account move function in the stack's region. The next plan after the
upgrade shows the following:

- **The keys move, they are not replaced.** `moved` blocks in `kms.tf` map
  `aws_kms_key.cloudwatch_logs[0]`, `aws_kms_alias.cloudwatch_logs[0]` and
  `aws_kms_key.sns_topics[0]` to the instance `"stack"`. A stack in
  `us-east-1` keeps its keys. A stack in another region keeps the key there
  while the quarantine release notification still uses it; otherwise that
  key is scheduled for deletion (30 days).
- **Detection outside `us-east-1` is replaced.** The rule, its targets, the
  topic, the auto-revert function with its queue and log group, and their
  keys are destroyed in the stack's region and created in `us-east-1`.
- **The account move function outside `us-east-1` is replaced.** The rule,
  its target and permission, the function and its log group are destroyed in
  the stack's region, with the logs in that group, and created in
  `us-east-1` with a log group key there. A stack in `us-east-1` keeps every
  address and plans no change for them.
- **Email subscriptions must be confirmed again.** The topic is new, so
  every address in `scp_revert_notification_emails` gets a new confirmation
  message, and receives no alert until it confirms.
- **IAM.28 shows failed in member accounts.** The Security Hub baseline no
  longer suppresses this control. The organization analyzer does not satisfy
  it, so it stays failed in every member account until you disable IAM.28 in
  the Security Hub standard.

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
