# Pipeline Module

Creates the TLZPipelineRole in the Deployment Account with cross-account `sts:AssumeRole` permissions. Supports CodePipeline, ECS, and external CI (GitHub/GitLab OIDC) pipeline types.

The CodePipeline variant sources the repository through an existing CodeConnections/CodeStar connection: set `source_connection_arn` to its ARN. The connection also performs change detection — a push to `branch_name` starts the pipeline, so the variant needs no EventBridge rule. While `source_connection_arn` is empty, the CodePipeline resources are not created and the plan reports that the variant is inactive.

The ECS variant has a different source model, see [ECS variant trigger](#ecs-variant-trigger): it listens to CodeCommit repository state change events of the repository named by `repository_name`, and it refuses a connection source at plan time.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `pipeline_type` | Type of CI/CD pipeline: codepipeline, ecs, or external | `string` | `"codepipeline"` | no |
| `repository_name` | Repository the pipeline sources from. codepipeline: full repository ID of the CodeConnections source (`owner/repo`). ecs: name of the CodeCommit repository in this account whose pushes trigger the task (letters, digits, `.` `_` `-`; no slash). `*` and `?` are refused: the external variant's OIDC subject condition is a `StringLike` | `string` | — | yes |
| `source_connection_arn` | ARN of the existing CodeConnections/CodeStar connection that provides the pipeline source. Required for `pipeline_type = "codepipeline"`; must stay empty for `pipeline_type = "ecs"` | `string` | `""` | no |
| `branch_name` | Branch name to trigger the pipeline on. `*` and `?` are refused, as on `repository_name` | `string` | `"main"` | no |
| `deployment_role_arns` | Map of account name to Deployment Role ARN for cross-account access. The key `management` is required: the pipeline's profile assumes that role before Terragrunt starts — see [Credentials of the pipeline](#credentials-of-the-pipeline) | `map(string)` | — | yes |
| `aws_profile` | Name of the AWS profile the stacks run with (the `aws_profile` of `env/common.hcl`). The build writes a profile of this name into the container before Terragrunt starts; it assumes `deployment_role_arns["management"]` with the container's own credentials. Non-empty, no quotes or whitespace — see [Credentials of the pipeline](#credentials-of-the-pipeline) | `string` | — | yes |
| `approval_notification_email` | Email address for pipeline approval notifications | `string` | `""` | no |
| `enable_pipeline_notifications` | Publish pipeline execution state changes to the approval SNS topic via EventBridge rules (CodePipeline variant); see [State-Change Notifications](#state-change-notifications) | `bool` | `false` | no |
| `pipeline_notification_states` | Pipeline execution states reported when `enable_pipeline_notifications` is set; one EventBridge rule per state | `list(string)` | `["STARTED", "SUCCEEDED", "FAILED", "SUPERSEDED", "CANCELED"]` | no |
| `approval_topic_name` | Name of the CodePipeline variant's approval SNS topic (also the notification target). The default is the module's standard name; `CreateTopic` is an upsert, so a live apply-test overrides it with a `tlz-l4test-` name. Must stay inside `tlz-` — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-pipeline-approval"` | no |
| `pipeline_state_rule_name_prefix` | Prefix of the per-state notification rule names (`<prefix>-<lowercased state>`). Same contract as `approval_topic_name` (`PutRule` is an upsert); must stay inside `tlz-`, at most 53 characters so `-superseded` still fits the 64-character rule limit | `string` | `"tlz-pipeline-state"` | no |
| `ecs_cluster_name` | Name of the ecs variant's ECS cluster. `CreateCluster` is idempotent (returns an existing cluster), so a live apply-test overrides it with a `tlz-l4test-` name. Not confined to `tlz-` (no guardrail names an ECS cluster) — see [Upsert-safe resource names](#upsert-safe-resource-names) | `string` | `"tlz-pipeline"` | no |
| `ecs_approval_topic_name` | Name of the ecs variant's approval SNS topic. Same contract as `approval_topic_name`; must stay inside `tlz-` | `string` | `"tlz-ecs-pipeline-approval"` | no |
| `ecs_trigger_rule_name` | Name of the ecs variant's EventBridge trigger rule. Same contract as `pipeline_state_rule_name_prefix` (`PutRule` is an upsert); must stay inside `tlz-` | `string` | `"tlz-ecs-pipeline-trigger"` | no |
| `external_ci_provider` | External CI provider for OIDC federation: github or gitlab | `string` | `"github"` | no |
| `external_ci_thumbprint` | TLS certificate thumbprint for the external CI OIDC provider | `string` | `""` | no |
| `external_ci_audiences` | List of audiences for the external CI OIDC provider | `list(string)` | `["sts.amazonaws.com"]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `pipeline_role_arn` | ARN of the Pipeline Role in the Deployment Account |
| `pipeline_role_name` | Name of the Pipeline Role in the Deployment Account |
| `oidc_role_arn` | ARN of the OIDC role for external CI (empty if pipeline_type is not external) |

## Resources

The module creates the resource types below. They are grouped by the file that declares them, so the grouping doubles as a map of the module. A type appears in more than one row when several files create it for their own purpose. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

| File | Resource types |
|---|---|
| `codepipeline.tf` | `aws_s3_bucket`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`, `aws_iam_role`, `aws_iam_role_policy`, `aws_codebuild_project`, `aws_sns_topic`, `aws_sns_topic_subscription`, `aws_codepipeline` |
| `ecs.tf` | `aws_ecs_cluster`, `aws_iam_role`, `aws_iam_role_policy_attachment`, `aws_iam_role_policy`, `aws_cloudwatch_log_group`, `aws_ecs_task_definition`, `aws_sns_topic`, `aws_sns_topic_subscription`, `aws_cloudwatch_event_rule`, `aws_cloudwatch_event_target` |
| `external.tf` | `aws_iam_openid_connect_provider`, `aws_iam_role`, `aws_iam_role_policy` |
| `main.tf` | `aws_iam_role`, `time_sleep`, `aws_iam_role_policy` |
| `notifications.tf` | `aws_kms_key`, `aws_cloudwatch_event_rule`, `aws_cloudwatch_event_target`, `aws_sns_topic_policy` |

## State-Change Notifications

Behind `enable_pipeline_notifications` (default `false`), one EventBridge rule per state in `pipeline_notification_states` matches "CodePipeline Pipeline Execution State Change" events of the deployment pipeline and publishes them to the approval SNS topic — the same topic (and e-mail subscription) that already carries the manual-approval notifications. The pipeline is addressed by its resource ARN, so the pattern works in every partition without constructing an ARN. A topic policy allows `events.amazonaws.com` to publish, scoped to exactly these rules. EventBridge cannot publish to a topic under the AWS managed key `alias/aws/sns`, so while notifications are on the approval topic is encrypted with a customer-managed key of this module that grants EventBridge `GenerateDataKey*` and `Decrypt`, and the CodePipeline service role gets the same two actions on that key for its approval messages. With notifications off the topic keeps `alias/aws/sns`. The rules exist only for the CodePipeline variant; the ECS and external variants have no pipeline whose states could be matched.

```hcl
enable_pipeline_notifications = true
pipeline_notification_states  = ["FAILED", "SUCCEEDED"]
```

## ECS variant trigger

The ECS variant has no pipeline and therefore no connection-based change
detection. Its only trigger is an EventBridge rule on the default bus that
matches `CodeCommit Repository State Change` events — a push
(`referenceCreated` / `referenceUpdated`) to `branch_name` — and starts one
Fargate task. The rule is scoped through the event's `resources` field to the
CodeCommit repository named by `repository_name`
(`arn:<partition>:codecommit:<region>:<account>:<repository_name>`), so a push to
another repository in the account does not start the task.

That is a different source model from the CodePipeline variant, and the two
cannot be crossed: a repository reached through a CodeConnections connection
(GitHub, GitLab, Bitbucket) emits no CodeCommit event, so the rule would never
match. Two validations refuse the impossible shapes at plan time instead of
letting them plan into a trigger that never fires:

- `pipeline_type = "ecs"` with a non-empty `source_connection_arn` is rejected.
  Use `pipeline_type = "codepipeline"` for a connection source.
- `pipeline_type = "ecs"` with a `repository_name` that is not a CodeCommit
  repository name (for example the `owner/repo` ID a connection source takes)
  is rejected — the ARN built from it would match no event.

The task is awsvpc/FARGATE, so the target needs a network: `ecs_subnet_ids` is
required (EventBridge refuses a FARGATE target without one), and a security
group is required too — unless the caller sets
`ecs_use_default_security_group = true`, which lets ECS attach the DEFAULT
security group of the subnets' VPC. That path is guarded twice, because the
flag is only the caller's word: the validation on `ecs_security_group_ids`
refuses "no group, no acknowledgement" before any provider call, and when the
task will carry the default group the module READS it (`aws_subnet` →
`aws_security_group` → `aws_vpc_security_group_rules` →
`aws_vpc_security_group_rule`, i.e. `ec2:DescribeSubnets`,
`ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules` at plan time)
and a precondition on the EventBridge target refuses when no egress rule of
that group allows all traffic or TCP covering port 443. In every VPC this
landing zone's networking module manages the default group has no rule at
all, so there the flag is refused on the fact; it is meant for a VPC this
landing zone does not manage.

```hcl
pipeline_type          = "ecs"
repository_name        = "landing-zone" # CodeCommit repository in this account
source_connection_arn  = ""
branch_name            = "main"
ecs_subnet_ids         = ["subnet-0123456789abcdef0"]
ecs_security_group_ids = ["sg-0123456789abcdef0"] # allows outbound HTTPS
```

## Upsert-safe resource names

Three APIs this module calls are **upserts** or idempotent creates, not
create-only: SNS `CreateTopic` returns an existing topic of the same name,
EventBridge `PutRule` updates an existing rule of the same name, and ECS
`CreateCluster` returns an existing cluster of the same name. That is fine in
production, but dangerous for a live `terraform test`: an apply-test that used
a fixed account-wide name would silently adopt the real resource, and the
test's automatic teardown would then **delete the live one**. Every such name
is therefore a variable defaulting to the module's standard name, so a production plan
stays empty while a test can scope its own resources:

| Variable | Default | Resource | `tlz-` pinned |
|---|---|---|---|
| `approval_topic_name` | `tlz-pipeline-approval` | `aws_sns_topic.approval` (subscription, topic policy and state-rule targets follow) | yes |
| `pipeline_state_rule_name_prefix` | `tlz-pipeline-state` | `aws_cloudwatch_event_rule.pipeline_state[<state>]` as `<prefix>-<lowercased state>` (targets follow) | yes |
| `ecs_cluster_name` | `tlz-pipeline` | `aws_ecs_cluster.pipeline` | **no** |
| `ecs_approval_topic_name` | `tlz-ecs-pipeline-approval` | `aws_sns_topic.ecs_approval` | yes |
| `ecs_trigger_rule_name` | `tlz-ecs-pipeline-trigger` | `aws_cloudwatch_event_rule.ecs_trigger` (ECS target follows) | yes |

Whether these exist in an account is a fact about that deployment, **not a
safety property** of a test: the first
deployment creates them under the defaults, and an apply-test asserting a
default becomes that resource's deletion. Enabling a variant or the
notifications needs no name change.

This module deploys into the **deployment account**, a member account under
the organization guardrails, so the `tlz-` pin is real protection there and
not only a namespace invariant: `ProtectSNSTopics` and
`ProtectEventBridgeRules` (`tlz-core-guardrails-1.json`) deny tampering only
for `arn:*:sns:*:*:tlz-*` and `arn:*:events:*:*:rule/tlz-*`, and a name that
is a variable would otherwise leave the namespace silently — the validations
carry that invariant and are its only enforcement (exercised with `expect_failures` in the module's
`terraform test`). The cluster name
is deliberately **not** pinned: no guardrail statement names an ECS cluster
ARN, so there is no
protection for a validation to preserve; it carries the ECS naming rule only.

**Fixed, deliberately** (create-only APIs — a collision fails loudly
instead of adopting): the artifact bucket, every IAM role (`TLZ*Role`), the
CodeBuild projects, the CodePipeline `tlz-deployment-pipeline`, the ECS task
definition family `tlz-pipeline` (every apply registers a new revision, none is
adopted) and the log group `/ecs/tlz-pipeline`. A live apply-test would fail on
these before its first assertion, which is the harmless failure mode.

**Leave the defaults unchanged in production** — a changed default is a
destroy/create of the deployed resource (for a topic, subscriptions included).

## Credentials of the pipeline

Terragrunt renders every unit's `provider.tf` and `backend.tf` with `profile = "<aws_profile>"` — for an operator and for the pipeline alike. A build container has no such profile, so the pipeline writes one before its first `terragrunt` command and then walks the operator's path: the profile is a management-account identity (it assumes the management deployment role), the member access roles and the state bucket's role are assumed from it.

- **codepipeline** and **ecs**: the build steps (`codepipeline.tf`) and the task command (`ecs.tf`) write `~/.aws/config` from the module inputs:

  ```ini
  [profile <aws_profile>]
  role_arn = <deployment_role_arns["management"]>
  credential_source = EcsContainer
  role_session_name = tlz-pipeline
  region = <region>
  ```

  `credential_source = EcsContainer` is the role CodeBuild or ECS attached to the container (the CodeBuild service role, the ECS task role); both services set the container credential variables the SDK reads. Nothing else is configured in the container.

- **external** (GitHub Actions, GitLab CI): the module writes no file. The runner's credentials step (for example `configure-aws-credentials`) exports the OIDC session of `TLZExternalCIRole` into the environment, and the runner writes the same profile with `credential_source = Environment` instead of `EcsContainer` before it starts Terragrunt:

  ```ini
  [profile <aws_profile>]
  role_arn = <deployment_role_arns["management"]>
  credential_source = Environment
  role_session_name = tlz-pipeline
  region = <region>
  ```

The session of a role assumed from another role is capped at one hour by AWS; the SDK renews it on its own, and no `duration` is set anywhere in this landing zone. The pipeline's checkout carries `env/common.hcl` and `env/accounts.hcl` with every account id, so no account lookup runs in the container (the container has no AWS CLI).

## Usage Example

```hcl
module "pipeline" {
  source = "./modules/pipeline"

  pipeline_type         = "codepipeline"
  repository_name       = "my-org/my-landing-zone"
  branch_name           = "main"
  source_connection_arn = "arn:aws:codeconnections:eu-central-1:123456789012:connection/11111111-2222-3333-4444-555555555555"
  aws_profile           = "my-landing-zone"
  deployment_role_arns = {
    management = module.deployment_role.role_arn
  }
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
