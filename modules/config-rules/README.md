# Config Rules Module

Organization-wide deployment of AWS Config Managed Rules, Custom Rules and Conformance Packs, and optional auto-remediation.

## Deployment Targets

Organization rules are created for the whole organization and narrowed down through exclusions. `deployment_targets` expresses the intended scope, and the module resolves every entry to the account IDs it stands for:

| Entry form | Resolution |
|---|---|
| 12-digit account ID | the account itself |
| account name | `account_ids[<name>]` |
| OU name | every account whose `account_ou_ids` entry equals `ou_name_to_id[<name>]` |

Accounts outside the resolved set are excluded from the rule. An entry that matches none of the three forms is rejected before the plan is applied — otherwise it would exclude every account and the rule would evaluate nothing. If a resolvable target set ends up empty (for example an OU without member accounts), the plan reports it as a warning.

## Evaluation Scope Selectors

A custom rule takes exactly one selector form that decides which resources
trigger its evaluation:

- **Resource types**: `resource_types_scope` lists the types
  (`["AWS::S3::Bucket", "AWS::EC2::Instance"]`).
- **Single resource**: `resource_id_scope` names one resource; the API
  requires exactly one `resource_types_scope` entry next to it.
- **Tag**: `tag_key_scope` (with an optional `tag_value_scope`) matches
  resources by tag; this form cannot be combined with the type or ID form.

```hcl
custom_rules = [
  {
    name                 = "bucket-owner-check"
    lambda_function_arn  = "arn:aws:lambda:eu-central-1:111111111111:function:evaluator"
    description          = "Evaluates the central data bucket"
    resource_types_scope = ["AWS::S3::Bucket"]
    resource_id_scope    = "central-data"
  }
]
```

## Cross-Account Remediation Documents

A remediation whose automation document lives in another account names that
account: `target_account_name` is a key of `account_ids`, `target_id` stays
the plain document name, and the module addresses the document by its full
ARN (`arn:<partition>:ssm:<region>:<account>:document/<name>`; the partition
comes from the deployment, not from a hardcoded prefix). `target_version`
pins the document version the remediation executes:

```hcl
remediation_configs = [
  {
    rule_name           = "encrypted-volumes"
    target_id           = "org-encrypt-volume"
    target_version      = "2"
    target_account_name = "Audit"
    automatic           = true
  }
]
```

## Configuration-Supplied Functions

Behind `enable_custom_rule_lambdas = true`, a `custom_rules` entry may
describe its evaluator instead of naming an existing ARN, and a
`remediation_configs` entry may describe the function its automation document
invokes. Both blocks carry the same five fields: `source_code` (the function
code as a string), `handler` (`<module>.<function>` — the file name inside
the deployment archive is derived from the module part and the runtime's
language), `runtime`, `timeout` (default 30 seconds) and `role_policy` (the
execution role policy as a JSON string, scoped by the rule's author).

The code and the policy arrive as strings because a file path would not
survive the deployment cache; the configuration loader resolves the file
forms `source_file` and `role_policy_file` (paths relative to the repository
root) to their content, so the static configuration layers can reference
files. Each function gets its own execution role: the trust policy and a log
policy limited to the function's own log group come from the versioned
templates under `configurations/policies/general/`, the execution policy is
the configuration-supplied one. Evaluator functions additionally receive the
resource-based permission AWS Config needs to invoke them from every member
account; remediation functions are invoked through the automation document's
assume role and carry none.

A remediation entry hands its created function to the automation document
through the token `__REMEDIATION_LAMBDA_ARN__` in one of its parameters'
`static_values`; the module replaces the token with the function ARN. Token
and `target_document_lambda` block require each other, so no function is
created that nothing invokes and no token reaches the document verbatim.

```hcl
enable_custom_rule_lambdas = true

custom_rules = [
  {
    name = "s3-bucket-check"
    lambda = {
      source_file = "configurations/lambda/s3-bucket-check.py" # loader-resolved
      handler     = "index.handler"
      runtime     = "python3.12"
      role_policy = jsonencode({
        Version   = "2012-10-17"
        Statement = [{ Effect = "Allow", Action = "config:PutEvaluations", Resource = "*" }]
      })
    }
  }
]

remediation_configs = [
  {
    rule_name = "s3-bucket-check"
    target_id = "tlz-fix-bucket-policy" # the automation document
    parameters = {
      FunctionArn = { static_values = ["__REMEDIATION_LAMBDA_ARN__"] }
    }
    target_document_lambda = {
      source_file = "configurations/lambda/fix-bucket-policy.py"
      handler     = "index.handler"
      runtime     = "python3.12"
      role_policy = jsonencode({
        Version   = "2012-10-17"
        Statement = [{ Effect = "Allow", Action = "s3:PutBucketPolicy", Resource = "*" }]
      })
    }
  }
]
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `managed_rules` | AWS-managed Config rules, each with an optional `description` and an optional `resource_types_scope` limiting evaluation to the listed resource types | `list(object)` | `[]` | no |
| `custom_rules` | Lambda-based custom rules, each with an optional `description` and one evaluation scope selector. The evaluator is either an existing function (`lambda_function_arn`) or a `lambda` block the module creates the function from. See [Evaluation Scope Selectors](#evaluation-scope-selectors) and [Configuration-Supplied Functions](#configuration-supplied-functions) | `list(object)` | `[]` | no |
| `enable_custom_rule_lambdas` | Create the functions that `custom_rules[].lambda` and `remediation_configs[].target_document_lambda` describe. Off, every function ARN comes from outside | `bool` | `false` | no |
| `config_lambda_log_retention_days` | Retention of the execution log group each created evaluator and remediation Lambda owns, `/aws/lambda/<function name>` (`0` = never expire). One value for the whole set. See [Lambda execution log groups](#lambda-execution-log-groups) | `number` | `365` | no |
| `conformance_packs` | Conformance packs, created as `aws_config_organization_conformance_pack`: AWS Config deploys each pack to the member accounts of the organization in the region the module runs in. `excluded_accounts` (12-digit account IDs) is merged with `global_excluded_accounts` | `list(object)` | `[]` | no |
| `remediation_configs` | Auto-remediation configurations. `target_version` pins the document version; `target_account_name` names the account (a key of `account_ids`) that owns the document — the module then addresses it by its full ARN. `target_document_lambda` creates the remediation function the automation document invokes — see [Configuration-Supplied Functions](#configuration-supplied-functions) | `list(object)` | `[]` | no |
| `account_ids` | Account name → account ID. Resolves account names in `deployment_targets` | `map(string)` | `{}` | no |
| `ou_name_to_id` | OU name → OU ID. Resolves OU names in `deployment_targets` | `map(string)` | `{}` | no |
| `account_ou_ids` | Account name → ID of the organizational unit that holds the account. Resolves OU names in `deployment_targets` | `map(string)` | `{}` | no |
| `management_only_rules` | Config rules that are created in the management account only instead of organization-wide, each with an optional `description` and `tags`. Tags are available on this rule form only — the organization-wide rule API carries none | `list(object)` | `[]` | no |
| `global_excluded_accounts` | Account IDs excluded from every organization Config rule and organization conformance pack, for accounts without a Config recorder | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `rule_arns` | Map of rule name → ARN (managed + custom) |
| `conformance_pack_arns` | Map of pack name → ARN |
| `managed_rule_count` | Number of managed rules |
| `custom_rule_count` | Number of custom rules |
| `conformance_pack_count` | Number of conformance packs |
| `remediation_count` | Number of auto-remediations |

## Resources

The module creates the resource types below. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

`main.tf`:

- `aws_config_organization_managed_rule`
- `aws_config_config_rule`
- `aws_config_organization_custom_rule`
- `aws_config_organization_conformance_pack`
- `aws_config_remediation_configuration`

A deployment that created conformance packs with an earlier version of this
module holds them as account-level packs (`aws_config_conformance_pack`) in the
management account. The first apply with this version deletes those packs and
creates organization packs of the same names in their place; evaluation
results of the old packs are not carried over. Organization packs need trusted
access for `config-multiaccountsetup` (the organization stack enables it with
logging) and a Config recorder in every account they are not excluded from.

`lambda-functions.tf` (behind `enable_custom_rule_lambdas`):

- `aws_iam_role`
- `aws_iam_role_policy`
- `aws_lambda_function`
- `aws_lambda_permission`

## Usage Example

```hcl
module "config_rules" {
  source = "./modules/config-rules"

  managed_rules = [
    {
      name              = "cloud-trail-enabled"
      source_identifier = "CLOUD_TRAIL_ENABLED"
    },
    {
      name              = "encrypted-volumes"
      source_identifier = "ENCRYPTED_VOLUMES"
      excluded_accounts = ["123456789012"]
    },
  ]

  conformance_packs = [
    {
      name            = "cis-benchmark"
      template_s3_uri = "s3://my-bucket/conformance-packs/cis.yaml"
    },
  ]
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
each evaluator and remediation function this module creates owns its group
as well:

| Log group | Resource | Retention |
|---|---|---|
| `/aws/lambda/<function name>`, one per entry of the created set | `aws_cloudwatch_log_group.config_lambda` (`for_each` over the same map as the functions) | `config_lambda_log_retention_days` (default `365`) |

Each name derives from its function rather than being spelled out again, so a
group can never disagree with the function it belongs to. The group set uses `for_each` over the
identical map, so an entry cannot gain a function without gaining its group.
`aws_lambda_permission.config_invoke` — the statement that lets AWS Config
invoke an evaluator — depends on the groups. The remediation functions are
invoked through the automation document's assume role, a path no resource in
this module gates, so nothing here can order that first invocation.

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
terragrunt import 'aws_cloudwatch_log_group.config_lambda["tlz-config-rule-<rule name>"]' /aws/lambda/tlz-config-rule-<rule name>
terragrunt import 'aws_cloudwatch_log_group.config_lambda["tlz-remediation-<rule name>"]' /aws/lambda/tlz-remediation-<rule name>
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
