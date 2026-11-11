# Accounts Module

Creates AWS Organizations member accounts with optional IAM Identity Center (SSO) integration and OU placement.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `accounts` | List of accounts to create. `quarantined = true` creates the account inside the quarantine OU (`quarantine_ou_id`) instead of its declared OU, see [Quarantine](#quarantine) | `list(object)` | — | yes |
| `enable_control_tower_enrollment` | Report the enrollment steps for newly created accounts through a `check` block | `bool` | `false` | no |
| `ou_name_to_id` | OU name → OU ID, supplied by the organization module. Falls back to the organization data source when empty | `map(string)` | `{}` | no |
| `ignored_ou_ids` | IDs of the OUs the organization module reports as ignored (`ignore = true`, or below such an OU). An account declared there is suspended: created and listed by `account_ids`, but left out of `active_account_ids` and `active_account_ou_ids`, so no downstream stack configures it | `list(string)` | `[]` | no |
| `organization_root_id` | Organization root ID for OU name resolution. Empty resolves the root from the organization data source | `string` | `""` | no |
| `account_access_role_name` | Role the deployment-account provider assumes to reach existing accounts; also the CreateAccount role while `created_account_role_name` is null | `string` | `"AWSControlTowerExecution"` | no |
| `created_account_role_name` | Role CreateAccount makes inside each new member account; `null` = same as `account_access_role_name` | `string` | `null` | no |
| `close_on_deletion` | Close account on removal from Terraform | `bool` | `false` | no |
| `management_account_alias` | IAM account alias (sign-in URL name) of the management account — the account this stack runs in. Empty sets none; see [Account Alias](#account-alias) | `string` | `""` | no |
| `default_tags` | Tags applied to all accounts | `map(string)` | `{}` | no |
| `enable_sso_assignment` | Binding gate for the per-account SSO assignment paths (`accounts[].sso {}` and `accounts[].sso_user_email`). Assignments are additionally skipped while IAM Identity Center is not provisioned. Does not gate `identity_center_permission_sets`/`identity_center_assignments` | `bool` | `false` | no |
| `sso_permission_set_name` | Permission set name for SSO | `string` | `"AWSAdministratorAccess"` | no |
| `sso_principal_type` | SSO principal type: GROUP or USER | `string` | `"GROUP"` | no |
| `sso_principal_name` | Display name of SSO group or user | `string` | `""` | no |
| `enable_account_warming` | Honour the `warm` field of each account. When enabled, warm accounts are created but skip security and networking configuration, and the module publishes the account-warming runbook shared to every warm-marked account; when disabled, the field is ignored and every account is configured fully | `bool` | `false` | no |
| `enable_deployment_account` | Write the account-metadata SSM parameters to the deployment account instead of the management account | `bool` | `false` | no |
| `deployment_account_id` | Account ID that holds the account-metadata parameters. Required when `enable_deployment_account` is set | `string` | `""` | no |
| `region` | Region of the module-owned `aws.deployment_account` provider configuration | `string` | `""` | no |
| `aws_profile` | Local AWS CLI profile of the module-owned `aws.deployment_account` provider configuration; empty uses the default credential chain | `string` | `""` | no |
| `identity_center_permission_sets` | IAM Identity Center permission sets to create | `list(object)` | `[]` | no |
| `identity_center_assignments` | IAM Identity Center account assignments to create | `list(object)` | `[]` | no |
| `account_ids` | Account name → account ID, used to resolve assignment targets by name | `map(string)` | `{}` | no |
| `quarantine_ou_id` | ID of the quarantine OU (output `quarantine_ou_id` of the organization module). An account with `quarantined = true` is created inside it instead of its declared OU; empty refuses any quarantined account at plan time. See [Quarantine](#quarantine) | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| `accounts` | Map of email → account details (id, arn, name, status) |
| `account_ids` | Map of account name → account ID |
| `sso_assignments` | Map of all planned SSO assignments: per-account entries keyed by email, `identity_center_assignments` entries keyed by principal/permission set/account |
| `sso_users` | Map of email → created IAM Identity Center users |
| `permission_set_arns` | Map of permission set name → ARN |
| `warm_account_ids` | IDs of accounts marked warm/standby — these skip security and networking configuration |
| `warm_account_names` | Names of accounts marked warm/standby — these skip security and networking configuration |
| `suspended_account_names` | Names of accounts declared in an ignored OU — these are no deployment targets and skip every downstream configuration |
| `active_account_ids` | Map of account name → account ID excluding warm and suspended accounts — the deployment targets for downstream stacks |
| `active_account_ou_ids` | Map of account name → its declared OU ID excluding warm and suspended accounts — OU-resolved deployment targets for downstream stacks; a quarantined account keeps its declared OU here |
| `quarantined_account_names` | Names of accounts marked `quarantined = true`; they are created inside the quarantine OU and released by `quarantined = false` |

## Resources

The module creates the resource types below. They are grouped by the file that declares them, so the grouping doubles as a map of the module. A type appears in more than one row when several files create it for their own purpose. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

| File | Resource types |
|---|---|
| `main.tf` | `aws_organizations_account`, `aws_ssm_parameter`, `aws_iam_account_alias` |
| `sso.tf` | `aws_identitystore_user`, `aws_ssoadmin_account_assignment`, `aws_ssoadmin_permission_set`, `aws_ssoadmin_managed_policy_attachment`, `aws_ssoadmin_permission_set_inline_policy`, `aws_ssoadmin_customer_managed_policy_attachment`, `aws_ssoadmin_permissions_boundary_attachment` |
| `warming.tf` | `aws_ssm_document` |

## Providers

The module uses the default `aws` provider for the AWS Organizations resources and
declares a second, module-owned configuration `aws.deployment_account` for the
account-metadata parameters in SSM Parameter Store. That configuration is built from
`region` and `aws_profile`, and — when `enable_deployment_account` is set — assumes
`account_access_role_name` in `deployment_account_id`. No provider configuration has
to be passed in, so the module directory can be validated and tested on its own.

## Account Alias

`management_account_alias` sets the IAM account alias — the human-readable name that replaces the 12-digit account ID in the AWS sign-in URL — for the account this stack runs in, the management account. The alias follows the IAM rule (3-63 characters, lowercase letters, digits and single hyphens, beginning and ending with a letter or digit) and must be unique across all of AWS; an account carries at most one.

The alias is a property of the account the provider authenticates to. Aliases for the accounts this module *creates* would each need their own provider configuration, which Terraform cannot produce per entry — setting them remains a per-account deployment concern.

```hcl
management_account_alias = "example-landing-zone"
```

## Account warming

The warm-account lifecycle (`enable_account_warming` + `accounts[].warm`)
marks new accounts and keeps them out of downstream configuration. The
warming itself — the reference procedure launches a temporary EC2 instance in
the **new** account for ~15 minutes, terminates it and flags the account —
ships as a declarative runbook: behind the same switch, `warming.tf` creates
the SSM Automation document `tlz-account-warming`
(`configurations/ssm-documents/account-warming.json`) and shares it with
every warm-marked account. The document encodes the whole procedure —
throwaway VPC and subnet, a small instance from the current Amazon Linux 2023
AMI parameter of the target partition, a bounded ISO-8601 warm duration
(default `PT15M`), removal of everything it created, and the flag
`<SsmPrefix>/account/pre-warmed` (`/tlz` by default) set to `true` only at
the successful end. A run that fails partway aborts, leaves the flag `false`,
and names what it had created in its step outputs — remove those leftovers
and start a fresh run.

One step stays operational by nature: **starting the run**, once per new
account, in that account. Terraform cannot express a resource that must be
created and destroyed within the same run, and the no-execution convention
rules out shell workarounds — so the module delivers the runbook, and the
operator (or the account-baseline process) executes it:

```bash
# in the new account, e.g. via the account access role
# <partition> is the partition of the deployment: aws, aws-us-gov, or aws-eusc
aws ssm start-automation-execution \
  --document-name "arn:<partition>:ssm:<region>:<management-account-id>:document/tlz-account-warming"
```

After the run, `<SsmPrefix>/account/pre-warmed` reads `true`; promote the
account by setting `warm = false` and re-running the pipeline.

## Quarantine

An account declared with `quarantined = true` is created inside the quarantine
OU (`quarantine_ou_id`, the organization module's output of the same name)
instead of its declared OU. The organization module attaches the quarantine
SCP to that OU in its own apply, so the account carries the SCP from the
moment it exists; the SCP denies every action to every principal except the
exempt roles (`AWSControlTowerExecution`, `TLZDeploymentRole`, `tlz-*`,
`OrganizationAccountAccessRole`), through which the fan-out configures the
account. The declared OU stays the account's deployment scope:
`active_account_ids` keeps the account and `active_account_ou_ids` publishes
the declared OU, so OU-scoped deployments reach it while it is quarantined.

The release is a declaration change: set `quarantined = false` and apply this
module, which moves the account to its declared OU in place. Two checks read
on every plan: `quarantined_accounts_named` lists the quarantined accounts
with that sentence, and `quarantine_exempts_access_roles` warns when
`account_access_role_name` or `created_account_role_name` matches none of the
exempt patterns, because the fan-out would then be denied in the account. A
quarantined account without `quarantine_ou_id` is refused at plan time; a
custom quarantine SCP document must exempt the access role itself.

Setting the flag on an account that already exists moves it into the
quarantine OU, under deny-all for its workloads, on the next apply; the flag
is meant for new entries.

## Usage Example

```hcl
module "accounts" {
  source = "./modules/accounts"

  organization_root_id     = data.aws_organizations_organization.current.roots[0].id
  accounts                 = var.accounts
  account_access_role_name = var.account_access_role_name
  default_tags             = var.default_tags

  enable_sso_assignment   = var.enable_sso_assignment
  sso_permission_set_name = var.sso_permission_set_name
  sso_principal_type      = var.sso_principal_type
  sso_principal_name      = var.sso_principal_name
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
