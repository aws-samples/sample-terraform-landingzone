# IAM Module

Baseline IAM roles, SAML identity providers, and customer-managed policies in the management account.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `roles` | IAM role definitions. Each entry may set `path` and `max_session_duration`; their defaults (`/`, 3600 seconds) are the values IAM applies to a role without them | `list(object)` | `[]` | no |
| `saml_providers` | SAML identity provider definitions | `list(object)` | `[]` | no |
| `customer_managed_policies` | Customer-managed policy definitions | `list(object)` | `[]` | no |
| `iam_users` | IAM users with their group memberships and managed policy attachments. A user gets a console login profile unless `disable_console_access = true`; `auto_generate_password = true` stores the initial password the login profile generates in Secrets Manager (`tlz/iam-user/<user>/password`), and needs console access | `list(object)` | `[]` | no |
| `iam_groups` | IAM groups with their managed policy attachments | `list(object)` | `[]` | no |
| `managed_active_directories` | Managed Microsoft AD and AD Connector directories to create. Credential handling and sharing are described under [Directory Credentials and Sharing](#directory-credentials-and-sharing) | `list(object)` | `[]` | no |
| `vpc_ids` | VPC name → VPC ID, supplied by the networking module. Places the directories | `map(string)` | `{}` | no |
| `subnet_ids` | `<vpc_name>.<subnet_name>` → subnet ID, supplied by the networking module. Places the directories | `map(string)` | `{}` | no |
| `resolver_endpoint_ids` | Outbound Route 53 Resolver endpoint name → endpoint ID, supplied by the networking module. The Managed AD FORWARD resolver rules route through the endpoint named in `resolver_endpoint_name` | `map(string)` | `{}` | no |
| `account_ids` | Account name → account ID for trust policies and for resolving account names in `secret_config` and `share_targets` | `map(string)` | `{}` | no |
| `ou_name_to_id` | OU name → OU ID for resolving `share_targets.organizational_units`, supplied by the organization stack | `map(string)` | `{}` | no |
| `account_ou_ids` | Account name → ID of the OU the account is placed in, supplied by the accounts stack | `map(string)` | `{}` | no |
| `mad_secret_access_role_name` | Role the module assumes in the account named by `secret_config.account` to place a directory admin secret there | `string` | `"AWSControlTowerExecution"` | no |
| `management_account_id` | Management account ID, used to honour `exclude_management_account` when resolving deployment targets | `string` | `""` | no |
| `enable_service_catalog` | Create the Service Catalog propagation role for cross-account portfolio sharing | `bool` | `false` | no |
| `enable_stackset_roles` | Create the CloudFormation StackSet administration and execution roles | `bool` | `false` | no |
| `is_management_account` | Select which StackSet role is created: the administration role in the management account, the execution role in member accounts | `bool` | `false` | no |
| `secrets_kms_key_arn` | Optional KMS key ARN for the Secrets Manager secrets holding auto-generated user passwords. Empty keeps the Secrets Manager service key (`aws/secretsmanager`); the module creates no key | `string` | `""` | no |
| `enable_break_glass` | Create the break-glass access package described under [Break-glass access](#break-glass-access) | `bool` | `false` | no |
| `break_glass_config` | Break-glass user set: `user_count` (1-10, default 2) numbered users named `<user_prefix>-01` … (default prefix `tlz-break-glass`), each capped by the mandatory `permissions_boundary` policy ARN | `object` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| `role_arns` | Map of role name → role ARN |
| `saml_provider_arns` | Map of provider name → provider ARN |
| `policy_arns` | Map of policy name → policy ARN |
| `instance_profile_arns` | Map of role name → instance profile ARN, for roles with `instance_profile = true` |
| `deployment_targets` | Map of resource type → resolved deployment targets, with the management account removed where `exclude_management_account` is set |
| `service_catalog_propagation_role_arn` | ARN of the Service Catalog propagation role (empty when disabled) |
| `stackset_admin_role_arn` | ARN of the CloudFormation StackSet administration role (management account only) |
| `stackset_execution_role_arn` | ARN of the CloudFormation StackSet execution role (member accounts only) |
| `user_names` | Map of IAM user name → user name (confirms creation) |
| `group_names` | Map of IAM group name → group name (confirms creation) |
| `managed_ad_ids` | Map of directory name → directory ID, for both Managed Microsoft AD and AD Connector directories. This is the handover point for the directory identifiers: a workload stack that has to join instances to a directory reads it from here. Empty until `managed_active_directories` is set together with `vpc_ids` and `subnet_ids` — `stacks/management/iam` supplies the latter two from the networking stack. |
| `managed_ad_dns_addresses` | Map of Managed Microsoft AD directory name → DNS server addresses of the directory (the resolvers the domain-join association hands to instances) |
| `managed_ad_domain_names` | Map of Managed Microsoft AD directory name → fully qualified domain name |
| `managed_ad_resolver_rule_ids` | Map of directory name → Route 53 Resolver rule ID. The rule is a FORWARD rule targeting the directory's DNS servers through the outbound endpoint named in `resolver_endpoint_name` — AD domains resolve only against the directory's own DNS servers, which VPC-standard resolution cannot reach. A resolver rule changes DNS behaviour only in VPCs it is associated with: set `vpc_associations` on the directory (VPC names from `vpc_ids`) and the module creates the `aws_route53_resolver_rule_association` itself, or read this output and associate the rule in the owning stack for VPCs this module does not manage. A rule with neither path is ineffective — a `check` block warns about it. |

## Resources

The module creates the resource types below, all of them in `main.tf` (the
break-glass package in `break-glass.tf`). Which of them a run actually creates
depends on the inputs — the `enable_*` toggles and the collections that are
filled.

- `aws_iam_role`
- `aws_iam_instance_profile`
- `aws_iam_saml_provider`
- `aws_iam_policy`
- `aws_iam_user`
- `aws_iam_user_policy_attachment`
- `aws_iam_user_login_profile`
- `random_password` (Managed Microsoft AD admin passwords)
- `aws_secretsmanager_secret`
- `aws_secretsmanager_secret_version`
- `aws_iam_group`
- `aws_iam_group_membership`
- `aws_iam_group_policy_attachment`
- `aws_iam_role_policy`
- `aws_directory_service_directory`
- `aws_route53_resolver_rule`
- `aws_route53_resolver_rule_association`
- `aws_directory_service_shared_directory`
- `aws_directory_service_log_subscription`
- `aws_cloudwatch_log_group`
- `aws_kms_key`
- `aws_kms_alias`
- `aws_iam_role_policy_attachment`
- `aws_iam_role_policy_attachments_exclusive`
- `aws_iam_role_policies_exclusive`

## Deployment Targets

Every role, policy, user and group is created in the account the provider runs
in; `stacks/management/iam` is the only stack that calls this module, so that is
the management account. `deployment_targets` is accepted and resolved into the
`deployment_targets` output, but the module creates nothing in the accounts it
names, and a `check` block warns on every plan that sets it. The shipped
`env/common.hcl.example` gives `Backup-Role` and `EC2-Default-SSM-Role` the
targets Security, Infrastructure and Workloads; neither role exists in a member
account after an apply. The organization backup policy `primary-backup-plan`
selects its resources with `arn:<partition>:iam::$account:role/Backup-Role` in
each member account it is attached to, so its backup jobs need that role there,
created by other means (for example a CloudFormation StackSet), before the
policy is attached.

## Role Policies and Exclusive Management

Managed and inline policies of the roles in `var.roles` are carried by
standalone resources: `aws_iam_role_policy_attachment.roles` attaches each
resolved managed policy ARN, `aws_iam_role_policy.roles` writes each declared
inline policy. Exclusivity is enforced per role by
`aws_iam_role_policy_attachments_exclusive.this` and
`aws_iam_role_policies_exclusive.this`: a policy attached or written out of
band is removed on the next apply. The exclusive inline list of a role also
contains the `tlz-mad-secret-access-*` policies the module itself writes for
roles named in `secret_access_role_names`, so the two writers agree on the
target state. Inline exclusivity applies uniformly to every role of
`var.roles`; a role without declared inline policies carries an empty exclusive
list, which removes out-of-band inline policies.

### State transition from the embedded role arguments

Earlier versions attached these policies through the `managed_policy_arns`
argument and `inline_policy` blocks of `aws_iam_role`. Those embedded arguments
are not separate state objects, so `moved` blocks cannot carry them over. The
transition is controlled instead: on the first plan after upgrading, Terraform
shows the new attachment, inline-policy and exclusive resources as additions.
For the policies the configuration declares, applying them is safe on an
existing deployment: `AttachRolePolicy` is idempotent for an already attached
policy and `PutRolePolicy` overwrites the identical document. The two exclusive
resources, however, detach every policy the configuration does not declare.
**Upgrade note:** on the first apply, a role of `var.roles` loses every managed
policy attached and every inline policy written outside Terraform, and a role
without declared policies carries an empty exclusive list, so it loses all of
them. Declare such a policy in the role's entry before you upgrade if the role
still needs it. The role resource itself keeps its recorded argument values
(both arguments are optional and computed in the provider), so removing them
from the configuration produces no change on the role.

## Account Names in Policy Documents

Trust policies, inline policies and customer-managed policy documents arrive as JSON strings, so they cannot carry a Terraform reference. To keep account IDs out of the configuration, write the account **name** as the mark `@@account_id:<name>@@` and the module resolves it against `account_ids`:

```hcl
roles = [
  {
    name = "TlzAuditRole"
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::@@account_id:audit@@:root" }
        Action    = "sts:AssumeRole"
      }]
    })
  }
]
```

The mark uses the same `@@…@@` form as the organization ID and home region marks in the configuration layer. A mark of another kind passes through unchanged; a mark naming an account that `account_ids` does not carry is reported by the `account_name_marks_resolve` check instead of travelling into the IAM document.

## Directory Credentials and Sharing

For entries in `managed_active_directories` the module handles credentials without ever carrying a password in its source:

- **Managed Microsoft AD** (`directory_type = "MicrosoftAD"`): the module generates the admin password, stores it in Secrets Manager as `tlz/mad/<directory>/admin-password` and encrypts it with the directory's own KMS key (`alias/tlz/mad/<directory>/secret`). Roles listed in `secret_access_role_names` may read it.
- **AD Connector** (`directory_type = "ADConnector"`): the password belongs to the existing on-premises service account named in `connect_settings.customer_username` and cannot be generated. Set `password_secret_name` to the name or ARN of the Secrets Manager secret that holds it; the module reads the value from there.

`shared_account_ids` lists the AWS accounts a directory is shared with. Directory Service accepts account targets only, so each entry must be a 12-digit account ID; the module rejects anything else before the plan is applied.

### Metadata, log retention, secret placement and OU share targets

Each `managed_active_directories` entry may additionally carry:

- `description` and `net_bios_domain_name` — directory metadata; the NetBIOS name is 1-15 characters of letters, digits and hyphens.
- `log_retention_days` — when set together with `log_group_name`, the module creates the CloudWatch log group itself with that retention (one of the CloudWatch retention values). Without it the subscription keeps pointing at an externally managed group. `log_group_kms_key_arn` optionally encrypts the created group with a customer-managed key; null keeps the CloudWatch service encryption.
- `secret_config` — name, account and region of the generated admin secret (Managed Microsoft AD only). `admin_secret_name` replaces the fixed `tlz/mad/<directory>/admin-password` form; `account` (a 12-digit ID or a key of `account_ids`) and `region` place the secret elsewhere via a role-assuming provider alias (`mad_secret_access_role_name` names the role, default `AWSControlTowerExecution`). The placement runs over one static alias, so all placing entries must name the same account and region. A placed secret cannot use the per-directory KMS key (the key is regional and lives in the management account) and falls back to the Secrets Manager service key of its destination; `secret_access_role_names` cannot be combined with a placed secret, because a management-account identity policy alone cannot read it.
- `resolver_rule_name` — creates a Route 53 Resolver FORWARD rule for the AD domain, targeting the directory's DNS servers (Managed Microsoft AD: the two provisioned DNS addresses; AD Connector: the configured `customer_dns_ips`). Requires `resolver_endpoint_name`, an outbound endpoint the networking module exports (a key of `resolver_endpoint_ids`), because Route 53 Resolver accepts FORWARD rules only with an outbound endpoint. Note for existing deployments: rules created by earlier module versions were SYSTEM rules — the type change forces a replacement of the rule and its associations on the next apply, and `resolver_endpoint_name` must be set for every directory that names a rule.
- `share_targets` — `organizational_units` names OUs (keys of `ou_name_to_id`) whose member accounts receive the directory; `excluded_accounts` (IDs or keys of `account_ids`) subtracts from that expansion. The module resolves OU names to accounts through the stack-supplied maps (`account_ids`, `ou_name_to_id`, `account_ou_ids`) — Directory Service itself accepts account targets only. An OU that resolves to no account is reported by a check block. Accounts already covered by `shared_account_ids` produce exactly one share.

```hcl
managed_active_directories = [
  {
    name                 = "corp"
    vpc_name             = "shared-vpc"
    subnet_names         = ["private-a", "private-b"]
    domain_name          = "corp.example.com"
    description          = "Corporate directory"
    net_bios_domain_name = "CORP"
    log_group_name       = "/aws/directoryservice/corp"
    log_retention_days   = 365
    secret_config = {
      admin_secret_name = "landing-zone/directory/corp-admin"
      account           = "audit"
      region            = "eu-central-1"
    }
    share_targets = {
      organizational_units = ["Workloads"]
      excluded_accounts    = ["sandbox"]
    }
  },
]
```

## Break-glass access

Behind `enable_break_glass` (default `false`) the module creates a small,
numbered set of emergency console users — `<user_prefix>-01` …
`-<user_count>` — for the management account: each carries the **mandatory**
permissions boundary from `break_glass_config.permissions_boundary`,
`AdministratorAccess` within that boundary, and a console login profile whose
initial password lands in Secrets Manager
(`tlz/break-glass/<user>/password`, deployment region) and must be changed at
first sign-in. The matching usage alarm is the monitoring module's
`enable_break_glass_alarm` — a metric filter on the CloudTrail log group over
the same `user_prefix`, with a mandatory notification target.

Operational boundaries, stated plainly:

- **The initial password stands in the Terraform state** as well as in
  Secrets Manager (the provider generates it; a delivered password cannot
  avoid the state). `password_reset_required` retires that copy at first
  sign-in. Protect the state accordingly — the same boundary the
  `auto_generate_password` path of `iam_users` carries.
- **Register MFA devices immediately after deployment** — Terraform cannot
  enroll them. Store password and MFA device with different trusted
  individuals (dual authorization).
- **No access keys.** Break-glass is console access; the module deliberately
  creates no long-lived API credentials.
- **No quarantine exemption is needed**: SCPs do not bind the management
  account, where these users live.

```hcl
enable_break_glass = true
break_glass_config = {
  permissions_boundary = "arn:aws:iam::111111111111:policy/tlz-boundary"
  # user_count = 2, user_prefix = "tlz-break-glass" (defaults)
}
```

## Role Path and Session Duration

Each `roles` entry may carry an IAM `path` (begins and ends with `/`, e.g. `/landing-zone/security/`) and a `max_session_duration` between 3600 and 43200 seconds. Both are optional: the defaults `/` and 3600 are exactly what IAM assigns to a role without them, so existing entries plan unchanged.

```hcl
roles = [
  {
    name                 = "AuditReader"
    assume_role_policy   = file("trust.json")
    path                 = "/landing-zone/audit/"
    max_session_duration = 14400
  },
]
```

## Usage Example

```hcl
module "iam" {
  source = "./modules/iam"

  roles                     = var.roles
  saml_providers            = var.saml_providers
  customer_managed_policies = var.customer_managed_policies
  account_ids               = module.accounts[0].account_ids
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
