# Getting Started

Step-by-step guide to deploy a landing zone from a blank AWS account.

## Prerequisites

| Tool | Version |
|---|---|
| Terraform | >= 1.14 |
| Terragrunt | >= 1.0 |
| AWS CLI | >= 2.x |

You need Admin credentials in the AWS account that will become the Management Account.

```bash
aws configure --profile your-mgmt-profile
aws sts get-caller-identity --profile your-mgmt-profile
```

Verify the output shows the correct account ID. This account must NOT already be a member of another AWS Organization.

## Control Tower (Optional)

TLZ works with or without AWS Control Tower.

| Mode | Setting | Cross-Account Role |
|---|---|---|
| Without Control Tower | `enable_control_tower = false` | `OrganizationAccountAccessRole` (created automatically by AWS Organizations) |
| With Control Tower | `enable_control_tower = true` | `AWSControlTowerExecution` (created by Control Tower) |

Without Control Tower, TLZ manages CloudTrail, Config, and governance directly. With Control Tower, set it up via the AWS Console first, then enable it in TLZ.

```hcl
# env/common.hcl
enable_control_tower     = false
account_access_role_name = "OrganizationAccountAccessRole"  # or "AWSControlTowerExecution" with CT
```

Two roles, not one, since 0.5.10: `account_access_role_name` is the role the stacks ASSUME to reach
an account that already exists; `created_account_role_name` is the role `CreateAccount` makes inside a
NEW account (unset, the default, means the same name). When the two differ -- for example
`AWSControlTowerExecution` to reach the existing accounts of a Control Tower organization and
`OrganizationAccountAccessRole` for the accounts TLZ creates -- a new account is reachable by the stacks
only once `account_access_role_name` exists inside it: Control Tower enrolment creates that role when it
IS the Control Tower role, otherwise you create it by hand (a role of that name trusting the management
account) before the next org-wide apply. Until then every cross-account unit for that account fails with
`Cannot assume IAM Role` (see Troubleshooting in docs/operations.md).

## 1. Clone and Configure

```bash
git clone <repository-url>
cd terraform-landing-zone
```

Create your local configuration files from the templates:

```bash
cp env/common.hcl.example env/common.hcl
cp env/accounts.hcl.example env/accounts.hcl
```

The `.example` files are committed to the repo with placeholder values. Your local copies (`common.hcl`, `accounts.hcl`) are gitignored — they contain your real AWS profile, email addresses, and account IDs.

Edit `env/common.hcl` with your values:

```hcl
locals {
  region            = "eu-central-1"        # Your home region
  aws_profile       = "your-mgmt-profile"   # AWS CLI profile name
  partition         = "aws"                  # "aws" or "aws-eusc"
  state_backend     = "local"               # "local" for first deployment; "s3" needs real state_bucket_name/lock_table_name (Deployment Modes)

  # Cross-account role — depends on Control Tower choice
  account_access_role_name = "OrganizationAccountAccessRole"

  # Start with only foundation modules enabled
  enable_organization = true
  enable_accounts     = true
  enable_logging      = false
  enable_security     = false
  enable_iam          = false
  enable_config_rules = false
  enable_networking   = false
  enable_monitoring   = false

  # Account definitions — use unique email addresses per account
  accounts = [
    {
      name                     = "Audit"
      email                    = "you+audit@example.com"
      organizational_unit_name = "Security"
      tags                     = { AccountType = "Audit" }
    },
    {
      name                     = "Log-Archive"
      email                    = "you+logs@example.com"
      organizational_unit_name = "Security"
      tags                     = { AccountType = "Log-Archive" }
    },
  ]
}
```

Leave `env/accounts.hcl` empty for now — the cross-account stacks resolve their account IDs through Terragrunt dependencies and SSM parameters.

One stack does not: `stacks/management/config-rules` evaluates member accounts only when `audit_account_id` is set in `env/accounts.hcl` (or `enable_config_recorder_members = true`). With the file empty it excludes every member account from every organization Config rule, also after Pass 2 has deployed recorders there. To have the rules evaluate the member accounts, copy the Audit account ID from `(cd stacks/management/accounts && terragrunt output account_ids)` into `audit_account_id` after Pass 1.

## 2. Phase 1 — Foundation (Organization + Accounts)

This creates the AWS Organization, OUs, SCPs, and member accounts. Requires two passes on the first deployment:

```bash
# Pass 1: Create Organization, OUs, policies, and accounts
(cd stacks && terragrunt run --all -- apply)    # Creates: Org, 8 OUs, SCPs, Accounts, SSM parameters

# Pass 2: Deploy cross-account stacks (config-recorder in member accounts)
# These resolve account IDs from the plain-ID parameters
# (/tlz/accounts/<AccountName>/id) written in Pass 1
(cd stacks && terragrunt run --all -- apply)    # Deploys: config-recorder in Audit, Log-Archive, workload accounts
```

After the first deployment, all subsequent changes are single-pass: `(cd stacks && terragrunt run --all -- apply)`.

Account IDs flow automatically — the accounts stack writes one plain-ID parameter per account (`/tlz/accounts/<AccountName>/id`, plus a `/metadata` JSON record), and the cross-account stacks resolve the plain ID at parse time. The security stack registers delegated admin for GuardDuty, SecurityHub, Macie, and Access Analyzer automatically.

Verify cross-account access works:

```bash
# Get the Audit account ID from the accounts output
(cd stacks/management/accounts && terragrunt output account_ids)

# Test cross-account role assumption
aws sts assume-role \
  --role-arn "arn:aws:iam::<AUDIT_ACCOUNT_ID>:role/OrganizationAccountAccessRole" \
  --role-session-name test \
  --profile your-mgmt-profile \
  --query 'Credentials.AccessKeyId'
```

If this returns an access key, proceed to Phase 2.

## 3. Phase 2 — Logging + Security

Enable logging and security in `env/common.hcl`:

```hcl
enable_logging  = true
enable_security = true
```

```bash
# Central logging (CloudTrail, Config Recorder, S3 bucket, KMS)
(cd stacks/management/logging && terragrunt plan && terragrunt apply)

# Config Recorder in each member account
(cd stacks/audit/config-recorder && terragrunt plan && terragrunt apply)

(cd stacks/log-archive/config-recorder && terragrunt plan && terragrunt apply)

# Security services (GuardDuty, SecurityHub, Macie, Access Analyzer)
(cd stacks/management/security && terragrunt plan && terragrunt apply)

# Delegated admin config (from Audit account)
(cd stacks/audit/security-org-config && terragrunt plan && terragrunt apply)
```

## 4. Phase 3 — Governance (Config Rules + Monitoring)

```hcl
enable_config_rules = true
enable_monitoring   = true
```

```bash
(cd stacks/management/config-rules && terragrunt plan && terragrunt apply)

(cd stacks/management/monitoring && terragrunt plan && terragrunt apply)
```

The `iam` stack belongs to Phase 5. It depends on `networking`: Managed Microsoft
AD and the AD Connector are placed in a VPC, and only the networking stack knows
the VPC and subnet identifiers. `terragrunt apply` on `iam` therefore needs the
state of `networking`.

## 5. Phase 4 — Extensions (Budgets, CUR, Backup)

```hcl
enable_budgets                 = true
enable_cost_and_usage_report   = true
```

```bash
(cd stacks/management/budgets && terragrunt plan && terragrunt apply)

(cd stacks/management/cur && terragrunt plan && terragrunt apply)

(cd stacks/management/backup && terragrunt plan && terragrunt apply)

(cd stacks/management/ssm-parameters && terragrunt plan && terragrunt apply)
```

## 6. Phase 5 — Networking and IAM

Networking is optional — enable it only if you have VPCs, Transit Gateway, or
Network Firewall configured. `iam` comes after it in either case, because the
directory services read the VPC and subnet identifiers from the networking
stack. Without a configured `managed_active_directories` both values arrive
empty, which is the module default and creates no directory.

```hcl
enable_networking = true
enable_iam        = true
```

```bash
(cd stacks/management/networking && terragrunt plan && terragrunt apply)

(cd stacks/management/iam && terragrunt plan && terragrunt apply)
```

## 7. Verify Deployment

After all phases complete:

```bash
# Drift-free check — should show no changes
(cd stacks && terragrunt run --all -- plan)

# Verify Config Recorder in the management account
aws configservice describe-configuration-recorder-status \
  --profile your-mgmt-profile --region eu-central-1

# Verify GuardDuty is active
aws guardduty list-detectors --profile your-mgmt-profile --region eu-central-1
```

## Deployment Phases Overview

![Five deployment phases and the modules each one applies: foundation, logging and security, rules and monitoring, budgets, CUR and backup, networking and IAM](diagrams/img/deployment-phases.png)

## Compliance Configurations

After the base deployment, enable a compliance framework:

```hcl
# env/common.hcl
compliance_frameworks = ["nist-800-53"]
```

Available: `nist-800-53`, `hipaa`, `cmmc`, `fedramp-moderate`, `fedramp-high`, `c5-2020`, `iso-27001`, `nist-800-171`

Multiple frameworks can be combined:

```hcl
compliance_frameworks = ["hipaa", "nist-800-53"]
```

Then re-apply all stacks:

```bash
(cd stacks && terragrunt run --all -- plan)
(cd stacks && terragrunt run --all -- apply)
```

See [Compliance Configurations](compliance-configurations.md) for details on what each framework covers.

## Multi-Partition (aws-eusc)

For European Sovereign Cloud:

```hcl
# env/common.hcl
region    = "eusc-de-east-1"
partition = "aws-eusc"
```

Services unavailable in aws-eusc (e.g. Macie) are automatically skipped.

## Deployment Modes

| Mode | Config | Use Case |
|---|---|---|
| Local state | `state_backend = "local"` | First deployment, experimentation |
| S3 remote state | `state_backend = "s3"` | Team collaboration (set real bucket and lock table names, then apply bootstrap first — see below) |
| Pipeline | `enable_pipeline = true` | CI/CD (requires Deployment Account + S3) |

With `state_backend = "local"`, each unit's state is written to a stable
absolute path **outside the repository**: `$TLZ_STATE_DIR/<unit>/terraform.tfstate`,
defaulting to `~/.tlz-state/<unit>/terraform.tfstate` (keyed per unit like
the S3 key) — **not** inside `.terragrunt-cache` and **not** inside the repo.
Both halves matter: a cache generation is disposable and gets re-hashed on
config changes, and a gitignored in-repo location is exactly what
`git clean -xfd` deletes. Several TLZ deployments on one machine need one
`TLZ_STATE_DIR` per clone, or the second clone is refused (see
[Operations](operations.md), one directory per deployment). Deployments that ran
before this behaviour existed have state inside the cache or under the
interim `<repo>/.state/` — see [Operations](operations.md) for the one-time
migration.

For S3 mode on a new deployment, set the backend first and create the bucket
second. `stacks/management/bootstrap` creates the state bucket and the
DynamoDB lock table from the names in `env/common.hcl`, and it refuses to run
while that file sets any other backend: `terragrunt run --all` skips it, and a
direct `init`, `plan` or `apply` stops with
`ERROR: stacks/management/bootstrap creates the S3 bucket ...`.

1. In `env/common.hcl`, set `state_backend = "s3"` and replace the
   placeholders of `state_bucket_name` (bucket names are globally unique) and
   `lock_table_name` with the real names.
2. Apply the bootstrap unit on its own, before any other unit. The
   subshell keeps you in the repository root, where the next step starts:
   ```bash
   (cd stacks/management/bootstrap && terragrunt apply)
   ```
   No unit depends on it, so `run --all` would initialise the others against
   a bucket that does not exist yet. The bootstrap unit's own state stays
   local, at `$TLZ_STATE_DIR/management/bootstrap/terraform.tfstate` (default
   `~/.tlz-state/...`), not in the bucket — keep that directory.
3. Then deploy the other stacks, starting with
   [Phase 1](#2-phase-1-foundation-organization-accounts); they keep their
   state in the bucket from the first init on.

A deployment that already holds local state does not follow these steps: it
moves its state as described in [Operations — Switching the backend from local
to S3](operations.md#switching-the-backend-from-local-to-s3).

## Destroy

By default, destroying does not close member accounts; with
`close_on_deletion = true` it does. With `close_on_deletion = false`
(the default), each account stays open and keeps billing. The provider's
destroy calls `RemoveAccountFromOrganization`. AWS refuses that call for an
account with no payment method of its own, which is every account this
landing zone creates, so the account stays `ACTIVE` in the organization.
If the call does go through, the account becomes a standalone account
outside every organization policy and gets its own bill. To close accounts,
do one of the following from the management account:

- Set `close_on_deletion = true` in `env/common.hcl` and apply the accounts
  stack before you destroy. The destroy then calls `CloseAccount`.
- Close each account yourself with
  `aws organizations close-account --account-id <account-id>` or in the
  Organizations console.

Either way, the account goes `PENDING_CLOSURE` and then `SUSPENDED`. AWS
Support can reinstate it within 90 days. Organizations closes at most 10% of
member accounts (10 to 1000) per rolling 30 days. When you hit that limit,
`CLOSE_ACCOUNT_QUOTA_EXCEEDED` stops the destroy and you close the rest later.

```bash
# Entire landing zone, local backend (reverse dependency order;
# run --all skips both bootstrap units in this mode)
(cd stacks && terragrunt run --all -- destroy)

# Single module
(cd stacks/management/networking && terragrunt destroy)
```

On the S3 backend, leave both bootstrap units for last. Their state bucket and
lock table hold the state of every other unit, and no unit depends on them, so
a plain `run --all` would destroy them in its first wave. Exclude them from the
run, then destroy them one after the other. The management bootstrap goes
last: it was applied first, and with the deployment account off its bucket is
the backend of every other unit. Run the deployment bootstrap line only with
`enable_deployment_account = true`:

```bash
# Entire landing zone, S3 backend
(cd stacks && terragrunt run --all --filter '!./management/bootstrap' --filter '!./deployment/bootstrap' -- destroy)
(cd stacks/deployment/bootstrap && terragrunt destroy)
(cd stacks/management/bootstrap && terragrunt destroy)
```

The state bucket is versioned and has no `force_destroy`, so AWS refuses to
delete it while it still holds state files; empty it first if it has to go.

## Further reading

- [Configuration Reference](configuration-reference.md) — Full variable reference with types, defaults and validations
- [Operations](operations.md) — Day-2 operations, troubleshooting and state management
- [Compliance Configurations](compliance-configurations.md) — Enable and combine framework-specific configurations
