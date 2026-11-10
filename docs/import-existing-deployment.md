# Importing the Existing Deployment Before the First Org-Wide Apply

A one-time runbook for the operator. It takes the 46 objects that an earlier
deployment left in the accounts into the S3 state, so the first
org-wide `terragrunt run --all -- apply` changes them in place instead of
colliding with them or overwriting them silently. It is run by hand, unit by
unit, with the management account's credentials. Nothing here is automated.

## 1. Why

A read-only plan against the management account in `eu-central-1`, with
the S3 state backend, shows:

- The org-wide plan wants to **add 195 objects** (audit/config-recorder 3,
  audit/security-config 7, audit/security-org-config 3,
  log-archive/config-recorder 3, management/accounts 9, management/backup 3,
  management/budgets 1, management/config-rules 35, management/cur 9,
  management/logging 43, management/security 76, workload-dev/config-recorder 3).
- **46 of those 195 already exist**, under exactly the names this
  configuration builds: the budget, two log buckets, the organization trail,
  the Kinesis stream and the Firehose delivery stream, two log groups,
  32 organization Config rules, the GuardDuty detector, the Security Hub
  hub, the Detective graph, the Access Analyzer, the Macie session and the
  backup vault.
- Most of them **collide loudly** on apply (`AlreadyExists`,
  `DuplicateRecordException`, `BucketAlreadyOwnedByYou`, ...), and the apply
  stops half-way.
- The **32 organization Config rules collide silently**: the provider
  creates them through `PutOrganizationConfigRule`, which is an upsert. The
  apply would overwrite the live rules' parameters with the configuration's
  and report success. Importing first turns that overwrite into a visible
  `~ update in-place` line per rule in the plan, which is the parameter
  review the rules need.
- **Macie trusted access.** `stacks/management/organization` builds the
  organization's trusted service list from the `enable_*` switches. With
  `enable_macie = false` the list lacks `macie.amazonaws.com`; the apply
  would try to remove Macie's trusted access and AWS refuses that
  (`ConstraintViolationException`) because Macie has a delegated
  administrator. Set `enable_macie = true` in `env/common.hcl` **first**; it
  also puts the Macie session and its log group into the configuration, which
  the import needs (a resource the configuration does not declare cannot be
  imported).

The state move to S3 already brought the organization objects into state;
`management/organization` and `management/bootstrap` are not part of this
runbook.

## 2. Preconditions

1. `env/common.hcl` has `state_backend = "s3"` and `enable_macie = true`.
2. The two organization state objects (`management/organization`,
   `management/bootstrap`) are already in the state bucket, and
   `cd stacks/management/organization && terragrunt plan` shows
   `0 to add, 1 to change, 0 to destroy` (the one change is the known
   perpetual diff on `base-rcp-guardrails-1`, see section 5).
3. Credentials for the management account, region `eu-central-1` on every
   call:

   ```sh
   # obtain administrator credentials for <MANAGEMENT_ACCOUNT_ID> with your usual
   # credential tool, for example: aws sso login --profile <MANAGEMENT_PROFILE>
   aws sts get-caller-identity
   export AWS_REGION=eu-central-1 AWS_DEFAULT_REGION=eu-central-1
   ```

   `get-caller-identity` must print the management account before anything
   else runs.
4. **Dependency outputs.** Four of the five units read outputs of units that
   have never been applied, and their mock outputs are allowed for `init`,
   `validate` and `plan` only, not for `import`:

   | Unit | Depends on (outputs) | Allowed mock commands |
   |---|---|---|
   | `management/budgets` | none | - |
   | `management/logging` | `accounts`, `organization` | `stacks/management/logging/terragrunt.hcl:28,39` |
   | `management/backup` | `accounts` | `stacks/management/backup/terragrunt.hcl:27` |
   | `management/security` | `logging`, `accounts`, `organization` | `stacks/management/security/terragrunt.hcl:35,48,60` |
   | `management/config-rules` | `accounts`, `organization`, `logging` | `stacks/management/config-rules/terragrunt.hcl:154,168,181` |

   `management/accounts` was never applied (9 to add), so
   `cd stacks/management/accounts && terragrunt output -json` prints `{}`,
   and an import in the four dependent units stops with terragrunt's
   "detected no outputs" error before it reaches AWS. Importing into
   `management/logging` is not a way to give it outputs for `security` and
   `config-rules`; its outputs come from an apply. Pick one of the two orders
   before starting; the choice is the operator's:

   - **(a) Dependency order, no file change.** Import `management/budgets`.
     Plan and apply `management/accounts` on its own (it holds none of the
     46; its 9 additions create a member account and carry their own cost). Import
     `management/logging` and `management/backup`, plan them clean, apply
     `management/logging`. Then import `management/security` and
     `management/config-rules`, plan them clean, then run the org-wide apply.
   - **(b) All imports before any apply.** In the local tree only, add
     `"import"` to each `mock_outputs_allowed_terraform_commands` listed in
     the table above, run every import, then revert those lines
     (`git diff --stat stacks/` must print nothing) before any plan used as
     evidence and before any apply. The mocks only feed module inputs; the
     providers come from `env/accounts.hcl` through `stacks/root.hcl`, and an
     import reads the live object by its ID, so a mock cannot change what is
     imported.

5. Before each unit: run `terragrunt plan -no-color > "${TMPDIR:-/tmp}/<unit>-before.txt"`
   in the unit directory and confirm every address this runbook imports
   there appears as `will be created`. An address that does not appear is not
   in the configuration (a switch is off); skip its row, the live object then
   does not collide.

## 3. Import table

Placeholders only the operator can fill; every command in THIS table is
read-only and runs in `eu-central-1`. The `terragrunt import` commands of
section 4 are not: they change no AWS resource, but each one writes and locks
the unit's state object in the S3 state bucket. The bucket keeps every version
(the bootstrap module enables versioning), and before a unit's first import you
also keep a copy the way back does not depend on:
`cd stacks/<unit> && terragrunt state pull > "${TMPDIR:-/tmp}/<unit>.tfstate.before-import.json"`
-- a wrong import is undone with `terragrunt state push` of that file (or by
restoring the previous object version in S3), never by `state rm` (section 6).

| Placeholder | Read command |
|---|---|
| `<MANAGEMENT_ACCOUNT_ID>` | `<READ: aws sts get-caller-identity --query Account --output text>` |
| `<LOG_ARCHIVE_ACCOUNT_ID>` | `<READ: grep log_archive_account_id env/accounts.hcl>`, then `aws s3api head-bucket --bucket tlz-central-logs-<LOG_ARCHIVE_ACCOUNT_ID>-eu-central-1` must return without error |
| `<GUARDDUTY_DETECTOR_ID>` | `<READ: aws guardduty list-detectors --region eu-central-1 --query 'DetectorIds[0]' --output text>` |
| `<DETECTIVE_GRAPH_ARN>` | `<READ: aws detective list-graphs --region eu-central-1 --query 'GraphList[0].Arn' --output text>` |

Every unit's module is the unit's root module (`source =
"${get_repo_root()}//modules/<name>"`), so no address carries a `module.`
prefix. Import ID formats are the ones the AWS provider documents for the
resource type.

| # | Unit (`stacks/...`) | Address | Import ID format | Live ID |
|---|---|---|---|---|
| 1 | management/budgets | `aws_budgets_budget.this["this"]` | `AccountID:BudgetName` | `<MANAGEMENT_ACCOUNT_ID>:tlz-monthly-budget` |
| 2 | management/logging | `aws_s3_bucket.central_logs` | bucket name | `tlz-central-logs-<LOG_ARCHIVE_ACCOUNT_ID>-eu-central-1` |
| 3 | management/logging | `aws_s3_bucket.elb_logs[0]` | bucket name | `tlz-elb-logs-<MANAGEMENT_ACCOUNT_ID>-eu-central-1` |
| 4 | management/logging | `aws_cloudtrail.org_trail` | trail ARN | `arn:aws:cloudtrail:eu-central-1:<MANAGEMENT_ACCOUNT_ID>:trail/tlz-org-trail` |
| 5 | management/logging | `aws_kinesis_stream.cw_to_s3[0]` | stream name | `tlz-cw-to-s3-stream` |
| 6 | management/logging | `aws_kinesis_firehose_delivery_stream.cw_to_s3[0]` | delivery stream ARN | `arn:aws:firehose:eu-central-1:<MANAGEMENT_ACCOUNT_ID>:deliverystream/tlz-cw-to-s3-delivery` |
| 7 | management/logging | `aws_cloudwatch_log_group.cloudtrail[0]` | log group name | `/aws/cloudtrail/tlz-org-trail` |
| 8-39 | management/config-rules | `aws_config_organization_managed_rule.this["<rule>"]` | rule name | the 32 `base-*` names of `configurations/base/managed-rules.json` (listed in section 4) |
| 40 | management/security | `aws_guardduty_detector.this[0]` | detector ID | `<GUARDDUTY_DETECTOR_ID>` |
| 41 | management/security | `aws_securityhub_account.this[0]` | account ID | `<MANAGEMENT_ACCOUNT_ID>` (the hub is `hub/default`) |
| 42 | management/security | `aws_detective_graph.this[0]` | graph ARN | `<DETECTIVE_GRAPH_ARN>` |
| 43 | management/security | `aws_accessanalyzer_analyzer.this[0]` | analyzer name | `tlz-org-access-analyzer` |
| 44 | management/security | `aws_macie2_account.this[0]` | account ID (the provider sets the ID to the account ID) | `<MANAGEMENT_ACCOUNT_ID>` |
| 45 | management/security | `aws_cloudwatch_log_group.macie_session_settings[0]` | log group name | `/aws/lambda/tlz-macie-session-settings` |
| 46 | management/backup | `aws_backup_vault.this["tlz-central-backup"]` | vault name | `tlz-central-backup` |

Row 45 exists in the configuration only while `enable_macie = true` and one of
`macie_automated_discovery`, `macie_classification_scope_excluded_buckets` or
`macie_publish_policy_findings` is set (`modules/security/macie.tf:96`). Row 46
assumes the entry in `backup_vaults` is named `tlz-central-backup`; the
instance key is the vault name.

## 4. Commands

Run from the repository root, one line at a time, after replacing the
placeholders. A failing line stops the unit; nothing below it runs until its
cause is known.

```sh
# management/budgets (1)
cd stacks/management/budgets && terragrunt import 'aws_budgets_budget.this["this"]' '<MANAGEMENT_ACCOUNT_ID>:tlz-monthly-budget'

# management/logging (6)
cd stacks/management/logging && terragrunt import 'aws_s3_bucket.central_logs' 'tlz-central-logs-<LOG_ARCHIVE_ACCOUNT_ID>-eu-central-1'
cd stacks/management/logging && terragrunt import 'aws_s3_bucket.elb_logs[0]' 'tlz-elb-logs-<MANAGEMENT_ACCOUNT_ID>-eu-central-1'
cd stacks/management/logging && terragrunt import 'aws_cloudtrail.org_trail' 'arn:aws:cloudtrail:eu-central-1:<MANAGEMENT_ACCOUNT_ID>:trail/tlz-org-trail'
cd stacks/management/logging && terragrunt import 'aws_kinesis_stream.cw_to_s3[0]' 'tlz-cw-to-s3-stream'
cd stacks/management/logging && terragrunt import 'aws_kinesis_firehose_delivery_stream.cw_to_s3[0]' 'arn:aws:firehose:eu-central-1:<MANAGEMENT_ACCOUNT_ID>:deliverystream/tlz-cw-to-s3-delivery'
cd stacks/management/logging && terragrunt import 'aws_cloudwatch_log_group.cloudtrail[0]' '/aws/cloudtrail/tlz-org-trail'

# management/config-rules (32)
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-iam-user-group-membership-check"]' 'base-iam-user-group-membership-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-cloudtrail-enabled"]' 'base-cloudtrail-enabled'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-emr-kerberos-enabled"]' 'base-emr-kerberos-enabled'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-s3-bucket-policy-grantee-check"]' 'base-s3-bucket-policy-grantee-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-ec2-instance-detailed-monitoring-enabled"]' 'base-ec2-instance-detailed-monitoring-enabled'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-ec2-volume-inuse-check"]' 'base-ec2-volume-inuse-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-guardduty-non-archived-findings"]' 'base-guardduty-non-archived-findings'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-sagemaker-endpoint-configuration-kms-key-configured"]' 'base-sagemaker-endpoint-configuration-kms-key-configured'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-dynamodb-table-encrypted-kms"]' 'base-dynamodb-table-encrypted-kms'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-account-part-of-organizations"]' 'base-account-part-of-organizations'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-codebuild-project-artifact-encryption"]' 'base-codebuild-project-artifact-encryption'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-dynamodb-throughput-limit-check"]' 'base-dynamodb-throughput-limit-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-ebs-optimized-instance"]' 'base-ebs-optimized-instance'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-lambda-dlq-check"]' 'base-lambda-dlq-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-secretsmanager-using-cmk"]' 'base-secretsmanager-using-cmk'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-api-gw-cache-enabled-and-encrypted"]' 'base-api-gw-cache-enabled-and-encrypted'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-ebs-in-backup-plan"]' 'base-ebs-in-backup-plan'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-ec2-instances-in-vpc"]' 'base-ec2-instances-in-vpc'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-rds-in-backup-plan"]' 'base-rds-in-backup-plan'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-aurora-resources-protected-by-backup-plan"]' 'base-aurora-resources-protected-by-backup-plan'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-backup-recovery-point-encrypted"]' 'base-backup-recovery-point-encrypted'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-ec2-instance-profile-attached"]' 'base-ec2-instance-profile-attached'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-iam-group-has-users-check"]' 'base-iam-group-has-users-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-iam-no-inline-policy-check"]' 'base-iam-no-inline-policy-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-cloudwatch-log-group-encrypted"]' 'base-cloudwatch-log-group-encrypted'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-sagemaker-notebook-instance-kms-key-configured"]' 'base-sagemaker-notebook-instance-kms-key-configured'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-no-unrestricted-route-to-igw"]' 'base-no-unrestricted-route-to-igw'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-backup-plan-min-frequency-and-min-retention-check"]' 'base-backup-plan-min-frequency-and-min-retention-check'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-backup-recovery-point-manual-deletion-disabled"]' 'base-backup-recovery-point-manual-deletion-disabled'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-ec2-resources-protected-by-backup-plan"]' 'base-ec2-resources-protected-by-backup-plan'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-elb-logging-enabled"]' 'base-elb-logging-enabled'
cd stacks/management/config-rules && terragrunt import 'aws_config_organization_managed_rule.this["base-internet-gateway-authorized-vpc-only"]' 'base-internet-gateway-authorized-vpc-only'

# management/security (6)
cd stacks/management/security && terragrunt import 'aws_guardduty_detector.this[0]' '<GUARDDUTY_DETECTOR_ID>'
cd stacks/management/security && terragrunt import 'aws_securityhub_account.this[0]' '<MANAGEMENT_ACCOUNT_ID>'
cd stacks/management/security && terragrunt import 'aws_detective_graph.this[0]' '<DETECTIVE_GRAPH_ARN>'
cd stacks/management/security && terragrunt import 'aws_accessanalyzer_analyzer.this[0]' 'tlz-org-access-analyzer'
cd stacks/management/security && terragrunt import 'aws_macie2_account.this[0]' '<MANAGEMENT_ACCOUNT_ID>'
cd stacks/management/security && terragrunt import 'aws_cloudwatch_log_group.macie_session_settings[0]' '/aws/lambda/tlz-macie-session-settings'

# management/backup (1)
cd stacks/management/backup && terragrunt import 'aws_backup_vault.this["tlz-central-backup"]' 'tlz-central-backup'
```

Each line starts from the repository root (`cd` is part of the line); in a
single shell, return with `cd -` or run each line in a subshell `( ... )`.

The 32 rule names are the full content of
`configurations/base/managed-rules.json` at this version, which is exactly the
32 `base-*` rules `describe-organization-config-rules` returned. A rule that
`env/common.hcl` or a framework adds on top is not live and is not imported.

## 5. Check after each unit

```sh
terragrunt plan -no-color > "${TMPDIR:-/tmp}/<unit>-after.txt"
grep -E ' will be created$' "${TMPDIR:-/tmp}/<unit>-after.txt"
```

- None of the unit's imported addresses may appear in the `will be created`
  list, and the unit's `to add` count must be lower than in the `-before`
  plan by exactly the number of rows imported there. `management/budgets`
  must show `0 to add`.
- No line may read `must be replaced` or `will be destroyed` for an imported
  address. A replacement means the configuration differs from the live object
  in a create-only attribute; stop and settle that difference in
  `env/common.hcl` before going on.
- `~ update in-place` on an imported object is expected and is the point of
  the exercise: it shows what the apply would change on the live object. For
  the 32 Config rules this is the parameter review; read every rule's diff.
- Objects that stay in `will be created` next to an imported parent (bucket
  versioning, encryption, public access block, policy and lifecycle, detector
  features, Security Hub standards) are separate resources with no identity
  of their own. Their create call writes the configuration's setting over the
  live one; read them like an in-place update.
- `management/organization` keeps showing `1 to change` on the RCP
  `base-rcp-guardrails-1`. That is the known perpetual diff and not caused by
  this runbook.

## 6. What not to do

- **No apply before every unit plans clean**, except the single-unit applies
  order (a) of section 2 names. A `run --all -- apply` with even one of the 46
  still in `will be created` either stops half-way on a collision or, for a
  Config rule, overwrites it silently.
- **Never delete the organization trail** `tlz-org-trail`, its bucket or its
  log group to "make room" for the apply. The trail is the organization's
  audit record; deleting it leaves a gap in the audit trail. Deleting any
  other of the 46 to let the apply recreate it loses its data or history
  (buckets, the backup vault, the Detective graph) and is not a substitute for
  the import.
- No `terragrunt state rm` of an imported address to retry a row; re-run the
  import of that row only after its plan shows why it failed.
- No import with credentials of another account: `aws sts get-caller-identity`
  before each unit.
