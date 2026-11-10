# Security Module

Organization-wide security services: GuardDuty, Security Hub, Macie, Detective, IAM Access Analyzer, and IAM password policy, with the Audit account as delegated administrator.

This module runs in the **management account** and is the only place the delegated administrator is *designated*: for GuardDuty, Security Hub, Macie and Detective it pairs the Organizations registration (`aws_organizations_delegated_administrator`) with the service's own designation (`aws_guardduty_organization_admin_account`, `aws_securityhub_organization_admin_account`, `aws_macie2_organization_admin_account`, `aws_detective_organization_admin_account`), because each service reads its administrator from its own `EnableOrganizationAdminAccount` — which AWS accepts only from the management account — and not from the Organizations registration alone. What the designated administrator then *configures* org-wide (detector features, org configurations, the Detective graph's member auto-enable, standards) is owned by `modules/security-org-config`, which runs in the Audit account. A designation made out-of-band is adopted with `terraform import` (paths in the code comments of `guardduty.tf`, `securityhub.tf`, `detective.tf`).

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `enable_ebs_default_encryption` | Encrypt every new EBS volume in the account by default | `bool` | `true` | no |
| `ebs_default_kms_key_arn` | Key that encrypts the new volumes. Empty uses the AWS-managed `aws/ebs` key | `string` | `""` | no |
| `enable_s3_public_access_block` | Block public access to every bucket of the account | `bool` | `true` | no |
| `audit_account_id` | Account ID of the delegated security admin | `string` | — | yes |
| `guardduty_s3_protection` | Have GuardDuty evaluate S3 data events | `bool` | `true` | no |
| `guardduty_malware_protection` | Have GuardDuty scan EBS volumes for malware (EBS_MALWARE_PROTECTION feature) | `bool` | `true` | no |
| `guardduty_eks_protection` | Have GuardDuty evaluate EKS audit logs | `bool` | `true` | no |
| `guardduty_lambda_protection` | Have GuardDuty evaluate Lambda network activity | `bool` | `true` | no |
| `guardduty_rds_protection` | Have GuardDuty evaluate RDS login events | `bool` | `true` | no |
| `enable_guardduty_s3_malware_protection` | Let GuardDuty scan S3 objects for malware. Requires `enable_guardduty` | `bool` | `false` | no |
| `guardduty_s3_malware_configs` | Buckets the malware scan covers, one protection plan per entry. `enable_malware_protection_tags` (default `true`) controls whether scanned objects receive the scan result tag; `tags` land on the protection plan | `list(object)` | `[]` | no |
| `guardduty_keep_malware_snapshots` | Keep the EBS snapshots the malware scan creates when it finds malware. `true` deploys a small settings function that applies the retention at deployment time and reverts it on removal; `false` creates nothing and leaves the service default | `bool` | `false` | no |
| `guardduty_scan_settings_log_retention_days` | Retention of the GuardDuty malware-scan settings Lambda's own execution log group `/aws/lambda/tlz-guardduty-scan-settings`, which the module declares (`0` = never expire). See [Lambda execution log groups](#lambda-execution-log-groups) | `number` | `365` | no |
| `macie_session_settings_log_retention_days` | Retention of the Macie session-settings Lambda's own execution log group `/aws/lambda/tlz-macie-session-settings`, which the module declares (`0` = never expire). See [Lambda execution log groups](#lambda-execution-log-groups) | `number` | `365` | no |
| `enable_security_hub_region_aggregation` | Collect the findings of the other regions in the home region | `bool` | `true` | no |
| `security_hub_aggregation_regions` | Regions the findings are collected from. Empty collects from every region | `list(string)` | `[]` | no |
| `enable_guardduty` | Enable GuardDuty | `bool` | `true` | no |
| `enable_security_hub` | Enable Security Hub | `bool` | `true` | no |
| `enable_macie` | Enable Macie | `bool` | `false` | no |
| `enable_access_analyzer` | Enable IAM Access Analyzer | `bool` | `true` | no |
| `enable_ssm_block_public_sharing` | Prevent SSM documents of this account and region from being shared publicly | `bool` | `true` | no |
| `is_eusc` | Whether the active partition is `aws-eusc`. Supplied by the caller so the module stays testable without a partition lookup | `bool` | `false` | no |
| `security_hub_standards` | Standards to switch on: `arn_suffix` plus an `enabled` flag (default `true`). A disabled entry is documentation only. Plain ARN suffix strings are accepted in the configuration layer, where the loader converts them to this form | `list(object)` | `[{ arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" }, { arn_suffix = "cis-aws-foundations-benchmark/v/1.4.0" }]` | no |
| `password_policy` | IAM password policy parameters. Every attribute is optional; the default object spells out each attribute's default so that static analysis can prove the policy compliant, see [Password Policy](#password-policy) | `object` | `{ minimum_length = 14 require_uppercase = true require_lowercase = true require_numbers = true require_symbols = true max_age = 90 password_reuse_prevention = 24 allow_users_to_change = true hard_expiry = false }` | no |
| `enable_session_manager_s3_logging` | Write session logs to S3. When unset, the bucket name is dropped from the session document regardless of `session_manager_s3_bucket_name` | `bool` | `false` | no |
| `enable_session_manager_logging` | Create the session document that governs session logging at all | `bool` | `false` | no |
| `session_manager_s3_bucket_name` | Bucket that holds the session logs. Empty leaves S3 logging off. A named bucket is looked up at plan time, see [Session Manager Log Targets](#session-manager-log-targets) | `string` | `""` | no |
| `session_manager_s3_key_prefix` | Prefix of the session logs inside the bucket | `string` | `"ssm-sessions/"` | no |
| `session_manager_cloudwatch_log_group` | Log group that holds the session logs. Empty leaves CloudWatch logging off. A named group is looked up at plan time, see [Session Manager Log Targets](#session-manager-log-targets) | `string` | `""` | no |
| `session_manager_attach_policy_to_roles` | Roles the session policy is attached to. An empty list creates no policy | `list(string)` | `[]` | no |
| `session_manager_excluded_accounts` | Account IDs excluded from the Session Manager logging configuration. A plan against a listed account warns | `list(string)` | `[]` | no |
| `session_manager_kms_key_id` | Key that encrypts the session data. Empty leaves the sessions unencrypted | `string` | `""` | no |
| `guardduty_export_frequency` | How often findings are written to S3: `FIFTEEN_MINUTES`, `ONE_HOUR` or `SIX_HOURS`. `null` exports nothing | `string` | `null` | no |
| `central_log_bucket_name` | S3 bucket name for findings delivery | `string` | `""` | no |
| `security_hub_automation_rules` | Rules that act on incoming findings. Criteria cover every finding field as string, number, date or key-value filter; the finding fields update can set severity, workflow status, note, types, user-defined fields, verification state, confidence, criticality and related findings. Each rule carries `enabled` (default `true`) and `exclude_regions` to skip named regions. See [Security Hub Automation Rules](#security-hub-automation-rules) | `list(object)` | `[]` | no |
| `security_hub_disabled_controls` | Controls to switch off, per standard. Each `standard_arn_suffix` must name a subscribed standard — an enabled `security_hub_standards` entry or a `security_hub_standards_config` entry — because a control of an unsubscribed standard does not exist | `list(object)` | `[]` | no |
| `resource_policy_enforcement` | Resource types whose policies are checked, with the optional remediation and `input_parameters` per entry. See [Resource Policy Enforcement](#resource-policy-enforcement) | `list(object)` | `[]` | no |
| `resource_policy_enforcement_network_perimeter` | Network perimeter for the enforcement templates: when `enabled`, the quoted placeholder `"{{NETWORK_PERIMETER_VPC_IDS}}"` in each `policy_template` is replaced with the JSON array of the perimeter VPC IDs. See [Resource Policy Enforcement](#resource-policy-enforcement) | `object` | `{}` | no |
| `resource_policy_enforcement_lambda_arn` | ARN of the Lambda evaluator backing the resource policy enforcement Config rules. Empty string means no evaluator is available and no Config rule is created. | `string` | `""` | no |
| `resource_policy_enforcement_document` | Content of the remediation document. Passed in as a string: a bare file path would not survive the Terragrunt cache copy. Repo-relative `file()` reads inside the module resolve because the stack sources use the double-slash form (`${get_repo_root()}//modules/security`), which makes the repo root the cache copy root | `string` | `""` | no |
| `guardduty_export_kms_key_arn` | Key that encrypts the exported findings. Required as soon as `guardduty_export_frequency` is set; a precondition enforces it | `string` | `""` | no |
| `guardduty_export_prefix` | Prefix the findings are written under | `string` | `"guardduty/"` | no |
| `enable_detective` | Enable Detective for investigating findings | `bool` | `false` | no |
| `enable_audit_manager` | Enable Audit Manager for collecting compliance evidence. Maintenance mode: as of April 30, 2026 AWS refuses new account registrations at apply time (ValidationException); existing registrations keep working and stay managed. Only enable for an account registered before the cutoff — a `check` block warns whenever the toggle is on | `bool` | `false` | no |
| `ssm_document_share_targets` | Accounts every custom SSM document is shared with. `all` shares them publicly. See [SSM Document Sharing](#ssm-document-sharing) | `list(string)` | `[]` | no |
| `ssm_documents` | SSM documents to create. `share_targets` per entry adds accounts and organizational units the document is shared with (see [SSM Document Sharing](#ssm-document-sharing)). A `deployment_targets` entry is accepted but reported by a `check` block | `list(object)` | `[]` | no |
| `account_ids` | Account name to account ID, for the `share_targets` resolution | `map(string)` | `{}` | no |
| `ou_name_to_id` | OU name to OU ID, for the `share_targets` resolution | `map(string)` | `{}` | no |
| `account_ou_ids` | Account name to the ID of the OU the account is placed in, for the `share_targets` resolution | `map(string)` | `{}` | no |
| `kms_keys` | Customer-managed keys to create, each with its alias. `is_enabled` keeps a key created but blocked for cryptographic operations, `removal_policy` (`destroy`/`retain`) controls the behaviour when a key leaves the configuration (see [Customer-Managed Key Sets](#customer-managed-key-sets)). A `deployment_targets` entry is accepted but reported by a `check` block | `list(object)` | `[]` | no |
| `guardduty_deployment_targets` | Accounts whose GuardDuty membership is configured selectively. Empty covers every account. Cross-account configuration runs through the `security-org-config` module, because this module cannot create providers for other accounts | `list(string)` | `[]` | no |
| `security_hub_standards_config` | Standards with their own target OUs or accounts, alongside `security_hub_standards` | `list(object)` | `[]` | no |
| `guardduty_eks_runtime_monitoring` | Have GuardDuty observe the runtime behaviour of EKS workloads | `bool` | `false` | no |
| `guardduty_eks_manage_agent` | Let GuardDuty deploy the runtime agent itself instead of leaving it to the cluster operator. Sub-configuration of `guardduty_eks_runtime_monitoring`, see [Configuration Path](#configuration-path) | `bool` | `false` | no |
| `enable_lambda_encryption` | Encrypt Lambda functions at rest with a customer-managed key | `bool` | `false` | no |
| `lambda_encryption_kms_key_arn` | Key used for that encryption. Empty creates one | `string` | `""` | no |
| `macie_publishing_frequency` | How often Macie publishes its findings: `FIFTEEN_MINUTES`, `ONE_HOUR` or `SIX_HOURS`. `null` leaves the service default in place | `string` | `null` | no |
| `audit_manager_reports_destination` | Bucket and prefix the assessment reports are written to. `null` leaves the destination unset | `object` | `null` | no |
| `guardduty_excluded_regions` | Regions in which GuardDuty is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `security_hub_excluded_regions` | Regions in which Security Hub is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `macie_excluded_regions` | Regions in which Macie is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `ebs_encryption_excluded_regions` | Regions in which the EBS default encryption is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `macie_publish_sensitive_data_findings` | Whether Macie publishes findings about sensitive data. `null` leaves the setting untouched | `bool` | `null` | no |
| `macie_automated_discovery` | Manage Macie automated sensitive data discovery: `true` enables, `false` explicitly disables, `null` leaves it unmanaged (see [Macie Fine-Tuning](#macie-fine-tuning)) | `bool` | `null` | no |
| `macie_classification_scope_excluded_buckets` | Buckets the automated discovery skips, as bucket names per region. Only the entries of the current region are applied there; the list replaces the previous exclusion state | `list(object)` | `[]` | no |
| `macie_disabled_regions` | Regions whose Macie session stays managed but suspended (`PAUSED`). Differs from `macie_excluded_regions` (unmanaged, warning only) | `list(string)` | `[]` | no |
| `macie_publish_policy_findings` | Manage the publication of Macie policy findings to Security Hub: `true` publishes, `false` stops it, `null` leaves the setting unmanaged. The sensitive-data side of the setting is preserved | `bool` | `null` | no |
| `guardduty_lifecycle_rules` | Retention of the exported findings under `guardduty_export_prefix`. `null` sets no rule. Refused without `replace_central_log_bucket_lifecycle`, see [Lifecycle rule set](#lifecycle-rule-set) | `object` | `null` | no |
| `replace_central_log_bucket_lifecycle` | Let this module write the lifecycle configuration of the central log bucket. `true` replaces the bucket's whole lifecycle, including the logging module's rules, and a destroy deletes them all | `bool` | `false` | no |
| `enable_per_account_kms_keys` | Create the CloudWatch and Lambda keys per account. Needed when the module is applied into member accounts | `bool` | `false` | no |
| `enable_audit_manager_bucket` | Create a dedicated, versioned and encrypted bucket for the Audit Manager reports | `bool` | `false` | no |
| `audit_manager_bucket_kms_key_arn` | Key that encrypts that bucket. Empty uses the AWS-managed `aws/s3` key | `string` | `""` | no |
| `audit_manager_bucket_lifecycle_days` | Days after which a report expires. `0` sets no rule, see [Configuration Path](#configuration-path) | `number` | `365` | no |
| `enable_ssm_resource_data_sync` | Write the SSM inventory to the central bucket | `bool` | `false` | no |
| `ssm_resource_data_sync_prefix` | Prefix the inventory is written under | `string` | `"ssm-inventory/"` | no |
| `enable_sqs_kms_key` | Create a dedicated key for queue encryption under the alias `tlz/sqs/kms` | `bool` | `false` | no |
| `s3_public_access_block_excluded_accounts` | Accounts the public access block is not enforced in. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `guardduty_s3_protection_excluded_regions` | Regions in which the GuardDuty S3 evaluation is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `guardduty_ec2_protection_excluded_regions` | Regions in which the GuardDuty EC2 malware protection is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `guardduty_eks_protection_excluded_regions` | Regions in which the GuardDuty EKS protection is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `guardduty_lambda_protection_excluded_regions` | Regions in which the GuardDuty Lambda protection is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `guardduty_rds_protection_excluded_regions` | Regions in which the GuardDuty RDS protection is not wanted. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `ssm_block_public_sharing_excluded_accounts` | Accounts the SSM sharing block is not enforced in. A `check` block reports a run in one of them | `list(string)` | `[]` | no |
| `root_credentials_management` | Intent only: central management of the member accounts' root credentials is wanted. Enables nothing; `true` raises a `check` warning, see [Provider Limits](#provider-limits) | `bool` | `true` | no |
| `allow_root_sessions` | Intent only: privileged root sessions in the member accounts are wanted. Enables nothing; `true` raises a `check` warning, see [Provider Limits](#provider-limits) | `bool` | `true` | no |
| `fms_policies` | Firewall Manager policies. Requires the Firewall Manager administrator registration, see [Firewall Manager administrator](#firewall-manager-administrator) | `list(object)` | `[]` | no |
| `fms_admin_account_registered` | Operator acknowledgement that the Firewall Manager administrator has been registered out of band and that the applying account is one. Required `true` while `fms_policies` is non-empty — the plan fails otherwise, see [Firewall Manager administrator](#firewall-manager-administrator) | `bool` | `false` | no |
| `enable_delete_default_vpc` | First step of removing the default VPC of the current region: it is taken into state. The removal itself happens in a second apply, after this toggle has been switched off again or the stack has been destroyed. Covers the current region only | `bool` | `false` | no |
| `enable_delete_default_sg_rules` | Empty the default security group of its ingress and egress rules. Covers one VPC per apply | `bool` | `false` | no |
| `default_vpc_id` | VPC whose default security group is emptied. Empty uses the default VPC of the region | `string` | `""` | no |
| `enable_fms_notification_channel` | Let Firewall Manager send its alerts to an SNS topic | `bool` | `false` | no |
| `fms_notification_sns_topic_arn` | Topic that receives the alerts. Required when `enable_fms_notification_channel` is set | `string` | `""` | no |
| `fms_notification_sns_role_name` | Role Firewall Manager assumes to publish to the topic | `string` | `"FMSNotificationRole"` | no |
| `enable_firewall_config_bucket` | Create a dedicated bucket for the configuration and licence files of third-party firewalls | `bool` | `false` | no |
| `firewall_config_bucket_name` | Name of that bucket. Has to be globally unique | `string` | `""` | no |
| `firewall_config_bucket_kms_key_arn` | Key that encrypts that bucket. Empty uses the AWS-managed `aws/s3` key | `string` | `""` | no |
| `guardduty_export_lifecycle_rules` | Full lifecycle rule set of the GuardDuty export prefix. `null` keeps the rule derived from `guardduty_lifecycle_rules`. Refused without `replace_central_log_bucket_lifecycle` | `list(object)` | `null` | no |
| `audit_manager_bucket_lifecycle_rules` | Full lifecycle rule set of the Audit Manager reports bucket. `null` keeps the rule derived from `audit_manager_bucket_lifecycle_days` | `list(object)` | `null` | no |
| `macie_export_lifecycle_rules` | Full lifecycle rule set of the Macie classification export prefix. `null` leaves the export without a lifecycle. Refused without `replace_central_log_bucket_lifecycle` | `list(object)` | `null` | no |
| `session_manager_lifecycle_rules` | Full lifecycle rule set of the Session Manager log bucket. The bucket is not the module's: a rule set replaces every lifecycle rule it has, and a destroy deletes them all. `null` leaves its lifecycle untouched | `list(object)` | `null` | no |

## Lifecycle rule set

The four `*_lifecycle_rules` inputs share one shape with the log module, so a
rule reads the same wherever it is written. Each entry is one S3 lifecycle rule:

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

- **`null` keeps what the module did.** For GuardDuty and the Audit Manager
  reports that is the rule derived from their day count; for Macie and the
  Session Manager it is no lifecycle at all.
- **An empty list removes every rule.** `[]` is the deliberate "no lifecycle"
  and is distinct from `null`.
- **A rule set replaces, it does not join.** Once given, it is the whole
  lifecycle of that path; a derived rule falls away.

Set `prefix` on every rule of an export path. Three of the four paths write into
a bucket another module owns, and a rule without a prefix would apply to that
whole bucket.

**The GuardDuty and Macie rules share one configuration.** S3 keeps exactly one
lifecycle configuration per bucket, and both export prefixes sit on the central
log bucket. Both rule sets therefore land in the same resource, each scoped to
its own prefix. Setting only `macie_export_lifecycle_rules` is supported and
creates that configuration on its own.

```hcl
# Only where no other configuration manages the bucket's lifecycle.
replace_central_log_bucket_lifecycle = true

guardduty_export_lifecycle_rules = [
  {
    id              = "guardduty-archive"
    prefix          = "guardduty/"
    expiration_days = 2555
    transitions     = [{ storage_class = "DEEP_ARCHIVE", days = 180 }]
  },
]

macie_export_lifecycle_rules = [
  {
    id              = "macie-archive"
    prefix          = "macie/classification-results/"
    expiration_days = 365
  },
]
```

**That configuration is the whole lifecycle of the central log bucket.** The
logging module writes the lifecycle of the same bucket, so two writers would
replace each other's rules on every apply, and a destroy of either deletes every
rule. The module therefore writes it only with
`replace_central_log_bucket_lifecycle = true`, meant for a bucket no other
configuration manages. Without it, a GuardDuty or Macie rule input that would
write the configuration is refused in the plan. In this repository's stacks the
logging module owns the bucket: put the export rules into its
`central_log_bucket_lifecycle_rules`. That input is the whole rule set of the
bucket, so it also has to carry the `cloudtrail/`, `config/` and
`s3-access-logs/` rules the logging module would otherwise derive.

A deployment that already wrote the export rules from this module drops the
resource when the inputs go back to `null`, and that destroy deletes the
bucket's lifecycle. Apply the logging stack right after it to write the
complete rule set again, or remove
`aws_s3_bucket_lifecycle_configuration.guardduty_export[0]` from the security
stack's state first so the destroy is not sent to S3.

**The Session Manager rules are the whole lifecycle of their bucket.** That
bucket is passed in by name and is not the module's. Setting
`session_manager_lifecycle_rules` replaces every rule the bucket already has and
a destroy deletes them all, so the rule set has to carry every rule the bucket
needs.

## Outputs

| Name | Description |
|------|-------------|
| `ebs_default_kms_key_arn` | Key registered as the account-wide EBS default encryption key — the supplied one, or the module's own when none was supplied (empty while the encryption is off) |
| `guardduty_detector_id` | GuardDuty detector ID |
| `security_hub_arn` | Security Hub ARN |
| `access_analyzer_arn` | IAM Access Analyzer ARN |
| `guardduty_export_frequency` | Export frequency in force for the GuardDuty findings (empty while the export is off) |
| `guardduty_excluded_regions` | Regions in which GuardDuty is not wanted |
| `security_hub_excluded_regions` | Regions in which Security Hub is not wanted |
| `macie_excluded_regions` | Regions in which Macie is not wanted |
| `ebs_encryption_excluded_regions` | Regions in which the EBS default encryption is not wanted |
| `s3_public_access_block_excluded_accounts` | Accounts the public access block is not enforced in |
| `guardduty_export_prefix` | Prefix the GuardDuty findings are written under |
| `firewall_config_bucket_name` | Name of the firewall configuration bucket (empty while it is not created) |
| `per_account_cloudwatch_kms_key_arn` | ARN of the per-account KMS key for CloudWatch Logs encryption (empty while `enable_per_account_kms_keys` is disabled) |

Every `enable_*` state of this module is observable through the resource the
toggle creates, and outputs that merely echoed an input were therefore dropped
in favour of resource assertions. The configured state of the central root user
management lives in the organization stack (see [Provider
Limits](#provider-limits)), not in this module.

## Resources

The module creates the resource types below. They are grouped by the file that declares them, so the grouping doubles as a map of the module. A type appears in more than one row when several files create it for their own purpose. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

| File | Resource types |
|---|---|
| `access-analyzer.tf` | `aws_accessanalyzer_analyzer` |
| `audit-manager.tf` | `aws_auditmanager_account_registration`, `aws_organizations_delegated_administrator`, `aws_s3_bucket`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_lifecycle_configuration` |
| `default-vpc.tf` | `aws_default_vpc`, `aws_default_security_group` |
| `delegated-admin.tf` | `aws_organizations_delegated_administrator` |
| `detective.tf` | `aws_detective_graph`, `aws_organizations_delegated_administrator`, `aws_detective_organization_admin_account` |
| `ebs-encryption.tf` | `aws_ebs_encryption_by_default`, `aws_ebs_default_kms_key`, `aws_kms_key`, `aws_kms_alias`, `aws_s3_account_public_access_block` |
| `firewall-manager.tf` | `aws_fms_policy`, `aws_s3_bucket`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_public_access_block`, `aws_iam_role`, `aws_iam_instance_profile`, `aws_iam_role_policy` |
| `guardduty.tf` | `aws_guardduty_detector`, `aws_guardduty_organization_admin_account`, `aws_guardduty_detector_feature`, `time_sleep`, `aws_guardduty_publishing_destination`, `aws_guardduty_malware_protection_plan`, `aws_iam_role`, `aws_iam_role_policy`, `aws_s3_bucket_lifecycle_configuration`, `aws_lambda_function`, `aws_lambda_invocation` |
| `kms.tf` | `aws_kms_key`, `aws_kms_alias` |
| `macie.tf` | `aws_macie2_account`, `aws_macie2_organization_admin_account`, `aws_macie2_classification_export_configuration`, `aws_iam_role`, `aws_iam_role_policy`, `aws_lambda_function`, `aws_lambda_invocation` |
| `password-policy.tf` | `aws_iam_account_password_policy` |
| `resource-policy-enforcement.tf` | `aws_config_organization_custom_rule`, `aws_config_remediation_configuration` |
| `securityhub.tf` | `aws_securityhub_account`, `aws_securityhub_organization_admin_account`, `aws_securityhub_standards_subscription`, `aws_securityhub_standards_control`, `aws_securityhub_finding_aggregator`, `aws_securityhub_automation_rule` |
| `session-manager.tf` | `aws_iam_policy`, `aws_iam_role_policy_attachment`, `aws_ssm_document` |
| `ssm-documents.tf` | `aws_ssm_service_setting`, `aws_ssm_document`, `aws_ssm_resource_data_sync` |

## GuardDuty Malware Scan Settings

`guardduty_keep_malware_snapshots = true` keeps the EBS snapshots the malware
scan creates when a scan finds malware, so the volume state is available for
forensics. The scan settings API has no plan-time resource: the module deploys
a small function that Terraform itself invokes synchronously at deployment
time (one call per apply). It applies the retention setting when the switch is
on and reverts the setting to the service default when the switch leaves the
configuration. With the default `false` nothing is created.

Per entry of `guardduty_s3_malware_configs`, `enable_malware_protection_tags`
(default `true`) controls whether scanned objects receive the scan result tag,
and `tags` assigns tags to the protection plan resource itself:

```hcl
guardduty_keep_malware_snapshots = true

guardduty_s3_malware_configs = [
  {
    bucket_name                    = "central-data"
    enable_malware_protection_tags = false
    tags                           = { DataClassification = "internal" }
  }
]
```

The per-feature region exclusion lists
(`guardduty_ec2_protection_excluded_regions`,
`guardduty_eks_protection_excluded_regions`,
`guardduty_lambda_protection_excluded_regions`,
`guardduty_rds_protection_excluded_regions`) document — next to the
configuration they exclude from — the regions in which a protection feature
is not wanted. Like the module's other region lists, a `check` block reports
a plan that runs against a listed region.

## Customer-Managed Key Sets

Each `kms_keys` entry creates one KMS key with its alias. Beyond alias,
description, policy, rotation and the deletion window, two attributes control
the key lifecycle:

- `is_enabled` (default `true`) — `false` creates the key (or moves an
  existing one) into the disabled state: the key exists and keeps its
  material, but encrypt and decrypt calls are refused until it is enabled
  again. Useful for staging a key ahead of a migration or for taking a
  suspected key out of service without scheduling deletion.
- `removal_policy` (default `destroy`) — what happens when the entry is
  removed from the configuration. `destroy` schedules key deletion after
  `deletion_window_in_days` (7–30 days, default 30), during which the
  deletion can still be cancelled. `retain` composes an additional statement
  into the key policy that denies `kms:ScheduleKeyDeletion` for every
  principal: any deletion attempt — a Terraform destroy, the console or the
  CLI — fails at the API. To actually remove a retained key, set its
  `removal_policy` back to `destroy`, apply, and remove the entry in a second
  apply. `PutKeyPolicy` intentionally stays allowed so this path never needs
  state surgery. A `snapshot` mode is not offered: KMS key material has no
  snapshot form, and the validation message says so.

With `removal_policy = "retain"` and no `policy`, the module renders the
explicit equivalent of the AWS default key policy (root account access) from
`configurations/policies/security/kms-default-key-policy.json` and appends the
deny statement — appending to the implicit default policy is not possible.
A supplied `policy` keeps all its statements and receives the deny statement
as the last entry. With `removal_policy = "destroy"` a supplied `policy`
passes through byte for byte.

```hcl
kms_keys = [
  {
    alias          = "app-data"
    description    = "Application data at rest"
    removal_policy = "retain"
  },
  {
    alias      = "migration-staging"
    is_enabled = false
  }
]
```

## Macie Fine-Tuning

Four inputs refine an enabled Macie deployment beyond the service switch:

- `macie_automated_discovery` — manages the automated sensitive data
  discovery (continuous sampling and analysis of S3 objects without manual
  classification jobs). `true` enables it, `false` explicitly disables it,
  `null` (the default) leaves the setting unmanaged. Removing the switch
  disables the discovery again.
- `macie_classification_scope_excluded_buckets` — S3 buckets the automated
  discovery skips, grouped as bucket names per region. The classification
  scope API is regional, so each deployment applies only the entries of its
  own region; the declared names replace the previous exclusion state, and
  removing the list clears it. Requires `macie_automated_discovery = true`.
- `macie_disabled_regions` — regions whose Macie session stays managed but
  explicitly suspended (`status = PAUSED`): analysis and billing stop while
  configuration and findings remain, and removing the region resumes the
  session. This differs from `macie_excluded_regions`, which only documents
  and reports an unmanaged region; a full regional disable remains
  `enable_macie = false` for that region's deployment.
- `macie_publish_policy_findings` — manages whether Macie publishes policy
  findings to Security Hub (`true`/`false`; `null` leaves the setting
  unmanaged — the service publishes policy findings by default). The
  sensitive-data side of the same publication setting is read first and
  preserved unchanged; removing the switch restores the service default.

The three session APIs behind the discovery, the exclusions and the
publication have no plan-time resource. The module deploys a small function
that Terraform itself invokes synchronously at deployment time (one
invocation per setting): it applies the declared state when a switch is set
and restores the service default when the switch leaves the configuration.
With all defaults nothing is created.

```hcl
enable_macie              = true
macie_automated_discovery = true

macie_classification_scope_excluded_buckets = [
  { names = ["public-assets", "cdn-content"], region = "eu-central-1" }
]

macie_disabled_regions        = ["eu-west-3"]
macie_publish_policy_findings = true
```

## Security Hub Automation Rules

`security_hub_automation_rules` creates one automation rule per entry. A rule
matches findings by criteria and applies its finding fields update to every
match. All finding fields the automation rules API knows are available as
criteria, in the filter form the field carries: string fields take
`comparison` (`EQUALS`, `PREFIX`, `NOT_EQUALS`, `PREFIX_NOT_EQUALS`,
`CONTAINS`, `NOT_CONTAINS`, `CONTAINS_WORD`) and `value`; the number fields
`confidence` and `criticality` take exactly one operator form — `eq` alone or
a combination of `gt`/`gte`/`lt`/`lte`, each bound 0-100; the date fields
(`created_at`, `first_observed_at`, `last_observed_at`, `note_updated_at`,
`updated_at`) take either a rolling `date_range` (`unit = "DAYS"`) or a fixed
window via ISO 8601 `start`/`end`; the key-value fields (`resource_tags`,
`resource_details_other`, `user_defined_fields`) take `key`, `value` and a
comparison of `EQUALS`, `NOT_EQUALS`, `CONTAINS`, `NOT_CONTAINS`.

The finding fields update can set the severity, a note, the workflow status,
finding types, user-defined fields, the verification state, `confidence` and
`criticality` (0-100) and link `related_findings` (id plus Security Hub
product ARN). `enabled = false` deploys a rule in disabled state;
`exclude_regions` skips the rule in the named regions while the remaining
configuration stays identical across deployments. `rule_order` decides the
evaluation order, `is_terminal` stops rule processing after a match.

```hcl
security_hub_automation_rules = [
  {
    rule_name   = "escalate-stale-critical"
    rule_order  = 5
    description = "Raise stale critical findings to the incident workflow"
    is_terminal = true
    criteria = {
      severity_label = [{ comparison = "EQUALS", value = "CRITICAL" }]
      workflow_status = [{ comparison = "EQUALS", value = "NEW" }]
      created_at     = [{ date_range = { unit = "DAYS", value = 30 } }]
      confidence     = [{ gte = 80 }]
    }
    actions = {
      finding_fields_update = {
        workflow    = { status = "NOTIFIED" }
        note        = { text = "Escalated by automation", updated_by = "landing-zone" }
        criticality = 90
      }
    }
  }
]
```

## Resource Policy Enforcement

`resource_policy_enforcement` names the resource types whose resource policies
are to be checked, one Config rule per enabled entry, and per entry the
remediation document that is to repair a violation. The check needs a Lambda
evaluator: an organization Config rule with a custom evaluation cannot exist
without one. As long as `resource_policy_enforcement_lambda_arn` is empty, the
module therefore creates no rule and no remediation, and the `check` block
`resource_policy_enforcement_requires_evaluator` says so — rather than planning a
rule that the service would reject.

`resource_policy_enforcement_document` carries the content of the remediation
document instead of its path, because a path relative to the configuration does
not survive the deployment cache. The module's own repo-relative `file()` reads
(`${path.module}/../../configurations`) do survive it: the stack sources use
the double-slash form (`${get_repo_root()}//modules/security`), so Terragrunt
copies the whole repo tree into the cache instead of the module directory
alone, and the relative paths resolve.

A `deployment_targets` entry is accepted so that the same configuration can be
read by per-account stacks, but it does not reach anything here: the module
cannot create providers for accounts it does not know at plan time. Every entry
that sets it is reported by `resource_policy_deployment_targets_warning`.

### Input parameters and the network perimeter

`input_parameters` per entry is a `map(string)` that rides along with the
template in the Config rule's input parameters, so the evaluator receives the
operator's key-value pairs with every evaluation. The key `policyTemplate` is
reserved for the template itself and rejected at plan; the module merges the
template last, so a colliding key could not displace it either way.

`resource_policy_enforcement_network_perimeter` resolves network references in
the templates. A template names the perimeter through the placeholder string
`"{{NETWORK_PERIMETER_VPC_IDS}}"` (quotes included); with `enabled = true` the
module replaces that quoted placeholder with the JSON array of the perimeter
VPC IDs, so the template is valid JSON before the replacement (a string value)
and after it (an array value). `managed_vpc_only = true` limits the perimeter
to `managed_vpc_ids` — the VPCs this landing zone manages, wired from the
networking outputs; `false` widens it to the declared `additional_vpc_ids`
(pre-existing VPCs). Unlike a deployment-time account scan, the perimeter is
declarative: a pre-existing VPC belongs to it exactly when it is declared.

Two guards keep the mechanism honest: a template that carries the placeholder
while the perimeter is disabled is rejected at plan (the evaluator would
receive the literal placeholder string), and an enabled perimeter must resolve
to at least one VPC ID (an empty array would match nothing).

```hcl
resource_policy_enforcement = [
  {
    resource_type   = "AWS::S3::Bucket"
    policy_template = file("policies/s3-perimeter.json") # carries "{{NETWORK_PERIMETER_VPC_IDS}}"
    input_parameters = {
      SourceAccount = "111122223333,444455556666"
    }
  }
]

resource_policy_enforcement_network_perimeter = {
  enabled            = true
  managed_vpc_only   = false
  managed_vpc_ids    = ["vpc-0a1b2c3d4e5f60718"] # from the networking outputs
  additional_vpc_ids = ["vpc-00112233445566778"] # pre-existing VPCs
}
```

## SSM Document Sharing

`ssm_document_share_targets` shares every custom SSM document with the listed
account IDs (`all` shares publicly). On top of that, each `ssm_documents`
entry takes an optional `share_targets` object with `accounts` (12-digit IDs
or keys of `account_ids`) and `organizational_units` (keys of
`ou_name_to_id`). The document-sharing API accepts account IDs only, so the
module resolves each named OU to the accounts that `account_ou_ids` places in
it — declaratively from the maps, not by scanning the organization at
deployment time. An account joins the share exactly when the maps declare it;
the maps come from the accounts and organization stacks, so newly created
accounts appear with the next plan.

A document without `share_targets` carries the global list verbatim, byte
for byte. With `share_targets`, the global list, the
resolved accounts and the resolved OU members are united and deduplicated.
Three guards reject unknown account names, unknown OU names and the
combination of per-document targets with a public `all` share; an OU that
resolves to no account is reported by the
`ssm_document_share_empty_ou_warning` check.

```hcl
account_ids    = { Audit = "444455556666", Sandbox = "666677778888" }
ou_name_to_id  = { Security = "ou-abcd-11111111" }
account_ou_ids = { Audit = "ou-abcd-11111111" }

ssm_document_share_targets = ["333333333333"] # every document

ssm_documents = [
  {
    name          = "tlz-patch-baseline"
    document_type = "Command"
    content       = file("documents/patch-baseline.json")
    share_targets = {
      accounts             = ["Sandbox"]    # resolved via account_ids
      organizational_units = ["Security"]   # resolved to the OU's accounts
    }
  }
]
```

## Session Manager Log Targets

The session document names its log targets — `session_manager_cloudwatch_log_group`
and `session_manager_s3_bucket_name` — and the SSM Document API accepts any
string for either. A log group or bucket that nothing creates therefore applies
cleanly and fails only when an operator opens a session: `Failed to upload
session logs`, or the session is refused outright where logging is enforced.
This module creates neither target — the bucket belongs to whoever passes its
name in (see the lifecycle note above), and the log group is not a resource of
any module in this repository.

Two `check` blocks in `session-manager.tf` close that gap at plan time:

- `session_manager_cloudwatch_log_group_exists` lists the account's log groups
  under the configured name as prefix and warns when the exact name is not among
  them.
- `session_manager_s3_bucket_exists` lists the account's buckets under the
  configured name as prefix and warns when the exact name is not among them.

Both are warnings, not blocking preconditions: the plan and the session document
go through unchanged, and the operator decides whether to create the target or
fix the name. Two consequences follow from the lookup being a listing:

- **A bucket owned by another account does not appear in `ListBuckets`.** The
  warning then fires although the name is correct and the bucket policy admits
  the writes. Treat it as the reminder to verify the cross-account grant, not
  as a defect of the configuration.
- **The plan role needs `logs:DescribeLogGroups` and `s3:ListAllMyBuckets`.**
  Without them the lookup fails — and a data source nested in a `check` block
  masks its provider errors as warnings, so the plan still goes through, with a
  permission warning in place of the existence verdict. The bundled
  `TLZDeploymentRole` (`configurations/policies/deployment/role-inline-policy.json`)
  grants both: `logs:DescribeLogGroups` in `SupportingServices` and
  `s3:ListAllMyBuckets` in its own statement `S3ListAllBuckets`, so under that
  role both checks give a real existence verdict. The S3 action sits apart from
  `S3Access` deliberately: `ListBuckets` takes no bucket ARN, so
  `s3:ListAllMyBuckets` is account-wide by nature and `Resource: "*"` is a
  property of the action rather than a choice of the policy — a reader
  tightening `S3Access` must not take it for one more action that can be
  scoped. What the grant adds is the ability to enumerate every bucket name in
  the account, nothing more (the role could already create, delete, read and
  write any bucket). A custom plan role that omits either action sees the
  permission warning instead of the verdict. No offline test pins the bundled
  grant: if `S3ListAllBuckets` is dropped from the bundled policy, the check
  block answers with its permission warning, not with a red test.

The existing check `session_manager_s3_logging_no_bucket` is unchanged and
covers the other half of the defect: S3 logging switched on with an *empty*
bucket name.

For the offline tests this is a structural conflict: the runs name targets that
exist nowhere, and the lookup answers correctly that they do not. The one run
that legitimately does so (`custom_configuration_platform`) carries a
run-scoped `override_data` describing the world in which its names exist; no
other run does, and two runs pin that the checks fire on a
near-miss name and on an empty listing.

## Password Policy

Every attribute of `password_policy` is optional and carries its own default, so
setting a single attribute keeps the remaining defaults, as the usage example
further down shows. The declared default object repeats those per-attribute
defaults explicitly — static analyzers evaluate the variable default but not the
type-level `optional()` defaults, so an empty default object would make the
compliant policy unprovable for the security scan. Both lists carry the same
values by design; change them together.

| Attribute | Type | Default | Accepted range |
|------|------|---------|----------------|
| `minimum_length` | `number` | `14` | 8–128 |
| `require_uppercase` | `bool` | `true` | — |
| `require_lowercase` | `bool` | `true` | — |
| `require_numbers` | `bool` | `true` | — |
| `require_symbols` | `bool` | `true` | — |
| `max_age` | `number` | `90` | 0–1095 days |
| `password_reuse_prevention` | `number` | `24` | 0–24 |
| `allow_users_to_change` | `bool` | `true` | — |
| `hard_expiry` | `bool` | `false` | — |

## Provider Limits

Two inputs record an intent and create nothing:

- `root_credentials_management` and `allow_root_sessions` — central management of
  the member accounts' root credentials and of privileged root sessions. No
  resource reads them; a `true` value only raises the warning of the `check`
  block `root_credentials_management_provider_limitation`.

Nothing in this repository enables the two features. The organization stack
registers trusted access for the IAM service principal through
`aws_service_access_principals` of `modules/organization`, switched by the
configuration key `enable_central_root_management`. That trusted access is the
prerequisite only: the features `RootCredentialsManagement` and `RootSessions`
stay off until they are enabled in the management account:

```sh
aws iam enable-organizations-root-credentials-management
aws iam enable-organizations-root-sessions
```

The provider version the lock file pins (`hashicorp/aws` 6.62.0) has a resource
for the two features, `aws_iam_organizations_features`; no module of this
repository declares it. The defaults stay `true` because the configuration
loader's default is `true` and the two must match. The warning is the reminder
that the step is still open; it is not a defect of the plan.

## Firewall Manager administrator

`aws_fms_policy` (`fms_policies`) is accepted by AWS only from a **Firewall
Manager administrator account**. The module does not register one, and nothing
else in this repository does either: `AssociateAdminAccount` is a one-time,
organization-level decision taken from the organization's management account
(it also registers the chosen account as Organizations delegated administrator
for `fms`), and its removal follows first-in-last-out semantics across every
administrator — not a resource for a module that is applied per stack. Without
the registration every configured policy fails at apply with
`InvalidOperationException` ("No default admin could be found").

The `fms` entry of `service_access_principals` in the organization stack is
**not** that registration: it calls `RegisterDelegatedAdministrator` on
Organizations, which does not make the account a Firewall Manager
administrator. The direction is the reverse — Firewall Manager registers the
delegated administrator as a side effect of `AssociateAdminAccount`.

Plan time cannot observe the registration: the provider has no data source for
the Firewall Manager administrator, and the Organizations delegated-administrator
list also contains plain `RegisterDelegatedAdministrator` entries, so a check
on it would pass exactly when the apply still fails. The module therefore asks
for an explicit acknowledgement:

1. Register the administrator once, from the management account:
   `aws fms associate-admin-account --admin-account <account-id>`.
2. Make sure the account that applies this module with `fms_policies` set is a
   Firewall Manager administrator — policies are created from the applying
   account, not from the registered one.
3. Set `fms_admin_account_registered = true`.

A `lifecycle` precondition on `aws_fms_policy.this` requires the
acknowledgement, so a configuration with `fms_policies` and the default `false`
fails at **plan** time with a message that names the missing step; a
configuration that did the step plans clean. The acknowledgement is an
attestation, not a verification — if it is set without the registration, the
apply still fails. In the `aws-eusc` partition the policy list is emptied
and the precondition has no instance to evaluate; only the partition warning
remains.

## Usage Example

```hcl
module "security" {
  source = "./modules/security"

  audit_account_id        = "123456789012"
  central_log_bucket_name = "tlz-central-logs-987654321098-eu-central-1"

  enable_guardduty       = true
  enable_security_hub    = true
  enable_macie           = true
  enable_access_analyzer = true

  security_hub_standards = [
    { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" },
    { arn_suffix = "cis-aws-foundations-benchmark/v/1.4.0" },
  ]

  password_policy = {
    minimum_length = 16
    max_age        = 60
  }
}
```

## Configuration Path

The module is deployed by `stacks/management/security`, which reads every input
from the compliance loader (`configurations/loader.hcl`). The loader merges
`configurations/base/base.tfvars`, `env/common.hcl` and the enabled compliance
frameworks, so a switch is set where it belongs and reaches the module through
one façade. Three consequences are worth knowing before changing a value:

- `enable_ebs_default_encryption`, `enable_s3_public_access_block` and
  `enable_ssm_block_public_sharing` are set to `true` in
  `configurations/base/base.tfvars`. Boolean switches are merged with OR (the
  most restrictive value wins), so a `false` in `env/common.hcl` has no effect on
  these three — switching them off means changing `base.tfvars`.
- `allow_root_sessions` is merged with AND: the restrictive value is `false`, so
  a `false` in any layer disables root sessions.
- `audit_manager_bucket_lifecycle_days` is deliberately not coupled to
  `log_retention_days`, because `0` means "no lifecycle rule" here.

`guardduty_eks_manage_agent` is a sub-configuration of
`guardduty_eks_runtime_monitoring`, not a switch of its own: it drives the
`EKS_ADDON_MANAGEMENT` additional configuration of the runtime monitoring
detector feature and is only submitted while runtime monitoring is enabled.

## Lambda execution log groups

Lambda creates a function's execution log group, `/aws/lambda/<function name>`,
implicitly on the first invocation when nothing has declared it. Such a group
sits outside the Terraform state, carries no retention — its logs never expire —
and no `destroy` and no test teardown removes it, in every deployment and not
only in a test. The monitoring module declares the groups of its two
functions for the same reason
([Lambda execution log groups](../monitoring/README.md#lambda-execution-log-groups));
each of this module's two settings functions owns its group as well:

| Log group | Resource | Retention |
|---|---|---|
| `/aws/lambda/tlz-guardduty-scan-settings` | `aws_cloudwatch_log_group.guardduty_scan_settings` | `guardduty_scan_settings_log_retention_days` (default `365`) |
| `/aws/lambda/tlz-macie-session-settings` | `aws_cloudwatch_log_group.macie_session_settings` | `macie_session_settings_log_retention_days` (default `365`) |

Each name derives from its function rather than being spelled out again, so a
group can never disagree with the function it belongs to. Both functions are invoked synchronously by
Terraform during the apply, so every `aws_lambda_invocation` depends on the
group — including each of the three Macie invocations, since which one runs
first depends on the toggles rather than on the chain between them.

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
terragrunt import 'aws_cloudwatch_log_group.guardduty_scan_settings[0]' /aws/lambda/tlz-guardduty-scan-settings
terragrunt import 'aws_cloudwatch_log_group.macie_session_settings[0]' /aws/lambda/tlz-macie-session-settings
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
