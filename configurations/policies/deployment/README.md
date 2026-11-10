# Deployment Policies

IAM inline policy and trust policy for the cross-account deployment role assumed by the CI/CD pipeline.

| File | Description |
|------|-------------|
| `role-inline-policy.json` | Inline policy for the deployment role granting Organizations, CloudTrail, Config, IAM, security services, S3, SSM, KMS, STS, and supporting service access. The default document of `modules/deployment-role` |
| `role-inline-policy-narrow.json` | The same document with the seven `service:*` grants replaced by enumerated actions (table below). Selected by `narrow_grants = true` of `modules/deployment-role`; everything outside those grants is identical to `role-inline-policy.json` |
| `role-trust-policy.json` | Trust policy allowing the deployment account to assume the deployment role |

## The narrow document

`role-inline-policy.json` grants `guardduty:*`, `securityhub:*`, `macie2:*`, `access-analyzer:*` (statement `SecurityServicesAccess`) and `sso:*`, `sso-directory:*`, `identitystore:*` (statement `SupportingServices`) on `Resource: "*"`. `role-inline-policy-narrow.json` replaces each of them by the actions the provider calls for the resource types the modules declare — create, read, update, delete, tagging and the lookups the data sources make. `tests/test_deployment_role_narrow_grants.py` derives those resource types from `modules/**/*.tf` and pins every row below to the document; `budgets:*`, `controltower:*` and `servicecatalog:*` on the same statement are out of scope and stay in both documents.

| Statement | Service prefix | Resource types the modules declare | Actions | Why `Resource` stays `*` |
|-----------|----------------|------------------------------------|---------|--------------------------|
| `SecurityServicesAccess` | `guardduty` | `aws_guardduty_detector`, `_detector_feature`, `_organization_admin_account`, `_organization_configuration`, `_organization_configuration_feature`, `_publishing_destination`, `_malware_protection_plan` | 20 | `CreateDetector`, the organization admin and organization configuration calls take no resource ARN; the detector, destination and plan ids are created by the first apply |
| `SecurityServicesAccess` | `securityhub` | `aws_securityhub_account`, `_organization_admin_account`, `_organization_configuration`, `_standards_subscription`, `_standards_control`, `_finding_aggregator`, `_automation_rule` | 25 | `EnableSecurityHub`, the organization calls and `GetEnabledStandards` take no resource ARN; the hub, aggregator and rule ARNs exist only after the first apply |
| `SecurityServicesAccess` | `macie2` | `aws_macie2_account`, `_organization_admin_account`, `_classification_export_configuration` | 9 | Every call is account- or organization-level and takes no resource ARN |
| `SecurityServicesAccess` | `access-analyzer` | `aws_accessanalyzer_analyzer` | 7 | `CreateAnalyzer` takes no resource ARN; the analyzer ARN carries region and account, which this static file cannot name per installation |
| `SupportingServices` | `sso` | `data.aws_ssoadmin_instances`, `data.aws_ssoadmin_permission_set`, `aws_ssoadmin_permission_set`, `_permission_set_inline_policy`, `_managed_policy_attachment`, `_customer_managed_policy_attachment`, `_permissions_boundary_attachment`, `_account_assignment` | 28 | `ListInstances` takes no resource ARN; instance and permission-set ARNs are per installation and the permission-set ids are created by the first apply |
| `SupportingServices` | `sso-directory` | none | 0 | The modules call the identitystore API only; no `sso-directory` action is granted |
| `SupportingServices` | `identitystore` | `aws_identitystore_user`, `data.aws_identitystore_user`, `data.aws_identitystore_group` | 9 | The identity store id and the user and group ids are per installation; `ListUsers`, `ListGroups`, `GetUserId`, `GetGroupId` act on the store |

Across all seven prefixes the enumerated action already fixes the resource type it can touch (`guardduty:UpdateDetector` acts on a detector and nothing else), so an ARN pattern with `*` for partition, region, account and id would narrow nothing the action name has not narrowed already. The remaining components — partition, region, account, the ids the first apply creates — are per-installation values; this file is read with `file()` and carries none of them. The compact document is 8045 characters (IAM inline-policy limit 10240).

The default of `narrow_grants` is `false`: a deployment that does not set the flag renders `role-inline-policy.json` byte for byte. See [the module README](../../../modules/deployment-role/README.md) for the flag.
