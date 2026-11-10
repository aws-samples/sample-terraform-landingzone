# Security Org Config Module

Configures org-wide security service enablement from the Audit account (delegated admin). Manages GuardDuty, Security Hub, Macie, and Detective with org-wide auto-enable and feature toggles.

Four notes on behaviour:

- **Who designates the delegated administrator.** This module does *not* make the delegated-admin designations (`aws_guardduty_organization_admin_account`, `aws_securityhub_organization_admin_account`, `aws_macie2_organization_admin_account`, `aws_detective_organization_admin_account`). AWS accepts each service's `EnableOrganizationAdminAccount` only from the organization management account, so `modules/security` (management stack) designates the Audit account; this module runs *as* that designated administrator and owns what the administrator configures — the detector, the org configurations, the graph, the standards. A state that holds `aws_macie2_organization_admin_account.this` or `aws_detective_organization_admin_account.this` under this module is forgotten by the bundled `removed` blocks without an API call (a `DisableOrganizationAdminAccount` from the Audit account would be refused, as the designation is); the designation itself lives in the management stack.
- **GuardDuty feature propagation.** Every toggle in `guardduty_features` is carried to the members by one `aws_guardduty_organization_configuration_feature` per feature (`auto_enable = "ALL"` when on, `"NONE"` when off — so switching a feature off also reaches the members). The deprecated `datasources` block of `aws_guardduty_organization_configuration` is not set: it covers only S3 data events, EKS audit logs and EBS malware protection, so RDS login events, Lambda network logs and EKS runtime monitoring would be enabled on the Audit account's own detector but never auto-enabled for members. The attribute is computed in the provider, so leaving the block out plans no change on the org configuration itself.
- **Security Hub standards** listed in `security_hub_standards` are subscribed in the delegated admin account (`aws_securityhub_standards_subscription`), the same form `modules/security` uses for the management account.
- **Macie and Detective** are skipped in the EU Sovereign Cloud — neither service is available in the `aws-eusc` partition. The decision is derived from the detected partition (`data.aws_partition.current`), so it does not depend on a caller passing `is_eusc`; the input stays available to force the same behaviour elsewhere. The `detective_partition_availability` check reports the Detective skip so the toggle never goes silently without effect; the Macie warning surface lives in `modules/security` (`macie_partition_availability`).

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `enable_guardduty` | Enable GuardDuty org-wide configuration from the Audit account | `bool` | `false` | no |
| `enable_security_hub` | Enable Security Hub org-wide configuration from the Audit account | `bool` | `false` | no |
| `enable_macie` | Enable Macie org-wide configuration from the Audit account | `bool` | `false` | no |
| `enable_detective` | Enable Detective org-wide configuration from the Audit account | `bool` | `false` | no |
| `is_eusc` | Whether the deployment is in the EU Sovereign Cloud partition (disables Macie and Detective) | `bool` | `false` | no |
| `guardduty_features` | GuardDuty detector feature toggles for org-wide configuration | `object` | `{}` | no |
| `guardduty_deployment_targets` | Selective account/OU targets for GuardDuty (empty = org-wide) | `list(string)` | `[]` | no |
| `security_hub_standards` | Security Hub standards to enable org-wide. Each entry is either a plain ARN suffix string or an object with `arn_suffix` and `enabled`; disabled entries are documentation only. All entries of one list must share a type. | `list(any)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `guardduty_detector_id` | GuardDuty detector ID in the Audit account |
| `guardduty_org_configuration_id` | GuardDuty organization configuration ID |
| `security_hub_enabled` | Whether Security Hub org configuration is enabled |
| `macie_enabled` | Whether Macie org configuration is enabled (false in EUSC) |
| `detective_graph_arn` | Detective graph ARN in the Audit account |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_guardduty_detector`
- `aws_guardduty_detector_feature`
- `aws_guardduty_organization_configuration`
- `aws_guardduty_organization_configuration_feature`
- `aws_securityhub_account`
- `aws_securityhub_organization_configuration`
- `aws_securityhub_standards_subscription`
- `aws_macie2_account`
- `aws_detective_graph`
- `aws_detective_organization_configuration`

The delegated-admin designations (`aws_*_organization_admin_account`) are resources of `modules/security`, see the first note above.

## Usage Example

```hcl
module "security_org_config" {
  source = "./modules/security-org-config"

  enable_guardduty    = true
  enable_security_hub = true
  enable_macie        = true
  enable_detective    = true
  is_eusc             = false

  guardduty_features = {
    s3_protection          = true
    eks_audit_logs         = true
    ebs_malware_protection = true
    rds_protection         = true
    lambda_protection      = true
  }
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
