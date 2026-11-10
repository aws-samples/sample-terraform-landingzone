# Control Tower Module

Creates and manages an AWS Control Tower Landing Zone with service roles, centralized logging, and optional guardrails (controls) on organizational units.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `management_account_id` | Management account ID for trust policies (resolved via aws_caller_identity when empty) | `string` | `""` | no |
| `audit_account_id` | Account ID of the Audit account | `string` | — | yes |
| `log_archive_account_id` | Account ID of the Log-Archive account | `string` | — | yes |
| `landing_zone_version` | Control Tower Landing Zone version (4.x only — the module builds the v4 manifest schema) | `string` | `"4.0"` | no |
| `governed_regions` | Regions under CT governance | `list(string)` | — | yes |
| `logging_retention_days` | Retention for CloudTrail logs in days | `number` | `365` | no |
| `access_logging_retention_days` | Retention for S3 access logs in days | `number` | `365` | no |
| `enable_identity_center` | Enable IAM Identity Center (SSO) | `bool` | `true` | no |
| `enable_organization_trail` | Whether Control Tower keeps its centralized logging — the organization-wide CloudTrail trail delivering into the Log Archive account. Disable only when an own organization trail replaces it | `bool` | `true` | no |
| `enable_backup_integration` | Whether Control Tower manages AWS Backup (manifest field `backup.enabled`). Default `false` keeps backup outside Control Tower — the backup module manages vaults and plans independently | `bool` | `false` | no |
| `control_tower_controls` | List of Control Tower controls (guardrails) to enable on specified OUs; each control may carry `parameters` (key/value pairs for the EnableControl API, values as JSON document strings) | `list(object)` | `[]` | no |
| `ou_name_to_arn` | Map of OU name to OU ARN for resolving control targets | `map(string)` | `{}` | no |
| `auto_enroll_ous` | OU names to be registered for Control Tower governance. Registration is reported by a `check` block instead of a resource, because the provider offers no native OU registration | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `landing_zone_id` | Control Tower Landing Zone ID |
| `landing_zone_arn` | Control Tower Landing Zone ARN |
| `drift_status` | Control Tower Drift Status |
| `control_tower_control_count` | Number of Control Tower controls (guardrails) enabled |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_iam_role`
- `aws_iam_role_policy_attachment`
- `aws_iam_role_policy`
- `time_sleep`
- `aws_controltower_landing_zone`
- `aws_controltower_control`

## Usage Example

```hcl
module "control_tower" {
  source = "./modules/control-tower"

  audit_account_id       = "123456789012"
  log_archive_account_id = "210987654321"
  governed_regions       = ["eu-central-1", "us-east-1"]

  logging_retention_days        = 365
  access_logging_retention_days = 365
  enable_identity_center        = true

  control_tower_controls = [
    {
      # A control_identifier is the partition-neutral control name; the
      # module builds the control ARN from the current partition. A full
      # control ARN is passed through unchanged.
      control_identifier   = "AWS-GR_RESTRICT_ROOT_USER"
      organizational_units = ["Workloads"]
    },
    {
      # Region-aware controls take their parameters at enablement — without
      # AllowedRegions the region-deny control refuses to deploy.
      control_identifier   = "AWS-GR_REGION_DENY"
      organizational_units = ["Workloads"]
      parameters = [
        { key = "AllowedRegions", value = jsonencode(["eu-central-1", "eu-west-1"]) },
      ]
    },
  ]

  ou_name_to_arn = module.organization.ou_name_to_arn
}
```

### Control parameters

Each `control_tower_controls` entry may carry a `parameters` list. A
parameter is a `key`/`value` pair forwarded to the `EnableControl` API call:
the key is the PascalCase parameter name the control defines (for example
`AllowedRegions`), the value is a JSON document string — build it with
`jsonencode`. The module rejects malformed keys, non-JSON values and
duplicate keys per control at plan time, where the API would otherwise fail
late during apply. Parameters apply to every organizational unit the control
is enabled on.

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
