# SSM Parameters Module

Creates SSM parameters in the Management Account for cross-account configuration sharing.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `ssm_parameters` | List of SSM Parameter definitions (`name`, `type`, `value`, optional `deployment_targets`, optional `key_id` — KMS key for a `SecureString` entry as key id, key ARN, alias name or alias ARN (anything else, `""` included, is refused at plan); unset keeps the AWS-managed `alias/aws/ssm` key, refused on `String`/`StringList`) | `list(object)` | `[]` | no |
| `default_tags` | Tags applied to all resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| `ssm_parameter_names` | Map of SSM parameter names to their ARNs |

## Resources

The module creates one resource type, in `main.tf`, one instance per entry of `ssm_parameters`:

- `aws_ssm_parameter`

## Usage Example

```hcl
module "ssm_parameters" {
  source = "./modules/ssm-parameters"

  ssm_parameters = [
    {
      name  = "/tlz/config/org-id"
      type  = "String"
      value = "o-abc123"
    },
    {
      name  = "/tlz/config/audit-account-id"
      type  = "String"
      value = "123456789012"
    }
  ]

  default_tags = {
    Project = "LandingZone"
  }
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
