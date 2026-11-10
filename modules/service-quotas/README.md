# Service Quotas Module

Manages AWS Service Quota increase requests in the Management Account. Each quota definition specifies a service code, quota code, and desired value.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `service_quota_increases` | List of service quota increase requests | `list(object)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `quota_request_ids` | Map of `"service_code/quota_code"` to request ID |

## Resources

The module creates one resource type, in `main.tf`, one instance per entry of `service_quota_increases`:

- `aws_servicequotas_service_quota`

## Usage Example

```hcl
module "service_quotas" {
  source = "./modules/service-quotas"

  service_quota_increases = [
    {
      service_code  = "vpc"
      quota_code    = "L-F678F1CE"
      desired_value = 10
    },
    {
      service_code  = "ec2"
      quota_code    = "L-1216C47A"
      desired_value = 500
      enabled       = false
    },
  ]
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
