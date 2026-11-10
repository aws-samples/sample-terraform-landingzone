# Bootstrap Module

Creates S3 bucket and DynamoDB table for Terraform remote state with optional KMS encryption.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `state_bucket_name` | S3 bucket name for Terraform state | `string` | — | yes |
| `lock_table_name` | DynamoDB table name | `string` | `"terraform-locks"` | no |
| `kms_key_alias` | KMS key alias (empty = AES256) | `string` | `""` | no |

With `kms_key_alias` set, the module-managed KMS key encrypts the state bucket
**and** the DynamoDB lock table (`server_side_encryption` with the same key —
one trust domain, no additional key). Without an alias, the bucket uses AES256
and the lock table keeps the DynamoDB service default (AWS-owned key). On an
existing deployment, setting the alias re-encrypts the lock table in place.

## Outputs

| Name | Description |
|------|-------------|
| `state_bucket_arn` | S3 bucket ARN |
| `lock_table_arn` | DynamoDB table ARN |
| `kms_key_arn` | KMS key ARN (empty if no key) |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_kms_key`
- `aws_kms_alias`
- `aws_s3_bucket`
- `aws_s3_bucket_versioning`
- `aws_s3_bucket_server_side_encryption_configuration`
- `aws_s3_bucket_public_access_block`
- `aws_s3_bucket_lifecycle_configuration`
- `aws_dynamodb_table`

## Usage Example

```hcl
module "bootstrap" {
  source = "./modules/bootstrap"

  state_bucket_name = "my-org-terraform-state"
  lock_table_name   = "terraform-locks"
  kms_key_alias     = "alias/terraform-state"
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
