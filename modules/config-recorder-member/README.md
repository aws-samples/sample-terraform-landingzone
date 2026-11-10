# Config Recorder Member Module

Creates an AWS Config Recorder and Delivery Channel for a single member account, delivering configuration snapshots to a central S3 log bucket.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `central_log_bucket_name` | Name of the central S3 log bucket for Config delivery | `string` | — | yes |

## Outputs

| Name | Description |
|------|-------------|
| `recorder_name` | Name of the Config Recorder |
| `delivery_channel_name` | Name of the Config Delivery Channel |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_config_configuration_recorder`
- `aws_config_delivery_channel`
- `aws_config_configuration_recorder_status`

## Prerequisite: Service-Linked Role

The recorder's `role_arn` points at the well-known path of the service-linked
role `AWSServiceRoleForConfig` (`role/aws-service-role/config.<dns_suffix>/`).
The module does not create that role — whether it exists in the target account
decides the success of the deployment. Accounts created by AWS Organizations
or Control Tower carry it; for other accounts create it once with
`aws iam create-service-linked-role --aws-service-name config.<dns_suffix>`
(the DNS suffix of the target partition) before applying this module.

## Usage Example

```hcl
module "config_recorder" {
  source = "./modules/config-recorder-member"

  providers = {
    aws = aws.member_account
  }

  central_log_bucket_name = module.logging.central_log_bucket_name
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
