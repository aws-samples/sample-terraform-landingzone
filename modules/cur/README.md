# CUR Module

Creates an AWS Cost and Usage Report with optional dedicated S3 bucket and KMS encryption. CUR is only available in us-east-1, and the report definition asserts this as a plan-time precondition — a provider in any other region fails the plan instead of the apply. In the aws-eusc partition the module is automatically skipped, since that billing region does not exist there and service availability is unconfirmed; a check block surfaces the skip as a plan warning. The two react differently on purpose: the wrong region has a caller-side fix (configure the CUR provider for us-east-1) and therefore blocks, while eusc has none and therefore warns.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `enable_cost_and_usage_report` | Enable AWS Cost and Usage Report | `bool` | `false` | no |
| `cur_config` | Cost and Usage Report configuration | `object` | `{}` | no |
| `cur_bucket_lifecycle_rules` | Full lifecycle rule set of the dedicated CUR bucket. `null` keeps the single derived rule | `list(object)` | `null` | no |
| `s3_bucket_name` | Name of the S3 bucket for CUR report storage; may be empty with the dedicated bucket (`enable_dedicated_bucket = true`) | `string` | — | yes |
| `s3_bucket_region` | Region of the S3 bucket for CUR report storage. The dedicated bucket falls back to the provider region — its real location by construction | `string` | `""` | with an external bucket (`enable_dedicated_bucket = false`) |
| `enable_dedicated_bucket` | Create a dedicated S3 bucket for CUR reports instead of using the central log bucket | `bool` | `false` | no |
| `kms_key_administrators` | ARNs for KMS key administration on the dedicated CUR bucket | `list(string)` | `[]` | no |
| `force_destroy` | Allow destruction of S3 buckets with content (for test environments only) | `bool` | `false` | no |
| `abort_incomplete_multipart_upload_days` | Days after which incomplete multipart uploads are aborted | `number` | `7` | no |
| `noncurrent_version_expiration_days` | Days after which noncurrent object versions expire | `number` | `365` | no |

## Report attributes

`cur_config` describes the report definition. Beside name, prefix, time unit,
format, compression and the schema elements it carries three delivery
attributes:

| Attribute | Type | Default | Meaning |
|---|---|---|---|
| `additional_artifacts` | `list(string)` | `null` | Manifests for downstream consumers: `REDSHIFT`, `QUICKSIGHT` or `ATHENA`. Unset requests none |
| `report_versioning` | `string` | `"OVERWRITE_REPORT"` | `OVERWRITE_REPORT` replaces the report on each delivery, `CREATE_NEW_REPORT` keeps every version |
| `refresh_closed_reports` | `bool` | `null` | Whether AWS refreshes reports after a billing period closed (detected refunds, credits). Unset keeps the API default |

`ATHENA` travels alone and requires the Parquet format pair and
`OVERWRITE_REPORT` versioning; the plan rejects every other combination, as the
API would.

## Lifecycle rule set

`cur_bucket_lifecycle_rules` takes the full rule shape of the log and security
buckets, so a rule reads the same wherever it is written. Each entry is one S3
lifecycle rule:

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

- **`null` keeps what the module did:** the single rule derived from the
  365-day expiration, `noncurrent_version_expiration_days` and
  `abort_incomplete_multipart_upload_days`.
- **An empty list removes every rule.** `[]` is the deliberate "no lifecycle"
  and is distinct from `null`.
- **A rule set replaces, it does not join.** Once given, it is the whole
  lifecycle of the bucket; the derived rule falls away.

The rule set applies to the dedicated bucket only
(`enable_dedicated_bucket = true`). The central log bucket belongs to the
logging module and carries its lifecycle there.

```hcl
cur_bucket_lifecycle_rules = [
  {
    id              = "reports-archive"
    expiration_days = 730
    transitions     = [{ storage_class = "DEEP_ARCHIVE", days = 180 }]
  },
]
```

## Outputs

| Name | Description |
|------|-------------|
| `cur_report_name` | Name of the Cost and Usage Report (empty when CUR is disabled) |
| `cur_bucket_name` | Name of the dedicated CUR S3 bucket (empty when dedicated bucket is disabled) |
| `cur_bucket_arn` | ARN of the dedicated CUR S3 bucket (empty when dedicated bucket is disabled) |
| `cur_kms_key_arn` | ARN of the KMS key for the dedicated CUR bucket (empty when dedicated bucket is disabled) |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_kms_key`
- `aws_kms_alias`
- `aws_s3_bucket`
- `aws_s3_bucket_versioning`
- `aws_s3_bucket_server_side_encryption_configuration`
- `aws_s3_bucket_public_access_block`
- `aws_s3_bucket_lifecycle_configuration`
- `aws_s3_bucket_policy`
- `aws_cur_report_definition`

## Usage Example

```hcl
module "cur" {
  source = "./modules/cur"

  enable_cost_and_usage_report = true
  s3_bucket_name               = module.logging.central_log_bucket_name
  # Required with an external bucket: the module cannot know where the
  # injected bucket lives, and CUR rejects a region mismatch.
  s3_bucket_region = "us-east-1"

  cur_config = {
    report_name          = "tlz-cost-usage-report"
    time_unit            = "DAILY"
    format               = "Parquet"
    compression          = "Parquet"
    additional_artifacts = ["ATHENA"]
  }
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
