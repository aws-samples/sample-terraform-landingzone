# Multi-Partition Support

Works in `aws` (Commercial/Global) and `aws-eusc` (European Sovereign Cloud) without code changes.

## How It Works

Every module that builds an ARN uses `data.aws_partition.current` for dynamic
partition detection:

```hcl
locals {
  partition  = data.aws_partition.current.partition    # "aws" or "aws-eusc"
  dns_suffix = data.aws_partition.current.dns_suffix   # "amazonaws.com" or "amazonaws.eu"
  arn_prefix = "arn:${local.partition}"
}
```

Three modules build no ARN and therefore carry no `data "aws_partition"` block:
`budgets`, `ssm-parameters` and `service-quotas`. `modules/service-catalog`
builds no ARN either, but carries the block for its partition guard (the service
is not available in `aws-eusc`, see the table below).

No hardcoded `"arn:aws:"` or `"arn:aws-eusc:"` strings in the reusable code
(`modules/`, `stacks/`, `configurations/`, `customizations/`). Policy documents
handed to AWS verbatim cannot use a Terraform expression; they carry a
`@@partition@@` marker that the configuration loader replaces with the
configured partition. ARN validation rules accept every AWS partition including
`aws-eusc`.

Values you supply yourself in `env/common.hcl` stay partition-neutral as well:
Control Tower controls and AWS managed policies are configured as plain names
(`CONFIG.CLOUDTRAIL.DT.5`, `AmazonSSMManagedInstanceCore`) and the receiving
module builds the ARN from the current partition — a full ARN is passed
through unchanged. Service principals in embedded trust policies take their
DNS suffix from `local.dns_suffix`, which the file derives from the partition.

## Service Availability

The table covers every AWS service this landing zone provisions. Unless a row
says otherwise, the `aws-eusc` statement is sourced from the official AWS
Services by Region data for `eusc-de-east-1`
(<https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/>,
read through the JSON data feed behind that page,
retrieved 2026-08-31). Marks: ✅ available, ❌ not available, ❓ unconfirmed
(the named sources carry no statement for the service; the row explains why).

| Service | `aws` | `aws-eusc` | Behavior |
|---|:---:|:---:|---|
| AWS Organizations | ✅ | ✅ | Full support |
| AWS Account Management (region opt-in) | ✅ | ❓ | The region data feed does not track the account-management API behind `aws_account_region`. No confirmed statement; a failure surfaces at the provider. |
| AWS Control Tower | ✅ | ✅ | Full support |
| AWS Config | ✅ | ✅ | Full support |
| AWS CloudTrail | ✅ | ✅ | Full support |
| Amazon CloudWatch (metrics, logs, alarms, dashboards) | ✅ | ✅ | Full support |
| Amazon EventBridge | ✅ | ✅ | Full support |
| Amazon GuardDuty | ✅ | ✅ | Full support |
| AWS Security Hub | ✅ | ✅ | Full support |
| Macie | ✅ | ❌ | Automatically skipped. Not tracked in the region data feed and never on the initial-services roadmap (AWS Security Blog "Announcing initial services available in the AWS European Sovereign Cloud", GA note 2026-01-15). |
| Detective | ✅ | ❌ | Automatically skipped. The region data feed lists Detective in 23 regions; `eusc-de-east-1` is not among them. |
| Audit Manager | ✅ | ❌ | Automatically skipped. The region data feed lists Audit Manager in 12 regions; `eusc-de-east-1` is not among them. |
| Firewall Manager | ✅ | ❌ | Automatically skipped. The region data feed lists Firewall Manager in 36 regions without `eusc-de-east-1`; the roadmap update of 2025-06-25 removed it from the initial services list. |
| IAM Access Analyzer | ✅ | ✅ | Full support |
| AWS IAM | ✅ | ✅ | Full support |
| AWS IAM Identity Center | ✅ | ✅ | Available per the region data feed. The configuration loader still excludes the `sso.<dns_suffix>` service access principal in `aws-eusc` (a conservative filter from the pre-GA roadmap); the `modules/accounts` resources follow the Identity Center instance lookup and deploy where an instance exists. |
| AWS Directory Service (Managed AD, AD Connector) | ✅ | ✅ | Full support |
| AWS KMS | ✅ | ✅ | Full support |
| AWS Secrets Manager | ✅ | ✅ | Full support |
| Amazon S3 | ✅ | ✅ | Full support |
| Amazon DynamoDB | ✅ | ✅ | Full support |
| AWS Backup | ✅ | ✅ | Full support |
| AWS Budgets | ✅ | ❓ | The region data feed does not track billing services. The initial-services roadmap named AWS Budgets; no per-region confirmation exists. |
| Cost and Usage Report | ✅ | ❓ | The region data feed does not track billing services and the roadmap did not name CUR. The report definition additionally requires the `us-east-1` billing region, which does not exist in `aws-eusc`; the module skips and warns (`check "cur_eusc_warning"`). |
| Amazon EC2 (incl. Auto Scaling, launch templates, EBS default encryption) | ✅ | ✅ | Full support |
| Amazon ECS | ✅ | ✅ | Full support (ECS pipeline variant) |
| Amazon VPC (subnets, endpoints, flow logs, NACLs, peering) | ✅ | ✅ | Full support |
| VPC IPAM | ✅ | ❓ | The region data feed does not track IPAM as its own service. No confirmed statement; a failure surfaces at the provider. |
| AWS Transit Gateway | ✅ | ✅ | Full support |
| AWS Direct Connect | ✅ | ✅ | Full support |
| AWS Site-to-Site VPN | ✅ | ✅ | Full support |
| Network Firewall | ✅ | ✅ | Full support |
| Amazon Route 53 (zones, records, resolver endpoints) | ✅ | ✅ | Full support |
| Route 53 Resolver DNS Firewall | ✅ | ❓ | The region data feed lists resolver endpoints but does not track the DNS Firewall feature separately. No confirmed statement; a failure surfaces at the provider. |
| Elastic Load Balancing | ✅ | ✅ | Full support |
| AWS Certificate Manager | ✅ | ✅ | Full support |
| AWS RAM | ✅ | ✅ | Full support |
| AWS Lambda | ✅ | ✅ | Full support |
| Amazon SNS | ✅ | ✅ | Full support |
| Amazon SQS | ✅ | ✅ | Full support |
| AWS Systems Manager | ✅ | ✅ | Full support |
| Amazon Kinesis Data Streams | ✅ | ✅ | Full support |
| Amazon Data Firehose | ✅ | ✅ | Full support |
| Service Catalog | ✅ | ❌ | Automatically skipped. The region data feed lists Service Catalog in 32 regions; `eusc-de-east-1` is not among them. |
| Service Quotas | ✅ | ✅ | Full support |
| CodePipeline | ✅ | ❌ | Automatically skipped. The region data feed lists CodePipeline in 32 regions; `eusc-de-east-1` is not among them. Use the `ecs` or `external` pipeline type in `aws-eusc`. |
| CodeBuild | ✅ | ❌ | Automatically skipped. The region data feed lists CodeBuild in 33 regions; `eusc-de-east-1` is not among them. Use the `ecs` or `external` pipeline type in `aws-eusc`. |

Every service marked ❌ follows the same pattern: the owning module gates the
resources on the detected partition and a `check` block issues a warning when
the service is requested in `aws-eusc`, so the skip is never silent. When
`enable_macie = true` in `aws-eusc`, a `check` block issues a warning and all
Macie resources are skipped; Detective, Audit Manager, Firewall Manager,
Service Catalog and the CodePipeline variant of the pipeline module behave the
same way.

## Region Formats

| Partition | Format | Examples |
|---|---|---|
| `aws` | `xx-xxxx-N` | `eu-central-1`, `us-east-1` |
| `aws-eusc` | `eusc-xx-xxxx-N` | `eusc-de-east-1` |

## Configuration

```hcl
# env/common.hcl
region = "eusc-de-east-1"
```

The partition is derived from the region prefix (`eusc-*` regions belong to
`aws-eusc`, every other region to `aws`) — there is no second value to keep in
sync. All other settings remain identical.

## Further reading

- [Compliance Configurations](compliance-configurations.md) — Framework-specific configurations and multi-partition handling
- [Configuration Reference](configuration-reference.md) — Full variable reference with types, defaults and validations
- [Architecture](architecture.md) — Module design, dependency graph and design decisions
