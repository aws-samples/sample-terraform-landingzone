# Policy Files

Externalized JSON policy documents used by Terraform modules via `file()` and `templatefile()`. Policies are organized into 13 thematic subfolders by functional domain.

**Total: 94 JSON policy files**

## Subfolder Structure

| Subfolder | Files | Description |
|-----------|------:|-------------|
| [backup/](backup/README.md) | 2 | KMS key policy and vault access policy for AWS Backup |
| [bootstrap/](bootstrap/README.md) | 1 | KMS key policy for the bootstrap module |
| [control-tower/](control-tower/README.md) | 6 | IAM trust and inline policies for Control Tower admin and stackset roles |
| [cur/](cur/README.md) | 2 | KMS key policy and S3 bucket policy for Cost and Usage Reports |
| [deployment/](deployment/README.md) | 2 | IAM trust and inline policies for the cross-account deployment role |
| [general/](general/README.md) | 6 | Cross-cutting policies: permission boundary, remediation, SSM, EventBridge, VPC endpoints |
| [iam/](iam/README.md) | 7 | IAM policies for StackSets, Service Catalog propagation, and Managed AD secrets |
| [logging/](logging/README.md) | 23 | IAM, trust, KMS, and S3 policies for CloudTrail, Config, Kinesis, Firehose, and S3 replication |
| [monitoring/](monitoring/README.md) | 8 | SNS, EventBridge, and KMS policies for Security Hub forwarding and alerting |
| [networking/](networking/README.md) | 3 | IAM and trust policies for VPC flow logs and Transit Gateway flow logs |
| [organization/](organization/README.md) | 21 | SCPs, RCPs, tag policies, backup policies, declarative policies, and automation Lambda policies |
| [pipeline/](pipeline/README.md) | 2 | IAM trust and assume policies for the CI/CD pipeline role |
| [security/](security/README.md) | 11 | KMS, IAM, and trust policies for GuardDuty, Security Hub, Session Manager, and Lambda encryption |

## Naming Convention

Policy filenames follow the pattern `<concern>-policy.json` or `<concern>-trust-policy.json`. The subfolder names the domain, so a file name carries no domain prefix — for example, `logging/cloudtrail-cloudwatch-policy.json`.

Organization-level policies (SCPs, RCPs, tag policies, backup policies, declarative policies) keep their prefixed names under `organization/` since their prefixes (`tlz-*`, `org-*`, `s3-tag-*`) don't match the subfolder name.

## Usage

Terraform modules reference these files via relative paths:

```hcl
# From a module .tf file
file("${path.module}/../../configurations/policies/<subfolder>/<filename>.json")
```

The Terragrunt loader reads them via:

```hcl
# From configurations/loader.hcl
file("${local._policy_dir}/<subfolder>/<filename>.json")
```

See the [SCP guardrails documentation](organization/README-tlz-core-guardrails-1.md) for detailed statement-level analysis of the core SCPs.
