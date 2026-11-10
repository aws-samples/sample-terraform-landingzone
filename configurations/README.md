# Compliance Configurations

Modular, framework-specific compliance configuration files that feed into the Landing Zone's existing Terraform modules.

## Directory Structure

```
configurations/
├── README.md                          # This file
├── loader.hcl                         # Terragrunt merge engine
├── base/
│   └── base.tfvars                    # Security baseline (always applied)
├── frameworks/
│   ├── nist-800-53.tfvars
│   ├── hipaa.tfvars
│   ├── cmmc.tfvars
│   ├── fedramp-moderate.tfvars
│   ├── fedramp-high.tfvars
│   ├── c5-2020.tfvars
│   ├── iso-27001.tfvars
│   └── nist-800-171.tfvars
├── policies/                          # Organization policy JSON files (94 files)
│   ├── backup/                        # AWS Backup policies (2 files)
│   ├── bootstrap/                     # Bootstrap KMS policies (1 file)
│   ├── control-tower/                 # Control Tower IAM policies (6 files)
│   ├── cur/                           # Cost and Usage Report policies (2 files)
│   ├── deployment/                    # Deployment role policies (2 files)
│   ├── general/                       # Cross-cutting policies (6 files)
│   ├── iam/                           # IAM StackSets and Service Catalog policies (7 files)
│   ├── logging/                       # Centralized logging policies (23 files)
│   ├── monitoring/                    # SNS, EventBridge, alerting policies (8 files)
│   ├── networking/                    # VPC and TGW flow log policies (3 files)
│   ├── organization/                  # SCPs, RCPs, tag and backup policies (21 files)
│   ├── pipeline/                      # CI/CD pipeline role policies (2 files)
│   └── security/                      # GuardDuty, Security Hub, KMS policies (11 files)
└── ssm-documents/                     # SSM Automation documents
    ├── attach-instance-profile.json
    ├── enable-elb-logging.json
    └── resource-policy-enforcement.yaml
```

## How to Enable a Framework

Set `compliance_frameworks` in `env/common.hcl`:

```hcl
compliance_frameworks = ["nist-800-53"]
```

Enable several at once and the loader merges them: lists concatenate and are
deduplicated, numbers take the most restrictive value, booleans are OR-ed.

| Framework | File |
|---|---|
| NIST 800-53 | `nist-800-53.tfvars` |
| NIST 800-171 | `nist-800-171.tfvars` |
| HIPAA | `hipaa.tfvars` |
| CMMC | `cmmc.tfvars` |
| FedRAMP Moderate | `fedramp-moderate.tfvars` |
| FedRAMP High | `fedramp-high.tfvars` |
| BSI C5:2020 | `c5-2020.tfvars` |
| ISO 27001 | `iso-27001.tfvars` |

## Cost

Enabling a framework creates billable resources. The drivers, largest first:

| Driver | Billing model | Notes |
|---|---|---|
| Config Rules | Per rule evaluation, per account and region | The baseline alone carries 32 organization-wide rules; each framework adds more. This is normally the biggest line item |
| Conformance Packs | Per rule evaluation inside the pack | A pack is a bundle of rules and is billed like them |
| AWS Config recording | Per configuration item recorded | Scales with the number of resources, not with the number of frameworks |
| Security Hub | Per security check and per finding ingested | Each additional standard multiplies the check count. Two CIS versions side by side pay twice for the same weakness |
| KMS keys | Per key and month, plus API requests | Frameworks that define `kms_keys` add one key each |
| GuardDuty, Macie | Per volume analysed | Independent of the framework configuration, driven by account activity |

Two rules of thumb: cost grows with the number of enabled *regions* and member
accounts, not with the number of framework files; and the merge is a union, so
enabling three overlapping frameworks costs roughly as much as the largest of
them rather than three times as much.

Model your own numbers with the AWS Pricing Calculator before enabling a
framework across a whole organization.

## Migration

Switching or adding a framework is a configuration change, not a migration
project — edit `compliance_frameworks` and apply. What to expect:

1. **Adding a framework.** The merge only ever adds or tightens: new Config
   Rules appear, retention values may rise, booleans may flip from `false` to
   `true`. Nothing that another layer switched on gets switched off. Run
   `terragrunt run --all -- plan` first; the plan is the authoritative diff.
2. **Removing a framework.** Resources that only that framework contributed are
   destroyed. Check the plan for Config Rules and KMS keys before applying — a
   removed KMS key enters a 30-day waiting period.
3. **Replacing a framework.** Enable both, apply, then remove the old one. This
   avoids a window in which neither baseline is active.
4. **Values that cannot be lowered from `env/common.hcl`.** Retention numbers
   are merged with `max()` and booleans with OR, so the restrictive value wins.
   To relax one, change it in `configurations/base/base.tfvars`.

## Compliance Disclaimer

These configurations are a starting point aligned with common compliance
frameworks. They do **not** make your environment compliant, and enabling one is
not an attestation. Compliance requires organizational, procedural and technical
controls beyond anything an infrastructure tool can provide — evidence
collection, personnel training, physical security, incident response, vendor
management. Validating that a deployment meets a specific regulatory requirement
remains your responsibility.

## Further Documentation

- [Compliance Configurations](../docs/compliance-configurations.md) — Available frameworks, merge behavior, multi-partition handling, cost estimation, and shared responsibility
- [Configuration Reference](../docs/configuration-reference.md) — All variables, types, defaults, and validations
- [Policy Files Index](policies/README.md) — Full subfolder index with file counts and descriptions
