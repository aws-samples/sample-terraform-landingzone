# Module Reference

Each module is self-contained under `modules/` with its own README, inputs, outputs, resources, and usage example. The `Resources` section of a module README lists the resource types the module declares, so what a module creates can be read without opening its `.tf` files; modules split across several files group the list by file.

| Module | Description |
|--------|-------------|
| [accounts](../../modules/accounts/README.md) | Creates AWS Organizations member accounts with optional IAM Identity Center (SSO) integration and OU placement |
| [backup](../../modules/backup/README.md) | Creates AWS Backup Vaults with optional cross-account access policies and KMS encryption |
| [bootstrap](../../modules/bootstrap/README.md) | Creates S3 bucket and DynamoDB table for Terraform remote state with optional KMS encryption |
| [budgets](../../modules/budgets/README.md) | Creates AWS Budgets for cost monitoring and alerting in the Management Account |
| [config-recorder-member](../../modules/config-recorder-member/README.md) | Creates an AWS Config Recorder and Delivery Channel for a single member account |
| [config-rules](../../modules/config-rules/README.md) | Organization-wide deployment of AWS Config Managed Rules, Custom Rules, Conformance Packs, and auto-remediation |
| [control-tower](../../modules/control-tower/README.md) | Creates and manages an AWS Control Tower Landing Zone with service roles and optional guardrails |
| [cur](../../modules/cur/README.md) | Creates an AWS Cost and Usage Report with optional S3 bucket and KMS encryption |
| [deployment-role](../../modules/deployment-role/README.md) | Creates the TLZDeploymentRole IAM role for cross-account Terraform operations |
| [ec2-compute](../../modules/ec2-compute/README.md) | EC2 building blocks for firewall appliances and workload compute: launch templates, auto-scaling groups, single instances, SSM documents and associations |
| [iam](../../modules/iam/README.md) | Baseline IAM roles, SAML identity providers, and customer-managed policies |
| [logging](../../modules/logging/README.md) | Centralized logging: org-wide CloudTrail, Config recorder/aggregator, and KMS-encrypted S3 bucket |
| [monitoring](../../modules/monitoring/README.md) | CloudWatch Dashboards, SNS Alerting, and EventBridge rules for landing zone observability |
| [networking](../../modules/networking/README.md) | VPCs, Subnets, NAT Gateways, Transit Gateway, Route 53, Network Firewall, IPAM, and Flow Logs |
| [organization](../../modules/organization/README.md) | Manages OUs, SCPs, Tag Policies, Backup Policies, and Delegated Administrator in AWS Organizations |
| [pipeline](../../modules/pipeline/README.md) | Creates the TLZPipelineRole with cross-account permissions for CodePipeline, ECS, or external CI |
| [security](../../modules/security/README.md) | Organization-wide GuardDuty, Security Hub, Macie, Access Analyzer, and IAM password policy |
| [security-org-config](../../modules/security-org-config/README.md) | Org-wide security service enablement from the Audit account (delegated admin) |
| [service-catalog](../../modules/service-catalog/README.md) | Service Catalog portfolios with products, launch constraints, and org-wide sharing |
| [service-quotas](../../modules/service-quotas/README.md) | Manages AWS Service Quota increase requests in the Management Account |
| [ssm-parameters](../../modules/ssm-parameters/README.md) | Creates SSM parameters for cross-account configuration sharing |

For detailed variable reference across all modules, see [Configuration Reference](../configuration-reference.md).
