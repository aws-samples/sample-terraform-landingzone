# Organization Policies

Organization-level policies including Service Control Policies (SCPs), Resource Control Policies (RCPs), tag policies, backup policies, declarative policies, and automation Lambda policies.

| File | Description |
|------|-------------|
| `account-move-logs-policy.json` | CloudWatch Logs permissions for the account-move Lambda function |
| `account-move-orgs-policy.json` | Organizations permissions for the account-move Lambda (MoveAccount, DescribeAccount) |
| `lambda-trust-policy.json` | Trust policy allowing Lambda service to assume organization automation roles |
| `org-tag-policy.json` | Organization tag policy enforcing allowed values for the BackupPlan tag |
| `pipeline-scp.json` | SCP protecting pipeline and deployment IAM roles from modification |
| `primary-backup-plan.json` | Organization backup policy defining Continuous, Hourly, Daily, Weekly, and Monthly backup plans. Every selection runs as `Backup-Role` in the member account; no stack creates that role in a member account (see [IAM module, Deployment Targets](../../../modules/iam/README.md#deployment-targets)), so create it in each account of the target OUs before you attach the policy |
| `quarantine-auto-detach-policy.json` | IAM policy for the quarantine auto-detach Lambda (DetachPolicy, logging) |
| `s3-tag-policy.json` | S3-specific tag policy enforcing BackupPlan tag values on S3 buckets |
| `scp-auto-revert-policy.json` | IAM policy for the SCP auto-revert Lambda (UpdatePolicy, AttachPolicy, logging) |
| `sns-eventbridge-policy.json` | SNS topic policy allowing EventBridge to publish notifications |
| `tlz-core-guardrails-1.json` | SCP protecting Config rules, Lambda functions, SNS topics, log groups, Kinesis streams, and EventBridge rules |
| `tlz-core-guardrails-2.json` | SCP protecting IAM roles, CloudFormation stacks, SSM parameters, S3 buckets, and security services |
| `tlz-core-rcp-guardrails-1.json` | RCP denying external S3 writes, enforcing confused-deputy protection, secure transport, and KMS key protection |
| `tlz-core-security-guardrails-1.json` | SCP preventing modification of GuardDuty, Security Hub, Macie, Access Analyzer, and S3 bucket deletion |
| `tlz-infrastructure-guardrails-1.json` | SCP denying network infrastructure changes and root account usage for infrastructure OUs |
| `tlz-quarantine-guardrails.json` | SCP denying all actions except provisioning roles for quarantined accounts |
| `tlz-sandbox-guardrails-1.json` | SCP denying IAM user creation and CloudTrail modification in sandbox accounts |
| `tlz-suspended-guardrails.json` | SCP denying all actions for suspended accounts |
| `tlz-workloads-guardrails-1.json` | SCP for workload accounts: denying network changes, enforcing encryption for EFS, RDS, and Aurora |
| `vpc-block-public-access.json` | Declarative policy blocking bidirectional internet gateway access for VPCs |
