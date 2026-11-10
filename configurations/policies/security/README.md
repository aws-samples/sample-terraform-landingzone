# Security Policies

IAM policies, trust policies, and KMS key policies for security services including GuardDuty, Network Firewall, Session Manager, and per-account encryption keys.

| File | Description |
|------|-------------|
| `firewall-config-reader-kms-policy.json` | IAM policy allowing the firewall config reader role to decrypt with KMS |
| `firewall-config-reader-s3-policy.json` | IAM policy allowing the firewall config reader role to read from S3 |
| `firewall-config-reader-trust-policy.json` | Trust policy allowing EC2 service to assume the firewall config reader role |
| `guardduty-malware-kms-policy.json` | IAM policy granting KMS access for GuardDuty malware protection scanning |
| `guardduty-malware-s3-policy.json` | IAM policy granting S3 access for GuardDuty malware protection scanning |
| `guardduty-malware-trust-policy.json` | Trust policy allowing GuardDuty malware protection service to assume the role |
| `lambda-encryption-kms-policy.json` | KMS key policy granting Lambda service encrypt/decrypt access |
| `per-account-cloudwatch-kms-policy.json` | KMS key policy granting CloudWatch Logs encrypt/decrypt access per account |
| `per-account-lambda-kms-policy.json` | KMS key policy granting Lambda service encrypt/decrypt access per account |
| `session-manager-ec2-policy.json` | IAM policy for EC2 Session Manager (SSM sessions, optional S3/CloudWatch/KMS logging) |
| `sns-eventbridge-kms-policy.json` | KMS key policy letting EventBridge publish to SNS topics encrypted with the key (GenerateDataKey*, Decrypt); used by the organization and pipeline modules |
| `sqs-kms-policy.json` | KMS key policy granting SQS service encrypt/decrypt access |
