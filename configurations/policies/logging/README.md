# Logging Policies

IAM policies, trust policies, KMS key policies, and S3 bucket policies for the centralized logging infrastructure including CloudTrail, Config, Kinesis, Firehose, S3 replication, and VPC flow logs.

| File | Description |
|------|-------------|
| `cloudtrail-cloudwatch-policy.json` | IAM policy allowing CloudTrail to write log events to CloudWatch Logs |
| `cloudtrail-cloudwatch-trust-policy.json` | Trust policy allowing CloudTrail service to assume the CloudWatch delivery role |
| `config-aggregator-trust-policy.json` | Trust policy allowing AWS Config service to assume the aggregator role |
| `cw-to-kinesis-policy.json` | IAM policy allowing CloudWatch Logs to put records into Kinesis streams |
| `cw-to-kinesis-trust-policy.json` | Trust policy allowing CloudWatch Logs service to assume the Kinesis delivery role |
| `firehose-delivery-policy.json` | IAM policy for Firehose to deliver to S3, read from Kinesis, and use KMS |
| `firehose-delivery-trust-policy.json` | Trust policy allowing Firehose service to assume the delivery role |
| `kms-cloudwatch-key-policy.json` | KMS key policy granting CloudWatch Logs encrypt/decrypt access |
| `kms-key-administrators-statement.json` | KMS policy statement granting key administration permissions to specified principals |
| `kms-log-bucket-key-policy.json` | KMS key policy for the central log bucket (CloudTrail, Config, CloudWatch, Kinesis, Firehose, GuardDuty, log delivery for VPC flow logs and other vended logs) |
| `kms-management-key-policy.json` | KMS key policy granting full access to the management account root |
| `kms-per-account-s3-key-policy.json` | KMS key policy granting S3 service encrypt/decrypt access for per-account keys |
| `kms-replication-dest-key-policy.json` | KMS key policy for the replication destination (S3 replication role, CloudTrail, Config) |
| `s3-access-logs-bucket-policy.json` | S3 bucket policy allowing S3 log delivery service to write access logs |
| `s3-central-logs-bucket-policy.json` | S3 bucket policy for the central logging bucket (CloudTrail, Config, GuardDuty, Macie, CUR delivery, log delivery for VPC flow logs and other vended logs) |
| `s3-elb-logs-bucket-policy.json` | S3 bucket policy allowing ELB log delivery service to write load balancer logs |
| `s3-replication-dest-bucket-policy.json` | S3 bucket policy allowing cross-region replication writes to the destination bucket |
| `s3-replication-policy.json` | IAM policy for S3 replication role (source read, destination write, KMS decrypt/encrypt) |
| `s3-replication-trust-policy.json` | Trust policy allowing S3 service to assume the replication role |
| `s3-vpc-flow-logs-bucket-policy.json` | S3 bucket policy allowing VPC flow log delivery service to write flow logs |
| `sns-cloudtrail-topic-policy.json` | SNS topic policy allowing CloudTrail to publish trail notifications |
| `vpc-flow-logs-replication-policy.json` | IAM policy for VPC flow logs S3 replication (source read, destination write, KMS) |
| `vpc-flow-logs-replication-trust-policy.json` | Trust policy allowing S3 service to assume the VPC flow logs replication role |
