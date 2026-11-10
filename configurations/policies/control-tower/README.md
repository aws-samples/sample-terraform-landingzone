# Control Tower Policies

IAM inline policies and trust policies for AWS Control Tower roles including the admin role, CloudTrail integration, Config aggregator, and StackSet execution.

| File | Description |
|------|-------------|
| `admin-inline-policy.json` | Inline policy for the Control Tower admin role (EC2 DescribeAvailabilityZones) |
| `admin-trust-policy.json` | Trust policy allowing Control Tower service to assume the admin role |
| `cloudtrail-trust-policy.json` | Trust policy allowing CloudTrail service to assume the Control Tower CloudTrail role |
| `config-aggregator-trust-policy.json` | Trust policy allowing AWS Config service to assume the aggregator role |
| `stackset-inline-policy.json` | Inline policy allowing the StackSet role to assume AWSControlTowerExecution in member accounts |
| `stackset-trust-policy.json` | Trust policy allowing the management account and CloudFormation to assume the StackSet role |
