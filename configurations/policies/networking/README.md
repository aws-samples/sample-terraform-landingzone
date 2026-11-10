# Networking Policies

IAM policies and trust policies for VPC and Transit Gateway flow log delivery.

| File | Description |
|------|-------------|
| `tgw-flow-logs-policy.json` | IAM policy allowing Transit Gateway flow logs to write to CloudWatch Logs |
| `vpc-flow-logs-policy.json` | IAM policy allowing VPC flow logs to write to CloudWatch Logs |
| `vpc-flow-logs-trust-policy.json` | Trust policy allowing VPC flow logs service to assume the delivery role |
