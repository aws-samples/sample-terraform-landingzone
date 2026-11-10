# General Policies

Cross-cutting policies that don't belong to a single domain, including the end-user permission boundary, SSM access, and VPC endpoint restrictions.

| File | Description |
|------|-------------|
| `end-user-policy.json` | Permission boundary for end-user roles: allows most actions, denies VPC/org changes, enforces boundary on role creation |
| `ssm-s3-policy.json` | IAM policy granting SSM agents read/write access to SSM-related S3 buckets |
| `vpc-endpoint-default-policy.json` | VPC endpoint policy restricting access to organization principals only; injected into the `endpoint_policies` entry `vpc-endpoint-default-policy` and referenced by endpoints through `policy_name` |

The EventBridge default bus policy lives under `../monitoring/` — the
monitoring module renders it itself, because partition, region and account
are only known there.
