# IAM Policies

IAM policies and trust policies for cross-account IAM resources including Managed AD secrets, Service Catalog propagation, and CloudFormation StackSet administration.

| File | Description |
|------|-------------|
| `mad-admin-secret-kms-key-policy.json` | KMS key policy allowing Secrets Manager to encrypt/decrypt Managed AD admin secrets, for callers of the key's own account through Secrets Manager in the key's region only |
| `mad-secret-access-policy.json` | IAM policy granting read access to Managed AD secrets in Secrets Manager |
| `service-catalog-propagation-policy.json` | IAM policy for Service Catalog portfolio propagation (share, associate, accept) |
| `service-catalog-propagation-trust-policy.json` | Trust policy allowing Service Catalog service to assume the propagation role |
| `stackset-admin-policy.json` | IAM policy allowing the StackSet admin role to assume the execution role in member accounts |
| `stackset-admin-trust-policy.json` | Trust policy allowing CloudFormation service to assume the StackSet admin role |
| `stackset-execution-trust-policy.json` | Trust policy allowing the management account StackSet admin role to assume the execution role |
