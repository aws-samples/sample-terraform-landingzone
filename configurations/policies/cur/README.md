# CUR Policies

KMS key policy and S3 bucket policy for AWS Cost and Usage Report (CUR) delivery.

| File | Description |
|------|-------------|
| `kms-key-policy.json` | KMS key policy granting the billing reports service encrypt/decrypt access for CUR data |
| `s3-bucket-policy.json` | S3 bucket policy allowing the billing reports service to deliver CUR files and enforcing TLS |
