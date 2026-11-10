# Monitoring Policies

IAM policies, trust policies, KMS key policies, and resource policies for EventBridge, SNS alerting, Security Hub event logging, and the SNS forwarder Lambda.

| File | Description |
|------|-------------|
| `eventbridge-default-bus-policy.json` | EventBridge default bus policy allowing organization accounts to put events and rules |
| `securityhub-custom-rules-eventbridge-log-policy.json` | CloudWatch Logs resource policy allowing EventBridge to write Security Hub custom rule events |
| `securityhub-eventbridge-log-policy.json` | CloudWatch Logs resource policy allowing EventBridge to write Security Hub finding events |
| `sns-forwarder-kms-statement.json` | KMS policy statement granting decrypt/generate-data-key for the SNS forwarder Lambda |
| `sns-forwarder-policy.json` | IAM policy for the SNS forwarder Lambda (SNS publish, CloudWatch Logs) |
| `sns-forwarder-trust-policy.json` | Trust policy allowing Lambda service to assume the SNS forwarder role |
| `sns-kms-key-policy.json` | KMS key policy granting SNS service encrypt/decrypt access for topic encryption |
| `sns-topic-policy.json` | SNS topic policy allowing EventBridge to publish notifications |
