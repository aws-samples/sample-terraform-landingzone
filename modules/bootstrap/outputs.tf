# Bootstrap module outputs

output "state_bucket_arn" {
  description = "ARN of the S3 state bucket"
  value       = aws_s3_bucket.state.arn
}

output "lock_table_arn" {
  description = "ARN of the DynamoDB lock table"
  value       = aws_dynamodb_table.lock.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key (empty when no key is created)"
  value       = length(aws_kms_key.state) > 0 ? aws_kms_key.state[0].arn : ""
}
