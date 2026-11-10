output "cur_report_name" {
  description = "Name of the Cost and Usage Report (empty string when CUR is disabled)"
  value       = local.cur_enabled ? aws_cur_report_definition.this["this"].report_name : ""
}

output "cur_bucket_name" {
  description = "Name of the dedicated CUR S3 bucket (empty when dedicated bucket is disabled)"
  value       = local.bucket_enabled ? aws_s3_bucket.cur[0].id : ""
}

output "cur_bucket_arn" {
  description = "ARN of the dedicated CUR S3 bucket (empty when dedicated bucket is disabled)"
  value       = local.bucket_enabled ? aws_s3_bucket.cur[0].arn : ""
}

output "cur_kms_key_arn" {
  description = "ARN of the KMS key for the dedicated CUR bucket (empty when dedicated bucket is disabled)"
  value       = local.bucket_enabled ? aws_kms_key.cur[0].arn : ""
}
