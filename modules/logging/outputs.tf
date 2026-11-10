output "cloudtrail_arn" {
  description = "ARN of the organization-wide CloudTrail trail"
  value       = aws_cloudtrail.org_trail.arn
}

output "central_log_bucket_arn" {
  description = "ARN of the central S3 log bucket"
  value       = aws_s3_bucket.central_logs.arn
}

output "central_log_bucket_name" {
  description = "Name of the central S3 log bucket"
  value       = aws_s3_bucket.central_logs.id
}

output "config_aggregator_name" {
  description = "Name of the organization-wide Config aggregator"
  value       = aws_config_configuration_aggregator.org.name
}

output "log_retention_days" {
  description = "Configured S3 lifecycle retention in days"
  value       = var.log_retention_days
}

output "cloudwatch_log_group_retention" {
  description = "CloudWatch Log Group retention in days (null if no log group)"
  value       = length(aws_cloudwatch_log_group.cloudtrail) > 0 ? aws_cloudwatch_log_group.cloudtrail[0].retention_in_days : null
}

output "kms_key_arn" {
  description = "ARN of the KMS key for S3 bucket encryption"
  value       = aws_kms_key.log_bucket.arn
}

output "cloudtrail_s3_data_events" {
  description = "Whether S3 Data Events are enabled in CloudTrail"
  value       = var.cloudtrail_s3_data_events
}

output "cloudtrail_lambda_data_events" {
  description = "Whether Lambda Data Events are enabled in CloudTrail"
  value       = var.cloudtrail_lambda_data_events
}

output "cloudtrail_insights" {
  description = "List of enabled CloudTrail Insight types"
  value       = var.cloudtrail_insights
}

output "s3_lifecycle_rules" {
  description = "Configured S3 lifecycle rules per prefix (null if using default single-rule behavior)"
  value       = var.s3_lifecycle_rules
}

# --- S3 Replication Outputs ---

output "replication_dest_bucket_arn" {
  description = "ARN of the replication destination bucket (empty if replication is disabled)"
  value       = local.replication_dest_bucket_arn
}

output "replication_dest_kms_key_arn" {
  description = "ARN of the KMS key used for replication destination encryption (empty if replication is disabled)"
  value       = local.replication_dest_kms_key_arn
}

# --- Per-Account KMS Keys ---

output "per_account_s3_kms_key_arn" {
  description = "ARN of the per-account S3 KMS key (empty if enable_per_account_kms_keys is false)"
  value       = var.enable_per_account_kms_keys ? aws_kms_key.per_account_s3[0].arn : ""
}

output "access_logs_bucket_name" {
  description = "Name of the separate access logs bucket (empty if enable_separate_access_logs_bucket is false)"
  value       = var.enable_separate_access_logs_bucket ? aws_s3_bucket.access_logs[0].id : ""
}

# --- Kinesis Pipeline Outputs (Gap 3.33) ---

output "kinesis_stream_arn" {
  description = "ARN of the Kinesis Data Stream for CloudWatch-to-S3 replication (empty when pipeline is disabled)"
  value       = local.kinesis_pipeline_enabled ? aws_kinesis_stream.cw_to_s3[0].arn : ""
}


# --- ELB Log Bucket ---

output "elb_log_bucket_name" {
  description = "Name of the ELB log bucket (empty if disabled)"
  value       = var.enable_elb_log_bucket ? aws_s3_bucket.elb_logs[0].id : ""
}


# --- CloudTrail Lake ---

output "cloudtrail_lake_event_data_store_arn" {
  description = "ARN of the CloudTrail Lake event data store (empty if disabled)"
  value       = var.enable_cloudtrail_lake ? aws_cloudtrail_event_data_store.this[0].arn : ""
}

# --- VPC Flow Logs Bucket ---

output "vpc_flow_logs_bucket_arn" {
  description = "ARN of the VPC flow logs dedicated bucket (empty if disabled)"
  value       = var.enable_vpc_flow_logs_bucket ? aws_s3_bucket.vpc_flow_logs[0].arn : ""
}
