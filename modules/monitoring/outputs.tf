# Monitoring module outputs

output "dashboard_arn" {
  description = "CloudWatch Dashboard ARN"
  value       = aws_cloudwatch_dashboard.landing_zone.dashboard_arn
}

output "sns_topic_arn" {
  description = "SNS Topic ARN for landing zone alerts (empty when severity topics are used)"
  value       = length(aws_sns_topic.alerts) > 0 ? aws_sns_topic.alerts[0].arn : ""
}

output "severity_topic_arns" {
  description = "Map of severity level to SNS topic ARN (empty when using single-topic fallback)"
  value       = { for k, v in aws_sns_topic.severity : k => v.arn }
}

# --- CloudWatch Metric Filters ---

output "metric_filter_names" {
  description = "Map of metric filter name to filter name"
  value       = { for k, v in aws_cloudwatch_log_metric_filter.this : k => v.name }
}

# --- CloudWatch Alarms ---

output "alarm_arns" {
  description = "Map of alarm name to alarm ARN"
  value       = { for k, v in aws_cloudwatch_metric_alarm.this : k => v.arn }
}


# --- SNS KMS Key ---

output "sns_kms_key_arn" {
  description = "ARN of the dedicated SNS KMS key (empty when sns_kms_encryption is false)"
  value       = var.sns_kms_encryption ? aws_kms_key.sns[0].arn : ""
}

# --- SecurityHub Findings CloudWatch Forwarding ---

output "securityhub_findings_log_group_arn" {
  description = "ARN of the SecurityHub findings CloudWatch Log Group."
  value       = try(aws_cloudwatch_log_group.securityhub_findings[0].arn, null)
}

# --- SNS Cross-Account Forwarder Lambda ---

output "sns_forwarder_lambda_arn" {
  description = "ARN of the SNS forwarder Lambda function (empty when disabled)"
  value       = var.enable_sns_forwarder ? aws_lambda_function.sns_forwarder[0].arn : ""
}

output "sns_forwarder_logs_kms_key_arn" {
  description = "ARN of the KMS key encrypting the SNS forwarder Lambda's execution log group (empty when enable_sns_forwarder is false)"
  value       = var.enable_sns_forwarder ? aws_kms_key.sns_forwarder_logs[0].arn : ""
}
