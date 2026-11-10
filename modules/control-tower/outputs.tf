output "landing_zone_id" {
  description = "Control Tower Landing Zone ID"
  value       = aws_controltower_landing_zone.this.id
}

output "landing_zone_arn" {
  description = "Control Tower Landing Zone ARN"
  value       = aws_controltower_landing_zone.this.arn
}

output "drift_status" {
  description = "Control Tower Drift Status"
  value       = aws_controltower_landing_zone.this.drift_status
}

output "control_tower_control_count" {
  description = "Number of Control Tower controls (guardrails) enabled"
  value       = length(aws_controltower_control.this)
}
