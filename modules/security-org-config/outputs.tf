output "guardduty_detector_id" {
  description = "GuardDuty detector ID in the Audit account"
  value       = var.enable_guardduty ? aws_guardduty_detector.this[0].id : null
}

output "guardduty_org_configuration_id" {
  description = "GuardDuty organization configuration ID"
  value       = var.enable_guardduty ? aws_guardduty_organization_configuration.this[0].id : null
}

output "security_hub_enabled" {
  description = "Whether Security Hub org configuration is enabled"
  value       = var.enable_security_hub
}

output "macie_enabled" {
  description = "Whether Macie org configuration is enabled (false in EUSC)"
  value       = var.enable_macie && !local.is_eusc
}

output "detective_graph_arn" {
  description = "Detective graph ARN in the Audit account (null in EUSC)"
  value       = var.enable_detective && !local.is_eusc ? aws_detective_graph.this[0].graph_arn : null
}

output "guardduty_publishing_destination_arn" {
  description = "S3 destination ARN of the GuardDuty findings export of the administrator (null without an export)"
  value       = length(aws_guardduty_publishing_destination.this) > 0 ? aws_guardduty_publishing_destination.this[0].destination_arn : null
}

output "security_hub_aggregator_arn" {
  description = "ARN of the Security Hub finding aggregator of the administrator (null without aggregation)"
  value       = length(aws_securityhub_finding_aggregator.this) > 0 ? aws_securityhub_finding_aggregator.this[0].arn : null
}

output "security_hub_member_ids" {
  description = "Account ids enrolled as Security Hub members of this administrator"
  value       = sort(keys(aws_securityhub_member.this))
}
