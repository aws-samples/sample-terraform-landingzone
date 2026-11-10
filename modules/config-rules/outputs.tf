# Config rules module outputs

output "rule_arns" {
  description = "Map of rule name to rule ARN (managed and custom rules)"
  value = merge(
    { for name, rule in aws_config_organization_managed_rule.this : name => rule.arn },
    { for name, rule in aws_config_organization_custom_rule.this : name => rule.arn },
  )
}

output "conformance_pack_arns" {
  description = "Map of conformance pack name to pack ARN"
  value = {
    for name, pack in aws_config_organization_conformance_pack.this : name => pack.arn
  }
}

output "managed_rule_count" {
  description = "Number of managed rules created"
  value       = length(aws_config_organization_managed_rule.this)
}

output "custom_rule_count" {
  description = "Number of custom rules created"
  value       = length(aws_config_organization_custom_rule.this)
}

output "conformance_pack_count" {
  description = "Number of conformance packs created"
  value       = length(aws_config_organization_conformance_pack.this)
}

output "remediation_count" {
  description = "Number of automatic remediations configured"
  value       = length(aws_config_remediation_configuration.this)
}
