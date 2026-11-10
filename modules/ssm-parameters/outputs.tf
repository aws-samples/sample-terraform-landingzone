output "ssm_parameter_names" {
  description = "Map of SSM parameter names to their ARNs"
  value       = { for k, v in aws_ssm_parameter.this : k => v.name }
}
