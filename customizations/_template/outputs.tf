# ← Example outputs — replace or extend with your own outputs.
# Every output carries a description and returns a map or list keyed the same way
# as the resource it reports on (see the output convention in
# customizations/README.md).
output "parameter_arns" {
  description = "Map of SSM parameter names to their ARNs"
  value       = { for k, v in aws_ssm_parameter.this : k => v.arn }
}

output "account_role_parameter_arns" {
  description = "Map of account name to the ARN of the SSM parameter holding its deployment role ARN"
  value       = { for k, v in aws_ssm_parameter.account_role_arn : k => v.arn }
}
