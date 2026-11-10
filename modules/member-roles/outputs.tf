output "role_arns" {
  description = "Map of role name to role ARN for the roles created in this account"
  value       = { for name, role in aws_iam_role.this : name => role.arn }
}

output "policy_arns" {
  description = "Map of policy name to policy ARN for the customer-managed policies created in this account"
  value       = { for name, policy in aws_iam_policy.this : name => policy.arn }
}

output "instance_profile_names" {
  description = "Names of the instance profiles created in this account"
  value       = [for profile in aws_iam_instance_profile.this : profile.name]
}
