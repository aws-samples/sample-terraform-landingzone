# Deployment Role Module — Outputs

output "role_arn" {
  description = "ARN of the TLZ Deployment Role"
  value       = aws_iam_role.deployment.arn
}

output "role_name" {
  description = "Name of the TLZ Deployment Role"
  value       = aws_iam_role.deployment.name
}
