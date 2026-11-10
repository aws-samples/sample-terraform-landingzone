# Pipeline Module — Outputs

output "pipeline_role_arn" {
  description = "ARN of the Pipeline Role in the Deployment Account"
  value       = aws_iam_role.pipeline.arn
}

output "pipeline_role_name" {
  description = "Name of the Pipeline Role in the Deployment Account"
  value       = aws_iam_role.pipeline.name
}

output "oidc_role_arn" {
  description = "ARN of the OIDC role for external CI (empty if pipeline_type is not external)"
  value       = var.pipeline_type == "external" ? aws_iam_role.oidc[0].arn : ""
}
