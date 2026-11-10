output "backup_vault_names" {
  description = "List of created backup vault names"
  value       = [for v in aws_backup_vault.this : v.name]
}

output "backup_vault_arns" {
  description = "Map of backup vault names to their ARNs"
  value       = { for k, v in aws_backup_vault.this : k => v.arn }
}
