output "ou_name_to_id" {
  description = "Map of OU name to OU ID (all levels)"
  value       = local.ou_name_to_id
}

output "scp_ids" {
  description = "Map of SCP name to SCP ID"
  value = {
    for name, policy in aws_organizations_policy.scp :
    name => policy.id
  }
}

output "quarantine_scp_id" {
  description = "ID of the Quarantine SCP (empty if disabled)"
  value       = var.enable_quarantine_scp ? aws_organizations_policy.quarantine[0].id : ""
}

# --- Ignored OU IDs ---

output "ignored_ou_ids" {
  description = "List of OU IDs marked with ignore = true, excluded from policy attachments"
  value       = local.ignored_ou_ids
}

# --- Chatbot Policy IDs ---

output "chatbot_policy_ids" {
  description = "Map of Chatbot Policy name to policy ID"
  value = {
    for name, policy in aws_organizations_policy.chatbot :
    name => policy.id
  }
}

# --- Account Move Automation ---

output "account_move_lambda_arn" {
  description = "ARN of the account move Lambda function (empty string when disabled)"
  value       = try(aws_lambda_function.account_move[0].arn, "")
}

# --- SCP Revert Detection (G4) ---

output "scp_revert_sns_topic_arn" {
  description = "ARN of the SNS topic for SCP revert detection notifications (empty if disabled)"
  value       = var.enable_scp_revert_detection ? aws_sns_topic.scp_revert[0].arn : ""
}

output "scp_auto_revert_lambda_arn" {
  description = "ARN of the SCP auto-revert Lambda function."
  value       = try(aws_lambda_function.scp_auto_revert[0].arn, null)
}

# --- Organization-Level Outputs (consumed by dependent Terragrunt stacks) ---

output "organization_id" {
  description = "ID of the AWS Organization"
  value       = local.organization_id
}

output "rcp_documents_unresolved" {
  description = "Resource control policies left out for an unresolved @@marker@@ and therefore not created. Empty once import_organization_id and log_archive_account_id are set."
  value       = var.unresolved_resource_control_policies
}

output "org_root_id" {
  description = "Root ID of the AWS Organization"
  value       = local.resolved_root_id
}

output "partition" {
  description = "AWS partition (e.g. aws, aws-cn, aws-us-gov)"
  value       = local.partition
}

output "dns_suffix" {
  description = "DNS suffix for the current partition (e.g. amazonaws.com)"
  value       = local.dns_suffix
}

output "master_account_id" {
  description = "Account ID of the AWS Organizations management account"
  value       = local.master_account_id
}
