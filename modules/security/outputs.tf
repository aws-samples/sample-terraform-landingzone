# Security module outputs

# --- EBS Default Encryption ---

output "ebs_default_kms_key_arn" {
  description = "KMS key ARN registered as the account-wide EBS default encryption key — the supplied ebs_default_kms_key_arn, or the module-managed key when none was supplied (empty if EBS default encryption is disabled)"
  value       = var.enable_ebs_default_encryption ? aws_ebs_default_kms_key.this[0].key_arn : ""
}

# --- S3 Account Public Access Block ---

output "guardduty_detector_id" {
  description = "GuardDuty detector ID (empty if GuardDuty disabled)"
  value       = var.enable_guardduty ? aws_guardduty_detector.this[0].id : ""
}

output "security_hub_arn" {
  description = "Security Hub ARN (empty if Security Hub disabled)"
  value       = var.enable_security_hub ? aws_securityhub_account.this[0].arn : ""
}

output "access_analyzer_arn" {
  description = "IAM Access Analyzer ARN (empty if Access Analyzer disabled)"
  value       = var.enable_access_analyzer ? aws_accessanalyzer_analyzer.this[0].arn : ""
}



# --- GuardDuty Export ---

output "guardduty_export_frequency" {
  description = "GuardDuty findings export frequency (empty if disabled)"
  value       = var.enable_guardduty && var.guardduty_export_frequency != null ? var.guardduty_export_frequency : ""
}


# --- Excluded Regions ---

output "guardduty_excluded_regions" {
  description = "List of regions where GuardDuty is excluded"
  value       = var.guardduty_excluded_regions
}

output "security_hub_excluded_regions" {
  description = "List of regions where Security Hub is excluded"
  value       = var.security_hub_excluded_regions
}

output "macie_excluded_regions" {
  description = "List of regions where Macie is excluded"
  value       = var.macie_excluded_regions
}

output "ebs_encryption_excluded_regions" {
  description = "List of regions where EBS default encryption is excluded"
  value       = var.ebs_encryption_excluded_regions
}

# --- S3 Public Access Block Excluded Accounts ---

output "s3_public_access_block_excluded_accounts" {
  description = "List of account IDs excluded from S3 public access block enforcement"
  value       = var.s3_public_access_block_excluded_accounts
}

# --- GuardDuty Export Prefix ---

output "guardduty_export_prefix" {
  description = "S3 prefix used for GuardDuty publishing destination"
  value       = var.guardduty_export_prefix
}

# --- Firewall Config S3 Bucket ---

output "firewall_config_bucket_name" {
  description = "Name of the firewall configuration S3 bucket"
  value       = try(aws_s3_bucket.firewall_config[0].id, "")
}

# --- Per-Account CloudWatch KMS Key ---

output "per_account_cloudwatch_kms_key_arn" {
  description = "ARN of the per-account KMS key for CloudWatch Logs encryption (empty if enable_per_account_kms_keys is disabled)"
  value       = var.enable_per_account_kms_keys ? aws_kms_key.per_account_cloudwatch[0].arn : ""
}
