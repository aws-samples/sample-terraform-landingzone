# =============================================================================
# IAM Account Password Policy
# =============================================================================

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.password_policy.minimum_length
  require_uppercase_characters   = var.password_policy.require_uppercase
  require_lowercase_characters   = var.password_policy.require_lowercase
  require_numbers                = var.password_policy.require_numbers
  require_symbols                = var.password_policy.require_symbols
  max_password_age               = var.password_policy.max_age
  password_reuse_prevention      = var.password_policy.password_reuse_prevention
  allow_users_to_change_password = var.password_policy.allow_users_to_change
  hard_expiry                    = var.password_policy.hard_expiry
}
