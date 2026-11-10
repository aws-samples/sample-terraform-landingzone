output "accounts" {
  description = "Map of email to account details"
  value = {
    for email, acct in aws_organizations_account.this : email => {
      id        = acct.id
      arn       = acct.arn
      name      = acct.name
      email     = acct.email
      parent_id = acct.parent_id
      status    = acct.state
    }
  }
}

output "account_ids" {
  description = "Map of account name to account ID"
  value = {
    for email, acct in aws_organizations_account.this :
    acct.name => acct.id
  }
}

output "sso_assignments" {
  # The output enumerates the assignment resources themselves,
  # so it carries exactly the condition the resources carry — the
  # per-account entries (keyed by email) exist only behind
  # local.sso_assignment_enabled, the identity_center_assignments entries
  # (keyed by principal/permission set/account) only while Identity Center
  # is provisioned.
  description = "Map of all planned SSO assignments: per-account entries keyed by email, identity_center_assignments entries keyed by principal/permission set/account (empty while the respective gate is off)"
  value = merge(
    {
      for email, assignment in aws_ssoadmin_account_assignment.this : email => {
        account_id         = assignment.target_id
        permission_set_arn = assignment.permission_set_arn
        principal_type     = assignment.principal_type
        principal_id       = assignment.principal_id
      }
    },
    {
      for email, assignment in aws_ssoadmin_account_assignment.user : email => {
        account_id         = assignment.target_id
        permission_set_arn = assignment.permission_set_arn
        principal_type     = assignment.principal_type
        principal_id       = assignment.principal_id
        sso_user_name      = aws_identitystore_user.this[email].user_name
      }
    },
    {
      for key, assignment in aws_ssoadmin_account_assignment.ic : key => {
        account_id         = assignment.target_id
        permission_set_arn = assignment.permission_set_arn
        principal_type     = assignment.principal_type
        principal_id       = assignment.principal_id
      }
    },
  )
}

output "sso_users" {
  description = "Map of email to created IAM Identity Center users (AFT-style)"
  value = {
    for email, user in aws_identitystore_user.this : email => {
      user_id      = user.user_id
      user_name    = user.user_name
      display_name = user.display_name
    }
  }
}

# --- Identity Center Permission Set ARNs ---

output "permission_set_arns" {
  description = "Map of permission set name to ARN"
  value = {
    for name, ps in aws_ssoadmin_permission_set.ic : name => ps.arn
  }
}

# --- Warm Account IDs ---

output "warm_account_ids" {
  description = "List of account IDs marked as warm/standby — these skip security and networking configuration"
  value       = local.warm_account_ids
}

output "warm_account_names" {
  description = "List of account names marked as warm/standby — these skip security and networking configuration"
  value = var.enable_account_warming ? [
    for email, acct in aws_organizations_account.this :
    acct.name
    if try(local.resolved_accounts[email].warm, false)
  ] : []
}

# --- Active Accounts (deployment targets) ---
# Warm accounts are created in AWS Organizations but skip security and
# networking configuration. Downstream stacks read these filtered pendants
# as their deployment targets instead of the raw maps above. While
# enable_account_warming is false, warm_account_names is empty, so both
# pendants are identical to the raw outputs (zero-diff).

output "active_account_ids" {
  description = "Map of account name to account ID excluding warm accounts — the deployment targets for downstream stacks"
  value = {
    for email, acct in aws_organizations_account.this :
    acct.name => acct.id
    if !contains(local.warm_account_names, acct.name)
  }
}

output "active_account_ou_ids" {
  description = "Map of account name to its OU (parent) ID excluding warm accounts — OU-resolved deployment targets for downstream stacks"
  value = {
    for email, acct in aws_organizations_account.this :
    acct.name => acct.parent_id
    if !contains(local.warm_account_names, acct.name)
  }
}
