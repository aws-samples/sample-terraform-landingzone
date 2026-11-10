# Optional IAM Identity Center (SSO) integration.
# Two configuration paths, each behind its own gate:
# - Per-account assignments (accounts[].sso {} and AFT-compatible user
#   creation via accounts[].sso_user_email/first_name/last_name): the one
#   binding gate is local.sso_assignment_enabled — enable_sso_assignment
#   AND a provisioned Identity Center instance.
# - Identity Center permission sets and assignments
#   (identity_center_permission_sets / identity_center_assignments): gated
#   by the provisioned Identity Center instance alone.

locals {
  # Identity Center is needed when legacy SSO or new permission sets/assignments are configured
  identity_center_enabled = var.enable_sso_assignment || length(var.identity_center_permission_sets) > 0 || length(var.identity_center_assignments) > 0
}

data "aws_ssoadmin_instances" "this" {
  count = local.identity_center_enabled ? 1 : 0
}

locals {
  sso_instance_arn  = local.identity_center_enabled && length(try(data.aws_ssoadmin_instances.this[0].arns, [])) > 0 ? tolist(data.aws_ssoadmin_instances.this[0].arns)[0] : null
  identity_store_id = local.identity_center_enabled && length(try(data.aws_ssoadmin_instances.this[0].identity_store_ids, [])) > 0 ? tolist(data.aws_ssoadmin_instances.this[0].identity_store_ids)[0] : null

  # True only when Identity Center is both requested AND actually provisioned
  identity_center_available = local.sso_instance_arn != null

  # The one binding gate for the per-account assignment paths.
  # identity_center_enabled above only decides whether the instance lookup
  # runs; assignments are created solely when this gate is true.
  sso_assignment_enabled = var.enable_sso_assignment && local.identity_center_available

  # Accounts that need a new SSO user (AFT-style: sso_user_email is set)
  sso_create_users = local.sso_assignment_enabled ? {
    for email, acct in local.resolved_accounts : email => {
      user_email      = acct.sso_user_email
      user_first_name = acct.sso_user_first_name
      user_last_name  = acct.sso_user_last_name
      user_name       = acct.sso_user_email
    } if acct.sso_user_email != null
  } : {}

  # Accounts with explicit sso {} block (existing principal assignment).
  # coalesce rejects a call where every argument is null or empty; with the
  # module default sso_principal_name = "" an account without an sso block
  # would abort the plan. try() turns that case into the empty string,
  # which the if clause below already skips.
  sso_explicit = local.sso_assignment_enabled ? {
    for email, acct in local.resolved_accounts : email => {
      principal_type      = coalesce(try(acct.sso.principal_type, null), var.sso_principal_type)
      principal_name      = try(coalesce(try(acct.sso.principal_name, null), var.sso_principal_name), "")
      permission_set_name = coalesce(try(acct.sso.permission_set_name, null), var.sso_permission_set_name)
    } if acct.sso_user_email == null && try(coalesce(try(acct.sso.principal_name, null), var.sso_principal_name), "") != ""
  } : {}

  # Unique permission set names across both paths
  sso_permission_set_names = local.sso_assignment_enabled ? toset(concat(
    [for k, v in local.sso_explicit : v.permission_set_name],
    length(local.sso_create_users) > 0 ? [var.sso_permission_set_name] : [],
  )) : toset([])

  # Unique group/user names to look up (explicit assignments only)
  sso_group_names = local.sso_assignment_enabled ? toset([
    for k, v in local.sso_explicit : v.principal_name if v.principal_type == "GROUP"
  ]) : toset([])

  sso_user_names = local.sso_assignment_enabled ? toset([
    for k, v in local.sso_explicit : v.principal_name if v.principal_type == "USER"
  ]) : toset([])
}

# --- Data sources ---

data "aws_ssoadmin_permission_set" "this" {
  for_each     = local.sso_permission_set_names
  instance_arn = local.sso_instance_arn
  name         = each.value
}

data "aws_identitystore_group" "this" {
  for_each          = local.sso_group_names
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = each.value
    }
  }
}

data "aws_identitystore_user" "this" {
  for_each          = local.sso_user_names
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = each.value
    }
  }
}

# --- AFT-style: create SSO user per account ---

resource "aws_identitystore_user" "this" {
  for_each          = local.sso_create_users
  identity_store_id = local.identity_store_id

  user_name    = each.value.user_name
  display_name = "${each.value.user_first_name} ${each.value.user_last_name}"

  name {
    given_name  = each.value.user_first_name
    family_name = each.value.user_last_name
  }

  emails {
    value   = each.value.user_email
    primary = true
  }
}

# Assign permission set to newly created users
resource "aws_ssoadmin_account_assignment" "user" {
  for_each = local.sso_create_users

  instance_arn       = local.sso_instance_arn
  permission_set_arn = data.aws_ssoadmin_permission_set.this[var.sso_permission_set_name].arn

  principal_id   = aws_identitystore_user.this[each.key].user_id
  principal_type = "USER"

  target_id   = aws_organizations_account.this[each.key].id
  target_type = "AWS_ACCOUNT"
}

# --- Explicit principal assignments (existing groups/users) ---

locals {
  sso_principal_ids = merge(
    { for name, group in data.aws_identitystore_group.this : name => group.group_id },
    { for name, user in data.aws_identitystore_user.this : name => user.user_id },
  )
}

resource "aws_ssoadmin_account_assignment" "this" {
  for_each = local.sso_explicit

  instance_arn       = local.sso_instance_arn
  permission_set_arn = data.aws_ssoadmin_permission_set.this[each.value.permission_set_name].arn

  principal_id   = local.sso_principal_ids[each.value.principal_name]
  principal_type = each.value.principal_type

  target_id   = aws_organizations_account.this[each.key].id
  target_type = "AWS_ACCOUNT"
}

# =============================================================================
# Identity Center Permission Sets & Assignments
# =============================================================================

# --- Permission Sets ---

locals {
  # Every ic_* derivation is intersected with
  # local.identity_center_available, mirroring the per-account path above.
  # Without the guard the resources below would be planned with a null
  # instance_arn when Identity Center is not provisioned and the plan
  # would fail with a provider error instead of skipping the capability.

  # Map permission set name → definition for for_each
  ic_permission_sets = local.identity_center_available ? {
    for ps in var.identity_center_permission_sets : ps.name => ps
  } : {}

  # Flatten managed policy attachments: one entry per (permission_set, policy_arn)
  ic_managed_policy_attachments = local.identity_center_available ? {
    for item in flatten([
      for ps in var.identity_center_permission_sets : [
        for arn in ps.managed_policy_arns : {
          key                = "${ps.name}/${arn}"
          permission_set     = ps.name
          managed_policy_arn = arn
        }
      ]
    ]) : item.key => item
  } : {}

  # Permission sets that have an inline policy
  ic_inline_policies = local.identity_center_available ? {
    for ps in var.identity_center_permission_sets : ps.name => ps
    if ps.inline_policy != null
  } : {}

  # Flatten customer managed policy attachments: one entry per (permission_set, policy_ref)
  ic_customer_managed_policy_attachments = local.identity_center_available ? {
    for item in flatten([
      for ps in var.identity_center_permission_sets : [
        for ref in ps.customer_managed_policy_references : {
          key            = "${ps.name}/${ref.name}"
          permission_set = ps.name
          name           = ref.name
          path           = ref.path
        }
      ]
    ]) : item.key => item
  } : {}

  # Permission sets that have a permissions boundary
  ic_permissions_boundary = local.identity_center_available ? {
    for ps in var.identity_center_permission_sets : ps.name => ps
    if ps.permissions_boundary != null
  } : {}
}

resource "aws_ssoadmin_permission_set" "ic" {
  for_each = local.ic_permission_sets

  instance_arn     = local.sso_instance_arn
  name             = each.value.name
  description      = each.value.description
  session_duration = each.value.session_duration
  relay_state      = each.value.relay_state
}

resource "aws_ssoadmin_managed_policy_attachment" "ic" {
  for_each = local.ic_managed_policy_attachments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.ic[each.value.permission_set].arn
  managed_policy_arn = each.value.managed_policy_arn
}

resource "aws_ssoadmin_permission_set_inline_policy" "ic" {
  for_each = local.ic_inline_policies

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.ic[each.key].arn
  inline_policy      = each.value.inline_policy
}

# Customer managed policy attachments per permission set
resource "aws_ssoadmin_customer_managed_policy_attachment" "ic" {
  for_each = local.ic_customer_managed_policy_attachments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.ic[each.value.permission_set].arn

  customer_managed_policy_reference {
    name = each.value.name
    path = each.value.path
  }
}

# Permissions boundary attachment per permission set (when specified)
resource "aws_ssoadmin_permissions_boundary_attachment" "ic" {
  for_each = local.ic_permissions_boundary

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.ic[each.key].arn

  permissions_boundary {
    managed_policy_arn = each.value.permissions_boundary.managed_policy_arn

    dynamic "customer_managed_policy_reference" {
      for_each = each.value.permissions_boundary.customer_managed_policy_ref != null ? [each.value.permissions_boundary.customer_managed_policy_ref] : []
      content {
        name = customer_managed_policy_reference.value.name
        path = customer_managed_policy_reference.value.path
      }
    }
  }
}

# --- Assignments ---

locals {
  # Build the account_ids map: merge passed-in map with locally created accounts
  ic_account_ids = merge(
    var.account_ids,
    { for email, acct in aws_organizations_account.this : acct.name => acct.id },
  )

  # Map of locally created permission set name → ARN
  ic_permission_set_arns = {
    for name, ps in aws_ssoadmin_permission_set.ic : name => ps.arn
  }

  # Flatten assignments: one entry per (principal, permission_set, account)
  ic_assignments_flat = flatten([
    for assignment in var.identity_center_assignments : [
      for account_name in assignment.account_names : {
        key                 = "${assignment.principal_type}/${assignment.principal_name}/${assignment.permission_set_name}/${account_name}"
        principal_type      = assignment.principal_type
        principal_name      = assignment.principal_name
        permission_set_name = assignment.permission_set_name
        account_name        = account_name
      }
    ]
  ])

  ic_assignments = local.identity_center_available ? {
    for item in local.ic_assignments_flat : item.key => item
  } : {}

  # Unique group/user names from identity_center_assignments for data source
  # lookup. Guarded like the collections above: the identitystore data
  # sources read local.identity_store_id, which is null without a
  # provisioned instance.
  ic_group_names = local.identity_center_available ? toset([
    for a in var.identity_center_assignments : a.principal_name
    if a.principal_type == "GROUP"
  ]) : toset([])

  ic_user_names = local.identity_center_available ? toset([
    for a in var.identity_center_assignments : a.principal_name
    if a.principal_type == "USER"
  ]) : toset([])
}

# --- Data sources for assignment principal resolution ---

data "aws_identitystore_group" "ic" {
  for_each          = local.ic_group_names
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = each.value
    }
  }
}

data "aws_identitystore_user" "ic" {
  for_each          = local.ic_user_names
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = each.value
    }
  }
}

locals {
  # Merge principal IDs from identity center assignment data sources
  ic_principal_ids = merge(
    { for name, group in data.aws_identitystore_group.ic : name => group.group_id },
    { for name, user in data.aws_identitystore_user.ic : name => user.user_id },
  )
}

resource "aws_ssoadmin_account_assignment" "ic" {
  for_each = local.ic_assignments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = local.ic_permission_set_arns[each.value.permission_set_name]

  principal_id   = local.ic_principal_ids[each.value.principal_name]
  principal_type = each.value.principal_type

  target_id   = local.ic_account_ids[each.value.account_name]
  target_type = "AWS_ACCOUNT"
}

# --- Check blocks for missing references ---

check "ic_permission_sets_exist" {
  assert {
    # Checked against the configured names, not local.ic_permission_sets:
    # the local is emptied while Identity Center is unavailable,
    # and referential integrity of the
    # configuration holds independently of the instance state.
    condition = alltrue([
      for a in var.identity_center_assignments :
      contains([for ps in var.identity_center_permission_sets : ps.name], a.permission_set_name)
    ])
    error_message = "One or more identity_center_assignments reference a permission_set_name that is not defined in identity_center_permission_sets."
  }
}

check "ic_accounts_exist" {
  assert {
    condition = alltrue([
      for a in var.identity_center_assignments :
      alltrue([
        for acct_name in a.account_names :
        contains(keys(local.ic_account_ids), acct_name)
      ])
    ])
    error_message = "One or more identity_center_assignments reference an account_name that does not exist in the account_ids map or locally created accounts."
  }
}

check "identity_center_available_when_requested" {
  assert {
    # This promise matches the actual scope:
    # both the per-account paths and the ic_* collections are emptied
    # while the instance is missing, so every SSO resource is skipped.
    condition     = !local.identity_center_enabled || local.identity_center_available
    error_message = "SSO assignments or Identity Center inputs are configured but IAM Identity Center is not provisioned in this account/region. All SSO and Identity Center resources are skipped. Enable Identity Center in the AWS console first, then re-run."
  }
}
