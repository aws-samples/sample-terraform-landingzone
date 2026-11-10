# =============================================================================
# Accounts Module Tests (modules/accounts)
# =============================================================================
# Coverage:
#   - Toggle-Off: accounts = [] and every enable_* toggle false => zero resources
#   - Default configuration (OU name resolution, SSM to management account)
#   - Custom configuration (OU path syntax, warming, deployment account,
#     Identity Center permission sets and assignments)
#   - Validation failure scenarios for every validated variable
#
# Providers used by the module: aws (default) and the module-owned alias
# aws.deployment_account (declared in providers.tf, used by
# aws_ssm_parameter.account_id_deployment).

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws"
    }
  }

  override_data {
    target = data.aws_ssoadmin_instances.this
    values = {
      arns               = ["arn:aws:sso:::instance/ssoins-1234567890abcdef"]
      identity_store_ids = ["d-1234567890"]
    }
  }

  # Mocked values must satisfy the provider-side ARN / UUID validators of the
  # ssoadmin resources, so they are pinned instead of randomly generated.
  override_data {
    target = data.aws_ssoadmin_permission_set.this
    values = {
      arn = "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef"
    }
  }

  override_data {
    target = data.aws_identitystore_group.this
    values = {
      group_id = "11111111-2222-3333-4444-555555555555"
    }
  }

  override_data {
    target = data.aws_identitystore_user.this
    values = {
      user_id = "66666666-7777-8888-9999-aaaaaaaaaaaa"
    }
  }

  override_data {
    target = data.aws_identitystore_group.ic
    values = {
      group_id = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    }
  }

  override_data {
    target = data.aws_identitystore_user.ic
    values = {
      user_id = "12345678-90ab-cdef-1234-567890abcdef"
    }
  }
}

mock_provider "aws" {
  alias = "deployment_account"
}

variables {
  # Passed explicitly so the organization-root data source stays unused (count = 0)
  organization_root_id = "r-abc1"
  ou_name_to_id = {
    Workloads      = "ou-abc1-11111111"
    Sandbox        = "ou-abc1-22222222"
    Production     = "ou-abc1-33333333"
    Infrastructure = "ou-abc1-44444444"
  }
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off — no accounts, all toggles disabled => zero resources
# -----------------------------------------------------------------------------
run "all_toggles_off_no_resources" {
  command = plan

  variables {
    accounts                        = []
    enable_sso_assignment           = false
    enable_account_warming          = false
    enable_deployment_account       = false
    enable_control_tower_enrollment = false
    identity_center_permission_sets = []
    identity_center_assignments     = []
  }

  assert {
    condition     = length(aws_organizations_account.this) == 0
    error_message = "No accounts must be created when the accounts list is empty."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_id_local) == 0
    error_message = "No management-account SSM parameters must be created without accounts."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_id_deployment) == 0
    error_message = "No deployment-account SSM parameters must be created when the toggle is off."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_plain_id_local) == 0
    error_message = "No management-account plain-ID SSM parameters must be created without accounts."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_plain_id_deployment) == 0
    error_message = "No deployment-account plain-ID SSM parameters must be created when the toggle is off."
  }
  assert {
    condition     = length(aws_iam_account_alias.management) == 0
    error_message = "No account alias must be created while management_account_alias is empty."
  }

  assert {
    condition     = length(aws_identitystore_user.this) == 0
    error_message = "No Identity Center users must be created when SSO is disabled."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.this) == 0
    error_message = "No explicit SSO assignments must be created when SSO is disabled."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.user) == 0
    error_message = "No user SSO assignments must be created when SSO is disabled."
  }

  assert {
    condition     = length(aws_ssoadmin_permission_set.ic) == 0
    error_message = "No permission sets must be created when none are configured."
  }

  assert {
    condition     = length(aws_ssoadmin_managed_policy_attachment.ic) == 0
    error_message = "No managed policy attachments must be created when no permission sets exist."
  }

  assert {
    condition     = length(aws_ssoadmin_permission_set_inline_policy.ic) == 0
    error_message = "No inline policies must be created when no permission sets exist."
  }

  assert {
    condition     = length(aws_ssoadmin_customer_managed_policy_attachment.ic) == 0
    error_message = "No customer managed policy attachments must be created when no permission sets exist."
  }

  assert {
    condition     = length(aws_ssoadmin_permissions_boundary_attachment.ic) == 0
    error_message = "No permissions boundary attachments must be created when no permission sets exist."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.ic) == 0
    error_message = "No Identity Center assignments must be created when none are configured."
  }

  assert {
    condition     = length(output.account_ids) == 0
    error_message = "account_ids output must be empty."
  }

  assert {
    condition     = length(output.warm_account_ids) == 0
    error_message = "warm_account_ids output must be empty."
  }

  assert {
    condition     = length(output.warm_account_names) == 0
    error_message = "warm_account_names output must be empty."
  }

  assert {
    condition     = length(output.sso_assignments) == 0
    error_message = "sso_assignments output must be empty when SSO is disabled."
  }

  assert {
    condition     = length(output.permission_set_arns) == 0
    error_message = "permission_set_arns output must be empty."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — accounts created, SSM in management account
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  variables {
    accounts = [
      {
        name                     = "Workload-A"
        email                    = "workload-a@example.com"
        organizational_unit_name = "Workloads"
      },
      {
        name                   = "Audit"
        email                  = "audit@example.com"
        organizational_unit_id = "ou-abc1-99999999"
      },
    ]
  }

  assert {
    condition     = length(aws_organizations_account.this) == 2
    error_message = "Both accounts must be created."
  }

  # OU name is resolved through ou_name_to_id
  assert {
    condition     = aws_organizations_account.this["workload-a@example.com"].parent_id == "ou-abc1-11111111"
    error_message = "OU name must be resolved to the OU ID from ou_name_to_id."
  }

  # An explicit organizational_unit_id wins over name resolution
  assert {
    condition     = aws_organizations_account.this["audit@example.com"].parent_id == "ou-abc1-99999999"
    error_message = "An explicit organizational_unit_id must take precedence."
  }

  assert {
    condition     = aws_organizations_account.this["workload-a@example.com"].name == "Workload-A"
    error_message = "Account name must match the input."
  }

  # created_account_role_name is unset here, so the CreateAccount role falls
  # back to account_access_role_name, whose default is AWSControlTowerExecution.
  assert {
    condition     = aws_organizations_account.this["workload-a@example.com"].role_name == "AWSControlTowerExecution"
    error_message = "With both role variables at their defaults, CreateAccount must use AWSControlTowerExecution (account_access_role_name's default, reached through created_account_role_name = null)."
  }

  assert {
    condition     = aws_organizations_account.this["workload-a@example.com"].iam_user_access_to_billing == "DENY"
    error_message = "iam_user_access_to_billing must default to DENY."
  }

  assert {
    condition     = aws_organizations_account.this["workload-a@example.com"].close_on_deletion == false
    error_message = "close_on_deletion must default to false."
  }

  # SSM parameters are written to the management account by default
  assert {
    condition     = length(aws_ssm_parameter.account_id_local) == 2
    error_message = "SSM parameters must be written to the management account by default."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_id_deployment) == 0
    error_message = "No deployment-account SSM parameters must be written by default."
  }

  assert {
    condition     = aws_ssm_parameter.account_id_local["workload-a@example.com"].name == "/tlz/accounts/Workload-A/metadata"
    error_message = "SSM parameter path must follow /tlz/accounts/<name>/metadata."
  }

  assert {
    condition     = aws_ssm_parameter.account_id_local["workload-a@example.com"].type == "String"
    error_message = "SSM parameter type must be String."
  }

  # Plain-ID discovery parameter: one per account, next to the metadata record
  assert {
    condition     = length(aws_ssm_parameter.account_plain_id_local) == 2
    error_message = "One plain-ID SSM parameter per account must be written to the management account by default."
  }

  assert {
    condition     = aws_ssm_parameter.account_plain_id_local["workload-a@example.com"].name == "/tlz/accounts/Workload-A/id"
    error_message = "The plain-ID SSM parameter path must follow /tlz/accounts/<name>/id."
  }

  assert {
    condition     = aws_ssm_parameter.account_plain_id_local["workload-a@example.com"].type == "String"
    error_message = "The plain-ID SSM parameter type must be String."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_plain_id_deployment) == 0
    error_message = "No deployment-account plain-ID SSM parameters must be written by default."
  }

  # Warming is off by default => no warm accounts reported
  assert {
    condition     = length(output.warm_account_names) == 0
    error_message = "warm_account_names must be empty while account warming is disabled."
  }

  # Zero-diff: without warm accounts the active pendants equal the raw outputs
  assert {
    condition     = sort(keys(output.active_account_ids)) == sort(keys(output.account_ids))
    error_message = "active_account_ids must equal account_ids while no account is warm."
  }

  assert {
    condition     = sort(keys(output.active_account_ou_ids)) == sort(keys(output.account_ids))
    error_message = "active_account_ou_ids must cover every account while no account is warm."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — OU paths, warming, deployment account,
#             Identity Center permission sets and assignments, SSO users
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    account_access_role_name = "OrganizationAccountAccessRole"
    close_on_deletion        = true
    # enable_account_warming stays false on purpose: the module's
    # "warm_accounts_skip_config_warning" check block is written as an
    # informational warning whose assertion is designed to fail as soon as a
    # warm account exists. terraform test treats a failing check block as a
    # test error, so the enabled path cannot be asserted here. The scenario
    # instead verifies that the toggle gates the warm logic (warm = true is
    # ignored while enable_account_warming = false) — which is exactly the
    # state the "warm_flags_without_toggle" check names, hence the
    # expect_failures below.
    enable_account_warming    = false
    enable_deployment_account = true
    deployment_account_id     = "555555555555"
    region                    = "eu-central-1"
    enable_sso_assignment     = true
    sso_permission_set_name   = "AWSAdministratorAccess"
    sso_principal_type        = "GROUP"
    sso_principal_name        = "Platform-Admins"
    default_tags = {
      ManagedBy = "terraform"
    }

    accounts = [
      {
        name = "Workload-B"
        # Path syntax: only the leaf segment is looked up
        email                      = "workload-b@example.com"
        organizational_unit_name   = "Workloads/Production"
        description                = "Production workload"
        iam_user_access_to_billing = "ALLOW"
        tags                       = { CostCenter = "1234" }
      },
      {
        name                     = "Standby"
        email                    = "standby@example.com"
        organizational_unit_name = "Sandbox"
        warm                     = true
      },
      {
        name                     = "AftUser"
        email                    = "aft@example.com"
        organizational_unit_name = "Infrastructure"
        sso_user_email           = "aft-admin@example.com"
        sso_user_first_name      = "Aft"
        sso_user_last_name       = "Admin"
      },
    ]

    identity_center_permission_sets = [
      {
        name                = "ReadOnly"
        description         = "Read-only access"
        session_duration    = "PT2H"
        managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
        inline_policy       = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        customer_managed_policy_references = [
          {
            name = "CustomBoundary"
          },
        ]
        permissions_boundary = {
          managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
        }
      },
      {
        name        = "Break-Glass"
        description = "Emergency access"
      },
    ]

    identity_center_assignments = [
      {
        principal_type      = "GROUP"
        principal_name      = "Platform-Admins"
        permission_set_name = "ReadOnly"
        account_names       = ["Workload-B", "Standby"]
      },
    ]
  }

  # The Standby account carries warm = true while the toggle is off — the
  # module names exactly this ineffective-flag state.
  expect_failures = [check.warm_flags_without_toggle]

  assert {
    condition     = length(aws_organizations_account.this) == 3
    error_message = "All three accounts must be created."
  }

  # OU path "Workloads/Production" resolves via the leaf segment "Production"
  assert {
    condition     = aws_organizations_account.this["workload-b@example.com"].parent_id == "ou-abc1-33333333"
    error_message = "OU path syntax must resolve through the leaf segment."
  }

  assert {
    condition     = aws_organizations_account.this["workload-b@example.com"].iam_user_access_to_billing == "ALLOW"
    error_message = "iam_user_access_to_billing must honour the per-account override."
  }

  assert {
    condition     = aws_organizations_account.this["workload-b@example.com"].close_on_deletion == true
    error_message = "close_on_deletion must honour the module input."
  }

  assert {
    condition     = aws_organizations_account.this["workload-b@example.com"].role_name == "OrganizationAccountAccessRole"
    error_message = "With created_account_role_name unset, the CreateAccount role must follow the account_access_role_name input."
  }

  # Tag merge: default_tags + per-account tags + Description
  assert {
    condition     = aws_organizations_account.this["workload-b@example.com"].tags["ManagedBy"] == "terraform"
    error_message = "default_tags must be merged into account tags."
  }

  assert {
    condition     = aws_organizations_account.this["workload-b@example.com"].tags["CostCenter"] == "1234"
    error_message = "Per-account tags must be merged into account tags."
  }

  assert {
    condition     = aws_organizations_account.this["workload-b@example.com"].tags["Description"] == "Production workload"
    error_message = "A non-empty description must be mapped to the Description tag."
  }

  assert {
    condition     = !contains(keys(aws_organizations_account.this["standby@example.com"].tags), "Description")
    error_message = "An empty description must not produce a Description tag."
  }

  # warm = true is ignored while the warming toggle is off
  assert {
    condition     = length(output.warm_account_names) == 0
    error_message = "warm = true must be ignored while enable_account_warming is false."
  }

  assert {
    condition     = length(output.warm_account_ids) == 0
    error_message = "warm_account_ids must stay empty while enable_account_warming is false."
  }

  # Toggle off => the active pendants equal the raw outputs (zero-diff),
  # even though a warm flag is set.
  assert {
    condition     = sort(keys(output.active_account_ids)) == sort(keys(output.account_ids))
    error_message = "active_account_ids must equal account_ids while enable_account_warming is false."
  }

  assert {
    condition     = contains(keys(output.active_account_ids), "Standby")
    error_message = "A warm-flagged account must stay in active_account_ids while the toggle is off."
  }

  # SSM parameters are routed to the deployment account
  assert {
    condition     = length(aws_ssm_parameter.account_id_deployment) == 3
    error_message = "SSM parameters must be routed to the deployment account when enabled."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_id_local) == 0
    error_message = "No management-account SSM parameters must be written when the deployment account is enabled."
  }

  # Plain-ID parameters follow the same provider routing
  assert {
    condition     = length(aws_ssm_parameter.account_plain_id_deployment) == 3
    error_message = "Plain-ID SSM parameters must be routed to the deployment account when enabled."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_plain_id_local) == 0
    error_message = "No management-account plain-ID SSM parameters must be written when the deployment account is enabled."
  }

  # AFT-style SSO user creation + assignment
  assert {
    condition     = length(aws_identitystore_user.this) == 1
    error_message = "One Identity Center user must be created for the account with sso_user_email."
  }

  assert {
    condition     = aws_identitystore_user.this["aft@example.com"].user_name == "aft-admin@example.com"
    error_message = "The created SSO user name must be the sso_user_email."
  }

  assert {
    condition     = aws_identitystore_user.this["aft@example.com"].display_name == "Aft Admin"
    error_message = "The SSO user display name must combine first and last name."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.user) == 1
    error_message = "One assignment must be created for the newly created SSO user."
  }

  # Explicit principal assignment for the two accounts without sso_user_email
  assert {
    condition     = length(aws_ssoadmin_account_assignment.this) == 2
    error_message = "Two explicit SSO assignments must be created from the global principal name."
  }

  # Identity Center permission sets
  assert {
    condition     = length(aws_ssoadmin_permission_set.ic) == 2
    error_message = "Both permission sets must be created."
  }

  assert {
    condition     = aws_ssoadmin_permission_set.ic["ReadOnly"].session_duration == "PT2H"
    error_message = "Permission set session_duration must match the input."
  }

  assert {
    condition     = aws_ssoadmin_permission_set.ic["Break-Glass"].session_duration == "PT1H"
    error_message = "Permission set session_duration must default to PT1H."
  }

  assert {
    condition     = length(aws_ssoadmin_managed_policy_attachment.ic) == 1
    error_message = "One managed policy attachment must be created."
  }

  assert {
    condition     = length(aws_ssoadmin_permission_set_inline_policy.ic) == 1
    error_message = "One inline policy must be created."
  }

  assert {
    condition     = length(aws_ssoadmin_customer_managed_policy_attachment.ic) == 1
    error_message = "One customer managed policy attachment must be created."
  }

  assert {
    condition     = length(aws_ssoadmin_permissions_boundary_attachment.ic) == 1
    error_message = "One permissions boundary attachment must be created."
  }

  # One assignment per (principal, permission set, account)
  assert {
    condition     = length(aws_ssoadmin_account_assignment.ic) == 2
    error_message = "Assignments must be flattened to one entry per account."
  }

  assert {
    condition     = aws_ssoadmin_account_assignment.ic["GROUP/Platform-Admins/ReadOnly/Workload-B"].principal_type == "GROUP"
    error_message = "Assignment principal_type must be taken from the input."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# An unresolvable organizational_unit_name must abort the plan. Falling
# through to the organization root would create the account outside every
# OU-bound SCP, RCP, tag policy and control — accepted by AWS and therefore
# silent.
# -----------------------------------------------------------------------------
run "unresolvable_ou_name_aborts" {
  command = plan

  variables {
    accounts = [
      {
        name                     = "Typo"
        email                    = "typo@example.com"
        organizational_unit_name = "Wrokloads"
      },
    ]
  }

  expect_failures = [resource.aws_organizations_account.this]
}

# A nested OU path whose leaf is missing from ou_name_to_id is rejected too —
# the data-source fallback only lists the direct children of the root.
run "unresolvable_ou_path_leaf_aborts" {
  command = plan

  variables {
    accounts = [
      {
        name                     = "Nested"
        email                    = "nested@example.com"
        organizational_unit_name = "Workloads/Staging"
      },
    ]
  }

  expect_failures = [resource.aws_organizations_account.this]
}

# -----------------------------------------------------------------------------
# identity_center_permission_sets[*].description must default to an absent
# value, not to the empty string: aws_ssoadmin_permission_set.description
# accepts 1-700 characters, so a defaulted "" would make every permission set
# without an explicit description fail.
# -----------------------------------------------------------------------------
run "permission_set_without_description_plans" {
  command = plan

  variables {
    accounts = []
    identity_center_permission_sets = [
      {
        name = "Break-Glass"
      },
    ]
  }

  assert {
    condition     = length(aws_ssoadmin_permission_set.ic) == 1
    error_message = "A permission set without an explicit description must be planned."
  }

  assert {
    condition     = aws_ssoadmin_permission_set.ic["Break-Glass"].description == null
    error_message = "An omitted description must stay absent instead of becoming an empty string."
  }
}

# An explicitly empty description is rejected at plan time by the module
# instead of by the provider at apply time.
run "permission_set_empty_description_rejected" {
  command = plan

  variables {
    accounts = []
    identity_center_permission_sets = [
      {
        name        = "Break-Glass"
        description = ""
      },
    ]
  }

  expect_failures = [var.identity_center_permission_sets]
}

run "account_without_ou_reference_rejected" {
  command = plan

  variables {
    accounts = [
      {
        name  = "NoOu"
        email = "no-ou@example.com"
      },
    ]
  }

  expect_failures = [var.accounts]
}

run "invalid_iam_user_access_to_billing_rejected" {
  command = plan

  variables {
    accounts = [
      {
        name                       = "BadBilling"
        email                      = "bad-billing@example.com"
        organizational_unit_name   = "Workloads"
        iam_user_access_to_billing = "MAYBE"
      },
    ]
  }

  expect_failures = [var.accounts]
}

run "invalid_ou_name_to_id_rejected" {
  command = plan

  variables {
    accounts = []
    ou_name_to_id = {
      Workloads = "not-an-ou-id"
    }
  }

  expect_failures = [var.ou_name_to_id]
}

run "invalid_organization_root_id_rejected" {
  command = plan

  variables {
    accounts             = []
    organization_root_id = "root-1234"
  }

  expect_failures = [var.organization_root_id]
}

run "invalid_account_access_role_name_rejected" {
  command = plan

  variables {
    accounts                 = []
    account_access_role_name = "invalid role name!"
  }

  expect_failures = [var.account_access_role_name]
}

# -----------------------------------------------------------------------------
# Two roles, two variables.
#   account_access_role_name — the role the stacks and this module's
#     aws.deployment_account provider ASSUME to reach accounts that already
#     exist (providers.tf, stacks/root.hcl, every cross_account.hcl).
#   created_account_role_name — the role CreateAccount makes INSIDE a new
#     member account (aws_organizations_account.this.role_name). null (the
#     default) means "same as account_access_role_name", so a configuration
#     that does not set it plans byte-identically.
# The provider's assume-role ARN is provider configuration, which terraform
# test cannot read as a plan value; what these cases observe is the
# CreateAccount site, and providers.tf keeps reading account_access_role_name.
# -----------------------------------------------------------------------------

# (a) unset: the CreateAccount role follows account_access_role_name, also
#     when that one is not at its default.
run "created_account_role_name_unset_follows_account_access_role_name" {
  command = plan

  variables {
    account_access_role_name = "OrganizationAccountAccessRole"
    accounts = [
      {
        name                     = "Workload-C"
        email                    = "workload-c@example.com"
        organizational_unit_name = "Workloads"
      },
    ]
  }

  assert {
    condition     = aws_organizations_account.this["workload-c@example.com"].role_name == "OrganizationAccountAccessRole"
    error_message = "With created_account_role_name unset, CreateAccount must use account_access_role_name (OrganizationAccountAccessRole here)."
  }

  assert {
    condition     = aws_organizations_account.this["workload-c@example.com"].role_name == var.account_access_role_name
    error_message = "With created_account_role_name unset, the CreateAccount role and the assumed role must be one name."
  }
}

# (b) set: CreateAccount gets the new name while account_access_role_name — the
#     name the deployment-account provider assumes — stays the other one. The
#     deployment account is switched on so the assume-role provider block is
#     part of this plan.
run "created_account_role_name_set_splits_the_two_roles" {
  command = plan

  variables {
    account_access_role_name  = "OrganizationAccountAccessRole"
    created_account_role_name = "AWSControlTowerExecution"
    enable_deployment_account = true
    deployment_account_id     = "555555555555"
    region                    = "eu-central-1"
    accounts = [
      {
        name                     = "Workload-D"
        email                    = "workload-d@example.com"
        organizational_unit_name = "Workloads"
      },
    ]
  }

  assert {
    condition     = aws_organizations_account.this["workload-d@example.com"].role_name == "AWSControlTowerExecution"
    error_message = "CreateAccount must use created_account_role_name (AWSControlTowerExecution here), not account_access_role_name."
  }

  assert {
    condition     = aws_organizations_account.this["workload-d@example.com"].role_name != var.account_access_role_name
    error_message = "With created_account_role_name set, the CreateAccount role must differ from the assumed role name."
  }

  assert {
    condition     = var.account_access_role_name == "OrganizationAccountAccessRole"
    error_message = "Setting created_account_role_name must leave account_access_role_name — the assumed role — untouched."
  }

  # The account record the deployment account receives is written through the
  # assume-role provider, whichever CreateAccount role the account carries.
  assert {
    condition     = length(aws_ssm_parameter.account_id_deployment) == 1
    error_message = "The deployment-account SSM record must still be planned when the two role names differ."
  }
}

# (c) an invalid created_account_role_name is refused by the same rule as
#     account_access_role_name.
run "invalid_created_account_role_name_rejected" {
  command = plan

  variables {
    accounts                  = []
    created_account_role_name = "invalid role name!"
  }

  expect_failures = [var.created_account_role_name]
}

# IAM role names are 1 to 64 characters. A longer name would plan green and
# fail only at CreateAccount or at the assume-role call, so both role-name
# variables refuse it at plan time.
run "too_long_account_access_role_name_rejected" {
  command = plan

  variables {
    accounts                 = []
    account_access_role_name = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }

  expect_failures = [var.account_access_role_name]
}

run "too_long_created_account_role_name_rejected" {
  command = plan

  variables {
    accounts                  = []
    created_account_role_name = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }

  expect_failures = [var.created_account_role_name]
}

# A role name of exactly 64 characters (the IAM limit) is accepted by both
# role-name variables, so an off-by-one in the length rule turns these red.
run "max_length_account_access_role_name_accepted" {
  command = plan

  variables {
    accounts                 = []
    account_access_role_name = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0064"
  }

  assert {
    condition     = length(var.account_access_role_name) == 64
    error_message = "The max-length pin needs an account_access_role_name of exactly 64 characters."
  }
}

run "max_length_created_account_role_name_accepted" {
  command = plan

  variables {
    accounts                  = []
    created_account_role_name = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0064"
  }

  assert {
    condition     = length(var.created_account_role_name) == 64
    error_message = "The max-length pin needs a created_account_role_name of exactly 64 characters."
  }
}

run "invalid_sso_principal_type_rejected" {
  command = plan

  variables {
    accounts           = []
    sso_principal_type = "TEAM"
  }

  expect_failures = [var.sso_principal_type]
}

run "invalid_deployment_account_id_rejected" {
  command = plan

  variables {
    accounts              = []
    deployment_account_id = "12345"
  }

  expect_failures = [var.deployment_account_id]
}

run "invalid_region_rejected" {
  command = plan

  variables {
    accounts = []
    region   = "EU-Central"
  }

  expect_failures = [var.region]
}

run "invalid_identity_center_assignment_principal_type_rejected" {
  command = plan

  variables {
    accounts = []
    identity_center_assignments = [
      {
        principal_type      = "ROLE"
        principal_name      = "Platform-Admins"
        permission_set_name = "ReadOnly"
        account_names       = ["Workload-A"]
      },
    ]
  }

  expect_failures = [var.identity_center_assignments]
}

# -----------------------------------------------------------------------------
# Identity Center reaches the deployment
#
# stacks/management/accounts passes the three variables of the Identity Center
# feature (identity_center_permission_sets, identity_center_assignments,
# account_ids) on.
#
# The run below holds the one part of the feature that the existing scenarios
# do not reach: an assignment whose target account is NOT created by this
# module. That target can only be resolved through var.account_ids, and
# var.account_ids is the variable that must not come from
# dependency.accounts.outputs.account_ids — this unit is the accounts unit, so
# that would be a dependency on itself, and local.ic_account_ids already merges
# the accounts created here.
# -----------------------------------------------------------------------------
run "regression_identity_center_assignment_targets_external_account" {
  command = plan

  variables {
    # sso_principal_name stays at its default "": local.sso_explicit wraps
    # the expression in try(coalesce(…), "") and simply skips an account
    # without an sso block, so this run exercises the target state directly.

    accounts = [
      {
        name                     = "Workload-A"
        email                    = "workload-a@example.com"
        organizational_unit_name = "Workloads"
      },
    ]

    # An account that exists in the organization but is not created here.
    account_ids = {
      "Pre-Existing" = "999999999999"
    }

    identity_center_permission_sets = [
      {
        name        = "ReadOnly"
        description = "Read-only access"
      },
    ]

    identity_center_assignments = [
      {
        principal_type      = "GROUP"
        principal_name      = "Platform-Admins"
        permission_set_name = "ReadOnly"
        account_names       = ["Pre-Existing", "Workload-A"]
      },
    ]
  }

  assert {
    condition     = length(aws_ssoadmin_permission_set.ic) == 1
    error_message = "The configured permission set must be created."
  }

  # One assignment per (principal, permission set, account): the external
  # account and the locally created one.
  assert {
    condition     = length(aws_ssoadmin_account_assignment.ic) == 2
    error_message = "Both assignment targets must be resolved — the external account through account_ids, the local one through aws_organizations_account.this."
  }

  # Only the external target has a known ID at plan time; the ID of a
  # locally created account is unknown before apply.
  assert {
    condition     = aws_ssoadmin_account_assignment.ic["GROUP/Platform-Admins/ReadOnly/Pre-Existing"].target_id == "999999999999"
    error_message = "An account name from account_ids must resolve to the ID given there."
  }

  assert {
    condition     = aws_ssoadmin_account_assignment.ic["GROUP/Platform-Admins/ReadOnly/Pre-Existing"].target_type == "AWS_ACCOUNT"
    error_message = "An Identity Center assignment must target an AWS account."
  }

  # With the feature reachable, the output permission_set_arns carries the
  # created permission set.
  assert {
    condition     = length(output.permission_set_arns) == 1
    error_message = "permission_set_arns must report the created permission set."
  }
}

# Counterpart: with both collections empty — the value every deployment used
# before the repair — nothing of the feature is planned, and the map passed in
# creates nothing on its own.
run "regression_identity_center_collections_empty_plan_nothing" {
  command = plan

  variables {
    accounts = []
    account_ids = {
      "Pre-Existing" = "999999999999"
    }
    identity_center_permission_sets = []
    identity_center_assignments     = []
  }

  assert {
    condition     = length(aws_ssoadmin_permission_set.ic) == 0
    error_message = "No permission set must be created from an empty collection."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.ic) == 0
    error_message = "No assignment must be created from an empty collection."
  }

  assert {
    condition     = length(output.permission_set_arns) == 0
    error_message = "permission_set_arns must stay empty without permission sets."
  }
}

# -----------------------------------------------------------------------------
# Scenario: IAM account alias of the management account
# The alias is a property of the account the provider authenticates to; the
# module therefore sets it only for the account the stack runs in.
# -----------------------------------------------------------------------------
run "management_account_alias_reaches_the_resource" {
  command = plan

  variables {
    accounts                 = []
    management_account_alias = "example-landing-zone"
  }

  assert {
    condition     = length(aws_iam_account_alias.management) == 1
    error_message = "A non-empty management_account_alias must create exactly one alias resource."
  }

  assert {
    condition     = aws_iam_account_alias.management[0].account_alias == "example-landing-zone"
    error_message = "The declared alias must reach aws_iam_account_alias.account_alias."
  }
}

run "invalid_management_account_alias_rejected" {
  command = plan

  variables {
    accounts                 = []
    management_account_alias = "Example-Alias"
  }

  expect_failures = [
    var.management_account_alias,
  ]
}

run "double_hyphen_management_account_alias_rejected" {
  command = plan

  variables {
    accounts                 = []
    management_account_alias = "example--alias"
  }

  expect_failures = [
    var.management_account_alias,
  ]
}

# -----------------------------------------------------------------------------
# Account warming runbook
# -----------------------------------------------------------------------------

run "account_warming_off_no_document" {
  command = plan

  variables {
    accounts               = []
    enable_account_warming = false
  }

  assert {
    condition     = length(aws_ssm_document.account_warming) == 0
    error_message = "Without enable_account_warming no warming runbook may be planned."
  }
}

run "account_warming_publishes_the_runbook" {
  command = plan

  variables {
    enable_account_warming = true
    accounts = [
      {
        name                   = "standby-account"
        email                  = "standby@example.com"
        organizational_unit_id = "ou-ab12-cdefgh34"
        warm                   = true
      },
    ]
  }

  # The warm-account warning is the DESIGNED behaviour of this configuration:
  # a warm-marked account exists, so the module's check block must fire and
  # remind the operator to keep the account out of downstream configuration.
  expect_failures = [check.warm_accounts_skip_config_warning]

  assert {
    condition     = length(aws_ssm_document.account_warming) == 1 && aws_ssm_document.account_warming[0].document_type == "Automation"
    error_message = "enable_account_warming must publish exactly one Automation document."
  }

  assert {
    condition     = aws_ssm_document.account_warming[0].name == "tlz-account-warming"
    error_message = "The runbook must carry the delivered name tlz-account-warming."
  }

  assert {
    condition     = can(jsondecode(aws_ssm_document.account_warming[0].content))
    error_message = "The runbook content must be valid JSON (configurations/ssm-documents/account-warming.json)."
  }

  assert {
    condition = alltrue([
      for step in ["resolveAmi", "createVpc", "createSubnet", "runInstance", "warmDuration", "terminateInstance", "waitInstanceTerminated", "deleteSubnet", "deleteVpc", "markWarmed"] :
      contains([for s in jsondecode(aws_ssm_document.account_warming[0].content).mainSteps : s.name], step)
    ])
    error_message = "The runbook must encode the full reference procedure: AMI from the partition's SSM parameter, throwaway VPC/subnet, temporary instance, warm duration, termination, cleanup, pre-warmed flag."
  }

  assert {
    condition     = jsondecode(aws_ssm_document.account_warming[0].content).parameters.WarmDuration.default == "PT15M"
    error_message = "The warm duration must default to the reference procedure's 15 minutes."
  }
}

# -----------------------------------------------------------------------------
# Warm-account exclusion: the active pendants are the deployment
# targets for downstream stacks — a warm account is missing from them while
# the raw outputs keep listing every created account.
# -----------------------------------------------------------------------------
run "warm_account_missing_from_active_outputs" {
  command = plan

  variables {
    enable_account_warming = true
    accounts = [
      {
        name                     = "Workload-C"
        email                    = "workload-c@example.com"
        organizational_unit_name = "Workloads"
      },
      {
        name                     = "Standby-1"
        email                    = "standby-1@example.com"
        organizational_unit_name = "Sandbox"
        warm                     = true
      },
    ]
  }

  # The warm-account warning is the DESIGNED behaviour of this configuration
  # (see account_warming_publishes_the_runbook).
  expect_failures = [check.warm_accounts_skip_config_warning]

  assert {
    condition     = !contains(keys(output.active_account_ids), "Standby-1")
    error_message = "A warm account must be excluded from active_account_ids."
  }

  assert {
    condition     = contains(keys(output.active_account_ids), "Workload-C")
    error_message = "A non-warm account must stay in active_account_ids."
  }

  assert {
    condition     = !contains(keys(output.active_account_ou_ids), "Standby-1")
    error_message = "A warm account must be excluded from active_account_ou_ids."
  }

  assert {
    condition     = contains(keys(output.active_account_ou_ids), "Workload-C")
    error_message = "A non-warm account must stay in active_account_ou_ids."
  }

  # The raw outputs stay unchanged — existing readers keep the full picture.
  assert {
    condition     = contains(keys(output.account_ids), "Standby-1")
    error_message = "The raw account_ids output must keep listing warm accounts."
  }

  assert {
    condition     = length(aws_organizations_account.this) == 2
    error_message = "Both accounts must be created — warm accounts are excluded from configuration, not from creation."
  }
}

# -----------------------------------------------------------------------------
# Ineffective warm flags: warm = true with enable_account_warming =
# false is named by its own check — and the active pendants stay identical to
# the raw outputs (zero-diff).
# -----------------------------------------------------------------------------
run "warm_flags_without_toggle_are_named" {
  command = plan

  variables {
    enable_account_warming = false
    accounts = [
      {
        name                     = "Standby-2"
        email                    = "standby-2@example.com"
        organizational_unit_name = "Sandbox"
        warm                     = true
      },
    ]
  }

  expect_failures = [check.warm_flags_without_toggle]

  assert {
    condition     = sort(keys(output.active_account_ids)) == sort(keys(output.account_ids))
    error_message = "active_account_ids must equal account_ids while enable_account_warming is false."
  }

  assert {
    condition     = contains(keys(output.active_account_ids), "Standby-2")
    error_message = "A warm-flagged account must stay in active_account_ids while the toggle is off."
  }

  assert {
    condition     = length(output.warm_account_ids) == 0
    error_message = "warm_account_ids must stay empty while enable_account_warming is false."
  }
}

# -----------------------------------------------------------------------------
# enable_sso_assignment is the one binding gate of the per-account SSO
# assignment paths. Identity Center availability alone must not create them:
# whoever maintains identity_center_permission_sets (which makes the instance
# lookup run) and sets an sso block or the global principal name must get no
# per-account assignments with enable_sso_assignment = false, and the output
# must agree with the resources.
# -----------------------------------------------------------------------------
run "regression_sso_gate_off_blocks_per_account_assignments" {
  command = plan

  variables {
    enable_sso_assignment = false
    sso_principal_name    = "Platform-Admins"

    accounts = [
      {
        name                     = "Workload-A"
        email                    = "workload-a@example.com"
        organizational_unit_name = "Workloads"
        sso = {
          principal_name = "Platform-Admins"
        }
      },
      {
        name                     = "AftUser"
        email                    = "aft@example.com"
        organizational_unit_name = "Infrastructure"
        sso_user_email           = "aft-admin@example.com"
        sso_user_first_name      = "Aft"
        sso_user_last_name       = "Admin"
      },
    ]

    # Keeps the Identity Center instance lookup active without the gate.
    identity_center_permission_sets = [
      {
        name        = "ReadOnly"
        description = "Read-only access"
      },
    ]
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.this) == 0
    error_message = "No explicit per-account assignment may be planned while enable_sso_assignment is false."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.user) == 0
    error_message = "No user assignment may be planned while enable_sso_assignment is false."
  }

  assert {
    condition     = length(aws_identitystore_user.this) == 0
    error_message = "No Identity Center user may be created while enable_sso_assignment is false."
  }

  # The ic path carries its own gate and stays unaffected.
  assert {
    condition     = length(aws_ssoadmin_permission_set.ic) == 1
    error_message = "identity_center_permission_sets must stay unaffected by enable_sso_assignment."
  }

  assert {
    condition     = length(output.sso_assignments) == 0
    error_message = "The output must be empty while no assignment resource is planned."
  }
}

# Counterpart: the gate on. The same configuration plans the per-account
# assignments, and the output enumerates every assignment resource — the
# per-account entries and the identity_center_assignments entries.
run "regression_sso_gate_on_plans_per_account_assignments" {
  command = plan

  variables {
    enable_sso_assignment = true
    sso_principal_name    = "Platform-Admins"

    accounts = [
      {
        name                     = "Workload-A"
        email                    = "workload-a@example.com"
        organizational_unit_name = "Workloads"
        sso = {
          principal_name = "Platform-Admins"
        }
      },
      {
        name                     = "AftUser"
        email                    = "aft@example.com"
        organizational_unit_name = "Infrastructure"
        sso_user_email           = "aft-admin@example.com"
        sso_user_first_name      = "Aft"
        sso_user_last_name       = "Admin"
      },
    ]

    identity_center_permission_sets = [
      {
        name        = "ReadOnly"
        description = "Read-only access"
      },
    ]

    identity_center_assignments = [
      {
        principal_type      = "GROUP"
        principal_name      = "Platform-Admins"
        permission_set_name = "ReadOnly"
        account_names       = ["Workload-A"]
      },
    ]
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.this) == 1
    error_message = "The explicit per-account assignment must be planned while the gate is on."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.user) == 1
    error_message = "The user assignment must be planned while the gate is on."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.ic) == 1
    error_message = "The identity_center_assignments entry must be planned."
  }

  assert {
    condition     = length(output.sso_assignments) == 3
    error_message = "The output must enumerate all three planned assignment resources."
  }

  assert {
    condition     = contains(keys(output.sso_assignments), "GROUP/Platform-Admins/ReadOnly/Workload-A")
    error_message = "The output must include the identity_center_assignments entries."
  }
}

# -----------------------------------------------------------------------------
# Identity Center not provisioned + configured ic inputs: every ic_*
# collection empties instead of planning resources with a null instance_arn.
# The module's check block warns about the skipped capability — that expected
# warning is this run's expect_failures.
# -----------------------------------------------------------------------------
run "regression_identity_center_absent_plans_zero_ic_resources" {
  command = plan

  override_data {
    target = data.aws_ssoadmin_instances.this
    values = {
      arns               = []
      identity_store_ids = []
    }
  }

  variables {
    accounts = []
    account_ids = {
      "Pre-Existing" = "999999999999"
    }

    identity_center_permission_sets = [
      {
        name                = "ReadOnly"
        description         = "Read-only access"
        managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
        inline_policy       = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        customer_managed_policy_references = [
          {
            name = "CustomBoundary"
          },
        ]
        permissions_boundary = {
          managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
        }
      },
    ]

    identity_center_assignments = [
      {
        principal_type      = "GROUP"
        principal_name      = "Platform-Admins"
        permission_set_name = "ReadOnly"
        account_names       = ["Pre-Existing"]
      },
    ]
  }

  expect_failures = [check.identity_center_available_when_requested]

  assert {
    condition     = length(aws_ssoadmin_permission_set.ic) == 0
    error_message = "No permission set may be planned while Identity Center is not provisioned."
  }

  assert {
    condition     = length(aws_ssoadmin_managed_policy_attachment.ic) == 0
    error_message = "No managed policy attachment may be planned while Identity Center is not provisioned."
  }

  assert {
    condition     = length(aws_ssoadmin_permission_set_inline_policy.ic) == 0
    error_message = "No inline policy may be planned while Identity Center is not provisioned."
  }

  assert {
    condition     = length(aws_ssoadmin_customer_managed_policy_attachment.ic) == 0
    error_message = "No customer managed policy attachment may be planned while Identity Center is not provisioned."
  }

  assert {
    condition     = length(aws_ssoadmin_permissions_boundary_attachment.ic) == 0
    error_message = "No permissions boundary attachment may be planned while Identity Center is not provisioned."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.ic) == 0
    error_message = "No Identity Center assignment may be planned while Identity Center is not provisioned."
  }

  assert {
    condition     = length(output.permission_set_arns) == 0
    error_message = "permission_set_arns must stay empty while Identity Center is not provisioned."
  }

  assert {
    condition     = length(output.sso_assignments) == 0
    error_message = "sso_assignments must stay empty while Identity Center is not provisioned."
  }
}

# -----------------------------------------------------------------------------
# Identity Center provisioned, the assignment gate on, one account without an
# sso block and sso_principal_name at its empty default: a bare double
# coalesce in local.sso_explicit would abort the plan ('Call to function
# "coalesce" failed: no non-null, non-empty-string arguments'); the account
# is skipped, exactly as the if clause of the derivation intends.
# -----------------------------------------------------------------------------
run "regression_empty_principal_name_skips_account" {
  command = plan

  variables {
    enable_sso_assignment = true
    # sso_principal_name stays at its module default ""

    accounts = [
      {
        name                     = "Workload-A"
        email                    = "workload-a@example.com"
        organizational_unit_name = "Workloads"
      },
    ]
  }

  assert {
    condition     = length(aws_organizations_account.this) == 1
    error_message = "The account itself must be planned."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.this) == 0
    error_message = "An account without an sso block must be skipped while sso_principal_name is empty — not abort the plan."
  }

  assert {
    condition     = length(output.sso_assignments) == 0
    error_message = "No assignment may be reported for the skipped account."
  }
}
