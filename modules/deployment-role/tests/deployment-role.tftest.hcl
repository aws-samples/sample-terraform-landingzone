# =============================================================================
# Deployment Role Module Tests (modules/deployment-role)
# =============================================================================
# Coverage:
#   - Default configuration (default role name, no permissions boundary)
#   - Custom configuration (custom role name, permissions boundary attached)
#   - Custom configuration with an explicitly empty boundary — the value the
#     stack delivers while none is configured
#   - Validation failures (account ID, role name, permissions boundary ARN)
#   - narrow_grants: the flag selects the enumerated policy document and the
#     default keeps the broad `service:*` grants
#
# Toggle scenario: this module has no enable_* variable. The role, its inline
# policy and the IAM propagation delay are created unconditionally — the "off"
# state is expressed by not instantiating the module in a stack. The remaining
# three mandatory scenarios are covered below.

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }
}

mock_provider "time" {}

# -----------------------------------------------------------------------------
# Scenario 1: Default configuration — default role name, no boundary
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  variables {
    deployment_account_id = "111111111111"
  }

  assert {
    condition     = aws_iam_role.deployment.name == "TLZDeploymentRole"
    error_message = "Role name must default to TLZDeploymentRole."
  }

  assert {
    condition     = aws_iam_role.deployment.permissions_boundary == null
    error_message = "No permissions boundary must be attached when permissions_boundary_arn is empty."
  }

  # The decoded document, not a substring: a second statement with Principal
  # "*" would keep a substring check green.
  assert {
    condition = jsondecode(aws_iam_role.deployment.assume_role_policy).Statement == [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::111111111111:root" }
        Action    = "sts:AssumeRole"
      },
    ]
    error_message = "Trust policy must hold exactly one statement: sts:AssumeRole for the deployment account root principal with the detected partition."
  }

  assert {
    condition     = aws_iam_role_policy.deployment.name == "TLZDeploymentRole-policy"
    error_message = "Inline policy name must be derived from the role name."
  }

  assert {
    condition     = length(aws_iam_role_policy.deployment.policy) > 0
    error_message = "Inline policy document must be rendered from the policy file."
  }

  assert {
    condition     = time_sleep.iam_propagation.create_duration == "30s"
    error_message = "IAM propagation delay must be 30s."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Custom configuration — custom role name and permissions boundary
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    deployment_account_id    = "222222222222"
    role_name                = "AcmeLandingZoneDeployment"
    permissions_boundary_arn = "arn:aws:iam::222222222222:policy/AcmeBoundary"
  }

  assert {
    condition     = aws_iam_role.deployment.name == "AcmeLandingZoneDeployment"
    error_message = "Role name must honour the custom value."
  }

  assert {
    condition     = aws_iam_role.deployment.permissions_boundary == "arn:aws:iam::222222222222:policy/AcmeBoundary"
    error_message = "Permissions boundary must be attached when an ARN is provided."
  }

  assert {
    condition     = aws_iam_role_policy.deployment.name == "AcmeLandingZoneDeployment-policy"
    error_message = "Inline policy name must follow the custom role name."
  }

  assert {
    condition = jsondecode(aws_iam_role.deployment.assume_role_policy).Statement == [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::222222222222:root" }
        Action    = "sts:AssumeRole"
      },
    ]
    error_message = "Trust policy must hold exactly one statement: sts:AssumeRole for the custom deployment account root principal."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2b: custom configuration — an explicitly empty boundary
#
# stacks/management/deployment-role passes
# permissions_boundary_arn through from the configuration layer, and the
# configured value is empty by default. Scenario 1 covers the module default
# (variable not set at all); this scenario covers the value the stack actually
# delivers, so both branches of local.has_permissions_boundary are asserted
# against the form the deployment uses.
# -----------------------------------------------------------------------------
run "explicit_empty_permissions_boundary" {
  command = plan

  variables {
    deployment_account_id    = "111111111111"
    role_name                = "TLZDeploymentRole"
    permissions_boundary_arn = ""
  }

  assert {
    condition     = aws_iam_role.deployment.permissions_boundary == null
    error_message = "An empty permissions_boundary_arn must leave the role without a boundary."
  }

  assert {
    condition     = aws_iam_role.deployment.name == "TLZDeploymentRole"
    error_message = "The role name passed by the stack must reach the role."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3a: Validation failure — invalid deployment account ID
# -----------------------------------------------------------------------------
run "invalid_deployment_account_id_rejected" {
  command = plan

  variables {
    deployment_account_id = "12345"
  }

  expect_failures = [
    var.deployment_account_id,
  ]
}

# env/accounts.hcl ships with empty values. The empty string is
# therefore the value this validation meets first in practice — it must be
# rejected at plan time instead of surfacing later as a malformed ARN.
run "empty_deployment_account_id_rejected" {
  command = plan

  variables {
    deployment_account_id = ""
  }

  expect_failures = [
    var.deployment_account_id,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 3b: Validation failure — invalid role name
# -----------------------------------------------------------------------------
run "invalid_role_name_rejected" {
  command = plan

  variables {
    deployment_account_id = "111111111111"
    role_name             = "invalid role name!"
  }

  expect_failures = [
    var.role_name,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 3c: Validation failure — invalid permissions boundary ARN
# -----------------------------------------------------------------------------
run "invalid_permissions_boundary_rejected" {
  command = plan

  variables {
    deployment_account_id    = "111111111111"
    permissions_boundary_arn = "not-an-arn"
  }

  expect_failures = [
    var.permissions_boundary_arn,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4: narrow_grants
# The flag selects the enumerated document instead of the service:* grants for
# the security services and Identity Center; the default keeps the broad grants.
#
# The flag selects configurations/policies/deployment/role-inline-policy-narrow.json,
# in which the seven in-scope `service:*` grants (guardduty, securityhub,
# macie2, access-analyzer, sso, sso-directory, identitystore) are replaced by
# the actions the modules' resource types call. Which actions those are is
# pinned by tests/test_deployment_role_narrow_grants.py against the modules;
# this scenario pins the wiring: the flag reaches the rendered policy, and the
# default does not move.
# -----------------------------------------------------------------------------
run "narrow_grants_selects_the_enumerated_document" {
  command = plan

  variables {
    deployment_account_id = "111111111111"
    narrow_grants         = true
  }

  assert {
    condition = alltrue([
      for service in ["guardduty", "securityhub", "macie2", "access-analyzer", "sso", "sso-directory", "identitystore"] :
      !strcontains(aws_iam_role_policy.deployment.policy, "\"${service}:*\"")
    ])
    error_message = "With narrow_grants = true the inline policy must carry no in-scope service:* grant."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.deployment.policy, "\"guardduty:CreateDetector\"") && strcontains(aws_iam_role_policy.deployment.policy, "\"sso:CreateAccountAssignment\"")
    error_message = "With narrow_grants = true the inline policy must carry the enumerated actions of the narrow document."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.deployment.policy, "\"budgets:*\"") && strcontains(aws_iam_role_policy.deployment.policy, "\"controltower:*\"") && strcontains(aws_iam_role_policy.deployment.policy, "\"servicecatalog:*\"")
    error_message = "The out-of-scope wildcards (budgets, controltower, servicecatalog) stay in the narrow document; the flag does not touch them."
  }
}

run "narrow_grants_default_keeps_todays_document" {
  command = plan

  variables {
    deployment_account_id = "111111111111"
  }

  assert {
    condition     = var.narrow_grants == false
    error_message = "narrow_grants must default to false until one organization-wide apply with the flag on has gone through."
  }

  assert {
    condition = alltrue([
      for service in ["guardduty", "securityhub", "macie2", "access-analyzer", "sso", "sso-directory", "identitystore"] :
      strcontains(aws_iam_role_policy.deployment.policy, "\"${service}:*\"")
    ])
    error_message = "With the default the inline policy must still carry the default document's seven service:* grants -- the default document must not change."
  }

  assert {
    condition     = aws_iam_role_policy.deployment.policy == jsonencode(jsondecode(file("${path.module}/../../configurations/policies/deployment/role-inline-policy.json")))
    error_message = "With the default the rendered inline policy must be role-inline-policy.json, byte for byte after the jsonencode round trip."
  }
}
