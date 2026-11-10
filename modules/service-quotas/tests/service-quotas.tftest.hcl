# =============================================================================
# Service Quotas Module Tests (modules/service-quotas)
# =============================================================================
# Coverage:
#   - Toggle-Off:   every entry disabled (enabled = false) -> zero resources
#   - Default:      variable default ([]) -> zero resources, empty outputs
#   - Custom:       multiple entries with mixed enabled flags, key format
#   - Validation:   empty service_code / quota_code, non-positive desired_value
#   - check block:  deployment_targets warning (cross-account not supported)
#
# Note: this module declares no `enable_*` variable. The per-entry `enabled`
# flag is the module's only creation toggle, so the mandatory Toggle-Off
# scenario is covered by setting `enabled = false` on every entry.
#
# Providers used directly by the module: aws (no aliases).

mock_provider "aws" {}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off — all entries disabled, zero resources created
# -----------------------------------------------------------------------------
run "toggle_off_all_entries_disabled" {
  command = plan

  variables {
    service_quota_increases = [
      {
        service_code  = "vpc"
        quota_code    = "L-F678F1CE"
        desired_value = 10
        enabled       = false
      },
      {
        service_code  = "ec2"
        quota_code    = "L-1216C47A"
        desired_value = 500
        enabled       = false
      },
    ]
  }

  assert {
    condition     = length(aws_servicequotas_service_quota.this) == 0
    error_message = "No service quota resources must be created when every entry is disabled."
  }

  assert {
    condition     = length(output.quota_request_ids) == 0
    error_message = "quota_request_ids output must be empty when every entry is disabled."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — variable default is an empty list
# -----------------------------------------------------------------------------
run "default_configuration_empty_list" {
  command = plan

  assert {
    condition     = length(aws_servicequotas_service_quota.this) == 0
    error_message = "No service quota resources must be created with the default configuration."
  }

  assert {
    condition     = length(output.quota_request_ids) == 0
    error_message = "quota_request_ids output must be empty with the default configuration."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — mixed enabled flags, key format
# -----------------------------------------------------------------------------
run "custom_configuration_mixed_entries" {
  command = plan

  variables {
    service_quota_increases = [
      {
        service_code  = "vpc"
        quota_code    = "L-F678F1CE"
        desired_value = 20
      },
      {
        service_code  = "ec2"
        quota_code    = "L-1216C47A"
        desired_value = 500
        enabled       = true
      },
      {
        service_code  = "lambda"
        quota_code    = "L-B99A9384"
        desired_value = 2000
        enabled       = false
      },
    ]
  }

  assert {
    condition     = length(aws_servicequotas_service_quota.this) == 2
    error_message = "Only the two enabled entries must create service quota resources."
  }

  assert {
    condition     = contains(keys(aws_servicequotas_service_quota.this), "vpc/L-F678F1CE")
    error_message = "Resource key must be composed as \"<service_code>/<quota_code>\"."
  }

  assert {
    condition     = !contains(keys(aws_servicequotas_service_quota.this), "lambda/L-B99A9384")
    error_message = "Disabled entries must not create a service quota resource."
  }

  assert {
    condition     = aws_servicequotas_service_quota.this["vpc/L-F678F1CE"].service_code == "vpc"
    error_message = "service_code must match the input entry."
  }

  assert {
    condition     = aws_servicequotas_service_quota.this["vpc/L-F678F1CE"].quota_code == "L-F678F1CE"
    error_message = "quota_code must match the input entry."
  }

  assert {
    condition     = aws_servicequotas_service_quota.this["vpc/L-F678F1CE"].value == 20
    error_message = "value must match the desired_value of the input entry."
  }

  assert {
    condition     = length(output.quota_request_ids) == 2
    error_message = "quota_request_ids output must contain one entry per enabled quota."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4a: Validation failure — empty service_code is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_empty_service_code" {
  command = plan

  variables {
    service_quota_increases = [
      {
        service_code  = ""
        quota_code    = "L-F678F1CE"
        desired_value = 10
      },
    ]
  }

  expect_failures = [
    var.service_quota_increases,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4b: Validation failure — empty quota_code is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_empty_quota_code" {
  command = plan

  variables {
    service_quota_increases = [
      {
        service_code  = "vpc"
        quota_code    = ""
        desired_value = 10
      },
    ]
  }

  expect_failures = [
    var.service_quota_increases,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4c: Validation failure — non-positive desired_value is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_non_positive_desired_value" {
  command = plan

  variables {
    service_quota_increases = [
      {
        service_code  = "vpc"
        quota_code    = "L-F678F1CE"
        desired_value = 0
      },
    ]
  }

  expect_failures = [
    var.service_quota_increases,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5: check block warns when deployment_targets are set
# -----------------------------------------------------------------------------
run "check_warns_on_deployment_targets" {
  command = plan

  variables {
    service_quota_increases = [
      {
        service_code       = "vpc"
        quota_code         = "L-F678F1CE"
        desired_value      = 10
        deployment_targets = ["111111111111", "222222222222"]
      },
    ]
  }

  expect_failures = [
    check.service_quota_deployment_targets_warning,
  ]

  assert {
    condition     = length(aws_servicequotas_service_quota.this) == 1
    error_message = "The quota resource must still be planned in the current account despite deployment_targets."
  }
}

# -----------------------------------------------------------------------------
# Scenario 6: no check warning when deployment_targets are absent
# -----------------------------------------------------------------------------
run "check_silent_without_deployment_targets" {
  command = plan

  variables {
    service_quota_increases = [
      {
        service_code  = "vpc"
        quota_code    = "L-F678F1CE"
        desired_value = 10
      },
    ]
  }

  assert {
    condition     = length(aws_servicequotas_service_quota.this) == 1
    error_message = "One quota resource must be planned without deployment_targets."
  }
}
