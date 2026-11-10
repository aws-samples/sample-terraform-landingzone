# =============================================================================
# Budgets Module Tests (modules/budgets)
# =============================================================================
# Mandatory scenarios:
#   1. Toggle-Off — enable_budgets = false => zero resources.
#   2. Default configuration — enable_budgets = true with a defaulted
#      budget_config object.
#   3. Custom configuration — custom name, limit, time unit and notifications
#      (email plus SNS subscribers).
#   4. Validation failures — invalid time_unit, invalid budget_type.
#
# Additionally covered: the cross-account deployment warning check block, and
# var.default_tags in both states (scenario 2 asserts the empty default,
# scenario 3c asserts the tags reach the budget). In the pinned provider
# (hashicorp/aws ~> 6.0) the aws_budgets_budget schema declares tags and
# tags_all.
#
# Providers used directly by the module: aws (default only, no aliases).
# The module declares no data sources, so no override_data blocks are needed.

mock_provider "aws" {}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off — no resources
# -----------------------------------------------------------------------------
run "budget_disabled" {
  command = plan

  variables {
    enable_budgets = false
  }

  assert {
    condition     = length(aws_budgets_budget.this) == 0
    error_message = "No budget must be created when disabled."
  }

  assert {
    condition     = output.budget_id == ""
    error_message = "budget_id must be empty when disabled."
  }
}

# -----------------------------------------------------------------------------
# Scenario 1b: Module defaults — enable_budgets defaults to false
# -----------------------------------------------------------------------------
run "module_defaults_create_nothing" {
  command = plan

  assert {
    condition     = length(aws_budgets_budget.this) == 0
    error_message = "Module defaults must not create a budget (enable_budgets defaults to false)."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — enabled with defaulted budget_config
# -----------------------------------------------------------------------------
run "budget_enabled_default_config" {
  command = plan

  variables {
    enable_budgets = true
  }

  assert {
    condition     = length(aws_budgets_budget.this) == 1
    error_message = "One budget must be created when enabled."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].name == "tlz-monthly-budget"
    error_message = "Budget name must match default."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].limit_amount == "1000"
    error_message = "Budget limit must match default (1000)."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].limit_unit == "USD"
    error_message = "Budget limit unit must be USD."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].time_unit == "MONTHLY"
    error_message = "Budget time unit must be MONTHLY."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].budget_type == "COST"
    error_message = "Budget type must default to COST."
  }

  assert {
    condition     = length(aws_budgets_budget.this["this"].notification) == 0
    error_message = "No notifications must be configured by default."
  }

  assert {
    condition     = length(aws_budgets_budget.this["this"].tags) == 0
    error_message = "The budget must carry no tags while default_tags is empty."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — custom limits and notifications
# -----------------------------------------------------------------------------
run "budget_enabled_custom_config" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      name         = "test-budget"
      limit_amount = "500"
      limit_unit   = "USD"
      time_unit    = "QUARTERLY"
      budget_type  = "COST"
      notifications = [
        {
          threshold                  = 80
          subscriber_email_addresses = ["test@example.com"]
        },
        {
          comparison_operator       = "GREATER_THAN"
          threshold                 = 100
          threshold_type            = "PERCENTAGE"
          notification_type         = "FORECASTED"
          subscriber_sns_topic_arns = ["arn:aws:sns:eu-central-1:123456789012:budget-alerts"]
        },
      ]
    }
  }

  assert {
    condition     = length(aws_budgets_budget.this) == 1
    error_message = "One budget must be created with custom config."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].name == "test-budget"
    error_message = "Budget name must match custom config."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].limit_amount == "500"
    error_message = "Budget limit must match custom config (500)."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].time_unit == "QUARTERLY"
    error_message = "Budget time unit must match custom config (QUARTERLY)."
  }

  assert {
    condition     = length(aws_budgets_budget.this["this"].notification) == 2
    error_message = "Both notifications from the custom config must be rendered."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b: deployment_targets triggers the cross-account warning check
# -----------------------------------------------------------------------------
run "budget_deployment_targets_warning" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      deployment_targets = ["111111111111"]
    }
  }

  expect_failures = [
    check.budget_cross_account_deployment_warning,
  ]

  assert {
    condition     = length(aws_budgets_budget.this) == 1
    error_message = "The budget must still be created in the management account."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3c: custom configuration — default_tags reach the budget
#
# var.default_tags must reach the budget like every other landing zone
# resource. Together with scenario 2 (empty default) this covers both states
# of the variable.
# -----------------------------------------------------------------------------
run "budget_carries_default_tags" {
  command = plan

  variables {
    enable_budgets = true
    default_tags = {
      ManagedBy   = "TLZ"
      Environment = "prod"
    }
  }

  assert {
    condition     = aws_budgets_budget.this["this"].tags["ManagedBy"] == "TLZ"
    error_message = "default_tags must reach the budget (ManagedBy)."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].tags["Environment"] == "prod"
    error_message = "default_tags must reach the budget (Environment)."
  }

  assert {
    condition     = length(aws_budgets_budget.this["this"].tags) == 2
    error_message = "The budget must carry exactly the tags from default_tags."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "invalid_time_unit_rejected" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      time_unit = "WEEKLY"
    }
  }

  expect_failures = [var.budget_config]
}

run "invalid_budget_type_rejected" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      budget_type = "SPEND"
    }
  }

  expect_failures = [var.budget_config]
}

# -----------------------------------------------------------------------------
# Scenario 5: Cost types — default and reach
# -----------------------------------------------------------------------------

# A configuration without cost-type attributes plans no cost_types block at
# all.
run "regression_cost_types_absent_by_default" {
  command = plan

  variables {
    enable_budgets = true
  }

  assert {
    condition     = length(aws_budgets_budget.this["this"].cost_types) == 0
    error_message = "A budget without cost-type attributes must not render a cost_types block."
  }

  assert {
    condition     = length(aws_budgets_budget.this) == 1
    error_message = "Only the primary budget must exist by default."
  }
}

# Reach: every set attribute lands in the block, every unset attribute is
# coalesced to the API default (include everything, unblended view).
run "budget_cost_types_reach_the_budget" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      include_credit = false
      include_refund = false
      use_amortized  = true
    }
  }

  assert {
    condition     = length(aws_budgets_budget.this["this"].cost_types) == 1
    error_message = "Setting a cost-type attribute must render the cost_types block."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].cost_types[0].include_credit == false
    error_message = "include_credit must reach the cost_types block."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].cost_types[0].include_refund == false
    error_message = "include_refund must reach the cost_types block."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].cost_types[0].use_amortized == true
    error_message = "use_amortized must reach the cost_types block."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].cost_types[0].include_tax == true
    error_message = "An unset include attribute must coalesce to the API default true."
  }

  assert {
    condition     = aws_budgets_budget.this["this"].cost_types[0].use_blended == false
    error_message = "An unset use attribute must coalesce to the API default false."
  }
}

# -----------------------------------------------------------------------------
# Scenario 6: Distribution — management and member selection
# -----------------------------------------------------------------------------

# Management deployment (deployment_account_name = ""): the primary budget is
# always created; additional budgets without targets or listing "management"
# are created; budgets targeting only member accounts are not.
run "budget_management_selects_untargeted_budgets" {
  command = plan

  variables {
    enable_budgets = true
    additional_budgets = [
      { name = "team-a" },
      { name = "dev-only", deployment_targets = ["workload-dev"] },
      { name = "shared", deployment_targets = ["management", "workload-dev"] },
    ]
  }

  # Deployment targets are configured, so the distribution reminder check
  # fires by design — expected here so the selection assertions can run.
  expect_failures = [
    check.budget_cross_account_deployment_warning,
  ]

  assert {
    condition     = length(aws_budgets_budget.this) == 3
    error_message = "Management must carry the primary budget, the untargeted budget and the budget listing management."
  }

  assert {
    condition     = contains(keys(aws_budgets_budget.this), "additional-team-a") && contains(keys(aws_budgets_budget.this), "additional-shared")
    error_message = "The untargeted and the management-targeted additional budget must be keyed by their names."
  }

  assert {
    condition     = !contains(keys(aws_budgets_budget.this), "additional-dev-only")
    error_message = "A budget targeting only member accounts must not be created in the management deployment."
  }

  assert {
    condition     = aws_budgets_budget.this["additional-team-a"].name == "team-a"
    error_message = "The additional budget must carry its configured name."
  }
}

# Member deployment: only the budgets that list this account's directory name
# are created — including the primary budget when it lists the account.
run "budget_member_selects_by_directory_name" {
  command = plan

  variables {
    enable_budgets          = true
    deployment_account_name = "workload-dev"
    budget_config = {
      deployment_targets = ["workload-dev"]
    }
    additional_budgets = [
      { name = "team-a" },
      { name = "dev-only", deployment_targets = ["workload-dev"] },
    ]
  }

  assert {
    condition     = length(aws_budgets_budget.this) == 2
    error_message = "The member deployment must create exactly the budgets that list its name."
  }

  assert {
    condition     = contains(keys(aws_budgets_budget.this), "this") && contains(keys(aws_budgets_budget.this), "additional-dev-only")
    error_message = "The targeted primary budget and the targeted additional budget must be created in the member account."
  }

  assert {
    condition     = !contains(keys(aws_budgets_budget.this), "additional-team-a")
    error_message = "An untargeted additional budget belongs to the management deployment, not to a member account."
  }
}

# Member deployment without a targeted primary budget: the primary stays in
# the management account and the budget_id output reports the absence.
run "budget_member_without_primary_reports_empty_id" {
  command = plan

  variables {
    enable_budgets          = true
    deployment_account_name = "workload-dev"
    additional_budgets = [
      { name = "dev-only", deployment_targets = ["workload-dev"] },
    ]
  }

  assert {
    condition     = length(aws_budgets_budget.this) == 1 && contains(keys(aws_budgets_budget.this), "additional-dev-only")
    error_message = "Only the targeted additional budget must exist in the member deployment."
  }

  assert {
    condition     = output.budget_id == ""
    error_message = "budget_id must be empty when this deployment does not carry the primary budget."
  }
}

# -----------------------------------------------------------------------------
# Scenario 7: Validation failures — cost types and distribution
# -----------------------------------------------------------------------------

run "budget_amortized_and_blended_rejected" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      use_amortized = true
      use_blended   = true
    }
  }

  expect_failures = [var.budget_config]
}

run "budget_additional_amortized_and_blended_rejected" {
  command = plan

  variables {
    enable_budgets = true
    additional_budgets = [
      { name = "broken", use_amortized = true, use_blended = true },
    ]
  }

  expect_failures = [var.additional_budgets]
}

run "budget_duplicate_additional_names_rejected" {
  command = plan

  variables {
    enable_budgets = true
    additional_budgets = [
      { name = "twice" },
      { name = "twice" },
    ]
  }

  expect_failures = [var.additional_budgets]
}

run "budget_padded_deployment_target_rejected" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      deployment_targets = ["Workload-Dev"]
    }
  }

  expect_failures = [var.budget_config]
}

run "budget_empty_additional_name_rejected" {
  command = plan

  variables {
    enable_budgets = true
    additional_budgets = [
      { name = "" },
    ]
  }

  expect_failures = [var.additional_budgets]
}

run "budget_bad_deployment_account_name_rejected" {
  command = plan

  variables {
    enable_budgets          = true
    deployment_account_name = "Workload Dev"
  }

  expect_failures = [var.deployment_account_name]
}

# A threshold without any subscriber is rejected by the Budgets API — but only
# after CreateBudget succeeded, leaving a tainted half-created budget. The
# validation turns that into a plan-time error; these runs pin it.
run "budget_notification_without_subscriber_rejected" {
  command = plan

  variables {
    enable_budgets = true
    budget_config = {
      notifications = [
        { threshold = 80 },
      ]
    }
  }

  expect_failures = [var.budget_config]
}

run "budget_additional_notification_without_subscriber_rejected" {
  command = plan

  variables {
    enable_budgets = true
    additional_budgets = [
      {
        name = "no-subscriber"
        notifications = [
          { threshold = 80 },
        ]
      },
    ]
  }

  expect_failures = [var.additional_budgets]
}
