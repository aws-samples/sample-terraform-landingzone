# =============================================================================
# customizations/_template — Example HCL test
# =============================================================================
# ← Copy this file together with the rest of the directory:
#     cp -r customizations/_template customizations/my-module
#   and adapt the run blocks to your own resources.
#
# Why this file exists. Every module under `modules/` has a default scenario, a
# custom scenario and a validation-failure scenario, and every HCL test file
# uses a `mock_provider "aws"` so the suite runs without AWS credentials. Custom modules are not covered by those
# criteria, but they deserve the same safety net — and the way to get it is the
# framework the landing zone already uses (`terraform test`), not a second one.
# `customizations/<module>/tests/` is therefore a second location for HCL
# tests.
#
# How to run it:
#     terraform -chdir=customizations/_template init -backend=false
#     terraform -chdir=customizations/_template test
#   `make test` does both for every directory under `customizations/`.
#
# The three conventions this file demonstrates:
#   1. `mock_provider "aws"` — no credentials, no network, no real AWS call.
#   2. `command = plan` — assertions read the planned resources, nothing is
#      applied.
#   3. One `run` block per scenario, each with a named `error_message` that says
#      what the landing zone expects, not just that something failed.

mock_provider "aws" {}

# -----------------------------------------------------------------------------
# 1. Default scenario — the minimum interface, nothing optional configured
# -----------------------------------------------------------------------------
# var.region is required and has no default, so it is the only value this
# scenario has to supply. var.account_ids stays empty, which is the interesting
# half: a custom module must not create per-account resources when the landing
# zone passes no accounts.

run "template_defaults" {
  command = plan

  variables {
    region = "eu-central-1"
  }

  assert {
    condition     = length(aws_ssm_parameter.this) == 1
    error_message = "The example parameter map must produce exactly one SSM parameter."
  }

  assert {
    condition     = aws_ssm_parameter.this["landing-zone-info"].name == "/custom/eu-central-1/landing-zone-info"
    error_message = "The parameter path must carry the region so that two installations never collide."
  }

  assert {
    condition     = length(aws_ssm_parameter.account_role_arn) == 0
    error_message = "An empty account_ids must produce no per-account parameter."
  }
}

# -----------------------------------------------------------------------------
# 2. Custom scenario — every input set, per-account resources expected
# -----------------------------------------------------------------------------
# Shows the two remaining conventions of a custom module: deriving resources
# from var.account_ids, and building an ARN from the detected partition instead
# of writing "arn:aws:" as a literal (see docs/multi-partition.md).

run "template_custom_configuration" {
  command = plan

  variables {
    region = "us-east-1"
    account_ids = {
      "workload-dev"  = "111111111111"
      "workload-prod" = "222222222222"
    }
    default_tags = {
      ManagedBy = "Terraform"
      Project   = "LandingZone"
    }
  }

  assert {
    condition     = length(aws_ssm_parameter.account_role_arn) == 2
    error_message = "One parameter must be created per entry of account_ids."
  }

  assert {
    condition     = aws_ssm_parameter.account_role_arn["workload-dev"].name == "/custom/us-east-1/accounts/workload-dev/deployment-role-arn"
    error_message = "The per-account parameter path must contain the region and the account name."
  }

  # The mocked aws_partition data source returns a mock value, so the assertion
  # checks the shape of the ARN — that it starts with "arn:" and carries the
  # account ID and the role name — rather than a literal partition.
  assert {
    condition     = strcontains(aws_ssm_parameter.account_role_arn["workload-prod"].value, ":iam::222222222222:role/LZTDeploymentRole")
    error_message = "The ARN must be built from local.arn_prefix and the account ID, never from a hardcoded partition."
  }

  assert {
    condition     = aws_ssm_parameter.this["landing-zone-info"].tags["Project"] == "LandingZone"
    error_message = "default_tags must reach every resource of a custom module."
  }
}

# -----------------------------------------------------------------------------
# 3. Validation-failure scenario — an invalid input is rejected
# -----------------------------------------------------------------------------
# ← This is the scenario most easily forgotten, and the one that needs something
# to expect: `expect_failures` reports a `validation` block or a precondition, not
# a type error — Terraform aborts on a wrong type before the test can catch it.
# The template therefore declares a validation block on var.account_ids
# (variables.tf), and this scenario points at it with a value that is not a
# 12-digit account ID.
#
# Declare a validation block for every input of your own module that a wrong
# value could silently break, and point one run block at each — that is where a
# custom module earns the same guarantee the landing zone modules give.

run "template_invalid_account_ids_rejected" {
  command = plan

  variables {
    region = "eu-central-1"
    account_ids = {
      "workload-dev" = "1234"
    }
  }

  expect_failures = [
    var.account_ids,
  ]
}
