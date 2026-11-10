# =============================================================================
# customizations/cloudformation — HCL tests
# =============================================================================
# Coverage:
#   1. Default scenario — empty lists, nothing is created
#   2. Custom scenario — one stack, one service-managed StackSet (OU names,
#      exclusion filter, auto-deployment), one self-managed StackSet
#      (account × region instances, role wiring)
#   3. Validation failures — capability set, permission-model target rules,
#      account-ID form, name rules, unresolvable OU name
#
# Conventions: mock_provider "aws" (no credentials), command = plan, one run
# per scenario with named error messages.
mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }
  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "999999999999"
    }
  }
}

variables {
  region = "eu-central-1"
}

# -----------------------------------------------------------------------------
# 1. Default scenario — empty lists create nothing
# -----------------------------------------------------------------------------
run "defaults_create_nothing" {
  command = plan

  assert {
    condition     = length(aws_cloudformation_stack.this) == 0 && length(aws_cloudformation_stack_set.this) == 0
    error_message = "Empty configuration lists must produce no stack and no StackSet."
  }

  assert {
    condition     = length(aws_cloudformation_stack_set_instance.service_managed) == 0 && length(aws_cloudformation_stack_set_instance.self_managed) == 0
    error_message = "Empty configuration lists must produce no StackSet instance."
  }
}

# -----------------------------------------------------------------------------
# 2. Custom scenario — stacks and both StackSet permission models
# -----------------------------------------------------------------------------
run "custom_configuration_reaches_every_resource" {
  command = plan

  variables {
    ou_name_to_id = {
      "Workloads" = "ou-ab12-workloads1"
    }
    cloudformation_stacks = [
      {
        name          = "management-baseline"
        template_body = "{\"Resources\":{\"Wait\":{\"Type\":\"AWS::CloudFormation::WaitConditionHandle\"}}}"
        parameters    = { Stage = "prod" }
        capabilities  = ["CAPABILITY_IAM"]
      }
    ]
    cloudformation_stack_sets = [
      {
        name                 = "workload-baseline"
        description          = "Baseline for every workload account"
        template_body        = "{\"Resources\":{\"Wait\":{\"Type\":\"AWS::CloudFormation::WaitConditionHandle\"}}}"
        organizational_units = ["Workloads", "ou-ab12-sandbox99"]
        excluded_account_ids = ["111111111111"]
        capabilities         = ["CAPABILITY_NAMED_IAM"]
        regions              = ["eu-central-1", "eu-west-1"]
      },
      {
        name               = "legacy-accounts"
        template_body      = "{\"Resources\":{\"Wait\":{\"Type\":\"AWS::CloudFormation::WaitConditionHandle\"}}}"
        permission_model   = "SELF_MANAGED"
        target_account_ids = ["222222222222", "333333333333"]
      }
    ]
  }

  assert {
    condition     = aws_cloudformation_stack.this["management-baseline"].parameters["Stage"] == "prod" && contains(aws_cloudformation_stack.this["management-baseline"].capabilities, "CAPABILITY_IAM")
    error_message = "The plain stack must carry its parameters and capabilities from the configuration."
  }

  assert {
    condition     = aws_cloudformation_stack_set.this["workload-baseline"].permission_model == "SERVICE_MANAGED" && aws_cloudformation_stack_set.this["workload-baseline"].auto_deployment[0].enabled
    error_message = "The service-managed StackSet must carry auto-deployment — accounts joining the OU later receive the stack without a code change."
  }

  assert {
    condition     = aws_cloudformation_stack_set.this["workload-baseline"].administration_role_arn == null
    error_message = "A service-managed StackSet must not name an administration role — CloudFormation deploys through the organization's trusted access."
  }

  assert {
    condition     = length(aws_cloudformation_stack_set_instance.service_managed) == 2
    error_message = "Two regions must produce two service-managed instances (targets travel in deployment_targets, not per account)."
  }

  assert {
    condition     = contains(aws_cloudformation_stack_set_instance.service_managed["workload-baseline:eu-central-1"].deployment_targets[0].organizational_unit_ids, "ou-ab12-workloads1")
    error_message = "The OU name Workloads must resolve to its ID through ou_name_to_id."
  }

  assert {
    condition     = aws_cloudformation_stack_set_instance.service_managed["workload-baseline:eu-central-1"].deployment_targets[0].account_filter_type == "DIFFERENCE" && contains(aws_cloudformation_stack_set_instance.service_managed["workload-baseline:eu-central-1"].deployment_targets[0].accounts, "111111111111")
    error_message = "excluded_account_ids must become the DIFFERENCE account filter — deploy to the OUs except these accounts."
  }

  assert {
    condition     = aws_cloudformation_stack_set.this["legacy-accounts"].administration_role_arn == "arn:aws:iam::999999999999:role/AWSCloudFormationStackSetAdministrationRole" && aws_cloudformation_stack_set.this["legacy-accounts"].execution_role_name == "AWSCloudFormationStackSetExecutionRole"
    error_message = "A self-managed StackSet must name the StackSet role pair of modules/iam, partition-correct via arn_prefix."
  }

  assert {
    condition     = length(aws_cloudformation_stack_set_instance.self_managed) == 2 && aws_cloudformation_stack_set_instance.self_managed["legacy-accounts:222222222222:eu-central-1"].account_id == "222222222222"
    error_message = "A self-managed StackSet must produce one instance per (account, region) with the default region of the deployment."
  }
}

# -----------------------------------------------------------------------------
# 3. Validation failures
# -----------------------------------------------------------------------------
run "invalid_capability_rejected" {
  command = plan

  variables {
    cloudformation_stacks = [
      {
        name          = "bad-capability"
        template_body = "{}"
        capabilities  = ["CAPABILITY_EVERYTHING"]
      }
    ]
  }

  expect_failures = [var.cloudformation_stacks]
}

run "service_managed_without_ous_rejected" {
  command = plan

  variables {
    cloudformation_stack_sets = [
      {
        name          = "no-targets"
        template_body = "{}"
      }
    ]
  }

  expect_failures = [var.cloudformation_stack_sets]
}

run "self_managed_with_ous_rejected" {
  command = plan

  variables {
    cloudformation_stack_sets = [
      {
        name                 = "mixed-targets"
        template_body        = "{}"
        permission_model     = "SELF_MANAGED"
        target_account_ids   = ["222222222222"]
        organizational_units = ["ou-ab12-workloads1"]
      }
    ]
  }

  expect_failures = [var.cloudformation_stack_sets]
}

run "bad_account_id_rejected" {
  command = plan

  variables {
    cloudformation_stack_sets = [
      {
        name                 = "bad-account"
        template_body        = "{}"
        organizational_units = ["ou-ab12-workloads1"]
        excluded_account_ids = ["11-not-an-account"]
      }
    ]
  }

  expect_failures = [var.cloudformation_stack_sets]
}

run "stack_name_with_space_rejected" {
  command = plan

  variables {
    cloudformation_stacks = [
      {
        name          = "has space"
        template_body = "{}"
      }
    ]
  }

  expect_failures = [var.cloudformation_stacks]
}

run "unresolvable_ou_name_aborts" {
  command = plan

  variables {
    cloudformation_stack_sets = [
      {
        name                 = "typo-ou"
        template_body        = "{}"
        organizational_units = ["Wrokloads"]
      }
    ]
  }

  expect_failures = [resource.aws_cloudformation_stack_set.this]
}
