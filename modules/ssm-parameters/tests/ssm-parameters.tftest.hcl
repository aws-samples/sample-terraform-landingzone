# =============================================================================
# SSM Parameters Module Tests (modules/ssm-parameters)
# =============================================================================
# Mandatory scenarios:
#   1. Toggle-Off — the module has NO enable_* variable. Resource creation is
#      driven solely by the ssm_parameters list, so the empty list is the
#      module's creation toggle: ssm_parameters = [] => zero resources.
#   2. Default configuration — no inputs at all (ssm_parameters defaults to []).
#   3. Custom configuration — all three parameter types plus default_tags.
#   4. Validation failures — unsupported parameter type, empty parameter name.
#
# Additionally covered: the cross-account deployment warning check block.
#
# Providers used directly by the module: aws (default only, no aliases).
# The module declares no data sources, so no override_data blocks are needed.

mock_provider "aws" {}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off equivalent — empty list => zero resources
# -----------------------------------------------------------------------------
run "ssm_empty_list" {
  command = plan

  variables {
    ssm_parameters = []
  }

  assert {
    condition     = length(aws_ssm_parameter.this) == 0
    error_message = "No SSM parameters must be created when list is empty."
  }

  assert {
    condition     = length(output.ssm_parameter_names) == 0
    error_message = "ssm_parameter_names output must be empty."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — no inputs at all
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  assert {
    condition     = length(aws_ssm_parameter.this) == 0
    error_message = "Module defaults must not create any SSM parameter."
  }

  assert {
    condition     = length(output.ssm_parameter_names) == 0
    error_message = "Module defaults must yield an empty ssm_parameter_names map."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2b: Single parameter
# -----------------------------------------------------------------------------
run "ssm_single_parameter" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name  = "/tlz/test-param"
        type  = "String"
        value = "test-value"
      }
    ]
  }

  assert {
    condition     = length(aws_ssm_parameter.this) == 1
    error_message = "One SSM parameter must be created."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/test-param"].name == "/tlz/test-param"
    error_message = "Parameter name must match input."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/test-param"].type == "String"
    error_message = "Parameter type must match input."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/test-param"].value == "test-value"
    error_message = "Parameter value must match input."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — all parameter types and default_tags
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    default_tags = {
      ManagedBy   = "terraform"
      Environment = "test"
    }
    ssm_parameters = [
      {
        name  = "/tlz/param-a"
        type  = "String"
        value = "value-a"
      },
      {
        name  = "/tlz/param-b"
        type  = "StringList"
        value = "val1,val2"
      },
      {
        name  = "/tlz/param-c"
        type  = "SecureString"
        value = "secret"
      }
    ]
  }

  assert {
    condition     = length(aws_ssm_parameter.this) == 3
    error_message = "Three SSM parameters must be created."
  }

  assert {
    condition     = length(output.ssm_parameter_names) == 3
    error_message = "ssm_parameter_names must contain three entries."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/param-b"].type == "StringList"
    error_message = "StringList parameters must keep their type."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/param-c"].type == "SecureString"
    error_message = "SecureString parameters must keep their type."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/param-a"].tags["ManagedBy"] == "terraform"
    error_message = "default_tags must be applied to every parameter."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/param-c"].tags["Environment"] == "test"
    error_message = "All default_tags entries must be applied to every parameter."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b: Cross-account deployment warning check block
# -----------------------------------------------------------------------------
run "ssm_cross_account_warning_no_targets" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name  = "/tlz/mgmt-only"
        type  = "String"
        value = "local"
      }
    ]
  }

  # The check block passes (no warning) when no deployment_targets are set
  assert {
    condition     = length(aws_ssm_parameter.this) == 1
    error_message = "Parameter must be created without deployment targets."
  }
}

run "ssm_cross_account_warning_with_targets" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name               = "/tlz/shared-param"
        type               = "String"
        value              = "shared"
        deployment_targets = ["111111111111", "222222222222"]
      }
    ]
  }

  # The check block warns when deployment_targets are present
  expect_failures = [
    check.ssm_parameters_cross_account_warning,
  ]

  assert {
    condition     = length(aws_ssm_parameter.this) == 1
    error_message = "Parameter must be created even with deployment_targets."
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/shared-param"].name == "/tlz/shared-param"
    error_message = "Parameter name must match input."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "invalid_parameter_type_rejected" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name  = "/tlz/bad-type"
        type  = "Secret"
        value = "x"
      }
    ]
  }

  expect_failures = [var.ssm_parameters]
}

run "empty_parameter_name_rejected" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name  = ""
        type  = "String"
        value = "x"
      }
    ]
  }

  expect_failures = [var.ssm_parameters]
}

# key_id on a String or StringList entry is refused at plan time.
# Only SecureString values are KMS-encrypted; the SSM API rejects a KeyId for
# the other two types, which would otherwise surface only at apply.
run "regression_key_id_on_plain_string_rejected" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name   = "/tlz/plain-with-key"
        type   = "String"
        value  = "x"
        key_id = "alias/example"
      }
    ]
  }

  expect_failures = [var.ssm_parameters]
}

# -----------------------------------------------------------------------------
# A SecureString entry can name a customer-managed key (CKV_AWS_337). The
# per-entry key_id is the opt-in; its null default keeps the AWS-managed
# alias/aws/ssm key.
# -----------------------------------------------------------------------------
run "regression_securestring_customer_managed_key" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name   = "/tlz/cmk-param"
        type   = "SecureString"
        value  = "secret"
        key_id = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000"
      },
      {
        name  = "/tlz/default-key-param"
        type  = "SecureString"
        value = "secret"
      }
    ]
  }

  assert {
    condition     = aws_ssm_parameter.this["/tlz/cmk-param"].key_id == "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000"
    error_message = "A SecureString entry with key_id must be encrypted with that key."
  }

  # key_id is provider-computed, so an unset key is unknown at plan; the
  # observable is the entry's optional() default, which main.tf passes through.
  assert {
    condition     = var.ssm_parameters[1].key_id == null
    error_message = "A SecureString entry without key_id must default to null (AWS-managed alias/aws/ssm)."
  }
}

# -----------------------------------------------------------------------------
# key_id must name a KMS key at plan time, so a value such as
# "not-a-key-id-or-arn-or-alias" does not wait for apply to fail. key_id
# takes the four forms the SSM API documents --
# bare key id, key ARN, alias name, alias ARN, in any partition -- and nothing
# else; an empty string is refused as well (null is the way to the
# AWS-managed alias/aws/ssm key).
# -----------------------------------------------------------------------------
run "regression_key_id_malformed_rejected" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name   = "/tlz/bad-key"
        type   = "SecureString"
        value  = "secret"
        key_id = "not-a-key-id-or-arn-or-alias"
      }
    ]
  }

  expect_failures = [var.ssm_parameters]
}

run "regression_key_id_empty_rejected" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name   = "/tlz/empty-key"
        type   = "SecureString"
        value  = "secret"
        key_id = ""
      }
    ]
  }

  expect_failures = [var.ssm_parameters]
}

# A KMS ARN of the wrong resource type (a grant, not a key or an
# alias) is not a key reference either.
run "regression_key_id_wrong_resource_arn_rejected" {
  command = plan

  variables {
    ssm_parameters = [
      {
        name   = "/tlz/grant-key"
        type   = "SecureString"
        value  = "secret"
        key_id = "arn:aws:kms:eu-central-1:111111111111:grant/00000000-0000-0000-0000-000000000000"
      }
    ]
  }

  expect_failures = [var.ssm_parameters]
}

# The key_id check takes every documented form.
run "regression_key_id_documented_forms_accepted" {
  command = plan

  variables {
    ssm_parameters = [
      { name = "/tlz/k-id", type = "SecureString", value = "s", key_id = "00000000-0000-0000-0000-000000000000" },
      { name = "/tlz/k-mrk", type = "SecureString", value = "s", key_id = "mrk-0123456789abcdef0123456789abcdef" },
      { name = "/tlz/k-arn", type = "SecureString", value = "s", key_id = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000" },
      { name = "/tlz/k-arn-gov", type = "SecureString", value = "s", key_id = "arn:aws-us-gov:kms:us-gov-west-1:111111111111:key/mrk-0123456789abcdef0123456789abcdef" },
      { name = "/tlz/k-alias", type = "SecureString", value = "s", key_id = "alias/tlz/ssm-params_1" },
      { name = "/tlz/k-alias-aws", type = "SecureString", value = "s", key_id = "alias/aws/ssm" },
      { name = "/tlz/k-alias-arn", type = "SecureString", value = "s", key_id = "arn:aws-eusc:kms:eusc-de-east-1:111111111111:alias/tlz-ssm" },
    ]
  }

  assert {
    condition     = length(aws_ssm_parameter.this) == 7
    error_message = "Every documented key_id form (key id, multi-Region key id, key ARN, alias name, alias ARN) must pass plan."
  }
}
