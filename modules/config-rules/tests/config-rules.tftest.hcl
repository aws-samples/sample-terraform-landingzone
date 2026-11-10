# =============================================================================
# Config Rules Module Tests (modules/config-rules)
# =============================================================================
# Coverage:
#   - Toggle-off equivalent: all rule lists empty (module defaults) → zero resources
#   - Default configuration: single managed rule with default options
#   - Custom configuration: managed + management-only + custom rules, conformance
#     pack, auto-remediation, deployment_targets and global account exclusions
#   - Validation failures: Lambda ARN, execution frequency, remediation target
#     type, remediation attempts, excluded account IDs, unresolvable
#     deployment_targets, malformed OU IDs
#   - deployment_targets resolution covers account IDs, account names and OU
#     names
#
# Toggle scenario: enable_custom_rule_lambdas (default false) gates the
# configuration-supplied Lambda functions; run "no_rules_configured" sets it
# explicitly to false (zero resources), the lambda runs exercise it enabled.
# Every other resource is driven by a collection variable, so the disabled
# state is expressed by empty lists — same run, zero resources.

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }
}

mock_provider "archive" {}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-off — defaults and the disabled Lambda switch create
# nothing
# -----------------------------------------------------------------------------
run "no_rules_configured" {
  command = plan

  variables {
    enable_custom_rule_lambdas = false
  }

  assert {
    condition     = length(aws_lambda_function.config) == 0
    error_message = "No Lambda functions must be created when enable_custom_rule_lambdas is false."
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == 0
    error_message = "No org managed rules must be created without managed_rules."
  }

  assert {
    condition     = length(aws_config_config_rule.management_only) == 0
    error_message = "No management-only rules must be created without management_only_rules."
  }

  assert {
    condition     = length(aws_config_organization_custom_rule.this) == 0
    error_message = "No org custom rules must be created without custom_rules."
  }

  assert {
    condition     = length(aws_config_conformance_pack.this) == 0
    error_message = "No conformance packs must be created without conformance_packs."
  }

  assert {
    condition     = length(aws_config_remediation_configuration.this) == 0
    error_message = "No remediation configurations must be created without remediation_configs."
  }

  assert {
    condition     = output.managed_rule_count == 0 && output.custom_rule_count == 0 && output.conformance_pack_count == 0 && output.remediation_count == 0
    error_message = "All count outputs must be zero when no rules are configured."
  }

  assert {
    condition     = length(output.rule_arns) == 0 && length(output.conformance_pack_arns) == 0
    error_message = "ARN map outputs must be empty when no rules are configured."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — one managed rule, no extra options
# -----------------------------------------------------------------------------
run "default_managed_rule" {
  command = plan

  variables {
    managed_rules = [
      {
        name              = "s3-bucket-public-read-prohibited"
        source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
      }
    ]
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == 1
    error_message = "One org managed rule must be created."
  }

  assert {
    condition     = aws_config_organization_managed_rule.this["s3-bucket-public-read-prohibited"].rule_identifier == "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    error_message = "Managed rule identifier must match the input."
  }

  assert {
    condition     = aws_config_organization_managed_rule.this["s3-bucket-public-read-prohibited"].input_parameters == null
    error_message = "input_parameters must stay null when no parameters are supplied."
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this["s3-bucket-public-read-prohibited"].excluded_accounts) == 0
    error_message = "No accounts must be excluded without deployment_targets or global exclusions."
  }

  assert {
    condition     = output.managed_rule_count == 1
    error_message = "managed_rule_count output must report one rule."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — all rule kinds, targets and exclusions
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    account_ids = {
      "log-archive" = "111111111111"
      "audit"       = "222222222222"
      "workload"    = "333333333333"
    }

    global_excluded_accounts = ["444444444444"]

    managed_rules = [
      {
        name               = "iam-password-policy"
        source_identifier  = "IAM_PASSWORD_POLICY"
        input_parameters   = { MinimumPasswordLength = "14" }
        deployment_targets = ["111111111111", "222222222222"]
      }
    ]

    management_only_rules = [
      {
        name              = "root-account-mfa-enabled"
        source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
        input_parameters  = { MaxAccessKeyAge = "90" }
      }
    ]

    custom_rules = [
      {
        name                        = "tlz-tag-compliance"
        lambda_function_arn         = "arn:aws:lambda:eu-central-1:111111111111:function:tlz-tag-compliance"
        trigger_types               = ["ScheduledNotification"]
        maximum_execution_frequency = "Six_Hours"
        excluded_accounts           = ["555555555555"]
      }
    ]

    conformance_packs = [
      {
        name          = "tlz-operational-best-practices"
        template_body = "Resources:\n  Placeholder:\n    Type: AWS::Config::ConfigRule\n"
      }
    ]

    remediation_configs = [
      {
        rule_name                  = "s3-bucket-public-read-prohibited"
        target_id                  = "AWS-DisableS3BucketPublicReadWrite"
        automatic                  = true
        maximum_automatic_attempts = 3
        retry_attempt_seconds      = 120
        parameters = {
          AutomationAssumeRole = { static_values = ["arn:aws:iam::111111111111:role/tlz-remediation"] }
          S3BucketName         = { resource_value = "RESOURCE_ID" }
        }
      }
    ]
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == 1
    error_message = "One org managed rule must be created."
  }

  assert {
    condition     = aws_config_organization_managed_rule.this["iam-password-policy"].input_parameters == jsonencode({ MinimumPasswordLength = "14" })
    error_message = "Managed rule input_parameters must be JSON-encoded."
  }

  # deployment_targets resolution: accounts outside the targets are excluded
  assert {
    condition     = contains(aws_config_organization_managed_rule.this["iam-password-policy"].excluded_accounts, "333333333333")
    error_message = "Accounts outside deployment_targets must be excluded."
  }

  assert {
    condition     = !contains(aws_config_organization_managed_rule.this["iam-password-policy"].excluded_accounts, "111111111111")
    error_message = "Accounts inside deployment_targets must not be excluded."
  }

  assert {
    condition     = contains(aws_config_organization_managed_rule.this["iam-password-policy"].excluded_accounts, "444444444444")
    error_message = "global_excluded_accounts must always be excluded."
  }

  assert {
    condition     = length(aws_config_config_rule.management_only) == 1
    error_message = "One management-only rule must be created."
  }

  assert {
    condition     = one(aws_config_config_rule.management_only["root-account-mfa-enabled"].source).owner == "AWS"
    error_message = "Management-only rules must use the AWS-managed source owner."
  }

  assert {
    condition     = length(aws_config_organization_custom_rule.this) == 1
    error_message = "One org custom rule must be created."
  }

  assert {
    condition     = aws_config_organization_custom_rule.this["tlz-tag-compliance"].maximum_execution_frequency == "Six_Hours"
    error_message = "Custom rule execution frequency must match the input."
  }

  assert {
    condition = alltrue([
      contains(aws_config_organization_custom_rule.this["tlz-tag-compliance"].excluded_accounts, "555555555555"),
      contains(aws_config_organization_custom_rule.this["tlz-tag-compliance"].excluded_accounts, "444444444444"),
    ])
    error_message = "Custom rule exclusions must merge rule-level and global exclusions."
  }

  assert {
    condition     = length(aws_config_conformance_pack.this) == 1
    error_message = "One conformance pack must be created."
  }

  assert {
    condition     = length(aws_config_remediation_configuration.this) == 1
    error_message = "One remediation configuration must be created."
  }

  assert {
    condition     = aws_config_remediation_configuration.this["s3-bucket-public-read-prohibited"].maximum_automatic_attempts == 3
    error_message = "Remediation attempts must be applied when automatic is true."
  }

  assert {
    condition     = output.custom_rule_count == 1 && output.conformance_pack_count == 1 && output.remediation_count == 1
    error_message = "Count outputs must reflect the custom configuration."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b: Custom configuration — non-automatic remediation drops attempts
# -----------------------------------------------------------------------------
run "custom_manual_remediation" {
  command = plan

  variables {
    remediation_configs = [
      {
        rule_name = "s3-bucket-public-read-prohibited"
        target_id = "AWS-DisableS3BucketPublicReadWrite"
        automatic = false
      }
    ]
  }

  assert {
    condition     = aws_config_remediation_configuration.this["s3-bucket-public-read-prohibited"].maximum_automatic_attempts == null
    error_message = "maximum_automatic_attempts must be null for manual remediation."
  }

  assert {
    condition     = aws_config_remediation_configuration.this["s3-bucket-public-read-prohibited"].retry_attempt_seconds == null
    error_message = "retry_attempt_seconds must be null for manual remediation."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3c: Custom configuration — deployment_targets by account name and OU
# name
#
# If deployment_targets were only compared against account IDs, an OU name — or
# an account name — would match no account and every account would end up in
# excluded_accounts: the organization rule would exist but evaluate nothing.
# -----------------------------------------------------------------------------
run "custom_deployment_targets_by_name_and_ou" {
  command = plan

  variables {
    account_ids = {
      "audit"       = "111111111111"
      "log-archive" = "222222222222"
      "workload-a"  = "333333333333"
      "workload-b"  = "444444444444"
    }

    ou_name_to_id = {
      "Security"  = "ou-abc1-11111111"
      "Workloads" = "ou-abc1-22222222"
    }

    account_ou_ids = {
      "audit"       = "ou-abc1-11111111"
      "log-archive" = "ou-abc1-11111111"
      "workload-a"  = "ou-abc1-22222222"
      "workload-b"  = "ou-abc1-22222222"
    }

    managed_rules = [
      {
        name               = "ou-scoped-rule"
        source_identifier  = "IAM_PASSWORD_POLICY"
        deployment_targets = ["Security"]
      },
      {
        name               = "name-scoped-rule"
        source_identifier  = "ENCRYPTED_VOLUMES"
        deployment_targets = ["workload-a"]
      },
    ]

    custom_rules = [
      {
        name                = "mixed-scoped-rule"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:111111111111:function:tlz-check"
        deployment_targets  = ["Workloads", "111111111111"]
      },
    ]
  }

  # OU name resolves to the accounts inside that OU
  assert {
    condition = alltrue([
      !contains(aws_config_organization_managed_rule.this["ou-scoped-rule"].excluded_accounts, "111111111111"),
      !contains(aws_config_organization_managed_rule.this["ou-scoped-rule"].excluded_accounts, "222222222222"),
    ])
    error_message = "Accounts inside the targeted OU must not be excluded."
  }

  assert {
    condition = alltrue([
      contains(aws_config_organization_managed_rule.this["ou-scoped-rule"].excluded_accounts, "333333333333"),
      contains(aws_config_organization_managed_rule.this["ou-scoped-rule"].excluded_accounts, "444444444444"),
    ])
    error_message = "Accounts outside the targeted OU must be excluded."
  }

  # An OU-scoped rule must never exclude every account
  assert {
    condition     = length(aws_config_organization_managed_rule.this["ou-scoped-rule"].excluded_accounts) < 4
    error_message = "An OU target must leave at least one account in scope — a full exclusion means the rule evaluates nothing."
  }

  # Account name resolves through account_ids
  assert {
    condition = alltrue([
      !contains(aws_config_organization_managed_rule.this["name-scoped-rule"].excluded_accounts, "333333333333"),
      contains(aws_config_organization_managed_rule.this["name-scoped-rule"].excluded_accounts, "111111111111"),
    ])
    error_message = "An account name target must resolve through account_ids."
  }

  # Mixed target list: OU name plus explicit account ID
  assert {
    condition = alltrue([
      !contains(aws_config_organization_custom_rule.this["mixed-scoped-rule"].excluded_accounts, "333333333333"),
      !contains(aws_config_organization_custom_rule.this["mixed-scoped-rule"].excluded_accounts, "444444444444"),
      !contains(aws_config_organization_custom_rule.this["mixed-scoped-rule"].excluded_accounts, "111111111111"),
      contains(aws_config_organization_custom_rule.this["mixed-scoped-rule"].excluded_accounts, "222222222222"),
    ])
    error_message = "A mixed target list must resolve OU names and account IDs together."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3d: Custom configuration — OU without member accounts is reported
# -----------------------------------------------------------------------------
run "custom_deployment_target_ou_without_accounts_is_reported" {
  command = plan

  variables {
    account_ids = {
      "audit" = "111111111111"
    }

    ou_name_to_id = {
      "Sandbox" = "ou-abc1-33333333"
    }

    account_ou_ids = {
      "audit" = "ou-abc1-11111111"
    }

    managed_rules = [
      {
        name               = "empty-ou-rule"
        source_identifier  = "IAM_PASSWORD_POLICY"
        deployment_targets = ["Sandbox"]
      },
    ]
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == 1
    error_message = "The rule is still created — the empty target set is a warning, not an error."
  }

  expect_failures = [
    check.deployment_targets_resolve_to_accounts,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4a: Validation failure — invalid Lambda function ARN
# -----------------------------------------------------------------------------
run "invalid_custom_rule_lambda_arn_rejected" {
  command = plan

  variables {
    custom_rules = [
      {
        name                = "tlz-broken"
        lambda_function_arn = "arn:aws:s3:::not-a-lambda"
      }
    ]
  }

  expect_failures = [
    var.custom_rules,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4b: Validation failure — invalid maximum_execution_frequency
# -----------------------------------------------------------------------------
run "invalid_custom_rule_frequency_rejected" {
  command = plan

  variables {
    custom_rules = [
      {
        name                        = "tlz-broken-frequency"
        lambda_function_arn         = "arn:aws:lambda:eu-central-1:111111111111:function:tlz-broken"
        maximum_execution_frequency = "Two_Hours"
      }
    ]
  }

  expect_failures = [
    var.custom_rules,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4c: Validation failure — unsupported remediation target type
# -----------------------------------------------------------------------------
run "invalid_remediation_target_type_rejected" {
  command = plan

  variables {
    remediation_configs = [
      {
        rule_name   = "some-rule"
        target_id   = "some-target"
        target_type = "LAMBDA"
      }
    ]
  }

  expect_failures = [
    var.remediation_configs,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4d: Validation failure — remediation attempts out of range
# -----------------------------------------------------------------------------
run "invalid_remediation_attempts_rejected" {
  command = plan

  variables {
    remediation_configs = [
      {
        rule_name                  = "some-rule"
        target_id                  = "some-target"
        maximum_automatic_attempts = 99
      }
    ]
  }

  expect_failures = [
    var.remediation_configs,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4e: Validation failure — invalid global excluded account ID
# -----------------------------------------------------------------------------
run "invalid_global_excluded_account_rejected" {
  command = plan

  variables {
    global_excluded_accounts = ["12345"]
  }

  expect_failures = [
    var.global_excluded_accounts,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4f: Validation failure — unresolvable managed rule deployment target
# -----------------------------------------------------------------------------
run "unresolvable_managed_rule_deployment_target_rejected" {
  command = plan

  variables {
    account_ids = {
      "audit" = "111111111111"
    }

    managed_rules = [
      {
        name               = "typo-target-rule"
        source_identifier  = "IAM_PASSWORD_POLICY"
        deployment_targets = ["Aduit"]
      },
    ]
  }

  expect_failures = [
    var.managed_rules,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4g: Validation failure — unresolvable custom rule deployment target
# -----------------------------------------------------------------------------
run "unresolvable_custom_rule_deployment_target_rejected" {
  command = plan

  variables {
    custom_rules = [
      {
        name                = "typo-target-custom-rule"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:111111111111:function:tlz-check"
        deployment_targets  = ["Workloads"]
      },
    ]
  }

  expect_failures = [
    var.custom_rules,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4h: Validation failure — malformed OU ID in account_ou_ids
# -----------------------------------------------------------------------------
run "invalid_account_ou_id_rejected" {
  command = plan

  variables {
    account_ou_ids = {
      "audit" = "111111111111"
    }
  }

  expect_failures = [
    var.account_ou_ids,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4i: Validation failure — malformed OU ID in ou_name_to_id
# -----------------------------------------------------------------------------
run "invalid_ou_name_to_id_rejected" {
  command = plan

  variables {
    ou_name_to_id = {
      "Security" = "Security"
    }
  }

  expect_failures = [
    var.ou_name_to_id,
  ]
}

# -----------------------------------------------------------------------------
# OU resolution inputs from the stack
#
# stacks/management/config-rules takes ou_name_to_id from the organization
# stack and derives account_ou_ids from the accounts output, whose parent_id per
# account is the ID of the OU the account was placed in. Without both maps an OU
# name in deployment_targets cannot resolve.
#
# The two runs below hold the properties that derivation depends on and that no
# other scenario covers.
# -----------------------------------------------------------------------------

# The derivation keys account_ou_ids by account name, exactly like account_ids
# (the accounts output supplies name, id and parent_id together). The run shows
# what happens if the two maps ever disagree on a name: the OU resolves to no
# account and the rule would evaluate nothing — reported, not silent.
run "regression_ou_resolution_needs_matching_account_names" {
  command = plan

  variables {
    account_ids = {
      "workload-a" = "333333333333"
    }

    ou_name_to_id = {
      "Workloads" = "ou-abc1-22222222"
    }

    # Same account, different spelling of the name: the OU membership can no
    # longer be joined to an account ID.
    account_ou_ids = {
      "Workload-A" = "ou-abc1-22222222"
    }

    managed_rules = [
      {
        name               = "ou-scoped-rule"
        source_identifier  = "IAM_PASSWORD_POLICY"
        deployment_targets = ["Workloads"]
      },
    ]
  }

  assert {
    condition     = contains(aws_config_organization_managed_rule.this["ou-scoped-rule"].excluded_accounts, "333333333333")
    error_message = "Without a matching account name the OU membership cannot be resolved and the account is excluded."
  }

  expect_failures = [
    check.deployment_targets_resolve_to_accounts,
  ]
}

# An account placed directly under the organization root carries a root ID as
# parent_id, not an OU ID. Both validations accept the r-<id> form, so the
# derived map may legitimately contain one — and the resolution must work for it.
run "regression_ou_resolution_accepts_a_root_parent" {
  command = plan

  variables {
    account_ids = {
      "workload-a" = "333333333333"
      "workload-b" = "444444444444"
    }

    ou_name_to_id = {
      "Root"      = "r-abc1"
      "Workloads" = "ou-abc1-22222222"
    }

    account_ou_ids = {
      "workload-a" = "r-abc1"
      "workload-b" = "ou-abc1-22222222"
    }

    managed_rules = [
      {
        name               = "root-scoped-rule"
        source_identifier  = "IAM_PASSWORD_POLICY"
        deployment_targets = ["Root"]
      },
    ]
  }

  assert {
    condition     = !contains(aws_config_organization_managed_rule.this["root-scoped-rule"].excluded_accounts, "333333333333")
    error_message = "An account whose parent is the organization root must resolve through a root ID in account_ou_ids."
  }

  assert {
    condition     = contains(aws_config_organization_managed_rule.this["root-scoped-rule"].excluded_accounts, "444444444444")
    error_message = "An account in another OU must stay excluded from a root-scoped rule."
  }
}

# -----------------------------------------------------------------------------
# Scenario: Rule metadata and selectors — defaults keep the plan
# -----------------------------------------------------------------------------
# Rules and remediations that set none of the metadata or selector fields plan
# without them: no description, no tags, no scope selectors, and the
# remediation target passes through unchanged.
run "regression_rule_metadata_defaults_keep_the_plan" {
  command = plan

  variables {
    managed_rules = [
      { name = "plain-managed", source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED" }
    ]
    management_only_rules = [
      { name = "plain-management", source_identifier = "IAM_PASSWORD_POLICY" }
    ]
    custom_rules = [
      {
        name                = "plain-custom"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:111111111111:function:evaluator"
      }
    ]
    remediation_configs = [
      { rule_name = "plain-managed", target_id = "AWS-PublishSNSNotification" }
    ]
  }

  assert {
    condition     = aws_config_organization_managed_rule.this["plain-managed"].description == null
    error_message = "Without a description the managed rule must carry none."
  }

  assert {
    condition     = aws_config_config_rule.management_only["plain-management"].tags == null
    error_message = "Without tags the management-only rule must carry none."
  }

  assert {
    condition = (
      aws_config_organization_custom_rule.this["plain-custom"].resource_id_scope == null &&
      aws_config_organization_custom_rule.this["plain-custom"].tag_key_scope == null &&
      aws_config_organization_custom_rule.this["plain-custom"].tag_value_scope == null
    )
    error_message = "Without selectors the custom rule must carry none."
  }

  assert {
    condition     = aws_config_remediation_configuration.this["plain-managed"].target_id == "AWS-PublishSNSNotification"
    error_message = "Without target_account_name the remediation target must pass through unchanged."
  }

  assert {
    condition     = aws_config_remediation_configuration.this["plain-managed"].target_version == null
    error_message = "Without target_version the remediation must carry none."
  }
}

# -----------------------------------------------------------------------------
# Scenario: Rule metadata and selectors reach the resources
# -----------------------------------------------------------------------------
run "rule_metadata_and_selectors_reach_the_resources" {
  command = plan

  variables {
    account_ids = {
      "Audit" = "333333333333"
    }
    managed_rules = [
      {
        name              = "described-managed"
        source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
        description       = "Public read access on buckets is prohibited"
      }
    ]
    management_only_rules = [
      {
        name              = "tagged-management"
        source_identifier = "IAM_PASSWORD_POLICY"
        description       = "Password policy of the management account"
        tags              = { Compliance = "baseline" }
      }
    ]
    custom_rules = [
      {
        name                 = "scoped-by-resource"
        lambda_function_arn  = "arn:aws:lambda:eu-central-1:111111111111:function:evaluator"
        description          = "Evaluates one named bucket"
        resource_types_scope = ["AWS::S3::Bucket"]
        resource_id_scope    = "central-data"
      },
      {
        name                = "scoped-by-tag"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:111111111111:function:evaluator"
        tag_key_scope       = "Environment"
        tag_value_scope     = "Production"
      }
    ]
    remediation_configs = [
      {
        rule_name           = "described-managed"
        target_id           = "org-remediation-document"
        target_version      = "2"
        target_account_name = "Audit"
      }
    ]
  }

  assert {
    condition     = aws_config_organization_managed_rule.this["described-managed"].description == "Public read access on buckets is prohibited"
    error_message = "The managed rule description must reach the resource."
  }

  assert {
    condition = (
      aws_config_config_rule.management_only["tagged-management"].description == "Password policy of the management account" &&
      aws_config_config_rule.management_only["tagged-management"].tags["Compliance"] == "baseline"
    )
    error_message = "Description and tags must reach the management-only rule."
  }

  assert {
    condition = (
      aws_config_organization_custom_rule.this["scoped-by-resource"].description == "Evaluates one named bucket" &&
      aws_config_organization_custom_rule.this["scoped-by-resource"].resource_id_scope == "central-data" &&
      aws_config_organization_custom_rule.this["scoped-by-tag"].tag_key_scope == "Environment" &&
      aws_config_organization_custom_rule.this["scoped-by-tag"].tag_value_scope == "Production"
    )
    error_message = "Selectors and description must reach the custom rules."
  }

  assert {
    condition     = aws_config_remediation_configuration.this["described-managed"].target_id == "arn:aws:ssm:eu-central-1:333333333333:document/org-remediation-document"
    error_message = "target_account_name must turn the remediation target into the cross-account document ARN."
  }

  assert {
    condition     = aws_config_remediation_configuration.this["described-managed"].target_version == "2"
    error_message = "target_version must reach the remediation configuration."
  }
}

# -----------------------------------------------------------------------------
# Scenario: Rule metadata and selectors — validation failures
# -----------------------------------------------------------------------------
run "rule_description_too_long_rejected" {
  command = plan
  variables {
    managed_rules = [
      {
        name              = "overlong"
        source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
        description       = join("", [for i in range(26) : "tenletters"])
      }
    ]
  }
  expect_failures = [var.managed_rules]
}

run "custom_rule_mixed_selector_forms_rejected" {
  command = plan
  variables {
    custom_rules = [
      {
        name                 = "mixed-selectors"
        lambda_function_arn  = "arn:aws:lambda:eu-central-1:111111111111:function:evaluator"
        resource_types_scope = ["AWS::S3::Bucket"]
        tag_key_scope        = "Environment"
      }
    ]
  }
  expect_failures = [var.custom_rules]
}

run "custom_rule_resource_id_without_single_type_rejected" {
  command = plan
  variables {
    custom_rules = [
      {
        name                = "id-without-type"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:111111111111:function:evaluator"
        resource_id_scope   = "central-data"
      }
    ]
  }
  expect_failures = [var.custom_rules]
}

run "custom_rule_tag_value_without_key_rejected" {
  command = plan
  variables {
    custom_rules = [
      {
        name                = "value-without-key"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:111111111111:function:evaluator"
        tag_value_scope     = "Production"
      }
    ]
  }
  expect_failures = [var.custom_rules]
}

run "remediation_target_version_with_whitespace_rejected" {
  command = plan
  variables {
    remediation_configs = [
      { rule_name = "some-rule", target_id = "doc", target_version = "1 beta" }
    ]
  }
  expect_failures = [var.remediation_configs]
}

run "remediation_unknown_target_account_rejected" {
  command = plan
  variables {
    account_ids = { "Audit" = "333333333333" }
    remediation_configs = [
      { rule_name = "some-rule", target_id = "doc", target_account_name = "Security" }
    ]
  }
  expect_failures = [var.remediation_configs]
}

run "remediation_target_account_with_arn_target_rejected" {
  command = plan
  variables {
    account_ids = { "Audit" = "333333333333" }
    remediation_configs = [
      {
        rule_name           = "some-rule"
        target_id           = "arn:aws:ssm:eu-central-1:333333333333:document/doc"
        target_account_name = "Audit"
      }
    ]
  }
  expect_failures = [var.remediation_configs]
}

run "management_rule_reserved_tag_key_rejected" {
  command = plan
  variables {
    management_only_rules = [
      {
        name              = "reserved-tag"
        source_identifier = "IAM_PASSWORD_POLICY"
        tags              = { "aws:reserved" = "value" }
      }
    ]
  }
  expect_failures = [var.management_only_rules]
}

# -----------------------------------------------------------------------------
# Scenario: configuration-supplied rule and remediation Lambdas
# -----------------------------------------------------------------------------
# enable_custom_rule_lambdas gates the module-created functions; off, every
# function ARN comes from outside. The code
# arrives as a string from the configuration layer and is packaged with
# archive_file; the token __REMEDIATION_LAMBDA_ARN__ hands the created
# remediation function to the automation document.
run "regression_external_lambda_arn_keeps_the_plan" {
  command = plan
  variables {
    custom_rules = [
      {
        name                = "s3-bucket-check"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:123456789012:function:existing-evaluator"
      }
    ]
  }
  assert {
    condition     = length(aws_lambda_function.config) == 0 && length(aws_iam_role.config_lambda) == 0 && length(aws_lambda_permission.config_invoke) == 0
    error_message = "An entry of the old form (external ARN, switch off) must create no function, no role and no permission."
  }
  assert {
    condition     = aws_config_organization_custom_rule.this["s3-bucket-check"].lambda_function_arn == "arn:aws:lambda:eu-central-1:123456789012:function:existing-evaluator"
    error_message = "An entry of the old form must carry exactly the external evaluator ARN — the form of every existing plan."
  }
}

run "custom_rule_lambda_reaches_function_role_and_permission" {
  command = plan
  variables {
    enable_custom_rule_lambdas = true
    custom_rules = [
      {
        name = "s3-bucket-check"
        lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "index.handler"
          runtime     = "python3.12"
          timeout     = 60
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"config:PutEvaluations\",\"Resource\":\"*\"}]}"
        }
      }
    ]
    remediation_configs = [
      {
        rule_name = "s3-bucket-check"
        target_id = "tlz-fix-bucket-policy"
        parameters = {
          FunctionArn = {
            static_values = ["__REMEDIATION_LAMBDA_ARN__"]
          }
        }
        target_document_lambda = {
          source_code = "exports.handler = async () => ({});\n"
          handler     = "remediate.handler"
          runtime     = "nodejs20.x"
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:PutBucketPolicy\",\"Resource\":\"*\"}]}"
        }
      }
    ]
  }
  assert {
    condition     = length(aws_lambda_function.config) == 2 && length(aws_iam_role.config_lambda) == 2 && length(aws_iam_role_policy.config_lambda) == 2 && length(aws_iam_role_policy.config_lambda_logs) == 2
    error_message = "One evaluator and one remediation function with their roles and both policies each must be planned."
  }
  assert {
    condition     = aws_lambda_function.config["tlz-config-rule-s3-bucket-check"].handler == "index.handler" && aws_lambda_function.config["tlz-config-rule-s3-bucket-check"].runtime == "python3.12" && aws_lambda_function.config["tlz-config-rule-s3-bucket-check"].timeout == 60
    error_message = "The evaluator function must carry handler, runtime and timeout from the entry."
  }
  assert {
    condition     = aws_lambda_function.config["tlz-remediation-s3-bucket-check"].runtime == "nodejs20.x" && aws_lambda_function.config["tlz-remediation-s3-bucket-check"].timeout == 30
    error_message = "The remediation function must carry its runtime and the timeout default of 30 seconds."
  }
  assert {
    condition     = aws_lambda_function.config["tlz-config-rule-s3-bucket-check"].reserved_concurrent_executions == 10
    error_message = "The functions must carry the module convention of a bounded concurrency reservation."
  }
  assert {
    condition     = endswith(data.archive_file.config_lambda["tlz-config-rule-s3-bucket-check"].output_path, "lambda-packages/tlz-config-rule-s3-bucket-check.zip")
    error_message = "The evaluator archive must be packaged under the module's lambda-packages directory."
  }
  assert {
    condition     = one(data.archive_file.config_lambda["tlz-config-rule-s3-bucket-check"].source).filename == "index.py" && one(data.archive_file.config_lambda["tlz-remediation-s3-bucket-check"].source).filename == "remediate.js"
    error_message = "The source file name inside the archive must follow the handler's module part and the runtime's language."
  }
  assert {
    condition     = strcontains(aws_iam_role_policy.config_lambda["tlz-config-rule-s3-bucket-check"].policy, "config:PutEvaluations")
    error_message = "The execution role must carry the configuration-supplied policy."
  }
  assert {
    condition     = strcontains(aws_iam_role_policy.config_lambda_logs["tlz-config-rule-s3-bucket-check"].policy, "log-group:/aws/lambda/tlz-config-rule-s3-bucket-check:*")
    error_message = "The module-owned log policy must be limited to the function's own log group."
  }
  assert {
    condition     = length(aws_lambda_permission.config_invoke) == 1 && aws_lambda_permission.config_invoke["s3-bucket-check"].principal == "config.amazonaws.com"
    error_message = "Exactly the evaluator function must carry the Config invocation permission — the remediation function is invoked through the automation role."
  }
}

run "custom_rule_lambda_form_errors_rejected" {
  command = plan
  variables {
    enable_custom_rule_lambdas = true
    custom_rules = [
      {
        name = "bad-runtime"
        lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "index.handler"
          runtime     = "python2.7"
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        }
      },
      {
        name = "bad-timeout"
        lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "index.handler"
          runtime     = "python3.12"
          timeout     = 901
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        }
      },
      {
        name = "bad-handler"
        lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "nodothandler"
          runtime     = "python3.12"
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        }
      },
      {
        name = "bad-policy"
        lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "index.handler"
          runtime     = "python3.12"
          role_policy = "{\"Version\":\"2012-10-17\"}"
        }
      }
    ]
  }
  expect_failures = [var.custom_rules]
}

run "custom_rule_lambda_source_ambiguity_rejected" {
  command = plan
  variables {
    enable_custom_rule_lambdas = true
    custom_rules = [
      {
        name                = "both-sources"
        lambda_function_arn = "arn:aws:lambda:eu-central-1:123456789012:function:existing"
        lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "index.handler"
          runtime     = "python3.12"
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        }
      },
      {
        name = "no-source"
      }
    ]
  }
  expect_failures = [var.custom_rules]
}

run "custom_rule_lambda_without_switch_rejected" {
  command = plan
  variables {
    custom_rules = [
      {
        name = "gated"
        lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "index.handler"
          runtime     = "python3.12"
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        }
      }
    ]
  }
  expect_failures = [var.custom_rules]
}

run "remediation_lambda_token_coupling_rejected" {
  command = plan
  variables {
    enable_custom_rule_lambdas = true
    remediation_configs = [
      {
        rule_name = "lambda-without-token"
        target_id = "tlz-fix-a"
        target_document_lambda = {
          source_code = "def handler(event, context):\n    return {}\n"
          handler     = "index.handler"
          runtime     = "python3.12"
          role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        }
      },
      {
        rule_name = "token-without-lambda"
        target_id = "tlz-fix-b"
        parameters = {
          FunctionArn = {
            static_values = ["__REMEDIATION_LAMBDA_ARN__"]
          }
        }
      }
    ]
  }
  expect_failures = [var.remediation_configs]
}

# -----------------------------------------------------------------------------
# resource_types_scope reaches the organization rule
# -----------------------------------------------------------------------------
# An attribute the object type does not declare is dropped by the type
# conversion, and the rule would evaluate all recorded resource types. The
# attribute exists on managed_rules and feeds
# aws_config_organization_managed_rule; an empty list keeps the argument null
# (behaviour-preserving for entries without a scope).

run "managed_rule_resource_types_scope" {
  command = plan

  variables {
    managed_rules = [
      {
        name                 = "scoped-rule"
        source_identifier    = "S3_BUCKET_LOGGING_ENABLED"
        resource_types_scope = ["AWS::S3::Bucket"]
      },
      {
        name              = "unscoped-rule"
        source_identifier = "CLOUD_TRAIL_ENABLED"
      },
    ]
  }

  assert {
    condition     = aws_config_organization_managed_rule.this["scoped-rule"].resource_types_scope == toset(["AWS::S3::Bucket"])
    error_message = "resource_types_scope of a managed rule must reach aws_config_organization_managed_rule."
  }

  assert {
    condition     = aws_config_organization_managed_rule.this["unscoped-rule"].resource_types_scope == null
    error_message = "A managed rule without resource_types_scope must keep the argument null (behaviour-preserving)."
  }
}

# -----------------------------------------------------------------------------
# conformance_packs excluded_accounts is refused
#
# aws_config_conformance_pack is account-level and has no exclusion list, so a
# configured exclusion would silently do nothing. The module refuses it instead.
# -----------------------------------------------------------------------------
run "conformance_pack_excluded_accounts_rejected" {
  command = plan

  variables {
    conformance_packs = [
      {
        name              = "tlz-operational-best-practices"
        template_body     = "Resources:\n  Placeholder:\n    Type: AWS::Config::ConfigRule\n"
        excluded_accounts = ["555555555555"]
      }
    ]
  }

  expect_failures = [
    var.conformance_packs,
  ]
}
