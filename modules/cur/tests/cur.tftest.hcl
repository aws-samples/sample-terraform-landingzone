# =============================================================================
# CUR Module Tests (modules/cur)
# =============================================================================
# Mandatory scenarios:
#   1. Toggle-Off — the module has two independent enable_* toggles, both are
#      covered with a dedicated off-scenario:
#      a) enable_cost_and_usage_report = false => zero resources of the module.
#      b) enable_dedicated_bucket = false (with CUR enabled) => zero resources
#         of the dedicated-bucket resource group.
#   2. Default configuration — enabled with a defaulted cur_config, report
#      written to the injected central log bucket.
#   3. Custom configuration — custom report settings, explicit bucket region,
#      dedicated CUR bucket with its own KMS key.
#   4. Validation failures — for every validated variable of the module.
#
# Additionally covered: the partition guard for aws-eusc (run-level
# override_data), where CUR resources are skipped and the check block warns,
# and the two preconditions of the report definition (hard failures, not
# warnings): the provider region must be us-east-1, and an external bucket
# (enable_dedicated_bucket = false) requires an explicit s3_bucket_region —
# the provider-region fallback belongs to the dedicated bucket alone.
#
# Providers used directly by the module: aws (default only, no aliases).
# data.aws_region.current.region is pinned because the AWS provider validates
# s3_region against a fixed region list — a randomly generated mock value
# would be rejected.

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
      account_id = "123456789012"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "us-east-1"
    }
  }
}

variables {
  s3_bucket_name = "tlz-central-logs-210987654321-us-east-1"
}

# -----------------------------------------------------------------------------
# Scenario 1a: Toggle-Off — enable_cost_and_usage_report = false, no resources
#
# Every resource declared by the module is asserted to be absent, including the
# dedicated-bucket group, which is additionally forced on to prove that the
# outer toggle wins over enable_dedicated_bucket.
# -----------------------------------------------------------------------------
run "cur_disabled" {
  command = plan

  variables {
    enable_cost_and_usage_report = false
    enable_dedicated_bucket      = true
  }

  assert {
    condition     = length(aws_cur_report_definition.this) == 0
    error_message = "CUR report must not be created when disabled."
  }

  assert {
    condition     = length(aws_s3_bucket.cur) == 0
    error_message = "No dedicated CUR bucket must be created when CUR is disabled."
  }

  assert {
    condition     = length(aws_kms_key.cur) == 0
    error_message = "No CUR KMS key must be created when CUR is disabled."
  }

  assert {
    condition     = length(aws_kms_alias.cur) == 0
    error_message = "No CUR KMS alias must be created when CUR is disabled."
  }

  assert {
    condition = alltrue([
      length(aws_s3_bucket_versioning.cur) == 0,
      length(aws_s3_bucket_server_side_encryption_configuration.cur) == 0,
      length(aws_s3_bucket_public_access_block.cur) == 0,
      length(aws_s3_bucket_lifecycle_configuration.cur) == 0,
      length(aws_s3_bucket_policy.cur) == 0,
    ])
    error_message = "No dedicated CUR bucket settings must be created when CUR is disabled."
  }

  assert {
    condition     = output.cur_report_name == ""
    error_message = "CUR report name must be empty when disabled."
  }

  assert {
    condition     = output.cur_bucket_name == "" && output.cur_bucket_arn == "" && output.cur_kms_key_arn == ""
    error_message = "All bucket-related outputs must be empty when disabled."
  }
}

# -----------------------------------------------------------------------------
# Scenario 1b: Module defaults — enable_cost_and_usage_report defaults to false
# -----------------------------------------------------------------------------
run "module_defaults_create_nothing" {
  command = plan

  assert {
    condition     = length(aws_cur_report_definition.this) == 0
    error_message = "Module defaults must not create a CUR report."
  }

  assert {
    condition     = length(aws_s3_bucket.cur) == 0
    error_message = "Module defaults must not create a dedicated CUR bucket."
  }
}

# -----------------------------------------------------------------------------
# Scenario 1c: Toggle-Off for the second toggle — enable_dedicated_bucket = false
#
# CUR itself stays enabled, so this isolates the dedicated-bucket toggle: none
# of its resources may be planned, and the report falls back to the injected
# central log bucket.
# -----------------------------------------------------------------------------
run "dedicated_bucket_disabled" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = false
    s3_bucket_region             = "us-east-1"
  }

  assert {
    condition = alltrue([
      length(aws_kms_key.cur) == 0,
      length(aws_kms_alias.cur) == 0,
      length(aws_s3_bucket.cur) == 0,
      length(aws_s3_bucket_versioning.cur) == 0,
      length(aws_s3_bucket_server_side_encryption_configuration.cur) == 0,
      length(aws_s3_bucket_public_access_block.cur) == 0,
      length(aws_s3_bucket_lifecycle_configuration.cur) == 0,
      length(aws_s3_bucket_policy.cur) == 0,
    ])
    error_message = "No dedicated bucket resource must be created when enable_dedicated_bucket is false."
  }

  assert {
    condition     = output.cur_bucket_name == "" && output.cur_bucket_arn == "" && output.cur_kms_key_arn == ""
    error_message = "All dedicated-bucket outputs must be empty when enable_dedicated_bucket is false."
  }

  assert {
    condition     = length(aws_cur_report_definition.this) == 1
    error_message = "The CUR report must still be created when only the dedicated bucket is disabled."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_bucket == "tlz-central-logs-210987654321-us-east-1"
    error_message = "Without a dedicated bucket the report must fall back to the injected bucket name."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — enabled, defaults for cur_config
# -----------------------------------------------------------------------------
run "cur_enabled_default_config" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    # Required since the external-bucket precondition: the injected central
    # log bucket is an external bucket, so its region must be stated. The
    # fallback to the provider region is pinned in scenario 5 on the
    # dedicated bucket, the only case in which it still exists.
    s3_bucket_region = "us-east-1"
  }

  assert {
    condition     = length(aws_cur_report_definition.this) == 1
    error_message = "CUR report must be created when enabled."
  }

  assert {
    condition     = output.cur_report_name == "tlz-cost-usage-report"
    error_message = "CUR report name must match default."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].time_unit == "DAILY"
    error_message = "CUR time unit must default to DAILY."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].format == "Parquet"
    error_message = "CUR format must default to Parquet."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_prefix == "cur"
    error_message = "CUR S3 prefix must default to cur."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_bucket == "tlz-central-logs-210987654321-us-east-1"
    error_message = "CUR must use the injected S3 bucket name."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_region == "us-east-1"
    error_message = "The explicit s3_bucket_region must reach the report definition."
  }

  assert {
    condition     = length(aws_s3_bucket.cur) == 0
    error_message = "No dedicated bucket must be created while enable_dedicated_bucket is false."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration
# -----------------------------------------------------------------------------
run "cur_enabled_custom_config" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    s3_bucket_region             = "eu-central-1"
    cur_config = {
      report_name                = "my-custom-report"
      s3_prefix                  = "custom-cur"
      time_unit                  = "MONTHLY"
      format                     = "textORcsv"
      compression                = "GZIP"
      additional_schema_elements = ["RESOURCES"]
    }
  }

  assert {
    condition     = output.cur_report_name == "my-custom-report"
    error_message = "CUR report name must match custom config."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_prefix == "custom-cur"
    error_message = "CUR S3 prefix must match custom config."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].time_unit == "MONTHLY"
    error_message = "CUR time unit must match custom config."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].compression == "GZIP"
    error_message = "CUR compression must match custom config."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_region == "eu-central-1"
    error_message = "An explicit s3_bucket_region must take precedence over the current region."
  }
}

run "cur_s3_bucket_injection" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    s3_bucket_name               = "custom-bucket-name"
    s3_bucket_region             = "us-east-1"
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_bucket == "custom-bucket-name"
    error_message = "CUR must use the provided S3 bucket name."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b: Custom configuration with a dedicated, encrypted CUR bucket
# -----------------------------------------------------------------------------
run "cur_dedicated_bucket" {
  command = plan

  variables {
    enable_cost_and_usage_report           = true
    enable_dedicated_bucket                = true
    force_destroy                          = true
    kms_key_administrators                 = ["arn:aws:iam::123456789012:role/KmsAdmin"]
    noncurrent_version_expiration_days     = 30
    abort_incomplete_multipart_upload_days = 3
  }

  assert {
    condition     = length(aws_s3_bucket.cur) == 1
    error_message = "A dedicated CUR bucket must be created when enable_dedicated_bucket is true."
  }

  assert {
    condition     = aws_s3_bucket.cur[0].bucket == "tlz-cur-123456789012-us-east-1"
    error_message = "The dedicated CUR bucket must follow the tlz-cur-<account>-<region> convention."
  }

  assert {
    condition     = aws_s3_bucket.cur[0].force_destroy == true
    error_message = "force_destroy must be propagated to the dedicated bucket."
  }

  assert {
    condition     = length(aws_kms_key.cur) == 1 && length(aws_kms_alias.cur) == 1
    error_message = "A dedicated KMS key and alias must be created for the CUR bucket."
  }

  assert {
    condition     = aws_kms_alias.cur[0].name == "alias/tlz/cur/kms"
    error_message = "The CUR KMS alias must be alias/tlz/cur/kms."
  }

  assert {
    condition     = aws_kms_key.cur[0].enable_key_rotation == true
    error_message = "The CUR KMS key must have rotation enabled."
  }

  assert {
    condition     = strcontains(aws_kms_key.cur[0].policy, "arn:aws:iam::123456789012:role/KmsAdmin")
    error_message = "kms_key_administrators must be rendered into the CUR KMS key policy."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.cur[0].block_public_acls == true && aws_s3_bucket_public_access_block.cur[0].restrict_public_buckets == true
    error_message = "The dedicated CUR bucket must block all public access."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.cur[0].versioning_configuration).status == "Enabled"
    error_message = "Versioning must be enabled on the dedicated CUR bucket."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.cur[0].rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "The dedicated CUR bucket must be encrypted with the dedicated KMS key."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.cur[0].rule).noncurrent_version_expiration[0].noncurrent_days == 30
    error_message = "noncurrent_version_expiration_days must be applied to the lifecycle rule."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.cur[0].rule).abort_incomplete_multipart_upload[0].days_after_initiation == 3
    error_message = "abort_incomplete_multipart_upload_days must be applied to the lifecycle rule."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3c: Partition guard — CUR is skipped in aws-eusc and warns
# -----------------------------------------------------------------------------
run "cur_skipped_in_eusc_partition" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
  }

  expect_failures = [
    check.cur_eusc_warning,
  ]

  assert {
    condition     = length(aws_cur_report_definition.this) == 0
    error_message = "No CUR report must be created in the aws-eusc partition."
  }

  assert {
    condition     = length(aws_s3_bucket.cur) == 0
    error_message = "No dedicated CUR bucket must be created in the aws-eusc partition."
  }

  assert {
    condition     = output.cur_report_name == ""
    error_message = "cur_report_name must be empty in the aws-eusc partition."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3e: Region guard — the CUR API exists only in us-east-1
#
# Without the precondition a provider in any other aws-partition region would
# pass plan and fail at apply, after the dedicated bucket group may
# already exist. The precondition is a hard failure, deliberately not a warning
# like the eusc check — the caller can fix the region, so the plan must stop.
# The dedicated bucket is on so the run isolates the region precondition from
# the external-bucket one below.
# -----------------------------------------------------------------------------
run "cur_wrong_region_rejected" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
  }

  expect_failures = [
    aws_cur_report_definition.this,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 3f: External bucket without a region — the fallback is a guess
#
# With enable_dedicated_bucket = false the report writes to an injected bucket
# whose region the module cannot know; after the us-east-1 guard the fallback
# always names us-east-1, which matches the bucket only by coincidence, and
# CUR rejects a mismatch. The region stays at the us-east-1 mock, so this run
# isolates the external-bucket precondition from the region one above.
# -----------------------------------------------------------------------------
run "cur_external_bucket_without_region_rejected" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = false
  }

  expect_failures = [
    aws_cur_report_definition.this,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "invalid_time_unit_rejected" {
  command = plan

  variables {
    cur_config = {
      time_unit = "WEEKLY"
    }
  }

  expect_failures = [var.cur_config]
}

run "invalid_format_rejected" {
  command = plan

  variables {
    cur_config = {
      format = "json"
    }
  }

  expect_failures = [var.cur_config]
}

run "invalid_compression_rejected" {
  command = plan

  variables {
    cur_config = {
      compression = "BZIP2"
    }
  }

  expect_failures = [var.cur_config]
}

run "empty_s3_bucket_name_rejected" {
  command = plan

  variables {
    s3_bucket_name = ""
  }

  expect_failures = [var.s3_bucket_name]
}

# regression: the dedicated bucket needs no external bucket name. The
# management cur stack passes "" so that it does not depend on the logging
# stack, whose outputs do not exist while logging is switched off.
run "regression_dedicated_bucket_accepts_empty_s3_bucket_name" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
    s3_bucket_name               = ""
  }

  assert {
    condition     = length(aws_s3_bucket.cur) == 1 && length(aws_cur_report_definition.this) == 1
    error_message = "With the dedicated bucket an empty s3_bucket_name must plan the bucket and the report."
  }
}

run "invalid_s3_bucket_region_rejected" {
  command = plan

  variables {
    s3_bucket_region = "not-a-region"
  }

  expect_failures = [var.s3_bucket_region]
}

run "invalid_kms_key_administrator_rejected" {
  command = plan

  variables {
    kms_key_administrators = ["arn:aws:iam::not-an-account:role/KmsAdmin"]
  }

  expect_failures = [var.kms_key_administrators]
}

run "invalid_noncurrent_version_expiration_days_rejected" {
  command = plan

  variables {
    noncurrent_version_expiration_days = 0
  }

  expect_failures = [var.noncurrent_version_expiration_days]
}

run "invalid_abort_incomplete_multipart_upload_days_rejected" {
  command = plan

  variables {
    abort_incomplete_multipart_upload_days = 0
  }

  expect_failures = [var.abort_incomplete_multipart_upload_days]
}

# -----------------------------------------------------------------------------
# Scenario 3d: the empty counterpart of the three wired inputs
# -----------------------------------------------------------------------------
# stacks/management/cur/terragrunt.hcl passes kms_key_administrators,
# noncurrent_version_expiration_days and abort_incomplete_multipart_upload_days
# to the dedicated CUR bucket. Scenario 3b holds the set case; this one holds
# the empty case, so that the wiring is nailed down in both directions.
#
# The empty case is also what the example configuration produces:
# env/common.hcl carries [] and 365, base.tfvars carries 7 — all three are the
# module default.
run "cur_dedicated_bucket_defaults" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
    kms_key_administrators       = []
  }

  assert {
    condition     = length(aws_kms_key.cur) == 1
    error_message = "The dedicated CUR bucket must keep its KMS key without configured administrators."
  }

  assert {
    condition     = !strcontains(aws_kms_key.cur[0].policy, "AllowKeyAdministrators")
    error_message = "Without kms_key_administrators the administrator statement must be absent from the CUR key policy."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.cur[0].rule).noncurrent_version_expiration[0].noncurrent_days == 365
    error_message = "Without an explicit value the lifecycle rule must use the documented default of 365 days."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.cur[0].rule).abort_incomplete_multipart_upload[0].days_after_initiation == 7
    error_message = "Without an explicit value the multipart abort must use the documented default of 7 days."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5: Report attributes — artifacts, versioning, refresh
# -----------------------------------------------------------------------------
# Three attributes of aws_cur_report_definition are configurable. Their
# defaults keep the plan of a deployment that sets none of them unchanged:
# report_versioning defaults to OVERWRITE_REPORT, and the two null defaults
# leave the arguments unset.

run "regression_cur_report_defaults_keep_the_plan" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].report_versioning == "OVERWRITE_REPORT"
    error_message = "Without an explicit choice the report must keep the default versioning."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].additional_artifacts == null
    error_message = "Without an explicit choice no artifact manifests may be requested."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].refresh_closed_reports == null
    error_message = "Without an explicit choice the API default for refreshing closed reports must stay untouched."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].s3_region == "us-east-1"
    error_message = "With the dedicated bucket — its only remaining case — s3_region must fall back to the provider region, which is where the module creates that bucket."
  }

  assert {
    condition     = length(one(aws_s3_bucket_lifecycle_configuration.cur[0].rule[*].id)) > 0 && one(aws_s3_bucket_lifecycle_configuration.cur[0].rule[*].id) == "cur-lifecycle"
    error_message = "Without a rule set the bucket must keep its single derived lifecycle rule."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.cur[0].rule[*].expiration[0].days) == 365
    error_message = "The derived rule must keep its 365-day expiration."
  }
}

run "cur_report_attributes_reach_the_definition" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    s3_bucket_region             = "us-east-1"
    cur_config = {
      additional_artifacts   = ["REDSHIFT", "QUICKSIGHT"]
      report_versioning      = "CREATE_NEW_REPORT"
      refresh_closed_reports = false
    }
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].additional_artifacts == toset(["REDSHIFT", "QUICKSIGHT"])
    error_message = "The artifact manifests must reach the report definition."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].report_versioning == "CREATE_NEW_REPORT"
    error_message = "The versioning choice must reach the report definition."
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].refresh_closed_reports == false
    error_message = "The refresh switch must reach the report definition."
  }
}

run "cur_athena_artifact_alone_is_accepted" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    s3_bucket_region             = "us-east-1"
    cur_config = {
      additional_artifacts = ["ATHENA"]
    }
  }

  assert {
    condition     = aws_cur_report_definition.this["this"].additional_artifacts == toset(["ATHENA"])
    error_message = "ATHENA alone with the Parquet defaults and overwrite versioning must be accepted."
  }
}

run "cur_invalid_report_versioning_rejected" {
  command = plan

  variables {
    cur_config = {
      report_versioning = "KEEP_ALL"
    }
  }

  expect_failures = [var.cur_config]
}

run "cur_invalid_artifact_rejected" {
  command = plan

  variables {
    cur_config = {
      additional_artifacts = ["TABLEAU"]
    }
  }

  expect_failures = [var.cur_config]
}

run "cur_duplicate_artifact_rejected" {
  command = plan

  variables {
    cur_config = {
      additional_artifacts = ["REDSHIFT", "REDSHIFT"]
    }
  }

  expect_failures = [var.cur_config]
}

run "cur_athena_with_other_artifact_rejected" {
  command = plan

  variables {
    cur_config = {
      additional_artifacts = ["ATHENA", "REDSHIFT"]
    }
  }

  expect_failures = [var.cur_config]
}

run "cur_athena_without_parquet_rejected" {
  command = plan

  variables {
    cur_config = {
      additional_artifacts = ["ATHENA"]
      format               = "textORcsv"
      compression          = "GZIP"
    }
  }

  expect_failures = [var.cur_config]
}

run "cur_athena_with_new_report_versioning_rejected" {
  command = plan

  variables {
    cur_config = {
      additional_artifacts = ["ATHENA"]
      report_versioning    = "CREATE_NEW_REPORT"
    }
  }

  expect_failures = [var.cur_config]
}

# -----------------------------------------------------------------------------
# Scenario 6: Full lifecycle rule set of the dedicated CUR bucket
# -----------------------------------------------------------------------------
# The bucket takes the same rule shape as the log and security buckets. null
# keeps the single derived rule (scenario 5 above); the empty list
# is the explicit statement "no rules"; a rule set replaces the derived rule.

run "cur_lifecycle_rules_reach_the_bucket" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
    cur_bucket_lifecycle_rules = [
      {
        id              = "reports-archive"
        prefix          = "cur/"
        expiration_days = 730
        transitions = [
          { storage_class = "STANDARD_IA", days = 30 },
          { storage_class = "DEEP_ARCHIVE", days = 180 },
        ]
        noncurrent_version_expiration_days = 90
        noncurrent_version_transitions = [
          { storage_class = "GLACIER", days = 30 },
        ]
        abort_incomplete_multipart_upload_days = 3
      },
      {
        id                           = "disabled-cleanup"
        enabled                      = false
        tags                         = { class = "temp" }
        expired_object_delete_marker = true
      },
    ]
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.cur[0].rule) == 2
    error_message = "Both rules of the set must reach the bucket, and the derived rule must fall away."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].id == "reports-archive" && aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].status == "Enabled"
    error_message = "Rule id and status must reach the bucket."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].filter[0].prefix == "cur/"
    error_message = "The prefix filter must reach the bucket."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].expiration[0].days == 730
    error_message = "The expiration must reach the bucket."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].transition) == 2
    error_message = "Both transitions must reach the bucket."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].noncurrent_version_expiration[0].noncurrent_days == 90
    error_message = "The noncurrent version expiration must reach the bucket."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].noncurrent_version_transition) == 1
    error_message = "The noncurrent version transition must reach the bucket."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.cur[0].rule[0].abort_incomplete_multipart_upload[0].days_after_initiation == 3
    error_message = "The multipart abort must reach the bucket."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.cur[0].rule[1].status == "Disabled"
    error_message = "A disabled rule must reach the bucket as Disabled instead of being dropped."
  }
}

run "cur_empty_lifecycle_rule_set_removes_every_rule" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
    cur_bucket_lifecycle_rules   = []
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.cur[0].rule) == 0
    error_message = "The empty list is the explicit statement 'no rules' — the derived rule must not creep back in."
  }
}

run "cur_invalid_lifecycle_storage_class_rejected" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
    cur_bucket_lifecycle_rules = [
      {
        id          = "bad-class"
        transitions = [{ storage_class = "COLD_HDD", days = 30 }]
      },
    ]
  }

  expect_failures = [var.cur_bucket_lifecycle_rules]
}

run "cur_invalid_lifecycle_rule_without_action_rejected" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = true
    cur_bucket_lifecycle_rules = [
      { id = "does-nothing", prefix = "cur/" },
    ]
  }

  expect_failures = [var.cur_bucket_lifecycle_rules]
}

run "cur_invalid_lifecycle_rules_without_bucket_rejected" {
  command = plan

  variables {
    enable_cost_and_usage_report = true
    enable_dedicated_bucket      = false
    # Not under test here — without it the external-bucket precondition fails
    # alongside the expected variable validation and fails the run as an
    # unlisted error.
    s3_bucket_region = "us-east-1"
    cur_bucket_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }

  expect_failures = [var.cur_bucket_lifecycle_rules]
}
