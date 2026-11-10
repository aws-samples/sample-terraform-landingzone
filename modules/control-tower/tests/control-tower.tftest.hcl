# =============================================================================
# Control Tower Module Tests (modules/control-tower)
# =============================================================================
# Coverage:
#   - Toggle scenario: the module has NO enable_* variable that gates resource
#     creation. The Landing Zone and its service roles are always created —
#     Control Tower is the module's reason to exist. The enable_* variables
#     (enable_identity_center, enable_backup_integration) switch manifest
#     sections (accessManagement, backup), so the toggle scenarios below
#     assert the manifest effect instead of a zero-resource count. Collections that CAN be empty
#     (control_tower_controls, auto_enroll_ous) are verified to produce zero
#     resources in the default scenario.
#   - Default configuration
#   - Custom configuration (controls on OUs, custom retention/version)
#   - Validation failure scenarios
#
# Providers used by the module: aws (default only, no aliases) and time
# (hashicorp/time for the IAM propagation wait).

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111111111111"
    }
  }
}

mock_provider "time" {}

variables {
  audit_account_id       = "222222222222"
  log_archive_account_id = "333333333333"
  governed_regions       = ["eu-central-1"]
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle — Identity Center disabled
# -----------------------------------------------------------------------------
run "identity_center_disabled" {
  command = plan

  variables {
    enable_identity_center = false
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).accessManagement.enabled == false
    error_message = "accessManagement.enabled must be false when enable_identity_center is false."
  }

  # No optional collections configured => no derived resources
  assert {
    condition     = length(aws_controltower_control.this) == 0
    error_message = "No Control Tower controls must be created when control_tower_controls is empty."
  }

  assert {
    condition     = output.control_tower_control_count == 0
    error_message = "control_tower_control_count must be 0 when control_tower_controls is empty."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  assert {
    condition     = aws_controltower_landing_zone.this.version == "4.0"
    error_message = "Landing Zone version must default to 4.0."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).accessManagement.enabled == true
    error_message = "accessManagement.enabled must default to true."
  }

  assert {
    condition     = length(jsondecode(aws_controltower_landing_zone.this.manifest_json).governedRegions) == 1 && jsondecode(aws_controltower_landing_zone.this.manifest_json).governedRegions[0] == "eu-central-1"
    error_message = "governedRegions must match the input variable."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.accountId == "333333333333"
    error_message = "centralizedLogging.accountId must be the Log-Archive account."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.configurations.loggingBucket.retentionDays == 365
    error_message = "loggingBucket.retentionDays must default to 365."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.configurations.accessLoggingBucket.retentionDays == 365
    error_message = "accessLoggingBucket.retentionDays must default to 365."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).securityRoles.accountId == "222222222222"
    error_message = "securityRoles.accountId must be the Audit account."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).config.accountId == "222222222222"
    error_message = "config.accountId must be the Audit account."
  }

  # v4 manifest: every service integration carries an explicit enabled flag
  assert {
    condition     = can(jsondecode(aws_controltower_landing_zone.this.manifest_json).backup.enabled)
    error_message = "The v4 manifest must contain a backup section with an enabled flag."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).backup.enabled == false
    error_message = "backup.enabled must default to false — Control Tower does not manage AWS Backup unless enable_backup_integration is set."
  }

  # Control Tower service roles
  assert {
    condition     = aws_iam_role.ct_admin.name == "AWSControlTowerAdmin"
    error_message = "CT admin role name must be AWSControlTowerAdmin."
  }

  assert {
    condition     = aws_iam_role.ct_admin.path == "/service-role/"
    error_message = "CT admin role must live under /service-role/."
  }

  assert {
    condition     = aws_iam_role.ct_cloudtrail.name == "AWSControlTowerCloudTrailRole"
    error_message = "CT CloudTrail role name must be AWSControlTowerCloudTrailRole."
  }

  assert {
    condition     = aws_iam_role.ct_stackset.name == "AWSControlTowerStackSetRole"
    error_message = "CT StackSet role name must be AWSControlTowerStackSetRole."
  }

  assert {
    condition     = aws_iam_role.ct_config_aggregator.name == "AWSControlTowerConfigAggregatorRoleForOrganizations"
    error_message = "CT Config aggregator role name must match the AWS-expected name."
  }

  # Partition-aware managed policy ARNs (data.aws_partition.current => "aws")
  assert {
    condition     = aws_iam_role_policy_attachment.ct_admin.policy_arn == "arn:aws:iam::aws:policy/service-role/AWSControlTowerServiceRolePolicy"
    error_message = "CT admin managed policy ARN must be built from the detected partition."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.ct_cloudtrail.policy_arn == "arn:aws:iam::aws:policy/service-role/AWSControlTowerCloudTrailRolePolicy"
    error_message = "CT CloudTrail managed policy ARN must be built from the detected partition."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.ct_config_aggregator.policy_arn == "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
    error_message = "CT Config aggregator managed policy ARN must be built from the detected partition."
  }

  # Management account falls back to the caller identity when not passed
  assert {
    condition     = strcontains(aws_iam_role.ct_stackset.assume_role_policy, "111111111111")
    error_message = "StackSet trust policy must embed the resolved management account ID."
  }

  assert {
    condition     = time_sleep.wait_for_iam_propagation.create_duration == "30s"
    error_message = "IAM propagation wait must be 30s."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2b: Toggle — backup integration enabled
# -----------------------------------------------------------------------------
run "backup_integration_enabled" {
  command = plan

  variables {
    enable_backup_integration = true
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).backup.enabled == true
    error_message = "backup.enabled must be true when enable_backup_integration is set."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2c: Toggle — backup integration explicitly disabled
# -----------------------------------------------------------------------------
run "backup_integration_disabled" {
  command = plan

  variables {
    enable_backup_integration = false
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).backup.enabled == false
    error_message = "backup.enabled must be false when enable_backup_integration is explicitly disabled."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — controls on OUs, custom retention/version
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    management_account_id         = "444444444444"
    landing_zone_version          = "4.1"
    governed_regions              = ["eu-central-1", "eu-west-1"]
    logging_retention_days        = 730
    access_logging_retention_days = 90
    control_tower_controls = [
      {
        control_identifier = "arn:aws:controltower:eu-central-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        # Second entry is already an OU ARN and passes through the
        # ou_name_to_arn resolution unchanged.
        organizational_units = [
          "Workloads",
          "arn:aws:organizations::444444444444:ou/o-abc123/ou-bbbb-22222222",
        ]
      },
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_RESTRICT_ROOT_USER"
        organizational_units = ["Workloads"]
      },
    ]
    ou_name_to_arn = {
      Workloads = "arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"
    }
  }

  assert {
    condition     = aws_controltower_landing_zone.this.version == "4.1"
    error_message = "Landing Zone version must match the custom input."
  }

  assert {
    condition     = length(jsondecode(aws_controltower_landing_zone.this.manifest_json).governedRegions) == 2
    error_message = "governedRegions must contain both custom regions."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.configurations.loggingBucket.retentionDays == 730
    error_message = "loggingBucket.retentionDays must match the custom input."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.configurations.accessLoggingBucket.retentionDays == 90
    error_message = "accessLoggingBucket.retentionDays must match the custom input."
  }

  # 3 control-OU pairs are flattened from 2 controls
  assert {
    condition     = length(aws_controltower_control.this) == 3
    error_message = "Three control-OU pairs must be created from the custom control list."
  }

  assert {
    condition     = output.control_tower_control_count == 3
    error_message = "control_tower_control_count must report three controls."
  }

  # Known OU name resolves to its ARN via ou_name_to_arn
  assert {
    condition     = aws_controltower_control.this["arn:aws:controltower:eu-central-1::control/AWS-GR_RESTRICT_ROOT_USER-Workloads"].target_identifier == "arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"
    error_message = "Known OU names must be resolved through ou_name_to_arn."
  }

  # A target that is already an OU ARN passes through unchanged
  assert {
    condition     = aws_controltower_control.this["arn:aws:controltower:eu-central-1::control/AWS-GR_ENCRYPTED_VOLUMES-arn:aws:organizations::444444444444:ou/o-abc123/ou-bbbb-22222222"].target_identifier == "arn:aws:organizations::444444444444:ou/o-abc123/ou-bbbb-22222222"
    error_message = "A target that is already an OU ARN must pass through unchanged."
  }

  # Explicit management_account_id overrides the caller identity
  assert {
    condition     = strcontains(aws_iam_role.ct_stackset.assume_role_policy, "444444444444")
    error_message = "StackSet trust policy must embed the explicitly passed management account ID."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "invalid_audit_account_id_rejected" {
  command = plan

  variables {
    audit_account_id = "12345"
  }

  expect_failures = [var.audit_account_id]
}

run "invalid_log_archive_account_id_rejected" {
  command = plan

  variables {
    log_archive_account_id = "not-an-account"
  }

  expect_failures = [var.log_archive_account_id]
}

run "empty_governed_regions_rejected" {
  command = plan

  variables {
    governed_regions = []
  }

  expect_failures = [var.governed_regions]
}

run "invalid_governed_region_rejected" {
  command = plan

  variables {
    governed_regions = ["EU-Central-1"]
  }

  expect_failures = [var.governed_regions]
}

run "invalid_landing_zone_version_rejected" {
  command = plan

  variables {
    landing_zone_version = "v4"
  }

  expect_failures = [var.landing_zone_version]
}

run "invalid_management_account_id_rejected" {
  command = plan

  variables {
    management_account_id = "abc"
  }

  expect_failures = [var.management_account_id]
}

run "invalid_logging_retention_days_rejected" {
  command = plan

  variables {
    logging_retention_days = 0
  }

  expect_failures = [var.logging_retention_days]
}

run "invalid_access_logging_retention_days_rejected" {
  command = plan

  variables {
    access_logging_retention_days = 99999
  }

  expect_failures = [var.access_logging_retention_days]
}

run "invalid_auto_enroll_ou_rejected" {
  command = plan

  variables {
    auto_enroll_ous = ["1InvalidStart"]
  }

  expect_failures = [var.auto_enroll_ous]
}

# -----------------------------------------------------------------------------
# An OU name that ou_name_to_arn does not resolve must be rejected at plan
# time. Otherwise the raw OU name would reach
# aws_controltower_control.target_identifier, where AWS expects an OU ARN,
# and a typo would surface only as a late, misleading provider error.
# -----------------------------------------------------------------------------
run "unresolvable_control_ou_name_rejected" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_RESTRICT_ROOT_USER"
        organizational_units = ["Wrokloads"]
      },
    ]
    ou_name_to_arn = {
      Workloads = "arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"
    }
  }

  expect_failures = [var.control_tower_controls]
}

# An empty ou_name_to_arn cannot resolve any name either.
run "control_ou_without_arn_map_rejected" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_RESTRICT_ROOT_USER"
        organizational_units = ["Workloads"]
      },
    ]
  }

  expect_failures = [var.control_tower_controls]
}

# A malformed ARN in the resolution map would end up as a control target.
run "invalid_ou_name_to_arn_value_rejected" {
  command = plan

  variables {
    ou_name_to_arn = {
      Workloads = "ou-aaaa-11111111"
    }
  }

  expect_failures = [var.ou_name_to_arn]
}

# -----------------------------------------------------------------------------
# The module builds the v4 manifest schema only. A 3.x version would reach
# CreateLandingZone with a manifest missing the organizationStructure section
# that schema requires, so the version validation rejects anything below 4.x
# at plan time.
# -----------------------------------------------------------------------------
run "landing_zone_v3_version_rejected" {
  command = plan

  variables {
    landing_zone_version = "3.3"
  }

  expect_failures = [var.landing_zone_version]
}

run "landing_zone_manifest_omits_the_organization_structure" {
  command = plan

  # landing_zone_version stays at the module default 4.0: the v4 schema does
  # not accept an organizationStructure section.
  assert {
    condition     = !can(jsondecode(aws_controltower_landing_zone.this.manifest_json).organizationStructure)
    error_message = "The v4 manifest must not carry an organizationStructure section — the v4 schema has none."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).accessManagement.enabled == true
    error_message = "The remaining manifest sections must be unaffected."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).securityRoles.accountId == "222222222222"
    error_message = "securityRoles must carry the audit account ID."
  }
}

# -----------------------------------------------------------------------------
# The stack passes logging_retention_days and access_logging_retention_days
# from the loader locals control_tower_logging_retention_days and
# control_tower_access_logging_retention_days, which follow log_retention_days,
# so Control Tower keeps logs as long as the rest of the landing zone.
#
# The runs hold the two ends of the path: a retention arriving from the
# configuration lands in the manifest, and a value above the documented ceiling
# is rejected by the module instead of being sent to AWS. The ceiling matters
# because the loader forms the value with max(): a key in env/common.hcl larger
# than 5475 wins that max().
# -----------------------------------------------------------------------------
run "regression_merged_retention_reaches_the_manifest" {
  command = plan

  variables {
    # 2555 days (seven years) is the longest retention any compliance framework
    # asks for, so this is the largest value the merge can produce without a
    # value from env/common.hcl.
    logging_retention_days        = 2555
    access_logging_retention_days = 2555
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.configurations.loggingBucket.retentionDays == 2555
    error_message = "The retention passed in must reach loggingBucket.retentionDays."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.configurations.accessLoggingBucket.retentionDays == 2555
    error_message = "The retention passed in must reach accessLoggingBucket.retentionDays."
  }
}

run "regression_retention_above_the_ceiling_rejected" {
  command = plan

  variables {
    logging_retention_days = 5476
  }

  expect_failures = [var.logging_retention_days]
}

run "regression_access_retention_above_the_ceiling_rejected" {
  command = plan

  variables {
    access_logging_retention_days = 5476
  }

  expect_failures = [var.access_logging_retention_days]
}

# -----------------------------------------------------------------------------
# Scenario: Control parameters — default, reach and rejection
# -----------------------------------------------------------------------------

# Default: a control list without parameters renders no parameters block on
# any control.
run "regression_controls_without_parameters_render_none" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        organizational_units = ["Workloads"]
      },
    ]
    ou_name_to_arn = {
      Workloads = "arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"
    }
  }

  assert {
    condition     = length(aws_controltower_control.this["arn:aws:controltower:eu-central-1::control/AWS-GR_ENCRYPTED_VOLUMES-Workloads"].parameters) == 0
    error_message = "A control without parameters must not render a parameters block."
  }
}

# Reach: every key/value pair lands on the control resource, one parameters
# block per pair, values as JSON document strings.
run "control_parameters_reach_the_control" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY"
        organizational_units = ["Workloads"]
        parameters = [
          { key = "AllowedRegions", value = jsonencode(["eu-central-1", "eu-west-1"]) },
          { key = "ExemptedPrincipalArns", value = jsonencode(["arn:aws:iam::444444444444:role/BreakGlass"]) },
        ]
      },
    ]
    ou_name_to_arn = {
      Workloads = "arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"
    }
  }

  assert {
    condition     = length(aws_controltower_control.this["arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY-Workloads"].parameters) == 2
    error_message = "Both parameters must reach the control."
  }

  assert {
    condition = anytrue([
      for p in aws_controltower_control.this["arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY-Workloads"].parameters :
      p.key == "AllowedRegions" && p.value == jsonencode(["eu-central-1", "eu-west-1"])
    ])
    error_message = "AllowedRegions must carry the JSON-encoded region list."
  }

  assert {
    condition = anytrue([
      for p in aws_controltower_control.this["arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY-Workloads"].parameters :
      p.key == "ExemptedPrincipalArns"
    ])
    error_message = "The second parameter key must reach the control as well."
  }
}

# Parameters ride on every OU pair of their control: one control on two OUs
# yields two resources, each carrying the parameter.
run "control_parameters_apply_per_ou_pair" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY"
        organizational_units = ["Workloads", "Sandbox"]
        parameters = [
          { key = "AllowedRegions", value = jsonencode(["eu-central-1"]) },
        ]
      },
    ]
    ou_name_to_arn = {
      Workloads = "arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"
      Sandbox   = "arn:aws:organizations::444444444444:ou/o-abc123/ou-bbbb-22222222"
    }
  }

  assert {
    condition     = length(aws_controltower_control.this) == 2
    error_message = "One control on two OUs must yield two control resources."
  }

  assert {
    condition = alltrue([
      for key in ["arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY-Workloads", "arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY-Sandbox"] :
      length(aws_controltower_control.this[key].parameters) == 1
    ])
    error_message = "Every OU pair of the control must carry the parameter."
  }
}

run "control_parameter_padded_key_rejected" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY"
        organizational_units = ["arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"]
        parameters = [
          { key = "Allowed Regions", value = jsonencode(["eu-central-1"]) },
        ]
      },
    ]
  }

  expect_failures = [var.control_tower_controls]
}

run "control_parameter_raw_string_value_rejected" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY"
        organizational_units = ["arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"]
        parameters = [
          # Not a JSON document: a bare region name misses the jsonencode.
          { key = "AllowedRegions", value = "eu-central-1" },
        ]
      },
    ]
  }

  expect_failures = [var.control_tower_controls]
}

run "control_parameter_duplicate_key_rejected" {
  command = plan

  variables {
    control_tower_controls = [
      {
        control_identifier   = "arn:aws:controltower:eu-central-1::control/AWS-GR_REGION_DENY"
        organizational_units = ["arn:aws:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"]
        parameters = [
          { key = "AllowedRegions", value = jsonencode(["eu-central-1"]) },
          { key = "AllowedRegions", value = jsonencode(["eu-west-1"]) },
        ]
      },
    ]
  }

  expect_failures = [var.control_tower_controls]
}

# -----------------------------------------------------------------------------
# Scenario: Organization trail switch — default and reach
# -----------------------------------------------------------------------------

# Default: without the input the manifest keeps centralized logging enabled.
run "regression_organization_trail_stays_enabled" {
  command = plan

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.enabled == true
    error_message = "centralizedLogging.enabled must default to true."
  }
}

# Reach: the switch reaches the manifest; the logging account and retention
# configuration stay in place either way.
run "organization_trail_switch_reaches_the_manifest" {
  command = plan

  variables {
    enable_organization_trail = false
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.enabled == false
    error_message = "enable_organization_trail = false must reach centralizedLogging.enabled."
  }

  assert {
    condition     = jsondecode(aws_controltower_landing_zone.this.manifest_json).centralizedLogging.accountId == "333333333333"
    error_message = "The logging account must stay in the manifest regardless of the switch."
  }
}
# -----------------------------------------------------------------------------
# Scenario: Partition-neutral control names and trust policies — under a
# mock partition the module builds the control ARN from
# the partition-neutral name, passes a full control ARN through unchanged and
# renders the service-role trust policies with the partition's DNS suffix.
# -----------------------------------------------------------------------------
run "control_names_and_trust_policies_follow_the_partition" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }
  variables {
    control_tower_controls = [
      {
        control_identifier   = "CONFIG.CLOUDTRAIL.DT.5"
        organizational_units = ["Workloads"]
      },
      {
        # A full control ARN is passed through unchanged, so an existing
        # configuration keeps its resource addresses.
        control_identifier   = "arn:aws-eusc:controltower:::control/AWS-GR_RESTRICT_ROOT_USER"
        organizational_units = ["Workloads"]
      },
    ]
    ou_name_to_arn = {
      Workloads = "arn:aws-eusc:organizations::444444444444:ou/o-abc123/ou-aaaa-11111111"
    }
  }
  assert {
    condition     = aws_controltower_control.this["arn:aws-eusc:controltower:::control/CONFIG.CLOUDTRAIL.DT.5-Workloads"].control_identifier == "arn:aws-eusc:controltower:::control/CONFIG.CLOUDTRAIL.DT.5"
    error_message = "A partition-neutral control name must become a control ARN of the current partition."
  }
  assert {
    condition     = aws_controltower_control.this["arn:aws-eusc:controltower:::control/AWS-GR_RESTRICT_ROOT_USER-Workloads"].control_identifier == "arn:aws-eusc:controltower:::control/AWS-GR_RESTRICT_ROOT_USER"
    error_message = "A full control ARN must pass through unchanged."
  }
  assert {
    condition     = strcontains(aws_iam_role.ct_admin.assume_role_policy, "controltower.amazonaws.eu")
    error_message = "The admin trust policy must carry the partition's DNS suffix."
  }
  assert {
    condition     = strcontains(aws_iam_role.ct_cloudtrail.assume_role_policy, "cloudtrail.amazonaws.eu")
    error_message = "The CloudTrail trust policy must carry the partition's DNS suffix."
  }
  assert {
    condition     = strcontains(aws_iam_role.ct_stackset.assume_role_policy, "cloudformation.amazonaws.eu")
    error_message = "The StackSet trust policy must carry the partition's DNS suffix."
  }
  assert {
    condition     = strcontains(aws_iam_role.ct_config_aggregator.assume_role_policy, "config.amazonaws.eu")
    error_message = "The Config aggregator trust policy must carry the partition's DNS suffix."
  }
}
