# =============================================================================
# Security Module Tests (modules/security)
# =============================================================================
# Coverage:
#   - Toggle-off: every enable_* toggle false → zero resources for all toggled
#     services (see note on the password policy below)
#   - Default configuration: module defaults (GuardDuty, Security Hub, Access
#     Analyzer, EBS encryption, S3 public access block, SSM sharing block)
#   - Default configuration warning: root management placeholders default to
#     true and therefore trip the provider-limitation check
#   - Custom configuration (security services): GuardDuty export and malware
#     protection, Security Hub standards/aggregation/control disabling, Macie,
#     Detective, Audit Manager including reports bucket
#   - Custom configuration (platform): customer-managed KMS keys, Session
#     Manager logging, SSM documents and inventory sync, per-account/Lambda/SQS
#     keys, firewall config bucket, custom password policy
#   - Custom configuration (default VPC hardening) with the documented
#     single-region/single-VPC limitation warnings
#   - Validation failures: audit account ID, password policy, GuardDuty export
#     frequency, KMS alias, excluded region format, SSM document type
#   - Scenarios 5a onwards: wiring, guard and silent-misconfiguration cases
#
# Note on the toggle-off scenario: aws_iam_account_password_policy.this has no
# enable_* toggle and is created unconditionally, so "zero resources" applies to
# all toggled services rather than to the whole module.
#
# Note on audit_account_id: the variable has no default and the check block
# "audit_account_configured" requires a non-empty value, so every scenario sets
# it. Scenario "audit_account_missing_warning" covers the empty case explicitly.
#
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
      region = "eu-central-1"
    }
  }

  # aws_kms_key validates its policy as JSON, so the generated key policy needs
  # a syntactically valid document instead of a random mock value.
  override_data {
    target = data.aws_iam_policy_document.ebs_default_key_policy
    values = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

mock_provider "time" {}

mock_provider "archive" {}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-off — all enable_* toggles false → no service resources
# -----------------------------------------------------------------------------
run "all_toggles_off_no_resources" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    enable_guardduty                       = false
    enable_security_hub                    = false
    enable_security_hub_region_aggregation = false
    enable_macie                           = false
    enable_access_analyzer                 = false
    enable_detective                       = false
    enable_audit_manager                   = false
    enable_audit_manager_bucket            = false
    enable_ebs_default_encryption          = false
    enable_s3_public_access_block          = false
    enable_ssm_block_public_sharing        = false
    enable_ssm_resource_data_sync          = false
    enable_session_manager_logging         = false
    enable_session_manager_s3_logging      = false
    enable_guardduty_s3_malware_protection = false
    enable_lambda_encryption               = false
    enable_per_account_kms_keys            = false
    enable_sqs_kms_key                     = false
    enable_delete_default_vpc              = false
    enable_delete_default_sg_rules         = false
    enable_fms_notification_channel        = false
    enable_firewall_config_bucket          = false
    root_credentials_management            = false
    allow_root_sessions                    = false
  }

  # --- GuardDuty ---
  assert {
    condition     = length(aws_guardduty_detector.this) == 0
    error_message = "No GuardDuty detector must be created when disabled."
  }

  assert {
    condition = alltrue([
      length(aws_guardduty_detector_feature.s3_logs) == 0,
      length(aws_guardduty_detector_feature.eks_audit_logs) == 0,
      length(aws_guardduty_detector_feature.ebs_malware) == 0,
      length(aws_guardduty_detector_feature.lambda_protection) == 0,
      length(aws_guardduty_detector_feature.rds_protection) == 0,
      length(aws_guardduty_detector_feature.eks_runtime_monitoring) == 0,
    ])
    error_message = "No GuardDuty detector features must be created when GuardDuty is disabled."
  }

  assert {
    condition     = length(aws_guardduty_publishing_destination.this) == 0 && length(time_sleep.guardduty_export_wait) == 0
    error_message = "No GuardDuty export must be configured when GuardDuty is disabled."
  }

  assert {
    condition     = length(aws_guardduty_malware_protection_plan.this) == 0 && length(aws_iam_role.guardduty_malware_scan) == 0
    error_message = "No GuardDuty malware protection resources must be created when disabled."
  }

  # --- Security Hub ---
  assert {
    condition = alltrue([
      length(aws_securityhub_account.this) == 0,
      length(aws_securityhub_standards_subscription.this) == 0,
      length(aws_securityhub_standards_subscription.config) == 0,
      length(aws_securityhub_standards_control.disabled) == 0,
      length(aws_securityhub_finding_aggregator.this) == 0,
      length(aws_securityhub_automation_rule.this) == 0,
    ])
    error_message = "No Security Hub resources must be created when disabled."
  }

  # --- Macie, Access Analyzer, Detective, Audit Manager ---
  assert {
    condition     = length(aws_macie2_account.this) == 0 && length(aws_macie2_organization_admin_account.this) == 0
    error_message = "No Macie resources must be created when disabled."
  }

  assert {
    condition     = length(aws_accessanalyzer_analyzer.this) == 0
    error_message = "No Access Analyzer must be created when disabled."
  }

  assert {
    condition     = length(aws_detective_graph.this) == 0
    error_message = "No Detective graph must be created when disabled."
  }

  assert {
    condition     = length(aws_auditmanager_account_registration.this) == 0 && length(aws_s3_bucket.audit_manager_reports) == 0
    error_message = "No Audit Manager resources must be created when disabled."
  }

  # --- Delegated administrators ---
  assert {
    condition = alltrue([
      length(aws_organizations_delegated_administrator.guardduty) == 0,
      length(aws_organizations_delegated_administrator.securityhub) == 0,
      length(aws_guardduty_organization_admin_account.this) == 0,
      length(aws_securityhub_organization_admin_account.this) == 0,
      length(aws_organizations_delegated_administrator.macie) == 0,
      length(aws_organizations_delegated_administrator.access_analyzer) == 0,
      length(aws_organizations_delegated_administrator.detective) == 0,
      length(aws_detective_organization_admin_account.this) == 0,
      length(aws_organizations_delegated_administrator.audit_manager) == 0,
    ])
    error_message = "No delegated administrator registrations must be created when all services are disabled."
  }

  # --- Account hardening ---
  assert {
    condition     = length(aws_ebs_encryption_by_default.this) == 0 && length(aws_kms_key.ebs_default) == 0 && length(aws_ebs_default_kms_key.this) == 0
    error_message = "No EBS encryption resources must be created when disabled."
  }

  assert {
    condition     = length(aws_s3_account_public_access_block.this) == 0
    error_message = "No S3 account public access block must be created when disabled."
  }

  assert {
    condition     = length(aws_default_vpc.this) == 0 && length(aws_default_security_group.this) == 0
    error_message = "No default VPC or default security group must be adopted when disabled."
  }

  # --- SSM / Session Manager ---
  assert {
    condition     = length(aws_ssm_service_setting.public_sharing) == 0
    error_message = "No SSM public sharing setting must be created when disabled."
  }

  assert {
    condition     = length(aws_ssm_document.session_manager) == 0 && length(aws_iam_policy.session_manager_ec2) == 0
    error_message = "No Session Manager resources must be created when disabled."
  }

  assert {
    condition     = length(aws_ssm_document.custom) == 0 && length(aws_ssm_resource_data_sync.this) == 0
    error_message = "No SSM documents or inventory sync must be created when disabled."
  }

  # --- KMS ---
  assert {
    condition = alltrue([
      length(aws_kms_key.custom) == 0,
      length(aws_kms_key.lambda_encryption) == 0,
      length(aws_kms_key.per_account_cloudwatch) == 0,
      length(aws_kms_key.per_account_lambda) == 0,
      length(aws_kms_key.sqs) == 0,
    ])
    error_message = "No KMS keys must be created when all key toggles are off."
  }

  # --- Firewall Manager ---
  # The FMS notification channel has no resource: the pinned AWS provider
  # exposes none, so the module surfaces it as a provider limitation only.
  assert {
    condition = alltrue([
      length(aws_fms_policy.this) == 0,
      length(aws_s3_bucket.firewall_config) == 0,
      length(aws_s3_bucket_lifecycle_configuration.firewall_config) == 0,
      length(aws_iam_role.firewall_config_reader) == 0,
    ])
    error_message = "No Firewall Manager resources must be created when disabled."
  }

  # --- Outputs ---
  assert {
    condition     = output.guardduty_detector_id == "" && output.security_hub_arn == "" && output.access_analyzer_arn == ""
    error_message = "Service ARN outputs must be empty when the services are disabled."
  }

  # The three assertions below name the resources the toggles govern: an
  # echoed `false` would say nothing about whether the resource is absent.
  assert {
    condition     = length(aws_ebs_encryption_by_default.this) == 0 && length(aws_s3_account_public_access_block.this) == 0
    error_message = "Account hardening must create no resources when disabled."
  }

  assert {
    condition     = length(aws_securityhub_finding_aggregator.this) == 0
    error_message = "No finding aggregator must be created when aggregation is disabled."
  }

  assert {
    condition     = length(aws_guardduty_publishing_destination.this) == 0 && length(aws_detective_graph.this) == 0
    error_message = "GuardDuty export and Detective must create no resources when disabled."
  }

  # --- Password policy is toggle-free and therefore always planned ---
  assert {
    condition     = aws_iam_account_password_policy.this.minimum_password_length == 14
    error_message = "The password policy has no toggle and must keep its default minimum length."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — module defaults enable the baseline set
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
  }

  # --- GuardDuty defaults ---
  assert {
    condition     = length(aws_guardduty_detector.this) == 1
    error_message = "GuardDuty detector must be created by default."
  }

  assert {
    condition     = aws_guardduty_detector_feature.s3_logs[0].status == "ENABLED"
    error_message = "GuardDuty S3 data events must be enabled by default."
  }

  assert {
    condition     = aws_guardduty_detector_feature.eks_runtime_monitoring[0].status == "DISABLED"
    error_message = "GuardDuty EKS runtime monitoring must be disabled by default."
  }

  assert {
    condition     = length(aws_guardduty_publishing_destination.this) == 0
    error_message = "GuardDuty export must stay off while guardduty_export_frequency is null."
  }

  # --- Security Hub defaults ---
  assert {
    condition     = length(aws_securityhub_account.this) == 1
    error_message = "Security Hub must be enabled by default."
  }

  assert {
    condition     = length(aws_securityhub_standards_subscription.this) == 2
    error_message = "The two default Security Hub standards must be subscribed."
  }

  assert {
    condition     = length(aws_securityhub_finding_aggregator.this) == 1 && aws_securityhub_finding_aggregator.this[0].linking_mode == "ALL_REGIONS"
    error_message = "Finding aggregation must be created and default to ALL_REGIONS."
  }

  # --- Access Analyzer / Macie / Detective defaults ---
  assert {
    condition     = length(aws_accessanalyzer_analyzer.this) == 1
    error_message = "Access Analyzer must be enabled by default."
  }

  assert {
    condition     = length(aws_macie2_account.this) == 0
    error_message = "Macie must stay disabled by default."
  }

  assert {
    condition     = length(aws_detective_graph.this) == 0
    error_message = "Detective must stay disabled by default."
  }

  # --- Delegated administrators for the enabled services ---
  assert {
    condition = alltrue([
      length(aws_organizations_delegated_administrator.guardduty) == 1,
      length(aws_organizations_delegated_administrator.securityhub) == 1,
      length(aws_organizations_delegated_administrator.access_analyzer) == 1,
      length(aws_organizations_delegated_administrator.macie) == 0,
    ])
    error_message = "Delegated administrators must be registered exactly for the enabled services."
  }

  # GuardDuty and Security Hub read their administrator from their own
  # designation API, not from the Organizations registration: both
  # designations must accompany the registrations and name the Audit account.
  assert {
    condition = alltrue([
      length(aws_guardduty_organization_admin_account.this) == 1,
      aws_guardduty_organization_admin_account.this[0].admin_account_id == "222222222222",
      length(aws_securityhub_organization_admin_account.this) == 1,
      aws_securityhub_organization_admin_account.this[0].admin_account_id == "222222222222",
    ])
    error_message = "GuardDuty and Security Hub must designate the Audit account as their organization administrator alongside the Organizations registration."
  }

  # --- Account hardening defaults ---
  assert {
    condition     = length(aws_ebs_encryption_by_default.this) == 1
    error_message = "EBS default encryption must be enabled by default."
  }

  assert {
    condition     = length(aws_kms_key.ebs_default) == 1 && length(aws_kms_alias.ebs_default) == 1
    error_message = "A managed EBS KMS key must be created when no key ARN is supplied."
  }

  assert {
    condition     = length(aws_ebs_default_kms_key.this) == 1
    error_message = "The module-managed EBS key must be registered as the account-wide default key."
  }

  assert {
    condition     = length(aws_s3_account_public_access_block.this) == 1
    error_message = "S3 account public access block must be enabled by default."
  }

  assert {
    condition     = length(aws_ssm_service_setting.public_sharing) == 1
    error_message = "SSM public document sharing must be blocked by default."
  }

  assert {
    condition     = aws_ssm_service_setting.public_sharing[0].setting_value == "Disable"
    error_message = "SSM public sharing setting value must be Disable."
  }

  # --- Password policy defaults ---
  # Read straight from aws_iam_account_password_policy.this, including the
  # three boolean attributes.
  assert {
    condition = alltrue([
      aws_iam_account_password_policy.this.minimum_password_length == 14,
      aws_iam_account_password_policy.this.max_password_age == 90,
      aws_iam_account_password_policy.this.password_reuse_prevention == 24,
      aws_iam_account_password_policy.this.require_symbols == true,
      aws_iam_account_password_policy.this.require_lowercase_characters == true,
      aws_iam_account_password_policy.this.require_numbers == true,
      aws_iam_account_password_policy.this.require_uppercase_characters == true,
    ])
    error_message = "Password policy defaults must be applied."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2b: Default root-management placeholders trip the limitation check
# -----------------------------------------------------------------------------
run "defaults_root_management_warning" {
  command = plan

  variables {
    audit_account_id = "222222222222"
  }

  expect_failures = [
    check.root_credentials_management_provider_limitation,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 2c: Empty audit account ID trips the delegation check
# -----------------------------------------------------------------------------
run "audit_account_missing_warning" {
  command = plan

  variables {
    audit_account_id            = ""
    root_credentials_management = false
    allow_root_sessions         = false
    # Detective defaults to off; on here so its guard is exercised, not vacuous.
    enable_detective = true
  }

  expect_failures = [
    check.audit_account_configured,
  ]

  assert {
    condition = alltrue([
      length(aws_organizations_delegated_administrator.guardduty) == 0,
      length(aws_organizations_delegated_administrator.securityhub) == 0,
      length(aws_organizations_delegated_administrator.access_analyzer) == 0,
      length(aws_organizations_delegated_administrator.detective) == 0,
      length(aws_guardduty_organization_admin_account.this) == 0,
      length(aws_securityhub_organization_admin_account.this) == 0,
      length(aws_detective_organization_admin_account.this) == 0,
    ])
    error_message = "No delegated administrator must be registered or designated without an audit account ID — the API rejects admin_account_id = \"\"."
  }

  assert {
    condition     = length(aws_guardduty_detector.this) == 1 && length(aws_detective_graph.this) == 1
    error_message = "Local service activation must still happen without an audit account ID."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — security services
# -----------------------------------------------------------------------------
run "custom_configuration_services" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    central_log_bucket_name     = "tlz-central-logs"

    # GuardDuty: feature toggles, export and S3 malware protection
    guardduty_s3_protection                = true
    guardduty_eks_protection               = false
    guardduty_lambda_protection            = false
    guardduty_rds_protection               = true
    guardduty_eks_runtime_monitoring       = true
    guardduty_export_frequency             = "FIFTEEN_MINUTES"
    guardduty_export_kms_key_arn           = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    guardduty_lifecycle_rules              = { retention_days = 90 }
    replace_central_log_bucket_lifecycle   = true
    enable_guardduty_s3_malware_protection = true
    guardduty_s3_malware_configs = [
      {
        bucket_name     = "tlz-scan-bucket"
        object_prefixes = ["uploads/"]
        kms_key_arn     = "arn:aws:kms:eu-central-1:123456789012:key/66666666-7777-8888-9999-000000000000"
      }
    ]

    # Security Hub: custom standards, region aggregation, disabled controls.
    # security_hub_standards carries the structured form; a plain
    # ARN suffix string is accepted at the configuration layer, where the
    # loader converts it to this form.
    security_hub_standards = [
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0", enabled = true },
      { arn_suffix = "pci-dss/v/3.2.1", enabled = false },
    ]
    security_hub_aggregation_regions = ["eu-central-1", "eu-west-1"]
    security_hub_standards_config = [
      { standard_arn_suffix = "nist-800-53/v/5.0.0" }
    ]
    security_hub_disabled_controls = [
      {
        standard_arn_suffix = "aws-foundational-security-best-practices/v/1.0.0"
        control_ids         = ["IAM.1", "IAM.2"]
      }
    ]

    # Macie
    enable_macie                          = true
    is_eusc                               = false
    macie_publishing_frequency            = "ONE_HOUR"
    macie_publish_sensitive_data_findings = true

    # Detective
    enable_detective = true

    # Audit Manager including reports bucket
    enable_audit_manager                = true
    enable_audit_manager_bucket         = true
    audit_manager_bucket_kms_key_arn    = "arn:aws:kms:eu-central-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    audit_manager_bucket_lifecycle_days = 180
    audit_manager_reports_destination = {
      s3_bucket_name = "tlz-audit-manager-reports"
      s3_prefix      = "reports"
    }
  }

  # Only kms_key_arn of audit_manager_reports_destination reaches AWS; the
  # module reports the unsupported S3 destination part as a limitation.
  # enable_audit_manager = true additionally fires the maintenance-mode
  # warning (new registrations refused by AWS since April 30, 2026). The
  # export runs here beside a designated administrator, which the module
  # reports as well.
  expect_failures = [
    check.audit_manager_reports_destination_provider_limitation,
    check.audit_manager_maintenance_mode,
    check.finding_consumers_in_administrator,
  ]

  # --- GuardDuty feature toggles map onto detector feature status ---
  assert {
    condition     = aws_guardduty_detector_feature.eks_audit_logs[0].status == "DISABLED"
    error_message = "EKS audit logs must be DISABLED when guardduty_eks_protection is false."
  }

  assert {
    condition     = aws_guardduty_detector_feature.lambda_protection[0].status == "DISABLED"
    error_message = "Lambda network logs must be DISABLED when guardduty_lambda_protection is false."
  }

  assert {
    condition     = aws_guardduty_detector_feature.rds_protection[0].status == "ENABLED"
    error_message = "RDS login events must be ENABLED when guardduty_rds_protection is true."
  }

  assert {
    condition     = aws_guardduty_detector_feature.eks_runtime_monitoring[0].status == "ENABLED"
    error_message = "EKS runtime monitoring must be ENABLED when the toggle is on."
  }

  # --- GuardDuty export ---
  assert {
    condition     = length(aws_guardduty_publishing_destination.this) == 1 && length(time_sleep.guardduty_export_wait) == 1
    error_message = "GuardDuty export must be configured with a frequency and a central log bucket."
  }

  assert {
    condition     = aws_guardduty_publishing_destination.this[0].destination_arn == "arn:aws:s3:::tlz-central-logs/guardduty"
    error_message = "GuardDuty export destination must use the detected partition, the central log bucket and the configured export prefix."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.guardduty_export) == 1
    error_message = "GuardDuty export lifecycle rules must be created when guardduty_lifecycle_rules is set."
  }

  # The publishing destination itself, and output.guardduty_export_frequency.
  assert {
    condition     = length(aws_guardduty_publishing_destination.this) == 1 && output.guardduty_export_frequency == "FIFTEEN_MINUTES"
    error_message = "GuardDuty export must create a publishing destination and reflect the configured frequency."
  }

  # --- GuardDuty S3 malware protection ---
  assert {
    condition     = length(aws_guardduty_malware_protection_plan.this) == 1
    error_message = "One malware protection plan must be created per configured bucket."
  }

  assert {
    condition     = length(aws_iam_role.guardduty_malware_scan) == 1 && length(aws_iam_role_policy.guardduty_malware_scan_s3) == 1
    error_message = "The malware scan role and its S3 policy must be created."
  }

  assert {
    condition     = length(aws_iam_role_policy.guardduty_malware_scan_kms) == 1
    error_message = "A KMS policy must be attached when malware configs reference a KMS key."
  }

  # --- Security Hub ---
  assert {
    condition     = length(aws_securityhub_standards_subscription.this) == 1
    error_message = "Only enabled standards must be subscribed (the disabled entry is documentation only)."
  }

  assert {
    condition     = aws_securityhub_standards_subscription.this["aws-foundational-security-best-practices/v/1.0.0"].standards_arn == "arn:aws:securityhub:eu-central-1::standards/aws-foundational-security-best-practices/v/1.0.0"
    error_message = "Standard ARN must be built from partition and region."
  }

  assert {
    condition     = length(aws_securityhub_standards_subscription.config) == 1
    error_message = "Per-standard configuration entries must create their own subscription."
  }

  assert {
    condition     = length(aws_securityhub_standards_control.disabled) == 2
    error_message = "Each disabled control ID must create its own control resource."
  }

  assert {
    condition     = aws_securityhub_finding_aggregator.this[0].linking_mode == "SPECIFIED_REGIONS"
    error_message = "Explicit aggregation regions must switch the linking mode to SPECIFIED_REGIONS."
  }

  assert {
    condition     = length(aws_securityhub_finding_aggregator.this[0].specified_regions) == 2
    error_message = "Both configured aggregation regions must be forwarded to the aggregator."
  }

  # --- Macie ---
  assert {
    condition     = length(aws_macie2_account.this) == 1 && length(aws_macie2_organization_admin_account.this) == 1
    error_message = "Macie account and org admin must be created when enabled outside EUSC."
  }

  assert {
    condition     = aws_macie2_account.this[0].finding_publishing_frequency == "ONE_HOUR"
    error_message = "The publishing frequency must be applied to the single Macie activation."
  }

  assert {
    condition     = length(aws_macie2_classification_export_configuration.this) == 1
    error_message = "Macie classification export must be configured for sensitive data findings."
  }

  # --- Detective and Audit Manager ---
  assert {
    condition     = length(aws_detective_graph.this) == 1 && length(aws_organizations_delegated_administrator.detective) == 1
    error_message = "Detective graph and delegated admin must be created when enabled."
  }

  # Detective reads its administrator from its own designation API: the
  # designation must accompany the registration and name the Audit account —
  # made from the Audit account, it would be refused by AWS.
  assert {
    condition = alltrue([
      length(aws_detective_organization_admin_account.this) == 1,
      aws_detective_organization_admin_account.this[0].account_id == "222222222222",
    ])
    error_message = "Detective must designate the Audit account as its organization administrator alongside the Organizations registration."
  }

  assert {
    condition     = length(aws_auditmanager_account_registration.this) == 1
    error_message = "Exactly one Audit Manager registration must be created for the account."
  }

  assert {
    condition     = aws_auditmanager_account_registration.this[0].delegated_admin_account == "222222222222"
    error_message = "The delegated admin account must be applied to the single Audit Manager registration."
  }

  assert {
    condition = alltrue([
      length(aws_s3_bucket.audit_manager_reports) == 1,
      length(aws_s3_bucket_versioning.audit_manager_reports) == 1,
      length(aws_s3_bucket_server_side_encryption_configuration.audit_manager_reports) == 1,
      length(aws_s3_bucket_public_access_block.audit_manager_reports) == 1,
      length(aws_s3_bucket_lifecycle_configuration.audit_manager_reports) == 1,
    ])
    error_message = "The Audit Manager reports bucket must be created with versioning, encryption, PAB and lifecycle."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b: Custom configuration — EUSC partition disables Macie
# -----------------------------------------------------------------------------
run "custom_configuration_eusc" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
    is_eusc                     = true
  }

  # enable_macie = true in aws-eusc trips the availability check by design —
  # docs/multi-partition.md promises the warning.
  expect_failures = [
    check.macie_partition_availability,
  ]

  assert {
    condition     = length(aws_macie2_account.this) == 0 && length(aws_macie2_organization_admin_account.this) == 0
    error_message = "Macie must not be created in the aws-eusc partition."
  }

  assert {
    condition     = length(aws_organizations_delegated_administrator.macie) == 0
    error_message = "No Macie delegated administrator must be registered in the aws-eusc partition."
  }

  assert {
    condition     = length(aws_guardduty_detector.this) == 1 && length(aws_securityhub_account.this) == 1
    error_message = "GuardDuty and Security Hub must stay available in the aws-eusc partition."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b-2: aws-eusc with enable_macie = false — no warning
# -----------------------------------------------------------------------------
# Counterpart to the scenario above. The availability check must only fire when
# Macie was actually asked for; a landing zone that leaves enable_macie at its
# default must deploy into aws-eusc without any warning. This run
# declares no expect_failures, so a check that fired here would fail the test.
run "eusc_without_macie_no_warning" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = false
    is_eusc                     = true
  }

  assert {
    condition     = length(aws_macie2_account.this) == 0
    error_message = "Macie must not be created when enable_macie is false."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b-3: aws-eusc skips Detective, Audit Manager and FMS with warnings
# -----------------------------------------------------------------------------
# The availability table in docs/multi-partition.md documents the
# three services as not available in aws-eusc (AWS Services by Region,
# eusc-de-east-1). Each follows the Macie pattern: resources are gated on the
# partition and a check block reports the skip.
run "eusc_skips_detective_audit_manager_and_fms_with_warnings" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_detective            = true
    enable_audit_manager        = true
    enable_audit_manager_bucket = true
    fms_policies = [{
      name               = "waf-baseline"
      type               = "WAF"
      resource_type_list = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
    }]
    is_eusc = true
  }

  expect_failures = [
    check.detective_partition_availability,
    check.audit_manager_partition_availability,
    check.audit_manager_maintenance_mode,
    check.fms_partition_availability,
  ]

  assert {
    condition = alltrue([
      length(aws_detective_graph.this) == 0,
      length(aws_organizations_delegated_administrator.detective) == 0,
      length(aws_detective_organization_admin_account.this) == 0,
    ])
    error_message = "Detective must not be created in the aws-eusc partition."
  }

  assert {
    condition     = length(aws_auditmanager_account_registration.this) == 0 && length(aws_organizations_delegated_administrator.audit_manager) == 0
    error_message = "Audit Manager must not be registered in the aws-eusc partition."
  }

  assert {
    condition     = length(aws_s3_bucket.audit_manager_reports) == 0
    error_message = "The Audit Manager reports bucket must not be created in the aws-eusc partition."
  }

  assert {
    condition     = length(aws_fms_policy.this) == 0
    error_message = "No FMS policy must be created in the aws-eusc partition."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b-4: aws-eusc without the three services — no warning
# -----------------------------------------------------------------------------
# Counterpart to the scenario above. The availability checks must only fire
# when the service was actually asked for; this run declares no
# expect_failures, so a check that fired here would fail the test.
run "eusc_without_unavailable_services_no_warning" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    is_eusc                     = true
  }

  assert {
    condition     = length(aws_detective_graph.this) == 0 && length(aws_auditmanager_account_registration.this) == 0 && length(aws_fms_policy.this) == 0
    error_message = "None of the partition-gated services must be created at their defaults."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3c: Custom configuration — platform resources
# -----------------------------------------------------------------------------
# This run names a session log group and bucket that exist nowhere, and the
# module looks both up at plan time (checks session_manager_cloudwatch_log_group_exists
# and session_manager_s3_bucket_exists in session-manager.tf). Under the mock
# provider a listing data source returns an empty collection, which is exactly
# the "target does not exist" answer the checks are built to catch — so the run
# describes the world in which its fictional names DO exist, scoped to this run
# alone. The file-level mock_provider block deliberately carries no such
# override: every other run still meets the empty answer, and the two
# regression_session_manager_missing_*_is_reported runs below pin that the
# checks fire on it.
run "custom_configuration_platform" {
  command = plan

  override_data {
    target = data.aws_cloudwatch_log_groups.session_manager
    values = {
      log_group_names = ["/aws/ssm/sessions"]
      arns            = ["arn:aws:logs:eu-central-1:123456789012:log-group:/aws/ssm/sessions"]
    }
  }

  override_data {
    target = data.aws_s3_buckets.session_manager
    values = {
      buckets = [
        {
          name          = "tlz-session-logs"
          bucket_arn    = "arn:aws:s3:::tlz-session-logs"
          bucket_region = "eu-central-1"
          creation_date = "2026-01-01T00:00:00Z"
        },
      ]
    }
  }

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    central_log_bucket_name     = "tlz-central-logs"

    # Customer-managed KMS keys
    kms_keys = [
      {
        alias                   = "tlz/app-secrets"
        description             = "Application secrets"
        deletion_window_in_days = 7
      }
    ]

    # Dedicated service keys
    enable_lambda_encryption    = true
    enable_per_account_kms_keys = true
    enable_sqs_kms_key          = true

    # Session Manager
    enable_session_manager_logging         = true
    enable_session_manager_s3_logging      = true
    session_manager_s3_bucket_name         = "tlz-session-logs"
    session_manager_s3_key_prefix          = "sessions/"
    session_manager_cloudwatch_log_group   = "/aws/ssm/sessions"
    session_manager_kms_key_id             = "arn:aws:kms:eu-central-1:123456789012:key/99999999-8888-7777-6666-555555555555"
    session_manager_attach_policy_to_roles = ["TlzEc2Role", "TlzOpsRole"]

    # SSM documents, sharing and inventory sync
    ssm_document_share_targets = ["333333333333"]
    ssm_documents = [
      {
        name          = "tlz-patch-baseline"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
      }
    ]
    enable_ssm_resource_data_sync = true
    ssm_resource_data_sync_prefix = "inventory/"

    # Firewall config bucket
    enable_firewall_config_bucket      = true
    firewall_config_bucket_name        = "tlz-firewall-config"
    firewall_config_bucket_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/12121212-3434-5656-7878-909090909090"

    # Custom EBS key and password policy
    ebs_default_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/deadbeef-1111-2222-3333-444444444444"
    password_policy = {
      minimum_length            = 20
      max_age                   = 60
      password_reuse_prevention = 12
      hard_expiry               = true
      require_symbols           = false
    }
  }

  # --- Customer-managed KMS keys ---
  assert {
    condition     = length(aws_kms_key.custom) == 1 && length(aws_kms_alias.custom) == 1
    error_message = "One customer-managed KMS key and alias must be created."
  }

  assert {
    condition     = aws_kms_alias.custom["tlz/app-secrets"].name == "alias/tlz/app-secrets"
    error_message = "KMS alias must be prefixed with alias/."
  }

  assert {
    condition     = aws_kms_key.custom["tlz/app-secrets"].deletion_window_in_days == 7
    error_message = "KMS deletion window must honour the configured value."
  }

  # --- Dedicated service keys ---
  assert {
    condition     = length(aws_kms_key.lambda_encryption) == 1 && length(aws_kms_alias.lambda_encryption) == 1
    error_message = "A Lambda encryption key must be created when no key ARN is supplied."
  }

  assert {
    condition = alltrue([
      length(aws_kms_key.per_account_cloudwatch) == 1,
      length(aws_kms_key.per_account_lambda) == 1,
      length(aws_kms_key.sqs) == 1,
    ])
    error_message = "Per-account CloudWatch/Lambda keys and the SQS key must be created when enabled."
  }

  assert {
    condition     = aws_kms_alias.sqs[0].name == "alias/tlz/sqs/kms"
    error_message = "SQS key alias must be alias/tlz/sqs/kms."
  }

  # --- Session Manager ---
  assert {
    condition     = length(aws_ssm_document.session_manager) == 1
    error_message = "Session Manager document must be created when logging is enabled."
  }

  assert {
    condition     = strcontains(aws_ssm_document.session_manager[0].content, "tlz-session-logs")
    error_message = "Session Manager document must reference the S3 logging bucket."
  }

  assert {
    condition     = length(aws_iam_policy.session_manager_ec2) == 1 && length(aws_iam_role_policy_attachment.session_manager_ec2) == 2
    error_message = "The Session Manager policy must be attached to every configured role."
  }

  # The resource the toggle governs, not an echo of the toggle.
  assert {
    condition     = length(aws_ssm_document.session_manager) == 1
    error_message = "The Session Manager document must be created when session manager logging is enabled."
  }

  # --- SSM documents and inventory sync ---
  assert {
    condition     = length(aws_ssm_document.custom) == 1
    error_message = "One custom SSM document must be created."
  }

  assert {
    condition     = aws_ssm_document.custom["tlz-patch-baseline"].permissions.account_ids == "333333333333"
    error_message = "Custom SSM documents must be shared with the configured accounts."
  }

  assert {
    condition     = length(aws_ssm_resource_data_sync.this) == 1
    error_message = "SSM inventory sync must be created when enabled with a central bucket."
  }

  assert {
    condition     = one(aws_ssm_resource_data_sync.this[0].s3_destination).prefix == "inventory/"
    error_message = "SSM inventory sync must use the configured prefix."
  }

  # --- Firewall config bucket ---
  assert {
    condition = alltrue([
      length(aws_s3_bucket.firewall_config) == 1,
      length(aws_s3_bucket_versioning.firewall_config) == 1,
      length(aws_s3_bucket_public_access_block.firewall_config) == 1,
      length(aws_s3_bucket_lifecycle_configuration.firewall_config) == 1,
      length(aws_iam_role.firewall_config_reader) == 1,
      length(aws_iam_instance_profile.firewall_config_reader) == 1,
      length(aws_iam_role_policy.firewall_config_reader_s3) == 1,
      length(aws_iam_role_policy.firewall_config_reader_kms) == 1,
    ])
    error_message = "The firewall config bucket and its reader role must be created when enabled."
  }

  # The lifecycle rule removes incomplete multipart uploads; retention of
  # config object versions stays with the deployment.
  assert {
    condition = alltrue([
      aws_s3_bucket_lifecycle_configuration.firewall_config[0].rule[0].status == "Enabled",
      aws_s3_bucket_lifecycle_configuration.firewall_config[0].rule[0].abort_incomplete_multipart_upload[0].days_after_initiation == 7,
    ])
    error_message = "The firewall config bucket lifecycle must abort incomplete multipart uploads after 7 days."
  }

  # --- Custom EBS key ---
  assert {
    condition     = length(aws_ebs_default_kms_key.this) == 1 && length(aws_kms_key.ebs_default) == 0
    error_message = "A supplied EBS key ARN must be assigned instead of creating a new key."
  }

  # --- Custom password policy ---
  # As in the defaults scenario: read from the resource.
  assert {
    condition = alltrue([
      aws_iam_account_password_policy.this.minimum_password_length == 20,
      aws_iam_account_password_policy.this.max_password_age == 60,
      aws_iam_account_password_policy.this.password_reuse_prevention == 12,
      aws_iam_account_password_policy.this.require_symbols == false,
    ])
    error_message = "Custom password policy values must be applied."
  }

  assert {
    condition     = aws_iam_account_password_policy.this.hard_expiry == true
    error_message = "hard_expiry must be applied from the password policy input."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3d: Custom configuration — default VPC hardening (documented limits)
# -----------------------------------------------------------------------------
run "custom_configuration_default_vpc_hardening" {
  command = plan

  variables {
    audit_account_id               = "222222222222"
    root_credentials_management    = false
    allow_root_sessions            = false
    enable_delete_default_vpc      = true
    enable_delete_default_sg_rules = true
    default_vpc_id                 = "vpc-0123456789abcdef0"
  }

  # Both features carry a documented single-region / single-VPC limitation
  expect_failures = [
    check.default_vpc_single_region_limitation,
    check.default_sg_per_vpc_limitation,
  ]

  assert {
    condition     = length(aws_default_vpc.this) == 1
    error_message = "The default VPC must be adopted when enable_delete_default_vpc is true."
  }

  assert {
    condition     = aws_default_vpc.this[0].force_destroy == true
    error_message = "Default VPC adoption must set force_destroy."
  }

  assert {
    condition     = length(aws_default_security_group.this) == 1
    error_message = "The default security group must be adopted when rule removal is enabled."
  }

  assert {
    condition     = aws_default_security_group.this[0].vpc_id == "vpc-0123456789abcdef0"
    error_message = "The default security group must be adopted in the supplied VPC."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4a: Validation failure — invalid audit account ID
# -----------------------------------------------------------------------------
run "invalid_audit_account_id_rejected" {
  command = plan

  variables {
    audit_account_id            = "22222"
    root_credentials_management = false
    allow_root_sessions         = false
  }

  expect_failures = [
    var.audit_account_id,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4b: Validation failure — password policy out of range
# -----------------------------------------------------------------------------
run "invalid_password_policy_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    password_policy = {
      minimum_length = 4
    }
  }

  expect_failures = [
    var.password_policy,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4c: Validation failure — unsupported GuardDuty export frequency
# -----------------------------------------------------------------------------
run "invalid_guardduty_export_frequency_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    guardduty_export_frequency  = "EVERY_MINUTE"
  }

  expect_failures = [
    var.guardduty_export_frequency,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4d: Validation failure — invalid KMS alias
# -----------------------------------------------------------------------------
run "invalid_kms_alias_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    kms_keys = [
      {
        alias = "invalid alias!"
      }
    ]
  }

  expect_failures = [
    var.kms_keys,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4e: Validation failure — invalid excluded region format
# -----------------------------------------------------------------------------
run "invalid_excluded_region_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    guardduty_excluded_regions  = ["EU-Central-1"]
  }

  expect_failures = [
    var.guardduty_excluded_regions,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4f: Validation failure — unsupported SSM document type
# -----------------------------------------------------------------------------
run "invalid_ssm_document_type_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    ssm_documents = [
      {
        name          = "tlz-broken"
        document_type = "Workflow"
        content       = "{}"
      }
    ]
  }

  expect_failures = [
    var.ssm_documents,
  ]
}

# =============================================================================
# Wiring, guard and singleton scenarios
# =============================================================================
# All of them are unreachable while the module does not load, so they double
# as the guard for the resource type that the pinned provider does not know.

# -----------------------------------------------------------------------------
# Scenario 5a: FMS notification channel without provider support
# -----------------------------------------------------------------------------
# aws_fms_notification_channel does not exist in the pinned provider; declaring
# it would stop the module from loading and abort every scenario in this file —
# a count guard does not protect against that. The toggle only trips documented
# limitation checks.
run "regression_fms_notification_channel_has_no_resource" {
  command = plan

  variables {
    audit_account_id                = "222222222222"
    root_credentials_management     = false
    allow_root_sessions             = false
    enable_fms_notification_channel = true
    fms_notification_sns_topic_arn  = "arn:aws:sns:eu-central-1:123456789012:tlz-fms-alerts"
    fms_notification_sns_role_name  = "FMSNotificationRole"
    fms_policies                    = []
  }

  expect_failures = [
    check.fms_notification_channel_provider_limitation,
    check.fms_notification_requires_delegated_admin,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5b: one resource per per-account singleton service
# -----------------------------------------------------------------------------
# A second resource block for the same per-account activation of Macie or
# Audit Manager would plan a second instance of the same AWS resource once a
# publishing frequency or a reports destination is set. Both settings are
# active here, and the counts must stay 1.
run "regression_singleton_services_planned_once" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false

    enable_macie               = true
    is_eusc                    = false
    macie_publishing_frequency = "SIX_HOURS"

    enable_audit_manager = true
    audit_manager_reports_destination = {
      s3_bucket_name = "tlz-audit-manager-reports"
      s3_prefix      = "reports"
      kms_key_arn    = "arn:aws:kms:eu-central-1:123456789012:key/abababab-cdcd-efef-0101-232323232323"
    }
  }

  expect_failures = [
    check.audit_manager_reports_destination_provider_limitation,
    check.audit_manager_maintenance_mode,
  ]

  assert {
    condition     = length(aws_macie2_account.this) == 1
    error_message = "Macie activation must be planned exactly once even with a publishing frequency set."
  }

  assert {
    condition     = aws_macie2_account.this[0].finding_publishing_frequency == "SIX_HOURS"
    error_message = "The publishing frequency must be carried by the single Macie activation."
  }

  assert {
    condition     = length(aws_auditmanager_account_registration.this) == 1
    error_message = "Audit Manager registration must be planned exactly once even with a reports destination set."
  }

  assert {
    condition     = aws_auditmanager_account_registration.this[0].kms_key == "arn:aws:kms:eu-central-1:123456789012:key/abababab-cdcd-efef-0101-232323232323"
    error_message = "The supported part of the reports destination (kms_key_arn) must reach the registration."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5c: module-managed EBS key is registered as default
# -----------------------------------------------------------------------------
# In the module default (no external key ARN) the module creates its own CMK;
# unless aws_ebs_default_kms_key registers it, EBS keeps using the AWS-managed
# aws/ebs key.
run "regression_ebs_module_key_is_registered" {
  command = plan

  variables {
    audit_account_id              = "222222222222"
    root_credentials_management   = false
    allow_root_sessions           = false
    enable_ebs_default_encryption = true
    ebs_default_kms_key_arn       = ""
  }

  assert {
    condition     = length(aws_kms_key.ebs_default) == 1 && length(aws_kms_alias.ebs_default) == 1
    error_message = "A module-managed EBS key and alias must be created when no key ARN is supplied."
  }

  assert {
    condition     = length(aws_ebs_default_kms_key.this) == 1
    error_message = "The module-managed EBS key must be registered as the account-wide default encryption key."
  }

  assert {
    condition     = length(aws_ebs_encryption_by_default.this) == 1
    error_message = "EBS default encryption must be switched on alongside the key registration."
  }

  assert {
    condition     = [for s in data.aws_iam_policy_document.ebs_default_key_policy[0].statement : s.sid] == ["EnableRootAccountAccess"]
    error_message = "Without the Auto Scaling service-linked role in the account the key policy must name no further principal — KMS refuses a principal that does not exist."
  }
}

# EC2 Auto Scaling launches encrypted volumes through its
# service-linked role, which the customer managed default key has to name.
# The lookup finds the role here, so both documented grants must be planned.
run "regression_ebs_module_key_grants_autoscaling_service_linked_role" {
  command = plan

  override_data {
    target = data.aws_iam_roles.autoscaling_service_linked
    values = {
      arns = ["arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
    }
  }

  variables {
    audit_account_id              = "222222222222"
    root_credentials_management   = false
    allow_root_sessions           = false
    enable_ebs_default_encryption = true
    ebs_default_kms_key_arn       = ""
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.ebs_default_key_policy[0].statement :
      s.sid == "AllowAutoScalingServiceLinkedRoleUse"
      && one(s.principals).identifiers == toset(["arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"])
      && toset(s.actions) == toset(["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"])
    ])
    error_message = "The key policy must let the Auto Scaling service-linked role encrypt, decrypt and generate data keys."
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.ebs_default_key_policy[0].statement :
      s.sid == "AllowAutoScalingServiceLinkedRoleGrants"
      && toset(s.actions) == toset(["kms:CreateGrant"])
      && try(one(s.condition).variable, "") == "kms:GrantIsForAWSResource"
      && try(toset(one(s.condition).values), toset([])) == toset(["true"])
    ])
    error_message = "The key policy must let the Auto Scaling service-linked role create grants, and only for AWS resources."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5d: GuardDuty export writes below the configured prefix
# -----------------------------------------------------------------------------
# guardduty_export_prefix must reach destination_arn: an export to the bucket
# root while the lifecycle rule filters on the prefix would leave the retention
# rule matching nothing. Both share one prefix.
run "regression_guardduty_export_prefix_reaches_destination" {
  command = plan

  variables {
    audit_account_id                     = "222222222222"
    root_credentials_management          = false
    allow_root_sessions                  = false
    central_log_bucket_name              = "tlz-central-logs"
    guardduty_export_frequency           = "SIX_HOURS"
    guardduty_export_kms_key_arn         = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    guardduty_export_prefix              = "findings/guardduty/"
    guardduty_lifecycle_rules            = { retention_days = 365 }
    replace_central_log_bucket_lifecycle = true
  }

  assert {
    condition     = aws_guardduty_publishing_destination.this[0].destination_arn == "arn:aws:s3:::tlz-central-logs/findings/guardduty"
    error_message = "The export destination must address the configured prefix inside the central log bucket."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule).filter[0].prefix == "findings/guardduty/"
    error_message = "The lifecycle rule must filter on the same prefix the export writes to."
  }

  # The export runs here beside a designated administrator, which the module
  # reports.
  expect_failures = [
    check.finding_consumers_in_administrator,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5e: GuardDuty export rejects a missing KMS key
# -----------------------------------------------------------------------------
# An enabled export with the empty-string default for
# guardduty_export_kms_key_arn would plan a publishing destination with an empty
# required argument, which AWS rejects at apply time. The cross-variable
# validation rejects the combination before the plan.
run "regression_guardduty_export_without_kms_key_rejected" {
  command = plan

  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    central_log_bucket_name      = "tlz-central-logs"
    guardduty_export_frequency   = "SIX_HOURS"
    guardduty_export_kms_key_arn = ""
  }

  # The export is configured here beside a designated administrator; the
  # module reports that too.
  expect_failures = [
    var.guardduty_export_kms_key_arn,
    check.finding_consumers_in_administrator,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5f: invalid GuardDuty export KMS ARN is rejected
# -----------------------------------------------------------------------------
run "regression_invalid_guardduty_export_kms_arn_rejected" {
  command = plan

  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    guardduty_export_kms_key_arn = "not-an-arn"
  }

  expect_failures = [
    var.guardduty_export_kms_key_arn,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5g: resource policy rules need an evaluator ARN
# -----------------------------------------------------------------------------
# A Config rule with lambda_function_arn = "" carries a required argument AWS
# rejects, which would make the whole feature undeployable. Without an
# evaluator ARN nothing is planned, and the gap is reported by a check.
run "regression_resource_policy_without_evaluator_plans_nothing" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    resource_policy_enforcement = [
      {
        resource_type      = "AWS::S3::Bucket"
        policy_template    = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        remediation_action = "TlzRemediateResourcePolicy"
      }
    ]
  }

  expect_failures = [
    check.resource_policy_enforcement_requires_evaluator,
  ]

  assert {
    condition     = length(aws_config_organization_custom_rule.resource_policy) == 0
    error_message = "No Config rule must be planned while no Lambda evaluator ARN is configured."
  }

  assert {
    condition     = length(aws_config_remediation_configuration.resource_policy) == 0
    error_message = "No remediation must be planned while no Config rule exists."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5h: resource policy rules use the supplied evaluator
# -----------------------------------------------------------------------------
run "regression_resource_policy_with_evaluator_is_deployable" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    resource_policy_enforcement_lambda_arn = "arn:aws:lambda:eu-central-1:123456789012:function:tlz-resource-policy-evaluator"
    resource_policy_enforcement = [
      {
        resource_type      = "AWS::S3::Bucket"
        policy_template    = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        remediation_action = "TlzRemediateResourcePolicy"
      },
      {
        resource_type   = "AWS::KMS::Key"
        policy_template = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        enabled         = false
      }
    ]
  }

  assert {
    condition     = length(aws_config_organization_custom_rule.resource_policy) == 1
    error_message = "Exactly the enabled entries must plan a Config rule."
  }

  assert {
    condition     = aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].lambda_function_arn == "arn:aws:lambda:eu-central-1:123456789012:function:tlz-resource-policy-evaluator"
    error_message = "The Config rule must reference the supplied Lambda evaluator instead of a placeholder."
  }

  assert {
    condition     = length(aws_config_remediation_configuration.resource_policy) == 1
    error_message = "An entry with a remediation action must plan a remediation configuration."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5i: invalid evaluator ARN is rejected
# -----------------------------------------------------------------------------
run "regression_invalid_resource_policy_evaluator_arn_rejected" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    resource_policy_enforcement_lambda_arn = "arn:aws:s3:::not-a-lambda"
  }

  expect_failures = [
    var.resource_policy_enforcement_lambda_arn,
  ]
}

# =============================================================================
# Module features wired through the stack
# =============================================================================
# stacks/management/security passes the module variables below. The scenarios
# hold the module side of that wiring: for each group the value has to arrive
# at a resource, and the switched-off state has to stay empty.

# -----------------------------------------------------------------------------
# Scenario 5j: GuardDuty protection plans follow their toggles
# -----------------------------------------------------------------------------
# The four data-source protection plans carry the module default true, so the
# switched-off state is the one to pin: the documented option to switch a plan
# off has to reach the resource. EBS malware protection
# has no toggle in this module and stays ENABLED.
run "regression_guardduty_protection_plans_follow_toggles" {
  command = plan

  variables {
    audit_account_id                 = "222222222222"
    root_credentials_management      = false
    allow_root_sessions              = false
    guardduty_s3_protection          = false
    guardduty_eks_protection         = false
    guardduty_lambda_protection      = false
    guardduty_rds_protection         = false
    guardduty_eks_runtime_monitoring = false
  }

  assert {
    condition = alltrue([
      aws_guardduty_detector_feature.s3_logs[0].status == "DISABLED",
      aws_guardduty_detector_feature.eks_audit_logs[0].status == "DISABLED",
      aws_guardduty_detector_feature.lambda_protection[0].status == "DISABLED",
      aws_guardduty_detector_feature.rds_protection[0].status == "DISABLED",
      aws_guardduty_detector_feature.eks_runtime_monitoring[0].status == "DISABLED",
    ])
    error_message = "Every GuardDuty protection plan must follow its toggle into the DISABLED state."
  }

  assert {
    condition     = aws_guardduty_detector_feature.ebs_malware[0].status == "ENABLED"
    error_message = "EBS malware protection has no toggle in this module and must stay ENABLED."
  }

  assert {
    condition     = length(aws_guardduty_detector_feature.eks_runtime_monitoring[0].additional_configuration) == 0
    error_message = "With runtime monitoring off there is nothing to manage, so no EKS_ADDON_MANAGEMENT sub-configuration must be submitted."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5k: GuardDuty manages the EKS agent when asked to
# -----------------------------------------------------------------------------
# guardduty_eks_manage_agent ("When false, EKS agent must be deployed
# manually") must reach the module. Its place is the additional configuration EKS_ADDON_MANAGEMENT of the runtime
# monitoring detector feature, the same form modules/security-org-config uses.
run "regression_guardduty_eks_addon_management_is_enabled" {
  command = plan

  variables {
    audit_account_id                 = "222222222222"
    root_credentials_management      = false
    allow_root_sessions              = false
    guardduty_eks_runtime_monitoring = true
    guardduty_eks_manage_agent       = true
  }

  assert {
    condition     = aws_guardduty_detector_feature.eks_runtime_monitoring[0].status == "ENABLED"
    error_message = "EKS runtime monitoring must be ENABLED when its toggle is on."
  }

  assert {
    condition     = one(aws_guardduty_detector_feature.eks_runtime_monitoring[0].additional_configuration).name == "EKS_ADDON_MANAGEMENT"
    error_message = "Agent management must be submitted as the EKS_ADDON_MANAGEMENT additional configuration of the runtime monitoring feature."
  }

  assert {
    condition     = one(aws_guardduty_detector_feature.eks_runtime_monitoring[0].additional_configuration).status == "ENABLED"
    error_message = "guardduty_eks_manage_agent = true must set EKS_ADDON_MANAGEMENT to ENABLED."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5l: manual EKS agent deployment stays possible
# -----------------------------------------------------------------------------
run "regression_guardduty_eks_addon_management_is_disabled" {
  command = plan

  variables {
    audit_account_id                 = "222222222222"
    root_credentials_management      = false
    allow_root_sessions              = false
    guardduty_eks_runtime_monitoring = true
    guardduty_eks_manage_agent       = false
  }

  assert {
    condition     = one(aws_guardduty_detector_feature.eks_runtime_monitoring[0].additional_configuration).status == "DISABLED"
    error_message = "guardduty_eks_manage_agent = false must set EKS_ADDON_MANAGEMENT to DISABLED so the agent can be deployed manually."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5m: GuardDuty region exclusions are reported
# -----------------------------------------------------------------------------
# The two region lists cannot narrow a single-region deployment; the module
# surfaces the mismatch with a check instead of silently ignoring the value. Both
# lists carry the deployment region here, so both checks have to report.
run "regression_guardduty_region_exclusions_are_reported" {
  command = plan

  variables {
    audit_account_id                         = "222222222222"
    root_credentials_management              = false
    allow_root_sessions                      = false
    guardduty_excluded_regions               = ["eu-central-1", "eu-west-1"]
    guardduty_s3_protection_excluded_regions = ["eu-central-1"]
  }

  expect_failures = [
    check.guardduty_excluded_region_check,
    check.guardduty_s3_protection_excluded_region_check,
  ]

  assert {
    condition     = length(aws_guardduty_detector.this) == 1
    error_message = "The excluded regions must not remove the detector of the deployment region — the mismatch is reported, not applied."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5n: GuardDuty deployment targets are reported
# -----------------------------------------------------------------------------
# Same input as run "guardduty_deployment_targets_warning" in
# modules/security-org-config/tests/security-org-config.tftest.hcl: both modules
# read one loader local for the target selection, so both have to answer the same
# input the same way — accept it, report the provider limitation, keep the
# management-account configuration.
run "regression_guardduty_deployment_targets_are_reported" {
  command = plan

  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    guardduty_deployment_targets = ["111111111111", "ou-abc1-11111111"]
  }

  expect_failures = [
    check.guardduty_deployment_targets_warning,
  ]

  assert {
    condition     = length(aws_guardduty_detector.this) == 1
    error_message = "GuardDuty must still be configured in the management account when deployment targets are set."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5o: supplied encryption keys replace the module keys
# -----------------------------------------------------------------------------
# Lambda encryption, the SQS key and the per-account keys were unreachable: no
# stack set their toggles. The supplied-ARN branch of the Lambda key had no
# scenario at all, so the module could have created a second key next to the
# supplied one without any test noticing.
run "regression_encryption_uses_supplied_keys" {
  command = plan

  variables {
    audit_account_id              = "222222222222"
    root_credentials_management   = false
    allow_root_sessions           = false
    enable_lambda_encryption      = true
    lambda_encryption_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/cccccccc-dddd-eeee-ffff-000000000000"
    enable_sqs_kms_key            = true
    enable_per_account_kms_keys   = true
  }

  assert {
    condition     = length(aws_kms_key.lambda_encryption) == 0 && length(aws_kms_alias.lambda_encryption) == 0
    error_message = "A supplied Lambda encryption key ARN must be used instead of creating a module-managed key."
  }

  assert {
    condition = alltrue([
      length(aws_kms_key.sqs) == 1,
      length(aws_kms_key.per_account_cloudwatch) == 1,
      length(aws_kms_key.per_account_lambda) == 1,
    ])
    error_message = "The SQS key and both per-account keys must be created when their toggles are on."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5p: EBS encryption region exclusion is reported
# -----------------------------------------------------------------------------
run "regression_ebs_encryption_region_exclusion_is_reported" {
  command = plan

  variables {
    audit_account_id                = "222222222222"
    root_credentials_management     = false
    allow_root_sessions             = false
    enable_ebs_default_encryption   = true
    ebs_encryption_excluded_regions = ["eu-central-1"]
  }

  expect_failures = [
    check.ebs_encryption_excluded_region_check,
  ]

  assert {
    condition     = length(aws_ebs_encryption_by_default.this) == 1
    error_message = "The excluded region must not silently switch off encryption in the deployment region — the mismatch is reported."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5q: the S3 logging toggle wins over the bucket name
# -----------------------------------------------------------------------------
# The variable description promises the toggle wins: "When false, s3BucketName is
# set to empty regardless of session_manager_s3_bucket_name". Nothing tested that
# promise, because no stack could set either value. Prefix and bucket both have
# to disappear from the session document while the toggle is off.
run "regression_session_manager_s3_logging_toggle_wins" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    enable_session_manager_logging    = true
    enable_session_manager_s3_logging = false
    session_manager_s3_bucket_name    = "tlz-session-logs"
    session_manager_s3_key_prefix     = "sessions/"
  }

  assert {
    condition     = length(aws_ssm_document.session_manager) == 1
    error_message = "The session document must still be created for CloudWatch-only logging."
  }

  assert {
    condition     = !strcontains(aws_ssm_document.session_manager[0].content, "tlz-session-logs")
    error_message = "With enable_session_manager_s3_logging = false the bucket name must not reach the session document."
  }

  assert {
    condition     = !strcontains(aws_ssm_document.session_manager[0].content, "sessions/")
    error_message = "With enable_session_manager_s3_logging = false the key prefix must not reach the session document either."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5r: S3 session logging without a bucket is reported
# -----------------------------------------------------------------------------
# session_manager_s3_bucket_name defaults to the empty string, and the loader
# passes that default through. Switching S3 logging on without naming a bucket is
# therefore the likely misconfiguration, and the module has to say so.
run "regression_session_manager_s3_logging_without_bucket_is_reported" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    enable_session_manager_logging    = true
    enable_session_manager_s3_logging = true
    session_manager_s3_bucket_name    = ""
  }

  expect_failures = [
    check.session_manager_s3_logging_no_bucket,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5r-2: export features without the central log bucket
# name are reported, not silently dropped
# -----------------------------------------------------------------------------
# Three features write to the central log bucket and multiply their count by
# central_log_bucket_name != "". With the name empty every one of them plans
# zero resources and the plan looks complete; the check names the skipped
# features. Each of the three consumers is switched on here so the message
# lists all of them, and the run pins that the resources are indeed absent —
# the check reports the skip, it does not create anything.
run "regression_export_features_without_central_log_bucket_are_reported" {
  command = plan

  variables {
    audit_account_id                      = "222222222222"
    root_credentials_management           = false
    allow_root_sessions                   = false
    enable_guardduty                      = true
    guardduty_export_frequency            = "SIX_HOURS"
    guardduty_export_kms_key_arn          = "arn:aws:kms:eu-central-1:111111111111:key/11111111-2222-3333-4444-555555555555"
    enable_macie                          = true
    macie_publish_sensitive_data_findings = true
    enable_ssm_resource_data_sync         = true
    central_log_bucket_name               = ""
  }

  assert {
    condition = alltrue([
      length(aws_guardduty_publishing_destination.this) == 0,
      length(aws_macie2_classification_export_configuration.this) == 0,
      length(aws_ssm_resource_data_sync.this) == 0,
    ])
    error_message = "With central_log_bucket_name empty none of the three export resources may be planned — the check reports the skip, it must not change the count gates."
  }

  assert {
    condition     = length(local.central_log_bucket_consumers) == 3
    error_message = "All three enabled consumers of the central log bucket must be named in the warning."
  }

  expect_failures = [
    check.central_log_bucket_configured,
  ]
}

# The same three features with the bucket name present raise no bucket check:
# the guard is about the empty name, not about the features. The one warning
# left is the administrator one — the export runs here while audit_account_id
# names a delegated administrator.
run "regression_export_features_with_central_log_bucket_raise_no_bucket_guard" {
  command = plan

  variables {
    audit_account_id                      = "222222222222"
    root_credentials_management           = false
    allow_root_sessions                   = false
    enable_guardduty                      = true
    guardduty_export_frequency            = "SIX_HOURS"
    guardduty_export_kms_key_arn          = "arn:aws:kms:eu-central-1:111111111111:key/11111111-2222-3333-4444-555555555555"
    enable_macie                          = true
    macie_publish_sensitive_data_findings = true
    enable_ssm_resource_data_sync         = true
    central_log_bucket_name               = "tlz-central-logs"
  }

  assert {
    condition = alltrue([
      length(aws_guardduty_publishing_destination.this) == 1,
      length(aws_macie2_classification_export_configuration.this) == 1,
      length(aws_ssm_resource_data_sync.this) == 1,
    ])
    error_message = "With central_log_bucket_name set all three export resources must be planned."
  }

  expect_failures = [
    check.finding_consumers_in_administrator,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5r-ii: a session log group that does not exist is reported
# -----------------------------------------------------------------------------
# The SSM Document API accepts any string as a logging target, so a log group
# nothing creates applies cleanly and fails only when an operator opens a
# session. The check looks the name up through a prefix listing; this run
# answers that listing with a near miss — the account holds a group that shares
# the prefix but not the name — so the check has to fire on the exact-name
# comparison, not merely on an empty answer. Scenario 3c is the only run that
# describes the world in which the fictional names exist; every other run, this
# one included, keeps the module's real answer.
run "regression_session_manager_missing_log_group_is_reported" {
  command = plan

  override_data {
    target = data.aws_cloudwatch_log_groups.session_manager
    values = {
      log_group_names = ["/aws/ssm/sessions-archive"]
      arns            = ["arn:aws:logs:eu-central-1:123456789012:log-group:/aws/ssm/sessions-archive"]
    }
  }

  variables {
    audit_account_id                     = "222222222222"
    root_credentials_management          = false
    allow_root_sessions                  = false
    enable_session_manager_logging       = true
    session_manager_cloudwatch_log_group = "/aws/ssm/sessions"
  }

  assert {
    condition     = length(aws_ssm_document.session_manager) == 1
    error_message = "The session document is still planned — the check warns, it does not block; the operator decides whether to create the group or fix the name."
  }

  expect_failures = [
    check.session_manager_cloudwatch_log_group_exists,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5r-iii: a session log bucket that does not exist is reported
# -----------------------------------------------------------------------------
# Same defect for the S3 target. The existing check
# session_manager_s3_logging_no_bucket covers only the EMPTY name; this one
# covers a NAMED bucket that ListBuckets does not return. No override here: the
# mock provider's empty listing is the "nothing with that prefix exists" answer.
run "regression_session_manager_missing_bucket_is_reported" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    enable_session_manager_logging    = true
    enable_session_manager_s3_logging = true
    session_manager_s3_bucket_name    = "tlz-session-logs"
  }

  assert {
    condition     = strcontains(aws_ssm_document.session_manager[0].content, "tlz-session-logs")
    error_message = "The bucket name still reaches the session document — the check warns, it does not rewrite the configuration."
  }

  expect_failures = [
    check.session_manager_s3_bucket_exists,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5s: SSM sharing exclusion for this account is reported
# -----------------------------------------------------------------------------
run "regression_ssm_sharing_exclusion_is_reported" {
  command = plan

  variables {
    audit_account_id                           = "222222222222"
    root_credentials_management                = false
    allow_root_sessions                        = false
    enable_ssm_block_public_sharing            = true
    ssm_block_public_sharing_excluded_accounts = ["123456789012"]
  }

  expect_failures = [
    check.ssm_block_public_sharing_excluded_account_check,
  ]

  assert {
    condition     = length(aws_ssm_service_setting.public_sharing) == 1
    error_message = "The exclusion list must not silently drop the setting — the module still blocks sharing and reports the mismatch."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5t: Security Hub aggregation toggle wins over regions
# -----------------------------------------------------------------------------
# The aggregation switch carries the module default true, so the switched-off
# state is the one to pin. Configured aggregation regions must not bring
# the aggregator back.
run "regression_security_hub_aggregation_toggle_wins" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    enable_security_hub                    = true
    enable_security_hub_region_aggregation = false
    security_hub_aggregation_regions       = ["eu-central-1", "eu-west-1"]
  }

  assert {
    condition     = length(aws_securityhub_finding_aggregator.this) == 0
    error_message = "No finding aggregator must be planned while enable_security_hub_region_aggregation is false."
  }


  assert {
    condition     = length(aws_securityhub_account.this) == 1
    error_message = "Security Hub itself must stay enabled — only the cross-region aggregation is off."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5u: Security Hub and Macie region exclusions reported
# -----------------------------------------------------------------------------
run "regression_security_hub_and_macie_region_exclusions_are_reported" {
  command = plan

  variables {
    audit_account_id              = "222222222222"
    root_credentials_management   = false
    allow_root_sessions           = false
    enable_security_hub           = true
    enable_macie                  = true
    is_eusc                       = false
    security_hub_excluded_regions = ["eu-central-1"]
    macie_excluded_regions        = ["eu-central-1"]
  }

  expect_failures = [
    check.security_hub_excluded_region_check,
    check.macie_excluded_region_check,
  ]

  assert {
    condition     = length(aws_securityhub_account.this) == 1 && length(aws_macie2_account.this) == 1
    error_message = "Both services must still be activated in the deployment region — the exclusion is reported, not applied."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5v: lifecycle days 0 means no lifecycle rule
# -----------------------------------------------------------------------------
# The variable description documents 0 as "disable lifecycle". That is why the
# loader merges audit_manager_bucket_lifecycle_days with max() over base.tfvars
# and env/common.hcl only and deliberately not against log_retention_days — a
# max() against the merged retention would make 0 unreachable.
run "regression_audit_manager_lifecycle_zero_means_none" {
  command = plan

  variables {
    audit_account_id                    = "222222222222"
    root_credentials_management         = false
    allow_root_sessions                 = false
    enable_audit_manager                = true
    enable_audit_manager_bucket         = true
    audit_manager_bucket_lifecycle_days = 0
    audit_manager_bucket_kms_key_arn    = ""
  }

  assert {
    condition     = length(aws_s3_bucket.audit_manager_reports) == 1
    error_message = "The reports bucket must be created even without a lifecycle rule."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.audit_manager_reports) == 0
    error_message = "audit_manager_bucket_lifecycle_days = 0 must plan no lifecycle configuration."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.audit_manager_reports[0].rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "Without a KMS key ARN the reports bucket must fall back to AES256."
  }

  # enable_audit_manager = true fires the maintenance-mode warning (new
  # registrations refused by AWS since April 30, 2026).
  expect_failures = [
    check.audit_manager_maintenance_mode,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5w: the reports bucket toggle wins over Audit Manager
# -----------------------------------------------------------------------------
run "regression_audit_manager_bucket_toggle_wins" {
  command = plan

  variables {
    audit_account_id                    = "222222222222"
    root_credentials_management         = false
    allow_root_sessions                 = false
    enable_audit_manager                = true
    enable_audit_manager_bucket         = false
    audit_manager_bucket_lifecycle_days = 180
  }

  assert {
    condition     = length(aws_auditmanager_account_registration.this) == 1
    error_message = "Audit Manager itself must stay registered when only the reports bucket is off."
  }

  assert {
    condition = alltrue([
      length(aws_s3_bucket.audit_manager_reports) == 0,
      length(aws_s3_bucket_versioning.audit_manager_reports) == 0,
      length(aws_s3_bucket_server_side_encryption_configuration.audit_manager_reports) == 0,
      length(aws_s3_bucket_public_access_block.audit_manager_reports) == 0,
      length(aws_s3_bucket_lifecycle_configuration.audit_manager_reports) == 0,
    ])
    error_message = "No reports bucket resource must be planned while enable_audit_manager_bucket is false."
  }

  # enable_audit_manager = true fires the maintenance-mode warning (new
  # registrations refused by AWS since April 30, 2026).
  expect_failures = [
    check.audit_manager_maintenance_mode,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5x: Firewall Manager policies reach a resource
# -----------------------------------------------------------------------------
# var.fms_policies is wired (aws_fms_policy exists in the pinned provider) and
# must plan a policy. This is the difference to the two notification-channel
# values, for which the provider has no resource at all — run
# regression_fms_notification_channel_has_no_resource keeps that apart.
run "regression_fms_policies_are_planned" {
  command = plan

  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    fms_admin_account_registered = true
    fms_policies = [
      {
        name                = "tlz-waf-baseline"
        type                = "WAF"
        resource_type_list  = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        remediation_enabled = true
        include_map         = ["111111111111"]
      }
    ]
  }

  # With the administrator registration acknowledged the plan is clean: no
  # expect_failures. The predecessor check fired on every non-empty policy list,
  # so an operator who had done the out-of-band step still saw a warning.

  assert {
    condition     = length(aws_fms_policy.this) == 1
    error_message = "Each configured FMS policy must plan an aws_fms_policy resource."
  }

  assert {
    condition     = one(aws_fms_policy.this["tlz-waf-baseline"].security_service_policy_data).type == "WAF"
    error_message = "The policy type must reach the security service policy data of the planned policy."
  }

  assert {
    condition     = one(aws_fms_policy.this["tlz-waf-baseline"].include_map).account == toset(["111111111111"])
    error_message = "The include map must reach the planned policy."
  }

  assert {
    condition     = length(aws_fms_policy.this["tlz-waf-baseline"].exclude_map) == 0
    error_message = "An empty exclude map must not produce an exclude_map block."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5x-neg: FMS policies without the administrator
# acknowledgement fail at PLAN time, not at apply
# -----------------------------------------------------------------------------
# aws_fms_policy is accepted only from a Firewall Manager administrator account,
# which this module does not register. Before this guard the module planned the
# policy cleanly and AWS answered InvalidOperationException ("No default admin
# could be found") at apply. The resource precondition moves the failure to the
# plan; the eusc scenario above shows the other side (policy map emptied, no
# instance, no precondition to evaluate).
run "regression_fms_policies_without_admin_acknowledgement_rejected" {
  command = plan

  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    fms_admin_account_registered = false
    fms_policies = [
      {
        name               = "tlz-waf-baseline"
        type               = "WAF"
        resource_type_list = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
      }
    ]
  }

  expect_failures = [
    aws_fms_policy.this,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5x-default: the acknowledgement defaults to false, and an empty
# policy list needs no acknowledgement — the default plan stays clean
# -----------------------------------------------------------------------------
run "regression_fms_admin_acknowledgement_defaults_false_and_is_not_required_without_policies" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
  }

  assert {
    condition     = var.fms_admin_account_registered == false
    error_message = "fms_admin_account_registered must default to false — the acknowledgement is an explicit operator step."
  }

  assert {
    condition     = length(aws_fms_policy.this) == 0
    error_message = "No FMS policy must be planned without fms_policies entries."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5y: S3 public access exclusion for this account
# -----------------------------------------------------------------------------
run "regression_s3_public_access_exclusion_is_reported" {
  command = plan

  variables {
    audit_account_id                         = "222222222222"
    root_credentials_management              = false
    allow_root_sessions                      = false
    enable_s3_public_access_block            = true
    s3_public_access_block_excluded_accounts = ["123456789012"]
  }

  expect_failures = [
    check.s3_pab_excluded_account_check,
  ]

  assert {
    condition     = length(aws_s3_account_public_access_block.this) == 1
    error_message = "The exclusion list must not silently drop the account-level block — the mismatch is reported."
  }
}

# -----------------------------------------------------------------------------
# Scenario 5z: root management placeholders report either switch
# -----------------------------------------------------------------------------
# allow_root_sessions is the only AND-merged switch of the landing zone: its
# restrictive value is false, so a false in any configuration layer disables root
# sessions. The provider has no resource for either setting, so the module has to
# report as soon as one of the two is on — run "defaults_root_management_warning"
# covers both being on, this one covers the mixed state.
run "regression_root_management_reports_single_switch" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = true
    allow_root_sessions         = false
  }

  expect_failures = [
    check.root_credentials_management_provider_limitation,
  ]

}

# =============================================================================
# Configurable S3 lifecycle rules
# =============================================================================
# Four export paths of this module write into S3, and each of them takes a rule
# set in the same shape modules/logging uses. Two of them have a derived
# lifecycle (the GuardDuty export prefix and the Audit Manager reports bucket)
# and the defaults runs hold that plan in place. Two have none (the Macie
# export prefix and the Session Manager logs) and their default creates
# nothing.
#
# The GuardDuty and the Macie rules share one resource because S3 keeps exactly
# one lifecycle configuration per bucket and both prefixes sit on the central log
# bucket. The runs below pin that down from both sides.
# -----------------------------------------------------------------------------
# Without a rule set the derived plan stays unchanged.
run "regression_security_lifecycle_defaults_keep_the_derived_plan" {
  command = plan
  variables {
    audit_account_id                     = "222222222222"
    root_credentials_management          = false
    allow_root_sessions                  = false
    enable_guardduty                     = true
    guardduty_export_frequency           = "FIFTEEN_MINUTES"
    guardduty_lifecycle_rules            = { retention_days = 90 }
    replace_central_log_bucket_lifecycle = true
    guardduty_export_kms_key_arn         = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    central_log_bucket_name              = "tlz-central-logs"
    enable_audit_manager                 = true
    enable_audit_manager_bucket          = true
    audit_manager_bucket_lifecycle_days  = 180
    audit_manager_bucket_kms_key_arn     = ""
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.guardduty_export) == 1
    error_message = "The GuardDuty export lifecycle must still be planned from guardduty_lifecycle_rules alone."
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule) == 1
    error_message = "Without a rule set the export lifecycle must carry exactly the one derived rule."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule[0].id == "guardduty-export-lifecycle"
    error_message = "The derived rule must keep the id guardduty-export-lifecycle."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule[0].expiration).days == 90
    error_message = "The derived rule must expire after guardduty_lifecycle_rules.retention_days."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule[0].abort_incomplete_multipart_upload).days_after_initiation == 7
    error_message = "The derived rule must keep aborting incomplete uploads after 7 days."
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.audit_manager_reports[0].rule) == 1
    error_message = "Without a rule set the reports bucket must keep exactly the one derived rule."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.audit_manager_reports[0].rule[0].id == "audit-manager-reports-lifecycle"
    error_message = "The derived rule of the reports bucket must keep its id."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.audit_manager_reports[0].rule[0].expiration).days == 180
    error_message = "The derived rule of the reports bucket must expire after audit_manager_bucket_lifecycle_days."
  }
  # The two paths that never had a lifecycle must still have none.
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.session_manager_logs) == 0
    error_message = "Without a rule set the Session Manager logs must have no lifecycle — the module never wrote one."
  }

  # enable_audit_manager = true fires the maintenance-mode warning (new
  # registrations refused by AWS since April 30, 2026); the export runs here
  # beside a designated administrator, which the module reports as well.
  expect_failures = [
    check.audit_manager_maintenance_mode,
    check.finding_consumers_in_administrator,
  ]
}
# -----------------------------------------------------------------------------
# Reach: explicit rule sets land on their resource with every attribute.
run "security_lifecycle_rules_reach_the_resources" {
  command = plan
  variables {
    audit_account_id                     = "222222222222"
    root_credentials_management          = false
    allow_root_sessions                  = false
    enable_guardduty                     = true
    guardduty_export_frequency           = "FIFTEEN_MINUTES"
    guardduty_lifecycle_rules            = { retention_days = 90 }
    replace_central_log_bucket_lifecycle = true
    guardduty_export_kms_key_arn         = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    central_log_bucket_name              = "tlz-central-logs"
    enable_audit_manager                 = true
    enable_audit_manager_bucket          = true
    audit_manager_bucket_kms_key_arn     = ""
    guardduty_export_lifecycle_rules = [
      {
        id              = "guardduty-archive"
        prefix          = "guardduty/"
        expiration_days = 2555
        transitions = [
          { storage_class = "STANDARD_IA", days = 30 },
          { storage_class = "DEEP_ARCHIVE", days = 180 },
        ]
        noncurrent_version_expiration_days     = 400
        abort_incomplete_multipart_upload_days = 3
      },
    ]
    audit_manager_bucket_lifecycle_rules = [
      { id = "reports-archive", expiration_days = 400, transitions = [{ storage_class = "GLACIER_IR", days = 30 }] },
    ]
    enable_macie = true
    macie_export_lifecycle_rules = [
      { id = "macie-archive", prefix = "macie/classification-results/", expiration_days = 365 },
    ]
    enable_session_manager_s3_logging = true
    session_manager_s3_bucket_name    = "tlz-session-logs"
    session_manager_lifecycle_rules = [
      { id = "session-archive", prefix = "session-logs/", expiration_days = 365, noncurrent_version_transitions = [{ storage_class = "GLACIER", days = 30 }] },
    ]
  }
  # The GuardDuty and Macie rules share one resource, so it carries both.
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule) == 2
    error_message = "The central bucket resource must carry the Macie rule and the GuardDuty rule and nothing derived."
  }
  assert {
    condition = length([
      for rule in aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule :
      rule if rule.id == "guardduty-archive"
    ]) == 1
    error_message = "The GuardDuty rule set must reach the resource."
  }
  assert {
    condition = length([
      for rule in aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule :
      rule if rule.id == "macie-archive"
    ]) == 1
    error_message = "The Macie rule set must reach the same resource — S3 keeps one lifecycle configuration per bucket."
  }
  assert {
    condition = length([
      for rule in aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule :
      rule if rule.id == "guardduty-export-lifecycle"
    ]) == 0
    error_message = "An explicit GuardDuty rule set must replace the derived rule, not join it."
  }
  assert {
    condition = one([
      for rule in aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule :
      one(rule.expiration).days if rule.id == "guardduty-archive"
    ]) == 2555
    error_message = "expiration_days of the GuardDuty rule must reach the expiration block."
  }
  assert {
    condition = one([
      for rule in aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule :
      length(rule.transition) if rule.id == "guardduty-archive"
    ]) == 2
    error_message = "Every transition of the GuardDuty rule must reach the resource."
  }
  assert {
    condition = one([
      for rule in aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule :
      one(rule.filter).prefix if rule.id == "macie-archive"
    ]) == "macie/classification-results/"
    error_message = "The Macie rule must stay scoped to its export prefix."
  }
  # The reports bucket and the session logs take their own resource.
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.audit_manager_reports[0].rule[0].id == "reports-archive"
    error_message = "The reports bucket must take its own rule set."
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.session_manager_logs) == 1
    error_message = "A Session Manager rule set must create the lifecycle configuration of its bucket."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.session_manager_logs[0].bucket == "tlz-session-logs"
    error_message = "The Session Manager lifecycle must target the bucket the session logs go to."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.session_manager_logs[0].rule[0].noncurrent_version_transition).noncurrent_days == 30
    error_message = "A noncurrent version transition of the Session Manager rule must reach the resource."
  }

  # enable_audit_manager = true fires the maintenance-mode warning (new
  # registrations refused by AWS since April 30, 2026); the export runs here
  # beside a designated administrator, which the module reports as well.
  expect_failures = [
    check.audit_manager_maintenance_mode,
    check.finding_consumers_in_administrator,
  ]
}
# Macie rules alone have to create the central bucket resource — before the
# bundle it existed only for the GuardDuty path, and a Macie-only deployment
# would otherwise carry an input without a reader.
run "security_macie_rules_alone_create_the_central_lifecycle" {
  command = plan
  variables {
    audit_account_id                     = "222222222222"
    root_credentials_management          = false
    allow_root_sessions                  = false
    enable_guardduty                     = false
    central_log_bucket_name              = "tlz-central-logs"
    replace_central_log_bucket_lifecycle = true
    enable_macie                         = true
    macie_export_lifecycle_rules = [
      { id = "macie-only", prefix = "macie/classification-results/", expiration_days = 365 },
    ]
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.guardduty_export) == 1
    error_message = "Macie rules alone must create the lifecycle configuration of the central bucket."
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule) == 1
    error_message = "With GuardDuty off only the Macie rule may stand — the derived GuardDuty rule reads an input that is null here."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.guardduty_export[0].rule[0].id == "macie-only"
    error_message = "The single rule must be the Macie rule."
  }
}
# The logging module writes the lifecycle of the same central log
# bucket. Without the opt-in, a rule input that would make this module write a
# second, competing configuration is refused, never planned and never dropped.
run "regression_central_lifecycle_needs_the_replace_opt_in" {
  command = plan
  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    central_log_bucket_name      = "tlz-central-logs"
    guardduty_export_frequency   = "SIX_HOURS"
    guardduty_export_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    guardduty_lifecycle_rules    = { retention_days = 90 }
  }
  # The export is configured here beside a designated administrator; the
  # module reports that too.
  expect_failures = [
    var.replace_central_log_bucket_lifecycle,
    check.finding_consumers_in_administrator,
  ]
}
# -----------------------------------------------------------------------------
# Validation — the checks on the rule shape, and the binding to each toggle
# -----------------------------------------------------------------------------
run "security_invalid_lifecycle_storage_class" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = true
    guardduty_export_lifecycle_rules = [
      { id = "archive", expiration_days = 400, transitions = [{ storage_class = "FREEZER", days = 30 }] },
    ]
  }
  expect_failures = [var.guardduty_export_lifecycle_rules]
}
run "security_invalid_lifecycle_transition_days_not_ascending" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = true
    guardduty_export_lifecycle_rules = [
      {
        id              = "archive"
        expiration_days = 400
        transitions = [
          { storage_class = "GLACIER", days = 90 },
          { storage_class = "DEEP_ARCHIVE", days = 30 },
        ]
      },
    ]
  }
  expect_failures = [var.guardduty_export_lifecycle_rules]
}
run "security_invalid_lifecycle_expiration_before_last_transition" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = true
    guardduty_export_lifecycle_rules = [
      { id = "archive", expiration_days = 60, transitions = [{ storage_class = "DEEP_ARCHIVE", days = 90 }] },
    ]
  }
  expect_failures = [var.guardduty_export_lifecycle_rules]
}
run "security_invalid_lifecycle_duplicate_id" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = true
    guardduty_export_lifecycle_rules = [
      { id = "same", expiration_days = 400 },
      { id = "same", expiration_days = 500 },
    ]
  }
  expect_failures = [var.guardduty_export_lifecycle_rules]
}
run "security_invalid_lifecycle_prefix_and_tags_together" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = true
    guardduty_export_lifecycle_rules = [
      { id = "both", prefix = "guardduty/", tags = { a = "b" }, expiration_days = 400 },
    ]
  }
  expect_failures = [var.guardduty_export_lifecycle_rules]
}
run "security_invalid_lifecycle_rule_without_action" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = true
    guardduty_export_lifecycle_rules = [
      { id = "does-nothing", prefix = "guardduty/" },
    ]
  }
  expect_failures = [var.guardduty_export_lifecycle_rules]
}
# Each of the four rule sets is bound to the toggle of its own export path — a
# rule set without its bucket is an input without a reader.
run "security_invalid_guardduty_rules_without_toggle" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = false
    guardduty_export_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }
  expect_failures = [var.guardduty_export_lifecycle_rules]
}
run "security_invalid_audit_manager_rules_without_bucket" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_audit_manager_bucket = false
    audit_manager_bucket_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }
  expect_failures = [var.audit_manager_bucket_lifecycle_rules]
}
run "security_invalid_macie_rules_without_toggle" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = false
    macie_export_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }
  expect_failures = [var.macie_export_lifecycle_rules]
}
run "security_invalid_session_manager_rules_without_logging" {
  command = plan
  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    enable_session_manager_s3_logging = false
    session_manager_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }
  expect_failures = [var.session_manager_lifecycle_rules]
}

# -----------------------------------------------------------------------------
# Scenario 7: Session Manager account exclusion list
# -----------------------------------------------------------------------------
# The module configures exactly one account; which accounts receive the stack
# is decided in the deployment layer. The exclusion list documents that
# decision next to the configuration, and the check reports a plan that runs
# against a listed account — the same contract as the two existing account
# exclusion lists of this module. Unlike those, the check is bound to
# enable_session_manager_logging: without the session document there is
# nothing the account could be excluded from.

run "session_manager_exclusion_is_reported" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    enable_session_manager_logging    = true
    session_manager_excluded_accounts = ["123456789012"]
  }

  expect_failures = [
    check.session_manager_excluded_account_check,
  ]

  assert {
    condition     = length(aws_ssm_document.session_manager) == 1
    error_message = "The exclusion list must not silently drop the session document — the mismatch is reported."
  }
}

run "session_manager_exclusion_of_another_account_stays_silent" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    enable_session_manager_logging    = true
    session_manager_excluded_accounts = ["999999999999"]
  }

  assert {
    condition     = length(aws_ssm_document.session_manager) == 1
    error_message = "Excluding another account must not touch the session document of this one."
  }
}

run "session_manager_exclusion_without_logging_stays_silent" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    enable_session_manager_logging    = false
    session_manager_excluded_accounts = ["123456789012"]
  }

  assert {
    condition     = length(aws_ssm_document.session_manager) == 0
    error_message = "Without the session document there is nothing to be excluded from — the check must stay silent."
  }
}

run "session_manager_invalid_excluded_account_rejected" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    session_manager_excluded_accounts = ["Management"]
  }

  expect_failures = [var.session_manager_excluded_accounts]
}

run "session_manager_duplicate_excluded_account_rejected" {
  command = plan

  variables {
    audit_account_id                  = "222222222222"
    root_credentials_management       = false
    allow_root_sessions               = false
    session_manager_excluded_accounts = ["111111111111", "111111111111"]
  }

  expect_failures = [var.session_manager_excluded_accounts]
}

# -----------------------------------------------------------------------------
# Scenario: Security Hub automation rules — defaults keep the plan
# -----------------------------------------------------------------------------
# A rule without the optional fields (no enabled flag, no exclude_regions, no
# number/date/key-value criteria, no confidence, criticality or related
# findings in the action) plans with the defaults: rule created in this region
# with rule_status ENABLED.
run "regression_automation_rules_defaults_keep_the_plan" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_security_hub         = true
    security_hub_automation_rules = [
      {
        rule_name   = "suppress-informational"
        rule_order  = 10
        description = "Suppress informational findings"
        criteria = {
          severity_label = [{ comparison = "EQUALS", value = "INFORMATIONAL" }]
        }
        actions = {
          finding_fields_update = {
            workflow = { status = "SUPPRESSED" }
          }
        }
      }
    ]
  }

  assert {
    condition     = length(aws_securityhub_automation_rule.this) == 1
    error_message = "A rule without exclude_regions must be created in the current region."
  }

  assert {
    condition     = aws_securityhub_automation_rule.this["suppress-informational"].rule_status == "ENABLED"
    error_message = "Without an enabled flag the rule must keep the default rule_status ENABLED."
  }
}

# -----------------------------------------------------------------------------
# Scenario: Security Hub automation rules — full criteria and action set
# -----------------------------------------------------------------------------
run "automation_rule_full_fields_reach_the_resource" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_security_hub         = true
    security_hub_automation_rules = [
      {
        rule_name   = "escalate-stale-critical"
        rule_order  = 5
        description = "Escalate stale critical findings"
        is_terminal = true
        enabled     = false
        criteria = {
          severity_label      = [{ comparison = "EQUALS", value = "CRITICAL" }]
          generator_id        = [{ comparison = "PREFIX", value = "aws-foundational" }]
          confidence          = [{ gte = 80 }]
          criticality         = [{ eq = 100 }]
          created_at          = [{ date_range = { unit = "DAYS", value = 30 } }]
          updated_at          = [{ start = "2024-01-01T00:00:00Z", end = "2024-06-30T23:59:59Z" }]
          user_defined_fields = [{ key = "team", value = "platform", comparison = "EQUALS" }]
        }
        actions = {
          finding_fields_update = {
            severity    = { label = "HIGH" }
            note        = { text = "Escalated by automation", updated_by = "landing-zone" }
            confidence  = 95
            criticality = 90
            related_findings = [
              { id = "finding-0001", product_arn = "arn:aws:securityhub:eu-central-1:222222222222:product/222222222222/default" }
            ]
          }
        }
      },
      {
        rule_name       = "not-in-this-region"
        rule_order      = 6
        description     = "Excluded from the test region"
        exclude_regions = ["eu-central-1"]
        criteria = {
          record_state = [{ comparison = "EQUALS", value = "ACTIVE" }]
        }
        actions = {
          finding_fields_update = {
            workflow = { status = "SUPPRESSED" }
          }
        }
      }
    ]
  }

  assert {
    condition     = length(aws_securityhub_automation_rule.this) == 1
    error_message = "A rule listing the current region in exclude_regions must not be created here."
  }

  assert {
    condition     = aws_securityhub_automation_rule.this["escalate-stale-critical"].rule_status == "DISABLED"
    error_message = "enabled = false must reach the resource as rule_status DISABLED."
  }
}

# -----------------------------------------------------------------------------
# Scenario: Security Hub automation rules — validation failures
# -----------------------------------------------------------------------------
run "automation_rule_invalid_string_comparison_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    security_hub_automation_rules = [
      {
        rule_name   = "bad-operator"
        rule_order  = 1
        description = "Unknown comparison operator"
        criteria = {
          title = [{ comparison = "MATCHES", value = "x" }]
        }
      }
    ]
  }
  expect_failures = [var.security_hub_automation_rules]
}

run "automation_rule_number_criteria_both_forms_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    security_hub_automation_rules = [
      {
        rule_name   = "bad-number-filter"
        rule_order  = 1
        description = "eq combined with a bound"
        criteria = {
          confidence = [{ eq = 50, gte = 10 }]
        }
      }
    ]
  }
  expect_failures = [var.security_hub_automation_rules]
}

run "automation_rule_date_criteria_both_forms_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    security_hub_automation_rules = [
      {
        rule_name   = "bad-date-filter"
        rule_order  = 1
        description = "rolling and fixed window at once"
        criteria = {
          created_at = [{ start = "2024-01-01T00:00:00Z", date_range = { unit = "DAYS", value = 7 } }]
        }
      }
    ]
  }
  expect_failures = [var.security_hub_automation_rules]
}

run "automation_rule_invalid_date_unit_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    security_hub_automation_rules = [
      {
        rule_name   = "bad-date-unit"
        rule_order  = 1
        description = "unsupported date range unit"
        criteria = {
          updated_at = [{ date_range = { unit = "HOURS", value = 4 } }]
        }
      }
    ]
  }
  expect_failures = [var.security_hub_automation_rules]
}

run "automation_rule_action_confidence_out_of_range_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    security_hub_automation_rules = [
      {
        rule_name   = "bad-action-confidence"
        rule_order  = 1
        description = "confidence beyond the 0-100 score range"
        actions = {
          finding_fields_update = {
            confidence = 101
          }
        }
      }
    ]
  }
  expect_failures = [var.security_hub_automation_rules]
}

run "automation_rule_invalid_related_finding_arn_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    security_hub_automation_rules = [
      {
        rule_name   = "bad-related-finding"
        rule_order  = 1
        description = "related finding without a Security Hub product ARN"
        actions = {
          finding_fields_update = {
            related_findings = [{ id = "finding-1", product_arn = "arn:aws:s3:::bucket" }]
          }
        }
      }
    ]
  }
  expect_failures = [var.security_hub_automation_rules]
}

run "automation_rule_invalid_exclude_region_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    security_hub_automation_rules = [
      {
        rule_name       = "bad-exclude-region"
        rule_order      = 1
        description     = "malformed region name"
        exclude_regions = ["Frankfurt"]
        criteria = {
          record_state = [{ comparison = "EQUALS", value = "ACTIVE" }]
        }
      }
    ]
  }
  expect_failures = [var.security_hub_automation_rules]
}

# -----------------------------------------------------------------------------
# Scenario: GuardDuty fine tuning — defaults keep the plan
# -----------------------------------------------------------------------------
# A malware configuration without the optional fields plans with the
# defaults: object tagging ENABLED, no plan tags. The snapshot
# preservation switch defaults to false and creates nothing.
run "regression_guardduty_fine_tuning_defaults_keep_the_plan" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    enable_guardduty                       = true
    enable_guardduty_s3_malware_protection = true
    guardduty_s3_malware_configs = [
      { bucket_name = "central-data" }
    ]
  }

  assert {
    condition     = aws_guardduty_malware_protection_plan.this["central-data"].actions[0].tagging[0].status == "ENABLED"
    error_message = "Without enable_malware_protection_tags the plan must keep the default ENABLED."
  }

  assert {
    condition     = aws_guardduty_malware_protection_plan.this["central-data"].tags == null
    error_message = "Without tags the protection plan must carry none."
  }

  assert {
    condition = (
      length(aws_lambda_function.guardduty_scan_settings) == 0 &&
      length(aws_lambda_invocation.guardduty_scan_settings) == 0 &&
      length(aws_iam_role.guardduty_scan_settings) == 0 &&
      length(data.archive_file.guardduty_scan_settings) == 0
    )
    error_message = "No scan settings resource may exist while guardduty_keep_malware_snapshots is false."
  }
}

# -----------------------------------------------------------------------------
# Scenario: GuardDuty fine tuning — settings reach the resources
# -----------------------------------------------------------------------------
run "guardduty_fine_tuning_reaches_the_resources" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    enable_guardduty                       = true
    enable_guardduty_s3_malware_protection = true
    guardduty_keep_malware_snapshots       = true
    guardduty_s3_malware_configs = [
      {
        bucket_name                    = "central-data"
        enable_malware_protection_tags = false
        tags                           = { DataClassification = "internal" }
      }
    ]
  }

  assert {
    condition     = aws_guardduty_malware_protection_plan.this["central-data"].actions[0].tagging[0].status == "DISABLED"
    error_message = "enable_malware_protection_tags = false must reach the tagging status."
  }

  assert {
    condition     = aws_guardduty_malware_protection_plan.this["central-data"].tags["DataClassification"] == "internal"
    error_message = "tags must reach the protection plan resource."
  }

  assert {
    condition = (
      length(aws_lambda_function.guardduty_scan_settings) == 1 &&
      length(aws_iam_role.guardduty_scan_settings) == 1 &&
      length(aws_iam_role_policy.guardduty_scan_settings) == 1 &&
      length(aws_lambda_invocation.guardduty_scan_settings) == 1
    )
    error_message = "guardduty_keep_malware_snapshots = true must create the settings function, its role, its policy and the invocation."
  }

  # The invocation input interpolates the detector ID and is unknown at plan
  # time; that the input requests RETENTION_WITH_FINDING is asserted by the
  # property test against the module source.
  assert {
    condition     = aws_lambda_invocation.guardduty_scan_settings[0].lifecycle_scope == "CRUD"
    error_message = "The invocation must use lifecycle scope CRUD so the setting is reverted on removal."
  }

  assert {
    condition     = aws_lambda_function.guardduty_scan_settings[0].function_name == "tlz-guardduty-scan-settings"
    error_message = "The settings function must carry its fixed name — the IAM policy scopes the log group to it."
  }

  assert {
    condition     = aws_lambda_function.guardduty_scan_settings[0].reserved_concurrent_executions == 1
    error_message = "The settings function must reserve a single execution."
  }
}

# -----------------------------------------------------------------------------
# Scenario: GuardDuty fine tuning — per-feature excluded region warnings
# -----------------------------------------------------------------------------
# The test region eu-central-1 is listed for every protection feature: each of
# the four check blocks must report. Resources still plan — the lists document
# and report, they do not gate (the contract of the module's region lists).
run "guardduty_feature_exclusions_report_the_current_region" {
  command = plan

  variables {
    audit_account_id                             = "222222222222"
    root_credentials_management                  = false
    allow_root_sessions                          = false
    enable_guardduty                             = true
    guardduty_ec2_protection_excluded_regions    = ["eu-central-1"]
    guardduty_eks_protection_excluded_regions    = ["eu-central-1"]
    guardduty_lambda_protection_excluded_regions = ["eu-central-1"]
    guardduty_rds_protection_excluded_regions    = ["eu-central-1"]
  }

  expect_failures = [
    check.guardduty_ec2_protection_excluded_region_check,
    check.guardduty_eks_protection_excluded_region_check,
    check.guardduty_lambda_protection_excluded_region_check,
    check.guardduty_rds_protection_excluded_region_check,
  ]
}

run "guardduty_feature_exclusions_stay_silent_for_other_regions" {
  command = plan

  variables {
    audit_account_id                             = "222222222222"
    root_credentials_management                  = false
    allow_root_sessions                          = false
    enable_guardduty                             = true
    guardduty_ec2_protection_excluded_regions    = ["eu-west-1"]
    guardduty_eks_protection_excluded_regions    = ["eu-west-1"]
    guardduty_lambda_protection_excluded_regions = ["eu-west-1"]
    guardduty_rds_protection_excluded_regions    = ["eu-west-1"]
  }

  assert {
    condition     = length(aws_guardduty_detector.this) == 1
    error_message = "Exclusion lists naming other regions must not affect the deployment."
  }
}

# -----------------------------------------------------------------------------
# Scenario: GuardDuty fine tuning — validation failures
# -----------------------------------------------------------------------------
run "guardduty_invalid_feature_exclusion_regions_rejected" {
  command = plan

  variables {
    audit_account_id                             = "222222222222"
    root_credentials_management                  = false
    allow_root_sessions                          = false
    guardduty_ec2_protection_excluded_regions    = ["Frankfurt"]
    guardduty_eks_protection_excluded_regions    = ["EU-WEST-1"]
    guardduty_lambda_protection_excluded_regions = ["eu_west_1"]
    guardduty_rds_protection_excluded_regions    = ["euwest1"]
  }

  expect_failures = [
    var.guardduty_ec2_protection_excluded_regions,
    var.guardduty_eks_protection_excluded_regions,
    var.guardduty_lambda_protection_excluded_regions,
    var.guardduty_rds_protection_excluded_regions,
  ]
}

run "guardduty_malware_plan_reserved_tag_key_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    guardduty_s3_malware_configs = [
      {
        bucket_name = "central-data"
        tags        = { "aws:reserved" = "value" }
      }
    ]
  }

  expect_failures = [var.guardduty_s3_malware_configs]
}
# -----------------------------------------------------------------------------
# Scenario: KMS key sets — defaults keep the plan
# -----------------------------------------------------------------------------
# A key entry without is_enabled and removal_policy plans with the defaults:
# key enabled, user policy passed through unchanged.
run "regression_kms_key_set_defaults_keep_the_plan" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    kms_keys = [
      {
        alias  = "app-data"
        policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Root\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"
      }
    ]
  }
  assert {
    condition     = aws_kms_key.custom["app-data"].is_enabled == true
    error_message = "Without is_enabled the key must stay enabled — the default."
  }
  assert {
    condition     = aws_kms_key.custom["app-data"].policy == "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Root\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"
    error_message = "With removal_policy destroy (the default) the user policy must pass through byte for byte."
  }
  assert {
    condition     = aws_kms_key.custom["app-data"].deletion_window_in_days == 30
    error_message = "The deletion window default of 30 days must stay."
  }
}
# -----------------------------------------------------------------------------
# Scenario: KMS key sets — fields reach the resources
# -----------------------------------------------------------------------------
run "kms_key_set_fields_reach_the_resources" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    kms_keys = [
      {
        alias      = "dormant"
        is_enabled = false
      },
      {
        alias          = "protected"
        removal_policy = "retain"
      },
      {
        alias          = "protected-custom"
        removal_policy = "retain"
        policy         = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Root\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"
      }
    ]
  }
  assert {
    condition     = aws_kms_key.custom["dormant"].is_enabled == false
    error_message = "is_enabled = false must reach the key resource."
  }
  assert {
    condition = contains(
      [for s in jsondecode(aws_kms_key.custom["protected"].policy).Statement : try(s.Sid, "")],
      "DenyScheduleKeyDeletion"
    )
    error_message = "A retained key without a user policy must carry the composed deny statement."
  }
  assert {
    condition = contains(
      [for s in jsondecode(aws_kms_key.custom["protected"].policy).Statement : try(s.Sid, "")],
      "EnableRootAccountAccess"
    )
    error_message = "A retained key without a user policy must keep the explicit equivalent of the AWS default key policy."
  }
  assert {
    condition = anytrue([
      for s in jsondecode(aws_kms_key.custom["protected"].policy).Statement :
      try(s.Effect, "") == "Deny" && try(s.Action, "") == "kms:ScheduleKeyDeletion"
    ])
    error_message = "The deny statement must target exactly kms:ScheduleKeyDeletion with effect Deny."
  }
  assert {
    condition = (
      length(jsondecode(aws_kms_key.custom["protected-custom"].policy).Statement) == 2 &&
      contains(
        [for s in jsondecode(aws_kms_key.custom["protected-custom"].policy).Statement : try(s.Sid, "")],
        "Root"
      ) &&
      contains(
        [for s in jsondecode(aws_kms_key.custom["protected-custom"].policy).Statement : try(s.Sid, "")],
        "DenyScheduleKeyDeletion"
      )
    )
    error_message = "A retained key with a user policy must keep the user statements and append the deny statement."
  }
  assert {
    condition     = jsondecode(aws_kms_key.custom["protected-custom"].policy).Version == "2012-10-17"
    error_message = "The composed policy must keep the Version of the user document."
  }
}
# -----------------------------------------------------------------------------
# Scenario: KMS key sets — validation failures
# -----------------------------------------------------------------------------
run "kms_key_invalid_removal_policy_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    kms_keys = [
      {
        alias          = "snapshotted"
        removal_policy = "snapshot"
      }
    ]
  }
  expect_failures = [var.kms_keys]
}
run "kms_key_policy_without_statement_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    kms_keys = [
      {
        alias  = "broken"
        policy = "{\"Version\":\"2012-10-17\"}"
      }
    ]
  }
  expect_failures = [var.kms_keys]
}
# -----------------------------------------------------------------------------
# Scenario: Macie fine-tuning — defaults keep the plan
# -----------------------------------------------------------------------------
# Macie without the fine-tuning inputs (no discovery switch, no exclusions, no
# disabled regions, no publication switch): session ENABLED, no settings
# resources.
run "regression_macie_fine_tuning_defaults_keep_the_plan" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
  }
  assert {
    condition     = aws_macie2_account.this[0].status == "ENABLED"
    error_message = "Without macie_disabled_regions the session must stay ENABLED — the provider default."
  }
  assert {
    condition = (
      length(aws_lambda_function.macie_session_settings) == 0 &&
      length(aws_iam_role.macie_session_settings) == 0 &&
      length(data.archive_file.macie_session_settings) == 0 &&
      length(aws_lambda_invocation.macie_automated_discovery) == 0 &&
      length(aws_lambda_invocation.macie_classification_scope) == 0 &&
      length(aws_lambda_invocation.macie_publish_policy_findings) == 0
    )
    error_message = "No session settings resource may exist while all three switches are unset."
  }
}
# -----------------------------------------------------------------------------
# Scenario: Macie fine-tuning — settings reach the resources
# -----------------------------------------------------------------------------
run "macie_fine_tuning_reaches_the_resources" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
    macie_automated_discovery   = true
    macie_classification_scope_excluded_buckets = [
      { names = ["public-assets", "cdn-content"], region = "eu-central-1" },
      { names = ["us-data-lake"], region = "us-east-1" },
    ]
    macie_disabled_regions        = ["eu-west-3"]
    macie_publish_policy_findings = false
  }
  assert {
    condition     = aws_macie2_account.this[0].status == "ENABLED"
    error_message = "A disabled-regions list naming other regions must not suspend this deployment."
  }
  assert {
    condition = (
      length(aws_lambda_function.macie_session_settings) == 1 &&
      length(aws_iam_role.macie_session_settings) == 1 &&
      length(aws_iam_role_policy.macie_session_settings) == 1 &&
      length(aws_lambda_invocation.macie_automated_discovery) == 1 &&
      length(aws_lambda_invocation.macie_classification_scope) == 1 &&
      length(aws_lambda_invocation.macie_publish_policy_findings) == 1
    )
    error_message = "All three settings must create the shared function, its role and policy, and one invocation each."
  }
  assert {
    condition     = jsondecode(aws_lambda_invocation.macie_automated_discovery[0].input).status == "ENABLED"
    error_message = "macie_automated_discovery = true must request status ENABLED."
  }
  assert {
    condition     = tolist(jsondecode(aws_lambda_invocation.macie_classification_scope[0].input).excluded_bucket_names) == tolist(["public-assets", "cdn-content"])
    error_message = "The classification scope invocation must carry only the region-local bucket names."
  }
  assert {
    condition     = jsondecode(aws_lambda_invocation.macie_publish_policy_findings[0].input).publish == false
    error_message = "macie_publish_policy_findings = false must reach the invocation."
  }
  assert {
    condition     = aws_lambda_invocation.macie_automated_discovery[0].lifecycle_scope == "CRUD"
    error_message = "The invocations must use lifecycle scope CRUD so removal restores the service defaults."
  }
  assert {
    condition     = aws_lambda_function.macie_session_settings[0].function_name == "tlz-macie-session-settings"
    error_message = "The settings function must carry its fixed name — the IAM policy scopes the log group to it."
  }
  assert {
    condition     = aws_lambda_function.macie_session_settings[0].reserved_concurrent_executions == 1
    error_message = "The settings function must reserve a single execution."
  }
}
# -----------------------------------------------------------------------------
# Scenario: Macie fine-tuning — regional suspension reaches the session
# -----------------------------------------------------------------------------
run "macie_disabled_region_pauses_the_session" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
    macie_disabled_regions      = ["eu-central-1"]
  }
  assert {
    condition     = aws_macie2_account.this[0].status == "PAUSED"
    error_message = "A disabled-regions entry naming the current region must suspend the session (PAUSED)."
  }
  assert {
    condition     = length(aws_lambda_function.macie_session_settings) == 0
    error_message = "The suspension alone manages no session settings — no function may appear."
  }
}
# -----------------------------------------------------------------------------
# Scenario: Macie fine-tuning — validation failures
# -----------------------------------------------------------------------------
run "macie_discovery_without_service_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = false
    macie_automated_discovery   = true
  }
  expect_failures = [var.macie_automated_discovery]
}
run "macie_exclusions_without_discovery_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
    macie_classification_scope_excluded_buckets = [
      { names = ["public-assets"], region = "eu-central-1" },
    ]
  }
  expect_failures = [var.macie_classification_scope_excluded_buckets]
}
run "macie_invalid_exclusion_forms_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
    macie_automated_discovery   = true
    macie_classification_scope_excluded_buckets = [
      { names = ["UPPERCASE-NAME"], region = "eu-central-1" },
      { names = [], region = "eu-west-1" },
      { names = ["valid-name"], region = "not_a_region" },
    ]
  }
  expect_failures = [var.macie_classification_scope_excluded_buckets]
}
run "macie_disabled_region_overlapping_excluded_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
    macie_excluded_regions      = ["eu-west-3"]
    macie_disabled_regions      = ["eu-west-3"]
  }
  expect_failures = [var.macie_disabled_regions]
}

# =============================================================================
# Scenario: Resource policy enforcement — perimeter and input parameters
# =============================================================================

# -----------------------------------------------------------------------------
# Scenario: entries of the old form keep their plan — no input parameters, no
# perimeter: the rule carries exactly the template under policyTemplate.
# -----------------------------------------------------------------------------
run "regression_resource_policy_parameters_default_keeps_the_plan" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    resource_policy_enforcement_lambda_arn = "arn:aws:lambda:eu-central-1:123456789012:function:tlz-resource-policy-evaluator"
    resource_policy_enforcement = [
      {
        resource_type   = "AWS::S3::Bucket"
        policy_template = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
      }
    ]
  }

  assert {
    condition = aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].input_parameters == jsonencode({
      policyTemplate = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    })
    error_message = "Without input_parameters and without a perimeter the rule must carry exactly the template under policyTemplate — the form of every existing plan."
  }
}

# -----------------------------------------------------------------------------
# Scenario: input parameters and the perimeter replacement reach the rule
# -----------------------------------------------------------------------------
run "resource_policy_parameters_and_perimeter_reach_the_rule" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    resource_policy_enforcement_lambda_arn = "arn:aws:lambda:eu-central-1:123456789012:function:tlz-resource-policy-evaluator"
    resource_policy_enforcement = [
      {
        resource_type   = "AWS::S3::Bucket"
        policy_template = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"{{NETWORK_PERIMETER_VPC_IDS}}\"}}}]}"
        input_parameters = {
          SourceAccount = "111122223333"
          environment   = "production"
        }
      }
    ]
    resource_policy_enforcement_network_perimeter = {
      enabled            = true
      managed_vpc_only   = false
      managed_vpc_ids    = ["vpc-0a1b2c3d4e5f60718"]
      additional_vpc_ids = ["vpc-00112233445566778"]
    }
  }

  assert {
    condition     = jsondecode(aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].input_parameters).SourceAccount == "111122223333"
    error_message = "Each input_parameters entry must reach the Config rule parameters next to the template."
  }

  assert {
    condition     = jsondecode(aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].input_parameters).environment == "production"
    error_message = "Every input_parameters key must ride along, not only the first."
  }

  assert {
    condition = strcontains(
      jsondecode(aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].input_parameters).policyTemplate,
      "[\"vpc-0a1b2c3d4e5f60718\",\"vpc-00112233445566778\"]"
    )
    error_message = "The quoted placeholder must be replaced with the JSON array of managed and additional VPC IDs."
  }

  assert {
    condition     = can(jsondecode(jsondecode(aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].input_parameters).policyTemplate))
    error_message = "The template must remain valid JSON after the placeholder replacement."
  }
}

# -----------------------------------------------------------------------------
# Scenario: managed_vpc_only narrows the perimeter to the managed set
# -----------------------------------------------------------------------------
run "resource_policy_perimeter_managed_only_narrows_the_set" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    resource_policy_enforcement_lambda_arn = "arn:aws:lambda:eu-central-1:123456789012:function:tlz-resource-policy-evaluator"
    resource_policy_enforcement = [
      {
        resource_type   = "AWS::S3::Bucket"
        policy_template = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"{{NETWORK_PERIMETER_VPC_IDS}}\"}}}]}"
      }
    ]
    resource_policy_enforcement_network_perimeter = {
      enabled            = true
      managed_vpc_only   = true
      managed_vpc_ids    = ["vpc-0a1b2c3d4e5f60718"]
      additional_vpc_ids = ["vpc-00112233445566778"]
    }
  }

  assert {
    condition = strcontains(
      jsondecode(aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].input_parameters).policyTemplate,
      "[\"vpc-0a1b2c3d4e5f60718\"]"
    )
    error_message = "With managed_vpc_only the perimeter must contain exactly the managed VPC IDs."
  }

  assert {
    condition = !strcontains(
      jsondecode(aws_config_organization_custom_rule.resource_policy["AWS::S3::Bucket"].input_parameters).policyTemplate,
      "vpc-00112233445566778"
    )
    error_message = "With managed_vpc_only no additional VPC ID may leak into the perimeter."
  }
}

# -----------------------------------------------------------------------------
# Scenario: resource_policy_enforcement_document — the declared document body
# reaches the SSM Automation document (ssm-documents.tf). The value is the
# content, not a path: the loader reads the file and hands the body over.
# -----------------------------------------------------------------------------
run "resource_policy_enforcement_document_reaches_the_ssm_document" {
  command = plan

  variables {
    audit_account_id                       = "222222222222"
    root_credentials_management            = false
    allow_root_sessions                    = false
    resource_policy_enforcement_lambda_arn = "arn:aws:lambda:eu-central-1:123456789012:function:tlz-resource-policy-evaluator"
    resource_policy_enforcement = [
      {
        resource_type   = "AWS::S3::Bucket"
        policy_template = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
      }
    ]
    resource_policy_enforcement_document = "schemaVersion: '0.3'\ndescription: Applies the compliant resource policy\nmainSteps: []\n"
  }

  assert {
    condition     = length(aws_ssm_document.resource_policy_enforcement) == 1
    error_message = "With enforcement rules and a document body the SSM Automation document must be created."
  }

  assert {
    condition     = aws_ssm_document.resource_policy_enforcement[0].content == "schemaVersion: '0.3'\ndescription: Applies the compliant resource policy\nmainSteps: []\n"
    error_message = "The declared document body must reach the SSM document verbatim."
  }

  assert {
    condition = (
      aws_ssm_document.resource_policy_enforcement[0].document_type == "Automation" &&
      aws_ssm_document.resource_policy_enforcement[0].document_format == "YAML" &&
      aws_ssm_document.resource_policy_enforcement[0].name == "tlz-resource-policy-enforcement"
    )
    error_message = "The enforcement document must register as a YAML Automation document under its fixed name."
  }
}

run "resource_policy_enforcement_document_path_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    # A file path instead of the document body would be registered as an SSM
    # document whose content is the path string — the validation rejects it.
    resource_policy_enforcement_document = "configurations/ssm/resource-policy-enforcement.yaml"
  }

  expect_failures = [var.resource_policy_enforcement_document]
}

# -----------------------------------------------------------------------------
# Scenario: resource policy perimeter and parameter validation failures
# -----------------------------------------------------------------------------
run "resource_policy_invalid_perimeter_vpc_id_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    resource_policy_enforcement_network_perimeter = {
      enabled         = true
      managed_vpc_ids = ["vpc-XYZ"]
    }
  }

  expect_failures = [var.resource_policy_enforcement_network_perimeter]
}

run "resource_policy_reserved_parameter_key_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    resource_policy_enforcement = [
      {
        resource_type    = "AWS::S3::Bucket"
        policy_template  = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        input_parameters = { policyTemplate = "not-allowed" }
      }
    ]
  }

  expect_failures = [var.resource_policy_enforcement]
}

run "resource_policy_placeholder_without_perimeter_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    resource_policy_enforcement = [
      {
        resource_type   = "AWS::S3::Bucket"
        policy_template = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Condition\":{\"StringNotEquals\":{\"aws:SourceVpc\":\"{{NETWORK_PERIMETER_VPC_IDS}}\"}}}]}"
      }
    ]
  }

  expect_failures = [var.resource_policy_enforcement]
}

run "resource_policy_enabled_perimeter_without_vpcs_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    resource_policy_enforcement_network_perimeter = {
      enabled            = true
      managed_vpc_only   = true
      additional_vpc_ids = ["vpc-00112233445566778"]
    }
  }

  expect_failures = [var.resource_policy_enforcement_network_perimeter]
}

# -----------------------------------------------------------------------------
# Scenario: SSM document sharing — defaults, reach and rejections
# -----------------------------------------------------------------------------
# The global ssm_document_share_targets list applies byte for byte to an entry
# without share_targets: it carries exactly the global list. Per-document share_targets add accounts (IDs or names) and
# organizational units, which the module resolves to the accounts they contain
# — the document-sharing API accepts account IDs only.
run "regression_ssm_document_sharing_defaults_keep_the_plan" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    ssm_document_share_targets  = ["333333333333"]
    ssm_documents = [
      {
        name          = "tlz-patch-baseline"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
      }
    ]
  }
  assert {
    condition     = aws_ssm_document.custom["tlz-patch-baseline"].permissions.account_ids == "333333333333"
    error_message = "An entry of the old form must carry exactly the global share list — the form of every existing plan."
  }
}

run "ssm_document_share_union_with_global" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    ssm_document_share_targets  = ["333333333333"]
    account_ids = {
      Sandbox = "666677778888"
    }
    ssm_documents = [
      {
        name          = "tlz-doc-shared"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
        share_targets = {
          accounts = ["Sandbox"]
        }
      },
      {
        name          = "tlz-doc-plain"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
      }
    ]
  }
  assert {
    condition     = aws_ssm_document.custom["tlz-doc-shared"].permissions.account_ids == "333333333333,666677778888"
    error_message = "Per-document accounts must be united with the global share list, global entries first."
  }
  assert {
    condition     = aws_ssm_document.custom["tlz-doc-plain"].permissions.account_ids == "333333333333"
    error_message = "A document without share_targets must keep the global list verbatim."
  }
}

run "ssm_document_share_ou_resolves_to_its_accounts" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    account_ids = {
      Audit      = "444455556666"
      LogArchive = "555566667777"
      Sandbox    = "666677778888"
    }
    ou_name_to_id = {
      Security  = "ou-abcd-11111111"
      Workloads = "ou-abcd-22222222"
    }
    account_ou_ids = {
      Audit      = "ou-abcd-11111111"
      LogArchive = "ou-abcd-11111111"
      Sandbox    = "ou-abcd-22222222"
    }
    ssm_documents = [
      {
        name          = "tlz-doc-shared"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
        share_targets = {
          # A raw ID, a resolvable name, and an ID that the OU below also
          # resolves to — distinct must deduplicate it.
          accounts             = ["111100002222", "Sandbox", "444455556666"]
          organizational_units = ["Security"]
        }
      },
      {
        name          = "tlz-doc-plain"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
      }
    ]
  }
  assert {
    condition     = aws_ssm_document.custom["tlz-doc-shared"].permissions.account_ids == "111100002222,666677778888,444455556666,555566667777"
    error_message = "OU share targets must resolve to the accounts the OU contains (lexical account-name order), names must resolve through account_ids, and duplicates must be removed."
  }
  assert {
    condition     = aws_ssm_document.custom["tlz-doc-plain"].permissions == null
    error_message = "Without a global list and without share_targets a document must carry no permissions — the default."
  }
}

run "ssm_document_share_unknown_account_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    ssm_documents = [
      {
        name          = "tlz-doc-shared"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
        share_targets = {
          accounts = ["Zebra"]
        }
      }
    ]
  }
  expect_failures = [var.ssm_documents]
}

run "ssm_document_share_unknown_ou_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    ou_name_to_id = {
      Security = "ou-abcd-11111111"
    }
    ssm_documents = [
      {
        name          = "tlz-doc-shared"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
        share_targets = {
          organizational_units = ["Nonexistent"]
        }
      }
    ]
  }
  expect_failures = [var.ssm_documents]
}

run "ssm_document_share_with_public_all_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    ssm_document_share_targets  = ["all"]
    ssm_documents = [
      {
        name          = "tlz-doc-shared"
        document_type = "Command"
        content       = "{\"schemaVersion\":\"2.2\",\"description\":\"noop\",\"mainSteps\":[]}"
        share_targets = {
          accounts = ["111100002222"]
        }
      }
    ]
  }
  expect_failures = [var.ssm_documents]
}

run "ssm_document_share_invalid_ou_map_value_rejected" {
  command = plan
  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    ou_name_to_id = {
      Security = "not-an-ou-id"
    }
  }
  expect_failures = [var.ou_name_to_id]
}

# -----------------------------------------------------------------------------
# Security Hub standards keyed by arn_suffix
#
# The standards subscription runs over a map keyed by arn_suffix instead of a
# count index: disabling or removing one entry does not shift the addresses
# of the remaining subscriptions (which would force a destroy/create cycle with
# a coverage gap in between). The variable carries the structured form; entries
# without an enabled flag take the optional default true — the exact shape the
# loader produces when it converts a plain ARN suffix string from the
# configuration layer.
# -----------------------------------------------------------------------------
run "regression_standards_subscription_keyed_by_arn_suffix" {
  command = plan

  variables {
    audit_account_id = "222222222222"

    # Off to keep the provider-limitation check quiet — the scenario is about
    # the standards subscription only.
    root_credentials_management = false
    allow_root_sessions         = false

    security_hub_standards = [
      # Converted string form: no enabled flag, the optional default applies.
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" },
      # Full object form with an explicit flag.
      { arn_suffix = "cis-aws-foundations-benchmark/v/3.0.0", enabled = true },
      # A disabled entry is documentation only and must not shift the others.
      { arn_suffix = "cis-aws-foundations-benchmark/v/1.2.0", enabled = false },
    ]
  }

  assert {
    condition     = length(aws_securityhub_standards_subscription.this) == 2
    error_message = "Only the enabled standards must be subscribed."
  }

  # The addresses are the arn_suffix keys — stable under list reordering and
  # unaffected by the disabled entry between them.
  assert {
    condition     = contains(keys(aws_securityhub_standards_subscription.this), "aws-foundational-security-best-practices/v/1.0.0")
    error_message = "The subscription must be addressed by its arn_suffix key."
  }

  assert {
    condition     = contains(keys(aws_securityhub_standards_subscription.this), "cis-aws-foundations-benchmark/v/3.0.0")
    error_message = "The entry with an explicit enabled flag must be subscribed under its arn_suffix key."
  }

  assert {
    condition     = aws_securityhub_standards_subscription.this["cis-aws-foundations-benchmark/v/3.0.0"].standards_arn == "arn:aws:securityhub:eu-central-1::standards/cis-aws-foundations-benchmark/v/3.0.0"
    error_message = "The standards ARN must be built from partition, region and the entry's arn_suffix."
  }
}

# A duplicated arn_suffix is rejected at plan time: under count the duplicate
# was billed twice, under for_each it would silently collapse into one key.
run "regression_duplicate_standard_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false

    security_hub_standards = [
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" },
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0", enabled = false },
    ]
  }

  expect_failures = [var.security_hub_standards]
}

# A disabled control of a standard that is never subscribed: the control ARN is
# string-built, so the plan is healthy and AWS answers ResourceNotFoundException
# at apply. The cross-variable validation rejects it at plan time instead.
run "regression_disabled_control_of_unsubscribed_standard_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false

    security_hub_standards = [
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" },
    ]
    security_hub_standards_config = []
    security_hub_disabled_controls = [
      {
        standard_arn_suffix = "nist-800-53/v/5.0.0"
        control_ids         = ["IAM.1"]
      }
    ]
  }

  expect_failures = [var.security_hub_disabled_controls]
}

# The subtle half of the same defect: the standard IS named in
# security_hub_standards but with enabled = false, so local.enabled_standards
# filters it out and no subscription is created for it. Unsubscribed is
# unsubscribed — a mere mention must not satisfy the requirement.
run "regression_disabled_control_of_disabled_standard_rejected" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false

    security_hub_standards = [
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" },
      { arn_suffix = "nist-800-53/v/5.0.0", enabled = false },
    ]
    security_hub_standards_config = []
    security_hub_disabled_controls = [
      {
        standard_arn_suffix = "nist-800-53/v/5.0.0"
        control_ids         = ["IAM.1"]
      }
    ]
  }

  expect_failures = [var.security_hub_disabled_controls]
}

# The counterpart that must stay accepted: the standard is subscribed through
# security_hub_standards_config rather than security_hub_standards. This is the
# combination whose controls need an ordering against their subscription too.
run "regression_disabled_control_of_config_subscribed_standard_accepted" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false

    security_hub_standards = [
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" },
    ]
    security_hub_standards_config = [
      { standard_arn_suffix = "nist-800-53/v/5.0.0" }
    ]
    security_hub_disabled_controls = [
      {
        standard_arn_suffix = "nist-800-53/v/5.0.0"
        control_ids         = ["IAM.1"]
      }
    ]
  }

  assert {
    condition     = length(aws_securityhub_standards_control.disabled) == 1
    error_message = "A control of a standard subscribed via security_hub_standards_config must still be planned."
  }
}

# -----------------------------------------------------------------------------
# GuardDuty malware protection toggle
# -----------------------------------------------------------------------------
# guardduty_malware_protection feeds the status of EBS_MALWARE_PROTECTION; the
# default true keeps existing deployments unchanged.

run "guardduty_malware_protection_off" {
  command = plan

  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    enable_guardduty             = true
    guardduty_malware_protection = false
  }

  assert {
    condition     = aws_guardduty_detector_feature.ebs_malware[0].status == "DISABLED"
    error_message = "guardduty_malware_protection = false must disable the EBS_MALWARE_PROTECTION detector feature."
  }
}

run "guardduty_malware_protection_default_on" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    enable_guardduty            = true
  }

  assert {
    condition     = aws_guardduty_detector_feature.ebs_malware[0].status == "ENABLED"
    error_message = "The default of guardduty_malware_protection must keep EBS_MALWARE_PROTECTION enabled (behaviour-preserving)."
  }
}

# -----------------------------------------------------------------------------
# Macie org admin registration is skipped without an Audit account
# -----------------------------------------------------------------------------
# Without the guard the plan would run through with audit_account_id = "" (the
# audit_account_configured check only warns) and the apply would fail on
# admin_account_id = "". The registration carries the same guard as every
# other delegated-admin resource of the module.
run "regression_macie_admin_without_audit_account_skipped" {
  command = plan

  variables {
    audit_account_id            = ""
    root_credentials_management = false
    allow_root_sessions         = false
    enable_macie                = true
  }

  expect_failures = [
    check.audit_account_configured,
  ]

  assert {
    condition     = length(aws_macie2_organization_admin_account.this) == 0
    error_message = "No Macie org admin must be registered without an audit account ID."
  }

  assert {
    condition     = length(aws_organizations_delegated_administrator.macie) == 0
    error_message = "No Macie delegated administrator must be registered without an audit account ID."
  }

  assert {
    condition     = length(aws_macie2_account.this) == 1
    error_message = "The local Macie activation must still happen without an audit account ID."
  }
}

# -----------------------------------------------------------------------------
# Macie classification export without a KMS key fails the plan
# -----------------------------------------------------------------------------
# The Macie API requires a KMS key for the S3 export destination; without the
# precondition the plan would be green and the apply would fail. Same defence as the
# GuardDuty export (regression_guardduty_export_without_kms_key_rejected).
run "regression_macie_export_without_kms_key_rejected" {
  command = plan

  variables {
    audit_account_id                      = "222222222222"
    root_credentials_management           = false
    allow_root_sessions                   = false
    enable_macie                          = true
    macie_publish_sensitive_data_findings = true
    central_log_bucket_name               = "tlz-central-logs"
    guardduty_export_kms_key_arn          = ""
  }

  expect_failures = [
    aws_macie2_classification_export_configuration.this,
  ]
}

# -----------------------------------------------------------------------------
# Explicit Audit Manager lifecycle rules survive lifecycle_days = 0
# -----------------------------------------------------------------------------
# audit_manager_bucket_lifecycle_days = 0 is the off switch for the DERIVED
# rule only. Explicit audit_manager_bucket_lifecycle_rules replace the derived
# rule and must apply independently of the day count — without the OR-form in
# the count they would silently vanish together with the whole resource.
run "regression_audit_manager_explicit_rules_survive_days_zero" {
  command = plan

  variables {
    audit_account_id                    = "222222222222"
    root_credentials_management         = false
    allow_root_sessions                 = false
    enable_audit_manager                = true
    enable_audit_manager_bucket         = true
    audit_manager_bucket_lifecycle_days = 0
    audit_manager_bucket_lifecycle_rules = [
      { id = "reports-archive", expiration_days = 400 },
    ]
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.audit_manager_reports) == 1
    error_message = "Explicit lifecycle rules must create the configuration even when audit_manager_bucket_lifecycle_days is 0."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.audit_manager_reports[0].rule) == 1
    error_message = "Only the explicit rule must be planned — the derived rule stays bound to lifecycle_days > 0."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.audit_manager_reports[0].rule).id == "reports-archive"
    error_message = "The planned rule must be the explicit one, not the derived audit-manager-reports-lifecycle rule."
  }

  # enable_audit_manager = true fires the maintenance-mode warning (new
  # registrations refused by AWS since April 30, 2026).
  expect_failures = [
    check.audit_manager_maintenance_mode,
  ]
}

# -----------------------------------------------------------------------------
# Scenario: firewall config bucket name — namespace pin and enable/name coupling
# -----------------------------------------------------------------------------
# The bucket name is a variable-fed guardrail-class name: ProtectS3Buckets in
# tlz-core-guardrails-2.json protects only arn:*:s3:::tlz-*, and the variable's
# validation is the namespace pin. A
# well-formed bucket name outside tlz- must be refused. The resource is
# count-gated by enable_firewall_config_bucket, not by the name, so the toggle
# on with an empty name would let the provider generate a random bucket name
# outside every guardrail — that combination is refused too.
run "firewall_config_bucket_name_outside_namespace_rejected" {
  command = plan

  variables {
    audit_account_id              = "222222222222"
    root_credentials_management   = false
    allow_root_sessions           = false
    enable_firewall_config_bucket = true
    firewall_config_bucket_name   = "l4test-firewall-config"
  }

  expect_failures = [var.firewall_config_bucket_name]
}

run "firewall_config_bucket_enabled_without_name_rejected" {
  command = plan

  variables {
    audit_account_id              = "222222222222"
    root_credentials_management   = false
    allow_root_sessions           = false
    enable_firewall_config_bucket = true
    firewall_config_bucket_name   = ""
  }

  expect_failures = [var.firewall_config_bucket_name]
}

# -----------------------------------------------------------------------------
# Scenario: finding consumers — where they run
# -----------------------------------------------------------------------------
# The GuardDuty export, the Macie export, the finding aggregator and the
# automation rules reach the member accounts' findings only in the delegated
# administrator (the Audit account, modules/security-org-config). The stack
# switches them off here with manage_finding_consumers = false once they run
# there; the default keeps every one of them in this account, as before.
run "regression_finding_consumers_default_keeps_the_plan" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    central_log_bucket_name     = "tlz-central-logs"

    guardduty_export_frequency           = "SIX_HOURS"
    guardduty_export_kms_key_arn         = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    guardduty_lifecycle_rules            = { retention_days = 90 }
    replace_central_log_bucket_lifecycle = true

    enable_macie                          = true
    macie_publish_sensitive_data_findings = true

    security_hub_standards = [
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0", enabled = true },
    ]
    security_hub_disabled_controls = [
      {
        standard_arn_suffix = "aws-foundational-security-best-practices/v/1.0.0"
        control_ids         = ["IAM.1"]
      }
    ]
    security_hub_automation_rules = [
      {
        rule_name   = "suppress-informational"
        rule_order  = 10
        description = "Suppress informational findings"
        criteria = {
          severity_label = [{ comparison = "EQUALS", value = "INFORMATIONAL" }]
        }
        actions = {
          finding_fields_update = {
            workflow = { status = "SUPPRESSED" }
          }
        }
      },
      {
        rule_name   = "suppress-low"
        rule_order  = 11
        description = "Suppress low findings"
        criteria = {
          severity_label = [{ comparison = "EQUALS", value = "LOW" }]
        }
        actions = {
          finding_fields_update = {
            workflow = { status = "SUPPRESSED" }
          }
        }
      },
    ]
  }

  assert {
    condition = alltrue([
      length(time_sleep.guardduty_export_wait) == 1,
      length(aws_guardduty_publishing_destination.this) == 1,
      length(aws_macie2_classification_export_configuration.this) == 1,
      length(aws_securityhub_finding_aggregator.this) == 1,
      length(aws_securityhub_automation_rule.this) == 2,
    ])
    error_message = "With manage_finding_consumers at its default every finding consumer must be planned in this account, as before."
  }

  # ... and the module reports that they run here beside a designated
  # administrator.
  expect_failures = [
    check.finding_consumers_in_administrator,
  ]
}

run "finding_consumers_off_creates_none" {
  command = plan

  variables {
    audit_account_id            = "222222222222"
    root_credentials_management = false
    allow_root_sessions         = false
    central_log_bucket_name     = "tlz-central-logs"
    manage_finding_consumers    = false

    guardduty_export_frequency           = "SIX_HOURS"
    guardduty_export_kms_key_arn         = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    guardduty_lifecycle_rules            = { retention_days = 90 }
    replace_central_log_bucket_lifecycle = true

    enable_macie                          = true
    macie_publish_sensitive_data_findings = true

    security_hub_standards = [
      { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0", enabled = true },
    ]
    security_hub_disabled_controls = [
      {
        standard_arn_suffix = "aws-foundational-security-best-practices/v/1.0.0"
        control_ids         = ["IAM.1"]
      }
    ]
    security_hub_automation_rules = [
      {
        rule_name   = "suppress-informational"
        rule_order  = 10
        description = "Suppress informational findings"
        criteria = {
          severity_label = [{ comparison = "EQUALS", value = "INFORMATIONAL" }]
        }
        actions = {
          finding_fields_update = {
            workflow = { status = "SUPPRESSED" }
          }
        }
      },
      {
        rule_name   = "suppress-low"
        rule_order  = 11
        description = "Suppress low findings"
        criteria = {
          severity_label = [{ comparison = "EQUALS", value = "LOW" }]
        }
        actions = {
          finding_fields_update = {
            workflow = { status = "SUPPRESSED" }
          }
        }
      },
    ]
  }

  assert {
    condition = alltrue([
      length(time_sleep.guardduty_export_wait) == 0,
      length(aws_guardduty_publishing_destination.this) == 0,
      length(aws_macie2_classification_export_configuration.this) == 0,
      length(aws_securityhub_finding_aggregator.this) == 0,
      length(aws_securityhub_automation_rule.this) == 0,
    ])
    error_message = "With manage_finding_consumers = false none of the five finding consumers may be planned in this account — they run in the administrator."
  }

  # Everything account-local stays: detector, Security Hub account, standards,
  # disabled controls, Macie session, and the bucket-side lifecycle rule.
  assert {
    condition = alltrue([
      length(aws_guardduty_detector.this) == 1,
      length(aws_guardduty_organization_admin_account.this) == 1,
      length(aws_securityhub_account.this) == 1,
      length(aws_securityhub_standards_subscription.this) == 1,
      length(aws_securityhub_standards_control.disabled) == 1,
      length(aws_macie2_account.this) == 1,
      length(aws_s3_bucket_lifecycle_configuration.guardduty_export) == 1,
    ])
    error_message = "manage_finding_consumers = false must leave the detector, Security Hub account, standards, disabled controls, Macie session and the export lifecycle rule in place."
  }

  # The export entries leave the central-bucket consumer list: the bucket name
  # is set here, and with it empty the check would otherwise name features
  # this account no longer writes.
  assert {
    condition     = !contains(local.central_log_bucket_consumers, "GuardDuty findings export (guardduty_export_frequency)") && !contains(local.central_log_bucket_consumers, "Macie classification export (macie_publish_sensitive_data_findings)")
    error_message = "With manage_finding_consumers = false the central-bucket consumer list must not name the exports."
  }
}

# Consumers kept here while an administrator is designated: every member
# finding passes them by. A warning, not a failure — the operator may defer
# the move with security_finding_consumers_in_audit = false.
run "finding_consumers_beside_an_administrator_are_reported" {
  command = plan

  variables {
    audit_account_id             = "222222222222"
    root_credentials_management  = false
    allow_root_sessions          = false
    central_log_bucket_name      = "tlz-central-logs"
    guardduty_export_frequency   = "SIX_HOURS"
    guardduty_export_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  expect_failures = [check.finding_consumers_in_administrator]
}

run "finding_consumers_without_an_administrator_stay_silent" {
  command = plan

  variables {
    audit_account_id             = ""
    root_credentials_management  = false
    allow_root_sessions          = false
    central_log_bucket_name      = "tlz-central-logs"
    guardduty_export_frequency   = "SIX_HOURS"
    guardduty_export_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
  }

  # Only the empty-administrator warning fires, not the consumer one.
  expect_failures = [check.audit_account_configured]
}
