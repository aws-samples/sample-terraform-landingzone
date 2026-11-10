# =============================================================================
# Base Configuration — Security Baseline
# =============================================================================
# Applied regardless of which compliance framework is selected.
# Provides a secure starting point for all Landing Zone deployments.
#
# IMPORTANT: This file is read by Terragrunt's read_tfvars_file() which cannot
# parse lists of objects with nested maps/lists. Complex types are stored in
# separate JSON files under configurations/base/:
#   - managed-rules.json              — AWS Config managed rules (31 rules)
#   - management-only-rules.json      — Management account Config rules (3 rules)
#   - security-hub-automation-rules.json — SecurityHub automation rules (36 rules)
#   - remediation-configs.json        — Config rule auto-remediation (2 configs)
#
# SCPs, RCPs, and SecurityHub standards are defined in env/common.hcl.
# =============================================================================

# The auto-remediation identities (remediation_assume_role_arn,
# remediation_instance_profile_name) belong here by subject but stay
# deliberately in env/common.hcl: both name IAM identities of one concrete
# installation (an account-bound role ARN and an instance profile), which is
# installation configuration, not a portable security baseline. The loader
# reads them from env/common.hcl only — an entry for either key in this file
# is not read. Every other key of this file reaches the loader (the loader
# wraps read_tfvars_file in jsondecode).

# --- Module Toggles ---
# The module on/off switches (enable_organization, enable_logging,
# enable_security, enable_iam, enable_config_rules, enable_monitoring) live in
# env/common.hcl: whether a module deploys at all is an operator decision per
# installation, not a security baseline. The stacks' exclude blocks read them
# from env/common.hcl only — entries here would have no reader.

# --- Security Services ---
enable_guardduty       = true
enable_security_hub    = true
enable_access_analyzer = true
enable_macie           = true

# --- Macie Configuration ---
macie_publishing_frequency            = "FIFTEEN_MINUTES"
macie_publish_sensitive_data_findings = false
macie_publish_policy_findings         = true

# --- GuardDuty Configuration ---
guardduty_export_frequency       = "SIX_HOURS"
guardduty_malware_protection     = true
guardduty_keep_malware_snapshots = false

# --- Password Policy (baseline) ---
password_policy = {
  minimum_length            = 14
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 90
  password_reuse_prevention = 24
  allow_users_to_change     = true
  hard_expiry               = false
}

# --- Logging (baseline) ---
log_retention_days             = 365
cloudwatch_log_group_retention = 365
cloudtrail_s3_data_events      = true
cloudtrail_lambda_data_events  = true
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Encryption (baseline) ---
enable_ebs_default_encryption   = true
enable_s3_public_access_block   = true
enable_ssm_block_public_sharing = true

# --- S3 Lifecycle Rules ---
# retention_days is the baseline *floor*, not the effective expiry. The loader
# raises it to the merged log_retention_days whenever a compliance framework
# demands a longer retention; it never falls below it. The
# 1000 days sit deliberately above glacier_transition_days so that the move to
# GLACIER_IR after a year has an effect at all.
# Effective retention_days per framework selection: none, c5-2020 and
# nist-800-53 keep 1000; fedramp-moderate, iso-27001 and nist-800-171 give 1095;
# cmmc, fedramp-high and hipaa give 2555.
s3_lifecycle_rules = {
  cloudtrail = {
    retention_days                         = 1000
    glacier_transition_days                = 365
    storage_class                          = "GLACIER_IR"
    abort_incomplete_multipart_upload_days = 7
  }
  config = {
    retention_days                         = 1000
    glacier_transition_days                = 365
    storage_class                          = "GLACIER_IR"
    abort_incomplete_multipart_upload_days = 7
  }
  access_logs = {
    retention_days                         = 1000
    glacier_transition_days                = 365
    storage_class                          = "GLACIER_IR"
    abort_incomplete_multipart_upload_days = 7
  }
}

# --- ELB Log Bucket (baseline) ---
enable_elb_log_bucket = true

# retention_days is a floor here too — see the note on s3_lifecycle_rules.
elb_log_bucket_lifecycle = {
  glacier_transition_days                = 365
  retention_days                         = 1000
  abort_incomplete_multipart_upload_days = 7
}

# --- Session Manager (baseline) ---
enable_session_manager_logging       = true
enable_session_manager_s3_logging    = false
session_manager_cloudwatch_log_group = "/aws/ssm/session-manager"

# --- SNS KMS Encryption ---
sns_kms_encryption = true

# --- Audit Manager ---
enable_audit_manager_bucket = false

# --- GuardDuty S3 Malware Protection ---
enable_guardduty_s3_malware_protection = false
guardduty_s3_malware_configs           = []
guardduty_eks_manage_agent             = false

# --- SecurityHub → CloudWatch Forwarding ---
enable_securityhub_cloudwatch_forwarding = false
securityhub_severity_filter              = []

# --- SCP Auto-Revert ---
enable_scp_auto_revert = false

# --- Quarantine Auto-Detach ---
enable_quarantine_auto_detach = false

# --- Default VPC/SG Cleanup ---
enable_delete_default_vpc      = false
enable_delete_default_sg_rules = false

# --- StackSet Roles ---
enable_stackset_roles = false

# =============================================================================
# Baseline statements for module inputs
# =============================================================================
# Each key below is declared by a module and documented in
# docs/configuration-reference.md. Every value here equals the module
# default, so making the baseline explicit does not change any deployment.
#
# Only switches whose module default is false are stated here. The loader merges
# booleans with OR, so a baseline "true" could not be switched off in
# env/common.hcl — those switches deliberately stay out of this file and keep
# their module default until env/common.hcl sets them (see the comment block at
# "Merge: Booleans by OR" in configurations/loader.hcl).

# --- Logging: separate access log bucket and per-account KMS keys ---
enable_separate_access_logs_bucket = false
enable_per_account_kms_keys        = false

# --- Encryption: Lambda environment variables and SQS ---
enable_lambda_encryption = false
enable_sqs_kms_key       = false

# --- SSM Inventory resource data sync ---
enable_ssm_resource_data_sync = false

# --- GuardDuty EKS runtime monitoring ---
guardduty_eks_runtime_monitoring = false

# --- Root sessions ---
# Merged with AND, not OR: the restrictive value is false, so every layer has to
# agree before root sessions are permitted. A "false" in env/common.hcl
# therefore takes effect against this baseline.
allow_root_sessions = true

# --- CloudWatch Logs data protection: categories of sensitive data ---
# Merged as a union, so every layer may add categories and none may drop one.
cloudwatch_log_data_protection_identifiers = [
  "CreditCardNumber",
  "CreditCardExpiration",
  "CreditCardSecurityCode",
  "EmailAddress",
  "IpAddress",
  "AwsSecretKey",
  "OpenSshPrivateKey",
  "PgpPrivateKey",
  "PkcsPrivateKey",
]

# =============================================================================
# Alarm baseline (CIS AWS Foundations controls 3.x/4.x)
# =============================================================================
# Each of the CIS AWS Foundations controls 3.x/4.x asks for a metric filter plus
# an alarm. Without values in cloudwatch_metric_filters and cloudwatch_alarms no
# deployment would create a single metric filter or alarm.
#
# Placed here and not in env/common.hcl because these ten controls are part of the
# security baseline of every installation, not of one. The loader concatenates the
# two layers (configurations/loader.hcl, cloudwatch_metric_filters /
# cloudwatch_alarms), so an installation may add its own filters and alarms on top
# without touching this file.
#
# Log group: /aws/cloudtrail/tlz-org-trail — the organization trail log group of
# modules/logging (modules/logging/cloudtrail.tf). It exists as long as
# cloudwatch_log_group_retention is not null (365 above), and
# stacks/management/monitoring declares a dependency on ../logging, so the group
# is created before the filters.
#
# Expected effect per region in the management account: 10 metric filters
# (no charge) and 10 metric alarms (one monthly fee per alarm; ten alarms are a
# single-digit dollar amount per month and region). No other resource changes.
#
# OPEN EDGE — the alarms notify nobody by default. alarm_actions stays empty on
# all ten: an SNS topic of severity HIGH does not belong here, because a sns_topics
# entry in this file would switch every installation from the single-topic
# fallback to severity topics (modules/monitoring/main.tf,
# use_severity_topics = length(var.sns_topics) > 0), which drops the
# fallback topic, its subscriptions and its GuardDuty rule, leaves
# CRITICAL findings (severity 9-10) without a route, and makes a per-installation
# HIGH topic impossible because local.severity_topics keys by severity and would
# hit a duplicate key. The recipients therefore belong in env/common.hcl, as
# sns_topics (severity topics) or sns_email_targets (fallback). Until they are
# configured, the alarms change state and stay visible in the console but send no
# notification.

cloudwatch_metric_filters = [
  {
    name             = "root-account-usage"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ $.userIdentity.type = \"Root\" }"
    metric_namespace = "TLZ/Security"
    metric_name      = "RootAccountUsage"
  },
  {
    name             = "unauthorized-api-calls"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "UnauthorizedApiCalls"
  },
  {
    name             = "console-signin-without-mfa"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "ConsoleSigninWithoutMfa"
  },
  {
    name             = "iam-policy-changes"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"Put*Policy\") || ($.eventName = \"Attach*Policy\") || ($.eventName = \"Detach*Policy\") || ($.eventName = \"Delete*Policy\") || ($.eventName = \"Create*Policy\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "IamPolicyChanges"
  },
  {
    name             = "cloudtrail-config-changes"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"StopLogging\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"UpdateTrail\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "CloudTrailConfigChanges"
  },
  {
    name             = "config-changes"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"StopConfigurationRecorder\") || ($.eventName = \"DeleteDeliveryChannel\") || ($.eventName = \"PutConfigurationRecorder\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "ConfigChanges"
  },
  {
    name             = "s3-bucket-policy-changes"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"PutBucketPolicy\") || ($.eventName = \"PutBucketAcl\") || ($.eventName = \"DeleteBucketPolicy\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "S3BucketPolicyChanges"
  },
  {
    name             = "kms-key-deletion"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"DisableKey\") || ($.eventName = \"ScheduleKeyDeletion\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "KmsKeyDeletion"
  },
  {
    name             = "security-group-changes"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "SecurityGroupChanges"
  },
  {
    name             = "organizations-changes"
    log_group_name   = "/aws/cloudtrail/tlz-org-trail"
    pattern          = "{ ($.eventName = \"LeaveOrganization\") || ($.eventName = \"RemoveAccountFromOrganization\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"UpdatePolicy\") }"
    metric_namespace = "TLZ/Security"
    metric_name      = "OrganizationsChanges"
  },
]

# One alarm per metric filter. Threshold 1 everywhere except
# unauthorized-api-calls: denied calls are common in normal operation, so that one
# uses 5 over 5 minutes to stay usable.
cloudwatch_alarms = [
  {
    name              = "root-account-usage"
    metric_name       = "RootAccountUsage"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.3 — the root user of an account was used."
  },
  {
    name               = "unauthorized-api-calls"
    metric_name        = "UnauthorizedApiCalls"
    namespace          = "TLZ/Security"
    threshold          = 5
    evaluation_periods = 1
    period             = 300
    alarm_description  = "CIS 3.1 — five or more unauthorized API calls within five minutes."
  },
  {
    name              = "console-signin-without-mfa"
    metric_name       = "ConsoleSigninWithoutMfa"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.2 — console sign-in without multi-factor authentication."
  },
  {
    name              = "iam-policy-changes"
    metric_name       = "IamPolicyChanges"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.4 — an IAM policy was created, changed, attached, detached or deleted."
  },
  {
    name              = "cloudtrail-config-changes"
    metric_name       = "CloudTrailConfigChanges"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.5 — a CloudTrail trail was stopped, changed or deleted."
  },
  {
    name              = "config-changes"
    metric_name       = "ConfigChanges"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.9 — an AWS Config recorder or delivery channel was changed."
  },
  {
    name              = "s3-bucket-policy-changes"
    metric_name       = "S3BucketPolicyChanges"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.8 — an S3 bucket policy or ACL was changed."
  },
  {
    name              = "kms-key-deletion"
    metric_name       = "KmsKeyDeletion"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.7 — a KMS key was disabled or scheduled for deletion."
  },
  {
    name              = "security-group-changes"
    metric_name       = "SecurityGroupChanges"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "CIS 3.10 — a security group or one of its ingress rules was changed."
  },
  {
    name              = "organizations-changes"
    metric_name       = "OrganizationsChanges"
    namespace         = "TLZ/Security"
    threshold         = 1
    alarm_description = "An account left the organization or an organization policy was changed."
  },
]
