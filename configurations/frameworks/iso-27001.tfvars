# =============================================================================
# ISO 27001:2022 — Information Security Management System (ISMS)
# =============================================================================
# Annex A control categories covered:
#   A.5 — Organizational Controls
#   A.6 — People Controls
#   A.8 — Technological Controls
# =============================================================================

# --- Security Hub Standards ---
# No dedicated ISO 27001 Security Hub standard exists.
# Base standards (FSBP, CIS) provide relevant coverage.
security_hub_standards = []

# --- Logging (A.8.15 — Logging, A.8.17 — Clock Synchronization) ---
log_retention_days             = 1095
cloudwatch_log_group_retention = 365
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Password Policy (A.5.17 — Authentication Information, A.8.5 — Secure Authentication) ---
password_policy = {
  minimum_length            = 14
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 90
  password_reuse_prevention = 24
}

# --- Config Rules (Annex A organizational, people, technological controls) ---
managed_rules = [
  # A.5 — Organizational Controls (A.5.15 — Access Control, A.5.18 — Access Rights)
  {
    name               = "iso-iam-policy-no-statements-with-admin-access"
    source_identifier  = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # A.5 — Organizational Controls (A.5.15 — Access Control, A.5.18 — Access Rights)
  {
    name               = "iso-iam-policy-no-statements-with-full-access"
    source_identifier  = "IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # A.6 — People Controls (A.6.1 — Screening, A.6.2 — Terms and Conditions)
  # CloudTrail monitors user activity for accountability
  {
    name               = "iso-cloudtrail-enabled"
    source_identifier  = "CLOUD_TRAIL_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # A.8 — Technological Controls (A.8.3 — Information Access Restriction)
  {
    name                 = "iso-s3-bucket-level-public-access-prohibited"
    source_identifier    = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
    resource_types_scope = ["AWS::S3::Bucket"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # A.8 — Technological Controls (A.8.15 — Logging)
  {
    name                 = "iso-rds-logging-enabled"
    source_identifier    = "RDS_LOGGING_ENABLED"
    resource_types_scope = ["AWS::RDS::DBInstance"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # A.8 — Technological Controls (A.8.22 — Web Filtering, A.8.20 — Network Security)
  {
    name               = "iso-wafv2-logging-enabled"
    source_identifier  = "WAFV2_LOGGING_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
]

# --- SCPs ---
service_control_policies = []

# --- KMS Keys ---
kms_keys = []
