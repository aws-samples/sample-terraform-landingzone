# =============================================================================
# NIST 800-53 Rev. 5 — Compliance Configuration
# =============================================================================
# Control families covered:
#   AC  — Access Control
#   AU  — Audit and Accountability
#   CM  — Configuration Management
#   IA  — Identification and Authentication
#   SC  — System and Communications Protection
#   SI  — System and Information Integrity
# =============================================================================

# --- Security Hub Standards (AC, CA, SI) ---
security_hub_standards = [
  "nist-800-53/v/5.0.0",
]

# --- Logging (AU family) ---
log_retention_days             = 365
cloudwatch_log_group_retention = 365
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Password Policy (IA family) ---
password_policy = {
  minimum_length            = 14
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 90
  password_reuse_prevention = 24
}

# --- Config Rules (AC, AU, CM, IA, SC, SI families) ---
managed_rules = [
  # AC — Access Control
  {
    name               = "nist-iam-root-access-key-check"
    source_identifier  = "IAM_ROOT_ACCESS_KEY_CHECK"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  {
    name               = "nist-iam-user-mfa-enabled"
    source_identifier  = "IAM_USER_MFA_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  {
    name               = "nist-mfa-enabled-for-iam-console-access"
    source_identifier  = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # AU — Audit and Accountability
  {
    name               = "nist-cloud-trail-enabled"
    source_identifier  = "CLOUD_TRAIL_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  {
    name               = "nist-cloudtrail-s3-dataevents-enabled"
    source_identifier  = "CLOUDTRAIL_S3_DATAEVENTS_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # CM — Configuration Management
  {
    name                 = "nist-ec2-instance-managed-by-ssm"
    source_identifier    = "EC2_INSTANCE_MANAGED_BY_SSM"
    resource_types_scope = ["AWS::SSM::ManagedInstanceInventory"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  {
    name               = "nist-ec2-managedinstance-patch-compliance"
    source_identifier  = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # SC — System and Communications Protection
  {
    name               = "nist-encrypted-volumes"
    source_identifier  = "ENCRYPTED_VOLUMES"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  {
    name               = "nist-s3-bucket-server-side-encryption-enabled"
    source_identifier  = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  {
    name               = "nist-rds-storage-encrypted"
    source_identifier  = "RDS_STORAGE_ENCRYPTED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # SI — System and Information Integrity
  {
    name               = "nist-guardduty-enabled-centralized"
    source_identifier  = "GUARDDUTY_ENABLED_CENTRALIZED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
]

# --- SCPs (AC, SC families) ---
service_control_policies = []
# Note: NIST 800-53 does not mandate specific preventive controls beyond what
# Config Rules and Security Hub cover. Add SCPs here if your organization
# requires additional preventive guardrails.

# --- KMS Keys (SC family) ---
kms_keys = []
