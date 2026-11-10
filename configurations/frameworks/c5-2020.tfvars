# =============================================================================
# BSI C5:2020 — Cloud Computing Compliance Criteria Catalogue
# =============================================================================
# Criteria domains covered:
#   OIS — Organisation of Information Security
#   AM  — Asset Management
#   IDM — Identity and Access Management
#   LOG — Logging and Monitoring
#   CRY — Cryptography and Key Management
# =============================================================================

# --- Security Hub Standards ---
# C5 aligns with CIS AWS Foundations Benchmark (already included in base).
security_hub_standards = []

# --- Logging (LOG criteria — LOG-01, LOG-02) ---
log_retention_days             = 365
cloudwatch_log_group_retention = 365
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Password Policy (IDM criteria — IDM-01, IDM-02) ---
password_policy = {
  minimum_length            = 12
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 90
  password_reuse_prevention = 12
}

# --- Config Rules (OIS, AM, IDM, LOG, CRY criteria) ---
managed_rules = [
  # IDM — Identity and Access Management (IDM-01 — User Group Membership)
  {
    name                 = "c5-iam-user-group-membership-check"
    source_identifier    = "IAM_USER_GROUP_MEMBERSHIP_CHECK"
    resource_types_scope = ["AWS::IAM::User"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # OIS — Organisation of Information Security (OIS-04 — Root Account Protection)
  {
    name               = "c5-root-account-mfa-enabled"
    source_identifier  = "ROOT_ACCOUNT_MFA_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # AM — Asset Management (AM-02 — Public Access Controls)
  {
    name               = "c5-s3-account-level-public-access-blocks"
    source_identifier  = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # LOG — Logging and Monitoring (LOG-01 — CloudTrail Integration)
  {
    name               = "c5-cloud-trail-cloud-watch-logs-enabled"
    source_identifier  = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # CRY — Cryptography and Key Management (CRY-02 — Key Rotation)
  {
    name               = "c5-cmk-backing-key-rotation-enabled"
    source_identifier  = "CMK_BACKING_KEY_ROTATION_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # IDM — Identity and Access Management (IDM-03 — Access Key Rotation)
  # maxAccessKeyAge is mandatory: AWS's generated template for the rule lists
  # it in the "Required" parameter group ("This parameter is required."), and
  # AWS Config refuses such a rule without its required parameters. The value
  # is the rule's documented default, as AWS's own conformance packs ship it;
  # a string because the module takes map(string).
  {
    name              = "c5-access-keys-rotated"
    source_identifier = "ACCESS_KEYS_ROTATED"
    input_parameters = {
      maxAccessKeyAge = "90"
    }
    excluded_accounts  = []
    deployment_targets = []
  },
]

# --- SCPs ---
service_control_policies = []

# --- KMS Keys ---
kms_keys = []
