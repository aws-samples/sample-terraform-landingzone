# =============================================================================
# NIST 800-171 Rev. 2 — Compliance Configuration
# =============================================================================
# Protecting Controlled Unclassified Information (CUI) in Nonfederal Systems
# and Organizations.
# Control families covered:
#   AC  — Access Control
#   AU  — Audit and Accountability
#   SC  — System and Communications Protection
# =============================================================================

# --- Security Hub Standards ---
# NIST 800-171 does not have a dedicated Security Hub standard.
security_hub_standards = []

# --- Logging (AU family — AU.L2-3.3.1, AU.L2-3.3.2) ---
log_retention_days             = 1095
cloudwatch_log_group_retention = 365
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Password Policy (AC family — AC.L2-3.1.8, IA.L2-3.5.7) ---
password_policy = {
  minimum_length            = 14
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 60
  password_reuse_prevention = 24
}

# --- Config Rules (AC, AU, SC families — CUI Protection Focus) ---
managed_rules = [
  # AC — Access Control (AC.L2-3.1.3 — Control CUI Flow)
  {
    name                 = "nist171-vpc-default-security-group-closed"
    source_identifier    = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
    resource_types_scope = ["AWS::EC2::SecurityGroup"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # AC — Access Control (AC.L2-3.1.20 — External System Connections)
  {
    name                 = "nist171-internet-gateway-authorized-vpc-only"
    source_identifier    = "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY"
    resource_types_scope = ["AWS::EC2::InternetGateway"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # AU — Audit and Accountability (AU.L2-3.3.8 — Protect Audit Information)
  {
    name                 = "nist171-db-instance-backup-enabled"
    source_identifier    = "DB_INSTANCE_BACKUP_ENABLED"
    resource_types_scope = ["AWS::RDS::DBInstance"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # SC — System and Communications Protection (SC.L2-3.13.16 — CUI at Rest)
  {
    name               = "nist171-sns-encrypted-kms"
    source_identifier  = "SNS_ENCRYPTED_KMS"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
]

# --- SCPs ---
service_control_policies = []
# Note: NIST 800-171 does not mandate specific preventive SCPs beyond what
# Config Rules and Security Hub cover. Add SCPs here if your organization
# requires additional preventive guardrails for CUI protection.

# --- KMS Keys ---
kms_keys = []
