# =============================================================================
# HIPAA — Compliance Configuration
# =============================================================================
# Safeguard categories covered:
#   Administrative Safeguards  — §164.308
#   Physical Safeguards        — §164.310
#   Technical Safeguards       — §164.312
#   Organizational Requirements — §164.314
# =============================================================================

# --- Security Hub Standards ---
# Security Hub publishes no HIPAA standard (the standards reference lists
# FSBP, CIS, NIST 800-53/800-171, PCI DSS and others — no HIPAA entry). A
# subscription to a standards ARN that does not exist passes plan/validate
# and fails at apply, so this file subscribes to none. The security baseline
# (env/common.hcl) already subscribes FSBP, CIS v3.0.0 and NIST 800-53; the
# nist-800-53 framework configuration adds its Config rules and SCPs on top
# when that framework is enabled alongside this one.
#
# HIPAA-specific detection comes from the managed_rules below. For broader
# coverage, deploy the AWS Config conformance pack "Operational Best
# Practices for HIPAA Security"
# (https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-hipaa_security.html):
# upload the sample template to an S3 bucket you own, then register it —
# either here via template_s3_uri or in env/common.hcl, where file() can
# inline a local copy as template_body:
#
#   conformance_packs = [{
#     name            = "Operational-Best-Practices-for-HIPAA-Security"
#     template_s3_uri = "s3://<your-template-bucket>/Operational-Best-Practices-for-HIPAA-Security.yaml"
#   }]
#
# No entry ships active: the template must exist in an operator-owned
# location first, and a placeholder URI would pass the plan and fail the
# apply.
security_hub_standards = []

# --- Logging (§164.312(b) — Audit Controls) ---
log_retention_days             = 2555
cloudwatch_log_group_retention = 365
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Password Policy (§164.312(d) — Person or Entity Authentication) ---
password_policy = {
  minimum_length            = 14
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 90
  password_reuse_prevention = 24
}

# --- Config Rules (Administrative, Technical, Organizational Safeguards) ---
managed_rules = [
  # Administrative Safeguards — §164.308
  {
    name               = "hipaa-cloud-trail-encryption-enabled"
    source_identifier  = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  {
    name               = "hipaa-cloudwatch-log-group-encrypted"
    source_identifier  = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # Technical Safeguards — §164.312
  {
    name                 = "hipaa-s3-bucket-logging-enabled"
    source_identifier    = "S3_BUCKET_LOGGING_ENABLED"
    resource_types_scope = ["AWS::S3::Bucket"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  {
    name                 = "hipaa-rds-instance-deletion-protection-enabled"
    source_identifier    = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
    resource_types_scope = ["AWS::RDS::DBInstance"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  {
    name                 = "hipaa-dynamodb-table-encrypted-kms"
    source_identifier    = "DYNAMODB_TABLE_ENCRYPTED_KMS"
    resource_types_scope = ["AWS::DynamoDB::Table"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  {
    name                 = "hipaa-lambda-function-public-access-prohibited"
    source_identifier    = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
    resource_types_scope = ["AWS::Lambda::Function"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # Organizational Requirements — §164.314
  # clusterDbEncrypted and loggingEnabled are mandatory: AWS's generated
  # template for the rule lists both in the "Required" parameter group ("This
  # parameter is required."), and AWS Config refuses such a rule without its
  # required parameters.
  # Values are the rule's documented defaults, exactly the two parameters
  # AWS's Operational-Best-Practices-for-HIPAA-Security pack ships; strings
  # because the module takes map(string). The third parameter, nodeTypes, is
  # Optional and deliberately left unset — setting it would restrict the check
  # to the named node types.
  {
    name                 = "hipaa-redshift-cluster-configuration-check"
    source_identifier    = "REDSHIFT_CLUSTER_CONFIGURATION_CHECK"
    resource_types_scope = ["AWS::Redshift::Cluster"]
    input_parameters = {
      clusterDbEncrypted = "true"
      loggingEnabled     = "true"
    }
    excluded_accounts  = []
    deployment_targets = []
  },
  {
    name                 = "hipaa-elb-logging-enabled"
    source_identifier    = "ELB_LOGGING_ENABLED"
    resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
]

# --- SCPs (§164.312(a) — Access Control, HIPAA-Eligible Services) ---
service_control_policies = [
  {
    name        = "hipaa-restrict-non-eligible-services"
    description = "Restricts usage to HIPAA-eligible AWS services only. Denies access to services not covered under the AWS BAA."
    content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyNonHIPAAEligibleServices\",\"Effect\":\"Deny\",\"Action\":[\"gamelift:*\",\"mechanicalturk:*\",\"ground-station:*\",\"iot-roborunner:*\",\"nimble:*\",\"finspace:*\",\"healthlake:*\"],\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"arn:*:iam::*:role/AWSControlTowerExecution\",\"arn:*:iam::*:role/stacksets-exec-*\"]}}}]}"
    targets     = []
  },
]

# --- KMS Keys (§164.312(a)(2)(iv) — Encryption and Decryption, PHI Protection) ---
# Attribute names follow the kms_keys type of modules/security: alias (required)
# and enable_key_rotation. Any other attribute name is dropped silently on type
# conversion, and a missing alias aborts every run of the security stack.
# policy is omitted — an empty string is not a valid key policy.
kms_keys = [
  {
    alias               = "hipaa-phi-encryption-key"
    description         = "KMS key for encrypting Protected Health Information (PHI) at rest. Supports HIPAA §164.312(a)(2)(iv) encryption requirements."
    enable_key_rotation = true
  },
]

# --- Networking Defaults (§164.312(e) — Transmission Security) ---
networking_defaults = {
  vpc_flow_logs_enabled = true
  private_subnet_only   = true
}
