# =============================================================================
# CMMC Level 2 — Compliance Configuration
# =============================================================================
# Cybersecurity Maturity Model Certification (CMMC) Level 2
# Domains covered:
#   AC  — Access Control
#   AU  — Audit and Accountability
#   CM  — Configuration Management
#   IA  — Identification and Authentication
#   IR  — Incident Response
#   SC  — System and Communications Protection
#   SI  — System and Information Integrity
# =============================================================================

# --- Security Hub Standards ---
# CMMC does not have a dedicated Security Hub standard.
security_hub_standards = []

# --- Logging (AU domain) ---
log_retention_days             = 2555
cloudwatch_log_group_retention = 365
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Password Policy (IA domain — IA.L2-3.5.7, IA.L2-3.5.8) ---
password_policy = {
  minimum_length            = 14
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 60
  password_reuse_prevention = 24
}

# --- Config Rules (AC, AU, CM, IA, IR, SC, SI domains) ---
managed_rules = [
  # IA — Identification and Authentication
  {
    name               = "cmmc-iam-password-policy"
    source_identifier  = "IAM_PASSWORD_POLICY"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # maxCredentialUsageAge is mandatory: AWS's generated template for the rule
  # lists it in the "Required" parameter group ("This parameter is required."),
  # and AWS Config refuses such a rule without its required parameters. The
  # value is the rule's documented default, as AWS's own conformance packs ship
  # it; a string because the module takes map(string).
  {
    name              = "cmmc-iam-user-unused-credentials-check"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
    input_parameters = {
      maxCredentialUsageAge = "90"
    }
    excluded_accounts  = []
    deployment_targets = []
  },
  # AU — Audit and Accountability
  {
    name               = "cmmc-multi-region-cloud-trail-enabled"
    source_identifier  = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # SC — System and Communications Protection
  {
    name               = "cmmc-vpc-flow-logs-enabled"
    source_identifier  = "VPC_FLOW_LOGS_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # AC — Access Control
  {
    name               = "cmmc-restricted-incoming-traffic"
    source_identifier  = "RESTRICTED_INCOMING_TRAFFIC"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # CM — Configuration Management
  {
    name                 = "cmmc-s3-bucket-versioning-enabled"
    source_identifier    = "S3_BUCKET_VERSIONING_ENABLED"
    resource_types_scope = ["AWS::S3::Bucket"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # AC — Access Control (network)
  {
    name               = "cmmc-incoming-ssh-disabled"
    source_identifier  = "INCOMING_SSH_DISABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # SC — System and Communications Protection (network isolation)
  {
    name                 = "cmmc-ec2-instances-in-vpc"
    source_identifier    = "INSTANCES_IN_VPC"
    resource_types_scope = ["AWS::EC2::Instance"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
]

# --- SCPs (AC domain — Data Residency, Service Restriction) ---
service_control_policies = [
  {
    name        = "cmmc-data-residency"
    description = "Restricts resource creation to approved AWS regions to enforce CMMC Level 2 data residency requirements for Controlled Unclassified Information (CUI)."
    content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyOutsideApprovedRegions\",\"Effect\":\"Deny\",\"NotAction\":[\"iam:*\",\"sts:*\",\"s3:GetBucketLocation\",\"s3:ListAllMyBuckets\",\"organizations:*\",\"support:*\",\"health:*\",\"trustedadvisor:*\",\"cloudfront:*\",\"route53:*\",\"budgets:*\",\"waf:*\",\"wafv2:*\",\"cloudwatch:Get*\",\"cloudwatch:List*\",\"cloudwatch:Describe*\"],\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:RequestedRegion\":[\"us-east-1\",\"us-east-2\",\"us-west-2\"]},\"StringNotLike\":{\"aws:PrincipalArn\":[\"arn:*:iam::*:role/AWSControlTowerExecution\",\"arn:*:iam::*:role/stacksets-exec-*\"]}}}]}"
    targets     = []
  },
  {
    name        = "cmmc-restrict-unapproved-services"
    description = "Restricts usage of AWS services not aligned with CMMC Level 2 security requirements. Denies access to high-risk or non-essential services."
    content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyUnapprovedServices\",\"Effect\":\"Deny\",\"Action\":[\"gamelift:*\",\"mechanicalturk:*\",\"ground-station:*\",\"nimble:*\",\"iot-roborunner:*\",\"lightsail:*\",\"appflow:*\"],\"Resource\":\"*\",\"Condition\":{\"StringNotLike\":{\"aws:PrincipalArn\":[\"arn:*:iam::*:role/AWSControlTowerExecution\",\"arn:*:iam::*:role/stacksets-exec-*\"]}}}]}"
    targets     = []
  },
]

# --- Permission Boundary (AC domain — AC.L2-3.1.2 Least Privilege) ---
customer_managed_policies = [
  {
    name        = "cmmc-least-privilege-boundary"
    description = "Permission boundary enforcing least-privilege access aligned with CMMC Level 2 practices. Restricts actions to approved services and denies privilege escalation."
    policy      = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowApprovedServices\",\"Effect\":\"Allow\",\"Action\":[\"ec2:*\",\"s3:*\",\"rds:*\",\"lambda:*\",\"dynamodb:*\",\"sns:*\",\"sqs:*\",\"kms:*\",\"logs:*\",\"cloudwatch:*\",\"cloudtrail:*\",\"config:*\",\"ssm:*\",\"secretsmanager:*\",\"guardduty:*\",\"securityhub:*\",\"iam:Get*\",\"iam:List*\",\"iam:PassRole\",\"sts:AssumeRole\",\"sts:GetCallerIdentity\"],\"Resource\":\"*\"},{\"Sid\":\"DenyPrivilegeEscalation\",\"Effect\":\"Deny\",\"Action\":[\"iam:CreateUser\",\"iam:CreateRole\",\"iam:PutRolePolicy\",\"iam:AttachRolePolicy\",\"iam:PutUserPolicy\",\"iam:AttachUserPolicy\",\"iam:DeleteRolePermissionsBoundary\",\"iam:DeleteUserPermissionsBoundary\",\"iam:SetDefaultPolicyVersion\",\"organizations:LeaveOrganization\"],\"Resource\":\"*\"}]}"
  },
]

# --- KMS Keys ---
kms_keys = []
