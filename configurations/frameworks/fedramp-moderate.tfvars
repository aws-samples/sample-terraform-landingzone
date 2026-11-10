# =============================================================================
# FedRAMP Moderate — Compliance Configuration
# =============================================================================
# Federal Risk and Authorization Management Program (FedRAMP) Moderate Baseline
# Control families covered:
#   AC  — Access Control
#   AU  — Audit and Accountability
#   CA  — Assessment, Authorization, and Monitoring
#   CM  — Configuration Management
#   CP  — Contingency Planning
#   IA  — Identification and Authentication
#   SC  — System and Communications Protection
#   SI  — System and Information Integrity
# =============================================================================

# --- Security Hub Standards ---
# FedRAMP Moderate aligns with CIS AWS Foundations Benchmark (already in base,
# but explicitly listed here for FedRAMP traceability).
security_hub_standards = [
  "cis-aws-foundations-benchmark/v/3.0.0",
]

# --- Logging (AU family — AU-6, AU-11) ---
log_retention_days             = 1095
cloudwatch_log_group_retention = 365
cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]

# --- Password Policy (IA family — IA-5) ---
password_policy = {
  minimum_length            = 14
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  max_age                   = 90
  password_reuse_prevention = 24
}

# --- Config Rules (AC, AU, CM, CP, SC, SI families) ---
managed_rules = [
  # AU — Audit and Accountability (AU-3, AU-6)
  {
    name               = "fedramp-mod-cloud-trail-log-file-validation-enabled"
    source_identifier  = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # AC — Access Control (AC-3, AC-4)
  {
    name                 = "fedramp-mod-s3-bucket-public-read-prohibited"
    source_identifier    = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    resource_types_scope = ["AWS::S3::Bucket"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  {
    name                 = "fedramp-mod-s3-bucket-public-write-prohibited"
    source_identifier    = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    resource_types_scope = ["AWS::S3::Bucket"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # CP — Contingency Planning (CP-10)
  {
    name                 = "fedramp-mod-rds-multi-az-support"
    source_identifier    = "RDS_MULTI_AZ_SUPPORT"
    resource_types_scope = ["AWS::RDS::DBInstance"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # SC — System and Communications Protection (SC-7)
  {
    name               = "fedramp-mod-ebs-snapshot-public-restorable-check"
    source_identifier  = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
    input_parameters   = {}
    excluded_accounts  = []
    deployment_targets = []
  },
  # SC — System and Communications Protection (SC-7 — Network Isolation)
  {
    name                 = "fedramp-mod-lambda-inside-vpc"
    source_identifier    = "LAMBDA_INSIDE_VPC"
    resource_types_scope = ["AWS::Lambda::Function"]
    input_parameters     = {}
    excluded_accounts    = []
    deployment_targets   = []
  },
  # SI — System and Information Integrity (SI-4)
  # The three parameters are mandatory: AWS refuses the rule without them
  # (400 InvalidParameterValueException on PutOrganizationConfigRule).
  # Values are the rule's documented defaults, as AWS's own conformance packs
  # ship them (FedRAMP-Moderate in lower case, FedRAMP-High in upper case);
  # spelled as in fedramp-high.tfvars so the two overlays agree, strings
  # because the module takes map(string).
  {
    name              = "fedramp-mod-cloudwatch-alarm-action-check"
    source_identifier = "CLOUDWATCH_ALARM_ACTION_CHECK"
    input_parameters = {
      alarmActionRequired            = "TRUE"
      insufficientDataActionRequired = "TRUE"
      okActionRequired               = "FALSE"
    }
    excluded_accounts  = []
    deployment_targets = []
  },
]

# --- SCPs (AC-2, SC-7 — Region Restriction, Encryption Enforcement) ---
service_control_policies = [
  {
    name        = "fedramp-mod-region-restriction"
    description = "Restricts resource creation to FedRAMP-authorized AWS regions. Supports AC-2 and SC-7 boundary protection controls for FedRAMP Moderate baseline."
    content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyOutsideFedRAMPRegions\",\"Effect\":\"Deny\",\"NotAction\":[\"iam:*\",\"sts:*\",\"s3:GetBucketLocation\",\"s3:ListAllMyBuckets\",\"organizations:*\",\"support:*\",\"health:*\",\"trustedadvisor:*\",\"cloudfront:*\",\"route53:*\",\"budgets:*\",\"waf:*\",\"wafv2:*\",\"cloudwatch:Get*\",\"cloudwatch:List*\",\"cloudwatch:Describe*\"],\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:RequestedRegion\":[\"us-east-1\",\"us-east-2\",\"us-west-1\",\"us-west-2\"]},\"StringNotLike\":{\"aws:PrincipalArn\":[\"arn:*:iam::*:role/AWSControlTowerExecution\",\"arn:*:iam::*:role/stacksets-exec-*\"]}}}]}"
    targets     = []
  },
  {
    name        = "fedramp-mod-enforce-encryption"
    description = "Enforces encryption at rest for S3 and EBS resources. Supports SC-28 protection of information at rest for FedRAMP Moderate baseline."
    content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyUnencryptedS3Uploads\",\"Effect\":\"Deny\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption\":\"aws:kms\"},\"Null\":{\"s3:x-amz-server-side-encryption\":\"false\"},\"StringNotLike\":{\"aws:PrincipalArn\":[\"arn:*:iam::*:role/AWSControlTowerExecution\",\"arn:*:iam::*:role/stacksets-exec-*\"]}}},{\"Sid\":\"DenyS3UploadsWithoutEncryptionHeader\",\"Effect\":\"Deny\",\"Action\":\"s3:PutObject\",\"Resource\":\"*\",\"Condition\":{\"Null\":{\"s3:x-amz-server-side-encryption\":\"true\"},\"StringNotLike\":{\"aws:PrincipalArn\":[\"arn:*:iam::*:role/AWSControlTowerExecution\",\"arn:*:iam::*:role/stacksets-exec-*\"]}}},{\"Sid\":\"DenyUnencryptedEBSVolumes\",\"Effect\":\"Deny\",\"Action\":\"ec2:CreateVolume\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"ec2:Encrypted\":\"false\"},\"StringNotLike\":{\"aws:PrincipalArn\":[\"arn:*:iam::*:role/AWSControlTowerExecution\",\"arn:*:iam::*:role/stacksets-exec-*\"]}}}]}"
    targets     = []
  },
]

# --- KMS Keys (SC-12, SC-13 — Cryptographic Key Management) ---
# Attribute names follow the kms_keys type of modules/security: alias (required)
# and enable_key_rotation. Any other attribute name is dropped silently on type
# conversion, and a missing alias aborts every run of the security stack.
# policy is omitted — an empty string is not a valid key policy.
kms_keys = [
  {
    alias               = "fedramp-mod-encryption-key"
    description         = "KMS key for FedRAMP Moderate data encryption at rest. Supports SC-12 key establishment and SC-13 cryptographic protection controls. Key rotation enforced."
    enable_key_rotation = true
  },
]

# --- Permission Boundary (AC-6 — Least Privilege, FedRAMP-Authorized Services) ---
customer_managed_policies = [
  {
    name        = "fedramp-mod-authorized-services-boundary"
    description = "Permission boundary restricting actions to FedRAMP-authorized AWS services. Supports AC-6 least privilege and prevents usage of non-authorized services."
    policy      = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowFedRAMPAuthorizedServices\",\"Effect\":\"Allow\",\"Action\":[\"ec2:*\",\"s3:*\",\"rds:*\",\"lambda:*\",\"dynamodb:*\",\"sns:*\",\"sqs:*\",\"kms:*\",\"logs:*\",\"cloudwatch:*\",\"cloudtrail:*\",\"config:*\",\"ssm:*\",\"secretsmanager:*\",\"guardduty:*\",\"securityhub:*\",\"elasticloadbalancing:*\",\"ecs:*\",\"ecr:*\",\"wafv2:*\",\"route53:*\",\"cloudfront:*\",\"iam:Get*\",\"iam:List*\",\"iam:PassRole\",\"sts:AssumeRole\",\"sts:GetCallerIdentity\"],\"Resource\":\"*\"},{\"Sid\":\"DenyPrivilegeEscalation\",\"Effect\":\"Deny\",\"Action\":[\"iam:CreateUser\",\"iam:CreateRole\",\"iam:PutRolePolicy\",\"iam:AttachRolePolicy\",\"iam:PutUserPolicy\",\"iam:AttachUserPolicy\",\"iam:DeleteRolePermissionsBoundary\",\"iam:DeleteUserPermissionsBoundary\",\"iam:SetDefaultPolicyVersion\",\"organizations:LeaveOrganization\"],\"Resource\":\"*\"}]}"
  },
]

# --- Networking Defaults (SC-7 — Boundary Protection, Hub-and-Spoke with Inspection) ---
networking_defaults = {
  transit_gateway_enabled  = true
  network_firewall_enabled = true
  vpc_flow_logs_enabled    = true
  private_subnet_only      = true
}
