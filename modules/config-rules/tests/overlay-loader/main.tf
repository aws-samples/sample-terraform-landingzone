# =============================================================================
# Test helper: load one compliance overlay exactly as the stack does
# =============================================================================
# Used only by tests/overlay_mandatory_parameters.tftest.hcl. It decodes a
# configurations/frameworks/<framework>.tfvars file with Terraform's own
# tfvars decoder — the same shape terragrunt's read_tfvars_file() hands the
# config-rules stack in configurations/loader.hcl — so the test that consumes
# this output runs the module against the overlay AS COMMITTED, not against a
# transcription of it. Nothing here is a source of truth for the product: the
# overlays are.
#
# The second thing this helper carries is the mandatory-parameter table
# (local.mandatory_parameters). It exists because a managed rule whose
# identifier has a required parameter is refused by AWS when the overlay
# passes input_parameters = {}: PutOrganizationConfigRule answers 400
# InvalidParameterValueException "The required parameter [...] is not present
# in the inputParameters" (for example for
# CLOUDWATCH_ALARM_ACTION_CHECK). Only the live apply-test in
# tests/live/modules/config-rules/ sees that, and it transcribes fedramp-high
# alone; the other overlays are applied nowhere. This table is what lets an
# offline plan test catch the same class.
#
# Provenance of the table — AWS publishes one generated CloudFormation
# template per managed rule at
#   https://s3.amazonaws.com/aws-configservice-us-east-1/cloudformation-templates-for-managed-rules/<IDENTIFIER>.template
# Each template lists its parameters in two Metadata groups, "Required" and
# "Optional"; every Required parameter also carries MinLength 1 and the
# ConstraintDescription "This parameter is required.", every Optional one an
# empty default. Calibration: for CLOUDWATCH_ALARM_ACTION_CHECK the Required
# group is exactly the three parameters AWS refuses the rule without, and the
# five action1..action5 sit in Optional. A documented default does NOT mean
# optional (all three required parameters have one); the group label does —
# REDSHIFT_CLUSTER_CONFIGURATION_CHECK's nodeTypes has a default and is
# Optional. Every distinct identifier the eight overlays use was read that
# way and has a row in the table: exactly four have a non-empty Required
# group, the others an empty one and so an empty row. Rows are copied from the
# templates, not from the rules' HTML pages. Only CLOUDWATCH_ALARM_ACTION_CHECK
# is proven against the live API; every other row is AWS's own published
# requirement, not a test of PutOrganizationConfigRule.
#
# The table is a closed world. The consuming test turns red for an identifier
# that has NO row — misspelt, or new and not yet read from its template. A row
# says two things: AWS served a template under that identifier on the day the
# row was written (so the identifier exists), and which parameters that
# template marks Required (possibly none). It does not say AWS accepts the
# rule in a given account or region; only the live apply-test measures that,
# for fedramp-high alone. The closed world catches an identifier that does not
# exist, such as EC2_INSTANCES_IN_VPC: no template exists under that name
# (HTTP 403), the rule ec2-instances-in-vpc is identified INSTANCES_IN_VPC.
# That is not a missing parameter (vpcId on this rule is Optional); a table
# with rows only for identifiers that require a parameter could not see it,
# which is why every identifier has a row. The cost of a closed world: an
# overlay that adopts a valid
# identifier this table has not met is red until its row is added, and the
# error message says so.

terraform {
  required_version = ">= 1.14"

  required_providers {
    terraform = {
      source = "terraform.io/builtin/terraform"
    }
  }
}

variable "framework" {
  description = "File stem of an overlay under configurations/frameworks, e.g. fedramp-high."
  type        = string
}

locals {
  frameworks_dir = "${path.module}/../../../../configurations/frameworks"

  overlay = provider::terraform::decode_tfvars(
    file("${local.frameworks_dir}/${var.framework}.tfvars")
  )

  # Identifier -> parameters AWS refuses the rule without. Source: the
  # "Required" parameter group of AWS's generated template for the identifier
  # (see header). The KEY SET is the closed world of identifiers the gate
  # accepts: an identifier absent here turns the consuming run red. A row
  # with [] is an identifier whose template exists and marks nothing Required.
  mandatory_parameters = {
    # --- non-empty Required group ---
    # Proven against the live API (see the live test's header).
    CLOUDWATCH_ALARM_ACTION_CHECK = ["alarmActionRequired", "insufficientDataActionRequired", "okActionRequired"]
    # From the templates' Required group; not tested against the API.
    ACCESS_KEYS_ROTATED                  = ["maxAccessKeyAge"]
    IAM_USER_UNUSED_CREDENTIALS_CHECK    = ["maxCredentialUsageAge"]
    REDSHIFT_CLUSTER_CONFIGURATION_CHECK = ["clusterDbEncrypted", "loggingEnabled"]

    # --- empty Required group (template served with HTTP 200) ---
    ALB_WAF_ENABLED                                   = []
    API_GW_EXECUTION_LOGGING_ENABLED                  = []
    CLOUDTRAIL_S3_DATAEVENTS_ENABLED                  = []
    CLOUDWATCH_LOG_GROUP_ENCRYPTED                    = []
    CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED              = []
    CLOUD_TRAIL_ENABLED                               = []
    CLOUD_TRAIL_ENCRYPTION_ENABLED                    = []
    CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED           = []
    CMK_BACKING_KEY_ROTATION_ENABLED                  = []
    CW_LOGGROUP_RETENTION_PERIOD_CHECK                = []
    DB_INSTANCE_BACKUP_ENABLED                        = []
    DYNAMODB_TABLE_ENCRYPTED_KMS                      = []
    EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK              = []
    EC2_INSTANCE_MANAGED_BY_SSM                       = []
    EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK = []
    ELB_LOGGING_ENABLED                               = []
    ENCRYPTED_VOLUMES                                 = []
    GUARDDUTY_ENABLED_CENTRALIZED                     = []
    GUARDDUTY_NON_ARCHIVED_FINDINGS                   = []
    IAM_PASSWORD_POLICY                               = []
    IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS        = []
    IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS         = []
    IAM_ROOT_ACCESS_KEY_CHECK                         = []
    IAM_USER_GROUP_MEMBERSHIP_CHECK                   = []
    IAM_USER_MFA_ENABLED                              = []
    INCOMING_SSH_DISABLED                             = []
    INSTANCES_IN_VPC                                  = []
    INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY              = []
    LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED          = []
    LAMBDA_INSIDE_VPC                                 = []
    MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS                = []
    MULTI_REGION_CLOUD_TRAIL_ENABLED                  = []
    RDS_INSTANCE_DELETION_PROTECTION_ENABLED          = []
    RDS_LOGGING_ENABLED                               = []
    RDS_MULTI_AZ_SUPPORT                              = []
    RDS_STORAGE_ENCRYPTED                             = []
    RESTRICTED_INCOMING_TRAFFIC                       = []
    ROOT_ACCOUNT_MFA_ENABLED                          = []
    S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC    = []
    S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED          = []
    S3_BUCKET_LOGGING_ENABLED                         = []
    S3_BUCKET_PUBLIC_READ_PROHIBITED                  = []
    S3_BUCKET_PUBLIC_WRITE_PROHIBITED                 = []
    S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED          = []
    S3_BUCKET_VERSIONING_ENABLED                      = []
    SECURITYHUB_ENABLED                               = []
    SNS_ENCRYPTED_KMS                                 = []
    VPC_DEFAULT_SECURITY_GROUP_CLOSED                 = []
    VPC_FLOW_LOGS_ENABLED                             = []
    WAFV2_LOGGING_ENABLED                             = []
  }
}

output "managed_rules" {
  description = "The overlay's managed_rules list, decoded from the committed tfvars file."
  value       = try(local.overlay.managed_rules, [])
}

output "frameworks" {
  description = "Every overlay file stem present under configurations/frameworks."
  value       = toset([for f in fileset(local.frameworks_dir, "*.tfvars") : trimsuffix(f, ".tfvars")])
}

output "mandatory_parameters" {
  description = "Identifier -> parameter names AWS requires (see header for provenance). The key set is the closed world of identifiers the gate accepts."
  value       = local.mandatory_parameters
}
