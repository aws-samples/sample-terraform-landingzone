# =============================================================================
# CloudWatch Log Data Protection
# =============================================================================
# Masks sensitive data (PII, credentials) in CloudWatch Log Groups.
# Applied to the CloudTrail log group by default when enabled.

locals {
  # Construct full data identifier ARNs from short names using the active partition
  data_protection_identifiers = [
    for id in var.cloudwatch_log_data_protection_identifiers :
    "arn:${local.partition}:dataprotection::aws:data-identifier/${id}"
  ]
}

resource "aws_cloudwatch_log_data_protection_policy" "cloudtrail" {
  count = var.enable_cloudwatch_log_data_protection && var.cloudwatch_log_group_retention != null ? 1 : 0

  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  policy_document = jsonencode({
    Name    = "tlz-data-protection-policy"
    Version = "2021-06-01"

    Statement = [
      {
        Sid            = "AuditSensitiveData"
        DataIdentifier = local.data_protection_identifiers
        Operation = {
          Audit = {
            FindingsDestination = {}
          }
        }
      },
      {
        Sid            = "MaskSensitiveData"
        DataIdentifier = local.data_protection_identifiers
        Operation = {
          Deidentify = {
            MaskConfig = {}
          }
        }
      },
    ]
  })
}

# Additional log groups for data protection (user-specified)
#
# The names reach PutDataProtectionPolicy unverified otherwise, and AWS
# answers a group that does not exist with ResourceNotFoundException at apply.
# Resolution as in modules/monitoring: a group this module creates itself — the
# account-trail groups; the org trail's group has its own policy above — is
# taken from the resource, which also orders the policy after the group; every
# other name is read through data.aws_cloudwatch_log_group so a missing group
# fails the PLAN with its name. A hard error and not a check: a scoped data
# source cannot use for_each, and an existing deployment whose policies
# applied has the groups.
locals {
  data_protection_additional_log_groups = toset(var.enable_cloudwatch_log_data_protection ? [
    for lg in var.cloudwatch_log_data_protection_log_groups : lg if lg != ""
  ] : [])

  # log group name → account trail name, for the groups cloudtrail.tf creates.
  data_protection_account_trail_log_groups = {
    for trail in var.cloudtrail_account_trails : "/aws/cloudtrail/${trail.name}" => trail.name
    if trail.send_to_cloudwatch_logs
  }

  data_protection_external_log_groups = toset([
    for lg in local.data_protection_additional_log_groups : lg
    if !contains(keys(local.data_protection_account_trail_log_groups), lg)
  ])
}

data "aws_cloudwatch_log_group" "data_protection_targets" {
  for_each = local.data_protection_external_log_groups

  name = each.value
}

resource "aws_cloudwatch_log_data_protection_policy" "additional" {
  for_each = local.data_protection_additional_log_groups

  log_group_name = (
    contains(keys(local.data_protection_account_trail_log_groups), each.value)
    ? aws_cloudwatch_log_group.account_trails[local.data_protection_account_trail_log_groups[each.value]].name
    : data.aws_cloudwatch_log_group.data_protection_targets[each.value].name
  )

  policy_document = jsonencode({
    Name    = "tlz-data-protection-policy"
    Version = "2021-06-01"

    Statement = [
      {
        Sid            = "AuditSensitiveData"
        DataIdentifier = local.data_protection_identifiers
        Operation = {
          Audit = {
            FindingsDestination = {}
          }
        }
      },
      {
        Sid            = "MaskSensitiveData"
        DataIdentifier = local.data_protection_identifiers
        Operation = {
          Deidentify = {
            MaskConfig = {}
          }
        }
      },
    ]
  })
}
