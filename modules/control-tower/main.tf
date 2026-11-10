# Control Tower module — creates or manages an AWS Control Tower Landing Zone
#
# Prerequisites (ensured by the root module):
# - AWS Organization with ALL features
# - Audit and Log-Archive accounts exist
# - CT service roles are created here

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  arn_prefix = "arn:${local.partition}"
  # DNS suffix of service principals — derived from the partition and handed
  # to the trust-policy templates, so the service roles trust the principal
  # that exists in the partition the module runs in.
  dns_suffix            = data.aws_partition.current.dns_suffix
  management_account_id = var.management_account_id != "" ? var.management_account_id : data.aws_caller_identity.current.account_id

  # Flatten control-OU pairs for aws_controltower_control resources.
  #
  # An entry of organizational_units is either an OU name that ou_name_to_arn
  # resolves, or an OU ARN that is passed through unchanged. var.
  # control_tower_controls rejects every other value at plan time, so an
  # unresolved OU name can never reach target_identifier — AWS expects an ARN
  # there and would otherwise fail late with a misleading message.
  #
  # control_identifier is a partition-neutral control name; the module builds
  # the ARN from local.arn_prefix, so the same configuration works in every
  # partition. A full control ARN is passed through unchanged —
  # the resolved ARN keys the resource map either way, so moving a
  # configuration from ARNs to names changes no resource address.
  control_ou_pairs = flatten([
    for control in var.control_tower_controls : [
      for ou in control.organizational_units : {
        identifier = (
          startswith(control.control_identifier, "arn:")
          ? control.control_identifier
          : "${local.arn_prefix}:controltower:::control/${control.control_identifier}"
        )
        ou         = ou
        ou_arn     = contains(keys(var.ou_name_to_arn), ou) ? var.ou_name_to_arn[ou] : ou
        parameters = control.parameters
      }
    ]
  ])

}

# --- Control Tower Service Roles ---

resource "aws_iam_role" "ct_admin" {
  name = "AWSControlTowerAdmin"
  path = "/service-role/"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/control-tower/admin-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy_attachment" "ct_admin" {
  role       = aws_iam_role.ct_admin.name
  policy_arn = "${local.arn_prefix}:iam::aws:policy/service-role/AWSControlTowerServiceRolePolicy"
}

resource "aws_iam_role_policy" "ct_admin" {
  name = "AWSControlTowerAdminPolicy"
  role = aws_iam_role.ct_admin.id

  policy = jsonencode(jsondecode(file("${path.module}/../../configurations/policies/control-tower/admin-inline-policy.json")))
}

resource "aws_iam_role" "ct_cloudtrail" {
  name = "AWSControlTowerCloudTrailRole"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/control-tower/cloudtrail-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

# AWS replaced the inline policy with a managed policy (since LZ 3.3+)
resource "aws_iam_role_policy_attachment" "ct_cloudtrail" {
  role       = aws_iam_role.ct_cloudtrail.name
  policy_arn = "${local.arn_prefix}:iam::aws:policy/service-role/AWSControlTowerCloudTrailRolePolicy"
}

resource "aws_iam_role" "ct_stackset" {
  name = "AWSControlTowerStackSetRole"
  path = "/service-role/"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/control-tower/stackset-trust-policy.json", {
    arn_prefix            = local.arn_prefix
    management_account_id = local.management_account_id
    dns_suffix            = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "ct_stackset" {
  name = "AWSControlTowerStackSetRolePolicy"
  role = aws_iam_role.ct_stackset.id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/control-tower/stackset-inline-policy.json", {
    arn_prefix = local.arn_prefix
  })))
}

resource "aws_iam_role" "ct_config_aggregator" {
  name = "AWSControlTowerConfigAggregatorRoleForOrganizations"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/control-tower/config-aggregator-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy_attachment" "ct_config_aggregator" {
  role       = aws_iam_role.ct_config_aggregator.name
  policy_arn = "${local.arn_prefix}:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

# --- Wait for IAM propagation ---
# AWS IAM takes up to 30 seconds until new roles are globally available.
# Without this wait, CreateLandingZone fails with
# "could not assume the AWSControlTowerAdmin role".

resource "time_sleep" "wait_for_iam_propagation" {
  create_duration = "30s"

  depends_on = [
    aws_iam_role_policy_attachment.ct_admin,
    aws_iam_role_policy.ct_admin,
    aws_iam_role_policy_attachment.ct_cloudtrail,
    aws_iam_role_policy.ct_stackset,
    aws_iam_role_policy_attachment.ct_config_aggregator,
  ]
}

# --- Control Tower Landing Zone ---

resource "aws_controltower_landing_zone" "this" {
  version = var.landing_zone_version

  # The module builds the v4 manifest schema: no organization-structure
  # section (v4.0 dropped it), securityRoles with enabled + accountId.
  # var.landing_zone_version rejects anything below 4.x at plan time
  # because a 3.x manifest would need the section v4 dropped and
  # would otherwise fail at CreateLandingZone.
  manifest_json = jsonencode({
    governedRegions = var.governed_regions
    centralizedLogging = {
      accountId = var.log_archive_account_id
      configurations = {
        loggingBucket = {
          retentionDays = var.logging_retention_days
        }
        accessLoggingBucket = {
          retentionDays = var.access_logging_retention_days
        }
      }
      # The switch of the Control Tower organization trail: disabling it
      # turns off the centralized logging the landing zone manages.
      enabled = var.enable_organization_trail
    }
    securityRoles = {
      accountId = var.audit_account_id
      enabled   = true
    }
    accessManagement = {
      enabled = var.enable_identity_center
    }
    config = {
      accountId = var.audit_account_id
      enabled   = true
    }
    # The v4 manifest requires an explicit enabled flag for every service
    # integration (accessManagement, backup, centralizedLogging, config,
    # securityRoles) — no defaults are provided by the API. Coupling rule:
    # config.enabled = false would force securityRoles, accessManagement
    # and backup to false as well; the module keeps config enabled, so
    # backup switches freely via enable_backup_integration.
    backup = {
      enabled = var.enable_backup_integration
    }
  })

  depends_on = [time_sleep.wait_for_iam_propagation]

  timeouts {
    create = "120m"
    update = "120m"
    delete = "120m"
  }
}

# --- Control Tower Controls / Guardrails ---
# Creates aws_controltower_control resources for each control-OU combination.
# Control identifiers are ARNs, target identifiers are OU ARNs.

resource "aws_controltower_control" "this" {
  for_each = {
    for c in local.control_ou_pairs : "${c.identifier}-${c.ou}" => c
  }

  control_identifier = each.value.identifier
  target_identifier  = each.value.ou_arn

  # Control parameters, forwarded to the EnableControl API. Region-aware
  # controls (for example the region-deny control) refuse to deploy without
  # their parameters — the value is a JSON document string per API contract.
  dynamic "parameters" {
    for_each = each.value.parameters
    content {
      key   = parameters.value.key
      value = parameters.value.value
    }
  }

  depends_on = [aws_controltower_landing_zone.this]
}


# --- CT OU Auto-Enrollment Guidance ---
# The Terraform AWS provider does not support OU registration for CT governance
# as a native resource. This check block documents the manual workflow when
# auto_enroll_ous is non-empty.

check "ct_ou_auto_enrollment_guidance" {
  assert {
    condition = length(var.auto_enroll_ous) == 0
    error_message = join(" ", [
      "OUs specified for CT auto-enrollment: [${join(", ", var.auto_enroll_ous)}].",
      "The Terraform AWS provider does not support aws_controltower_organizational_unit_registration as a native resource.",
      "To register OUs for CT governance:",
      "(1) AWS Control Tower console → Organization → select OU → Register,",
      "(2) CLI: 'aws controltower register-organizational-unit --organizational-unit-id <ou-id>',",
      "(3) Once registered, CT controls configured via aws_controltower_control are applied to the OU.",
    ])
  }
}
