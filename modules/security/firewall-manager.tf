# =============================================================================
# AWS Firewall Manager Policies — Conditional (skip in aws-eusc partition)
# =============================================================================
# Firewall Manager is not available in the aws-eusc partition (AWS Services by
# Region, eusc-de-east-1; the AWS European Sovereign Cloud roadmap does not
# list it among the initial services). The policy
# map is emptied in aws-eusc, following the Macie pattern in macie.tf.

locals {
  fms_policy_map = local.is_eusc ? {} : { for p in var.fms_policies : p.name => p }
}

# Without this check the skip would be silent: configured fms_policies would
# look like they took effect. The check warns instead of failing (same
# convention as macie_partition_availability).
check "fms_partition_availability" {
  assert {
    condition     = !(length(var.fms_policies) > 0 && local.is_eusc)
    error_message = "fms_policies are configured but Firewall Manager is not available in the aws-eusc partition. All FMS policies are skipped in this deployment. Remove the fms_policies entries to suppress this warning."
  }
}

# PutPolicy is accepted only from a Firewall Manager administrator account.
# The module does not register one: AssociateAdminAccount is a one-time,
# organization-level decision taken from the management account (it also
# registers the account as Organizations delegated administrator for FMS), and
# its removal follows first-in-last-out across every administrator — not a
# resource to carry inside a module that is applied per stack. Without the
# registration every policy fails at apply with InvalidOperationException ("No
# default admin could be found"). Plan time cannot observe the registration
# (no provider data source; the Organizations delegated-administrator list
# also lists plain RegisterDelegatedAdministrator entries, such as the one the
# organization module itself creates for fms, so it would pass exactly when the
# apply still fails), so the precondition asks the operator to attest it. An
# operator who did the step gets a clean plan; one who did not fails at plan
# instead of at apply. The predecessor was a check that fired on every
# non-empty policy list — permanent noise no configuration could satisfy.
resource "aws_fms_policy" "this" {
  for_each = local.fms_policy_map

  name                  = each.value.name
  exclude_resource_tags = each.value.exclude_resource_tags
  remediation_enabled   = each.value.remediation_enabled
  resource_type_list    = each.value.resource_type_list

  security_service_policy_data {
    type = each.value.type
  }

  dynamic "include_map" {
    for_each = length(each.value.include_map) > 0 ? [1] : []
    content {
      account = each.value.include_map
    }
  }

  dynamic "exclude_map" {
    for_each = length(each.value.exclude_map) > 0 ? [1] : []
    content {
      account = each.value.exclude_map
    }
  }

  lifecycle {
    precondition {
      condition     = var.fms_admin_account_registered
      error_message = "fms_policies is configured but fms_admin_account_registered is false. aws_fms_policy can only be created by a Firewall Manager administrator account, and this module does not register one — without it the apply fails with InvalidOperationException (\"No default admin could be found\"). Register the administrator once from the organization's management account (aws fms associate-admin-account --admin-account <account-id>), make sure the account applying this module is a Firewall Manager administrator, then set fms_admin_account_registered = true. Or remove the fms_policies entries."
    }
  }
}

# =============================================================================
# FMS Notification Channel — provider limitation
# =============================================================================
# The AWS provider exposes no resource for the Firewall Manager notification
# channel (FMS PutNotificationChannel). The only FMS resources in the pinned
# provider are aws_fms_admin_account, aws_fms_policy and aws_fms_resource_set.
# Declaring a resource type the provider does not know aborts loading of the
# whole module for every configuration — a count guard does not help, because
# the resource type is resolved before count is evaluated. The intent is
# therefore surfaced as a provider limitation, the same convention the root
# management placeholders in main.tf use. var.fms_notification_sns_topic_arn
# and var.fms_notification_sns_role_name keep the intended values until a
# native resource becomes available.

check "fms_notification_channel_provider_limitation" {
  assert {
    condition     = !var.enable_fms_notification_channel
    error_message = "enable_fms_notification_channel is enabled, but the AWS Terraform provider exposes no resource for the Firewall Manager notification channel (PutNotificationChannel). fms_notification_sns_topic_arn and fms_notification_sns_role_name are therefore not applied — configure the notification channel in the FMS delegated admin account and monitor AWS provider releases (~> 6.x) for native resource support."
  }
}

check "fms_notification_requires_delegated_admin" {
  assert {
    condition = !var.enable_fms_notification_channel || (
      length(var.fms_policies) > 0 &&
      var.fms_notification_sns_topic_arn != "" &&
      var.fms_notification_sns_role_name != ""
    )
    error_message = "FMS notification channel is enabled but its prerequisites are incomplete. It requires configured fms_policies (which in turn require the out-of-band Firewall Manager administrator registration acknowledged by fms_admin_account_registered) and non-empty values for fms_notification_sns_topic_arn and fms_notification_sns_role_name."
  }
}

# =============================================================================
# Firewall Config S3 Bucket
# =============================================================================

resource "aws_s3_bucket" "firewall_config" {
  count  = var.enable_firewall_config_bucket ? 1 : 0
  bucket = var.firewall_config_bucket_name
}

resource "aws_s3_bucket_versioning" "firewall_config" {
  count  = var.enable_firewall_config_bucket ? 1 : 0
  bucket = aws_s3_bucket.firewall_config[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "firewall_config" {
  #checkov:skip=CKV2_AWS_67:default kms_master_key_id null selects the AWS-managed aws/s3 key, which AWS rotates itself; firewall_config_bucket_kms_key_arn is a caller-owned key whose rotation is set where that key is defined
  count  = var.enable_firewall_config_bucket ? 1 : 0
  bucket = aws_s3_bucket.firewall_config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.firewall_config_bucket_kms_key_arn != "" ? var.firewall_config_bucket_kms_key_arn : null
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "firewall_config" {
  count  = var.enable_firewall_config_bucket ? 1 : 0
  bucket = aws_s3_bucket.firewall_config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Removes fragments of incomplete multipart uploads after 7 days — cost
# hygiene without a retention decision: config objects and their versions
# are kept, their retention stays with the deployment.
resource "aws_s3_bucket_lifecycle_configuration" "firewall_config" {
  count  = var.enable_firewall_config_bucket ? 1 : 0
  bucket = aws_s3_bucket.firewall_config[0].id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_iam_role" "firewall_config_reader" {
  count = var.enable_firewall_config_bucket ? 1 : 0
  name  = "tlz-firewall-config-reader"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/firewall-config-reader-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_instance_profile" "firewall_config_reader" {
  count = var.enable_firewall_config_bucket ? 1 : 0
  name  = "tlz-firewall-config-reader"
  role  = aws_iam_role.firewall_config_reader[0].name
}

resource "aws_iam_role_policy" "firewall_config_reader_s3" {
  count = var.enable_firewall_config_bucket ? 1 : 0
  name  = "firewall-config-s3-read"
  role  = aws_iam_role.firewall_config_reader[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/firewall-config-reader-s3-policy.json", {
    bucket_arn = aws_s3_bucket.firewall_config[0].arn
  })))
}

resource "aws_iam_role_policy" "firewall_config_reader_kms" {
  count = var.enable_firewall_config_bucket && var.firewall_config_bucket_kms_key_arn != "" ? 1 : 0
  name  = "firewall-config-kms-decrypt"
  role  = aws_iam_role.firewall_config_reader[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/firewall-config-reader-kms-policy.json", {
    kms_key_arn = var.firewall_config_bucket_kms_key_arn
  })))
}
