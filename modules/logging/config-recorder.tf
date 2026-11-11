# =============================================================================
# AWS Config Recorder in Management Account
# =============================================================================

# The recorder references the service-linked role AWSServiceRoleForConfig and
# does not create it. The role must exist in the account before the first
# apply; create it once with
# `aws iam create-service-linked-role --aws-service-name config.<dns_suffix>`.

# One recorder per account and region: AWS Config rejects a second
# PutConfigurationRecorder with MaxNumberOfConfigurationRecordersExceeded.
# When another owner holds the slot, manage_config_recorder = false skips the
# recorder, its delivery channel and its status — and only those three. The
# organization aggregator below reads member-account recorders through the
# aggregator role and does not depend on a local recorder, so it stays.
resource "aws_config_configuration_recorder" "this" {
  count = var.manage_config_recorder ? 1 : 0

  name     = "tlz-config-recorder"
  role_arn = var.use_config_service_linked_role ? "${local.arn_prefix}:iam::${local.account_id}:role/aws-service-role/config.${local.dns_suffix}/AWSServiceRoleForConfig" : var.config_recorder_custom_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# The role pair configures the recorder; with the recorder unmanaged there is
# nothing for the ARN to be missing from, so the check is silent then.
check "config_custom_role_required" {
  assert {
    condition     = !var.manage_config_recorder || var.use_config_service_linked_role || var.config_recorder_custom_role_arn != ""
    error_message = "config_recorder_custom_role_arn must be provided when use_config_service_linked_role is false."
  }
}

resource "aws_config_delivery_channel" "this" {
  count = var.manage_config_recorder ? 1 : 0

  name           = "tlz-config-delivery"
  s3_bucket_name = aws_s3_bucket.central_logs.id
  s3_key_prefix  = "config"

  # PutDeliveryChannel VERIFIES the bucket policy synchronously: AWS Config
  # performs its own s3:GetBucketAcl / PutObject check against the target
  # bucket during the API call and rejects it with
  # "InsufficientDeliveryPolicyException: Insufficient delivery policy to s3
  # bucket" when the AWSConfigBucketPermissionsCheck /
  # AWSConfigBucketExistenceCheck / AWSConfigDelivery grants are not in place
  # yet. Referencing aws_s3_bucket.central_logs.id orders this after the BUCKET
  # but not after its POLICY, which is a separate resource, so a fresh apply is
  # free to call PutDeliveryChannel first. This is NOT a redundant edge — do not
  # tidy it away. Same reason and same target as the two org/account trails
  # (cloudtrail.tf), whose CreateTrail validates the same policy the same way.
  #
  # depends_on alone is sufficient here: the Config grants come unconditionally
  # from the in-repo policy template, so there is no variable that could point
  # the channel at a bucket the policy does not grant. The one way to remove the
  # grants is central_log_bucket_policies.s3_override, which is already gated
  # behind the explicit allow_bucket_policy_overrides confirmation.
  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.central_logs,
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = var.manage_config_recorder ? 1 : 0

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# --- Organization-wide Config Aggregator ---
# Independent of manage_config_recorder: the aggregator collects from the
# member accounts' recorders via aws_iam_role.config_aggregator and needs no
# recorder of its own in this account.
#
# Both names are variables defaulting to the production names (see variables.tf,
# "Organization Config aggregator names"). PutConfigurationAggregator is an
# UPSERT — under the fixed name a live apply-test would adopt the live
# organization-wide aggregator and delete it on teardown — so a live test must
# set a test-scoped name. Aggregators are not an account singleton (the live
# account carries a legacy one beside the tlz- one), which is what makes the
# name a real fix rather than a count gate.

resource "aws_config_configuration_aggregator" "org" {
  name = var.config_aggregator_name

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator.arn
  }
}

resource "aws_iam_role" "config_aggregator" {
  name = var.config_aggregator_role_name

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/config-aggregator-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy_attachment" "config_aggregator" {
  role       = aws_iam_role.config_aggregator.name
  policy_arn = "${local.arn_prefix}:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}
