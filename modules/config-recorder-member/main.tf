# Config Recorder for a single member account
# Called per account with the respective cross-account provider.
# Creates: Config Recorder, Delivery Channel, Recorder Status.
# Prerequisite: the service-linked role AWSServiceRoleForConfig must already
# exist in the target account (see README) — the recorder references its
# well-known path but this module does not create it.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  arn_prefix = "arn:${data.aws_partition.current.partition}"
  dns_suffix = data.aws_partition.current.dns_suffix
  account_id = data.aws_caller_identity.current.account_id
}

resource "aws_config_configuration_recorder" "this" {
  name     = "tlz-config-recorder"
  role_arn = "${local.arn_prefix}:iam::${local.account_id}:role/aws-service-role/config.${local.dns_suffix}/AWSServiceRoleForConfig"

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "tlz-config-delivery"
  s3_bucket_name = var.central_log_bucket_name
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}
