# customizations/_template — Example Custom Module
# Copy this directory to create your own module:
#   cp -r customizations/_template customizations/my-module
#
# See docs/customizations.md for the full how-to guide.

data "aws_partition" "current" {}

locals {
  # ← Replace with your own resource map or derive from variables.
  # The region is part of the parameter path so that two installations in
  # different regions never collide on the same name.
  example_parameters = {
    "landing-zone-info" = "This parameter was created by a custom module in ${var.region}"
  }

  # ← Use this prefix whenever you build an ARN yourself — never write the
  # partition as a literal (see docs/multi-partition.md).
  arn_prefix = "arn:${data.aws_partition.current.partition}"

  # ← One parameter per landing zone account, so the example shows how to derive
  # resources from var.account_ids. Empty account_ids means no parameters here.
  example_account_parameters = {
    for name, id in var.account_ids : name => id
  }
}

# ← Replace this example resource with your own resources
resource "aws_ssm_parameter" "this" {
  #checkov:skip=CKV_AWS_337:type is the literal "String", which SSM does not KMS-encrypt; key_id applies only to SecureString (checkov 3.3.16 SSMParameterUsesCMK passes non-SecureString)
  for_each = local.example_parameters # ← Use for_each over a local map (not count)

  name  = "/custom/${var.region}/${each.key}" # ← Customize the parameter path
  type  = "String"
  value = each.value

  tags = var.default_tags # ← Always pass default_tags to every resource
}

# ← Second example: one parameter per account, holding the ARN of that account's
# landing zone deployment role. It shows both remaining conventions in one
# place — deriving resources from var.account_ids, and building an ARN from
# local.arn_prefix instead of a hardcoded partition.
resource "aws_ssm_parameter" "account_role_arn" {
  #checkov:skip=CKV_AWS_337:type is the literal "String", which SSM does not KMS-encrypt; key_id applies only to SecureString (checkov 3.3.16 SSMParameterUsesCMK passes non-SecureString)
  for_each = local.example_account_parameters

  name  = "/custom/${var.region}/accounts/${each.key}/deployment-role-arn"
  type  = "String"
  value = "${local.arn_prefix}:iam::${each.value}:role/LZTDeploymentRole"

  tags = var.default_tags
}
