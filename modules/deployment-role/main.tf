# Deployment Role Module — creates TLZDeploymentRole in the Management Account
# Trust policy allows the Deployment Account to assume this role for TLZ operations.

data "aws_partition" "current" {}

locals {
  partition                = data.aws_partition.current.partition
  arn_prefix               = "arn:${local.partition}"
  has_permissions_boundary = var.permissions_boundary_arn != ""

  # Two documents, one flag. The narrow document enumerates the
  # security-service and Identity Center actions the modules call; the default
  # document keeps the broad `service:*` grants until the flag is flipped.
  inline_policy_file = var.narrow_grants ? "role-inline-policy-narrow.json" : "role-inline-policy.json"
}

# --- IAM Role: TLZDeploymentRole ---

resource "aws_iam_role" "deployment" {
  name = var.role_name

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/deployment/role-trust-policy.json", {
    arn_prefix            = local.arn_prefix
    deployment_account_id = var.deployment_account_id
  })))

  permissions_boundary = local.has_permissions_boundary ? var.permissions_boundary_arn : null
}

# --- IAM propagation delay ---

resource "time_sleep" "iam_propagation" {
  depends_on      = [aws_iam_role.deployment]
  create_duration = "30s"
}

# --- Managed policy: scoped to Landing Zone operations ---

resource "aws_iam_role_policy" "deployment" {
  name = "${var.role_name}-policy"
  role = aws_iam_role.deployment.id

  policy = jsonencode(jsondecode(file("${path.module}/../../configurations/policies/deployment/${local.inline_policy_file}")))
}
