# Pipeline Module — Shared resources (all pipeline types)
# Creates the Pipeline_Role in the Deployment Account with sts:AssumeRole
# permissions scoped to deployment_role_arns only.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  arn_prefix = "arn:${local.partition}"
  # DNS suffix of service principals — derived from the partition, so trust
  # policies name the principal that exists in the partition the module runs
  # in.
  dns_suffix = data.aws_partition.current.dns_suffix
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  # EU Sovereign Cloud detection: CodePipeline and CodeBuild are not available
  # in aws-eusc (AWS Services by Region, eusc-de-east-1). The codepipeline variant is gated on this value; the ecs and
  # external variants are unaffected.
  is_eusc = local.partition == "aws-eusc"
}

# --- IAM Role: Pipeline_Role (shared across all pipeline types) ---

resource "aws_iam_role" "pipeline" {
  name = "TLZPipelineRole"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/pipeline/role-trust-policy.json", {
    pipeline_type = var.pipeline_type
    arn_prefix    = local.arn_prefix
    account_id    = local.account_id
    dns_suffix    = local.dns_suffix
  })))
}

# --- IAM propagation delay ---

resource "time_sleep" "pipeline_role_propagation" {
  depends_on      = [aws_iam_role.pipeline]
  create_duration = "30s"
}

# --- Pipeline_Role policy: sts:AssumeRole on deployment_role_arns ONLY ---
# No direct Management Account permissions (Organizations, IAM, etc.)

resource "aws_iam_role_policy" "pipeline_assume" {
  name = "TLZPipelineRole-assume-deployment-roles"
  role = aws_iam_role.pipeline.id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/pipeline/role-assume-policy.json", {
    deployment_role_arns_json = jsonencode(values(var.deployment_role_arns))
  })))
}
