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

  # The profile the build writes into the container's ~/.aws/config before the
  # first terragrunt command (codepipeline.tf, ecs.tf): a named profile of the
  # configured name that assumes the management deployment role with the
  # container's own credentials, so Terragrunt's provider.tf and backend.tf --
  # which name exactly this profile -- resolve in the pipeline as they do on an
  # operator's machine. lookup(), not an index: the validation on
  # deployment_role_arns names the missing key; this expression must not fail
  # before it. One line per shell argument, each single-quoted, so the values
  # are never read as a printf format.
  pipeline_management_role_arn = lookup(var.deployment_role_arns, "management", "")
  pipeline_profile_command     = "mkdir -p ~/.aws && printf '%s\\n' '[profile ${var.aws_profile}]' 'role_arn = ${local.pipeline_management_role_arn}' 'credential_source = EcsContainer' 'role_session_name = tlz-pipeline' 'region = ${local.region}' > ~/.aws/config"
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
