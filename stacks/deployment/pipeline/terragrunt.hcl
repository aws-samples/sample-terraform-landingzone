# Pipeline — deploys CI/CD pipeline infrastructure in the Deployment Account
# Excluded when enable_pipeline = false

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Audience of the external CI OIDC provider. The audience is an STS endpoint
  # name and therefore carries the DNS suffix of the partition, so it is derived
  # here instead of being carried as a configuration key — same
  # partition-to-suffix mapping as
  # stacks/management/config-recorder-members/terragrunt.hcl.
  sts_dns_suffix = {
    "aws"      = "amazonaws.com"
    "aws-eusc" = "amazonaws.eu"
  }
  external_ci_audiences = ["sts.${local.sts_dns_suffix[local.common.locals.partition]}"]
}

exclude {
  if      = !local.common.locals.enable_pipeline
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/pipeline"
}

dependency "bootstrap" {
  config_path  = "../bootstrap"
  skip_outputs = true
}

# The mock role ARN has to satisfy the validation of
# modules/pipeline.deployment_role_arns: the empty string fails it, so validate
# and plan would abort in exactly the situation mock outputs exist for. The
# partition comes from the configuration, not from a literal.
dependency "deployment_role" {
  config_path = "../../management/deployment-role"
  mock_outputs = {
    role_arn = "arn:${local.common.locals.partition}:iam::000000000000:role/mock-deployment-role"
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  pipeline_type               = local.common.locals.pipeline_type
  repository_name             = local.common.locals.repository_name
  deployment_role_arns        = { management = dependency.deployment_role.outputs.role_arn }
  approval_notification_email = local.common.locals.approval_notification_email

  # The profile Terragrunt writes into every unit's provider.tf and backend.tf.
  # The build writes a profile of this name into its container before the
  # first terragrunt command (it assumes the management deployment role above),
  # so the pipeline runs the stacks exactly as an operator with that profile.
  aws_profile = local.common.locals.aws_profile

  # State-change notifications: EventBridge rules on the selected pipeline
  # execution states, published to the approval topic. Off by default; the
  # state list falls back to the module default (all state changes).
  enable_pipeline_notifications = try(local.common.locals.enable_pipeline_notifications, false)
  pipeline_notification_states  = try(local.common.locals.pipeline_notification_states, ["STARTED", "SUCCEEDED", "FAILED", "SUPERSEDED", "CANCELED"])

  # Pipeline source. Both values gate the CodePipeline variant: while
  # source_connection_arn is empty the module creates none of its resources and
  # reports that in the plan (check "codepipeline_requires_source_connection").
  source_connection_arn = local.compliance.locals.source_connection_arn
  branch_name           = local.compliance.locals.pipeline_branch_name

  # External CI over OIDC. The three values belong together — a provider
  # without thumbprint and audience federates nothing.
  external_ci_provider   = local.common.locals.external_ci_provider
  external_ci_thumbprint = local.compliance.locals.external_ci_thumbprint
  external_ci_audiences  = local.external_ci_audiences

  # Customer-managed key for the build output of both CodeBuild projects.
  # Empty (the loader default) keeps alias/aws/s3 and the plan.
  codebuild_encryption_kms_key_arn = local.compliance.locals.codebuild_encryption_kms_key_arn
}
