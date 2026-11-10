# =============================================================================
# Pipeline Module Tests (modules/pipeline)
# =============================================================================
# Coverage:
#   - Toggle-Off:   inactive pipeline variants create zero resources
#   - Default:      minimal valid input -> codepipeline variant (default)
#   - Custom:       ecs variant and external CI variant with custom values
#   - Validation:   pipeline_type, repository_name, branch_name,
#                   deployment_role_arns, approval_notification_email,
#                   external_ci_provider, source_connection_arn,
#                   ecs_subnet_ids, ecs_security_group_ids (incl. the refusal
#                   of an ecs variant that names no group and does not set
#                   ecs_use_default_security_group)
#
# CONVENTION for the ecs scenarios: since the module
# refuses pipeline_type = "ecs" that names no security group unless
# ecs_use_default_security_group is set, every ecs run whose subject is
# something else names one group explicitly —
# ecs_security_group_ids = ["sg-0123456789abcdef0"] — instead of inheriting it
# from the file-level variables block. Deliberately NOT inherited: a group in
# that block would be a blanket waiver that every future ecs run picks up
# silently, and it would leave the DEFAULT of ecs_security_group_ids exercised
# by no run at all. With the line per run, a new ecs scenario that forgets the
# network is refused with the module's own message, and the two runs whose
# subject IS this law — ecs_acknowledged_default_group_names_no_security_group_
# and_no_public_ip and ecs_variant_without_security_group_and_without_
# acknowledgement_rejected — are the only ones that read the variable's
# default.
#   - Wiring:       source action and trigger of the codepipeline variant use
#                   one and the same attachment mechanism
#   - Wiring:       the ecs variant's Fargate target carries a network
#                   configuration (PutTargets answers 400 without one) and
#                   refuses to plan without a subnet
#   - Fact-check:   on the acknowledged path (ecs_use_default_security_group,
#                   no group named) the module READS the default group of the
#                   subnets' VPC and the EventBridge target refuses without an
#                   egress rule covering HTTPS — four refused worlds (one of
#                   them two VPCs with the rule in only one: the law holds per
#                   VPC),
#                   two passing ones, and the named-group path that reads
#                   nothing. Mocked data sources per run.
#
# Note: this module declares no `enable_*` variable. `pipeline_type` is the
# module's creation toggle: it selects exactly one of three mutually exclusive
# variants (codepipeline, ecs, external). The mandatory Toggle-Off scenario is
# therefore expressed as "the two non-selected variants create zero resources".
#
# Providers used directly by the module: aws (no aliases) and time.
# Computed attributes are never asserted on — only counts and input-derived
# attributes, so the plan stays deterministic under mocked providers.

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      name   = "eu-central-1"
      region = "eu-central-1"
    }
  }
}

mock_provider "time" {}

variables {
  repository_name       = "my-org/landing-zone"
  source_connection_arn = "arn:aws:codeconnections:eu-central-1:123456789012:connection/11111111-2222-3333-4444-555555555555"
  deployment_role_arns = {
    management = "arn:aws:iam::111111111111:role/TLZDeploymentRole"
    audit      = "arn:aws:iam::222222222222:role/TLZDeploymentRole"
  }
  # The ecs variant's Fargate task runs in awsvpc network mode and the module
  # refuses pipeline_type = "ecs" without a subnet, so every ecs scenario
  # inherits one from here; the other two variants ignore it. The refusal
  # itself is proven by ecs_variant_without_subnets_rejected, which clears it.
  ecs_subnet_ids = ["subnet-0a1b2c3d4e5f60718"]
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off — external variant creates no codepipeline/ecs resources
# -----------------------------------------------------------------------------
run "toggle_off_codepipeline_and_ecs_variants" {
  command = plan

  variables {
    pipeline_type          = "external"
    external_ci_provider   = "github"
    external_ci_thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"
  }

  # CodePipeline variant must be completely absent
  assert {
    condition     = length(aws_codepipeline.this) == 0
    error_message = "No CodePipeline must be created when pipeline_type is not codepipeline."
  }

  assert {
    condition     = length(aws_s3_bucket.artifacts) == 0
    error_message = "No artifact bucket must be created when pipeline_type is not codepipeline."
  }

  assert {
    condition = alltrue([
      length(aws_s3_bucket_versioning.artifacts) == 0,
      length(aws_s3_bucket_server_side_encryption_configuration.artifacts) == 0,
      length(aws_s3_bucket_public_access_block.artifacts) == 0,
      length(aws_s3_bucket_lifecycle_configuration.artifacts) == 0,
    ])
    error_message = "No artifact bucket settings must be created when pipeline_type is not codepipeline."
  }

  assert {
    condition = alltrue([
      length(aws_codebuild_project.plan) == 0,
      length(aws_codebuild_project.apply) == 0,
    ])
    error_message = "No CodeBuild projects must be created when pipeline_type is not codepipeline."
  }

  assert {
    condition = alltrue([
      length(aws_iam_role.codepipeline) == 0,
      length(aws_iam_role.codebuild) == 0,
    ])
    error_message = "No CodePipeline IAM roles must be created when pipeline_type is not codepipeline."
  }

  assert {
    condition     = length(aws_sns_topic.approval) == 0
    error_message = "No CodePipeline notification resources must be created when pipeline_type is not codepipeline."
  }

  # ECS variant must be completely absent
  assert {
    condition = alltrue([
      length(aws_ecs_cluster.pipeline) == 0,
      length(aws_ecs_task_definition.pipeline) == 0,
      length(aws_cloudwatch_log_group.pipeline) == 0,
      length(aws_kms_key.ecs_logs) == 0,
      length(aws_kms_alias.ecs_logs) == 0,
    ])
    error_message = "No ECS resources must be created when pipeline_type is not ecs."
  }

  assert {
    condition = alltrue([
      length(aws_iam_role.ecs_execution) == 0,
      length(aws_iam_role.ecs_task) == 0,
      length(aws_iam_role.eventbridge_ecs) == 0,
    ])
    error_message = "No ECS IAM roles must be created when pipeline_type is not ecs."
  }

  assert {
    condition = alltrue([
      length(aws_sns_topic.ecs_approval) == 0,
      length(aws_cloudwatch_event_rule.ecs_trigger) == 0,
    ])
    error_message = "No ECS notification or trigger resources must be created when pipeline_type is not ecs."
  }

  # Shared resources are always created
  assert {
    condition     = aws_iam_role.pipeline.name == "TLZPipelineRole"
    error_message = "The shared pipeline role must be created for every pipeline_type."
  }

  # External variant is active
  assert {
    condition     = length(aws_iam_openid_connect_provider.external_ci) == 1
    error_message = "One OIDC provider must be created when pipeline_type is external."
  }

  assert {
    condition     = length(aws_iam_role.oidc) == 1
    error_message = "One OIDC role must be created when pipeline_type is external."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — codepipeline variant, branch main
# -----------------------------------------------------------------------------
run "default_configuration_codepipeline" {
  command = plan

  assert {
    condition     = var.pipeline_type == "codepipeline"
    error_message = "pipeline_type must default to codepipeline."
  }

  assert {
    condition     = var.branch_name == "main"
    error_message = "branch_name must default to main."
  }

  assert {
    condition     = aws_iam_role.pipeline.name == "TLZPipelineRole"
    error_message = "The shared pipeline role must be named TLZPipelineRole."
  }

  assert {
    condition     = length(aws_codepipeline.this) == 1
    error_message = "One CodePipeline must be created with the default pipeline_type."
  }

  assert {
    condition     = aws_codepipeline.this[0].name == "tlz-deployment-pipeline"
    error_message = "CodePipeline name must be tlz-deployment-pipeline."
  }

  # --- Source and trigger -----------------------------------------------------
  # The source action needs the configured ConnectionArn, and a connection
  # source produces no CodeCommit EventBridge event. Source and trigger must
  # describe the same mechanism.
  assert {
    condition     = aws_codepipeline.this[0].stage[0].action[0].configuration["ConnectionArn"] == var.source_connection_arn
    error_message = "The source action must use the configured connection ARN, never an empty string."
  }

  assert {
    condition     = aws_codepipeline.this[0].stage[0].action[0].configuration["ConnectionArn"] != ""
    error_message = "The source action ConnectionArn must not be empty — CodePipeline rejects the pipeline."
  }

  assert {
    condition     = aws_codepipeline.this[0].stage[0].action[0].configuration["DetectChanges"] == "true"
    error_message = "Change detection must run through the connection, since no EventBridge rule triggers this variant."
  }

  assert {
    condition     = aws_codepipeline.this[0].stage[0].action[0].configuration["BranchName"] == var.branch_name
    error_message = "The source action must watch the configured branch."
  }

  # --- end source and trigger -------------------------------------------------

  assert {
    condition = alltrue([
      length(aws_s3_bucket.artifacts) == 1,
      length(aws_s3_bucket_versioning.artifacts) == 1,
      length(aws_s3_bucket_server_side_encryption_configuration.artifacts) == 1,
      length(aws_s3_bucket_public_access_block.artifacts) == 1,
      length(aws_s3_bucket_lifecycle_configuration.artifacts) == 1,
    ])
    error_message = "The artifact bucket and all its settings must be created for the codepipeline variant."
  }

  # The lifecycle rule removes incomplete multipart uploads; artifact
  # retention itself stays with the deployment.
  assert {
    condition = alltrue([
      aws_s3_bucket_lifecycle_configuration.artifacts[0].rule[0].status == "Enabled",
      aws_s3_bucket_lifecycle_configuration.artifacts[0].rule[0].abort_incomplete_multipart_upload[0].days_after_initiation == 7,
    ])
    error_message = "The artifact bucket lifecycle must abort incomplete multipart uploads after 7 days."
  }

  assert {
    condition     = aws_s3_bucket.artifacts[0].bucket == "tlz-pipeline-artifacts-123456789012-eu-central-1"
    error_message = "The artifact bucket name must include account id and region."
  }

  assert {
    condition = alltrue([
      length(aws_codebuild_project.plan) == 1,
      length(aws_codebuild_project.apply) == 1,
    ])
    error_message = "Both CodeBuild projects must be created for the codepipeline variant."
  }

  # Both CodeBuild projects must declare their log destination explicitly instead of
  # relying on the implicit service default.
  assert {
    condition = alltrue([
      length(aws_codebuild_project.plan[0].logs_config) == 1,
      aws_codebuild_project.plan[0].logs_config[0].cloudwatch_logs[0].status == "ENABLED",
      length(aws_codebuild_project.apply[0].logs_config) == 1,
      aws_codebuild_project.apply[0].logs_config[0].cloudwatch_logs[0].status == "ENABLED",
    ])
    error_message = "Both CodeBuild projects must carry an explicit logs_config with CloudWatch logging enabled."
  }

  assert {
    condition     = length(aws_sns_topic.approval) == 1
    error_message = "The approval topic must be created for the codepipeline variant."
  }

  # No email subscription without an approval address
  assert {
    condition     = length(aws_sns_topic_subscription.approval_email) == 0
    error_message = "No email subscription must be created when approval_notification_email is empty."
  }

  # Inactive variants
  assert {
    condition = alltrue([
      length(aws_ecs_cluster.pipeline) == 0,
      length(aws_iam_openid_connect_provider.external_ci) == 0,
      length(aws_iam_role.oidc) == 0,
    ])
    error_message = "The ecs and external variants must be inactive with the default pipeline_type."
  }

  assert {
    condition     = output.oidc_role_arn == ""
    error_message = "oidc_role_arn output must be empty when pipeline_type is not external."
  }

  assert {
    condition     = output.pipeline_role_name == "TLZPipelineRole"
    error_message = "pipeline_role_name output must expose the shared role name."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3a: Custom configuration — ecs variant with approval email
# -----------------------------------------------------------------------------
run "custom_configuration_ecs_variant" {
  command = plan

  variables {
    pipeline_type               = "ecs"
    repository_name             = "landing-zone"
    source_connection_arn       = ""
    branch_name                 = "release"
    approval_notification_email = "platform@example.com"
    ecs_security_group_ids      = ["sg-0123456789abcdef0"]
  }

  assert {
    condition     = length(aws_ecs_cluster.pipeline) == 1
    error_message = "One ECS cluster must be created for the ecs variant."
  }

  assert {
    condition     = aws_ecs_cluster.pipeline[0].name == "tlz-pipeline"
    error_message = "ECS cluster name must be tlz-pipeline."
  }

  assert {
    condition     = aws_ecs_task_definition.pipeline[0].family == "tlz-pipeline"
    error_message = "ECS task definition family must be tlz-pipeline."
  }

  assert {
    condition = alltrue([
      length(aws_iam_role.ecs_execution) == 1,
      length(aws_iam_role.ecs_task) == 1,
      length(aws_iam_role_policy_attachment.ecs_execution) == 1,
    ])
    error_message = "ECS execution and task roles must be created for the ecs variant."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.pipeline) == 1
    error_message = "The ECS log group must be created for the ecs variant."
  }

  # Approval email creates the subscription
  assert {
    condition     = length(aws_sns_topic_subscription.ecs_approval_email) == 1
    error_message = "An email subscription must be created when approval_notification_email is set."
  }

  assert {
    condition     = aws_sns_topic_subscription.ecs_approval_email[0].endpoint == "platform@example.com"
    error_message = "The email subscription endpoint must match approval_notification_email."
  }

  # Custom branch reaches the EventBridge pattern
  assert {
    condition     = strcontains(aws_cloudwatch_event_rule.ecs_trigger[0].event_pattern, "release")
    error_message = "The EventBridge event pattern must reference the custom branch_name."
  }

  # The trigger follows the configured source: the pattern is scoped to the
  # CodeCommit repository named by repository_name (partition, region and
  # account from the provider data), not to every repository in the account.
  assert {
    condition     = contains(jsondecode(aws_cloudwatch_event_rule.ecs_trigger[0].event_pattern).resources, "arn:aws:codecommit:eu-central-1:123456789012:landing-zone")
    error_message = "The ECS trigger must be scoped to the CodeCommit repository ARN built from repository_name."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.ecs_trigger[0].event_pattern).source == ["aws.codecommit"]
    error_message = "The ECS trigger listens to CodeCommit events — the only source model of this variant."
  }

  # Inactive variants
  assert {
    condition = alltrue([
      length(aws_codepipeline.this) == 0,
      length(aws_s3_bucket.artifacts) == 0,
      length(aws_iam_role.oidc) == 0,
    ])
    error_message = "The codepipeline and external variants must be inactive for the ecs variant."
  }

  assert {
    condition     = output.oidc_role_arn == ""
    error_message = "oidc_role_arn output must be empty when pipeline_type is not external."
  }
}

# -----------------------------------------------------------------------------
# The ecs variant's log group carries a customer-managed KMS key and a
# variable, non-hardcoded retention. checkov never sees
# aws_cloudwatch_log_group.pipeline (count = 0 with the default pipeline_type),
# so `make scan` cannot catch a missing key or a hardcoded retention here.
# Toggle-off is already covered by toggle_off_codepipeline_and_ecs_
# variants (aws_kms_key.ecs_logs is asserted absent below too); this run pins
# the ecs-selected shape the toggle-off run cannot reach.
# -----------------------------------------------------------------------------
run "ecs_log_group_kms_key_and_retention" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  # The log group's kms_key_id is asserted against the key's own arn below,
  # and a KMS key's arn is not known at plan time; the plan-time override
  # pins it so the comparison becomes assertable (same technique as
  # codebuild_ssm_statement_covers_published_prefix above).
  override_resource {
    target          = aws_kms_key.ecs_logs[0]
    override_during = plan
    values = {
      arn = "arn:aws:kms:eu-central-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    }
  }

  assert {
    condition     = length(aws_kms_key.ecs_logs) == 1 && length(aws_kms_alias.ecs_logs) == 1
    error_message = "The ecs variant must create its own KMS key and alias for the log group, count-gated on pipeline_type == \"ecs\" so an unchanged deployment creates and pays for neither."
  }

  assert {
    condition     = aws_kms_key.ecs_logs[0].enable_key_rotation == true && aws_kms_key.ecs_logs[0].deletion_window_in_days == 30
    error_message = "The ECS log group's KMS key must rotate and use the module's standard 30-day deletion window."
  }

  assert {
    condition     = aws_cloudwatch_log_group.pipeline[0].kms_key_id == aws_kms_key.ecs_logs[0].arn
    error_message = "The ECS log group must be encrypted with the module's own KMS key, not left unencrypted."
  }

  assert {
    condition     = var.ecs_log_retention_in_days == 365
    error_message = "ecs_log_retention_in_days must default to 365 (CKV_AWS_338)."
  }

  assert {
    condition     = aws_cloudwatch_log_group.pipeline[0].retention_in_days == var.ecs_log_retention_in_days
    error_message = "The log group's retention must follow the variable, not a hardcoded literal."
  }
}

run "ecs_log_group_retention_reaches_the_variable" {
  command = plan

  variables {
    pipeline_type             = "ecs"
    repository_name           = "landing-zone"
    source_connection_arn     = ""
    ecs_security_group_ids    = ["sg-0123456789abcdef0"]
    ecs_log_retention_in_days = 0
  }

  assert {
    condition     = aws_cloudwatch_log_group.pipeline[0].retention_in_days == 0
    error_message = "ecs_log_retention_in_days = 0 (never expire) must reach the log group unchanged."
  }
}

run "ecs_log_retention_in_days_rejects_invalid_value" {
  command = plan

  variables {
    pipeline_type             = "ecs"
    repository_name           = "landing-zone"
    source_connection_arn     = ""
    ecs_security_group_ids    = ["sg-0123456789abcdef0"]
    ecs_log_retention_in_days = 91
  }

  expect_failures = [var.ecs_log_retention_in_days]
}

# -----------------------------------------------------------------------------
# Scenario 3b: Custom configuration — external variant, gitlab, custom audience
#
# Uses `command = apply` (against mock providers, no AWS calls) because the
# generated trust policy embeds the OIDC provider ARN and is therefore unknown
# during the plan phase.
# -----------------------------------------------------------------------------
run "custom_configuration_external_gitlab" {
  command = apply

  variables {
    pipeline_type          = "external"
    external_ci_provider   = "gitlab"
    external_ci_thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"
    external_ci_audiences  = ["https://gitlab.com", "sts.amazonaws.com"]
    branch_name            = "trunk"
  }

  assert {
    condition     = aws_iam_openid_connect_provider.external_ci[0].url == "https://gitlab.com"
    error_message = "The OIDC provider URL must match the gitlab provider."
  }

  assert {
    condition     = length(aws_iam_openid_connect_provider.external_ci[0].client_id_list) == 2
    error_message = "The OIDC provider must carry both configured audiences."
  }

  assert {
    condition     = length(aws_iam_openid_connect_provider.external_ci[0].thumbprint_list) == 1
    error_message = "The OIDC provider must carry the configured thumbprint."
  }

  assert {
    condition     = aws_iam_role.oidc[0].name == "TLZExternalCIRole"
    error_message = "The OIDC role must be named TLZExternalCIRole."
  }

  # The decoded document, not a substring: a `...trunk*` subject or a second
  # statement would keep a substring check green.
  assert {
    condition = alltrue([
      length(jsondecode(aws_iam_role.oidc[0].assume_role_policy).Statement) == 1,
      jsondecode(aws_iam_role.oidc[0].assume_role_policy).Statement[0].Condition.StringLike == {
        "gitlab.com:sub" = "project_path:my-org/landing-zone:ref_type:branch:ref:trunk"
      },
    ])
    error_message = "The gitlab trust policy must hold one statement whose subject is exactly the configured repository and branch."
  }

  assert {
    condition     = length(aws_iam_role_policy.oidc_assume) == 1
    error_message = "The OIDC role policy must be created for the external variant."
  }

  # The external CI role must read the discovery parameters under /tlz/*
  assert {
    condition     = strcontains(aws_iam_role_policy.oidc_assume[0].policy, "parameter/tlz/*")
    error_message = "The external CI SSM statement must cover the published parameter prefix /tlz/*."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.oidc_assume[0].policy, "parameter/lzt/")
    error_message = "The external CI SSM statement must not grant the stale /lzt/* prefix — no parameter is published there."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3c: Custom configuration — external variant without thumbprint
# -----------------------------------------------------------------------------
run "custom_configuration_external_without_thumbprint" {
  command = plan

  variables {
    pipeline_type        = "external"
    external_ci_provider = "github"
  }

  assert {
    condition     = length(aws_iam_openid_connect_provider.external_ci[0].thumbprint_list) == 0
    error_message = "The thumbprint list must stay empty when no thumbprint is configured."
  }

  assert {
    condition     = aws_iam_openid_connect_provider.external_ci[0].url == "https://token.actions.githubusercontent.com"
    error_message = "The OIDC provider URL must match the github provider."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3e: Custom configuration — the three OIDC values as the stack
# delivers them
#
# stacks/deployment/pipeline passes external_ci_provider, external_ci_thumbprint
# and external_ci_audiences together; the audience is derived from the partition
# in the stack, so in partition `aws` it is sts.amazonaws.com. This scenario
# asserts that the audience reaches both places it has to reach: the audience
# list of the OIDC provider and the `:aud` condition of the role trust policy.
# The github subject form is asserted here — scenario 3b covers gitlab.
#
# Uses `command = apply` for the same reason as scenario 3b: the trust policy
# embeds the provider ARN and is unknown during plan.
# -----------------------------------------------------------------------------
run "custom_configuration_external_github_all_oidc_inputs" {
  command = apply

  variables {
    pipeline_type          = "external"
    external_ci_provider   = "github"
    external_ci_thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"
    external_ci_audiences  = ["sts.amazonaws.com"]
    branch_name            = "release"
  }

  assert {
    condition     = aws_iam_openid_connect_provider.external_ci[0].url == "https://token.actions.githubusercontent.com"
    error_message = "The OIDC provider URL must match the github provider."
  }

  assert {
    condition = alltrue([
      length(aws_iam_openid_connect_provider.external_ci[0].client_id_list) == 1,
      contains(aws_iam_openid_connect_provider.external_ci[0].client_id_list, "sts.amazonaws.com"),
    ])
    error_message = "The configured audience must be the only audience of the OIDC provider."
  }

  assert {
    condition = alltrue([
      length(aws_iam_openid_connect_provider.external_ci[0].thumbprint_list) == 1,
      contains(aws_iam_openid_connect_provider.external_ci[0].thumbprint_list, "6938fd4d98bab03faadb97b34396831e3780aea1"),
    ])
    error_message = "The configured thumbprint must reach the OIDC provider."
  }

  assert {
    condition     = strcontains(aws_iam_role.oidc[0].assume_role_policy, "token.actions.githubusercontent.com:aud")
    error_message = "The trust policy must bind the audience condition to the github provider host."
  }

  assert {
    condition     = strcontains(aws_iam_role.oidc[0].assume_role_policy, "sts.amazonaws.com")
    error_message = "The configured audience must reach the :aud condition of the trust policy."
  }

  # The decoded document, not a substring: a `...release*` subject or a
  # second statement would keep a substring check green.
  assert {
    condition = alltrue([
      length(jsondecode(aws_iam_role.oidc[0].assume_role_policy).Statement) == 1,
      jsondecode(aws_iam_role.oidc[0].assume_role_policy).Statement[0].Condition.StringLike == {
        "token.actions.githubusercontent.com:sub" = "repo:my-org/landing-zone:ref:refs/heads/release"
      },
    ])
    error_message = "The github trust policy must hold one statement whose subject is exactly the configured repository and branch."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3d: codepipeline selected without a connection ARN creates no
# pipeline and says so in the plan
#
# A source action with ConnectionArn = "" cannot be deployed, so the connection
# ARN gates the variant and the check block reports the inactive state instead
# of failing at apply time.
# -----------------------------------------------------------------------------
run "regression_codepipeline_without_source_connection" {
  command = plan

  variables {
    source_connection_arn = ""
  }

  assert {
    condition = alltrue([
      length(aws_codepipeline.this) == 0,
      length(aws_s3_bucket.artifacts) == 0,
      length(aws_codebuild_project.plan) == 0,
      length(aws_codebuild_project.apply) == 0,
      length(aws_iam_role.codepipeline) == 0,
      length(aws_iam_role.codebuild) == 0,
      length(aws_sns_topic.approval) == 0,
    ])
    error_message = "Without a connection ARN the codepipeline variant must create no resources at all."
  }

  # The shared role stays — it is independent of the variant.
  assert {
    condition     = aws_iam_role.pipeline.name == "TLZPipelineRole"
    error_message = "The shared pipeline role must be created for every pipeline_type."
  }

  expect_failures = [
    check.codepipeline_requires_source_connection,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4a: Validation failure — unknown pipeline_type is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_unknown_pipeline_type" {
  command = plan

  variables {
    pipeline_type = "jenkins"
  }

  expect_failures = [
    var.pipeline_type,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4b: Validation failure — empty repository_name is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_empty_repository_name" {
  command = plan

  variables {
    repository_name = ""
  }

  expect_failures = [
    var.repository_name,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4c: Validation failure — empty branch_name is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_empty_branch_name" {
  command = plan

  variables {
    branch_name = ""
  }

  expect_failures = [
    var.branch_name,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4c-2: Validation failure — a wildcard in branch_name or
# repository_name is rejected. Both reach the OIDC subject, a StringLike, of
# the external variant's trust policy: `*` or `?` would widen who may assume
# TLZExternalCIRole.
# -----------------------------------------------------------------------------
run "validation_rejects_wildcards_in_the_oidc_subject_inputs" {
  command = plan

  variables {
    pipeline_type   = "external"
    branch_name     = "release*"
    repository_name = "my-org/?"
  }

  expect_failures = [
    var.branch_name,
    var.repository_name,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4d: Validation failure — malformed deployment role ARN is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_malformed_deployment_role_arn" {
  command = plan

  variables {
    deployment_role_arns = {
      management = "not-an-arn"
    }
  }

  expect_failures = [
    var.deployment_role_arns,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4e: Validation failure — malformed approval email is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_malformed_approval_email" {
  command = plan

  variables {
    approval_notification_email = "not-an-email"
  }

  expect_failures = [
    var.approval_notification_email,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4f: Validation failure — unknown external CI provider is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_unknown_external_ci_provider" {
  command = plan

  variables {
    pipeline_type        = "external"
    external_ci_provider = "bitbucket"
  }

  expect_failures = [
    var.external_ci_provider,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4g: Validation failure — malformed connection ARN is rejected
# -----------------------------------------------------------------------------
run "validation_rejects_malformed_source_connection_arn" {
  command = plan

  variables {
    source_connection_arn = "codeconnections/not-an-arn"
  }

  expect_failures = [
    var.source_connection_arn,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4h: ecs variant with a connection source is refused (its trigger
# could never fire)
# -----------------------------------------------------------------------------
# The ecs variant's only trigger matches "CodeCommit Repository State Change"
# events; a repository reached through a CodeConnections connection (GitHub,
# GitLab, Bitbucket) emits none. Without this validation the combination would
# plan cleanly and the task would never start — silently. The file-level
# variables block carries a connection ARN, which is exactly the shape every
# ecs scenario above clears explicitly.
run "regression_ecs_variant_with_connection_source_rejected" {
  command = plan

  variables {
    pipeline_type   = "ecs"
    repository_name = "landing-zone"
    # source_connection_arn inherited from the file-level block: a connection ARN
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  expect_failures = [
    var.source_connection_arn,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4i: ecs variant with an owner/repo repository ID is refused; the
# trigger ARN needs a CodeCommit repository name (otherwise it could never fire)
# -----------------------------------------------------------------------------
run "regression_ecs_variant_with_repository_id_rejected" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "my-org/landing-zone"
    source_connection_arn  = ""
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  expect_failures = [
    var.repository_name,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4j: the two validations are ecs-only — the codepipeline variant keeps
# accepting a connection ARN together with an owner/repo repository ID
# -----------------------------------------------------------------------------
run "codepipeline_variant_keeps_connection_source_and_repository_id" {
  command = plan

  variables {
    pipeline_type   = "codepipeline"
    repository_name = "my-org/landing-zone"
    # source_connection_arn inherited from the file-level block: a connection ARN
  }

  assert {
    condition     = length(aws_codepipeline.this) == 1 && length(aws_cloudwatch_event_rule.ecs_trigger) == 0
    error_message = "The codepipeline variant must plan with a connection source and a repository ID, and create no ECS trigger."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4k: the ecs variant's network — the Fargate task's subnets, security
# groups and public-IP setting reach the EventBridge target
# -----------------------------------------------------------------------------
# The task definition is awsvpc/FARGATE, and EventBridge refuses an ECS target
# for a FARGATE launch type that carries no NetworkConfiguration (PutTargets
# 400 ValidationException: "Parameter NetworkConfiguration must be specified
# for target tlz-ecs-pipeline when launch type is FARGATE"). A mock provider
# accepts any PutTargets, so these runs pin the block onto the
# resource; the live apply-test proves it against AWS.
run "ecs_network_reaches_the_trigger_target" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_subnet_ids         = ["subnet-0a1b2c3d4e5f60718", "subnet-0f1e2d3c4b5a69788"]
    ecs_security_group_ids = ["sg-0123456789abcdef0", "sg-0fedcba9876543210"]
    ecs_assign_public_ip   = true
  }

  # The launch type is what makes the block mandatory; pinned so a change to
  # EC2 launch type (which does not need one) cannot pass this scenario by
  # accident.
  assert {
    condition     = aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].launch_type == "FARGATE"
    error_message = "The ECS target must keep launch_type FARGATE — the task definition is awsvpc/FARGATE and this is the launch type whose target EventBridge refuses without a network configuration."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration) == 1
    error_message = "The ECS target must carry exactly one network_configuration block — without it PutTargets answers 400 ValidationException for a FARGATE launch type, and the variant cannot be applied by anyone."
  }

  # Both subnets, so a module that passed only the first entry is caught.
  assert {
    condition     = aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration[0].subnets == toset(var.ecs_subnet_ids)
    error_message = "ecs_subnet_ids must reach the target's network configuration as its subnets, every entry of it."
  }

  assert {
    condition     = aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration[0].security_groups == toset(var.ecs_security_group_ids)
    error_message = "ecs_security_group_ids must reach the target's network configuration as its security groups, every entry of it."
  }

  assert {
    condition     = aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration[0].assign_public_ip == var.ecs_assign_public_ip
    error_message = "ecs_assign_public_ip must reach the target's network configuration."
  }
}

# The defaults of the two optional halves: no security group named, no public
# IP. Emptiness is asserted as a PROPERTY (try(length(...), 0)) rather than
# against a typed empty literal — a null-versus-[] comparison does not hold
# reliably against a live provider.
#
# Without ecs_use_default_security_group ECS would attach the VPC's default
# group, which in a VPC this landing zone manages has no egress rule, so every
# triggered task would fail at runtime. A caller in a VPC this landing zone
# does not manage may legitimately take that path, so this run sets the
# acknowledgement. ecs_security_group_ids is NOT set here: this run is the one
# that reads its DEFAULT, so "at its default the target names no security
# group" is measured rather than restated about an explicit [].
#
# The module READS the default group the caller vouches for (ecs.tf, four data
# sources ending in aws_vpc_security_group_rule) and its EventBridge target
# refuses when that group has no egress rule for HTTPS. A mock provider's
# default world is exactly the refused one — generated
# collections are empty, so the group has zero rules — which is the world of
# every VPC this landing zone manages. The override_data blocks below give this
# run the world its acknowledgement claims: one default group in the subnet's
# VPC with one all-traffic egress rule (is_egress = true, ip_protocol = "-1",
# the shape AWS creates in a VPC nobody stripped). Three assertions pin the
# target; a fourth pins that the fact was actually read on this path, the
# mirror of ecs_named_security_groups_skip_the_default_group_fact.
run "ecs_acknowledged_default_group_names_no_security_group_and_no_public_ip" {
  command = plan

  variables {
    pipeline_type                  = "ecs"
    repository_name                = "landing-zone"
    source_connection_arn          = ""
    ecs_subnet_ids                 = ["subnet-0a1b2c3d4e5f60718"]
    ecs_use_default_security_group = true
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0a1b2c3d4e5f60718"]
    values = {
      vpc_id = "vpc-0a1b2c3d4e5f60718"
    }
  }

  override_data {
    target = data.aws_security_group.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      id = "sg-0d0e0f0a0b0c0d0e0"
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rules.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      ids = ["sgr-0a1b2c3d4e5f60718"]
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rule.ecs_default["sgr-0a1b2c3d4e5f60718"]
    values = {
      is_egress   = true
      ip_protocol = "-1"
      from_port   = -1
      to_port     = -1
      cidr_ipv4   = "0.0.0.0/0"
    }
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration) == 1
    error_message = "A subnet alone must be enough for the network configuration block to exist — security groups and the public IP are optional."
  }

  assert {
    condition     = try(length(aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration[0].security_groups), 0) == 0
    error_message = "With ecs_security_group_ids at its default the target must name no security group (ECS then uses the VPC's default group)."
  }

  assert {
    condition     = aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration[0].assign_public_ip == false
    error_message = "ecs_assign_public_ip must default to false — a pipeline task gets a public address only when a caller asks for one."
  }

  assert {
    condition     = length(data.aws_subnet.ecs) == 1 && length(data.aws_security_group.ecs_default) == 1 && length(data.aws_vpc_security_group_rule.ecs_default) == 1
    error_message = "On the acknowledged path the module must READ the default group: one subnet, one default group of its VPC, one rule of that group — the fact behind the caller's word, not the word."
  }
}

# -----------------------------------------------------------------------------
# The FACT behind ecs_use_default_security_group
# -----------------------------------------------------------------------------
# The validation on ecs_security_group_ids sees variables only; the flag is
# the caller's word about the world. These runs pin the second stage — the
# precondition on aws_cloudwatch_event_target.ecs_trigger that reads the
# default group of the subnets' VPC — against the world a mock provider is told
# to show. They rest on MOCKED data sources (override_data per run), so what
# they prove is that the module refuses or passes on the fields it reads; that
# AWS fills those fields as the schema says (is_egress, ip_protocol, from_port,
# to_port of aws_vpc_security_group_rule, hashicorp/aws 6.62.0) is not proven
# here and no run of this file talks to AWS.
#
# Without the precondition, the three refusal runs fail with "Missing expected
# failure": the shape would be accepted and the target planned, whatever the
# group looked like — including the world of every VPC this landing zone
# manages, whose default group aws_default_security_group.vpc strips of every
# rule.

# (a) Acknowledged, and the default group has NO rule at all — the managed-VPC
# shape. Refused at the target, at plan time. The rules list is overridden to
# [] explicitly even though a mock would generate the same, so the world this
# run asserts about is written down rather than inherited.
run "ecs_acknowledged_default_group_without_any_rule_refused" {
  command = plan

  variables {
    pipeline_type                  = "ecs"
    repository_name                = "landing-zone"
    source_connection_arn          = ""
    ecs_subnet_ids                 = ["subnet-0a1b2c3d4e5f60718"]
    ecs_use_default_security_group = true
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0a1b2c3d4e5f60718"]
    values = {
      vpc_id = "vpc-0a1b2c3d4e5f60718"
    }
  }

  override_data {
    target = data.aws_security_group.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      id = "sg-0d0e0f0a0b0c0d0e0"
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rules.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      ids = []
    }
  }

  expect_failures = [aws_cloudwatch_event_target.ecs_trigger]
}

# (a') Acknowledged, and the default group has one rule — an all-traffic
# INGRESS rule, no egress. Refused: the direction is read, not the presence of
# a rule. A law that counted rules would pass this world.
run "ecs_acknowledged_default_group_with_ingress_only_refused" {
  command = plan

  variables {
    pipeline_type                  = "ecs"
    repository_name                = "landing-zone"
    source_connection_arn          = ""
    ecs_subnet_ids                 = ["subnet-0a1b2c3d4e5f60718"]
    ecs_use_default_security_group = true
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0a1b2c3d4e5f60718"]
    values = {
      vpc_id = "vpc-0a1b2c3d4e5f60718"
    }
  }

  override_data {
    target = data.aws_security_group.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      id = "sg-0d0e0f0a0b0c0d0e0"
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rules.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      ids = ["sgr-0a1b2c3d4e5f60718"]
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rule.ecs_default["sgr-0a1b2c3d4e5f60718"]
    values = {
      is_egress                    = false
      ip_protocol                  = "-1"
      from_port                    = -1
      to_port                      = -1
      referenced_security_group_id = "sg-0d0e0f0a0b0c0d0e0"
    }
  }

  expect_failures = [aws_cloudwatch_event_target.ecs_trigger]
}

# (a'') Acknowledged, and the default group's only egress rule is TCP 80 —
# egress exists, HTTPS does not. Refused: the task pulls its image and reaches
# AWS APIs over 443, and a law that stopped at "some egress rule" would pass
# this world.
run "ecs_acknowledged_default_group_with_egress_not_covering_https_refused" {
  command = plan

  variables {
    pipeline_type                  = "ecs"
    repository_name                = "landing-zone"
    source_connection_arn          = ""
    ecs_subnet_ids                 = ["subnet-0a1b2c3d4e5f60718"]
    ecs_use_default_security_group = true
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0a1b2c3d4e5f60718"]
    values = {
      vpc_id = "vpc-0a1b2c3d4e5f60718"
    }
  }

  override_data {
    target = data.aws_security_group.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      id = "sg-0d0e0f0a0b0c0d0e0"
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rules.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      ids = ["sgr-0a1b2c3d4e5f60718"]
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rule.ecs_default["sgr-0a1b2c3d4e5f60718"]
    values = {
      is_egress   = true
      ip_protocol = "tcp"
      from_port   = 80
      to_port     = 80
      cidr_ipv4   = "0.0.0.0/0"
    }
  }

  expect_failures = [aws_cloudwatch_event_target.ecs_trigger]
}

# (a''') Acknowledged, and the subnets span TWO VPCs: the default group of the
# first has an all-traffic egress rule, the default group of the second has no
# rule at all (ids = [] written explicitly, as in (a)). Refused — the law holds
# PER VPC: a task started in a subnet of the second VPC would carry that VPC's
# default group and reach nothing, and a law over the UNION of every group's
# rules would pass this world on the first VPC's rule alone, so without the
# per-VPC law this run fails with "Missing expected failure". Nothing in the
# module stops a caller from naming
# subnets of two VPCs (the validations on ecs_subnet_ids check shape, count and
# duplicates only), so the world is reachable at plan time; that EventBridge
# and ECS document such a subnet list as invalid is not this run's subject.
run "ecs_acknowledged_default_groups_of_two_vpcs_one_without_https_egress_refused" {
  command = plan

  variables {
    pipeline_type                  = "ecs"
    repository_name                = "landing-zone"
    source_connection_arn          = ""
    ecs_subnet_ids                 = ["subnet-0a1b2c3d4e5f60718", "subnet-0f1e2d3c4b5a69788"]
    ecs_use_default_security_group = true
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0a1b2c3d4e5f60718"]
    values = {
      vpc_id = "vpc-0a1b2c3d4e5f60718"
    }
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0f1e2d3c4b5a69788"]
    values = {
      vpc_id = "vpc-0f1e2d3c4b5a69788"
    }
  }

  override_data {
    target = data.aws_security_group.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      id = "sg-0d0e0f0a0b0c0d0e0"
    }
  }

  override_data {
    target = data.aws_security_group.ecs_default["vpc-0f1e2d3c4b5a69788"]
    values = {
      id = "sg-0f0e0d0c0b0a0f0e0"
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rules.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      ids = ["sgr-0a1b2c3d4e5f60718"]
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rules.ecs_default["vpc-0f1e2d3c4b5a69788"]
    values = {
      ids = []
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rule.ecs_default["sgr-0a1b2c3d4e5f60718"]
    values = {
      is_egress   = true
      ip_protocol = "-1"
      from_port   = -1
      to_port     = -1
      cidr_ipv4   = "0.0.0.0/0"
    }
  }

  expect_failures = [aws_cloudwatch_event_target.ecs_trigger]
}

# (b') Acknowledged, and the default group's egress is NOT allow-all: one TCP
# rule whose range covers 443, to a prefix list (gateway endpoints), no CIDR.
# Passes — the legitimate narrower shape the destination-agnostic law exists
# for; a law that demanded 0.0.0.0/0 or ip_protocol "-1" would false-red it.
# Two subnets in the SAME VPC, so the derivation reads every subnet and still
# resolves one default group (distinct vpc ids), not one group per subnet.
run "ecs_acknowledged_default_group_with_https_egress_to_prefix_list_passes" {
  command = plan

  variables {
    pipeline_type                  = "ecs"
    repository_name                = "landing-zone"
    source_connection_arn          = ""
    ecs_subnet_ids                 = ["subnet-0a1b2c3d4e5f60718", "subnet-0f1e2d3c4b5a69788"]
    ecs_use_default_security_group = true
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0a1b2c3d4e5f60718"]
    values = {
      vpc_id = "vpc-0a1b2c3d4e5f60718"
    }
  }

  override_data {
    target = data.aws_subnet.ecs["subnet-0f1e2d3c4b5a69788"]
    values = {
      vpc_id = "vpc-0a1b2c3d4e5f60718"
    }
  }

  override_data {
    target = data.aws_security_group.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      id = "sg-0d0e0f0a0b0c0d0e0"
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rules.ecs_default["vpc-0a1b2c3d4e5f60718"]
    values = {
      ids = ["sgr-0a1b2c3d4e5f60718"]
    }
  }

  override_data {
    target = data.aws_vpc_security_group_rule.ecs_default["sgr-0a1b2c3d4e5f60718"]
    values = {
      is_egress      = true
      ip_protocol    = "tcp"
      from_port      = 443
      to_port        = 443
      prefix_list_id = "pl-0a1b2c3d4e5f60718"
    }
  }

  assert {
    condition     = length(data.aws_subnet.ecs) == 2 && length(data.aws_security_group.ecs_default) == 1
    error_message = "Two subnets of one VPC must be read as two subnets and ONE default group — the VPC is derived from every subnet, and distinct ids resolve one group."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.ecs_trigger) == 1 && try(length(aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration[0].security_groups), 0) == 0
    error_message = "With an HTTPS egress rule on the default group the acknowledged path must plan, and the target must still name no security group."
  }
}

# (c) The caller names its own groups: the task never carries the default
# group, so the fact is not read — none of the four data sources has an
# instance, and the target plans with the named groups as before. Under a mock
# provider this is also the run that proves the precondition does not reach
# into the twelve other ecs runs: were the group read here, the mock's empty
# rule list would refuse every one of them.
run "ecs_named_security_groups_skip_the_default_group_fact" {
  command = plan

  variables {
    pipeline_type                  = "ecs"
    repository_name                = "landing-zone"
    source_connection_arn          = ""
    ecs_subnet_ids                 = ["subnet-0a1b2c3d4e5f60718"]
    ecs_security_group_ids         = ["sg-0123456789abcdef0"]
    ecs_use_default_security_group = true
  }

  assert {
    condition     = length(data.aws_subnet.ecs) == 0 && length(data.aws_security_group.ecs_default) == 0 && length(data.aws_vpc_security_group_rules.ecs_default) == 0 && length(data.aws_vpc_security_group_rule.ecs_default) == 0
    error_message = "With a security group named, nothing about the VPC's default group may be read — the fact-check belongs to the task that would carry that group, and to no other."
  }

  assert {
    condition     = aws_cloudwatch_event_target.ecs_trigger[0].ecs_target[0].network_configuration[0].security_groups == toset(var.ecs_security_group_ids)
    error_message = "The named groups must reach the target unchanged — the fact-check must not alter the path that names a group."
  }
}

# Rejection: an ecs variant that names no security
# group and does not acknowledge the VPC's default group is refused at plan
# time, by the module, with a message that names the way out — not at runtime
# by a task that can reach nothing. Both variables of the law are left at their
# DEFAULTS here (empty list, acknowledgement false) and the file-level block
# supplies neither, so this run is exactly the shape a caller produces by
# forgetting the network. Without this validation it fails with "Missing
# expected failure": the shape would be accepted, and a whole pipeline built
# around a task that could reach nothing.
run "ecs_variant_without_security_group_and_without_acknowledgement_rejected" {
  command = plan

  variables {
    pipeline_type         = "ecs"
    repository_name       = "landing-zone"
    source_connection_arn = ""
  }

  expect_failures = [var.ecs_security_group_ids]
}

# Rejection: the ecs variant without a subnet is refused at plan time, by the
# module and with a message that names the variable — not twenty seconds into
# the apply by EventBridge. The security group is named so that this run
# isolates the subnet law: without it the run would report two failing
# variables and its expect_failures list would no longer say what it proves.
run "ecs_variant_without_subnets_rejected" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_subnet_ids         = []
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  expect_failures = [var.ecs_subnet_ids]
}

# The requirement is ecs-only: the two other variants keep planning with the
# default (empty) network, so no existing caller is broken by it. The
# production default (codepipeline, nothing set) is the one that matters.
run "codepipeline_variant_needs_no_ecs_network" {
  command = plan

  variables {
    ecs_subnet_ids = []
  }

  assert {
    condition     = length(aws_codepipeline.this) == 1 && length(aws_cloudwatch_event_target.ecs_trigger) == 0
    error_message = "The codepipeline variant must plan with ecs_subnet_ids empty — the subnet requirement belongs to the ecs variant alone."
  }
}

run "external_variant_needs_no_ecs_network" {
  command = plan

  variables {
    pipeline_type          = "external"
    external_ci_thumbprint = "1234567890abcdef1234567890abcdef12345678"
    ecs_subnet_ids         = []
  }

  assert {
    condition     = length(aws_iam_openid_connect_provider.external_ci) == 1 && length(aws_cloudwatch_event_target.ecs_trigger) == 0
    error_message = "The external variant must plan with ecs_subnet_ids empty — the subnet requirement belongs to the ecs variant alone."
  }
}

# Rejection: the AWS identifier shapes. A name where an ID belongs would reach
# PutTargets as an invalid subnet or group; both are refused before the plan.
run "ecs_network_ids_of_the_wrong_shape_rejected" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_subnet_ids         = ["private-a"]
    ecs_security_group_ids = ["pipeline-tasks"]
  }

  expect_failures = [var.ecs_subnet_ids, var.ecs_security_group_ids]
}

run "ecs_network_duplicate_ids_rejected" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_subnet_ids         = ["subnet-0a1b2c3d4e5f60718", "subnet-0a1b2c3d4e5f60718"]
    ecs_security_group_ids = ["sg-0123456789abcdef0", "sg-0123456789abcdef0"]
  }

  expect_failures = [var.ecs_subnet_ids, var.ecs_security_group_ids]
}

# -----------------------------------------------------------------------------
# Scenario: State-change notifications
# -----------------------------------------------------------------------------

# Toggle off: no rule, no target, no topic policy — the plan of every
# deployment without the switch stays untouched. The switch is set to false
# explicitly (not just left at its default) so the off-state is pinned.
run "pipeline_notifications_off_no_resources" {
  command = plan

  variables {
    enable_pipeline_notifications = false
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.pipeline_state) == 0
    error_message = "Without enable_pipeline_notifications no EventBridge rule may be planned."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.pipeline_state) == 0
    error_message = "Without enable_pipeline_notifications no EventBridge target may be planned."
  }

  assert {
    condition     = length(aws_sns_topic_policy.pipeline_state_events) == 0
    error_message = "Without enable_pipeline_notifications no topic policy may be planned."
  }

  assert {
    condition     = length(aws_kms_key.approval_topic) == 0 && aws_sns_topic.approval[0].kms_master_key_id == "alias/aws/sns"
    error_message = "Without enable_pipeline_notifications no key may be planned and the approval topic keeps alias/aws/sns."
  }
}

run "pipeline_notifications_reach_rules_and_topic" {
  command = plan

  variables {
    enable_pipeline_notifications = true
    pipeline_notification_states  = ["FAILED", "SUCCEEDED"]
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.pipeline_state) == 2
    error_message = "One EventBridge rule per selected state must be planned."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.pipeline_state["FAILED"].name == "tlz-pipeline-state-failed"
    error_message = "The rule name must carry the lowercased state."
  }

  # The event pattern and the topic policy embed the pipeline/rule ARNs —
  # computed attributes, unknown at plan (see the note at the top of this
  # file). No offline test pins their shape (detail-type, state list,
  # service principal); the plan asserts stay on counts and input-derived
  # attributes.

  # EventBridge cannot publish to a topic under alias/aws/sns: with
  # notifications on, the topic's key grants the EventBridge principal exactly
  # GenerateDataKey* and Decrypt, with no aws:SourceAccount / aws:SourceArn
  # condition (AWS does not support them in a KMS policy on this path; the
  # topic policy keeps the SourceArn scope).
  assert {
    condition = jsondecode(aws_kms_key.approval_topic[0].policy).Statement == [
      {
        Sid       = "EnableRootAccountAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowEventBridgePublishToEncryptedTopic"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
      },
    ]
    error_message = "The approval topic key policy must hold exactly the account root statement and the EventBridge statement (GenerateDataKey* and Decrypt, no source condition)."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.pipeline_state) == 2
    error_message = "Each rule must carry exactly one target."
  }

  assert {
    condition     = length(aws_sns_topic_policy.pipeline_state_events) == 1
    error_message = "The topic policy allowing EventBridge to publish must be planned."
  }
}

# The notifications hang on the VARIANT gate as well: with the switch on but
# the CodePipeline variant inactive (no source connection), no rule exists —
# there is no pipeline whose states could be matched.
run "pipeline_notifications_require_the_codepipeline_variant" {
  command = plan

  variables {
    pipeline_type                 = "external"
    external_ci_thumbprint        = "1234567890abcdef1234567890abcdef12345678"
    enable_pipeline_notifications = true
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.pipeline_state) == 0
    error_message = "Without the CodePipeline variant no state rule may be planned."
  }

  assert {
    condition     = length(aws_sns_topic_policy.pipeline_state_events) == 0
    error_message = "Without the CodePipeline variant no topic policy may be planned."
  }
}

run "invalid_notification_state_rejected" {
  command = plan

  variables {
    enable_pipeline_notifications = true
    pipeline_notification_states  = ["FAILED", "EXPLODED"]
  }

  expect_failures = [
    var.pipeline_notification_states,
  ]
}

run "empty_notification_states_rejected" {
  command = plan

  variables {
    enable_pipeline_notifications = true
    pipeline_notification_states  = []
  }

  expect_failures = [
    var.pipeline_notification_states,
  ]
}

run "duplicate_notification_states_rejected" {
  command = plan

  variables {
    enable_pipeline_notifications = true
    pipeline_notification_states  = ["FAILED", "FAILED"]
  }

  expect_failures = [
    var.pipeline_notification_states,
  ]
}
# -----------------------------------------------------------------------------
# Scenario: Service principals follow the partition —
# under a mock partition every trust policy of the module names its service
# principal with the partition's DNS suffix instead of a fixed one, and the
# templated shared-role trust policy renders with the same suffix.
# -----------------------------------------------------------------------------
# The mock partition is aws-iso (suffix c2s.ic.gov): a real partition-suffix
# pair that keeps the codepipeline variant active. aws-eusc cannot serve as the
# mock here since the module gates the variant off in that partition — the
# aws-eusc behaviour has its own scenario below.
run "codepipeline_principals_follow_the_partition" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-iso"
      dns_suffix = "c2s.ic.gov"
    }
  }
  assert {
    condition     = strcontains(aws_iam_role.codepipeline[0].assume_role_policy, "codepipeline.c2s.ic.gov")
    error_message = "The CodePipeline trust policy must carry the partition's DNS suffix."
  }
  assert {
    condition     = strcontains(aws_iam_role.codebuild[0].assume_role_policy, "codebuild.c2s.ic.gov")
    error_message = "The CodeBuild trust policy must carry the partition's DNS suffix."
  }
  assert {
    condition     = strcontains(aws_iam_role.pipeline.assume_role_policy, "codebuild.c2s.ic.gov")
    error_message = "The templated shared-role trust policy must render the partition's DNS suffix."
  }
}
# -----------------------------------------------------------------------------
# Scenario: aws-eusc skips the codepipeline variant with a warning
# — CodePipeline and CodeBuild are not available in the partition, so the
# variant creates nothing and both availability checks fire. The shared role
# stays and still renders the partition's DNS suffix.
# -----------------------------------------------------------------------------
run "eusc_skips_codepipeline_with_warning" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }
  expect_failures = [
    check.codepipeline_partition_availability,
    check.codebuild_partition_availability,
  ]
  assert {
    condition     = length(aws_codepipeline.this) == 0 && length(aws_codebuild_project.plan) == 0 && length(aws_codebuild_project.apply) == 0
    error_message = "No CodePipeline or CodeBuild resources must be created in the aws-eusc partition."
  }
  assert {
    condition = alltrue([
      length(aws_s3_bucket.artifacts) == 0,
      length(aws_iam_role.codepipeline) == 0,
      length(aws_iam_role.codebuild) == 0,
      length(aws_sns_topic.approval) == 0,
    ])
    error_message = "The whole codepipeline variant must be skipped in the aws-eusc partition."
  }
  assert {
    condition     = strcontains(aws_iam_role.pipeline.assume_role_policy, "codebuild.amazonaws.eu")
    error_message = "The templated shared-role trust policy must render the partition's DNS suffix."
  }
}
# -----------------------------------------------------------------------------
# Scenario: aws-eusc with the ecs variant — no warning, ECS stays available
# -----------------------------------------------------------------------------
# Counterpart to the scenario above: the availability checks must only fire
# when the codepipeline variant was actually selected. This run declares no
# expect_failures, so a check that fired here would fail the test.
run "eusc_with_ecs_variant_no_warning" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }
  variables {
    pipeline_type               = "ecs"
    repository_name             = "landing-zone"
    source_connection_arn       = ""
    approval_notification_email = "platform@example.com"
    ecs_security_group_ids      = ["sg-0123456789abcdef0"]
  }
  assert {
    condition     = length(aws_ecs_cluster.pipeline) == 1 && length(aws_codepipeline.this) == 0
    error_message = "The ecs variant must deploy in the aws-eusc partition without CodePipeline resources."
  }
}
run "ecs_principals_follow_the_partition" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }
  variables {
    pipeline_type               = "ecs"
    repository_name             = "landing-zone"
    source_connection_arn       = ""
    approval_notification_email = "platform@example.com"
    ecs_security_group_ids      = ["sg-0123456789abcdef0"]
  }
  assert {
    condition     = strcontains(aws_iam_role.ecs_execution[0].assume_role_policy, "ecs-tasks.amazonaws.eu")
    error_message = "The ECS execution trust policy must carry the partition's DNS suffix."
  }
  assert {
    condition     = strcontains(aws_iam_role.ecs_task[0].assume_role_policy, "ecs-tasks.amazonaws.eu")
    error_message = "The ECS task trust policy must carry the partition's DNS suffix."
  }
  assert {
    condition     = strcontains(aws_iam_role.eventbridge_ecs[0].assume_role_policy, "events.amazonaws.eu")
    error_message = "The EventBridge trust policy must carry the partition's DNS suffix."
  }
}

# -----------------------------------------------------------------------------
# Discovery-parameter IAM coverage
#
# The accounts module publishes the cross-account discovery parameters under
# /tlz/accounts/<name>/{id,metadata}. Each pipeline variant's SSM statement
# must grant exactly that prefix — and nothing under /lzt/*, where no
# parameter is published.
#
# The CodeBuild policy JSON embeds the artifact bucket ARN, which is unknown
# at plan time; the plan-time override pins it so the whole policy document
# becomes assertable.
# -----------------------------------------------------------------------------
run "codebuild_ssm_statement_covers_published_prefix" {
  command = plan

  override_resource {
    target          = aws_s3_bucket.artifacts
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-pipeline-artifacts-123456789012-eu-central-1"
    }
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.codebuild[0].policy, "parameter/tlz/*")
    error_message = "The CodeBuild SSM statement must cover the published parameter prefix /tlz/*."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.codebuild[0].policy, "parameter/lzt/")
    error_message = "The CodeBuild SSM statement must not grant the stale /lzt/* prefix — no parameter is published there."
  }
}

run "ecs_task_ssm_statement_covers_published_prefix" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.ecs_task[0].policy, "parameter/tlz/*")
    error_message = "The ECS task SSM statement must cover the published parameter prefix /tlz/*."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.ecs_task[0].policy, "parameter/lzt/")
    error_message = "The ECS task SSM statement must not grant the stale /lzt/* prefix — no parameter is published there."
  }
}

# -----------------------------------------------------------------------------
# Upsert-safe resource names
# -----------------------------------------------------------------------------
# SNS CreateTopic, EventBridge PutRule and ECS CreateCluster are upserts or
# idempotent creates: an apply against a deployment account already carrying
# the name adopts the live resource and a test teardown deletes it. Every
# such fixed name is therefore overridable; the defaults are the module's
# standard names, so a production plan stays empty. That a stack is not
# deployed yet is not a safety property.

# Default: the CodePipeline variant's two names are the standard names (the
# ecs cluster default is pinned in custom_configuration_ecs_variant and the
# state-rule default in pipeline_notifications_reach_rules_and_topic).
run "upsert_names_default_to_the_literals" {
  command = plan

  variables {
    enable_pipeline_notifications = true
    pipeline_notification_states  = ["SUPERSEDED"]
  }

  assert {
    condition     = aws_sns_topic.approval[0].name == "tlz-pipeline-approval"
    error_message = "approval_topic_name must default to tlz-pipeline-approval so a production plan stays empty."
  }

  # The longest state suffix under the default prefix — the length bound of
  # the prefix validation is derived from exactly this name (64 - 11 = 53).
  assert {
    condition     = aws_cloudwatch_event_rule.pipeline_state["SUPERSEDED"].name == "tlz-pipeline-state-superseded"
    error_message = "pipeline_state_rule_name_prefix must default to tlz-pipeline-state so a production plan stays empty."
  }
}

run "ecs_upsert_names_default_to_the_literals" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  assert {
    condition = alltrue([
      aws_ecs_cluster.pipeline[0].name == "tlz-pipeline",
      aws_sns_topic.ecs_approval[0].name == "tlz-ecs-pipeline-approval",
      aws_cloudwatch_event_rule.ecs_trigger[0].name == "tlz-ecs-pipeline-trigger",
    ])
    error_message = "The ecs variant's cluster, approval topic and trigger rule must default to the standard names so a production plan stays empty."
  }
}

# Reach: an override lands on each CodePipeline-variant resource; the state
# rules' targets follow the renamed rules (the rule name is the join key) and
# the topic policy still hangs on the renamed topic.
run "upsert_names_reach_the_codepipeline_resources" {
  command = plan

  variables {
    enable_pipeline_notifications   = true
    pipeline_notification_states    = ["FAILED", "SUCCEEDED"]
    approval_notification_email     = "platform@example.com"
    approval_topic_name             = "tlz-l4test-pipeline-approval"
    pipeline_state_rule_name_prefix = "tlz-l4test-pipeline-state"
  }

  assert {
    condition     = aws_sns_topic.approval[0].name == "tlz-l4test-pipeline-approval"
    error_message = "approval_topic_name must reach the approval SNS topic."
  }

  assert {
    condition = alltrue([
      aws_cloudwatch_event_rule.pipeline_state["FAILED"].name == "tlz-l4test-pipeline-state-failed",
      aws_cloudwatch_event_rule.pipeline_state["SUCCEEDED"].name == "tlz-l4test-pipeline-state-succeeded",
    ])
    error_message = "pipeline_state_rule_name_prefix must reach every per-state rule as <prefix>-<lowercased state>."
  }

  assert {
    condition = alltrue([
      aws_cloudwatch_event_target.pipeline_state["FAILED"].rule == "tlz-l4test-pipeline-state-failed",
      aws_cloudwatch_event_target.pipeline_state["SUCCEEDED"].rule == "tlz-l4test-pipeline-state-succeeded",
    ])
    error_message = "Each state rule's target must follow the renamed rule."
  }

  assert {
    condition     = length(aws_sns_topic_policy.pipeline_state_events) == 1 && length(aws_sns_topic_subscription.approval_email) == 1
    error_message = "The topic policy and the e-mail subscription must still hang on the renamed approval topic."
  }
}

# Reach: the ecs variant's three names land, and the trigger's target still
# follows the renamed rule.
run "upsert_names_reach_the_ecs_resources" {
  command = plan

  variables {
    pipeline_type           = "ecs"
    repository_name         = "landing-zone"
    source_connection_arn   = ""
    ecs_cluster_name        = "tlz-l4test-pipeline"
    ecs_approval_topic_name = "tlz-l4test-ecs-pipeline-approval"
    ecs_trigger_rule_name   = "tlz-l4test-ecs-pipeline-trigger"
    ecs_security_group_ids  = ["sg-0123456789abcdef0"]
  }

  assert {
    condition     = aws_ecs_cluster.pipeline[0].name == "tlz-l4test-pipeline"
    error_message = "ecs_cluster_name must reach the ECS cluster."
  }

  assert {
    condition     = aws_sns_topic.ecs_approval[0].name == "tlz-l4test-ecs-pipeline-approval"
    error_message = "ecs_approval_topic_name must reach the ecs approval topic."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.ecs_trigger[0].name == "tlz-l4test-ecs-pipeline-trigger"
    error_message = "ecs_trigger_rule_name must reach the ECS trigger rule."
  }

  assert {
    condition     = aws_cloudwatch_event_target.ecs_trigger[0].rule == "tlz-l4test-ecs-pipeline-trigger"
    error_message = "The ECS target must follow the renamed trigger rule."
  }
}

# Rejection: the two topics and the two rule names are guardrail classes —
# the organization SCPs, which DO apply to the deployment account, protect
# only tlz-* topics and rules — so a name outside the namespace is refused
# before the plan can create an unprotected resource.
run "approval_topic_name_outside_namespace_rejected" {
  command = plan

  variables {
    approval_topic_name = "pipeline-approval"
  }

  expect_failures = [var.approval_topic_name]
}

run "pipeline_state_rule_name_prefix_outside_namespace_rejected" {
  command = plan

  variables {
    enable_pipeline_notifications   = true
    pipeline_state_rule_name_prefix = "pipeline-state"
  }

  expect_failures = [var.pipeline_state_rule_name_prefix]
}

run "ecs_topic_and_rule_names_outside_namespace_rejected" {
  command = plan

  variables {
    pipeline_type           = "ecs"
    repository_name         = "landing-zone"
    source_connection_arn   = ""
    ecs_approval_topic_name = "ecs-pipeline-approval"
    ecs_trigger_rule_name   = "ecs-pipeline-trigger"
    ecs_security_group_ids  = ["sg-0123456789abcdef0"]
  }

  expect_failures = [var.ecs_approval_topic_name, var.ecs_trigger_rule_name]
}

# Rejection: the AWS naming rules still apply inside the namespace — a topic
# name with a dot, and a 54-character prefix whose "-superseded" rule name
# would exceed EventBridge's 64 characters.
run "upsert_names_breaking_the_aws_naming_rule_rejected" {
  command = plan

  variables {
    enable_pipeline_notifications   = true
    approval_topic_name             = "tlz-pipeline.approval"
    pipeline_state_rule_name_prefix = "tlz-${join("", [for i in range(50) : "x"])}"
  }

  expect_failures = [var.approval_topic_name, var.pipeline_state_rule_name_prefix]
}

# The cluster name is deliberately NOT pinned to tlz- (no guardrail names an
# ECS cluster ARN), so a name outside the namespace passes — and only the ECS
# naming rule refuses (a dot).
run "ecs_cluster_name_outside_namespace_accepted" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_cluster_name       = "team-pipeline"
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  assert {
    condition     = aws_ecs_cluster.pipeline[0].name == "team-pipeline"
    error_message = "ecs_cluster_name is not confined to tlz- (no guardrail covers ECS), so a name outside the namespace must be accepted."
  }
}

run "ecs_cluster_name_breaking_the_ecs_naming_rule_rejected" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_cluster_name       = "tlz.pipeline"
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  expect_failures = [var.ecs_cluster_name]
}

# -----------------------------------------------------------------------------
# The deployment pipeline must not download and execute a mutable third-party binary while its role
# can assume the account-provisioning roles.
# -----------------------------------------------------------------------------
# The CodeBuild service role holds sts:AssumeRole on every entry of
# deployment_role_arns (Sid AssumeDeploymentRoles), so a terragrunt binary
# fetched from `releases/latest` and made executable unverified would run with
# that reach if it were compromised or altered. This test reads the two rendered buildspecs and fails
# if either points at releases/latest or lacks a checksum check between
# the download and the chmod.
run "regression_2026_09_22_terragrunt_pin_and_checksum" {
  command = plan

  assert {
    condition = alltrue([
      length(regexall("releases/latest", aws_codebuild_project.plan[0].source[0].buildspec)) == 0,
      length(regexall("releases/latest", aws_codebuild_project.apply[0].source[0].buildspec)) == 0,
    ])
    error_message = "The buildspec must not fetch terragrunt from releases/latest — a mutable pointer downloaded while the CodeBuild role can assume every deployment_role_arns entry."
  }

  # The whole sequence on three consecutive lines: download to one path,
  # verify that same path against the pinned sum (nothing after `-c -`, so no
  # `|| true`), then chmod it. A count of `sha256sum -c` alone would stay
  # green for a reorder, a swallowed failure or a check of another file.
  assert {
    condition = alltrue([
      for buildspec in [
        aws_codebuild_project.plan[0].source[0].buildspec,
        aws_codebuild_project.apply[0].source[0].buildspec,
      ] :
      length(regexall(
        "\\n *- curl -fsSL \"https://github\\.com/gruntwork-io/terragrunt/releases/download/\\$\\{TERRAGRUNT_VERSION\\}/terragrunt_linux_amd64\" -o /usr/local/bin/terragrunt\\n *- echo \"\\$\\{TERRAGRUNT_SHA256\\}  /usr/local/bin/terragrunt\" \\| sha256sum -c -\\n *- chmod \\+x /usr/local/bin/terragrunt\\n",
        buildspec
      )) == 1
    ])
    error_message = "Each buildspec must download terragrunt, verify that file with sha256sum -c (no || true), and only then chmod +x it, on three consecutive lines."
  }
}

# -----------------------------------------------------------------------------
# The ecs variant's Fargate task must not run a mutable third-party image.
# -----------------------------------------------------------------------------
# The pin above covers the codepipeline variant's two build steps. The ecs
# variant has the same exposure by a different route: a tag such as
# "alpine/terragrunt:latest" can be moved by the publisher, is resolved at task
# start and runs with the task role that assumes every deployment_role_arns
# entry. The first run reads the rendered container definitions of the
# ecs variant, the second proves the variable's validation refuses a tag-only
# override, so the default cannot be undone silently by a caller.
run "regression_2026_09_22_ecs_task_image_pinned_by_digest" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
  }

  assert {
    condition = alltrue([
      for container in jsondecode(aws_ecs_task_definition.pipeline[0].container_definitions) :
      can(regex("@sha256:[0-9a-f]{64}$", container.image))
    ])
    error_message = "Every container of the ecs variant's task definition must name its image by digest — a tag is a mutable pointer pulled into a task that holds the deployment-assume role."
  }

  assert {
    condition = alltrue([
      for container in jsondecode(aws_ecs_task_definition.pipeline[0].container_definitions) :
      length(regexall(":latest", container.image)) == 0
    ])
    error_message = "The ecs variant's task definition must not name an image by the latest tag."
  }
}

run "ecs_task_image_without_digest_rejected" {
  command = plan

  variables {
    pipeline_type          = "ecs"
    repository_name        = "landing-zone"
    source_connection_arn  = ""
    ecs_security_group_ids = ["sg-0123456789abcdef0"]
    ecs_task_image         = "alpine/terragrunt:tf1.16.1"
  }

  expect_failures = [var.ecs_task_image]
}

# -----------------------------------------------------------------------------
# codebuild_encryption_kms_key_arn — reaches BOTH CodeBuild projects
# (plan and apply), grants the shared service role exactly the six operations
# it needs on exactly that key, and stays inert when empty
# -----------------------------------------------------------------------------

# Empty case: the default must leave the plan exactly as without the
# variable — no extra policy resource, and the plan otherwise unchanged.
#
# encryption_key is Optional+Computed on aws_codebuild_project: even with the
# module's own null passed through, a mocked provider still generates a fake
# value for it (per Terraform's mock-data rules, an optional+computed
# attribute without an explicit default is always filled), so its exact
# value cannot be asserted here — same reason this file's own header says
# "Computed attributes are never asserted on". The controllable, module-owned
# signal for "empty leaves the plan unchanged" is the absence of the grant,
# asserted below; the reverse (a named key setting encryption_key) is proven
# in the next run, where the value is known at plan time once
# override_resource pins it directly.
run "codebuild_encryption_kms_empty_leaves_plan_unchanged" {
  command = plan

  variables {
    codebuild_encryption_kms_key_arn = ""
  }

  assert {
    condition     = length(aws_iam_role_policy.codebuild_encryption_kms) == 0
    error_message = "An empty codebuild_encryption_kms_key_arn must create no extra IAM policy resource."
  }
}

# Named case: the key reaches both projects' encryption_key AND the shared
# CodeBuild service role is granted exactly the six key operations the module
# names (kms:Decrypt, kms:DescribeKey, kms:Encrypt, kms:GenerateDataKey,
# kms:ReEncryptFrom, kms:ReEncryptTo — the real IAM action names; there is no
# single "kms:ReEncrypt" action, so a grant naming that string instead would
# grant nothing while looking complete) on exactly that key's ARN — one grant,
# because both projects share aws_iam_role.codebuild.
run "codebuild_encryption_kms_named_reaches_both_projects_and_grants_six_actions_only" {
  command = apply

  variables {
    codebuild_encryption_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/aaaa-bbbb"
  }

  override_resource {
    target = aws_iam_role.codebuild[0]
    values = {
      arn = "arn:aws:iam::123456789012:role/TLZCodeBuildServiceRole"
      id  = "TLZCodeBuildServiceRole"
    }
  }

  override_resource {
    target = aws_iam_role.codepipeline[0]
    values = {
      arn = "arn:aws:iam::123456789012:role/TLZCodePipelineServiceRole"
      id  = "TLZCodePipelineServiceRole"
    }
  }

  assert {
    condition     = aws_codebuild_project.plan[0].encryption_key == "arn:aws:kms:eu-central-1:123456789012:key/aaaa-bbbb"
    error_message = "A named codebuild_encryption_kms_key_arn must reach the plan project's encryption_key."
  }

  assert {
    condition     = aws_codebuild_project.apply[0].encryption_key == "arn:aws:kms:eu-central-1:123456789012:key/aaaa-bbbb"
    error_message = "A named codebuild_encryption_kms_key_arn must reach the apply project's encryption_key."
  }

  assert {
    condition     = length(aws_iam_role_policy.codebuild_encryption_kms) == 1
    error_message = "A named codebuild_encryption_kms_key_arn must create exactly one grant, shared by both projects' service role."
  }

  assert {
    condition = (
      toset(jsondecode(aws_iam_role_policy.codebuild_encryption_kms[0].policy).Statement[0].Action) == toset([
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
      ])
    )
    error_message = "The grant must allow exactly these six key operations — no more, no fewer, and not the non-existent single action kms:ReEncrypt."
  }

  assert {
    condition     = jsondecode(aws_iam_role_policy.codebuild_encryption_kms[0].policy).Statement[0].Resource == "arn:aws:kms:eu-central-1:123456789012:key/aaaa-bbbb"
    error_message = "The grant must be scoped to exactly the named key's ARN, not a wider resource."
  }

  assert {
    condition     = jsondecode(aws_iam_role_policy.codebuild_encryption_kms[0].policy).Statement[0].Effect == "Allow"
    error_message = "The grant statement must be an Allow."
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.codebuild_encryption_kms[0].policy).Statement) == 1
    error_message = "The grant must carry exactly one statement."
  }
}
