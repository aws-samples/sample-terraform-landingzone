# Pipeline Module — CodePipeline variant
# Created only when pipeline_type == "codepipeline" AND source_connection_arn is set
# Resources: CodePipeline, CodeBuild, S3 artifact bucket, IAM roles, SNS
#
# Source and trigger use one single mechanism: the source action is a
# CodeStar/CodeConnections connection, and change detection runs through that
# same connection via the pipeline's own git trigger (pipeline type V2). The
# connection ARN therefore gates the whole variant — without it the source
# action would be incomplete and CodePipeline would reject the pipeline.

locals {
  # Creation condition of the CodePipeline variant. The connection ARN is part
  # of the condition because the source action cannot be built without it.
  # The partition is part of the condition because CodePipeline and CodeBuild
  # are not available in aws-eusc (see the checks below).
  codepipeline_enabled = var.pipeline_type == "codepipeline" && var.source_connection_arn != "" && !local.is_eusc
}

# The variant is selected but unusable without a connection — make that visible
# in the plan instead of silently creating nothing.
check "codepipeline_requires_source_connection" {
  assert {
    condition     = var.pipeline_type != "codepipeline" || var.source_connection_arn != ""
    error_message = "pipeline_type is codepipeline but source_connection_arn is empty — no CodePipeline resources are created. Set source_connection_arn to the ARN of an existing CodeConnections/CodeStar connection."
  }
}

# CodePipeline is not available in the aws-eusc partition (AWS Services by
# Region, eusc-de-east-1). Without this check the skip
# would be silent. The check warns instead of failing (same convention as
# macie_partition_availability in modules/security).
check "codepipeline_partition_availability" {
  assert {
    condition     = !(var.pipeline_type == "codepipeline" && local.is_eusc)
    error_message = "pipeline_type is codepipeline but CodePipeline is not available in the aws-eusc partition. All CodePipeline resources are skipped in this deployment. Use pipeline_type = \"ecs\" or \"external\" in aws-eusc."
  }
}

# CodeBuild backs the plan and apply stages of the codepipeline variant and is
# not available in aws-eusc either (same source). Own check, because the
# availability table documents the two services separately.
check "codebuild_partition_availability" {
  assert {
    condition     = !(var.pipeline_type == "codepipeline" && local.is_eusc)
    error_message = "pipeline_type is codepipeline but CodeBuild is not available in the aws-eusc partition. The CodeBuild projects of the codepipeline variant are skipped in this deployment. Use pipeline_type = \"ecs\" or \"external\" in aws-eusc."
  }
}

# --- S3 Artifact Bucket ---

resource "aws_s3_bucket" "artifacts" {
  count  = local.codepipeline_enabled ? 1 : 0
  bucket = "tlz-pipeline-artifacts-${local.account_id}-${local.region}"
}

resource "aws_s3_bucket_versioning" "artifacts" {
  count  = local.codepipeline_enabled ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  #checkov:skip=CKV2_AWS_67:SSE-S3 (AES256), no CMK exists to rotate; AWS-managed encryption for pipeline artifacts is the accepted choice
  count  = local.codepipeline_enabled ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  count  = local.codepipeline_enabled ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Removes fragments of incomplete multipart uploads after 7 days — cost
# hygiene without a retention decision: pipeline artifacts themselves are
# kept, their retention stays with the deployment.
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  count  = local.codepipeline_enabled ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --- IAM Role: CodePipeline service role ---

resource "aws_iam_role" "codepipeline" {
  count = local.codepipeline_enabled ? 1 : 0
  name  = "TLZCodePipelineServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "codepipeline.${local.dns_suffix}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "codepipeline" {
  count = local.codepipeline_enabled ? 1 : 0
  name  = "TLZCodePipelineServiceRole-policy"
  role  = aws_iam_role.codepipeline[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "S3ArtifactAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetBucketVersioning",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.artifacts[0].arn,
          "${aws_s3_bucket.artifacts[0].arn}/*",
        ]
      },
      {
        Sid    = "CodeBuildAccess"
        Effect = "Allow"
        Action = [
          "codebuild:StartBuild",
          "codebuild:BatchGetBuilds",
        ]
        Resource = aws_codebuild_project.plan[0].arn
      },
      {
        Sid    = "CodeBuildApplyAccess"
        Effect = "Allow"
        Action = [
          "codebuild:StartBuild",
          "codebuild:BatchGetBuilds",
        ]
        Resource = aws_codebuild_project.apply[0].arn
      },
      {
        Sid      = "SNSApprovalAccess"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.approval[0].arn
      },
      {
        Sid    = "CodeStarConnectionAccess"
        Effect = "Allow"
        Action = [
          "codestar-connections:UseConnection",
          "codeconnections:UseConnection",
        ]
        # Scoped to the connection that feeds this pipeline.
        Resource = var.source_connection_arn
      },
      ], local.pipeline_notifications_enabled ? [
      {
        # Publishing to the approval topic under its customer-managed key
        # (notifications.tf) needs the key as well as sns:Publish.
        Sid      = "SNSApprovalTopicKey"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource = aws_kms_key.approval_topic[0].arn
      },
    ] : [])
  })
}

# --- IAM Role: CodeBuild service role ---

resource "aws_iam_role" "codebuild" {
  count = local.codepipeline_enabled ? 1 : 0
  name  = "TLZCodeBuildServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "codebuild.${local.dns_suffix}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "codebuild" {
  count = local.codepipeline_enabled ? 1 : 0
  name  = "TLZCodeBuildServiceRole-policy"
  role  = aws_iam_role.codebuild[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:log-group:/aws/codebuild/tlz-*"
      },
      {
        Sid    = "S3ArtifactAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetBucketVersioning",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.artifacts[0].arn,
          "${aws_s3_bucket.artifacts[0].arn}/*",
        ]
      },
      {
        Sid      = "AssumeDeploymentRoles"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = values(var.deployment_role_arns)
      },
      {
        Sid    = "SSMAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
        ]
        Resource = "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:parameter/tlz/*"
      },
      {
        Sid      = "STSGetCaller"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ]
  })
}

# The grant that makes codebuild_encryption_kms_key_arn usable. CodeBuild
# encrypts its build output with the SERVICE ROLE's credentials, so a
# customer-managed key without these five operations produces two projects that
# plan and apply cleanly and then fail every build at artifact upload. Its own
# resource, present only while a key is named, so the policy above stays the
# same document for every deployment that does not use a key.
resource "aws_iam_role_policy" "codebuild_encryption_kms" {
  count = local.codepipeline_enabled && var.codebuild_encryption_kms_key_arn != "" ? 1 : 0

  name = "TLZCodeBuildServiceRole-encryption-kms"
  role = aws_iam_role.codebuild[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BuildOutputEncryption"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo",
        ]
        Resource = var.codebuild_encryption_kms_key_arn
      },
    ]
  })
}

# --- CodeBuild Projects ---

resource "aws_codebuild_project" "plan" {
  count        = local.codepipeline_enabled ? 1 : 0
  name         = "tlz-terragrunt-plan"
  description  = "Terragrunt plan stage for Landing Zone"
  service_role = aws_iam_role.codebuild[0].arn

  # Empty leaves CodeBuild on the AWS-managed S3 key. A key named here is also granted to the service role
  # (aws_iam_role_policy.codebuild_encryption_kms), without which every build
  # fails when it uploads its artifact.
  encryption_key = var.codebuild_encryption_kms_key_arn != "" ? var.codebuild_encryption_kms_key_arn : null

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_MEDIUM"
    image           = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = false
  }

  # Explicit logging configuration. CloudWatch Logs with the service-managed
  # log group is CodeBuild's default behaviour; stating it makes the build
  # log destination part of the reviewed configuration instead of an implicit
  # service default.
  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }
  }

  source {
    type = "CODEPIPELINE"
    # Terragrunt is pinned to an exact release and its binary is verified
    # against the SHA256 the release itself publishes before it is made
    # executable — see the header comment above install for why: the plan
    # stage's role can assume every deployment_role_arns entry
    # (aws_iam_role_policy.codebuild, Sid AssumeDeploymentRoles), so an
    # unpinned "latest" download here is a mutable third-party binary running
    # with account-provisioning reach. Same precedent as .gitlab-ci.yml's
    # Terraform install (version variable + SHA256SUMS, checksum verified
    # before use).
    buildspec = <<-YAML
      version: 0.2
      phases:
        install:
          commands:
            - TERRAGRUNT_VERSION=v1.1.6
            - TERRAGRUNT_SHA256=d75a80bb264758ba00dabcb17f4b507fcdab4ca90d9e41f96750df036bf69b04
            - curl -fsSL "https://github.com/gruntwork-io/terragrunt/releases/download/$${TERRAGRUNT_VERSION}/terragrunt_linux_amd64" -o /usr/local/bin/terragrunt
            - echo "$${TERRAGRUNT_SHA256}  /usr/local/bin/terragrunt" | sha256sum -c -
            - chmod +x /usr/local/bin/terragrunt
        build:
          commands:
            - terragrunt run --all -- plan -out=tfplan
      artifacts:
        files:
          - '**/*'
    YAML
  }
}

resource "aws_codebuild_project" "apply" {
  count        = local.codepipeline_enabled ? 1 : 0
  name         = "tlz-terragrunt-apply"
  description  = "Terragrunt apply stage for Landing Zone"
  service_role = aws_iam_role.codebuild[0].arn

  # Same knob and same grant as the plan project above.
  encryption_key = var.codebuild_encryption_kms_key_arn != "" ? var.codebuild_encryption_kms_key_arn : null

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_MEDIUM"
    image           = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = false
  }

  # Explicit logging configuration — same reasoning as on the plan project.
  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }
  }

  source {
    type = "CODEPIPELINE"
    # Same pin and verification as the plan project's buildspec above — this
    # stage's role carries the same AssumeDeploymentRoles grant and runs the
    # apply.
    buildspec = <<-YAML
      version: 0.2
      phases:
        install:
          commands:
            - TERRAGRUNT_VERSION=v1.1.6
            - TERRAGRUNT_SHA256=d75a80bb264758ba00dabcb17f4b507fcdab4ca90d9e41f96750df036bf69b04
            - curl -fsSL "https://github.com/gruntwork-io/terragrunt/releases/download/$${TERRAGRUNT_VERSION}/terragrunt_linux_amd64" -o /usr/local/bin/terragrunt
            - echo "$${TERRAGRUNT_SHA256}  /usr/local/bin/terragrunt" | sha256sum -c -
            - chmod +x /usr/local/bin/terragrunt
        build:
          commands:
            - terragrunt run --all -- apply tfplan
      artifacts:
        files:
          - '**/*'
    YAML
  }
}

# --- SNS Topic for Manual Approval ---

resource "aws_sns_topic" "approval" {
  count = local.codepipeline_enabled ? 1 : 0
  # SNS CreateTopic is an upsert (adopts an existing topic of this name) — see
  # var.approval_topic_name for why an apply-test must scope this.
  name = var.approval_topic_name
  # The customer-managed key only while EventBridge publishes here
  # (notifications.tf); otherwise the AWS managed key as before.
  kms_master_key_id = local.pipeline_notifications_enabled ? aws_kms_key.approval_topic[0].arn : "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "approval_email" {
  count     = local.codepipeline_enabled && var.approval_notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.approval[0].arn
  protocol  = "email"
  endpoint  = var.approval_notification_email
}

# --- CodePipeline ---

resource "aws_codepipeline" "this" {
  count    = local.codepipeline_enabled ? 1 : 0
  name     = "tlz-deployment-pipeline"
  role_arn = aws_iam_role.codepipeline[0].arn

  artifact_store {
    location = aws_s3_bucket.artifacts[0].bucket
    type     = "S3"
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        ConnectionArn    = var.source_connection_arn
        FullRepositoryId = var.repository_name
        BranchName       = var.branch_name
        # The connection detects pushes to BranchName and starts the pipeline.
        # This is the only trigger of this variant — no EventBridge rule.
        DetectChanges = "true"
      }
    }
  }

  stage {
    name = "Plan"

    action {
      name             = "TerragruntPlan"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      output_artifacts = ["plan_output"]

      configuration = {
        ProjectName = aws_codebuild_project.plan[0].name
      }
    }
  }

  stage {
    name = "Approve"

    action {
      name     = "ManualApproval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"

      configuration = {
        NotificationArn = aws_sns_topic.approval[0].arn
        CustomData      = "Review the Terragrunt plan output before applying changes."
      }
    }
  }

  stage {
    name = "Apply"

    action {
      name            = "TerragruntApply"
      category        = "Build"
      owner           = "AWS"
      provider        = "CodeBuild"
      version         = "1"
      input_artifacts = ["plan_output"]

      configuration = {
        ProjectName = aws_codebuild_project.apply[0].name
      }
    }
  }
}

# --- Trigger ---
#
# There is no EventBridge rule for this variant. The source action is a
# CodeStar/CodeConnections connection, and the connection itself detects pushes
# to the configured branch (DetectChanges = true in the Source stage above).
# A CodeCommit-based EventBridge rule would never match, because a repository
# reached through a connection does not emit "CodeCommit Repository State
# Change" events.
