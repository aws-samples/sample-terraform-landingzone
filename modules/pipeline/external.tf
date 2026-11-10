# Pipeline Module — External CI variant (GitHub Actions / GitLab CI)
# Created only when pipeline_type == "external"
# Resources: IAM OIDC provider, OIDC role with trust policy

locals {
  oidc_provider_urls = {
    github = "https://token.actions.githubusercontent.com"
    gitlab = "https://gitlab.com"
  }
  oidc_provider_url = lookup(local.oidc_provider_urls, var.external_ci_provider, "")
}

# --- IAM OIDC Provider ---

resource "aws_iam_openid_connect_provider" "external_ci" {
  count = var.pipeline_type == "external" ? 1 : 0

  url             = local.oidc_provider_url
  client_id_list  = var.external_ci_audiences
  thumbprint_list = var.external_ci_thumbprint != "" ? [var.external_ci_thumbprint] : []
}

# --- IAM Role: OIDC-federated Pipeline_Role ---

resource "aws_iam_role" "oidc" {
  count = var.pipeline_type == "external" ? 1 : 0
  name  = "TLZExternalCIRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.external_ci[0].arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(local.oidc_provider_url, "https://", "")}:aud" = var.external_ci_audiences
          }
          StringLike = {
            "${replace(local.oidc_provider_url, "https://", "")}:sub" = var.external_ci_provider == "github" ? "repo:${var.repository_name}:ref:refs/heads/${var.branch_name}" : "project_path:${var.repository_name}:ref_type:branch:ref:${var.branch_name}"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "oidc_assume" {
  count = var.pipeline_type == "external" ? 1 : 0
  name  = "TLZExternalCIRole-assume-deployment-roles"
  role  = aws_iam_role.oidc[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
