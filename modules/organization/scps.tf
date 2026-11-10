# --- Service Control Policies (SCPs) ---

locals {
  # AWS-managed policies are attached by their well-known, partition-stable
  # IDs — AWS owns the document, so no aws_organizations_policy is created.
  aws_managed_scp_ids = {
    FullAWSAccess = "p-FullAWSAccess"
  }
}

resource "aws_organizations_policy" "scp" {
  for_each = {
    for scp in var.service_control_policies :
    scp.name => scp
    if scp.type == "customer-managed"
  }

  name        = each.value.name
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.content

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "scp" {
  for_each = {
    for att in local.scp_attachments :
    att.key => att
  }

  policy_id = (
    each.value.aws_managed
    ? local.aws_managed_scp_ids[each.value.policy]
    : aws_organizations_policy.scp[each.value.policy].id
  )
  target_id = lookup(local.target_name_to_id, each.value.target, each.value.target)

  lifecycle {
    # Hard quota: at most 5 SCPs directly attached per target (scp-quota.tf).
    # Rejecting the plan here keeps the API from attaching part of the set
    # and then failing on the sixth policy.
    precondition {
      condition     = local.scp_attachment_count_by_target[each.value.target] <= local.scp_attachments_per_target_quota
      error_message = local.scp_quota_error
    }
  }
}

# --- Pipeline SCP: Protect Deployment_Role and Pipeline_Role ---
# When enable_pipeline_scp is true, creates an SCP that denies modification
# of the protected IAM roles. Exempt are principals of the Management Account
# (aws:PrincipalAccount) and the AWSControlTowerExecution role — the IaC path
# that manages these roles in member accounts. A ":root" PrincipalArn
# exemption would match no principal the SCP applies to: that ARN is only
# carried by a member account's own root user, and SCPs never apply to the
# Management Account itself.

resource "aws_organizations_policy" "pipeline_scp" {
  count = var.enable_pipeline_scp ? 1 : 0

  name        = "TLZPipelineRoleProtection"
  description = "Deny modification of TLZ Deployment and Pipeline roles"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/pipeline-scp.json", {
    arn_prefix            = local.arn_prefix
    deployment_role_name  = var.pipeline_scp_config.deployment_role_name
    pipeline_role_name    = var.pipeline_scp_config.pipeline_role_name
    management_account_id = var.pipeline_scp_config.management_account_id
  })))

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "pipeline_scp" {
  count = var.enable_pipeline_scp ? 1 : 0

  policy_id = aws_organizations_policy.pipeline_scp[0].id
  target_id = var.pipeline_scp_config.infrastructure_ou_id

  lifecycle {
    # Hard quota: at most 5 SCPs directly attached per target (scp-quota.tf).
    # The pipeline SCP counts toward the quota of its infrastructure OU.
    precondition {
      condition     = local.scp_attachment_count_by_target[var.pipeline_scp_config.infrastructure_ou_id] <= local.scp_attachments_per_target_quota
      error_message = local.scp_quota_error
    }
  }
}

# --- Plan-time warning: created SCP without any target ---
# A customer-managed SCP with targets = [] exists as an unattached shell and
# restricts no account. Compliance framework configurations ship their SCPs
# this way on purpose: attaching a guardrail to an OU is a deliberate
# operator decision, so the module warns instead of picking targets itself.

locals {
  scps_without_targets = [
    for scp in var.service_control_policies : scp.name
    if scp.type == "customer-managed" && length(scp.targets) == 0
  ]
}

check "scp_without_targets" {
  assert {
    condition = length(local.scps_without_targets) == 0
    error_message = format(
      "SCP(s) created without any target — the policy exists but restricts no account: %s. Add OU names or account IDs to each entry's targets to attach it. See docs/compliance-configurations.md (Framework SCPs Require Targets).",
      join(", ", local.scps_without_targets)
    )
  }
}
