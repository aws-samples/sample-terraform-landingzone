# --- Resource Control Policies ---

resource "aws_organizations_policy" "rcp" {
  for_each = {
    for policy in var.resource_control_policies :
    policy.name => policy
  }

  name        = each.value.name
  description = each.value.description
  type        = "RESOURCE_CONTROL_POLICY"
  content     = each.value.content

  depends_on = [aws_organizations_organization.this]
}

# A dropped RCP is a warning, not a refusal: a new organization has no ID
# before its first apply, so a refusal would block exactly that apply.
check "rcp_documents_unresolved" {
  assert {
    condition = length(var.unresolved_resource_control_policies) == 0
    error_message = join(" ", [
      "Resource control policies [${join(", ", var.unresolved_resource_control_policies)}] are NOT created:",
      "their document still carries an unresolved @@marker@@.",
      "Set import_organization_id in env/common.hcl (the organization_id output of this stack)",
      "and log_archive_account_id in env/accounts.hcl, then apply this stack again.",
    ])
  }
}

resource "aws_organizations_policy_attachment" "rcp" {
  for_each = {
    for att in local.rcp_attachments :
    att.key => att
  }

  policy_id = aws_organizations_policy.rcp[each.value.policy].id
  target_id = lookup(local.target_name_to_id, each.value.target, each.value.target)
}
