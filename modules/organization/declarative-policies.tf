# --- Declarative Policies ---

resource "aws_organizations_policy" "declarative" {
  for_each = {
    for policy in var.declarative_policies :
    policy.name => policy
  }

  name        = each.value.name
  description = each.value.description
  type        = "DECLARATIVE_POLICY_EC2"
  content     = each.value.content

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "declarative" {
  for_each = {
    for att in local.declarative_policy_attachments :
    att.key => att
  }

  policy_id = aws_organizations_policy.declarative[each.value.policy].id
  target_id = lookup(local.target_name_to_id, each.value.target, each.value.target)
}
