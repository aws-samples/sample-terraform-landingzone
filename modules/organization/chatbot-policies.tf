# --- Chatbot Policies ---

resource "aws_organizations_policy" "chatbot" {
  for_each = {
    for policy in var.chatbot_policies :
    policy.name => policy
  }

  name        = each.value.name
  description = each.value.description
  type        = "CHATBOT_POLICY"
  content     = each.value.content

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "chatbot" {
  for_each = {
    for att in local.chatbot_policy_attachments :
    att.key => att
  }

  policy_id = aws_organizations_policy.chatbot[each.value.policy].id
  target_id = lookup(local.target_name_to_id, each.value.target, each.value.target)
}
