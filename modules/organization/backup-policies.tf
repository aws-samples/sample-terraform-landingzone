# --- Backup Policies ---

resource "aws_organizations_policy" "backup" {
  for_each = {
    for policy in var.backup_policies :
    policy.name => policy
  }

  name        = each.value.name
  description = each.value.description
  type        = "BACKUP_POLICY"
  content     = each.value.content

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "backup" {
  for_each = {
    for att in local.backup_policy_attachments :
    att.key => att
  }

  policy_id = aws_organizations_policy.backup[each.value.policy].id
  target_id = lookup(local.target_name_to_id, each.value.target, each.value.target)
}
