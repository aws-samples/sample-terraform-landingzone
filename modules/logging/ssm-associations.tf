# =============================================================================
# SSM Associations — Inventory
# =============================================================================
# Creates SSM State Manager associations for automated inventory collection.

resource "aws_ssm_association" "this" {
  for_each = { for assoc in var.ssm_associations : assoc.name => assoc }

  name                = each.value.name
  schedule_expression = each.value.schedule_expression

  dynamic "targets" {
    for_each = each.value.targets
    content {
      key    = targets.value.key
      values = targets.value.values
    }
  }
}
