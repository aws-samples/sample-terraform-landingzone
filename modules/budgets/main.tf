# modules/budgets — AWS Budgets for cost monitoring and alerting

locals {
  # Every budget of this configuration under a stable state key: the primary
  # budget keeps the historical key "this" (state continuity), additional
  # budgets are keyed by their name behind an "additional-" prefix so no user
  # name can collide with the primary key.
  all_budgets = merge(
    { this = var.budget_config },
    { for b in var.additional_budgets : "additional-${b.name}" => b }
  )

  # Which budgets THIS deployment creates. The management deployment (empty
  # deployment_account_name) always carries the primary budget and every
  # budget that names no targets or lists the literal "management"; a
  # member-account budgets unit creates exactly the budgets whose
  # deployment_targets list its directory name. Budgets are account-scoped
  # resources, so distribution to further accounts runs over the per-account
  # stack units (stacks/<account>/budgets), never over a second provider.
  effective_budgets = var.enable_budgets ? {
    for key, budget in local.all_budgets : key => budget
    if var.deployment_account_name == "" ? (
      key == "this"
      || length(budget.deployment_targets) == 0
      || contains(budget.deployment_targets, "management")
    ) : contains(budget.deployment_targets, var.deployment_account_name)
  } : {}

  # A budget renders a cost_types block only when at least one of the eleven
  # cost-type attributes is set — a configuration without them plans no
  # cost_types block at all.
  budget_cost_types_set = {
    for key, budget in local.all_budgets : key => anytrue([
      for value in [
        budget.include_credit,
        budget.include_discount,
        budget.include_other_subscription,
        budget.include_recurring,
        budget.include_refund,
        budget.include_subscription,
        budget.include_support,
        budget.include_tax,
        budget.include_upfront,
        budget.use_amortized,
        budget.use_blended,
      ] : value != null
    ])
  }
}

resource "aws_budgets_budget" "this" {
  for_each = local.effective_budgets

  name         = each.value.name
  budget_type  = each.value.budget_type
  limit_amount = each.value.limit_amount
  limit_unit   = each.value.limit_unit
  time_unit    = each.value.time_unit

  # Cost-type filters: which charges count toward the budget. Unset
  # attributes fall back to the API defaults (include everything, use the
  # unblended view) so a partially specified block never flips an unrelated
  # filter.
  dynamic "cost_types" {
    for_each = local.budget_cost_types_set[each.key] ? [each.value] : []
    content {
      include_credit             = coalesce(cost_types.value.include_credit, true)
      include_discount           = coalesce(cost_types.value.include_discount, true)
      include_other_subscription = coalesce(cost_types.value.include_other_subscription, true)
      include_recurring          = coalesce(cost_types.value.include_recurring, true)
      include_refund             = coalesce(cost_types.value.include_refund, true)
      include_subscription       = coalesce(cost_types.value.include_subscription, true)
      include_support            = coalesce(cost_types.value.include_support, true)
      include_tax                = coalesce(cost_types.value.include_tax, true)
      include_upfront            = coalesce(cost_types.value.include_upfront, true)
      use_amortized              = coalesce(cost_types.value.use_amortized, false)
      use_blended                = coalesce(cost_types.value.use_blended, false)
    }
  }

  dynamic "notification" {
    for_each = each.value.notifications
    content {
      comparison_operator        = notification.value.comparison_operator
      threshold                  = notification.value.threshold
      threshold_type             = notification.value.threshold_type
      notification_type          = notification.value.notification_type
      subscriber_email_addresses = notification.value.subscriber_email_addresses
      subscriber_sns_topic_arns  = notification.value.subscriber_sns_topic_arns
    }
  }

  # The budget carries the landing zone tags like every other resource: in the
  # pinned provider (hashicorp/aws ~> 6.0) the aws_budgets_budget schema
  # declares tags and tags_all.
  tags = var.default_tags
}

# --- Cross-account distribution reminder ---
# Terraform cannot verify from here that a budgets stack unit exists for every
# listed account — the units are separate Terragrunt configurations. The check
# reminds the management deployment of the contract; the member units
# themselves stay silent because their presence is the proof.

check "budget_cross_account_deployment_warning" {
  assert {
    condition = var.deployment_account_name != "" || alltrue([
      for key, budget in local.all_budgets : length(budget.deployment_targets) == 0
    ])
    error_message = "Budget deployment targets are configured. Each listed account receives its budgets only through its own budgets stack unit (stacks/<account>/budgets, self-selecting on deployment_targets — copy the workload-dev unit). Verify such a unit exists for every listed directory name; an entry without a unit is silently ignored."
  }
}
