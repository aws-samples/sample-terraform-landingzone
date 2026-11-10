output "budget_id" {
  description = "ID of the primary budget (empty string when budgets are disabled or when this deployment does not carry the primary budget)"
  value       = contains(keys(aws_budgets_budget.this), "this") ? aws_budgets_budget.this["this"].id : ""
}

output "budget_ids" {
  description = "Map of budget key (this for the primary budget, additional-<name> for further budgets) to budget ID for every budget this deployment creates"
  value       = { for key, budget in aws_budgets_budget.this : key => budget.id }
}
