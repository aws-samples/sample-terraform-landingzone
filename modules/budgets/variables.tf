variable "enable_budgets" {
  description = "Enable AWS Budgets for cost monitoring and alerting"
  type        = bool
  default     = false
}

variable "budget_config" {
  description = "Primary AWS Budget with thresholds, notification targets, cost-type filters and distribution targets. The eleven cost-type attributes select which charges count toward the budget; unset (null) attributes leave the account defaults untouched. deployment_targets lists the stack directory names of further accounts whose budgets stack unit creates this budget as well."
  type = object({
    name         = optional(string, "tlz-monthly-budget")
    limit_amount = optional(string, "1000")
    limit_unit   = optional(string, "USD")
    time_unit    = optional(string, "MONTHLY")
    budget_type  = optional(string, "COST")
    notifications = optional(list(object({
      comparison_operator        = optional(string, "GREATER_THAN")
      threshold                  = number
      threshold_type             = optional(string, "PERCENTAGE")
      notification_type          = optional(string, "ACTUAL")
      subscriber_email_addresses = optional(list(string), [])
      subscriber_sns_topic_arns  = optional(list(string), [])
    })), [])
    include_credit             = optional(bool)
    include_discount           = optional(bool)
    include_other_subscription = optional(bool)
    include_recurring          = optional(bool)
    include_refund             = optional(bool)
    include_subscription       = optional(bool)
    include_support            = optional(bool)
    include_tax                = optional(bool)
    include_upfront            = optional(bool)
    use_amortized              = optional(bool)
    use_blended                = optional(bool)
    deployment_targets         = optional(list(string), [])
  })
  default = {}

  validation {
    condition     = contains(["MONTHLY", "QUARTERLY", "ANNUALLY"], var.budget_config.time_unit)
    error_message = "budget_config.time_unit must be MONTHLY, QUARTERLY, or ANNUALLY."
  }

  validation {
    condition     = contains(["COST", "USAGE", "RI_UTILIZATION", "RI_COVERAGE", "SAVINGS_PLANS_UTILIZATION", "SAVINGS_PLANS_COVERAGE"], var.budget_config.budget_type)
    error_message = "budget_config.budget_type must be one of: COST, USAGE, RI_UTILIZATION, RI_COVERAGE, SAVINGS_PLANS_UTILIZATION, SAVINGS_PLANS_COVERAGE."
  }

  # The Budgets API refuses CostTypes with both UseAmortized and UseBlended —
  # the two are alternative views of the same charge. Rejecting the pair here
  # turns an apply-time API error into a plan-time message.
  validation {
    condition     = !(coalesce(var.budget_config.use_amortized, false) && coalesce(var.budget_config.use_blended, false))
    error_message = "budget_config must not set use_amortized and use_blended together — the Budgets API rejects the combination."
  }

  # Distribution runs over the per-account stack units, which select
  # themselves by comparing their directory name against this list. A name
  # that cannot be a stack directory (uppercase, spaces, padding) would
  # silently never match, so the shape is enforced at plan time.
  validation {
    condition = alltrue([
      for t in var.budget_config.deployment_targets :
      can(regex("^[a-z0-9][a-z0-9-]*$", t))
    ])
    error_message = "Each budget_config.deployment_targets entry must be a stack directory name: lowercase letters, digits and hyphens (e.g. workload-dev)."
  }

  validation {
    condition     = length(distinct(var.budget_config.deployment_targets)) == length(var.budget_config.deployment_targets)
    error_message = "budget_config.deployment_targets entries must be unique."
  }

  # The Budgets API refuses a notification without a delivery target
  # ("Budget notification must have at least one subscriber") — and it refuses
  # it only after CreateBudget has already succeeded, leaving a real budget and
  # a tainted state entry behind. Rejecting it here turns that half-applied
  # failure into a plan-time message.
  validation {
    condition = alltrue([
      for n in var.budget_config.notifications :
      length(n.subscriber_email_addresses) + length(n.subscriber_sns_topic_arns) > 0
    ])
    error_message = "Each budget_config.notifications entry needs at least one subscriber_email_addresses or subscriber_sns_topic_arns entry — the Budgets API rejects a threshold without a subscriber."
  }
}

variable "additional_budgets" {
  description = "Further AWS Budgets beside the primary budget_config. Each entry carries the same attributes as budget_config; name is required and keys the resource. Entries without deployment_targets are created by the management deployment; entries with deployment_targets are created by the budgets stack units of the listed accounts (directory names, plus the literal management for the management account)."
  type = list(object({
    name         = string
    limit_amount = optional(string, "1000")
    limit_unit   = optional(string, "USD")
    time_unit    = optional(string, "MONTHLY")
    budget_type  = optional(string, "COST")
    notifications = optional(list(object({
      comparison_operator        = optional(string, "GREATER_THAN")
      threshold                  = number
      threshold_type             = optional(string, "PERCENTAGE")
      notification_type          = optional(string, "ACTUAL")
      subscriber_email_addresses = optional(list(string), [])
      subscriber_sns_topic_arns  = optional(list(string), [])
    })), [])
    include_credit             = optional(bool)
    include_discount           = optional(bool)
    include_other_subscription = optional(bool)
    include_recurring          = optional(bool)
    include_refund             = optional(bool)
    include_subscription       = optional(bool)
    include_support            = optional(bool)
    include_tax                = optional(bool)
    include_upfront            = optional(bool)
    use_amortized              = optional(bool)
    use_blended                = optional(bool)
    deployment_targets         = optional(list(string), [])
  }))
  default = []

  # The budget name keys the resource map — an empty name would collide with
  # nothing visible and a duplicate would silently drop one budget.
  validation {
    condition     = alltrue([for b in var.additional_budgets : length(b.name) > 0])
    error_message = "Each additional_budgets entry needs a non-empty name."
  }

  validation {
    condition     = length(distinct([for b in var.additional_budgets : b.name])) == length(var.additional_budgets)
    error_message = "additional_budgets names must be unique — the module keys its budgets by name and a duplicate would silently drop one entry."
  }

  validation {
    condition     = alltrue([for b in var.additional_budgets : contains(["MONTHLY", "QUARTERLY", "ANNUALLY"], b.time_unit)])
    error_message = "Each additional_budgets time_unit must be MONTHLY, QUARTERLY, or ANNUALLY."
  }

  validation {
    condition     = alltrue([for b in var.additional_budgets : contains(["COST", "USAGE", "RI_UTILIZATION", "RI_COVERAGE", "SAVINGS_PLANS_UTILIZATION", "SAVINGS_PLANS_COVERAGE"], b.budget_type)])
    error_message = "Each additional_budgets budget_type must be one of: COST, USAGE, RI_UTILIZATION, RI_COVERAGE, SAVINGS_PLANS_UTILIZATION, SAVINGS_PLANS_COVERAGE."
  }

  # Same API constraint as on budget_config: amortized and blended views are
  # mutually exclusive.
  validation {
    condition = alltrue([
      for b in var.additional_budgets :
      !(coalesce(b.use_amortized, false) && coalesce(b.use_blended, false))
    ])
    error_message = "No additional_budgets entry may set use_amortized and use_blended together — the Budgets API rejects the combination."
  }

  validation {
    condition = alltrue([
      for b in var.additional_budgets : alltrue([
        for t in b.deployment_targets :
        can(regex("^[a-z0-9][a-z0-9-]*$", t))
      ])
    ])
    error_message = "Each additional_budgets deployment_targets entry must be a stack directory name: lowercase letters, digits and hyphens (e.g. workload-dev), or the literal management."
  }

  validation {
    condition = alltrue([
      for b in var.additional_budgets :
      length(distinct(b.deployment_targets)) == length(b.deployment_targets)
    ])
    error_message = "additional_budgets deployment_targets entries must be unique per budget."
  }

  # Same API constraint as on budget_config: a notification without a
  # delivery target is rejected only after CreateBudget succeeded, leaving a
  # tainted half-created budget behind. Reject it at plan time instead.
  validation {
    condition = alltrue([
      for b in var.additional_budgets : alltrue([
        for n in b.notifications :
        length(n.subscriber_email_addresses) + length(n.subscriber_sns_topic_arns) > 0
      ])
    ])
    error_message = "Each additional_budgets notifications entry needs at least one subscriber_email_addresses or subscriber_sns_topic_arns entry — the Budgets API rejects a threshold without a subscriber."
  }
}

variable "deployment_account_name" {
  description = "Stack directory name of the account this deployment runs in. Empty means the management deployment: it creates the primary budget and every budget without deployment targets. A member-account budgets unit passes its directory name and creates exactly the budgets whose deployment_targets list it."
  type        = string
  default     = ""

  validation {
    condition     = var.deployment_account_name == "" || can(regex("^[a-z0-9][a-z0-9-]*$", var.deployment_account_name))
    error_message = "deployment_account_name must be empty (management deployment) or a stack directory name: lowercase letters, digits and hyphens."
  }
}

variable "default_tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default     = {}

  # AWS tag limits: key 1-128 characters, value up to 256, and the reserved
  # prefix "aws:" is refused by the API. Validating here turns an apply-time
  # rejection into a plan-time message that names the offending key.
  validation {
    condition = alltrue([
      for k, v in var.default_tags :
      length(k) >= 1 && length(k) <= 128 && length(v) <= 256 && !startswith(lower(k), "aws:")
    ])
    error_message = "Each default_tags key must be 1-128 characters, each value at most 256 characters, and no key may start with the reserved prefix \"aws:\"."
  }
}
