# Minimum interface variables — every custom module declares these three
# (customizations/_template). The module's own inputs follow below.

variable "region" {
  description = "AWS region"
  type        = string
  # No default — this is required and passed by Terragrunt
}

variable "default_tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default     = {}
}

variable "account_ids" {
  description = "Map of account name to account ID"
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for id in values(var.account_ids) :
      length(id) == 12 && can(regex("^[0-9]+$", id))
    ])
    error_message = "Each account_ids value must be a 12-digit AWS account ID."
  }
}

variable "ou_name_to_id" {
  description = "Map of OU name to OU ID, supplied by the organization stack. Resolves organizational_units entries given as names; entries that are already ou-/r- IDs pass through unchanged."
  type        = map(string)
  default     = {}
}

# --- User-defined CloudFormation stacks ---

variable "cloudformation_stacks" {
  description = "User-defined CloudFormation stacks in the current account and region. template_body carries the template as a string — the stack layer reads it from the configuration (inline or via file path). An empty list creates nothing."
  type = list(object({
    name              = string
    template_body     = string
    parameters        = optional(map(string), {})
    capabilities      = optional(list(string), [])
    notification_arns = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for s in var.cloudformation_stacks :
      can(regex("^[A-Za-z][A-Za-z0-9-]{0,127}$", s.name))
    ])
    error_message = "Each cloudformation_stacks name must start with a letter and contain only alphanumeric characters and hyphens (max 128, no spaces) — the CloudFormation stack name rules."
  }

  validation {
    condition     = length(distinct([for s in var.cloudformation_stacks : s.name])) == length(var.cloudformation_stacks)
    error_message = "cloudformation_stacks names must be unique — duplicate names collide at the CloudFormation API."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stacks :
      length(trimspace(s.template_body)) > 0
    ])
    error_message = "Each cloudformation_stacks template_body must be a non-empty template string — an empty template deploys nothing and fails only at the API."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stacks : alltrue([
        for c in s.capabilities :
        contains(["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"], c)
      ])
    ])
    error_message = "Each cloudformation_stacks capabilities entry must be one of: CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_AUTO_EXPAND."
  }
}

# --- User-defined CloudFormation StackSets ---

variable "cloudformation_stack_sets" {
  description = "User-defined CloudFormation StackSets. permission_model SERVICE_MANAGED (default) targets organizational_units (names or ou-/r- IDs) with optional auto-deployment on account join and an optional excluded_account_ids filter; SELF_MANAGED targets target_account_ids through the StackSet roles of modules/iam (enable_stackset_roles). regions defaults to the deployment region. An empty list creates nothing."
  type = list(object({
    name                             = string
    description                      = optional(string, "")
    template_body                    = string
    parameters                       = optional(map(string), {})
    capabilities                     = optional(list(string), [])
    permission_model                 = optional(string, "SERVICE_MANAGED")
    auto_deployment_enabled          = optional(bool, true)
    retain_stacks_on_account_removal = optional(bool, false)
    organizational_units             = optional(list(string), [])
    excluded_account_ids             = optional(list(string), [])
    target_account_ids               = optional(list(string), [])
    regions                          = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for s in var.cloudformation_stack_sets :
      can(regex("^[A-Za-z][A-Za-z0-9-]{0,127}$", s.name))
    ])
    error_message = "Each cloudformation_stack_sets name must start with a letter and contain only alphanumeric characters and hyphens (max 128, no spaces) — the CloudFormation StackSet name rules."
  }

  validation {
    condition     = length(distinct([for s in var.cloudformation_stack_sets : s.name])) == length(var.cloudformation_stack_sets)
    error_message = "cloudformation_stack_sets names must be unique — duplicate names collide at the CloudFormation API."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stack_sets :
      length(trimspace(s.template_body)) > 0
    ])
    error_message = "Each cloudformation_stack_sets template_body must be a non-empty template string — an empty template deploys nothing and fails only at the API."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stack_sets : alltrue([
        for c in s.capabilities :
        contains(["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"], c)
      ])
    ])
    error_message = "Each cloudformation_stack_sets capabilities entry must be one of: CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_AUTO_EXPAND."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stack_sets :
      contains(["SERVICE_MANAGED", "SELF_MANAGED"], s.permission_model)
    ])
    error_message = "Each cloudformation_stack_sets permission_model must be SERVICE_MANAGED or SELF_MANAGED."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stack_sets :
      s.permission_model != "SERVICE_MANAGED" || (length(s.organizational_units) > 0 && length(s.target_account_ids) == 0)
    ])
    error_message = "A SERVICE_MANAGED entry deploys to organizational units: organizational_units must name at least one OU and target_account_ids must stay empty (accounts are excluded via excluded_account_ids)."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stack_sets :
      s.permission_model != "SELF_MANAGED" || (length(s.target_account_ids) > 0 && length(s.organizational_units) == 0 && length(s.excluded_account_ids) == 0)
    ])
    error_message = "A SELF_MANAGED entry deploys to accounts through the StackSet roles: target_account_ids must name at least one account, organizational_units and excluded_account_ids must stay empty (the account filter is a service-managed feature)."
  }

  validation {
    condition = alltrue([
      for s in var.cloudformation_stack_sets : alltrue([
        for id in concat(s.excluded_account_ids, s.target_account_ids) :
        can(regex("^[0-9]{12}$", id))
      ])
    ])
    error_message = "Each excluded_account_ids and target_account_ids entry must be a 12-digit AWS account ID."
  }
}
