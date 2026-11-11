variable "account_name" {
  description = "Name of the member account the provider points at (a key of the accounts stack's account map)."
  type        = string
}

variable "account_id" {
  description = "12-digit ID of the member account the provider points at."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "account_ou_id" {
  description = "ID of the organizational unit the account sits in. Empty when unknown: then only the account name or ID can select it."
  type        = string
  default     = ""
}

variable "ou_name_to_id" {
  description = "OU name to OU ID map of the organization; resolves an OU name in deployment_targets."
  type        = map(string)
  default     = {}
}

variable "account_ou_names" {
  description = "Names of the account's OU and of every OU above it. A deployment target naming one of them selects the account, so an OU target reaches the accounts of its nested OUs. Empty: only the OU of account_ou_id selects it."
  type        = list(string)
  default     = []
}

variable "partition" {
  description = "AWS partition of the deployment (aws or aws-eusc); expands partition-neutral managed policy names."
  type        = string
  default     = "aws"

  validation {
    condition     = contains(["aws", "aws-eusc"], var.partition)
    error_message = "partition must be aws or aws-eusc."
  }
}

variable "roles" {
  description = "IAM role definitions, the same list the iam stack reads. A role is created in this account when one of its deployment_targets is the account's name, its ID, the name of its OU or of an OU above it; a role without deployment_targets is never created here. customer_managed_policy_names and a permissions_boundary given by name refer to customer_managed_policies created in the same account."
  type = list(object({
    name                          = string
    assume_role_policy            = string # JSON-String
    path                          = optional(string, "/")
    max_session_duration          = optional(number, 3600)
    managed_policy_arns           = optional(list(string), [])
    customer_managed_policy_names = optional(list(string), [])
    permissions_boundary          = optional(string, null)
    instance_profile              = optional(bool, false)
    inline_policies = optional(list(object({
      name   = string
      policy = string # JSON-String
    })), [])
    deployment_targets = optional(list(string), [])
  }))
  default = []

  validation {
    condition     = alltrue([for role in var.roles : can(regex("^[a-zA-Z0-9+=,.@_-]+$", role.name))])
    error_message = "Role name must contain only alphanumeric characters and +=,.@_- characters."
  }
}

variable "customer_managed_policies" {
  description = "Customer-managed IAM policy definitions, the same list the iam stack reads. A policy is created in this account under the same deployment_targets rule as a role."
  type = list(object({
    name               = string
    policy             = string # JSON-String
    deployment_targets = optional(list(string), [])
  }))
  default = []
}
