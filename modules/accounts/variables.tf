variable "accounts" {
  description = "List of accounts to create"
  type = list(object({
    name                       = string
    email                      = string
    organizational_unit_id     = optional(string)
    organizational_unit_name   = optional(string)
    description                = optional(string, "")
    iam_user_access_to_billing = optional(string, "DENY")
    tags                       = optional(map(string), {})
    sso = optional(object({
      principal_type      = optional(string)
      principal_name      = optional(string)
      permission_set_name = optional(string)
    }))
    sso_user_email      = optional(string)
    sso_user_first_name = optional(string)
    sso_user_last_name  = optional(string)
    # GovCloud account linking:
    # - The Terraform AWS provider aws_organizations_account does not support
    #   direct GovCloud account creation (verified: provider ~> 6.x).
    # - GovCloud linking requires the commercial account to exist first.
    # - The linked GovCloud account is a separate account with its own ID.
    # - Use AWS CLI: aws organizations create-gov-cloud-account
    enable_govcloud = optional(bool, false)
    # Warm account lifecycle:
    # 1. Creation: account is created in AWS Organizations with warm = true
    # 2. Warm state: account exists but skips security/networking configuration
    # 3. Promotion: set warm = false to include account in all downstream modules
    # 4. Cold state: account has full security, networking, and compliance config
    warm = optional(bool, false)
  }))

  validation {
    condition = alltrue([
      for acct in var.accounts :
      acct.organizational_unit_id != null || acct.organizational_unit_name != null
    ])
    error_message = "Each account requires either organizational_unit_id or organizational_unit_name."
  }

  validation {
    condition = alltrue([
      for acct in var.accounts :
      contains(["ALLOW", "DENY"], acct.iam_user_access_to_billing)
    ])
    error_message = "iam_user_access_to_billing must be either ALLOW or DENY."
  }
}

variable "enable_control_tower_enrollment" {
  description = "Enable check block guidance for enrolling accounts in AWS Control Tower after creation"
  type        = bool
  default     = false
}

variable "ou_name_to_id" {
  description = "External OU name → ID map (from organization module). Falls back to data source if empty."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name, id in var.ou_name_to_id :
      can(regex("^ou-[a-z0-9]+-[a-z0-9]+$", id))
    ])
    error_message = "Each OU ID must match the format ou-xxxx-xxxxxxxx."
  }
}

variable "organization_root_id" {
  description = "ID of the organization root (used for OU name resolution). Empty = auto-resolve via data source."
  type        = string
  default     = ""

  validation {
    condition     = var.organization_root_id == "" || can(regex("^r-[a-z0-9]+$", var.organization_root_id))
    error_message = "organization_root_id must be empty or match the format r-xxxx."
  }
}

variable "account_access_role_name" {
  description = "Name of the cross-account role this module's deployment-account provider and the stacks ASSUME to reach accounts that already exist (providers.tf, stacks/root.hcl, every cross_account.hcl). It is also the name CreateAccount gives the role inside a new member account while created_account_role_name is null."
  type        = string
  default     = "AWSControlTowerExecution"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]+$", var.account_access_role_name))
    error_message = "Role name must contain only alphanumeric characters and +=,.@_- characters."
  }

  validation {
    condition     = length(var.account_access_role_name) >= 1 && length(var.account_access_role_name) <= 64
    error_message = "account_access_role_name must be 1 to 64 characters long (the IAM role name limit); the name given is ${length(var.account_access_role_name)} characters."
  }
}

variable "created_account_role_name" {
  description = "Name of the role CreateAccount makes INSIDE each new member account (aws_organizations_account.role_name) — not the role this module assumes to reach existing accounts, which is account_access_role_name. null (the default) means the same name as account_access_role_name, so a configuration that sets only that one plans as before. Set it when the accounts this module creates should carry a different role than the one the stacks assume."
  type        = string
  default     = null

  validation {
    condition     = var.created_account_role_name == null || can(regex("^[a-zA-Z0-9+=,.@_-]+$", var.created_account_role_name))
    error_message = "created_account_role_name must be null or contain only alphanumeric characters and +=,.@_- characters."
  }

  validation {
    condition     = var.created_account_role_name == null || try(length(var.created_account_role_name) >= 1 && length(var.created_account_role_name) <= 64, false)
    error_message = "created_account_role_name must be null or 1 to 64 characters long (the IAM role name limit); the name given is ${var.created_account_role_name == null ? 0 : length(var.created_account_role_name)} characters."
  }
}

variable "close_on_deletion" {
  description = "Close the account on removal from Terraform"
  type        = bool
  default     = false
}

variable "management_account_alias" {
  description = "IAM account alias (sign-in URL name) for the management account — the account this stack runs in. An account carries at most one alias, and the alias must be unique across all of AWS. Empty (the default) sets none. Aliases for the accounts this module creates would each need their own provider configuration, which Terraform cannot produce per entry; they remain a per-account deployment concern."
  type        = string
  default     = ""

  validation {
    condition     = var.management_account_alias == "" || can(regex("^[a-z0-9](-?[a-z0-9])+$", var.management_account_alias)) && length(var.management_account_alias) >= 3 && length(var.management_account_alias) <= 63
    error_message = "management_account_alias must be empty or 3-63 characters of lowercase letters, digits and single hyphens, beginning and ending with a letter or digit — the IAM account alias rule."
  }
}

variable "default_tags" {
  description = "Tags applied to all accounts"
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

# --- SSO (IAM Identity Center) ---

variable "enable_sso_assignment" {
  description = "Assign an IAM Identity Center permission set to each created account"
  type        = bool
  default     = false
}

variable "sso_permission_set_name" {
  description = "Name of the IAM Identity Center permission set to assign"
  type        = string
  default     = "AWSAdministratorAccess"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,32}$", var.sso_permission_set_name))
    error_message = "sso_permission_set_name must be 1-32 characters of letters, digits, underscore or hyphen — the IAM Identity Center naming rule for permission sets."
  }
}

variable "sso_principal_type" {
  description = "Type of the SSO principal: GROUP or USER"
  type        = string
  default     = "GROUP"

  validation {
    condition     = contains(["GROUP", "USER"], var.sso_principal_type)
    error_message = "sso_principal_type must be GROUP or USER."
  }
}

variable "sso_principal_name" {
  description = "Display name of the SSO group or username of the SSO user to assign"
  type        = string
  default     = ""

  # The assignment is only created when the name is set, so the empty default
  # stays valid; a name with leading or trailing blanks silently matches no
  # Identity Center principal.
  validation {
    condition     = var.sso_principal_name == "" || (trimspace(var.sso_principal_name) == var.sso_principal_name && length(var.sso_principal_name) <= 256)
    error_message = "sso_principal_name must be empty or a principal name without leading or trailing whitespace and at most 256 characters."
  }
}

variable "enable_account_warming" {
  description = "Enable warm account lifecycle. When true, accounts with warm = true are created but skip security/networking configuration, and the module publishes the account-warming runbook (SSM Automation document tlz-account-warming) shared to every warm-marked account. When false, the warm field is ignored and all accounts are fully configured."
  type        = bool
  default     = false
}

# --- Deployment Account ---

variable "enable_deployment_account" {
  description = "When true, SSM parameters are written to the Deployment Account instead of the Management Account"
  type        = bool
  default     = false
}

variable "deployment_account_id" {
  description = "Account ID of the Deployment Account (required when enable_deployment_account is true)"
  type        = string
  default     = ""

  validation {
    condition     = var.deployment_account_id == "" || can(regex("^[0-9]{12}$", var.deployment_account_id))
    error_message = "deployment_account_id must be empty or a 12-digit AWS account ID."
  }
}

variable "region" {
  description = "AWS region for the deployment provider alias"
  type        = string
  default     = ""

  validation {
    condition     = var.region == "" || can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", var.region))
    error_message = "region must be empty or a valid AWS region name (e.g., us-east-1, eu-central-1)."
  }
}

# --- Identity Center Permission Sets (G6) ---

variable "identity_center_permission_sets" {
  description = "List of IAM Identity Center permission set definitions to create"
  type = list(object({
    name = string
    # No default: IAM Identity Center accepts 1-700 characters for a permission
    # set description and rejects the empty string. An omitted description
    # stays absent instead of being sent as "".
    description         = optional(string)
    session_duration    = optional(string, "PT1H")
    relay_state         = optional(string, null)
    managed_policy_arns = optional(list(string), [])
    inline_policy       = optional(string, null)
    customer_managed_policy_references = optional(list(object({
      name = string
      path = optional(string, "/")
    })), [])
    permissions_boundary = optional(object({
      managed_policy_arn = optional(string, null)
      customer_managed_policy_ref = optional(object({
        name = string
        path = optional(string, "/")
      }), null)
    }), null)
  }))
  default = []

  validation {
    condition = alltrue([
      for ps in var.identity_center_permission_sets :
      ps.description == null || (length(ps.description) >= 1 && length(ps.description) <= 700)
    ])
    error_message = "Each identity_center_permission_sets description must be omitted or contain 1 to 700 characters (IAM Identity Center limit)."
  }
}

# --- Identity Center Assignments (G7) ---

variable "identity_center_assignments" {
  description = "List of IAM Identity Center account assignment definitions"
  type = list(object({
    principal_type      = string # GROUP or USER
    principal_name      = string
    permission_set_name = string
    account_names       = list(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for a in var.identity_center_assignments :
      contains(["GROUP", "USER"], a.principal_type)
    ])
    error_message = "Each identity_center_assignments principal_type must be GROUP or USER."
  }
}

# --- Account IDs map (for assignment resolution) ---

variable "account_ids" {
  description = "Map of account name to account ID (passed from root module for assignment resolution)"
  type        = map(string)
  default     = {}
}

