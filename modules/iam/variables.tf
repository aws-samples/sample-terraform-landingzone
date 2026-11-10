# IAM module variables

variable "roles" {
  description = "List of IAM role definitions for the management account. path and max_session_duration default to the values AWS applies anyway (/ and 3600 seconds), so entries without them keep their current form."
  type = list(object({
    name                       = string
    assume_role_policy         = string # JSON-String
    path                       = optional(string, "/")
    max_session_duration       = optional(number, 3600)
    managed_policy_arns        = optional(list(string), [])
    permissions_boundary       = optional(string, null)
    instance_profile           = optional(bool, false)
    exclude_management_account = optional(bool, true)
    inline_policies = optional(list(object({
      name   = string
      policy = string # JSON-String
    })), [])
    deployment_targets = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for role in var.roles :
      can(regex("^[a-zA-Z0-9+=,.@_-]+$", role.name))
    ])
    error_message = "Role name must contain only alphanumeric characters and +=,.@_- characters."
  }

  validation {
    condition = alltrue([
      for role in var.roles :
      can(regex("^/([A-Za-z0-9_.,+@=-]+/)*$", role.path))
    ])
    error_message = "Each role path must begin and end with a slash and carry only alphanumeric segments plus _.,+@=- between slashes (IAM path rule), e.g. / or /landing-zone/."
  }

  validation {
    condition = alltrue([
      for role in var.roles :
      role.max_session_duration >= 3600 && role.max_session_duration <= 43200
    ])
    error_message = "Each role max_session_duration must lie between 3600 and 43200 seconds (1 to 12 hours, the IAM bounds)."
  }
}

variable "saml_providers" {
  description = "List of SAML identity provider definitions"
  type = list(object({
    name                   = string
    saml_metadata_document = string
  }))
  default = []

  validation {
    condition = alltrue([
      for sp in var.saml_providers :
      can(regex("^[a-zA-Z0-9._-]+$", sp.name))
    ])
    error_message = "SAML provider name must contain only alphanumeric characters and ._- characters."
  }
}

variable "customer_managed_policies" {
  description = "List of customer-managed IAM policy definitions"
  type = list(object({
    name                       = string
    policy                     = string # JSON-String
    deployment_targets         = optional(list(string), [])
    exclude_management_account = optional(bool, true)
  }))
  default = []

  validation {
    condition = alltrue([
      for p in var.customer_managed_policies :
      can(regex("^[a-zA-Z0-9+=,.@_-]+$", p.name))
    ])
    error_message = "Policy name must contain only alphanumeric characters and +=,.@_- characters."
  }
}

variable "iam_users" {
  description = "List of IAM user definitions with group membership and managed policy attachments"
  type = list(object({
    name                       = string
    groups                     = optional(list(string), [])
    managed_policy_arns        = optional(list(string), [])
    permissions_boundary       = optional(string, null)
    deployment_targets         = optional(list(string), [])
    exclude_management_account = optional(bool, true)
    auto_generate_password     = optional(bool, false)
    disable_console_access     = optional(bool, false)
  }))
  default = []

  validation {
    condition = alltrue([
      for u in var.iam_users :
      can(regex("^[a-zA-Z0-9+=,.@_-]+$", u.name))
    ])
    error_message = "IAM user name must contain only alphanumeric characters and +=,.@_- characters."
  }

  # auto_generate_password stores the initial console password the login
  # profile generates; a user without console access has none to store.
  validation {
    condition = alltrue([
      for u in var.iam_users : !(u.auto_generate_password && u.disable_console_access)
    ])
    error_message = "auto_generate_password stores the user's initial console password and needs console access: it cannot be combined with disable_console_access = true."
  }
}

variable "iam_groups" {
  description = "List of IAM group definitions with managed policy attachments"
  type = list(object({
    name                       = string
    managed_policy_arns        = optional(list(string), [])
    deployment_targets         = optional(list(string), [])
    exclude_management_account = optional(bool, true)
  }))
  default = []

  validation {
    condition = alltrue([
      for g in var.iam_groups :
      can(regex("^[a-zA-Z0-9+=,.@_-]+$", g.name))
    ])
    error_message = "IAM group name must contain only alphanumeric characters and +=,.@_- characters."
  }
}

variable "managed_active_directories" {
  description = "List of AWS Managed Microsoft AD and AD Connector definitions. Managed Microsoft AD admin passwords are generated and stored in Secrets Manager; AD Connectors read the service account password from the Secrets Manager secret named in password_secret_name. shared_account_ids lists the AWS account IDs the directory is shared with — Directory Service accepts account targets only. share_targets adds organizational units (resolved to the accounts they contain, minus excluded_accounts). secret_config controls name, account and region of the admin secret; log_retention_days makes the module create the log group named in log_group_name with that retention. vpc_associations lists VPC names (keys of vpc_ids) the directory's Route 53 Resolver rule is associated with — without an association the rule changes no DNS behaviour. resolver_rule_name creates a FORWARD rule targeting the directory DNS servers and requires resolver_endpoint_name, the name of an outbound Route 53 Resolver endpoint from the networking module (a key of resolver_endpoint_ids) — Route 53 Resolver accepts FORWARD rules only with an outbound endpoint."
  type = list(object({
    name                     = string
    directory_type           = optional(string, "MicrosoftAD")
    edition                  = optional(string, "Standard")
    description              = optional(string, null)
    net_bios_domain_name     = optional(string, null)
    vpc_name                 = string
    subnet_names             = list(string)
    domain_name              = string
    resolver_rule_name       = optional(string, null)
    resolver_endpoint_name   = optional(string, null)
    vpc_associations         = optional(list(string), [])
    shared_account_ids       = optional(list(string), [])
    log_group_name           = optional(string, null)
    log_retention_days       = optional(number, null)
    log_group_kms_key_arn    = optional(string, null)
    secret_access_role_names = optional(list(string), [])
    password_secret_name     = optional(string, null)
    secret_config = optional(object({
      admin_secret_name = optional(string, null)
      account           = optional(string, null)
      region            = optional(string, null)
    }), {})
    share_targets = optional(object({
      organizational_units = optional(list(string), [])
      excluded_accounts    = optional(list(string), [])
    }), {})
    connect_settings = optional(object({
      customer_dns_ips  = list(string)
      customer_username = string
    }), null)
  }))
  default = []

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      contains(["MicrosoftAD", "ADConnector"], d.directory_type)
    ])
    error_message = "Directory type must be MicrosoftAD or ADConnector."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      length(d.vpc_associations) == 0 || d.resolver_rule_name != null
    ])
    error_message = "vpc_associations requires resolver_rule_name — the association attaches the directory's Route 53 Resolver rule to the named VPCs."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.directory_type != "MicrosoftAD" || contains(["Standard", "Enterprise"], d.edition)
    ])
    error_message = "Managed AD edition must be Standard or Enterprise."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.resolver_rule_name == null || d.resolver_endpoint_name != null
    ])
    error_message = "resolver_rule_name requires resolver_endpoint_name: Route 53 Resolver accepts FORWARD rules only with an outbound endpoint. Name an outbound endpoint the networking module exports (keys of resolver_endpoint_ids)."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.directory_type != "ADConnector" || d.connect_settings != null
    ])
    error_message = "AD Connector requires connect_settings with customer_dns_ips."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.directory_type != "ADConnector" || length(d.vpc_name) > 0
    ])
    error_message = "AD Connector requires a non-empty vpc_name to resolve the VPC ID for connect_settings."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.directory_type != "ADConnector" || length(d.subnet_names) >= 2
    ])
    error_message = "AD Connector requires at least 2 subnet_names to resolve subnet IDs for connect_settings."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.directory_type != "ADConnector" || (
        d.connect_settings != null && length(d.connect_settings.customer_dns_ips) > 0
      )
    ])
    error_message = "AD Connector requires non-empty customer_dns_ips in connect_settings to resolve the on-premises directory."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.directory_type != "ADConnector" || (
        d.password_secret_name != null && length(trimspace(coalesce(d.password_secret_name, ""))) > 0
      )
    ])
    error_message = "AD Connector requires password_secret_name — the name or ARN of the Secrets Manager secret holding the password of the on-premises service account (customer_username). The module never carries directory passwords in its source."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.managed_active_directories : [
        for account_id in d.shared_account_ids :
        can(regex("^[0-9]{12}$", account_id))
      ]
    ]))
    error_message = "Each shared_account_ids entry must be a 12-digit AWS account ID. Directory Service shares a directory with accounts only — an organizational unit ID is not a valid share target."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.net_bios_domain_name == null || can(regex("^[A-Za-z0-9-]{1,15}$", d.net_bios_domain_name))
    ])
    error_message = "Each net_bios_domain_name must be 1-15 characters of letters, digits or hyphens — the NetBIOS naming rule."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.log_retention_days == null || contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], coalesce(d.log_retention_days, 1))
    ])
    error_message = "Each log_retention_days must be one of the CloudWatch Logs retention values (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288 or 3653 days)."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.log_retention_days == null || d.log_group_name != null
    ])
    error_message = "log_retention_days requires log_group_name — the retention describes the log group the module then creates, and without a name there is no group to create."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.log_group_kms_key_arn == null || can(regex("^arn:[a-z0-9-]+:kms:", d.log_group_kms_key_arn))
    ])
    error_message = "Each log_group_kms_key_arn must be a KMS key ARN (arn:<partition>:kms:...). The partition is not pinned."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.log_group_kms_key_arn == null || d.log_retention_days != null
    ])
    error_message = "log_group_kms_key_arn applies to the log group the module creates — set log_retention_days (and log_group_name) with it; an externally managed group carries its own key."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.secret_config.admin_secret_name == null || can(regex("^[A-Za-z0-9/_+=.@-]{1,512}$", d.secret_config.admin_secret_name))
    ])
    error_message = "Each secret_config.admin_secret_name must follow the Secrets Manager naming rule: 1-512 characters of letters, digits and /_+=.@- only."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.secret_config.account == null || can(regex("^[0-9]{12}$", d.secret_config.account)) || contains(keys(var.account_ids), coalesce(d.secret_config.account, "-"))
    ])
    error_message = "Each secret_config.account must be a 12-digit AWS account ID or a key of account_ids — an unknown name cannot be resolved to an account."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.secret_config.region == null || can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", d.secret_config.region))
    ])
    error_message = "Each secret_config.region must be a valid AWS region name (e.g., us-east-1, eu-central-1)."
  }

  # One static provider alias carries the secret placement, and Terraform
  # cannot multiply provider configurations per entry — so all directories
  # that place their secret must name the same target.
  validation {
    condition     = length(distinct([for d in var.managed_active_directories : d.secret_config.account if d.secret_config.account != null])) <= 1
    error_message = "All secret_config.account values must name the same account — the secret placement runs over one static provider alias, and Terraform cannot create provider configurations per entry."
  }

  validation {
    condition     = length(distinct([for d in var.managed_active_directories : d.secret_config.region if d.secret_config.region != null])) <= 1
    error_message = "All secret_config.region values must name the same region — the secret placement runs over one static provider alias, and Terraform cannot create provider configurations per entry."
  }

  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.directory_type == "MicrosoftAD" || (
        d.secret_config.admin_secret_name == null && d.secret_config.account == null && d.secret_config.region == null
      )
    ])
    error_message = "secret_config applies to Managed Microsoft AD only — an AD Connector has no module-generated admin secret; its service account password is read from password_secret_name."
  }

  # A management-account identity policy alone cannot read a secret that
  # lives in another account (the secret's resource policy and its key would
  # both have to grant it). The module names the limit instead of producing
  # a grant that never works.
  validation {
    condition = alltrue([
      for d in var.managed_active_directories :
      d.secret_config.account == null || length(d.secret_access_role_names) == 0
    ])
    error_message = "secret_access_role_names cannot be combined with secret_config.account — the roles live in the management account, and an identity policy alone cannot read a secret placed in another account."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.managed_active_directories : [
        for ou in d.share_targets.organizational_units :
        contains(keys(var.ou_name_to_id), ou)
      ]
    ]))
    error_message = "Each share_targets.organizational_units entry must be a key of ou_name_to_id — an unknown OU name cannot be resolved to its accounts."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.managed_active_directories : [
        for entry in d.share_targets.excluded_accounts :
        can(regex("^[0-9]{12}$", entry)) || contains(keys(var.account_ids), entry)
      ]
    ]))
    error_message = "Each share_targets.excluded_accounts entry must be a 12-digit AWS account ID or a key of account_ids — an unknown name cannot be resolved to an account."
  }
}

variable "vpc_ids" {
  description = "Map of VPC name to VPC ID (from networking module)"
  type        = map(string)
  default     = {}
}

variable "subnet_ids" {
  description = "Map of vpc_name.subnet_name to subnet ID (from networking module)"
  type        = map(string)
  default     = {}
}

variable "resolver_endpoint_ids" {
  description = "Map of outbound Route 53 Resolver endpoint name to endpoint ID (from networking module). Managed AD FORWARD resolver rules route through the endpoint named in resolver_endpoint_name."
  type        = map(string)
  default     = {}
}

variable "account_ids" {
  description = "Map of account name to account ID for cross-account trust policies"
  type        = map(string)
  default     = {}
}

# Account and OU maps for the directory share-target resolution: OU names are
# resolved to the accounts they contain, because Directory Service shares a
# directory with accounts only (ShareTarget.Type accepts ACCOUNT). Same maps
# and value forms as the SSM document sharing in modules/security.

variable "ou_name_to_id" {
  description = "Map of OU name to OU ID for resolving share_targets.organizational_units of managed_active_directories. Supplied by the organization stack; empty when no directory shares with an OU."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name, id in var.ou_name_to_id :
      can(regex("^ou-[a-z0-9]+-[a-z0-9]+$", id))
    ])
    error_message = "Each ou_name_to_id value must be an OU ID (ou-<roots>-<suffix>)."
  }
}

variable "account_ou_ids" {
  description = "Map of account name to the ID of the OU the account is placed in. Supplied by the accounts stack; together with account_ids and ou_name_to_id it resolves OU share targets to the accounts they contain."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name, id in var.account_ou_ids :
      can(regex("^(ou-[a-z0-9]+-[a-z0-9]+|r-[a-z0-9]+)$", id))
    ])
    error_message = "Each account_ou_ids value must be an OU ID (ou-<roots>-<suffix>) or a root ID (r-<id>)."
  }
}

variable "mad_secret_access_role_name" {
  description = "Name of the IAM role the module assumes in the account named by secret_config.account to place a directory admin secret there. The role must exist in the target account; the default is the account access role AWS Control Tower creates."
  type        = string
  default     = "AWSControlTowerExecution"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]+$", var.mad_secret_access_role_name))
    error_message = "Role name must contain only alphanumeric characters and +=,.@_- characters."
  }
}

variable "management_account_id" {
  description = "Management account ID for exclude_management_account filtering"
  type        = string
  default     = ""

  validation {
    condition     = var.management_account_id == "" || can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be empty or a 12-digit AWS account ID."
  }
}

variable "enable_service_catalog" {
  description = "Enable Service Catalog propagation role for cross-account portfolio sharing"
  type        = bool
  default     = false
}

# =============================================================================
# CloudFormation StackSet Roles
# =============================================================================

variable "enable_stackset_roles" {
  description = "Create CloudFormation StackSet administration and execution IAM roles."
  type        = bool
  default     = false
}

variable "is_management_account" {
  description = "Whether the current deployment context is the management account. Controls which StackSet role is created (admin in management, execution in member accounts)."
  type        = bool
  default     = false
}

variable "secrets_kms_key_arn" {
  description = "Optional KMS key ARN for encrypting the Secrets Manager secrets that hold auto-generated IAM user passwords. Empty string keeps the Secrets Manager service key (aws/secretsmanager); no key is created by this module."
  type        = string
  default     = ""

  validation {
    condition     = var.secrets_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.secrets_kms_key_arn))
    error_message = "secrets_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}

# --- Break-Glass Access ---

variable "enable_break_glass" {
  description = "Create the break-glass access package: numbered emergency IAM users with mandatory permissions boundary, AdministratorAccess, console login profile, and the initial password in Secrets Manager. The matching usage alarm lives in modules/monitoring (enable_break_glass_alarm)."
  type        = bool
  default     = false
}

variable "break_glass_config" {
  description = "Break-glass user set (required when enable_break_glass is true). user_count numbered users (1-10) named <user_prefix>-01 … -NN; permissions_boundary is the mandatory policy ARN that caps every emergency session."
  type = object({
    user_count           = optional(number, 2)
    user_prefix          = optional(string, "tlz-break-glass")
    permissions_boundary = string
  })
  default = null

  validation {
    condition     = !var.enable_break_glass || var.break_glass_config != null
    error_message = "enable_break_glass requires break_glass_config (at least the mandatory permissions_boundary)."
  }

  validation {
    condition = (
      var.break_glass_config == null
      || try(var.break_glass_config.user_count >= 1 && var.break_glass_config.user_count <= 10, false)
    )
    error_message = "break_glass_config.user_count must be between 1 and 10 — an empty set alarms nobody, and more than ten emergency users are a directory, not a break-glass set."
  }

  validation {
    condition = (
      var.break_glass_config == null
      || can(regex("^arn:[a-z0-9-]+:iam::([0-9]{12}|aws):policy/.+", var.break_glass_config.permissions_boundary))
    )
    error_message = "break_glass_config.permissions_boundary must be an IAM policy ARN (arn:<partition>:iam::<account-id|aws>:policy/<name>) — the boundary is the mandatory cap on every emergency session."
  }

  validation {
    condition = (
      var.break_glass_config == null
      || can(regex("^[a-zA-Z0-9+=,.@_-]+$", var.break_glass_config.user_prefix))
    )
    error_message = "break_glass_config.user_prefix must contain only alphanumeric characters and +=,.@_- characters (IAM user name character set)."
  }
}
