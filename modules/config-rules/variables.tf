# Config rules module variables

# --- Managed Rules (AWS-managed Config rules) ---

variable "managed_rules" {
  description = "List of AWS-managed Config rule definitions for organization-wide deployment. Each deployment_targets entry is an account ID, an account name from account_ids, or an OU name from ou_name_to_id. description documents what the rule evaluates."
  type = list(object({
    name                 = string
    source_identifier    = string
    description          = optional(string, null)
    input_parameters     = optional(map(string), {})
    excluded_accounts    = optional(list(string), [])
    deployment_targets   = optional(list(string), [])
    resource_types_scope = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue(flatten([
      for rule in var.managed_rules : [
        for target in rule.deployment_targets :
        can(regex("^[0-9]{12}$", target)) ||
        contains(keys(var.account_ids), target) ||
        contains(keys(var.ou_name_to_id), target)
      ]
    ]))
    error_message = "Each managed_rules deployment_targets entry must be a 12-digit account ID, a key of account_ids, or a key of ou_name_to_id. An unresolvable target would exclude every account and leave the rule without any account to evaluate."
  }

  validation {
    condition = alltrue([
      for rule in var.managed_rules :
      rule.description == null || length(rule.description) <= 256
    ])
    error_message = "Each managed_rules description must be at most 256 characters — the AWS limit for Config rule descriptions."
  }
}

# --- Custom Rules (Lambda-based Config rules) ---

variable "enable_custom_rule_lambdas" {
  description = "Create the evaluator and remediation Lambda functions that custom_rules[].lambda and remediation_configs[].target_document_lambda describe. Off, every function ARN comes from outside."
  type        = bool
  default     = false
}

variable "config_lambda_log_retention_days" {
  description = "Retention of the execution log group each created evaluator and remediation Lambda owns, /aws/lambda/<function name> (0 = never expire). One value for the whole set: the functions are one mechanism with one operational lifetime. Lambda would otherwise create each group implicitly on the first invocation — outside the state, without retention, never destroyed. See README, \"Lambda execution log groups\"."
  type        = number
  default     = 365

  # CloudWatch accepts only this fixed set of retention values; 0 means never
  # expire. Any other number is rejected at apply time.
  validation {
    condition = contains(
      [0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.config_lambda_log_retention_days
    )
    error_message = "config_lambda_log_retention_days must be one of the CloudWatch retention values: 0 (never expire), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

variable "config_lambda_log_kms_key_arn" {
  description = "Optional KMS key ARN for encrypting the execution log groups of the created evaluator and remediation Lambda functions. Empty string keeps the CloudWatch service default encryption; no key is created by this module."
  type        = string
  default     = ""

  validation {
    condition     = var.config_lambda_log_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.config_lambda_log_kms_key_arn))
    error_message = "config_lambda_log_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}

variable "custom_rules" {
  description = "List of custom Config rule definitions (Lambda-based). Each entry names its evaluator either by lambda_function_arn (an existing function) or by a lambda block (the module creates the function from the configuration-supplied code; requires enable_custom_rule_lambdas). Each deployment_targets entry is an account ID, an account name from account_ids, or an OU name from ou_name_to_id. The evaluation scope takes one selector form: resource types (resource_types_scope), a single resource (resource_id_scope plus exactly one resource type), or a tag (tag_key_scope with optional tag_value_scope)."
  type = list(object({
    name                        = string
    lambda_function_arn         = optional(string, "")
    description                 = optional(string, null)
    trigger_types               = optional(list(string), ["ConfigurationItemChangeNotification"])
    input_parameters            = optional(map(string), {})
    excluded_accounts           = optional(list(string), [])
    deployment_targets          = optional(list(string), [])
    resource_types_scope        = optional(list(string), [])
    resource_id_scope           = optional(string, null)
    tag_key_scope               = optional(string, null)
    tag_value_scope             = optional(string, null)
    maximum_execution_frequency = optional(string, null)
    lambda = optional(object({
      source_code = string
      handler     = string
      runtime     = string
      timeout     = optional(number, 30)
      role_policy = string
    }), null)
  }))
  default = []

  # Exactly one evaluator source: an entry with both forms would leave the
  # effective function ambiguous, an entry with neither has no evaluator and
  # the API rejects the rule.
  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      (rule.lambda_function_arn != "") != (rule.lambda != null)
    ])
    error_message = "Each custom_rules entry must set exactly one of lambda_function_arn or lambda — the rule needs exactly one evaluator source."
  }

  # Without the switch the function ARN comes from outside. A lambda block behind a disabled switch would silently plan
  # a rule without an evaluator.
  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda == null
    ]) || var.enable_custom_rule_lambdas
    error_message = "custom_rules entries with a lambda block require enable_custom_rule_lambdas = true — without the switch the module creates no function and the rule would have no evaluator."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda_function_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):lambda:", rule.lambda_function_arn))
    ])
    error_message = "Each custom_rules lambda_function_arn must be a valid Lambda function ARN (arn:<partition>:lambda:<region>:<account-id>:function:<name>)."
  }

  # The module derives the function name tlz-config-rule-<name> (Lambda limit
  # 64 characters) and the archive file name from the handler's module part.
  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda == null || length(rule.name) <= 48
    ])
    error_message = "Each custom_rules entry with a lambda block must have a name of at most 48 characters — the derived function name tlz-config-rule-<name> is limited to 64."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda == null || contains(["python3.10", "python3.11", "python3.12", "python3.13", "nodejs18.x", "nodejs20.x", "nodejs22.x"], rule.lambda.runtime)
    ])
    error_message = "Each custom_rules lambda runtime must be one of: python3.10, python3.11, python3.12, python3.13, nodejs18.x, nodejs20.x, nodejs22.x."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda == null || (rule.lambda.timeout >= 1 && rule.lambda.timeout <= 900)
    ])
    error_message = "Each custom_rules lambda timeout must be between 1 and 900 seconds — the Lambda limits."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda == null || can(regex("^[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+$", rule.lambda.handler))
    ])
    error_message = "Each custom_rules lambda handler must have the form <module>.<function> (letters, digits, underscore) — the source file name inside the archive is derived from the module part."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda == null || length(trimspace(rule.lambda.source_code)) > 0
    ])
    error_message = "Each custom_rules lambda source_code must be non-empty — it is the function code itself, supplied as a string by the configuration layer (a path would not survive the deployment cache)."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.lambda == null || can(jsondecode(rule.lambda.role_policy).Statement)
    ])
    error_message = "Each custom_rules lambda role_policy must be a JSON policy document with a Statement field — it becomes the execution role policy of the created function."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.maximum_execution_frequency == null || contains(["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"], rule.maximum_execution_frequency)
    ])
    error_message = "Each custom_rules maximum_execution_frequency must be null or one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }

  validation {
    condition = alltrue(flatten([
      for rule in var.custom_rules : [
        for target in rule.deployment_targets :
        can(regex("^[0-9]{12}$", target)) ||
        contains(keys(var.account_ids), target) ||
        contains(keys(var.ou_name_to_id), target)
      ]
    ]))
    error_message = "Each custom_rules deployment_targets entry must be a 12-digit account ID, a key of account_ids, or a key of ou_name_to_id. An unresolvable target would exclude every account and leave the rule without any account to evaluate."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.description == null || length(rule.description) <= 256
    ])
    error_message = "Each custom_rules description must be at most 256 characters — the AWS limit for Config rule descriptions."
  }

  # A resource ID scopes the rule to one resource of one type; the API
  # requires exactly one resource type next to the ID.
  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.resource_id_scope == null || length(rule.resource_types_scope) == 1
    ])
    error_message = "Each custom_rules resource_id_scope requires exactly one resource_types_scope entry — the API scopes a resource ID to a single resource type."
  }

  # The tag selector is its own form: a tag value without a key would be
  # meaningless, and combining the tag form with the type or ID form would
  # leave the effective scope ambiguous.
  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.tag_value_scope == null || rule.tag_key_scope != null
    ])
    error_message = "Each custom_rules tag_value_scope requires tag_key_scope — a tag value cannot be matched without its key."
  }

  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      rule.tag_key_scope == null || (length(rule.resource_types_scope) == 0 && rule.resource_id_scope == null)
    ])
    error_message = "Each custom_rules entry uses one selector form: tag_key_scope cannot be combined with resource_types_scope or resource_id_scope."
  }
}

# --- Conformance Packs ---

variable "conformance_packs" {
  description = "List of Conformance Pack definitions, deployed as account-level packs in the account and region the module runs in (not organization-wide). excluded_accounts must stay empty: an account-level pack has no accounts to exclude."
  type = list(object({
    name              = string
    template_body     = optional(string, null)
    template_s3_uri   = optional(string, null)
    input_parameters  = optional(map(string), {})
    excluded_accounts = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for pack in var.conformance_packs :
      can(regex("^[a-zA-Z][-a-zA-Z0-9]{0,127}$", pack.name))
    ])
    error_message = "Each conformance_packs name must start with a letter and contain only letters, digits and hyphens (max 128 characters)."
  }

  # A conformance pack needs exactly one template source. Both set is a silent
  # precedence question, neither set produces an empty pack.
  validation {
    condition = alltrue([
      for pack in var.conformance_packs :
      (try(pack.template_body, null) != null) != (try(pack.template_s3_uri, null) != null)
    ])
    error_message = "Each conformance_packs entry must set exactly one of template_body or template_s3_uri."
  }

  # aws_config_conformance_pack is account-level: it deploys to this account
  # only and has no exclusion list, so a configured exclusion would silently do
  # nothing; it is refused instead.
  # shortcut: refusal rather than an organization pack; switch to
  # aws_config_organization_conformance_pack when exclusions are needed.
  validation {
    condition = alltrue([
      for pack in var.conformance_packs : length(try(pack.excluded_accounts, [])) == 0
    ])
    error_message = "conformance_packs excluded_accounts is not supported: the module creates account-level conformance packs in the account it runs in, which exclude no account. Remove the entry's excluded_accounts."
  }
}

# --- Auto-Remediation ---

variable "remediation_configs" {
  description = "Optional auto-remediation configurations for Config rules. target_version pins the automation document version; target_account_name names the account (a key of account_ids) that owns the document — the module then addresses the document by its full ARN. target_document_lambda describes a remediation function the module creates from configuration-supplied code (requires enable_custom_rule_lambdas); its ARN replaces the token __REMEDIATION_LAMBDA_ARN__ in the entry's static_values, so the automation document receives the function it invokes as a parameter."
  type = list(object({
    rule_name           = string
    target_id           = string
    target_type         = optional(string, "SSM_DOCUMENT")
    target_version      = optional(string, null)
    target_account_name = optional(string, null)
    parameters = optional(map(object({
      static_values  = optional(list(string), [])
      resource_value = optional(string, null)
    })), {})
    automatic                  = optional(bool, false)
    maximum_automatic_attempts = optional(number, 5)
    retry_attempt_seconds      = optional(number, 60)
    target_document_lambda = optional(object({
      source_code = string
      handler     = string
      runtime     = string
      timeout     = optional(number, 30)
      role_policy = string
    }), null)
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      contains(["SSM_DOCUMENT"], r.target_type)
    ])
    error_message = "Each remediation_configs target_type must be SSM_DOCUMENT."
  }

  # Without the switch remediation identities and functions come from outside.
  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_document_lambda == null
    ]) || var.enable_custom_rule_lambdas
    error_message = "remediation_configs entries with target_document_lambda require enable_custom_rule_lambdas = true — without the switch the module creates no function and the token __REMEDIATION_LAMBDA_ARN__ stays unresolvable."
  }

  # The created function is only reachable through the token: an entry that
  # creates a function without referencing it configures a function nothing
  # invokes, and a token without a function would reach the document verbatim.
  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      (r.target_document_lambda != null) == contains(flatten([
        for parameter in values(r.parameters) : parameter.static_values
      ]), "__REMEDIATION_LAMBDA_ARN__")
    ])
    error_message = "Each remediation_configs entry with target_document_lambda must carry the token __REMEDIATION_LAMBDA_ARN__ in one of its static_values (and the token requires the lambda block) — the automation document receives the created function through that parameter."
  }

  # The module derives the function name tlz-remediation-<rule_name> (Lambda
  # limit 64 characters).
  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_document_lambda == null || length(r.rule_name) <= 48
    ])
    error_message = "Each remediation_configs entry with target_document_lambda must have a rule_name of at most 48 characters — the derived function name tlz-remediation-<rule_name> is limited to 64."
  }

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_document_lambda == null || contains(["python3.10", "python3.11", "python3.12", "python3.13", "nodejs18.x", "nodejs20.x", "nodejs22.x"], r.target_document_lambda.runtime)
    ])
    error_message = "Each remediation_configs target_document_lambda runtime must be one of: python3.10, python3.11, python3.12, python3.13, nodejs18.x, nodejs20.x, nodejs22.x."
  }

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_document_lambda == null || (r.target_document_lambda.timeout >= 1 && r.target_document_lambda.timeout <= 900)
    ])
    error_message = "Each remediation_configs target_document_lambda timeout must be between 1 and 900 seconds — the Lambda limits."
  }

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_document_lambda == null || can(regex("^[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+$", r.target_document_lambda.handler))
    ])
    error_message = "Each remediation_configs target_document_lambda handler must have the form <module>.<function> (letters, digits, underscore) — the source file name inside the archive is derived from the module part."
  }

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_document_lambda == null || length(trimspace(r.target_document_lambda.source_code)) > 0
    ])
    error_message = "Each remediation_configs target_document_lambda source_code must be non-empty — it is the function code itself, supplied as a string by the configuration layer (a path would not survive the deployment cache)."
  }

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_document_lambda == null || can(jsondecode(r.target_document_lambda.role_policy).Statement)
    ])
    error_message = "Each remediation_configs target_document_lambda role_policy must be a JSON policy document with a Statement field — it becomes the execution role policy of the created function."
  }

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.maximum_automatic_attempts >= 1 && r.maximum_automatic_attempts <= 25
    ])
    error_message = "Each remediation_configs maximum_automatic_attempts must be between 1 and 25."
  }

  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_version == null || can(regex("^[^\\s]+$", r.target_version))
    ])
    error_message = "Each remediation_configs target_version must be a non-empty string without whitespace (e.g. 1 or $DEFAULT)."
  }

  # The account name resolves through account_ids into the document ARN; an
  # unresolvable name would only fail when the remediation runs.
  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_account_name == null || contains(keys(var.account_ids), r.target_account_name)
    ])
    error_message = "Each remediation_configs target_account_name must be a key of account_ids — the module builds the cross-account document ARN from it."
  }

  # With an owning account the module addresses the document by ARN; the
  # target_id must then be the plain document name, not an ARN of its own.
  validation {
    condition = alltrue([
      for r in var.remediation_configs :
      r.target_account_name == null || (!startswith(r.target_id, "arn:"))
    ])
    error_message = "Each remediation_configs target_account_name requires a plain document name in target_id — the module derives the ARN itself."
  }
}

variable "account_ids" {
  description = "Map of account name to account ID for deployment_targets resolution"
  type        = map(string)
  default     = {}
}

variable "ou_name_to_id" {
  description = "Map of OU name to OU ID for deployment_targets resolution"
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for ou_id in values(var.ou_name_to_id) :
      can(regex("^(ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|r-[0-9a-z]{4,32})$", ou_id))
    ])
    error_message = "Each ou_name_to_id value must be an OU ID (ou-<roots>-<suffix>) or a root ID (r-<id>)."
  }
}

variable "account_ou_ids" {
  description = "Map of account name to the ID of the organizational unit the account is placed in. Required to resolve OU names in deployment_targets to the accounts they contain."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for ou_id in values(var.account_ou_ids) :
      can(regex("^(ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|r-[0-9a-z]{4,32})$", ou_id))
    ])
    error_message = "Each account_ou_ids value must be an OU ID (ou-<roots>-<suffix>) or a root ID (r-<id>)."
  }
}

# --- Management-Only Rules ---

variable "management_only_rules" {
  description = "List of Config rules deployed only to the Management account (not org-wide). These use aws_config_config_rule instead of aws_config_organization_managed_rule. description documents what the rule evaluates; tags are assigned to the rule resource."
  type = list(object({
    name              = string
    source_identifier = string
    description       = optional(string, null)
    input_parameters  = optional(map(string), {})
    tags              = optional(map(string), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.management_only_rules :
      can(regex("^[a-zA-Z0-9._-]{1,128}$", rule.name))
    ])
    error_message = "Each management_only_rules name must be 1-128 characters of letters, digits, dot, underscore or hyphen."
  }

  validation {
    condition = alltrue([
      for rule in var.management_only_rules :
      can(regex("^[A-Z0-9_]+$", rule.source_identifier))
    ])
    error_message = "Each management_only_rules source_identifier must be an AWS managed rule identifier in upper snake case (e.g. IAM_PASSWORD_POLICY)."
  }

  validation {
    condition = alltrue([
      for rule in var.management_only_rules :
      rule.description == null || length(rule.description) <= 256
    ])
    error_message = "Each management_only_rules description must be at most 256 characters — the AWS limit for Config rule descriptions."
  }

  validation {
    condition = alltrue(flatten([
      for rule in var.management_only_rules : [
        for key, value in rule.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in management_only_rules must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

variable "global_excluded_accounts" {
  description = "Account IDs excluded from ALL org Config rules (accounts without Config Recorder)"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.global_excluded_accounts : can(regex("^[0-9]{12}$", id))])
    error_message = "Each entry in global_excluded_accounts must be a 12-digit AWS account ID."
  }
}
