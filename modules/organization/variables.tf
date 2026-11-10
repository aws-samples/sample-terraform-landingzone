# --- Organization module variables ---

variable "import_organization_id" {
  description = "ID of an existing AWS Organization to import (e.g. o-abc123). When set, Terraform imports the org instead of creating a new one. Leave empty to create a new Organization."
  type        = string
  default     = ""

  validation {
    condition     = var.import_organization_id == "" || can(regex("^o-[a-z0-9]+$", var.import_organization_id))
    error_message = "import_organization_id must be empty or in o-xxxx format."
  }
}

variable "organization_root_id" {
  description = "ID of the Organization Root (e.g. r-xxxx). Empty = automatic resolution from the Organization resource."
  type        = string
  default     = ""

  validation {
    condition     = var.organization_root_id == "" || can(regex("^r-[a-z0-9]+$", var.organization_root_id))
    error_message = "organization_root_id must be empty or in r-xxxx format."
  }
}

variable "aws_service_access_principals" {
  description = "Complete list of AWS service principals with trusted access in the organization (e.g. cloudtrail.amazonaws.com, guardduty.amazonaws.com). aws_organizations_organization.this owns the whole list: a principal missing here has its trusted access disabled on apply. Must not be empty."
  type        = list(string)
  default     = []

  # The Organization resource owns the COMPLETE trusted-access list, so [] is
  # not "no change" but "disable every trusted access the organization has
  # today". No landing zone works without it (Config, GuardDuty, Security Hub
  # ...), so an empty list is refused rather than applied — including the
  # default, which is kept only so that a missing input fails with this message.
  validation {
    condition     = length(var.aws_service_access_principals) > 0
    error_message = "aws_service_access_principals is empty. aws_organizations_organization.this owns the COMPLETE trusted-access list, so an apply with [] disables trusted access for EVERY service the organization trusts today (Config, GuardDuty, Security Hub, ...). Refused. Read today's list as the management account with `aws organizations list-aws-service-access-for-organization` and pass every service principal the landing zone needs in aws_service_access_principals. From a stacks/ deployment, set additional_aws_service_access_principals in env/common.hcl: the stack appends those entries to the list its module toggles derive."
  }

  # A blank entry is refused before the principal-shape check so that its
  # message is the one an operator reads first. The stack deliberately does
  # NOT compact() the operator's additional list: a "" dropped in silence
  # lets the plan succeed with the service the operator meant to name absent,
  # and nothing downstream shows it. try() covers a null element, which
  # trimspace() would not accept.
  validation {
    condition = alltrue([
      for principal in var.aws_service_access_principals :
      try(trimspace(principal), "") != ""
    ])
    error_message = "aws_service_access_principals contains a blank entry. An empty string, a null or a string of spaces in additional_aws_service_access_principals (env/common.hcl) is not a service principal: it usually is a leftover from editing the list. It is refused rather than dropped, because dropping it would let the plan succeed with the service you meant to name silently absent. Remove the blank entry, or replace it with the principal you meant, such as ram.amazonaws.com."
  }

  # The shape check explicitly PASSES a blank or null entry: the blank
  # validation above is the only rule that refuses one, so its diagnostic is
  # the only one an operator reads for a blank, and the module test case that
  # pins it (d12_blank_service_access_entry_refused) turns red when that rule
  # is removed instead of staying green on this regex.
  validation {
    condition = alltrue([
      for principal in var.aws_service_access_principals :
      try(trimspace(principal), "") == "" || can(regex("^[a-z0-9.-]+\\.(amazonaws\\.com|amazonaws\\.com\\.cn|amazonaws\\.eu)$", principal))
    ])
    error_message = "Each aws_service_access_principals entry must be an AWS service principal such as cloudtrail.amazonaws.com. This checks only the SHAPE of the principal: nothing here checks that the named service exists or that the configured partition offers it, and what Organizations returns for a well-formed principal of a service it does not know is not checked either. Check every name you add yourself."
  }

  validation {
    condition     = length(distinct(var.aws_service_access_principals)) == length(var.aws_service_access_principals)
    error_message = "aws_service_access_principals must not contain duplicates."
  }
}

variable "feature_set" {
  description = "Feature set of the AWS Organization (ALL or CONSOLIDATED_BILLING)"
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ALL", "CONSOLIDATED_BILLING"], var.feature_set)
    error_message = "feature_set must be ALL or CONSOLIDATED_BILLING."
  }
}

variable "organizational_units" {
  description = "List of OU definitions with nested hierarchy (up to 5 levels)"
  type = list(object({
    name        = string
    parent_name = optional(string, "__root__") # "__root__" = directly under Organization Root
    ignore      = optional(bool, false)        # exclude from policy attachments
  }))
  default = []

  # The hierarchy is keyed by OU name at every level, and so is ou_name_to_id.
  # Two OUs sharing a name would overwrite each other in that map and in the
  # level resources, so the name must identify the OU uniquely.
  validation {
    condition = length(distinct([for ou in var.organizational_units : ou.name])) == length(
      var.organizational_units
    )
    error_message = "Each organizational_units name must be unique — the OU name is the key of the hierarchy and of the ou_name_to_id output."
  }

  # "__root__" is the sentinel for "directly under the organization root" and
  # must not double as an OU name.
  validation {
    condition = alltrue([
      for ou in var.organizational_units :
      ou.name != "__root__" && can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", ou.name))
    ])
    error_message = "Each organizational_units name must start with a letter, contain only alphanumeric characters, spaces, hyphens and underscores, and must not be the reserved value \"__root__\"."
  }

  # A parent_name that matches no declared OU leaves the OU outside every level
  # of the hierarchy, where it would be created by no resource at all.
  validation {
    condition = alltrue([
      for ou in var.organizational_units :
      ou.parent_name == "__root__" || contains(
        [for parent in var.organizational_units : parent.name], ou.parent_name
      )
    ])
    error_message = "Each organizational_units parent_name must be \"__root__\" or the name of another declared organizational unit."
  }
}

variable "enable_allow_list_detach" {
  description = "Allow policy entries with strategy = allow-list to detach the AWS default policy (FullAWSAccess / RCPFullAWSAccess) from their targets. Off keeps the purely additive attaching; an allow-list entry behind the disabled switch is rejected at plan."
  type        = bool
  default     = false
}

variable "service_control_policies" {
  description = "List of SCP definitions with name, description, content, and target OUs/accounts. type selects between customer-managed (the default: the module creates the policy from content) and aws-managed (the entry names an AWS-managed policy such as FullAWSAccess, which is attached by its well-known ID and carries no content). strategy selects between deny-list (the default: the AWS default policy stays attached) and allow-list (the module detaches FullAWSAccess from the entry's targets, so only the granted services remain; requires enable_allow_list_detach)."
  type = list(object({
    name        = string
    description = optional(string, "")
    content     = optional(string, "") # JSON string (max 5120 characters)
    targets     = list(string)         # OU names or account IDs
    type        = optional(string, "customer-managed")
    strategy    = optional(string, "deny-list")
  }))
  default = []

  # The limit is measured against the compact form (jsonencode of the parsed
  # document) — the same normalization the configuration loader applies to
  # injected content, and the form AWS Organizations counts. Content that is
  # not parseable JSON is measured raw; its syntax is rejected elsewhere.
  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      length(try(jsonencode(jsondecode(scp.content)), scp.content)) <= 5120
    ])
    error_message = "SCP content must not exceed 5120 characters in its compact JSON form (AWS limit)."
  }

  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      contains(["customer-managed", "aws-managed"], scp.type)
    ])
    error_message = "Each service_control_policies type must be customer-managed or aws-managed."
  }

  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      contains(["deny-list", "allow-list"], scp.strategy)
    ])
    error_message = "Each service_control_policies strategy must be deny-list or allow-list."
  }

  # The module attaches an AWS-managed policy by its well-known ID; an unknown
  # name would be handed to the API as a policy ID and fail at apply.
  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      scp.type != "aws-managed" || contains(["FullAWSAccess"], scp.name)
    ])
    error_message = "Each aws-managed service_control_policies entry must name a known AWS-managed policy (FullAWSAccess) — the module attaches it by its well-known ID."
  }

  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      scp.type != "aws-managed" || scp.content == ""
    ])
    error_message = "An aws-managed service_control_policies entry must not carry content — AWS owns the policy document."
  }

  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      scp.type != "customer-managed" || length(scp.content) > 0
    ])
    error_message = "Each customer-managed service_control_policies entry must carry content — without a document the policy would be empty."
  }

  # FullAWSAccess is the policy the allow-list strategy detaches; attaching it
  # while detaching it would be contradictory.
  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      scp.type != "aws-managed" || scp.strategy == "deny-list"
    ])
    error_message = "An aws-managed service_control_policies entry must keep strategy deny-list — FullAWSAccess is the policy the allow-list strategy detaches."
  }

  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      scp.strategy != "allow-list" || length(scp.targets) > 0
    ])
    error_message = "Each allow-list service_control_policies entry must name at least one target — the entry's own policy is what keeps a detached target authorized."
  }

  validation {
    condition = alltrue([
      for scp in var.service_control_policies :
      scp.strategy != "allow-list"
    ]) || var.enable_allow_list_detach
    error_message = "service_control_policies entries with strategy allow-list require enable_allow_list_detach = true — without the switch the module never detaches FullAWSAccess and the allow-list would not restrict anything."
  }

  validation {
    condition = alltrue(flatten([
      for scp in var.service_control_policies : [
        for target in scp.targets :
        can(regex("^\\d{12}$", target)) || can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", target))
      ]
    ]))
    error_message = "Each SCP target must be either a 12-digit account ID or a valid OU name (starting with a letter, containing only alphanumeric characters, spaces, hyphens, and underscores)."
  }
}

variable "tag_policies" {
  description = "List of Tag Policy definitions"
  type = list(object({
    name        = string
    description = optional(string, "")
    content     = string       # JSON string
    targets     = list(string) # OU names or account IDs
  }))
  default = []

  validation {
    condition = alltrue([
      for policy in var.tag_policies :
      length(policy.content) <= 10000
    ])
    error_message = "Tag policy content must not exceed 10000 characters (AWS limit)."
  }

  validation {
    condition = alltrue(flatten([
      for policy in var.tag_policies : [
        for target in policy.targets :
        can(regex("^\\d{12}$", target)) || can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", target))
      ]
    ]))
    error_message = "Each tag policy target must be either a 12-digit account ID or a valid OU name (starting with a letter, containing only alphanumeric characters, spaces, hyphens, and underscores)."
  }
}

variable "backup_policies" {
  description = "List of Backup Policy definitions"
  type = list(object({
    name        = string
    description = optional(string, "")
    content     = string       # JSON string
    targets     = list(string) # OU names or account IDs
  }))
  default = []

  validation {
    condition = alltrue([
      for policy in var.backup_policies :
      length(policy.content) <= 10000
    ])
    error_message = "Backup policy content must not exceed 10000 characters (AWS limit)."
  }

  validation {
    condition = alltrue(flatten([
      for policy in var.backup_policies : [
        for target in policy.targets :
        can(regex("^\\d{12}$", target)) || can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", target))
      ]
    ]))
    error_message = "Each backup policy target must be either a 12-digit account ID or a valid OU name (starting with a letter, containing only alphanumeric characters, spaces, hyphens, and underscores)."
  }
}

variable "service_access_principals" {
  description = "List of AWS service principals for delegated administrator access"
  type = list(object({
    service_principal = string # e.g. "guardduty.amazonaws.com"
    account_id        = string # Target account (e.g. Audit account)
  }))
  default = []

  validation {
    condition = alltrue([
      for principal in var.service_access_principals :
      can(regex("^[a-z0-9.-]+\\.amazonaws\\.(com|eu)$", principal.service_principal))
    ])
    error_message = "service_principal must be a valid AWS service principal (e.g. guardduty.amazonaws.com or guardduty.amazonaws.eu)."
  }

  validation {
    condition = alltrue([
      for principal in var.service_access_principals :
      can(regex("^\\d{12}$", principal.account_id))
    ])
    error_message = "Each service_access_principals account_id must be a 12-digit AWS account ID for the delegated administrator."
  }

  # Cross-variable: a delegated administrator can only be registered for a
  # service whose trusted access is enabled on the organization, and that list
  # is aws_service_access_principals. A service_principal named here but absent
  # there passes every per-variable check and produces a healthy-looking plan,
  # then fails at apply with AccountNotRegisteredException ("You must enable
  # service access before you can register a delegated administrator"). Both
  # lists live in this module, so the requirement is a pure plan-time set check.
  validation {
    condition = alltrue([
      for principal in var.service_access_principals :
      contains(var.aws_service_access_principals, principal.service_principal)
    ])
    error_message = "Every service_access_principals service_principal must also appear in aws_service_access_principals — a delegated administrator cannot be registered for a service whose trusted access is not enabled on the organization."
  }
}

# --- Pipeline SCP ---

variable "enable_pipeline_scp" {
  description = "Create a Pipeline SCP that protects Deployment_Role and Pipeline_Role from modification"
  type        = bool
  default     = false
}

variable "pipeline_scp_config" {
  description = "Configuration for the Pipeline SCP (required when enable_pipeline_scp is true)"
  type = object({
    deployment_role_name  = string
    pipeline_role_name    = string
    infrastructure_ou_id  = string
    management_account_id = string
  })
  default = null

  validation {
    condition = (
      var.pipeline_scp_config == null
      || can(regex("^[0-9]{12}$", var.pipeline_scp_config.management_account_id))
    )
    error_message = "pipeline_scp_config.management_account_id must be a 12-digit AWS account ID."
  }

  validation {
    condition = (
      var.pipeline_scp_config == null
      || can(regex("^(ou-[a-z0-9]+-[a-z0-9]+|r-[a-z0-9]+)$", var.pipeline_scp_config.infrastructure_ou_id))
    )
    error_message = "pipeline_scp_config.infrastructure_ou_id must be an OU ID (ou-xxxx-xxxxxxxx) or a root ID (r-xxxx)."
  }

  # The two role names go into the SCP condition. An empty name would produce a
  # policy that matches every principal instead of the two deployment roles.
  validation {
    condition = (
      var.pipeline_scp_config == null
      || (
        can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.pipeline_scp_config.deployment_role_name))
        && can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.pipeline_scp_config.pipeline_role_name))
      )
    )
    error_message = "pipeline_scp_config deployment_role_name and pipeline_role_name must each be 1-64 characters of the IAM role name character set (letters, digits and +=,.@_-)."
  }
}

# --- Quarantine SCP ---

variable "enable_quarantine_scp" {
  description = "Create a Quarantine SCP for new accounts. The default document (tlz-quarantine-guardrails.json) denies every action to every principal except the roles AWSControlTowerExecution, TLZDeploymentRole, tlz-* and OrganizationAccountAccessRole; those roles keep every action, not only sts:AssumeRole."
  type        = bool
  default     = false
}

variable "quarantine_scp_content" {
  description = "Custom JSON policy content for the Quarantine SCP. Empty string uses the default document, which denies every action except to the four exempt role patterns named in enable_quarantine_scp (they keep every action)."
  type        = string
  default     = ""

  # Compact-form measurement, matching var.service_control_policies.
  validation {
    condition     = var.quarantine_scp_content == "" || length(try(jsonencode(jsondecode(var.quarantine_scp_content)), var.quarantine_scp_content)) <= 5120
    error_message = "quarantine_scp_content must be empty or at most 5120 characters in its compact JSON form (AWS SCP limit)."
  }
}

variable "quarantine_scp_targets" {
  description = "List of OU names or account IDs to attach the Quarantine SCP to"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for target in var.quarantine_scp_targets :
      can(regex("^\\d{12}$", target)) || can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", target))
    ])
    error_message = "Each quarantine SCP target must be either a 12-digit account ID or a valid OU name (starting with a letter, containing only alphanumeric characters, spaces, hyphens, and underscores)."
  }
}

# --- Resource Control Policies ---

variable "resource_control_policies" {
  description = "List of Resource Control Policy definitions with name, description, content, and target OUs/accounts. strategy selects between deny-list (the default: the AWS default policy RCPFullAWSAccess stays attached) and allow-list (the module detaches RCPFullAWSAccess from the entry's targets, so only the granted access remains; requires enable_allow_list_detach)."
  type = list(object({
    name        = string
    description = optional(string, "")
    content     = string
    targets     = list(string)
    strategy    = optional(string, "deny-list")
  }))
  default = []

  validation {
    condition = alltrue(flatten([
      for policy in var.resource_control_policies : [
        for target in policy.targets :
        can(regex("^\\d{12}$", target)) || can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", target))
      ]
    ]))
    error_message = "Each RCP target must be either a 12-digit account ID or a valid OU name."
  }

  validation {
    condition = alltrue([
      for policy in var.resource_control_policies :
      contains(["deny-list", "allow-list"], policy.strategy)
    ])
    error_message = "Each resource_control_policies strategy must be deny-list or allow-list."
  }

  validation {
    condition = alltrue([
      for policy in var.resource_control_policies :
      policy.strategy != "allow-list" || length(policy.targets) > 0
    ])
    error_message = "Each allow-list resource_control_policies entry must name at least one target — the entry's own policy is what keeps a detached target authorized."
  }

  validation {
    condition = alltrue([
      for policy in var.resource_control_policies :
      policy.strategy != "allow-list"
    ]) || var.enable_allow_list_detach
    error_message = "resource_control_policies entries with strategy allow-list require enable_allow_list_detach = true — without the switch the module never detaches RCPFullAWSAccess and the allow-list would not restrict anything."
  }
}

variable "unresolved_resource_control_policies" {
  description = "Names of resource control policies the caller left out because their document still carries an unresolved @@marker@@ (configurations/loader.hcl). The module creates none of them and names them in the check block rcp_documents_unresolved and the output of the same name."
  type        = list(string)
  default     = []
}

# --- Declarative Policies ---

variable "declarative_policies" {
  description = "List of Declarative Policy (EC2) definitions with name, description, content, and target OUs/accounts"
  type = list(object({
    name        = string
    description = optional(string, "")
    content     = string
    targets     = list(string)
  }))
  default = []

  validation {
    condition = alltrue(flatten([
      for policy in var.declarative_policies : [
        for target in policy.targets :
        can(regex("^\\d{12}$", target)) || can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", target))
      ]
    ]))
    error_message = "Each declarative policy target must be either a 12-digit account ID or a valid OU name."
  }
}

# --- Chatbot Policies ---

variable "chatbot_policies" {
  description = "List of Chatbot Policy definitions with name, description, content, and target OUs/accounts"
  type = list(object({
    name        = string
    description = optional(string, "")
    content     = string
    targets     = list(string)
  }))
  default = []

  validation {
    condition = alltrue(flatten([
      for policy in var.chatbot_policies : [
        for target in policy.targets :
        can(regex("^\\d{12}$", target)) || can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", target))
      ]
    ]))
    error_message = "Each chatbot policy target must be either a 12-digit account ID or a valid OU name."
  }
}

variable "additional_enabled_policy_types" {
  description = "Policy types to keep enabled on the organization root in addition to the ones the policy lists derive, for example AISERVICES_OPT_OUT_POLICY. aws_organizations_organization.this owns the COMPLETE enabled_policy_types list, so a type an adopted organization has enabled and this module does not derive is disabled on apply unless it is named here (read today's types with `aws organizations list-roots`). Empty keeps the derived list."
  type        = list(string)
  default     = []

  # shortcut: shape only, the provider's own validation knows the type names;
  # a list of names here would need an update with every new policy type.
  validation {
    condition     = alltrue([for t in var.additional_enabled_policy_types : can(regex("^[A-Z][A-Z0-9_]*$", t))])
    error_message = "Each additional_enabled_policy_types entry must be an Organizations policy type in upper case, such as AISERVICES_OPT_OUT_POLICY."
  }
}

# --- Quarantine SCP Auto-Detach ---

# --- Opt-In Region Auto-Enablement ---

variable "opt_in_regions" {
  description = "List of AWS opt-in region names to auto-enable via API (e.g. af-south-1, ap-east-1, eu-south-1, me-south-1). Empty list disables opt-in region management."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for region in var.opt_in_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", region))
    ])
    error_message = "Each opt-in region must be a valid AWS region name (e.g. af-south-1, ap-east-1)."
  }
}

variable "enable_quarantine_auto_detach" {
  description = "Enable automatic detachment of the quarantine SCP from new accounts after pipeline completion via Lambda. Requires enable_quarantine_scp = true."
  type        = bool
  default     = false
}

variable "quarantine_detach_pipeline_names" {
  description = "CodePipeline names whose SUCCEEDED state triggers the quarantine-SCP detach (enable_quarantine_auto_detach). The rule matches only these pipelines in this account and region; before this input it matched every pipeline. The default is the name modules/pipeline gives the TLZ deployment pipeline."
  type        = list(string)
  default     = ["tlz-deployment-pipeline"]

  validation {
    condition = length(var.quarantine_detach_pipeline_names) > 0 && alltrue([
      for name in var.quarantine_detach_pipeline_names :
      can(regex("^[A-Za-z0-9.@_-]{1,100}$", name))
    ])
    error_message = "quarantine_detach_pipeline_names must name at least one pipeline, each 1-100 characters of letters, digits, '.', '@', '_' and '-' (the CodePipeline name rule)."
  }
}

variable "quarantine_detach_topic_name" {
  description = "Name of the SNS topic that carries the quarantine-SCP detach notification (created when enable_quarantine_scp and enable_quarantine_auto_detach are both true). The default is the module's standard name. SNS CreateTopic is an UPSERT: an account already carrying this name is silently adopted rather than failing, so any apply-test of this module against a live account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live topic, subscriptions included. That the topic does not exist while the toggle is off is NOT a safety property: enabling enable_quarantine_auto_detach in production creates it under this default overnight, and a test asserting the default name becomes the deletion. The name must stay inside the tlz- namespace: the organization guardrails (ProtectSNSTopics) protect only arn:*:sns:*:*:tlz-* from tampering, so this validation carries the invariant. A changed default is a destroy/create of a deployed topic, so leave it at the literal below in production."
  type        = string
  default     = "tlz-quarantine-scp-detach-notification"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9_-]{1,252}$", var.quarantine_detach_topic_name))
    error_message = "quarantine_detach_topic_name must start with tlz- and be 1-256 characters of letters, digits, underscore or hyphen in total — the AWS SNS topic naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "quarantine_detach_rule_name" {
  description = "Name of the EventBridge rule that detects CodePipeline SUCCEEDED events for the quarantine-SCP detach (created when enable_quarantine_scp and enable_quarantine_auto_detach are both true). The default is the module's standard name. EventBridge PutRule is an UPSERT: an account already carrying this name is silently adopted rather than failing, so any apply-test of this module against a live account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rule and both its targets (SNS and Lambda). A toggle that is off is not a safety property — see quarantine_detach_topic_name. The name must stay inside the tlz- namespace: the organization guardrails (ProtectEventBridgeRules) protect only arn:*:events:*:*:rule/tlz-* from tampering; this validation carries the invariant. A changed default is a destroy/create of a deployed rule, so leave it at the literal below in production."
  type        = string
  default     = "tlz-quarantine-scp-pipeline-completion"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", var.quarantine_detach_rule_name))
    error_message = "quarantine_detach_rule_name must start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "quarantine_auto_detach_dlq_name" {
  description = "Name of the SQS dead-letter queue of the quarantine auto-detach Lambda (created when enable_quarantine_scp and enable_quarantine_auto_detach are both true). The default is the module's standard name. SQS CreateQueue is IDEMPOTENT for an existing queue with identical attributes (the module's own attributes always are): it returns the existing queue instead of failing, so any apply-test of this module against a live account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live queue together with every failed detach event it holds. A toggle that is off is not a safety property — see quarantine_detach_topic_name. The Lambda's execution policy (sqs:SendMessage on the DLQ) follows this name; Lambda validates that grant against dead_letter_config at create. Deliberately NOT pinned to the tlz- namespace: no organization guardrail names an SQS queue ARN (the RCPs' sqs:* statements are name-independent), so there is no protection for a validation to preserve; keep the prefix anyway for legibility. A changed default is a destroy/create of a deployed queue (its messages included), so leave it at the literal below in production."
  type        = string
  default     = "tlz-quarantine-auto-detach-dlq"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,80}$", var.quarantine_auto_detach_dlq_name))
    error_message = "quarantine_auto_detach_dlq_name must be 1-80 characters of letters, digits, underscore or hyphen — the SQS standard-queue naming rule (no dot, so no accidental .fifo suffix on a standard queue)."
  }
}

# --- SCP Revert Detection (G4) ---

# --- Account Move Automation ---

variable "enable_account_move_automation" {
  description = "Enable EventBridge + Lambda automation to move accounts between OUs based on Organizations API events"
  type        = bool
  default     = false
}

variable "account_move_log_retention_days" {
  description = "CloudWatch log retention in days for the account move Lambda's own execution log group /aws/lambda/tlz-account-move (0 = never expire). The default is one year: CKV_AWS_338 requires at least that, and the group holds only this function's own execution output, so the storage is a few MB per year"
  type        = number
  default     = 365

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.account_move_log_retention_days)
    error_message = "account_move_log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

# The module's three other automation Lambdas own their execution log groups
# too, each behind its function's toggle and with its own retention — the same
# per-function shape account_move_log_retention_days already has. Without the
# declaration Lambda creates /aws/lambda/<function name> implicitly on the
# first invocation, outside the state and without any retention. See README,
# "Lambda execution log groups".

variable "policy_strategy_detach_log_retention_days" {
  description = "CloudWatch log retention in days for the policy-strategy detach Lambda's own execution log group /aws/lambda/tlz-policy-strategy-detach (0 = never expire). Default of 365 keeps at least one year on hand for an SCP/RCP detach action, the org-wide operation this function performs."
  type        = number
  default     = 365

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.policy_strategy_detach_log_retention_days)
    error_message = "policy_strategy_detach_log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

variable "policy_strategy_detach_log_kms_key_arn" {
  description = "Optional KMS key ARN for encrypting the policy-strategy detach Lambda's execution log group. Empty string keeps the CloudWatch service default encryption; no key is created by this module."
  type        = string
  default     = ""

  validation {
    condition     = var.policy_strategy_detach_log_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.policy_strategy_detach_log_kms_key_arn))
    error_message = "policy_strategy_detach_log_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}

variable "quarantine_auto_detach_log_retention_days" {
  description = "CloudWatch log retention in days for the quarantine auto-detach Lambda's own execution log group /aws/lambda/tlz-quarantine-auto-detach (0 = never expire). The default is one year: CKV_AWS_338 requires at least that, and the group holds only this function's own execution output, so the storage is a few MB per year"
  type        = number
  default     = 365

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.quarantine_auto_detach_log_retention_days)
    error_message = "quarantine_auto_detach_log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

variable "scp_auto_revert_log_retention_days" {
  description = "CloudWatch log retention in days for the SCP auto-revert Lambda's own execution log group /aws/lambda/tlz-scp-auto-revert (0 = never expire). The default is one year: CKV_AWS_338 requires at least that, and the group holds only this function's own execution output, so the storage is a few MB per year"
  type        = number
  default     = 365

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.scp_auto_revert_log_retention_days)
    error_message = "scp_auto_revert_log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

variable "account_move_rule_name" {
  description = "Name of the EventBridge rule that triggers the account-move Lambda on Organizations CreateAccount and MoveAccount events (created when enable_account_move_automation is true). The default is the module's standard name. EventBridge PutRule is an UPSERT: an account already carrying this name is silently adopted rather than failing, so any apply-test of this module against a live account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rule and its Lambda target. That the rule does not exist while the toggle is off is NOT a safety property: enabling enable_account_move_automation in production creates it under this default overnight. The name must stay inside the tlz- namespace: the organization guardrails (ProtectEventBridgeRules) protect only arn:*:events:*:*:rule/tlz-* from tampering, so this validation carries the invariant. The Lambda function, its role and its log group keep their fixed names (create-only APIs — a collision fails loudly instead of adopting). A changed default is a destroy/create of a deployed rule, so leave it at the literal below in production."
  type        = string
  default     = "tlz-account-move"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", var.account_move_rule_name))
    error_message = "account_move_rule_name must start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

# --- SCP Revert Detection (G4) ---

variable "enable_scp_revert_detection" {
  description = "Enable EventBridge-based detection of SCP modifications outside Terraform. AWS Organizations delivers its CloudTrail events to EventBridge in us-east-1 only (aws partition): in any other region the rule receives nothing, and the check scp_revert_detection_region warns at plan."
  type        = bool
  default     = false
}

variable "scp_revert_notification_emails" {
  description = "List of email addresses to notify when SCP modifications are detected"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for address in var.scp_revert_notification_emails :
      can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[a-zA-Z]{2,}$", address))
    ])
    error_message = "Each scp_revert_notification_emails entry must be an email address. SNS accepts a malformed address as a pending subscription that never confirms, so the SCP change notification stays silently undelivered."
  }

  validation {
    condition     = length(distinct(var.scp_revert_notification_emails)) == length(var.scp_revert_notification_emails)
    error_message = "scp_revert_notification_emails must not contain duplicates."
  }
}

variable "scp_revert_topic_name" {
  description = "Name of the SNS topic that carries SCP modification notifications (created when enable_scp_revert_detection is true). The default is the module's account-wide standard name, which may already exist in a deployed management account. SNS CreateTopic is an UPSERT: an account already carrying this name is silently adopted rather than failing, so any apply-test of this module against a live account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live topic, subscriptions included. The name must stay inside the tlz- namespace: the organization guardrails (ProtectSNSTopics) protect only arn:*:sns:*:*:tlz-* from tampering. A changed default is a destroy/create of the live topic, so leave it at the literal below in production."
  type        = string
  default     = "tlz-scp-revert-detection"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9_-]{1,252}$", var.scp_revert_topic_name))
    error_message = "scp_revert_topic_name must start with tlz- and be 1-256 characters of letters, digits, underscore or hyphen in total — the AWS SNS topic naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "scp_revert_rule_name" {
  description = "Name of the EventBridge rule that detects SCP modifications (created when enable_scp_revert_detection is true). The default is the module's account-wide standard name, which may already exist in a deployed management account. EventBridge PutRule is an UPSERT: an account already carrying this name is silently adopted rather than failing, so any apply-test of this module against a live account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rule and its targets. The name must stay inside the tlz- namespace: the organization guardrails (ProtectEventBridgeRules) protect only arn:*:events:*:*:rule/tlz-* from tampering. A changed default is a destroy/create of the live rule, so leave it at the literal below in production."
  type        = string
  default     = "tlz-scp-modification-detection"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", var.scp_revert_rule_name))
    error_message = "scp_revert_rule_name must start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "enable_scp_auto_revert" {
  description = "Enable automatic revert of unauthorized SCP modifications via Lambda. Requires enable_scp_revert_detection = true. UpdatePolicy is reverted to the content this module deployed (SCPs, RCPs, quarantine and pipeline SCP); a policy the module does not manage and DeletePolicy are reported as not reverted. DetachPolicy is undone by re-attaching."
  type        = bool
  default     = false
}

variable "scp_auto_revert_dlq_name" {
  description = "Name of the SQS dead-letter queue of the SCP auto-revert Lambda (created when enable_scp_revert_detection and enable_scp_auto_revert are both true). The default is the module's standard name. SQS CreateQueue is IDEMPOTENT for an existing queue with identical attributes (the module's own attributes always are): it returns the existing queue instead of failing, so any apply-test of this module against a live account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live queue together with every unauthorized SCP change whose revert failed, which for a security guard function must stay observable and replayable. That the queue does not exist while the toggle is off is NOT a safety property: enabling enable_scp_auto_revert in production creates it under this default overnight. The Lambda's execution policy (sqs:SendMessage on the DLQ) follows this name; Lambda validates that grant against dead_letter_config at create. Deliberately NOT pinned to the tlz- namespace: no organization guardrail names an SQS queue ARN (the RCPs' sqs:* statements are name-independent), so there is no protection for a validation to preserve; keep the prefix anyway for legibility. A changed default is a destroy/create of a deployed queue (its messages included), so leave it at the literal below in production."
  type        = string
  default     = "tlz-scp-auto-revert-dlq"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,80}$", var.scp_auto_revert_dlq_name))
    error_message = "scp_auto_revert_dlq_name must be 1-80 characters of letters, digits, underscore or hyphen — the SQS standard-queue naming rule (no dot, so no accidental .fifo suffix on a standard queue)."
  }
}
