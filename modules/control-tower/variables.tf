variable "management_account_id" {
  description = "Management account ID for trust policies (optional — resolved via aws_caller_identity when empty)"
  type        = string
  default     = ""

  validation {
    condition     = var.management_account_id == "" || can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be empty or a 12-digit AWS account ID."
  }
}

variable "audit_account_id" {
  description = "Account ID of the Audit account"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.audit_account_id))
    error_message = "audit_account_id must be a 12-digit AWS account ID."
  }
}

variable "log_archive_account_id" {
  description = "Account ID of the Log-Archive account"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.log_archive_account_id))
    error_message = "log_archive_account_id must be a 12-digit AWS account ID."
  }
}

variable "landing_zone_version" {
  description = "Control Tower Landing Zone version (4.x — the module builds the v4 manifest schema only)"
  type        = string
  default     = "4.0"

  # The module assembles the v4 manifest schema only. A 3.x
  # version would need the organizationStructure section the v4 schema
  # dropped, so anything below 4 is rejected here instead of failing at
  # CreateLandingZone with an incomplete manifest.
  validation {
    condition     = can(regex("^4\\.[0-9]+$", var.landing_zone_version))
    error_message = "landing_zone_version must be a 4.x version (e.g. '4.0') — the module builds the v4 manifest schema only."
  }
}

variable "governed_regions" {
  description = "Regions under CT governance"
  type        = list(string)

  validation {
    condition     = length(var.governed_regions) > 0
    error_message = "governed_regions must not be empty — at least one region is required."
  }

  validation {
    condition     = alltrue([for r in var.governed_regions : can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))])
    error_message = "Each region must have a valid AWS region format (e.g. 'eu-central-1')."
  }
}

variable "logging_retention_days" {
  description = "Retention for CloudTrail logs in days"
  type        = number
  default     = 365

  validation {
    condition     = var.logging_retention_days >= 1 && var.logging_retention_days <= 5475
    error_message = "logging_retention_days must be between 1 and 5475 (15 years)."
  }
}

variable "access_logging_retention_days" {
  description = "Retention for S3 access logs in days"
  type        = number
  default     = 365

  validation {
    condition     = var.access_logging_retention_days >= 1 && var.access_logging_retention_days <= 5475
    error_message = "access_logging_retention_days must be between 1 and 5475 (15 years)."
  }
}

variable "enable_identity_center" {
  description = "Enable IAM Identity Center (SSO)"
  type        = bool
  default     = true
}

variable "enable_organization_trail" {
  description = "Whether Control Tower keeps its centralized logging — the organization-wide CloudTrail trail delivering into the Log Archive account (manifest field centralizedLogging.enabled). Default true; disable only when an own organization trail replaces it."
  type        = bool
  default     = true
}

variable "enable_backup_integration" {
  description = "Whether Control Tower manages AWS Backup (manifest field backup.enabled). The v4 manifest requires an explicit enabled flag for every service integration; default false keeps backup outside Control Tower — the backup module manages vaults and plans independently."
  type        = bool
  default     = false
}

# --- CT Controls ---

variable "control_tower_controls" {
  description = "List of Control Tower controls (guardrails) to enable on specified OUs. control_identifier is the partition-neutral control name (e.g. CONFIG.CLOUDTRAIL.DT.5) — the module builds the control ARN from the current partition; a full control ARN is passed through unchanged. Each control may carry parameters — key/value pairs forwarded to the EnableControl API, where the value is a JSON document string (use jsonencode). Region-aware controls such as the region-deny control take their region scope this way (e.g. key AllowedRegions with a JSON list of regions)."
  type = list(object({
    control_identifier   = string
    organizational_units = list(string)
    parameters = optional(list(object({
      key   = string
      value = string
    })), [])
  }))
  default = []

  # aws_controltower_control.target_identifier requires an OU ARN. Each entry of
  # organizational_units must therefore either be resolvable through
  # ou_name_to_arn or already be an OU ARN. Anything else — a typo in the OU
  # name, an incomplete ou_name_to_arn — is rejected here instead of being
  # forwarded to AWS as a target identifier.
  validation {
    condition = alltrue(flatten([
      for control in var.control_tower_controls : [
        for ou in control.organizational_units :
        contains(keys(var.ou_name_to_arn), ou) || can(regex("^arn:[a-z0-9-]+:organizations::[0-9]{12}:ou/o-[a-z0-9]+/ou-[a-z0-9]+-[a-z0-9]+$", ou))
      ]
    ]))
    error_message = "Each control_tower_controls organizational_units entry must be a key of ou_name_to_arn or an OU ARN (arn:<partition>:organizations::<account-id>:ou/o-<org-id>/ou-<root>-<ou>). Unresolvable OU names cannot be used as a Control Tower control target."
  }

  # Parameter keys are the PascalCase names the EnableControl API defines per
  # control (AllowedRegions, ExemptedPrincipalArns, ...). The set is
  # control-specific and grows with the control catalog, so the shape is
  # enforced instead of a closed list — a closed list would wrongly reject
  # valid keys of newer controls, while a malformed key can never be valid.
  validation {
    condition = alltrue(flatten([
      for control in var.control_tower_controls : [
        for parameter in control.parameters :
        can(regex("^[A-Za-z][A-Za-z0-9]*$", parameter.key))
      ]
    ]))
    error_message = "Each control_tower_controls parameter key must be an alphanumeric API parameter name starting with a letter (e.g. AllowedRegions)."
  }

  # The API expects every parameter value as a JSON document. Rejecting a
  # non-JSON value here turns the late EnableControl failure (which only
  # surfaces during apply, after minutes of control provisioning) into a
  # plan-time message.
  validation {
    condition = alltrue(flatten([
      for control in var.control_tower_controls : [
        for parameter in control.parameters :
        can(jsondecode(parameter.value))
      ]
    ]))
    error_message = "Each control_tower_controls parameter value must be a JSON document string — build it with jsonencode (e.g. jsonencode([\"eu-central-1\"]))."
  }

  validation {
    condition = alltrue([
      for control in var.control_tower_controls :
      length(distinct([for parameter in control.parameters : parameter.key])) == length(control.parameters)
    ])
    error_message = "control_tower_controls parameter keys must be unique per control — the API takes each parameter once and a duplicate would silently drop one value."
  }
}

variable "ou_name_to_arn" {
  description = "Map of OU name to OU ARN, passed from root module for resolving OU names in control targets"
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name, arn in var.ou_name_to_arn :
      can(regex("^arn:[a-z0-9-]+:organizations::[0-9]{12}:ou/o-[a-z0-9]+/ou-[a-z0-9]+-[a-z0-9]+$", arn))
    ])
    error_message = "Each ou_name_to_arn value must be an OU ARN (arn:<partition>:organizations::<account-id>:ou/o-<org-id>/ou-<root>-<ou>)."
  }
}

# --- CT OU Auto-Enrollment ---

variable "auto_enroll_ous" {
  description = "List of OU names to register for AWS Control Tower governance. Registration is documented via check block — the Terraform provider does not support OU registration as a native resource."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for ou in var.auto_enroll_ous :
      can(regex("^[a-zA-Z][a-zA-Z0-9 _-]*$", ou)) && length(ou) > 0
    ])
    error_message = "Each auto_enroll_ous entry must be a non-empty string starting with a letter, containing only alphanumeric characters, spaces, hyphens, and underscores."
  }
}
