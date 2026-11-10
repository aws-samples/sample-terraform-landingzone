# Security module variables

# --- EBS Default Encryption ---

variable "enable_ebs_default_encryption" {
  description = "Enable EBS default encryption for all new volumes in the account"
  type        = bool
  default     = true
}

variable "ebs_default_kms_key_arn" {
  description = "Custom KMS key ARN for EBS default encryption. Empty string uses the AWS-managed aws/ebs key."
  type        = string
  default     = ""

  validation {
    condition     = var.ebs_default_kms_key_arn == "" || can(regex("^arn:", var.ebs_default_kms_key_arn))
    error_message = "ebs_default_kms_key_arn must be empty or a valid ARN starting with 'arn:'."
  }
}

# --- S3 Account Public Access Block ---

variable "enable_s3_public_access_block" {
  description = "Enable S3 account-level public access block to prevent public access to all S3 buckets"
  type        = bool
  default     = true
}

variable "audit_account_id" {
  description = "Account ID for the delegated security admin (Audit account). Empty string disables delegation."
  type        = string

  validation {
    condition     = var.audit_account_id == "" || can(regex("^\\d{12}$", var.audit_account_id))
    error_message = "audit_account_id must be empty or a 12-digit AWS account ID."
  }
}

# --- GuardDuty Protection Toggles ---

variable "guardduty_s3_protection" {
  description = "Enable GuardDuty S3 Data Events protection (S3_DATA_EVENTS detector feature)"
  type        = bool
  default     = true
}

variable "guardduty_malware_protection" {
  description = "Enable GuardDuty EBS Malware Protection (EBS_MALWARE_PROTECTION detector feature)"
  type        = bool
  default     = true
}

variable "guardduty_eks_protection" {
  description = "Enable GuardDuty EKS Audit Logs protection (EKS_AUDIT_LOGS detector feature)"
  type        = bool
  default     = true
}

# --- GuardDuty Lambda Protection (G1) ---

variable "guardduty_lambda_protection" {
  description = "Enable GuardDuty Lambda Network Logs protection (LAMBDA_NETWORK_LOGS detector feature)"
  type        = bool
  default     = true
}

# --- GuardDuty RDS Protection (G2) ---

variable "guardduty_rds_protection" {
  description = "Enable GuardDuty RDS Login Events protection (RDS_LOGIN_EVENTS detector feature)"
  type        = bool
  default     = true
}

# --- GuardDuty S3 Malware Protection ---

variable "enable_guardduty_s3_malware_protection" {
  description = "Enable GuardDuty S3 Malware Protection to scan S3 objects for malware. Requires enable_guardduty = true."
  type        = bool
  default     = false
}

variable "guardduty_s3_malware_configs" {
  description = "List of S3 bucket configurations for GuardDuty malware scanning. Each entry creates a malware protection plan for the specified bucket. enable_malware_protection_tags controls whether scanned objects receive the scan result tag (default true); tags are assigned to the protection plan resource."
  type = list(object({
    bucket_name                    = string
    object_prefixes                = optional(list(string), [])
    kms_key_arn                    = optional(string, null)
    enable_malware_protection_tags = optional(bool, true)
    tags                           = optional(map(string), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for c in var.guardduty_s3_malware_configs :
      length(trimspace(c.bucket_name)) > 0
    ])
    error_message = "Each guardduty_s3_malware_configs entry must have a non-empty bucket_name."
  }

  validation {
    condition = alltrue([
      for c in var.guardduty_s3_malware_configs :
      c.kms_key_arn == null || can(regex("^arn:", c.kms_key_arn))
    ])
    error_message = "Each guardduty_s3_malware_configs kms_key_arn must be null or a valid ARN starting with 'arn:'."
  }

  validation {
    condition = alltrue(flatten([
      for c in var.guardduty_s3_malware_configs : [
        for key, value in c.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in guardduty_s3_malware_configs must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

variable "guardduty_keep_malware_snapshots" {
  description = "Keep the EBS snapshots GuardDuty creates while scanning for malware, when the scan finds malware. false applies the service default (no retention) and creates nothing; true deploys a small settings function that applies the retention setting to the detector at deployment time and reverts it on removal."
  type        = bool
  default     = false
}

# The module's two settings Lambdas own their execution log groups. Lambda
# would otherwise create /aws/lambda/<function name> implicitly on the first
# invocation — outside the state, without retention, never destroyed. Both
# functions are invoked synchronously by Terraform during the apply, so the
# group has to exist before the invocation runs. See README, "Lambda execution
# log groups".

variable "guardduty_scan_settings_log_retention_days" {
  description = "Retention of the GuardDuty malware-scan settings Lambda's own execution log group /aws/lambda/tlz-guardduty-scan-settings, which the module declares (0 = never expire). The default is one year: CKV_AWS_338 requires at least that, and the group holds only this function's own execution output, so the storage is a few MB per year"
  type        = number
  default     = 365

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.guardduty_scan_settings_log_retention_days)
    error_message = "guardduty_scan_settings_log_retention_days must be one of the CloudWatch retention values: 0 (never expire), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

variable "macie_session_settings_log_retention_days" {
  description = "Retention of the Macie session-settings Lambda's own execution log group /aws/lambda/tlz-macie-session-settings, which the module declares (0 = never expire). The default is one year: CKV_AWS_338 requires at least that, and the group holds only this function's own execution output, so the storage is a few MB per year"
  type        = number
  default     = 365

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.macie_session_settings_log_retention_days)
    error_message = "macie_session_settings_log_retention_days must be one of the CloudWatch retention values: 0 (never expire), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

# --- Security Hub Region Aggregation ---

variable "enable_security_hub_region_aggregation" {
  description = "Enable Security Hub cross-region finding aggregation to the home region"
  type        = bool
  default     = true
}

variable "security_hub_aggregation_regions" {
  description = "List of regions to aggregate findings from. Empty list uses ALL_REGIONS linking mode."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.security_hub_aggregation_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in security_hub_aggregation_regions must be a valid AWS region format (e.g., eu-central-1)."
  }
}

# --- Service Toggles ---

variable "enable_guardduty" {
  description = "Enable GuardDuty organization-wide threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub organization-wide security posture management"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable Macie for sensitive data discovery (not available in aws-eusc)"
  type        = bool
  default     = false
}

variable "enable_access_analyzer" {
  description = "Enable IAM Access Analyzer at organization level"
  type        = bool
  default     = true
}

# --- SSM Block Public Document Sharing ---

variable "enable_ssm_block_public_sharing" {
  description = "Block public sharing of SSM documents in this account/region"
  type        = bool
  default     = true
}

# --- Partition ---

variable "is_eusc" {
  description = "Whether the active partition is aws-eusc (passed from root module for testability)"
  type        = bool
  default     = false
}

# --- Security Hub Standards ---

variable "security_hub_standards" {
  # A per-entry choice between an ARN suffix string and an object cannot be
  # expressed by a Terraform list type — list(any) rejects a mixed list during
  # type unification. The module
  # takes the structured form only; a plain list of ARN suffix strings stays
  # accepted at the configuration layer, where the loader converts it to this
  # form (configurations/loader.hcl, _normalized_security_hub_standards).
  description = "List of Security Hub standard definitions: arn_suffix plus an enabled flag (default true). Disabled standards serve as documentation only. Plain ARN suffix strings are accepted in the configuration layer and converted by the loader."
  type = list(object({
    arn_suffix = string
    enabled    = optional(bool, true)
  }))
  default = [
    { arn_suffix = "aws-foundational-security-best-practices/v/1.0.0" },
    { arn_suffix = "cis-aws-foundations-benchmark/v/1.4.0" }
  ]

  # An ARN suffix looks like <standard-name>/v/<version>. A bare standard name
  # without the version segment is accepted by the API as an unknown ARN and the
  # standard never gets enabled.
  validation {
    condition = alltrue([
      for standard in var.security_hub_standards :
      can(regex("^[a-z0-9-]+/v/[0-9]+\\.[0-9]+\\.[0-9]+$", standard.arn_suffix))
    ])
    error_message = "Each security_hub_standards ARN suffix must have the form <standard-name>/v/<major>.<minor>.<patch>, for example cis-aws-foundations-benchmark/v/3.0.0."
  }

  validation {
    condition = length(distinct([
      for standard in var.security_hub_standards : standard.arn_suffix
    ])) == length(var.security_hub_standards)
    error_message = "security_hub_standards must not name the same standard twice — the duplicate would be billed for the same checks."
  }
}

# --- Password Policy ---

variable "password_policy" {
  description = "IAM account password policy configuration"
  type = object({
    minimum_length            = optional(number, 14)
    require_uppercase         = optional(bool, true)
    require_lowercase         = optional(bool, true)
    require_numbers           = optional(bool, true)
    require_symbols           = optional(bool, true)
    max_age                   = optional(number, 90)
    password_reuse_prevention = optional(number, 24)
    allow_users_to_change     = optional(bool, true)
    hard_expiry               = optional(bool, false)
  })
  # The default object spells out every attribute even though the optional()
  # defaults in the type would produce the same values for an empty object.
  # Static analyzers evaluate variable defaults but not type-level optional()
  # defaults, so `default = {}` made the compliant password policy unprovable
  # for the security scan. Keep both lists in sync when changing a default.
  default = {
    minimum_length            = 14
    require_uppercase         = true
    require_lowercase         = true
    require_numbers           = true
    require_symbols           = true
    max_age                   = 90
    password_reuse_prevention = 24
    allow_users_to_change     = true
    hard_expiry               = false
  }

  validation {
    condition     = var.password_policy.minimum_length >= 8 && var.password_policy.minimum_length <= 128
    error_message = "password_policy.minimum_length must be between 8 and 128."
  }

  validation {
    condition     = var.password_policy.max_age >= 0 && var.password_policy.max_age <= 1095
    error_message = "password_policy.max_age must be between 0 and 1095 days."
  }

  validation {
    condition     = var.password_policy.password_reuse_prevention >= 0 && var.password_policy.password_reuse_prevention <= 24
    error_message = "password_policy.password_reuse_prevention must be between 0 and 24."
  }
}

# --- Session Manager Logging ---

variable "enable_session_manager_s3_logging" {
  description = "Enable/disable Session Manager S3 logging. When false, s3BucketName is set to empty regardless of session_manager_s3_bucket_name."
  type        = bool
  default     = false
}

variable "enable_session_manager_logging" {
  description = "Enable Session Manager logging to S3 and/or CloudWatch via SSM document"
  type        = bool
  default     = false
}

variable "session_manager_s3_bucket_name" {
  description = "S3 bucket name for Session Manager session logging. Empty string disables S3 logging."
  type        = string
  default     = ""

  validation {
    condition     = var.session_manager_s3_bucket_name == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.session_manager_s3_bucket_name))
    error_message = "session_manager_s3_bucket_name must be empty (S3 logging disabled) or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

variable "session_manager_s3_key_prefix" {
  description = "S3 key prefix for Session Manager session logs"
  type        = string
  default     = "ssm-sessions/"

  # A leading slash produces an empty first path segment in S3, so the objects
  # land one level below where the prefix reads.
  validation {
    condition     = var.session_manager_s3_key_prefix == "" || !startswith(var.session_manager_s3_key_prefix, "/")
    error_message = "session_manager_s3_key_prefix must not start with a slash — S3 keys are relative and a leading slash creates an empty path segment."
  }
}

variable "session_manager_cloudwatch_log_group" {
  description = "CloudWatch Log Group name for Session Manager session logging. Empty string disables CloudWatch logging."
  type        = string
  default     = ""

  validation {
    condition     = var.session_manager_cloudwatch_log_group == "" || can(regex("^/[A-Za-z0-9_./#-]{1,511}$", var.session_manager_cloudwatch_log_group))
    error_message = "session_manager_cloudwatch_log_group must be empty (CloudWatch logging disabled) or a log group name starting with a slash, for example /aws/ssm/session-manager."
  }
}

# --- Session Manager IAM Policy Attachment ---

variable "session_manager_attach_policy_to_roles" {
  description = "List of IAM role names to attach the Session Manager IAM policy to. Empty list skips policy creation."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for name in var.session_manager_attach_policy_to_roles :
      can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", name))
    ])
    error_message = "Each session_manager_attach_policy_to_roles entry must be an IAM role name (1-64 characters of letters, digits and +=,.@_-), not an ARN."
  }

  validation {
    condition     = length(distinct(var.session_manager_attach_policy_to_roles)) == length(var.session_manager_attach_policy_to_roles)
    error_message = "session_manager_attach_policy_to_roles must not contain duplicates."
  }
}

# --- Session Manager Excluded Accounts ---

variable "session_manager_excluded_accounts" {
  description = "List of account IDs excluded from the Session Manager logging configuration. The current account is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.session_manager_excluded_accounts :
      can(regex("^[0-9]{12}$", id))
    ])
    error_message = "Each session_manager_excluded_accounts entry must be a 12-digit AWS account ID — an account name would silently never match and the exclusion would not apply."
  }

  validation {
    condition     = length(distinct(var.session_manager_excluded_accounts)) == length(var.session_manager_excluded_accounts)
    error_message = "session_manager_excluded_accounts must not contain duplicates."
  }
}

# --- Session Manager KMS Encryption ---

variable "session_manager_kms_key_id" {
  description = "KMS key ID or ARN for Session Manager session encryption. Empty string disables KMS encryption."
  type        = string
  default     = ""

  validation {
    condition = (
      var.session_manager_kms_key_id == ""
      || can(regex("^(arn:[a-z0-9-]+:kms:|alias/|[0-9a-f-]{36}$)", var.session_manager_kms_key_id))
    )
    error_message = "session_manager_kms_key_id must be empty (no KMS encryption), a KMS key ARN, an alias/<name> or a key UUID."
  }
}

# --- GuardDuty Export Configuration ---

variable "guardduty_export_frequency" {
  description = "Frequency for exporting GuardDuty findings to S3. Valid values: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS. Set to null to disable export."
  type        = string
  default     = null

  validation {
    condition     = var.guardduty_export_frequency == null || contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_export_frequency)
    error_message = "guardduty_export_frequency must be null, FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "central_log_bucket_name" {
  description = "Name of the central logging S3 bucket for GuardDuty findings export. Required when guardduty_export_frequency is set."
  type        = string
  default     = ""

  validation {
    condition     = var.central_log_bucket_name == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.central_log_bucket_name))
    error_message = "central_log_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

# --- Security Hub Automation Rules ---

variable "security_hub_automation_rules" {
  description = "List of Security Hub automation rules to create. Each rule can filter findings by string, number, date and key-value criteria and apply finding field updates such as severity, workflow status, notes, confidence, criticality and related findings. Rules can be disabled per entry (enabled) and skipped in named regions (exclude_regions)."
  type = list(object({
    rule_name       = string
    rule_order      = number
    description     = string
    is_terminal     = optional(bool, false)
    enabled         = optional(bool, true)
    exclude_regions = optional(list(string), [])
    criteria = optional(object({
      # --- string filters: comparison + value ---
      product_name = optional(list(object({
        comparison = string
        value      = string
      })), [])
      severity_label = optional(list(object({
        comparison = string
        value      = string
      })), [])
      resource_id = optional(list(object({
        comparison = string
        value      = string
      })), [])
      resource_type = optional(list(object({
        comparison = string
        value      = string
      })), [])
      workflow_status = optional(list(object({
        comparison = string
        value      = string
      })), [])
      compliance_status = optional(list(object({
        comparison = string
        value      = string
      })), [])
      record_state = optional(list(object({
        comparison = string
        value      = string
      })), [])
      title = optional(list(object({
        comparison = string
        value      = string
      })), [])
      type = optional(list(object({
        comparison = string
        value      = string
      })), [])
      aws_account_id = optional(list(object({
        comparison = string
        value      = string
      })), [])
      compliance_security_control_id = optional(list(object({
        comparison = string
        value      = string
      })), [])
      aws_account_name = optional(list(object({
        comparison = string
        value      = string
      })), [])
      company_name = optional(list(object({
        comparison = string
        value      = string
      })), [])
      compliance_associated_standards_id = optional(list(object({
        comparison = string
        value      = string
      })), [])
      description = optional(list(object({
        comparison = string
        value      = string
      })), [])
      generator_id = optional(list(object({
        comparison = string
        value      = string
      })), [])
      id = optional(list(object({
        comparison = string
        value      = string
      })), [])
      note_text = optional(list(object({
        comparison = string
        value      = string
      })), [])
      note_updated_by = optional(list(object({
        comparison = string
        value      = string
      })), [])
      product_arn = optional(list(object({
        comparison = string
        value      = string
      })), [])
      related_findings_id = optional(list(object({
        comparison = string
        value      = string
      })), [])
      related_findings_product_arn = optional(list(object({
        comparison = string
        value      = string
      })), [])
      resource_application_arn = optional(list(object({
        comparison = string
        value      = string
      })), [])
      resource_application_name = optional(list(object({
        comparison = string
        value      = string
      })), [])
      resource_partition = optional(list(object({
        comparison = string
        value      = string
      })), [])
      resource_region = optional(list(object({
        comparison = string
        value      = string
      })), [])
      source_url = optional(list(object({
        comparison = string
        value      = string
      })), [])
      verification_state = optional(list(object({
        comparison = string
        value      = string
      })), [])
      # --- number filters: one exact value (eq) or a bound combination ---
      confidence = optional(list(object({
        eq  = optional(number)
        gt  = optional(number)
        gte = optional(number)
        lt  = optional(number)
        lte = optional(number)
      })), [])
      criticality = optional(list(object({
        eq  = optional(number)
        gt  = optional(number)
        gte = optional(number)
        lt  = optional(number)
        lte = optional(number)
      })), [])
      # --- date filters: rolling date_range or fixed start/end window ---
      created_at = optional(list(object({
        start = optional(string)
        end   = optional(string)
        date_range = optional(object({
          unit  = string
          value = number
        }))
      })), [])
      first_observed_at = optional(list(object({
        start = optional(string)
        end   = optional(string)
        date_range = optional(object({
          unit  = string
          value = number
        }))
      })), [])
      last_observed_at = optional(list(object({
        start = optional(string)
        end   = optional(string)
        date_range = optional(object({
          unit  = string
          value = number
        }))
      })), [])
      note_updated_at = optional(list(object({
        start = optional(string)
        end   = optional(string)
        date_range = optional(object({
          unit  = string
          value = number
        }))
      })), [])
      updated_at = optional(list(object({
        start = optional(string)
        end   = optional(string)
        date_range = optional(object({
          unit  = string
          value = number
        }))
      })), [])
      # --- key-value filters: comparison + key + value ---
      resource_tags = optional(list(object({
        key        = string
        value      = string
        comparison = string
      })), [])
      resource_details_other = optional(list(object({
        key        = string
        value      = string
        comparison = string
      })), [])
      user_defined_fields = optional(list(object({
        key        = string
        value      = string
        comparison = string
      })), [])
    }), {})
    actions = optional(object({
      type = optional(string, "FINDING_FIELDS_UPDATE")
      finding_fields_update = optional(object({
        severity = optional(object({
          label   = optional(string)
          product = optional(string)
        }))
        note = optional(object({
          text       = string
          updated_by = string
        }))
        workflow = optional(object({
          status = string
        }))
        verification_state  = optional(string)
        types               = optional(list(string))
        user_defined_fields = optional(map(string))
        confidence          = optional(number)
        criticality         = optional(number)
        related_findings = optional(list(object({
          id          = string
          product_arn = string
        })), [])
      }))
    }), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules :
      r.rule_order >= 1 && r.rule_order <= 1000
    ])
    error_message = "Each security_hub_automation_rules entry must have a rule_order between 1 and 1000."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for region in r.exclude_regions :
        can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", region))
      ])
    ])
    error_message = "Each exclude_regions entry in security_hub_automation_rules must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules :
      r.actions.type == "FINDING_FIELDS_UPDATE"
    ])
    error_message = "Each security_hub_automation_rules actions.type must be FINDING_FIELDS_UPDATE — the only action type the Security Hub automation rules API defines."
  }

  # One operator vocabulary for every string criteria list. The API rejects an
  # unknown comparison only when a matching finding arrives; the plan-time check
  # keeps the mistake out of the deployed rule.
  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for f in concat(
          r.criteria.product_name, r.criteria.severity_label, r.criteria.resource_id,
          r.criteria.resource_type, r.criteria.workflow_status, r.criteria.compliance_status,
          r.criteria.record_state, r.criteria.title, r.criteria.type,
          r.criteria.aws_account_id, r.criteria.compliance_security_control_id,
          r.criteria.aws_account_name, r.criteria.company_name,
          r.criteria.compliance_associated_standards_id, r.criteria.description,
          r.criteria.generator_id, r.criteria.id, r.criteria.note_text,
          r.criteria.note_updated_by, r.criteria.product_arn,
          r.criteria.related_findings_id, r.criteria.related_findings_product_arn,
          r.criteria.resource_application_arn, r.criteria.resource_application_name,
          r.criteria.resource_partition, r.criteria.resource_region,
          r.criteria.source_url, r.criteria.verification_state
          ) : contains(
          ["EQUALS", "PREFIX", "NOT_EQUALS", "PREFIX_NOT_EQUALS", "CONTAINS", "NOT_CONTAINS", "CONTAINS_WORD"],
          f.comparison
        )
      ])
    ])
    error_message = "Each string criteria comparison in security_hub_automation_rules must be one of: EQUALS, PREFIX, NOT_EQUALS, PREFIX_NOT_EQUALS, CONTAINS, NOT_CONTAINS, CONTAINS_WORD."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for f in concat(r.criteria.resource_tags, r.criteria.resource_details_other, r.criteria.user_defined_fields) :
        contains(["EQUALS", "NOT_EQUALS", "CONTAINS", "NOT_CONTAINS"], f.comparison) && length(f.key) > 0
      ])
    ])
    error_message = "Each key-value criteria entry in security_hub_automation_rules needs a non-empty key and a comparison of: EQUALS, NOT_EQUALS, CONTAINS, NOT_CONTAINS."
  }

  # A number criterion is either exact (eq) or a bound combination
  # (gt/gte/lt/lte) — exactly one operator form, never both, never neither.
  # Confidence and criticality are 0-100 scores, so every bound stays in range.
  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for f in concat(r.criteria.confidence, r.criteria.criticality) : (
          (f.eq != null && f.gt == null && f.gte == null && f.lt == null && f.lte == null) ||
          (f.eq == null && (f.gt != null || f.gte != null || f.lt != null || f.lte != null))
        )
      ])
    ])
    error_message = "Each number criteria entry (confidence, criticality) in security_hub_automation_rules must use exactly one operator form: either eq alone, or a combination of gt/gte/lt/lte."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for f in concat(r.criteria.confidence, r.criteria.criticality) : alltrue([
          for v in [f.eq, f.gt, f.gte, f.lt, f.lte] :
          v == null || (try(v >= 0, false) && try(v <= 100, false))
        ])
      ])
    ])
    error_message = "Each number criteria bound (confidence, criticality) in security_hub_automation_rules must be between 0 and 100."
  }

  # A date criterion is either a rolling window (date_range) or a fixed window
  # (start and/or end) — exactly one form. The only unit the API defines for
  # the rolling form is DAYS.
  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for f in concat(
          r.criteria.created_at, r.criteria.first_observed_at, r.criteria.last_observed_at,
          r.criteria.note_updated_at, r.criteria.updated_at
          ) : (
          (f.date_range != null && f.start == null && f.end == null) ||
          (f.date_range == null && (f.start != null || f.end != null))
        )
      ])
    ])
    error_message = "Each date criteria entry in security_hub_automation_rules must use exactly one form: either a rolling date_range, or a fixed window via start and/or end."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for f in concat(
          r.criteria.created_at, r.criteria.first_observed_at, r.criteria.last_observed_at,
          r.criteria.note_updated_at, r.criteria.updated_at
        ) :
        f.date_range == null || (try(f.date_range.unit, "") == "DAYS" && try(f.date_range.value, 0) >= 1)
      ])
    ])
    error_message = "Each date_range in security_hub_automation_rules must use unit DAYS with a value of at least 1 — DAYS is the only unit the API defines."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : alltrue([
        for f in concat(
          r.criteria.created_at, r.criteria.first_observed_at, r.criteria.last_observed_at,
          r.criteria.note_updated_at, r.criteria.updated_at
          ) : alltrue([
            for v in [f.start, f.end] :
            v == null || can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})?$", v))
        ])
      ])
    ])
    error_message = "Each date criteria start/end in security_hub_automation_rules must be an ISO 8601 timestamp (e.g. 2024-01-01T00:00:00Z)."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : (
        r.actions.finding_fields_update == null || alltrue([
          for v in [
            try(r.actions.finding_fields_update.confidence, null),
            try(r.actions.finding_fields_update.criticality, null),
          ] :
          v == null || (try(v >= 0, false) && try(v <= 100, false))
        ])
      )
    ])
    error_message = "Each finding_fields_update confidence and criticality in security_hub_automation_rules must be between 0 and 100."
  }

  validation {
    condition = alltrue([
      for r in var.security_hub_automation_rules : (
        r.actions.finding_fields_update == null || alltrue([
          for rf in r.actions.finding_fields_update.related_findings :
          length(rf.id) > 0 && can(regex("^arn:[a-z0-9-]+:securityhub:", rf.product_arn))
        ])
      )
    ])
    error_message = "Each related_findings entry in security_hub_automation_rules needs a non-empty id and a product_arn beginning with arn:<partition>:securityhub:."
  }
}

# --- Security Hub Disable Controls (G3) ---

variable "security_hub_disabled_controls" {
  description = "List of Security Hub controls to disable per standard. Each entry specifies a standard ARN suffix and a list of control IDs to disable."
  type = list(object({
    standard_arn_suffix = string
    control_ids         = list(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for entry in var.security_hub_disabled_controls :
      can(regex("^[a-z0-9-]+/v/[0-9]+\\.[0-9]+\\.[0-9]+$", entry.standard_arn_suffix))
    ])
    error_message = "Each security_hub_disabled_controls standard_arn_suffix must have the form <standard-name>/v/<major>.<minor>.<patch>."
  }

  validation {
    condition = alltrue([
      for entry in var.security_hub_disabled_controls :
      length(entry.control_ids) > 0
    ])
    error_message = "Each security_hub_disabled_controls entry must name at least one control_id — an empty list disables nothing."
  }

  validation {
    condition = alltrue(flatten([
      for entry in var.security_hub_disabled_controls : [
        for id in entry.control_ids : can(regex("^[A-Za-z][A-Za-z0-9]*\\.[0-9]+$", id))
      ]
    ]))
    error_message = "Each security_hub_disabled_controls control_id must be a security control ID such as S3.1 or CloudTrail.2."
  }

  # Cross-variable: a control only exists once its standard is SUBSCRIBED. The
  # subscribed set is the enabled entries of security_hub_standards plus every
  # entry of security_hub_standards_config. standards_control_arn is string-built
  # from this variable, so an unsubscribed standard_arn_suffix produces a
  # perfectly healthy plan and AWS answers ResourceNotFoundException /
  # InvalidAccessException at apply. A suffix present in security_hub_standards
  # with enabled = false counts as unsubscribed — local.enabled_standards filters
  # it out, so no subscription is created for it.
  # The parentheses around the negation are required: the HCL parser used by the
  # `scan` target rejects a line that opens with `||` when the line before it
  # ends in a negated operand, and then skips this whole file.
  validation {
    condition = (
      (!var.enable_security_hub)
      || alltrue([
        for entry in var.security_hub_disabled_controls :
        contains(
          setunion(
            toset([for s in var.security_hub_standards : s.arn_suffix if s.enabled]),
            toset([for c in var.security_hub_standards_config : c.standard_arn_suffix])
          ),
          entry.standard_arn_suffix
        )
      ])
    )
    error_message = "Every security_hub_disabled_controls standard_arn_suffix must name a SUBSCRIBED standard — an enabled security_hub_standards entry or a security_hub_standards_config entry. A control of an unsubscribed standard does not exist and AWS rejects disabling it at apply."
  }
}

# --- Resource Policy Enforcement (G5) ---

variable "resource_policy_enforcement" {
  description = "List of resource policy enforcement rules. Each entry creates a Config custom rule and optional remediation. Supports S3, KMS, IAM, Secrets Manager, ECR, SNS, SQS, and other resource types. input_parameters are passed to the evaluator alongside the policy template as additional Config rule input parameters."
  type = list(object({
    resource_type      = string
    policy_template    = string
    remediation_action = optional(string, null)
    deployment_targets = optional(list(string), [])
    policy_set         = optional(string, "default")
    enabled            = optional(bool, true)
    input_parameters   = optional(map(string), {})
  }))
  default = []

  # The module derives the Config rule name from resource_type, so the value
  # has to be a CloudFormation-style type identifier.
  validation {
    condition = alltrue([
      for rule in var.resource_policy_enforcement :
      can(regex("^[A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+$", rule.resource_type))
    ])
    error_message = "Each resource_policy_enforcement resource_type must be a CloudFormation resource type such as AWS::S3::Bucket."
  }

  validation {
    condition = alltrue([
      for rule in var.resource_policy_enforcement :
      can(jsondecode(rule.policy_template))
    ])
    error_message = "Each resource_policy_enforcement policy_template must be a valid JSON policy document — the module passes it to the Config rule as an input parameter, where a parse error only surfaces at evaluation time."
  }

  validation {
    condition     = length(distinct([for rule in var.resource_policy_enforcement : rule.resource_type])) == length(var.resource_policy_enforcement)
    error_message = "resource_policy_enforcement must not name the same resource_type twice — the module keys its Config rules by resource type and a duplicate would silently drop one entry."
  }

  validation {
    condition = alltrue([
      for rule in var.resource_policy_enforcement :
      try(rule.policy_set, "default") != "" && can(regex("^[a-z0-9-]+$", try(rule.policy_set, "default")))
    ])
    error_message = "Each resource_policy_enforcement policy_set must be lowercase letters, digits or hyphens — it becomes part of the generated Config rule name."
  }

  # The module transports the template under the key policyTemplate; a user
  # parameter of the same name would be overwritten silently. Empty keys are
  # rejected because the evaluator could never address them.
  validation {
    condition = alltrue(flatten([
      for rule in var.resource_policy_enforcement : [
        for key, value in rule.input_parameters :
        length(key) > 0 && key != "policyTemplate"
      ]
    ]))
    error_message = "Each resource_policy_enforcement input_parameters key must be non-empty and must not be policyTemplate — the module reserves that key for the policy template it passes to the evaluator."
  }

  # A template that carries the perimeter placeholder while the perimeter is
  # disabled would hand the literal placeholder string to the evaluator, where
  # it fails only at evaluation time.
  validation {
    condition = alltrue([
      for rule in var.resource_policy_enforcement :
      !strcontains(rule.policy_template, "{{NETWORK_PERIMETER_VPC_IDS}}") || var.resource_policy_enforcement_network_perimeter.enabled
    ])
    error_message = "A resource_policy_enforcement policy_template contains the placeholder {{NETWORK_PERIMETER_VPC_IDS}} but resource_policy_enforcement_network_perimeter.enabled is false. Enable the network perimeter or remove the placeholder — otherwise the evaluator receives the literal placeholder string."
  }
}

variable "resource_policy_enforcement_network_perimeter" {
  description = "Network perimeter for the resource policy enforcement templates. When enabled, the module replaces the quoted placeholder \"{{NETWORK_PERIMETER_VPC_IDS}}\" in each policy_template with the JSON array of the perimeter VPC IDs before handing the template to the evaluator. managed_vpc_only = true limits the perimeter to managed_vpc_ids (the VPCs this landing zone manages); false widens it to the declared additional_vpc_ids (pre-existing VPCs) as well."
  type = object({
    enabled            = optional(bool, false)
    managed_vpc_only   = optional(bool, false)
    managed_vpc_ids    = optional(list(string), [])
    additional_vpc_ids = optional(list(string), [])
  })
  default = {}

  # Both conditions below are deliberately single-expression one-liners: the
  # HCL parser used by the `scan` target fails on this variable when the
  # multi-line forms (a for-expression over a multi-line concat plus a
  # parenthesised ||-chain) appear together, and then skips this whole file —
  # which unresolves every variable default the scan relies on.
  validation {
    condition = alltrue([
      for id in concat(var.resource_policy_enforcement_network_perimeter.managed_vpc_ids, var.resource_policy_enforcement_network_perimeter.additional_vpc_ids) :
      can(regex("^vpc-[0-9a-f]{8,17}$", id))
    ])
    error_message = "Each resource_policy_enforcement_network_perimeter VPC ID must have the form vpc-<8 to 17 hex characters>."
  }

  # An enabled perimeter with an empty VPC set would replace the placeholder
  # with an empty array — a policy condition that matches nothing and silently
  # blocks or allows everything, depending on the template.
  validation {
    condition     = !var.resource_policy_enforcement_network_perimeter.enabled || length(concat(var.resource_policy_enforcement_network_perimeter.managed_vpc_ids, var.resource_policy_enforcement_network_perimeter.managed_vpc_only ? [] : var.resource_policy_enforcement_network_perimeter.additional_vpc_ids)) > 0
    error_message = "resource_policy_enforcement_network_perimeter.enabled requires at least one VPC ID in the effective set (managed_vpc_ids, or additional_vpc_ids when managed_vpc_only is false). An empty perimeter would render every placeholder as an empty list."
  }
}

variable "resource_policy_enforcement_lambda_arn" {
  description = "ARN of the Lambda evaluator backing the resource policy enforcement Config rules. Empty string means no evaluator is available and no Config rule is created."
  type        = string
  default     = ""

  validation {
    condition     = var.resource_policy_enforcement_lambda_arn == "" || can(regex("^arn:[a-z0-9-]+:lambda:[a-z0-9-]+:[0-9]{12}:function:", var.resource_policy_enforcement_lambda_arn))
    error_message = "resource_policy_enforcement_lambda_arn must be empty or a valid Lambda function ARN (arn:<partition>:lambda:<region>:<account-id>:function:<name>)."
  }
}

variable "resource_policy_enforcement_document" {
  description = "YAML content for the resource policy enforcement SSM Automation document. Passed from the loader to avoid file() path issues in Terragrunt cache."
  type        = string
  default     = ""

  # The value is the document body, not a path: the loader reads the file and
  # hands the content over. A path slipped in here would be registered as an
  # SSM document whose content is the path string.
  validation {
    condition     = var.resource_policy_enforcement_document == "" || can(regex("(schemaVersion|description|mainSteps)", var.resource_policy_enforcement_document))
    error_message = "resource_policy_enforcement_document must be empty or the body of an SSM Automation document (containing schemaVersion, description or mainSteps), not a file path — the loader reads the file and passes its content."
  }
}

variable "guardduty_export_kms_key_arn" {
  description = "KMS key ARN used to encrypt GuardDuty findings exported to S3. Required when guardduty_export_frequency is set — the export resource enforces this via a precondition."
  type        = string
  default     = ""

  validation {
    condition     = var.guardduty_export_kms_key_arn == "" || can(regex("^arn:[a-z0-9-]+:kms:", var.guardduty_export_kms_key_arn))
    error_message = "guardduty_export_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }

  # kms_key_arn is a required argument of aws_guardduty_publishing_destination.
  # The condition mirrors the creation condition of that resource, so an export
  # without a key is rejected before the plan instead of at apply time.
  # The parentheses around the negation are required: the HCL parser used by the
  # `scan` target rejects a line that opens with `||` when the line before it
  # ends in a negated operand, and then skips this whole file.
  validation {
    condition = (
      (!var.enable_guardduty)
      || var.guardduty_export_frequency == null
      || var.central_log_bucket_name == ""
      || var.guardduty_export_kms_key_arn != ""
    )
    error_message = "guardduty_export_kms_key_arn must be set when GuardDuty export is configured (enable_guardduty with guardduty_export_frequency and central_log_bucket_name). The export destination requires a KMS key ARN."
  }
}

# --- GuardDuty Export Prefix Override ---

variable "guardduty_export_prefix" {
  description = "S3 prefix for GuardDuty publishing destination. Allows overriding the default 'guardduty/' prefix."
  type        = string
  default     = "guardduty/"

  validation {
    condition     = var.guardduty_export_prefix == "" || !startswith(var.guardduty_export_prefix, "/")
    error_message = "guardduty_export_prefix must not start with a slash — S3 keys are relative and a leading slash creates an empty path segment."
  }
}

# --- Detective ---

variable "enable_detective" {
  description = "Enable Amazon Detective for security investigation and behavior analysis"
  type        = bool
  default     = false
}

# --- Audit Manager ---

variable "enable_audit_manager" {
  description = "Enable AWS Audit Manager for automated compliance evidence collection. Maintenance mode: as of April 30, 2026 AWS refuses new account registrations at apply time (ValidationException); existing registrations keep working and stay managed. Only enable for an account registered before the cutoff — a check block warns whenever the toggle is on."
  type        = bool
  default     = false
}

# --- SSM Documents ---

variable "ssm_document_share_targets" {
  description = "List of AWS account IDs to share SSM documents with. When non-empty, all custom SSM documents are shared to these accounts. Use 'all' to share publicly (not recommended)."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.ssm_document_share_targets :
      can(regex("^\\d{12}$", id)) || lower(id) == "all"
    ])
    error_message = "Each entry in ssm_document_share_targets must be a 12-digit AWS account ID or 'all'."
  }
}

variable "ssm_documents" {
  description = "List of SSM document definitions to create. Each document accepts name, document_type, and content (JSON string). share_targets per entry names accounts (12-digit IDs or keys of account_ids) and organizational units (keys of ou_name_to_id) the document is shared with, in addition to the global ssm_document_share_targets list; OU entries are resolved to the accounts they contain, because the document-sharing API accepts account IDs only. deployment_targets is accepted for configuration compatibility but triggers a check block warning."
  type = list(object({
    name               = string
    document_type      = string
    content            = string
    target_type        = optional(string, null)
    deployment_targets = optional(list(string), [])
    share_targets = optional(object({
      accounts             = optional(list(string), [])
      organizational_units = optional(list(string), [])
    }), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for d in var.ssm_documents :
      contains(["Automation", "Command", "Session", "Package", "Policy"], d.document_type)
    ])
    error_message = "Each ssm_documents entry must have a document_type of Automation, Command, Session, Package, or Policy."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.ssm_documents : [
        for entry in d.share_targets.accounts :
        can(regex("^[0-9]{12}$", entry)) || contains(keys(var.account_ids), entry)
      ]
    ]))
    error_message = "Each ssm_documents share_targets.accounts entry must be a 12-digit AWS account ID or a key of account_ids — an unknown name cannot be resolved to an account."
  }

  validation {
    condition = alltrue(flatten([
      for d in var.ssm_documents : [
        for ou in d.share_targets.organizational_units :
        contains(keys(var.ou_name_to_id), ou)
      ]
    ]))
    error_message = "Each ssm_documents share_targets.organizational_units entry must be a key of ou_name_to_id — an unknown OU name cannot be resolved to its accounts."
  }

  # 'all' shares a document publicly; account-scoped additions on top of a
  # public share are contradictory, and the API rejects the mixed list.
  validation {
    condition = alltrue([
      for d in var.ssm_documents :
      length(d.share_targets.accounts) + length(d.share_targets.organizational_units) == 0
    ]) || !contains([for t in var.ssm_document_share_targets : lower(t)], "all")
    error_message = "ssm_documents share_targets cannot be combined with 'all' in ssm_document_share_targets — a public share cannot be narrowed by per-document account additions."
  }
}

# Account and OU maps for the share-target resolution: OU names are resolved
# to the accounts they contain, because the document-sharing API accepts
# account IDs only. The maps mirror modules/config-rules and come from the
# accounts and organization stacks.
variable "account_ids" {
  description = "Map of account name to account ID for share_targets resolution"
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for id in values(var.account_ids) :
      can(regex("^[0-9]{12}$", id))
    ])
    error_message = "Each account_ids value must be a 12-digit AWS account ID."
  }
}

variable "ou_name_to_id" {
  description = "Map of OU name to OU ID for share_targets resolution"
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
  description = "Map of account name to the ID of the organizational unit the account is placed in. Required to resolve OU names in share_targets to the accounts they contain."
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

# --- KMS Keys ---

variable "kms_keys" {
  description = "List of KMS customer-managed key definitions. Each key creates an aws_kms_key and aws_kms_alias. is_enabled keeps a key available for cryptographic operations (false creates or keeps the key in the disabled state). removal_policy controls what happens when a key leaves the configuration: destroy schedules deletion after deletion_window_in_days, retain appends a key-policy statement that denies kms:ScheduleKeyDeletion for every principal, so any deletion attempt is refused at the API until the policy is set back to destroy in a prior apply. deployment_targets is accepted for configuration compatibility but triggers a check block warning."
  type = list(object({
    alias                   = string
    description             = optional(string, "")
    policy                  = optional(string, null)
    enable_key_rotation     = optional(bool, true)
    deletion_window_in_days = optional(number, 30)
    is_enabled              = optional(bool, true)
    removal_policy          = optional(string, "destroy")
    deployment_targets      = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for k in var.kms_keys :
      can(regex("^[a-zA-Z0-9/_-]+$", k.alias))
    ])
    error_message = "Each kms_keys alias must contain only alphanumeric characters, hyphens, underscores, and forward slashes."
  }

  validation {
    condition = alltrue([
      for k in var.kms_keys :
      k.deletion_window_in_days >= 7 && k.deletion_window_in_days <= 30
    ])
    error_message = "Each kms_keys deletion_window_in_days must be between 7 and 30."
  }

  validation {
    condition = alltrue([
      for k in var.kms_keys :
      contains(["destroy", "retain"], k.removal_policy)
    ])
    error_message = "Each kms_keys removal_policy must be destroy (removal schedules key deletion after the deletion window) or retain (the key policy denies kms:ScheduleKeyDeletion, so removal is refused until the policy is set back to destroy). A snapshot mode is not offered because KMS key material has no snapshot form."
  }

  validation {
    condition = alltrue([
      for k in var.kms_keys :
      k.policy == null || can(jsondecode(k.policy == null ? "{}" : k.policy).Statement)
    ])
    error_message = "Each kms_keys policy must be null (AWS default key policy) or a JSON policy document with a Statement field — removal_policy = retain composes its deny statement into this document."
  }
}

# --- GuardDuty Deployment Targets ---
# IMPORTANT: Terraform cannot dynamically create providers for cross-account GuardDuty
# configuration. Setting this variable triggers a check block warning. The recommended
# approach for member account GuardDuty configuration is the delegated admin pattern
# via the security-org-config module (modules/security-org-config/), which configures
# GuardDuty organization-wide from the delegated admin (Audit) account.

variable "guardduty_deployment_targets" {
  description = "List of account names or IDs for selective GuardDuty member configuration. Empty list applies to all accounts (default). NOTE: Cross-account GuardDuty configuration requires the delegated admin pattern via the security-org-config module — Terraform cannot dynamically create providers for per-account deployment."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for target in var.guardduty_deployment_targets : trimspace(target) != ""])
    error_message = "guardduty_deployment_targets must not contain empty entries — leave the list empty to cover all accounts."
  }

  validation {
    condition     = length(distinct(var.guardduty_deployment_targets)) == length(var.guardduty_deployment_targets)
    error_message = "guardduty_deployment_targets must not contain duplicates."
  }
}

# --- Security Hub Standards per OU/Account ---

variable "security_hub_standards_config" {
  description = "List of Security Hub standard configurations with optional deployment targets for per-OU/Account activation. Use this alongside security_hub_standards for targeted standard deployment."
  type = list(object({
    standard_arn_suffix = string
    deployment_targets  = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for entry in var.security_hub_standards_config :
      can(regex("^[a-z0-9-]+/v/[0-9]+\\.[0-9]+\\.[0-9]+$", entry.standard_arn_suffix))
    ])
    error_message = "Each security_hub_standards_config standard_arn_suffix must have the form <standard-name>/v/<major>.<minor>.<patch>."
  }

  validation {
    condition = alltrue(flatten([
      for entry in var.security_hub_standards_config : [
        for target in try(entry.deployment_targets, []) : trimspace(target) != ""
      ]
    ]))
    error_message = "security_hub_standards_config deployment_targets must not contain empty entries — leave the list empty for org-wide activation."
  }
}

# --- GuardDuty EKS Runtime Monitoring ---

variable "guardduty_eks_runtime_monitoring" {
  description = "Enable GuardDuty EKS Runtime Monitoring (EKS_RUNTIME_MONITORING detector feature)"
  type        = bool
  default     = false
}

variable "guardduty_eks_manage_agent" {
  description = "Enable GuardDuty-managed EKS runtime monitoring agent deployment. When false, EKS agent must be deployed manually."
  type        = bool
  default     = false
}

# --- Lambda Encryption ---

variable "enable_lambda_encryption" {
  description = "Enable Lambda function encryption at rest with a customer-managed KMS key"
  type        = bool
  default     = false
}

variable "lambda_encryption_kms_key_arn" {
  description = "KMS key ARN for Lambda function encryption. When empty and enable_lambda_encryption is true, a new KMS key is created."
  type        = string
  default     = ""

  validation {
    condition     = var.lambda_encryption_kms_key_arn == "" || can(regex("^arn:", var.lambda_encryption_kms_key_arn))
    error_message = "lambda_encryption_kms_key_arn must be empty or a valid ARN starting with 'arn:'."
  }
}

# --- Macie Publishing Frequency ---

variable "macie_publishing_frequency" {
  description = "Frequency for Macie finding publishing. Valid values: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS. Set to null to use AWS default."
  type        = string
  default     = null

  validation {
    condition     = var.macie_publishing_frequency == null || contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.macie_publishing_frequency)
    error_message = "macie_publishing_frequency must be null, FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

# --- Audit Manager Reports Destination ---

variable "audit_manager_reports_destination" {
  description = "S3 destination for Audit Manager assessment reports. Set to null to skip configuration."
  type = object({
    s3_bucket_name = string
    s3_prefix      = optional(string, "audit-manager-reports")
    kms_key_arn    = optional(string, null)
  })
  default = null

  validation {
    condition = (
      var.audit_manager_reports_destination == null
      || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.audit_manager_reports_destination.s3_bucket_name))
    )
    error_message = "audit_manager_reports_destination.s3_bucket_name must be a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }

  validation {
    condition = (
      var.audit_manager_reports_destination == null
      || !startswith(try(var.audit_manager_reports_destination.s3_prefix, "audit-manager-reports"), "/")
    )
    error_message = "audit_manager_reports_destination.s3_prefix must not start with a slash — S3 keys are relative."
  }

  validation {
    condition = (
      var.audit_manager_reports_destination == null
      || try(var.audit_manager_reports_destination.kms_key_arn, null) == null
      || can(regex("^arn:[a-z0-9-]+:kms:", var.audit_manager_reports_destination.kms_key_arn))
    )
    error_message = "audit_manager_reports_destination.kms_key_arn must be null or a KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}

# --- Excluded Regions ---

variable "guardduty_excluded_regions" {
  description = "List of AWS regions where GuardDuty should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.guardduty_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in guardduty_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

variable "security_hub_excluded_regions" {
  description = "List of AWS regions where Security Hub should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.security_hub_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in security_hub_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

variable "macie_excluded_regions" {
  description = "List of AWS regions where Macie should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.macie_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in macie_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

variable "ebs_encryption_excluded_regions" {
  description = "List of AWS regions where EBS default encryption should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.ebs_encryption_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in ebs_encryption_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

# --- Macie Sensitive Data Findings ---

variable "macie_publish_sensitive_data_findings" {
  description = "Enable Macie to publish sensitive data findings. Set to null to skip configuration."
  type        = bool
  default     = null
}

# --- Macie Fine-Tuning ---

variable "macie_automated_discovery" {
  description = "Manage Macie automated sensitive data discovery (continuous sampling and analysis of S3 objects without manual classification jobs). true enables it, false explicitly disables it, null (the default) leaves the setting unmanaged. Applied at deployment time by a module-owned function; removing the switch disables automated discovery again."
  type        = bool
  default     = null

  validation {
    condition     = var.macie_automated_discovery == null || var.enable_macie
    error_message = "macie_automated_discovery is set but enable_macie is false — the setting is applied to the Macie session and needs the service enabled. Remove the switch or enable Macie."
  }
}

variable "macie_classification_scope_excluded_buckets" {
  description = "S3 buckets Macie skips during automated sensitive data discovery, grouped as bucket names per region. The classification scope API is regional: only the entries whose region matches the current deployment are applied there; the declared list replaces the previous exclusion state. Requires macie_automated_discovery = true; removing the list clears the exclusions."
  type = list(object({
    names  = list(string)
    region = string
  }))
  default = []

  validation {
    condition     = length(var.macie_classification_scope_excluded_buckets) == 0 || var.macie_automated_discovery == true
    error_message = "macie_classification_scope_excluded_buckets only takes effect during automated discovery — set macie_automated_discovery = true or remove the exclusions."
  }

  validation {
    condition = alltrue([
      for entry in var.macie_classification_scope_excluded_buckets :
      length(entry.names) > 0
    ])
    error_message = "Each macie_classification_scope_excluded_buckets entry must name at least one bucket — remove an entry instead of leaving it empty."
  }

  validation {
    condition = alltrue(flatten([
      for entry in var.macie_classification_scope_excluded_buckets : [
        for name in entry.names :
        can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", name))
      ]
    ]))
    error_message = "Each macie_classification_scope_excluded_buckets name must be a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric) — the exact, resolved name, no placeholders."
  }

  validation {
    condition = alltrue([
      for entry in var.macie_classification_scope_excluded_buckets :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", entry.region))
    ])
    error_message = "Each macie_classification_scope_excluded_buckets region must be a valid AWS region format (e.g., us-east-1, eu-central-1) — the classification scope API only accepts buckets of its own region."
  }
}

variable "macie_disabled_regions" {
  description = "List of AWS regions where the Macie session is kept managed but explicitly suspended (status PAUSED): analysis and billing stop, configuration and findings remain, and removing the region resumes the session. Differs from macie_excluded_regions (unmanaged, warning only); a full regional disable remains enable_macie = false for that region's deployment."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.macie_disabled_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in macie_disabled_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }

  validation {
    condition     = length(distinct(var.macie_disabled_regions)) == length(var.macie_disabled_regions)
    error_message = "macie_disabled_regions must not contain duplicates."
  }

  validation {
    condition     = length(setintersection(toset(var.macie_disabled_regions), toset(var.macie_excluded_regions))) == 0
    error_message = "A region cannot be listed in macie_disabled_regions and macie_excluded_regions at once — suspended means managed, excluded means unmanaged."
  }
}

variable "macie_publish_policy_findings" {
  description = "Manage the publication of Macie policy findings to Security Hub. true publishes them, false stops the publication, null (the default) leaves the setting unmanaged (the service publishes policy findings by default). The sensitive-data side of the same publication setting is preserved unchanged. Read only while enable_macie is set; removing the switch restores the service default."
  type        = bool
  default     = null
}

# --- GuardDuty Lifecycle Rules ---

variable "guardduty_lifecycle_rules" {
  description = "S3 lifecycle rules for GuardDuty export prefix. Set to null to skip lifecycle configuration. Written only with replace_central_log_bucket_lifecycle = true, refused without it."
  type = object({
    retention_days = number
  })
  default = null

  # 0 would expire the export on the day it is written; the S3 lifecycle API
  # requires at least one day.
  validation {
    condition     = var.guardduty_lifecycle_rules == null || var.guardduty_lifecycle_rules.retention_days >= 1
    error_message = "guardduty_lifecycle_rules.retention_days must be at least 1 — set the whole object to null to skip the lifecycle configuration."
  }
}

variable "replace_central_log_bucket_lifecycle" {
  description = "Let this module write the lifecycle configuration of central_log_bucket_name from guardduty_lifecycle_rules, guardduty_export_lifecycle_rules and macie_export_lifecycle_rules. S3 keeps one lifecycle configuration per bucket, so true REPLACES the whole lifecycle of that bucket, including every rule the logging module writes for it, and a destroy deletes all of them. Leave false where modules/logging manages the bucket (every stack of this repository) and put the export rules into its central_log_bucket_lifecycle_rules."
  type        = bool
  default     = false

  # The same condition as the count of
  # aws_s3_bucket_lifecycle_configuration.guardduty_export, without the bucket
  # name: a rule input that would write the bucket's lifecycle is refused
  # instead of being dropped without a word.
  validation {
    condition = var.replace_central_log_bucket_lifecycle || !(
      (var.enable_guardduty && var.guardduty_export_frequency != null && (var.guardduty_lifecycle_rules != null || var.guardduty_export_lifecycle_rules != null)) ||
      (var.enable_macie && length(coalesce(var.macie_export_lifecycle_rules, [])) > 0)
    )
    error_message = "guardduty_lifecycle_rules, guardduty_export_lifecycle_rules or macie_export_lifecycle_rules would write the whole lifecycle configuration of the central log bucket, which the logging module already writes — the two would replace each other's rules on every apply. Put these rules into central_log_bucket_lifecycle_rules of the logging module and set the three inputs to null, or set replace_central_log_bucket_lifecycle = true where no other configuration manages the bucket's lifecycle."
  }
}

# --- Per-Account KMS Keys ---

variable "enable_per_account_kms_keys" {
  description = "Enable per-account KMS keys for CloudWatch and Lambda. Enable when deploying via cross-account Terragrunt stacks to member accounts."
  type        = bool
  default     = false
}

# --- Audit Manager S3 Reports Bucket ---

variable "enable_audit_manager_bucket" {
  description = "Create a dedicated S3 bucket for Audit Manager reports with versioning, KMS encryption, PAB, and lifecycle rules."
  type        = bool
  default     = false
}

variable "audit_manager_bucket_kms_key_arn" {
  description = "KMS key ARN for Audit Manager S3 bucket encryption. When empty, uses the default aws/s3 key."
  type        = string
  default     = ""

  validation {
    condition     = var.audit_manager_bucket_kms_key_arn == "" || can(regex("^arn:", var.audit_manager_bucket_kms_key_arn))
    error_message = "audit_manager_bucket_kms_key_arn must be empty or a valid ARN starting with 'arn:'."
  }
}

variable "audit_manager_bucket_lifecycle_days" {
  description = "Number of days before Audit Manager report objects expire. Set to 0 to disable lifecycle."
  type        = number
  default     = 365

  # 0 is the documented off switch (no lifecycle rule); everything above must be
  # a whole number of days.
  validation {
    condition     = var.audit_manager_bucket_lifecycle_days >= 0 && floor(var.audit_manager_bucket_lifecycle_days) == var.audit_manager_bucket_lifecycle_days
    error_message = "audit_manager_bucket_lifecycle_days must be a whole number of days, 0 to disable the lifecycle rule."
  }
}

# --- SSM Resource Data Sync ---

variable "enable_ssm_resource_data_sync" {
  description = "Enable SSM Inventory resource data sync to central S3 bucket."
  type        = bool
  default     = false
}

variable "ssm_resource_data_sync_prefix" {
  description = "S3 prefix for SSM resource data sync destination."
  type        = string
  default     = "ssm-inventory/"

  validation {
    condition     = var.ssm_resource_data_sync_prefix == "" || !startswith(var.ssm_resource_data_sync_prefix, "/")
    error_message = "ssm_resource_data_sync_prefix must not start with a slash — S3 keys are relative and a leading slash creates an empty path segment."
  }
}

# --- SQS KMS Key ---

variable "enable_sqs_kms_key" {
  description = "Create a dedicated KMS key for SQS queue encryption with alias tlz/sqs/kms."
  type        = bool
  default     = false
}

# --- S3 Public Access Block Excluded Accounts ---

variable "s3_public_access_block_excluded_accounts" {
  description = "List of account IDs excluded from S3 public access block enforcement. The current account is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.s3_public_access_block_excluded_accounts :
      can(regex("^[0-9]{12}$", id))
    ])
    error_message = "Each s3_public_access_block_excluded_accounts entry must be a 12-digit AWS account ID — an account name would silently never match and the exclusion would not apply."
  }

  validation {
    condition     = length(distinct(var.s3_public_access_block_excluded_accounts)) == length(var.s3_public_access_block_excluded_accounts)
    error_message = "s3_public_access_block_excluded_accounts must not contain duplicates."
  }
}

# --- GuardDuty S3 Protection Excluded Regions ---

variable "guardduty_s3_protection_excluded_regions" {
  description = "List of AWS regions where GuardDuty S3 protection should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.guardduty_s3_protection_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in guardduty_s3_protection_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

variable "guardduty_ec2_protection_excluded_regions" {
  description = "List of AWS regions where GuardDuty EC2 malware protection should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.guardduty_ec2_protection_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in guardduty_ec2_protection_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

variable "guardduty_eks_protection_excluded_regions" {
  description = "List of AWS regions where GuardDuty EKS protection should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.guardduty_eks_protection_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in guardduty_eks_protection_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

variable "guardduty_lambda_protection_excluded_regions" {
  description = "List of AWS regions where GuardDuty Lambda protection should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.guardduty_lambda_protection_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in guardduty_lambda_protection_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

variable "guardduty_rds_protection_excluded_regions" {
  description = "List of AWS regions where GuardDuty RDS protection should not be enabled. The current region is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for r in var.guardduty_rds_protection_excluded_regions :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", r))
    ])
    error_message = "Each entry in guardduty_rds_protection_excluded_regions must be a valid AWS region format (e.g., us-east-1, eu-central-1)."
  }
}

# --- Security Hub Excluded Regions ---
# Note: securityhub_excluded_regions is already defined above as security_hub_excluded_regions.

# --- SSM Block Public Sharing Excluded Accounts ---

variable "ssm_block_public_sharing_excluded_accounts" {
  description = "List of account IDs excluded from SSM block public sharing enforcement. The current account is checked against this list via a check block warning."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.ssm_block_public_sharing_excluded_accounts :
      can(regex("^\\d{12}$", id))
    ])
    error_message = "Each entry in ssm_block_public_sharing_excluded_accounts must be a 12-digit AWS account ID."
  }
}

# --- Root Management Capability Placeholders ---
# No resource reads these two inputs; they only feed the warning
# root_credentials_management_provider_limitation (main.tf). Nothing in this
# repository enables the features: the organization stack registers trusted
# access for iam.<dns_suffix>, which is the prerequisite only. To enable them,
# run in the management account:
#   aws iam enable-organizations-root-credentials-management
#   aws iam enable-organizations-root-sessions
# The default stays true because the loader's default is true (a loader
# default equals the module default) and the stack always passes a value; the
# description says what the value does.

variable "root_credentials_management" {
  description = "Intent only: whether central root credentials management is wanted. The module enables nothing for it; a true value raises a warning that the feature has to be enabled outside Terraform."
  type        = bool
  default     = true
}

variable "allow_root_sessions" {
  description = "Intent only: whether privileged root sessions are wanted. The module enables nothing for it; a true value raises a warning that the feature has to be enabled outside Terraform."
  type        = bool
  default     = true
}

# --- FMS Policy Management ---

variable "fms_policies" {
  description = "List of AWS Firewall Manager policy definitions. Firewall Manager policies can only be created by a Firewall Manager administrator account; the module does not register one — set fms_admin_account_registered once the out-of-band registration is done, otherwise a non-empty list fails at plan time."
  type = list(object({
    name                  = string
    type                  = string
    resource_type_list    = optional(list(string), [])
    exclude_resource_tags = optional(bool, false)
    remediation_enabled   = optional(bool, false)
    include_map           = optional(list(string), [])
    exclude_map           = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for p in var.fms_policies :
      contains(["WAF", "SHIELD_ADVANCED", "SECURITY_GROUPS_COMMON", "SECURITY_GROUPS_CONTENT_AUDIT"], p.type)
    ])
    error_message = "Each fms_policies type must be WAF, SHIELD_ADVANCED, SECURITY_GROUPS_COMMON, or SECURITY_GROUPS_CONTENT_AUDIT."
  }
}

variable "fms_admin_account_registered" {
  description = "Operator acknowledgement that the Firewall Manager administrator account has been registered out of band (fms:AssociateAdminAccount from the organization's management account) and that the account applying this module is a Firewall Manager administrator. aws_fms_policy can only be created by such an administrator, and the module does not register one: that is a one-time, organization-level step with its own blast radius. Required true while fms_policies is non-empty — the plan fails otherwise. This is an attestation, not a verification: the provider has no data source for the Firewall Manager administrator, and the Organizations delegated-administrator list cannot tell a RegisterDelegatedAdministrator entry from an AssociateAdminAccount registration."
  type        = bool
  default     = false
}

# --- Default VPC Removal (adopt, then destroy) ---

variable "enable_delete_default_vpc" {
  description = "Adopt the default VPC of the current region into Terraform state as the first step of removing it. The apply itself does not delete the VPC — disable this toggle again (or destroy the stack) in a second apply, which destroys the adopted VPC via force_destroy. Applies to the current region only; cross-account and multi-region removal requires deploying this module via cross-account providers in each target account and region."
  type        = bool
  default     = false
}

# --- Default Security Group Rules Removal ---

variable "enable_delete_default_sg_rules" {
  description = "Remove all ingress and egress rules from the default security group. The aws_default_security_group resource manages the default security group in the current VPC only — per-VPC application requires deploying this module with the appropriate VPC ID for each target VPC."
  type        = bool
  default     = false
}

variable "default_vpc_id" {
  description = "VPC ID for the default security group. Empty string uses the default VPC."
  type        = string
  default     = ""

  validation {
    condition     = var.default_vpc_id == "" || can(regex("^vpc-[0-9a-f]{8,17}$", var.default_vpc_id))
    error_message = "default_vpc_id must be empty (use the default VPC) or a VPC ID (vpc-…)."
  }
}

# --- FMS Notification Channels ---

variable "enable_fms_notification_channel" {
  description = "Enable Firewall Manager notification channel for security alerts via SNS"
  type        = bool
  default     = false
}

variable "fms_notification_sns_topic_arn" {
  description = "SNS topic ARN for FMS notification delivery. Required when enable_fms_notification_channel is true."
  type        = string
  default     = ""

  validation {
    condition     = var.fms_notification_sns_topic_arn == "" || can(regex("^arn:", var.fms_notification_sns_topic_arn))
    error_message = "fms_notification_sns_topic_arn must be empty or a valid ARN starting with 'arn:'."
  }
}

variable "fms_notification_sns_role_name" {
  description = "IAM role name for FMS to publish SNS notifications. FMS uses this role to send alerts."
  type        = string
  default     = "FMSNotificationRole"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.fms_notification_sns_role_name))
    error_message = "fms_notification_sns_role_name must be an IAM role name (1-64 characters of letters, digits and +=,.@_-), not an ARN — the module builds the ARN from the active partition."
  }
}

# --- Firewall Config S3 Bucket ---

variable "enable_firewall_config_bucket" {
  description = "Create a dedicated S3 bucket for third-party firewall configuration and license files"
  type        = bool
  default     = false
}

variable "firewall_config_bucket_name" {
  description = "Name for the firewall configuration S3 bucket. Must be globally unique. Required (non-empty) when enable_firewall_config_bucket is true — the resource is count-gated by the toggle, not by this name, so an empty name with the toggle on would hand the provider an empty bucket argument and let it generate a random terraform-… name outside every guardrail. A non-empty name must stay inside the tlz- namespace: ProtectS3Buckets in tlz-core-guardrails-2.json protects only arn:*:s3:::tlz-* from deletion and policy tampering, and the static prefix guard reads this validation as the namespace pin of a variable-fed bucket name."
  type        = string
  default     = ""

  validation {
    condition     = var.firewall_config_bucket_name == "" || can(regex("^tlz-[a-z0-9.\\-]{0,58}[a-z0-9]$", var.firewall_config_bucket_name))
    error_message = "firewall_config_bucket_name must be empty (bucket disabled) or start with tlz- and be a valid S3 bucket name of 5-63 characters in total (lowercase letters, digits, dots and hyphens, ending in a letter or digit) — inside the guardrail-protected tlz- namespace."
  }

  validation {
    condition     = !var.enable_firewall_config_bucket || var.firewall_config_bucket_name != ""
    error_message = "firewall_config_bucket_name must be set when enable_firewall_config_bucket is true — with an empty name the provider would generate a random bucket name outside the tlz- namespace."
  }
}

variable "firewall_config_bucket_kms_key_arn" {
  description = "KMS key ARN for firewall config bucket encryption. Empty string uses the default aws/s3 key."
  type        = string
  default     = ""

  validation {
    condition     = var.firewall_config_bucket_kms_key_arn == "" || can(regex("^arn:", var.firewall_config_bucket_kms_key_arn))
    error_message = "firewall_config_bucket_kms_key_arn must be empty or a valid ARN starting with 'arn:'."
  }
}

# --- Configurable S3 Lifecycle Rules ---

variable "guardduty_export_lifecycle_rules" {
  description = "Lifecycle rules for the GuardDuty export prefix of the central log bucket. Each entry is one S3 rule with a filter, transitions into colder storage classes, an expiration and the handling of noncurrent versions. null keeps the single rule the module derives from guardduty_lifecycle_rules. Written only with replace_central_log_bucket_lifecycle = true, refused without it."
  type = list(object({
    id                           = string
    enabled                      = optional(bool, true)
    prefix                       = optional(string, null)
    tags                         = optional(map(string), null)
    expiration_days              = optional(number, null)
    expired_object_delete_marker = optional(bool, null)
    transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    noncurrent_version_expiration_days = optional(number, null)
    noncurrent_version_transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    abort_incomplete_multipart_upload_days = optional(number, null)
  }))
  default = null

  # The id shows in the plan and in the AWS console; S3 rejects two rules with
  # the same id, and an empty id makes the rule impossible to find.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every guardduty_export_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.guardduty_export_lifecycle_rules, [])))
    error_message = "Every id in guardduty_export_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in guardduty_export_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) : concat(
        [
          for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
          transition.days >= 0 && floor(transition.days) == transition.days
        ],
        rule.expiration_days == null ? [] : [
          rule.expiration_days >= 1 && floor(rule.expiration_days) == rule.expiration_days
        ],
        rule.noncurrent_version_expiration_days == null ? [] : [
          rule.noncurrent_version_expiration_days >= 1 && floor(rule.noncurrent_version_expiration_days) == rule.noncurrent_version_expiration_days
        ],
        rule.abort_incomplete_multipart_upload_days == null ? [] : [
          rule.abort_incomplete_multipart_upload_days >= 1 && floor(rule.abort_incomplete_multipart_upload_days) == rule.abort_incomplete_multipart_upload_days
        ],
      )
    ])))
    error_message = "Every day value in guardduty_export_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every guardduty_export_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every guardduty_export_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every guardduty_export_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every guardduty_export_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a guardduty_export_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A guardduty_export_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.guardduty_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.guardduty_export_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every guardduty_export_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_guardduty, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.guardduty_export_lifecycle_rules == null || var.enable_guardduty)
    error_message = "guardduty_export_lifecycle_rules is only read when enable_guardduty is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
}

variable "audit_manager_bucket_lifecycle_rules" {
  description = "Lifecycle rules for the Audit Manager reports bucket. null keeps the single rule the module derives from audit_manager_bucket_lifecycle_days."
  type = list(object({
    id                           = string
    enabled                      = optional(bool, true)
    prefix                       = optional(string, null)
    tags                         = optional(map(string), null)
    expiration_days              = optional(number, null)
    expired_object_delete_marker = optional(bool, null)
    transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    noncurrent_version_expiration_days = optional(number, null)
    noncurrent_version_transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    abort_incomplete_multipart_upload_days = optional(number, null)
  }))
  default = null

  # The id shows in the plan and in the AWS console; S3 rejects two rules with
  # the same id, and an empty id makes the rule impossible to find.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every audit_manager_bucket_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.audit_manager_bucket_lifecycle_rules, [])))
    error_message = "Every id in audit_manager_bucket_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in audit_manager_bucket_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) : concat(
        [
          for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
          transition.days >= 0 && floor(transition.days) == transition.days
        ],
        rule.expiration_days == null ? [] : [
          rule.expiration_days >= 1 && floor(rule.expiration_days) == rule.expiration_days
        ],
        rule.noncurrent_version_expiration_days == null ? [] : [
          rule.noncurrent_version_expiration_days >= 1 && floor(rule.noncurrent_version_expiration_days) == rule.noncurrent_version_expiration_days
        ],
        rule.abort_incomplete_multipart_upload_days == null ? [] : [
          rule.abort_incomplete_multipart_upload_days >= 1 && floor(rule.abort_incomplete_multipart_upload_days) == rule.abort_incomplete_multipart_upload_days
        ],
      )
    ])))
    error_message = "Every day value in audit_manager_bucket_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every audit_manager_bucket_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every audit_manager_bucket_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every audit_manager_bucket_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every audit_manager_bucket_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a audit_manager_bucket_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A audit_manager_bucket_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.audit_manager_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.audit_manager_bucket_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every audit_manager_bucket_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_audit_manager_bucket, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.audit_manager_bucket_lifecycle_rules == null || var.enable_audit_manager_bucket)
    error_message = "audit_manager_bucket_lifecycle_rules is only read when enable_audit_manager_bucket is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
}

variable "macie_export_lifecycle_rules" {
  description = "Lifecycle rules for the Macie classification export prefix of the central log bucket. null leaves the export without a lifecycle. Written only with replace_central_log_bucket_lifecycle = true, refused without it."
  type = list(object({
    id                           = string
    enabled                      = optional(bool, true)
    prefix                       = optional(string, null)
    tags                         = optional(map(string), null)
    expiration_days              = optional(number, null)
    expired_object_delete_marker = optional(bool, null)
    transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    noncurrent_version_expiration_days = optional(number, null)
    noncurrent_version_transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    abort_incomplete_multipart_upload_days = optional(number, null)
  }))
  default = null

  # The id shows in the plan and in the AWS console; S3 rejects two rules with
  # the same id, and an empty id makes the rule impossible to find.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every macie_export_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.macie_export_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.macie_export_lifecycle_rules, [])))
    error_message = "Every id in macie_export_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in macie_export_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) : concat(
        [
          for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
          transition.days >= 0 && floor(transition.days) == transition.days
        ],
        rule.expiration_days == null ? [] : [
          rule.expiration_days >= 1 && floor(rule.expiration_days) == rule.expiration_days
        ],
        rule.noncurrent_version_expiration_days == null ? [] : [
          rule.noncurrent_version_expiration_days >= 1 && floor(rule.noncurrent_version_expiration_days) == rule.noncurrent_version_expiration_days
        ],
        rule.abort_incomplete_multipart_upload_days == null ? [] : [
          rule.abort_incomplete_multipart_upload_days >= 1 && floor(rule.abort_incomplete_multipart_upload_days) == rule.abort_incomplete_multipart_upload_days
        ],
      )
    ])))
    error_message = "Every day value in macie_export_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every macie_export_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every macie_export_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every macie_export_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every macie_export_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a macie_export_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A macie_export_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.macie_export_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.macie_export_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every macie_export_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_macie, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.macie_export_lifecycle_rules == null || var.enable_macie)
    error_message = "macie_export_lifecycle_rules is only read when enable_macie is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
}

variable "session_manager_lifecycle_rules" {
  description = "Lifecycle rules for the Session Manager log bucket. The module does not own that bucket, and S3 keeps one lifecycle configuration per bucket: a rule set REPLACES every lifecycle rule the bucket has, and a destroy deletes them all. null leaves the bucket's lifecycle untouched."
  type = list(object({
    id                           = string
    enabled                      = optional(bool, true)
    prefix                       = optional(string, null)
    tags                         = optional(map(string), null)
    expiration_days              = optional(number, null)
    expired_object_delete_marker = optional(bool, null)
    transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    noncurrent_version_expiration_days = optional(number, null)
    noncurrent_version_transitions = optional(list(object({
      storage_class = string
      days          = number
    })), [])
    abort_incomplete_multipart_upload_days = optional(number, null)
  }))
  default = null

  # The id shows in the plan and in the AWS console; S3 rejects two rules with
  # the same id, and an empty id makes the rule impossible to find.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every session_manager_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.session_manager_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.session_manager_lifecycle_rules, [])))
    error_message = "Every id in session_manager_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in session_manager_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) : concat(
        [
          for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
          transition.days >= 0 && floor(transition.days) == transition.days
        ],
        rule.expiration_days == null ? [] : [
          rule.expiration_days >= 1 && floor(rule.expiration_days) == rule.expiration_days
        ],
        rule.noncurrent_version_expiration_days == null ? [] : [
          rule.noncurrent_version_expiration_days >= 1 && floor(rule.noncurrent_version_expiration_days) == rule.noncurrent_version_expiration_days
        ],
        rule.abort_incomplete_multipart_upload_days == null ? [] : [
          rule.abort_incomplete_multipart_upload_days >= 1 && floor(rule.abort_incomplete_multipart_upload_days) == rule.abort_incomplete_multipart_upload_days
        ],
      )
    ])))
    error_message = "Every day value in session_manager_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every session_manager_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every session_manager_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every session_manager_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every session_manager_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a session_manager_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A session_manager_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.session_manager_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.session_manager_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every session_manager_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_session_manager_s3_logging, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.session_manager_lifecycle_rules == null || var.enable_session_manager_s3_logging)
    error_message = "session_manager_lifecycle_rules is only read when enable_session_manager_s3_logging is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
}
