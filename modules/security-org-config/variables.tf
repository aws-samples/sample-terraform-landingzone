variable "enable_guardduty" {
  description = "Enable GuardDuty org-wide configuration from the Audit account"
  type        = bool
  default     = false
}

variable "enable_security_hub" {
  description = "Enable Security Hub org-wide configuration from the Audit account"
  type        = bool
  default     = false
}

variable "enable_macie" {
  description = "Enable Macie org-wide configuration from the Audit account"
  type        = bool
  default     = false
}

variable "enable_detective" {
  description = "Enable Detective org-wide configuration from the Audit account"
  type        = bool
  default     = false
}

variable "is_eusc" {
  description = "Whether the deployment is in the EU Sovereign Cloud partition (disables Macie)"
  type        = bool
  default     = false
}

variable "guardduty_features" {
  description = "GuardDuty detector feature toggles for org-wide configuration"
  type = object({
    s3_protection          = optional(bool, true)
    eks_audit_logs         = optional(bool, true)
    eks_runtime_monitoring = optional(bool, false)
    eks_manage_agent       = optional(bool, false)
    ebs_malware_protection = optional(bool, true)
    rds_protection         = optional(bool, true)
    lambda_protection      = optional(bool, true)
  })
  default = {}

  # eks_manage_agent is a sub-setting of eks_runtime_monitoring, not a switch of
  # its own: AWS only accepts the EKS_ADDON_MANAGEMENT additional configuration
  # while runtime monitoring is enabled. Set on its own it is silently dropped.
  # The parentheses around the negation are required: the HCL parser used by the
  # `scan` target rejects a line that opens with `||` when the line before it
  # ends in a negated operand, and then skips this whole file.
  validation {
    condition = (
      (!try(var.guardduty_features.eks_manage_agent, false))
      || try(var.guardduty_features.eks_runtime_monitoring, false)
    )
    error_message = "guardduty_features.eks_manage_agent requires eks_runtime_monitoring = true — agent management is an additional configuration of runtime monitoring and has no effect on its own."
  }
}

variable "guardduty_deployment_targets" {
  description = "Selective account/OU targets for GuardDuty. Empty = org-wide."
  type        = list(string)
  default     = []

  # A target is either a 12-digit account ID or an OU ID. Anything else
  # resolves to no account, and the empty list already means org-wide.
  validation {
    condition = alltrue([
      for target in var.guardduty_deployment_targets :
      can(regex("^([0-9]{12}|ou-[a-z0-9]+-[a-z0-9]+|r-[a-z0-9]+)$", target))
    ])
    error_message = "Each guardduty_deployment_targets entry must be a 12-digit account ID, an OU ID (ou-xxxx-xxxxxxxx) or a root ID (r-xxxx). Leave the list empty for org-wide coverage."
  }

  validation {
    condition     = length(distinct(var.guardduty_deployment_targets)) == length(var.guardduty_deployment_targets)
    error_message = "guardduty_deployment_targets must not contain duplicates."
  }
}

variable "security_hub_standards" {
  description = "Security Hub standards to enable org-wide from the delegated admin account. Each entry is either a plain ARN suffix string or an object with arn_suffix and enabled, the same two forms modules/security accepts. Disabled entries serve as documentation only."
  # list(any) rather than list(string): the compliance loader hands over the
  # object form ({ arn_suffix, enabled }), which a list(string) would reject
  # before the plan. All entries of one list still have to share a type.
  type    = list(any)
  default = []

  validation {
    condition = alltrue([
      for s in var.security_hub_standards :
      length(can(s.arn_suffix) ? tostring(s.arn_suffix) : tostring(s)) > 0
    ])
    error_message = "Each security_hub_standards entry must carry a non-empty standard ARN suffix, either as a plain string or as the arn_suffix field of an object."
  }
}

# --- Finding consumers of the administrator (consumers.tf) ---
# Every default below creates nothing: a deployment that keeps the finding
# consumers in the management account plans no change here.

variable "central_log_bucket_name" {
  description = "Name of the central log bucket (logging module, management account) that the GuardDuty findings export and the Macie classification export write to. Required when guardduty_export_frequency or macie_publish_sensitive_data_findings is set; empty creates no export."
  type        = string
  default     = ""

  validation {
    condition     = var.central_log_bucket_name == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.central_log_bucket_name))
    error_message = "central_log_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

variable "guardduty_export_kms_key_arn" {
  description = "KMS key ARN of the central log bucket, used to encrypt the GuardDuty findings export and the Macie classification export. Required when an export is configured — both export resources enforce this via a precondition."
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

variable "guardduty_export_frequency" {
  description = "Frequency of the GuardDuty findings export to the central log bucket and of the administrator's detector. Valid values: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS. null creates no export and keeps the detector's default frequency."
  type        = string
  default     = null

  validation {
    condition     = var.guardduty_export_frequency == null || contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_export_frequency)
    error_message = "guardduty_export_frequency must be null, FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

variable "guardduty_export_prefix" {
  description = "S3 prefix of the GuardDuty findings export in the central log bucket. Must carry the same value as the logging module's guardduty_export_prefix — the bucket policy grants PutObject under that prefix."
  type        = string
  default     = "guardduty/"

  validation {
    condition     = var.guardduty_export_prefix == "" || !startswith(var.guardduty_export_prefix, "/")
    error_message = "guardduty_export_prefix must not start with a slash — S3 keys are relative and a leading slash creates an empty path segment."
  }
}

variable "macie_publish_sensitive_data_findings" {
  description = "Write the Macie classification results of the organization to the central log bucket (macie/classification-results/). Needs central_log_bucket_name and guardduty_export_kms_key_arn; false creates no export."
  type        = bool
  default     = false
}

variable "enable_security_hub_region_aggregation" {
  description = "Create the Security Hub cross-region finding aggregator in the administrator account. The members inherit the administrator's aggregation. Off by default here: the stack passes the configured value, the module alone plans nothing."
  type        = bool
  default     = false
}

variable "security_hub_aggregation_regions" {
  description = "Regions the finding aggregator links. Empty uses the ALL_REGIONS linking mode."
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

variable "security_hub_disabled_controls" {
  description = "Security Hub controls to disable in the administrator account, per standard. Each entry names a standard ARN suffix and the control ids. Disables the administrator account's own controls; org-wide disablement needs Security Hub central configuration."
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

  # Cross-variable: a control only exists once its standard is SUBSCRIBED — an
  # enabled entry of security_hub_standards (either notation). The control ARN
  # is string-built from this variable, so an unsubscribed standard_arn_suffix
  # produces a healthy plan and AWS answers ResourceNotFoundException at apply.
  # The parentheses around the negation are required: the HCL parser used by the
  # `scan` target rejects a line that opens with `||` when the line before it
  # ends in a negated operand, and then skips this whole file.
  validation {
    condition = (
      (!var.enable_security_hub)
      || alltrue([
        for entry in var.security_hub_disabled_controls :
        contains(
          [
            for s in var.security_hub_standards :
            can(s.arn_suffix) ? tostring(s.arn_suffix) : tostring(s)
            if can(s.enabled) ? tobool(s.enabled) : true
          ],
          entry.standard_arn_suffix
        )
      ])
    )
    error_message = "Every security_hub_disabled_controls standard_arn_suffix must name a SUBSCRIBED standard — an enabled security_hub_standards entry. A control of an unsubscribed standard does not exist and AWS rejects disabling it at apply."
  }
}

variable "security_hub_member_account_ids" {
  description = "Accounts to enrol as Security Hub members of this administrator (invite = false, the organization form): the existing member accounts and the management account. Accounts that join the organization later are enrolled by the auto-enable setting; this list covers the accounts that existed before it. Never the administrator account itself."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.security_hub_member_account_ids : can(regex("^[0-9]{12}$", id))
    ])
    error_message = "Every security_hub_member_account_ids entry must be a 12-digit AWS account id."
  }

  validation {
    condition     = length(distinct(var.security_hub_member_account_ids)) == length(var.security_hub_member_account_ids)
    error_message = "security_hub_member_account_ids must not contain duplicates."
  }
}

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

  # Security Hub allows 100 automation rules per account and Region; the 101st
  # CreateAutomationRule fails at apply, after the first hundred exist.
  validation {
    condition     = length(var.security_hub_automation_rules) <= 100
    error_message = "security_hub_automation_rules holds more than 100 rules — Security Hub allows 100 automation rules per account and Region."
  }
}
