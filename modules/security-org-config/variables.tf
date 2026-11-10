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
