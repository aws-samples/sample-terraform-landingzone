variable "backup_vaults" {
  description = "List of AWS Backup Vault definitions. When deployment_targets is specified, an access policy allows those accounts to write backups. Each deployment_targets entry is a 12-digit account ID or an account name declared in account_ids. policy attaches a full access policy document as a JSON string instead."
  type = list(object({
    name               = string
    kms_key_arn        = optional(string, null)
    deployment_targets = optional(list(string), [])
    policy             = optional(string, null)
  }))
  default = []

  validation {
    condition = alltrue([
      for v in var.backup_vaults :
      can(regex("^[a-zA-Z0-9_-]+$", v.name))
    ])
    error_message = "Each backup vault name must contain only alphanumeric characters, hyphens, and underscores."
  }

  validation {
    condition = alltrue([
      for v in var.backup_vaults :
      v.kms_key_arn == null || can(regex("^arn:", v.kms_key_arn))
    ])
    error_message = "kms_key_arn must be null or a valid ARN starting with 'arn:'."
  }

  validation {
    condition = alltrue(flatten([
      for v in var.backup_vaults : [
        for target in v.deployment_targets :
        can(regex("^[0-9]{12}$", target)) || contains(keys(var.account_ids), target)
      ]
    ]))
    error_message = "Each backup_vaults deployment_targets entry must be a 12-digit AWS account ID or an account name declared in account_ids. An unresolved name would be built into a principal ARN (arn:<partition>:iam::<name>:root) that AWS rejects."
  }

  # A policy that does not decode would only fail at apply time, inside the
  # provider — the plan names the vault instead.
  validation {
    condition = alltrue([
      for v in var.backup_vaults :
      v.policy == null || can(jsondecode(v.policy))
    ])
    error_message = "Each backup_vaults policy must be a JSON-decodable policy document."
  }

  # Version and Statement are what makes a decodable string a policy document.
  # AWS rejects a document without them, and a policy handed in as a list or a
  # bare string would otherwise pass the decode check.
  validation {
    condition = alltrue([
      for v in var.backup_vaults :
      v.policy == null || (can(jsondecode(v.policy).Version) && can(jsondecode(v.policy).Statement))
    ])
    error_message = "Each backup_vaults policy must carry the Version and Statement fields of an IAM policy document."
  }

  # Both attributes describe the same resource: the one access policy of the
  # vault. Taking both would silently drop one of the two — the plan refuses
  # the combination instead.
  validation {
    condition = alltrue([
      for v in var.backup_vaults :
      v.policy == null || length(v.deployment_targets) == 0
    ])
    error_message = "A backup_vaults entry sets policy or deployment_targets, never both — both describe the one access policy of the vault."
  }
}

variable "account_ids" {
  description = "Map of account names to account IDs, used for resolving deployment_targets"
  type        = map(string)
  default     = {}
}
