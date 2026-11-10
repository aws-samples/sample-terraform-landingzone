variable "enable_cost_and_usage_report" {
  description = "Enable AWS Cost and Usage Report. CUR is only available in us-east-1."
  type        = bool
  default     = false
}

variable "cur_config" {
  description = "Cost and Usage Report configuration. Reports are written to the central log bucket."
  type = object({
    report_name                = optional(string, "tlz-cost-usage-report")
    s3_prefix                  = optional(string, "cur")
    time_unit                  = optional(string, "DAILY")
    format                     = optional(string, "Parquet")
    compression                = optional(string, "Parquet")
    additional_schema_elements = optional(list(string), ["RESOURCES"])
    additional_artifacts       = optional(list(string), null)
    report_versioning          = optional(string, "OVERWRITE_REPORT")
    refresh_closed_reports     = optional(bool, null)
  })
  default = {}

  validation {
    condition     = contains(["DAILY", "HOURLY", "MONTHLY"], var.cur_config.time_unit)
    error_message = "cur_config.time_unit must be DAILY, HOURLY, or MONTHLY."
  }

  validation {
    condition     = contains(["Parquet", "textORcsv"], var.cur_config.format)
    error_message = "cur_config.format must be Parquet or textORcsv."
  }

  validation {
    condition     = contains(["Parquet", "GZIP", "ZIP"], var.cur_config.compression)
    error_message = "cur_config.compression must be Parquet, GZIP, or ZIP."
  }

  validation {
    condition     = contains(["CREATE_NEW_REPORT", "OVERWRITE_REPORT"], var.cur_config.report_versioning)
    error_message = "cur_config.report_versioning must be CREATE_NEW_REPORT or OVERWRITE_REPORT."
  }

  # The manifest values the API accepts. A typo would only surface at apply
  # time, and the report definition would be rejected there.
  validation {
    condition = (var.cur_config.additional_artifacts == null || alltrue([
      for artifact in coalesce(var.cur_config.additional_artifacts, []) :
      contains(["REDSHIFT", "QUICKSIGHT", "ATHENA"], artifact)
    ]))
    error_message = "Every cur_config.additional_artifacts entry must be one of REDSHIFT, QUICKSIGHT, ATHENA."
  }

  validation {
    condition     = (var.cur_config.additional_artifacts == null || length(distinct(coalesce(var.cur_config.additional_artifacts, []))) == length(coalesce(var.cur_config.additional_artifacts, [])))
    error_message = "cur_config.additional_artifacts must not contain duplicates."
  }

  # The API takes ATHENA alone: a report that feeds Athena cannot also carry
  # the Redshift or QuickSight manifests.
  validation {
    condition     = (var.cur_config.additional_artifacts == null || (!contains(coalesce(var.cur_config.additional_artifacts, []), "ATHENA")) || length(coalesce(var.cur_config.additional_artifacts, [])) == 1)
    error_message = "cur_config.additional_artifacts with ATHENA must not name any other artifact — the API takes ATHENA alone."
  }

  # An Athena manifest additionally requires the Parquet format pair and
  # overwrite versioning; the API rejects every other combination.
  validation {
    condition     = (var.cur_config.additional_artifacts == null || (!contains(coalesce(var.cur_config.additional_artifacts, []), "ATHENA")) || (var.cur_config.format == "Parquet" && var.cur_config.compression == "Parquet" && var.cur_config.report_versioning == "OVERWRITE_REPORT"))
    error_message = "cur_config.additional_artifacts with ATHENA requires format Parquet, compression Parquet and report_versioning OVERWRITE_REPORT — the API rejects every other combination."
  }
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for CUR report storage (injected via Terragrunt dependency from the logging stack). Used as fallback when enable_dedicated_bucket is false."
  type        = string

  validation {
    condition     = length(var.s3_bucket_name) > 0
    error_message = "s3_bucket_name must be non-empty — an S3 bucket is required for CUR report storage."
  }
}

variable "s3_bucket_region" {
  description = "Region of the S3 bucket for CUR report storage. Required when the report is delivered to an external bucket (enable_dedicated_bucket = false); only the dedicated bucket may fall back to the provider region, which is its real location by construction."
  type        = string
  default     = ""

  validation {
    condition     = var.s3_bucket_region == "" || can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", var.s3_bucket_region))
    error_message = "s3_bucket_region must be empty or a valid AWS region name (e.g., us-east-1, eu-central-1)."
  }
}

variable "enable_dedicated_bucket" {
  description = "Create a dedicated S3 bucket for CUR reports instead of using the central log bucket."
  type        = bool
  default     = false
}

variable "kms_key_administrators" {
  description = "ARNs for KMS key administration on the dedicated CUR bucket"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.kms_key_administrators :
      can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):iam::[0-9]{12}:", arn))
    ])
    error_message = "Each kms_key_administrators entry must be a valid IAM ARN (arn:<partition>:iam::<account-id>:<resource>)."
  }
}

variable "force_destroy" {
  description = "Allow destruction of S3 buckets with content (for test environments only)"
  type        = bool
  default     = false
}

variable "abort_incomplete_multipart_upload_days" {
  description = "Number of days after which incomplete multipart uploads are aborted"
  type        = number
  default     = 7

  validation {
    condition     = var.abort_incomplete_multipart_upload_days >= 1
    error_message = "abort_incomplete_multipart_upload_days must be a positive integer (at least 1 day)."
  }
}

variable "noncurrent_version_expiration_days" {
  description = "Number of days after which noncurrent object versions expire"
  type        = number
  default     = 365

  validation {
    condition     = var.noncurrent_version_expiration_days >= 1
    error_message = "noncurrent_version_expiration_days must be a positive integer (at least 1 day)."
  }
}

variable "cur_bucket_lifecycle_rules" {
  description = "Lifecycle rules for the dedicated CUR bucket. Each entry is one S3 rule with a filter, transitions into colder storage classes, an expiration and the handling of noncurrent versions. null keeps the single rule the module derives from noncurrent_version_expiration_days and abort_incomplete_multipart_upload_days."
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
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every cur_bucket_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.cur_bucket_lifecycle_rules, [])))
    error_message = "Every id in cur_bucket_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in cur_bucket_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) : concat(
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
    error_message = "Every day value in cur_bucket_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every cur_bucket_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every cur_bucket_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every cur_bucket_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every cur_bucket_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a cur_bucket_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A cur_bucket_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.cur_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.cur_bucket_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every cur_bucket_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_cost_and_usage_report and enable_dedicated_bucket, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.cur_bucket_lifecycle_rules == null || (var.enable_cost_and_usage_report && var.enable_dedicated_bucket))
    error_message = "cur_bucket_lifecycle_rules is only read when enable_cost_and_usage_report and enable_dedicated_bucket is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
}

