# Logging module: Variables

variable "log_archive_account_id" {
  description = "Account ID of the Log-Archive account for central logs"
  type        = string

  validation {
    condition     = var.log_archive_account_id == "" || can(regex("^\\d{12}$", var.log_archive_account_id))
    error_message = "log_archive_account_id must be empty or a 12-digit AWS account ID."
  }
}

variable "organization_id" {
  description = "AWS Organizations ID"
  type        = string

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organization_id))
    error_message = "organization_id must be a valid AWS Organizations ID in the format o-xxxxxxxxxx."
  }
}

variable "log_retention_days" {
  description = "S3 lifecycle retention in days (default: 365)"
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days > 0
    error_message = "log_retention_days must be a positive integer (at least 1 day) for the S3 log bucket lifecycle retention period."
  }
}

variable "cloudwatch_log_group_retention" {
  description = "CloudWatch Log Group retention in days (optional, null = no log group)"
  type        = number
  default     = null

  validation {
    condition     = var.cloudwatch_log_group_retention == null || contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.cloudwatch_log_group_retention)
    error_message = "cloudwatch_log_group_retention must be null or a valid CloudWatch retention value."
  }
}

variable "kms_key_administrators" {
  description = "ARNs for KMS key administration"
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

  validation {
    condition     = var.force_destroy == true || var.force_destroy == false
    error_message = "force_destroy must be a boolean value (true or false)."
  }
}

# --- CloudTrail Management Events Toggle ---

variable "cloudtrail_management_events" {
  description = "Enable Management Events in the CloudTrail advanced_event_selector. Set to false to omit management event logging (not recommended for production)."
  type        = bool
  default     = true
}

# --- CloudTrail Data Event Toggles ---

variable "cloudtrail_s3_data_events" {
  description = "Enable S3 Data Events in the CloudTrail advanced_event_selector. Set to false to omit S3 data event logging and reduce costs."
  type        = bool
  default     = true
}

variable "cloudtrail_lambda_data_events" {
  description = "Enable Lambda Data Events in the CloudTrail advanced_event_selector. Set to false to omit Lambda data event logging and reduce costs."
  type        = bool
  default     = true
}

# --- CloudTrail Insights ---

variable "cloudtrail_insights" {
  description = "List of CloudTrail Insight types to enable. Valid values: ApiCallRateInsight, ApiErrorRateInsight."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for insight in var.cloudtrail_insights :
      contains(["ApiCallRateInsight", "ApiErrorRateInsight"], insight)
    ])
    error_message = "Each entry in cloudtrail_insights must be either 'ApiCallRateInsight' or 'ApiErrorRateInsight'."
  }
}

# --- S3 Lifecycle Granularity ---

variable "s3_lifecycle_rules" {
  description = "Per-prefix S3 lifecycle rules for the central log bucket. When provided, separate rules are created for cloudtrail/, config/, and s3-access-logs/ prefixes. When null, the single log_retention_days value applies to all objects."
  type = object({
    cloudtrail = optional(object({
      retention_days               = optional(number)
      glacier_transition_days      = optional(number)
      deep_archive_transition_days = optional(number)
    }))
    config = optional(object({
      retention_days               = optional(number)
      glacier_transition_days      = optional(number)
      deep_archive_transition_days = optional(number)
    }))
    access_logs = optional(object({
      retention_days               = optional(number)
      glacier_transition_days      = optional(number)
      deep_archive_transition_days = optional(number)
    }))
  })
  default = null

  validation {
    condition = var.s3_lifecycle_rules == null || alltrue(flatten([
      var.s3_lifecycle_rules.cloudtrail != null ? [
        var.s3_lifecycle_rules.cloudtrail.retention_days == null || var.s3_lifecycle_rules.cloudtrail.retention_days > 0,
        var.s3_lifecycle_rules.cloudtrail.glacier_transition_days == null || var.s3_lifecycle_rules.cloudtrail.glacier_transition_days > 0,
        var.s3_lifecycle_rules.cloudtrail.deep_archive_transition_days == null || var.s3_lifecycle_rules.cloudtrail.deep_archive_transition_days > 0,
      ] : [],
      var.s3_lifecycle_rules.config != null ? [
        var.s3_lifecycle_rules.config.retention_days == null || var.s3_lifecycle_rules.config.retention_days > 0,
        var.s3_lifecycle_rules.config.glacier_transition_days == null || var.s3_lifecycle_rules.config.glacier_transition_days > 0,
        var.s3_lifecycle_rules.config.deep_archive_transition_days == null || var.s3_lifecycle_rules.config.deep_archive_transition_days > 0,
      ] : [],
      var.s3_lifecycle_rules.access_logs != null ? [
        var.s3_lifecycle_rules.access_logs.retention_days == null || var.s3_lifecycle_rules.access_logs.retention_days > 0,
        var.s3_lifecycle_rules.access_logs.glacier_transition_days == null || var.s3_lifecycle_rules.access_logs.glacier_transition_days > 0,
        var.s3_lifecycle_rules.access_logs.deep_archive_transition_days == null || var.s3_lifecycle_rules.access_logs.deep_archive_transition_days > 0,
      ] : [],
    ]))
    error_message = "All s3_lifecycle_rules day values must be positive integers when specified."
  }

  # The lifecycle must not delete log objects before the retention
  # period is over. The effective retention is merged from three layers
  # (configurations/base/base.tfvars, env/common.hcl and the enabled compliance
  # frameworks) and only exists as one number here, where log_retention_days and
  # s3_lifecycle_rules arrive together. That is why the guard sits in the module
  # and not in the loader: the loader has no way to fail, and a check block would
  # only warn while the shortened lifecycle is applied anyway.
  validation {
    condition = var.s3_lifecycle_rules == null || alltrue([
      for rule in [
        var.s3_lifecycle_rules.cloudtrail,
        var.s3_lifecycle_rules.config,
        var.s3_lifecycle_rules.access_logs,
      ] :
      rule == null || rule.retention_days == null || rule.retention_days >= var.log_retention_days
    ])
    error_message = "Every s3_lifecycle_rules retention_days must be greater than or equal to log_retention_days — a shorter value expires the log objects before the required retention period ends."
  }
}


# --- S3 Cross-Region Replication ---

variable "s3_replication_config" {
  description = "S3 cross-region replication configuration for the central log bucket. When non-empty, creates replication rules with KMS re-encryption. Set to {} to disable."
  type = object({
    destination_region      = optional(string, "")
    destination_bucket_arn  = optional(string, "")
    destination_kms_key_arn = optional(string, "")
    rules = optional(list(object({
      id       = string
      prefix   = optional(string, "")
      status   = optional(string, "Enabled")
      priority = optional(number, 0)
    })), [])
  })
  default = {}

  validation {
    condition = (
      var.s3_replication_config.destination_region == "" ||
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", var.s3_replication_config.destination_region))
    )
    error_message = "destination_region must be empty or a valid AWS region name (e.g., us-east-1, eu-west-1)."
  }

  # The module creates a replica KMS key only together with the destination
  # bucket. For an externally provided bucket, the key of that bucket must be
  # passed in — replication of KMS-encrypted objects needs a replica key.
  validation {
    condition = (
      var.s3_replication_config.destination_region == "" ||
      var.s3_replication_config.destination_bucket_arn == "" ||
      var.s3_replication_config.destination_bucket_arn == null ||
      (var.s3_replication_config.destination_kms_key_arn != "" && var.s3_replication_config.destination_kms_key_arn != null)
    )
    error_message = "destination_kms_key_arn is required when destination_bucket_arn is set — the module only creates a replica KMS key for a destination bucket it creates itself."
  }
}

# --- CloudTrail Account Trails ---

variable "cloudtrail_account_trails" {
  description = "List of additional account-level CloudTrail trails (separate from the org trail). Per trail: region scope (multi_region, include_global_service_events), a management event scope, Insight types, and delivery into an own CloudWatch log group (send_to_cloudwatch_logs with cloudwatch_logs_retention). The defaults keep the plan of an existing trail."
  type = list(object({
    name                       = string
    s3_bucket_name             = optional(string, "")
    s3_key_prefix              = optional(string, "")
    enable_log_file_validation = optional(bool, true)
    advanced_event_selectors   = optional(list(any), [])
    # Region scope: both defaults are the resource's production values
    # (multi-region trail, global service events included).
    multi_region                  = optional(bool, true)
    include_global_service_events = optional(bool, true)
    # Management event scope: null records no management events (the
    # default), All/ReadOnly/WriteOnly add a management event selector.
    management_events = optional(string, null)
    # Insight selectors of this trail.
    insights = optional(list(string), [])
    # Delivery into an own CloudWatch log group /aws/cloudtrail/<name>; the
    # retention is the pair of the toggle and required with it.
    send_to_cloudwatch_logs   = optional(bool, false)
    cloudwatch_logs_retention = optional(number, null)
  }))
  default = []

  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      can(regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$", trail.name))
    ])
    error_message = "Each cloudtrail_account_trails name must be 3-128 characters, start with a letter or digit and contain only letters, digits, dot, underscore or hyphen — the AWS CloudTrail naming rule."
  }

  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      try(trail.s3_bucket_name, "") == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", trail.s3_bucket_name))
    ])
    error_message = "Each cloudtrail_account_trails s3_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }

  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      alltrue([
        for insight in trail.insights :
        contains(["ApiCallRateInsight", "ApiErrorRateInsight"], insight)
      ])
    ])
    error_message = "Each cloudtrail_account_trails insights entry must be 'ApiCallRateInsight' or 'ApiErrorRateInsight' — the two Insight types CloudTrail knows."
  }

  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      length(distinct(trail.insights)) == length(trail.insights)
    ])
    error_message = "cloudtrail_account_trails insights must not contain duplicates — a repeated type would write the same selector twice."
  }

  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      trail.management_events == null || contains(["All", "ReadOnly", "WriteOnly"], trail.management_events)
    ])
    error_message = "Each cloudtrail_account_trails management_events must be null (no management events, the default), 'All', 'ReadOnly' or 'WriteOnly'."
  }

  # The toggle and the retention are one decision: a log group cannot be
  # created without a retention, and a retention without the delivery would be
  # a value without a reader.
  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      trail.send_to_cloudwatch_logs == (trail.cloudwatch_logs_retention != null)
    ])
    error_message = "cloudtrail_account_trails: send_to_cloudwatch_logs and cloudwatch_logs_retention belong together — the delivery needs a retention for its log group, and a retention without the delivery would silently do nothing."
  }

  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      trail.cloudwatch_logs_retention == null || contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], trail.cloudwatch_logs_retention)
    ])
    error_message = "Each cloudtrail_account_trails cloudwatch_logs_retention must be null or a valid CloudWatch retention value."
  }

  # The delivery role is named tlz-cloudtrail-cw-<trail name>; IAM caps role
  # names at 64 characters, so the trail name may carry at most 46. The trail
  # itself allows 128 — without this check the plan would pass and the apply
  # would fail on the role.
  validation {
    condition = alltrue([
      for trail in var.cloudtrail_account_trails :
      !trail.send_to_cloudwatch_logs || length(trail.name) <= 46
    ])
    error_message = "cloudtrail_account_trails: a trail with send_to_cloudwatch_logs needs a name of at most 46 characters — the delivery role tlz-cloudtrail-cw-<name> may not exceed the 64-character IAM limit."
  }
}

# --- Organization Trail Region Scope ---

variable "cloudtrail_org_trail_settings" {
  description = "Region scope of the organization trail: multi-region recording and the inclusion of global service events. Both default to true — the production values of the trail."
  type = object({
    multi_region                  = optional(bool, true)
    include_global_service_events = optional(bool, true)
  })
  default = {}
}

# --- CloudWatch Log Subscriptions ---

variable "cloudwatch_log_subscriptions" {
  description = "List of CloudWatch Log subscription filters. When destination_arn is empty, the subscription targets the module-managed Kinesis Data Stream."
  type = list(object({
    name            = string
    log_group_name  = string
    filter_pattern  = string
    destination_arn = optional(string, "")
  }))
  default = []

  validation {
    condition = alltrue([
      for sub in var.cloudwatch_log_subscriptions :
      sub.name != "" && sub.log_group_name != ""
    ])
    error_message = "Each cloudwatch_log_subscriptions entry needs a non-empty name and log_group_name — an empty log group name silently creates no filter."
  }

  validation {
    condition = alltrue([
      for sub in var.cloudwatch_log_subscriptions :
      startswith(sub.log_group_name, "/")
    ])
    error_message = "Each cloudwatch_log_subscriptions log_group_name must start with a slash (e.g. /aws/cloudtrail/organization)."
  }

  # An empty destination_arn is the documented opt-in for the module-managed
  # Kinesis stream, so only a non-empty value is checked.
  validation {
    condition = alltrue([
      for sub in var.cloudwatch_log_subscriptions :
      try(sub.destination_arn, "") == "" || can(regex("^arn:[a-z0-9-]+:", sub.destination_arn))
    ])
    error_message = "Each cloudwatch_log_subscriptions destination_arn must be empty (use the module-managed Kinesis stream) or a valid ARN."
  }

  validation {
    condition     = length(distinct([for sub in var.cloudwatch_log_subscriptions : sub.name])) == length(var.cloudwatch_log_subscriptions)
    error_message = "cloudwatch_log_subscriptions names must be unique — the module keys its filters by name and a duplicate would silently drop one entry."
  }
}

# --- CloudWatch Log Exclusions ---

variable "cloudwatch_log_exclusions" {
  description = "List of log group names or patterns to exclude from subscription filters."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for pattern in var.cloudwatch_log_exclusions : trimspace(pattern) != ""])
    error_message = "cloudwatch_log_exclusions must not contain empty entries — an empty pattern would exclude nothing and hide a configuration mistake."
  }
}

variable "cloudwatch_log_exclusion_rules" {
  description = "Structured exclusion rules beside the flat cloudwatch_log_exclusions list. Each entry scopes by accounts (12-digit IDs), organizational units and regions — unset scopes match — and excludes log groups by exact name, by name prefix with a trailing *, or entirely (exclude_all). A rule applies when every given scope matches this deployment; matching subscriptions are not created. [] keeps only the name-based list."
  type = list(object({
    accounts             = optional(list(string), [])
    organizational_units = optional(list(string), [])
    regions              = optional(list(string), [])
    log_group_names      = optional(list(string), [])
    exclude_all          = optional(bool, false)
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.cloudwatch_log_exclusion_rules :
      alltrue([for id in rule.accounts : can(regex("^[0-9]{12}$", id))])
    ])
    error_message = "Each cloudwatch_log_exclusion_rules accounts entry must be a 12-digit AWS account ID — an account name would silently never match."
  }

  validation {
    condition = alltrue([
      for rule in var.cloudwatch_log_exclusion_rules :
      alltrue([for region in rule.regions : can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+$", region))])
    ])
    error_message = "Each cloudwatch_log_exclusion_rules regions entry must be a valid AWS region name (e.g. eu-central-1) — a mistyped region would silently never match."
  }

  validation {
    condition = alltrue([
      for rule in var.cloudwatch_log_exclusion_rules :
      alltrue([for ou in rule.organizational_units : trimspace(ou) != "" && ou == trimspace(ou)])
    ])
    error_message = "Each cloudwatch_log_exclusion_rules organizational_units entry must be non-empty without surrounding whitespace — a padded name would silently never match."
  }

  validation {
    condition = alltrue([
      for rule in var.cloudwatch_log_exclusion_rules :
      alltrue([for name in rule.log_group_names : trimspace(name) != ""])
    ])
    error_message = "cloudwatch_log_exclusion_rules log_group_names must not contain empty entries — an empty pattern would exclude nothing and hide a configuration mistake."
  }

  # exclude_all is the whole point of an entry or it is absent: together with
  # name selectors one of the two would silently win.
  validation {
    condition = alltrue([
      for rule in var.cloudwatch_log_exclusion_rules :
      !rule.exclude_all || length(rule.log_group_names) == 0
    ])
    error_message = "A cloudwatch_log_exclusion_rules entry with exclude_all must not carry log_group_names — the blanket exclusion supersedes the name selectors and one of the two would silently win."
  }

  # An entry has to say what it excludes; scope alone excludes nothing.
  validation {
    condition = alltrue([
      for rule in var.cloudwatch_log_exclusion_rules :
      rule.exclude_all || length(rule.log_group_names) > 0
    ])
    error_message = "Each cloudwatch_log_exclusion_rules entry needs exclude_all or at least one log_group_names pattern — an entry with only scope selectors would silently exclude nothing."
  }
}

variable "deployment_organizational_unit" {
  description = "Organizational unit of the account this module deploys into, as the configuration's account list names it. Read by the organizational_units selector of cloudwatch_log_exclusion_rules. Empty when the account sits in no organizational unit (the management account)."
  type        = string
  default     = ""

  validation {
    condition     = var.deployment_organizational_unit == trimspace(var.deployment_organizational_unit)
    error_message = "deployment_organizational_unit must not carry surrounding whitespace — a padded name would silently never match an exclusion rule."
  }
}

# --- Account-Wide CloudWatch Log Subscription ---

variable "cloudwatch_log_account_subscription" {
  description = "Account-wide CloudWatch Logs subscription filter policy. Where cloudwatch_log_subscriptions attaches one filter per named log group, this policy covers every log group of the account, minus what selection_criteria excludes (format: LogGroupName NOT IN [\"a\", \"b\"]). An empty destination_arn targets the module-managed Kinesis Data Stream. policy_name defaults to the production name (tlz-account-log-subscription). Logs PutAccountPolicy is an UPSERT keyed by that name, and an account allows ONE subscription filter policy per region: a live apply-test that keeps the default silently adopts a live policy of that name and its teardown deletes it, whereas a test-scoped name (tlz-l4test-) makes the same collision fail loudly with LimitExceededException — so override it in every live test. Not pinned to the tlz- namespace: no organization guardrail names a Logs account-policy ARN. {} keeps the account without such a policy."
  type = object({
    enabled            = optional(bool, false)
    filter_pattern     = optional(string, "")
    destination_arn    = optional(string, "")
    selection_criteria = optional(string, null)
    policy_name        = optional(string, "tlz-account-log-subscription")
  })
  default = {}

  # The CloudWatch Logs account-policy naming rule: 1-256 characters, must
  # not start with aws/ (reserved). Checked even when disabled — the default
  # always satisfies it, so this never fires on {}.
  validation {
    condition = (
      length(var.cloudwatch_log_account_subscription.policy_name) >= 1 &&
      length(var.cloudwatch_log_account_subscription.policy_name) <= 256 &&
      !startswith(var.cloudwatch_log_account_subscription.policy_name, "aws/")
    )
    error_message = "cloudwatch_log_account_subscription policy_name must be 1-256 characters and must not start with aws/ — the CloudWatch Logs account-policy naming rule."
  }

  validation {
    condition = (
      var.cloudwatch_log_account_subscription.selection_criteria == null ||
      can(regex("^LogGroupName NOT IN \\[.*\\]$", var.cloudwatch_log_account_subscription.selection_criteria))
    )
    error_message = "cloudwatch_log_account_subscription selection_criteria must be null or of the form LogGroupName NOT IN [\"name\", ...] — the one selection form the account policy supports."
  }

  # Same contract as cloudwatch_log_subscriptions: empty means the
  # module-managed Kinesis stream, so only a non-empty value is checked.
  validation {
    condition = (
      var.cloudwatch_log_account_subscription.destination_arn == "" ||
      can(regex("^arn:[a-z0-9-]+:", var.cloudwatch_log_account_subscription.destination_arn))
    )
    error_message = "cloudwatch_log_account_subscription destination_arn must be empty (use the module-managed Kinesis stream) or a valid ARN."
  }

  # Values on a disabled policy would silently do nothing and are rejected —
  # the binding every gated input of this module carries.
  validation {
    condition = (
      var.cloudwatch_log_account_subscription.enabled ||
      (
        var.cloudwatch_log_account_subscription.selection_criteria == null &&
        var.cloudwatch_log_account_subscription.filter_pattern == "" &&
        var.cloudwatch_log_account_subscription.destination_arn == "" &&
        var.cloudwatch_log_account_subscription.policy_name == "tlz-account-log-subscription"
      )
    )
    error_message = "cloudwatch_log_account_subscription values require enabled = true — a criteria, pattern, destination or policy_name on a disabled policy would silently do nothing."
  }
}

# --- Kinesis/Firehose Archive Pipeline Tuning ---

variable "kinesis_pipeline_config" {
  description = "Tuning of the module-managed CloudWatch-to-S3 archive pipeline (Kinesis stream, Firehose delivery, optional record-processor Lambda). {} keeps the production values: 24 h retention, on-demand capacity, 64 MiB / 60 s delivery buffer, no compression, no file extension, the default error prefix and no processor Lambda — the delivery stream then decompresses the gzip subscription records with the native Firehose Decompression processor. The pipeline itself is switched by cloudwatch_log_subscriptions / cloudwatch_log_account_subscription."
  type = object({
    kinesis_retention_hours             = optional(number, 24)
    kinesis_stream_mode                 = optional(string, "ON_DEMAND")
    kinesis_shard_count                 = optional(number)
    firehose_buffering_size_mb          = optional(number, 64)
    firehose_buffering_interval_seconds = optional(number, 60)
    firehose_compression_format         = optional(string, "UNCOMPRESSED")
    firehose_file_extension             = optional(string)
    firehose_error_output_prefix        = optional(string, "cloudwatch-logs-errors/!{firehose:error-output-type}/")
    lambda_processor = optional(object({
      enabled                 = optional(bool, false)
      buffer_size_mb          = optional(number, 0.2)
      buffer_interval_seconds = optional(number, 60)
      retries                 = optional(number, 3)
    }), {})
  })
  default = {}

  validation {
    condition = (
      var.kinesis_pipeline_config.kinesis_retention_hours >= 24 &&
      var.kinesis_pipeline_config.kinesis_retention_hours <= 8760 &&
      floor(var.kinesis_pipeline_config.kinesis_retention_hours) == var.kinesis_pipeline_config.kinesis_retention_hours
    )
    error_message = "kinesis_pipeline_config.kinesis_retention_hours must be a whole number of hours between 24 and 8760 (one year) — the Kinesis retention bounds."
  }

  validation {
    condition     = contains(["ON_DEMAND", "PROVISIONED"], var.kinesis_pipeline_config.kinesis_stream_mode)
    error_message = "kinesis_pipeline_config.kinesis_stream_mode must be ON_DEMAND or PROVISIONED."
  }

  # A shard count is a property of provisioned capacity; on an on-demand
  # stream it would silently do nothing and is rejected.
  validation {
    condition = (
      var.kinesis_pipeline_config.kinesis_shard_count == null || (
        var.kinesis_pipeline_config.kinesis_stream_mode == "PROVISIONED" &&
        var.kinesis_pipeline_config.kinesis_shard_count >= 1 &&
        floor(var.kinesis_pipeline_config.kinesis_shard_count) == var.kinesis_pipeline_config.kinesis_shard_count
      )
    )
    error_message = "kinesis_pipeline_config.kinesis_shard_count must be unset, or a whole number of at least 1 together with kinesis_stream_mode = PROVISIONED."
  }

  validation {
    condition = (
      var.kinesis_pipeline_config.firehose_buffering_size_mb >= 1 &&
      var.kinesis_pipeline_config.firehose_buffering_size_mb <= 128 &&
      floor(var.kinesis_pipeline_config.firehose_buffering_size_mb) == var.kinesis_pipeline_config.firehose_buffering_size_mb
    )
    error_message = "kinesis_pipeline_config.firehose_buffering_size_mb must be a whole number between 1 and 128 MiB — the Firehose S3 buffering bounds."
  }

  validation {
    condition = (
      var.kinesis_pipeline_config.firehose_buffering_interval_seconds >= 60 &&
      var.kinesis_pipeline_config.firehose_buffering_interval_seconds <= 900 &&
      floor(var.kinesis_pipeline_config.firehose_buffering_interval_seconds) == var.kinesis_pipeline_config.firehose_buffering_interval_seconds
    )
    error_message = "kinesis_pipeline_config.firehose_buffering_interval_seconds must be a whole number between 60 and 900 seconds — the Firehose S3 buffering bounds."
  }

  validation {
    condition     = contains(["UNCOMPRESSED", "GZIP", "ZIP", "Snappy", "HADOOP_SNAPPY"], var.kinesis_pipeline_config.firehose_compression_format)
    error_message = "kinesis_pipeline_config.firehose_compression_format must be one of: UNCOMPRESSED, GZIP, ZIP, Snappy, HADOOP_SNAPPY."
  }

  validation {
    condition = (
      var.kinesis_pipeline_config.firehose_file_extension == null ||
      can(regex("^\\.[0-9a-z!\\-_.*'()]+$", var.kinesis_pipeline_config.firehose_file_extension))
    )
    error_message = "kinesis_pipeline_config.firehose_file_extension must be unset or start with a dot followed by lowercase letters, digits or the S3-safe special characters (e.g. .json.gz) — the Firehose file-extension rule."
  }

  validation {
    condition     = length(var.kinesis_pipeline_config.firehose_error_output_prefix) <= 512
    error_message = "kinesis_pipeline_config.firehose_error_output_prefix must be at most 512 characters — the Firehose prefix limit."
  }

  validation {
    condition = (
      var.kinesis_pipeline_config.lambda_processor.buffer_size_mb >= 0.2 &&
      var.kinesis_pipeline_config.lambda_processor.buffer_size_mb <= 3
    )
    error_message = "kinesis_pipeline_config.lambda_processor.buffer_size_mb must be between 0.2 and 3 MB — the Lambda processor payload bounds."
  }

  validation {
    condition = (
      var.kinesis_pipeline_config.lambda_processor.buffer_interval_seconds >= 60 &&
      var.kinesis_pipeline_config.lambda_processor.buffer_interval_seconds <= 900 &&
      floor(var.kinesis_pipeline_config.lambda_processor.buffer_interval_seconds) == var.kinesis_pipeline_config.lambda_processor.buffer_interval_seconds
    )
    error_message = "kinesis_pipeline_config.lambda_processor.buffer_interval_seconds must be a whole number between 60 and 900 seconds."
  }

  validation {
    condition = (
      var.kinesis_pipeline_config.lambda_processor.retries >= 0 &&
      var.kinesis_pipeline_config.lambda_processor.retries <= 512 &&
      floor(var.kinesis_pipeline_config.lambda_processor.retries) == var.kinesis_pipeline_config.lambda_processor.retries
    )
    error_message = "kinesis_pipeline_config.lambda_processor.retries must be a whole number between 0 and 512."
  }

  # Tuning on a disabled processor would silently do nothing and is rejected —
  # the binding every gated input of this module carries.
  validation {
    condition = (
      var.kinesis_pipeline_config.lambda_processor.enabled || (
        var.kinesis_pipeline_config.lambda_processor.buffer_size_mb == 0.2 &&
        var.kinesis_pipeline_config.lambda_processor.buffer_interval_seconds == 60 &&
        var.kinesis_pipeline_config.lambda_processor.retries == 3
      )
    )
    error_message = "kinesis_pipeline_config.lambda_processor tuning requires enabled = true — buffer or retry values on a disabled processor would silently do nothing."
  }
}

# --- CloudTrail SNS Topic ---

variable "cloudtrail_sns_topic_name" {
  description = "Name of an SNS topic to create and attach to the org CloudTrail trail. Empty string disables SNS. A non-empty name must stay inside the tlz- namespace: the organization guardrails (ProtectSNSTopics in tlz-core-guardrails-1.json) protect only arn:*:sns:*:*:tlz-* from tampering, and the static prefix guard reads this validation as the namespace pin of a variable-fed name — without it, a topic named here would be the one SNS topic of the landing zone outside every Deny statement."
  type        = string
  default     = ""

  validation {
    condition     = var.cloudtrail_sns_topic_name == "" || can(regex("^tlz-[a-zA-Z0-9_-]{1,252}$", var.cloudtrail_sns_topic_name))
    error_message = "cloudtrail_sns_topic_name must be empty (SNS disabled) or start with tlz- and be 1-256 characters of letters, digits, underscore or hyphen in total — the AWS SNS topic naming rule inside the guardrail-protected tlz- namespace."
  }
}

# --- Fixed resource names of the organization trail ---
#
# Each name defaults to the production name, so a live
# plan stays empty. They exist so a live apply-test of the module can scope its
# own resources: CreateTrail, CreateRole and CreateAlias are create-only and
# fail with an AlreadyExists error against the live resource of the same name.
# A changed default is a destroy/create of the live resource — leave the
# defaults in production. See the README, "Fixed resource names".

variable "cloudtrail_org_trail_name" {
  description = "Name of the organization trail. The default is the production name of the trail; the CloudWatch log group of the trail derives from it as /aws/cloudtrail/<name>. A changed value replaces the live trail."
  type        = string
  default     = "tlz-org-trail"

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$", var.cloudtrail_org_trail_name))
    error_message = "cloudtrail_org_trail_name must be 3-128 characters, start with a letter or digit and contain only letters, digits, dot, underscore or hyphen — the AWS CloudTrail naming rule."
  }
}

variable "cloudtrail_cloudwatch_role_name" {
  description = "Name of the IAM role the organization trail assumes to deliver into its CloudWatch log group (created with cloudwatch_log_group_retention). The default is the production name of the role."
  type        = string
  default     = "tlz-cloudtrail-cloudwatch-role"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.cloudtrail_cloudwatch_role_name))
      && startswith(var.cloudtrail_cloudwatch_role_name, "tlz-")
    )
    error_message = "cloudtrail_cloudwatch_role_name must be 1-64 characters of letters, digits or +=,.@_- (the IAM role naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectIAMRoles statement in configurations/policies/organization/tlz-core-guardrails-2.json DENIES modification and deletion only for arn:*:iam::*:role/tlz-*, so a role named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

variable "cloudtrail_cloudwatch_policy_name" {
  description = "Name of the inline policy on the CloudWatch delivery role of the organization trail. The default is the production name of the policy."
  type        = string
  default     = "tlz-cloudtrail-cloudwatch-policy"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]{1,128}$", var.cloudtrail_cloudwatch_policy_name))
    error_message = "cloudtrail_cloudwatch_policy_name must be 1-128 characters of letters, digits or +=,.@_- — the IAM policy naming rule."
  }
}

# --- Fixed resource names of the CloudWatch-to-S3 Kinesis pipeline ---
#
# Same contract as the trail names above: each defaults to the production
# name, so a live plan stays empty, and
# exists so a live apply-test of the module can scope its own pipeline.
# CreateStream, CreateDeliveryStream, CreateRole and CreateFunction are all
# create-only and fail with a ResourceInUse / EntityAlreadyExists /
# ResourceConflict error against the live resource of the same name. A
# changed default is a destroy/create of the live resource.
#
# Six of the nine names are guardrail classes and pin the tlz- namespace in
# their validation: the stream and the delivery stream (ProtectKinesisStreams
# in tlz-core-guardrails-1.json denies for arn:*:kinesis:*:*:stream/tlz-* and
# arn:*:firehose:*:*:deliverystream/tlz-*), the processor function
# (ProtectLambdaFunctions, arn:*:lambda:*:*:function:tlz-*, and its log group
# /aws/lambda/tlz-* under ProtectCloudWatchLogGroups) and the three roles
# (ProtectIAMRoles in tlz-core-guardrails-2.json, arn:*:iam::*:role/tlz-*).
# The three inline policies have no ARN of their own and no guardrail names
# them, so they carry the IAM naming rule only — like
# cloudtrail_cloudwatch_policy_name.

variable "kinesis_stream_name" {
  description = "Name of the Kinesis data stream the CloudWatch Logs subscriptions deliver into (created while the pipeline is enabled). The default is the production name of the stream. A changed value replaces the live stream."
  type        = string
  default     = "tlz-cw-to-s3-stream"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9_.-]{1,128}$", var.kinesis_stream_name))
      && startswith(var.kinesis_stream_name, "tlz-")
    )
    error_message = "kinesis_stream_name must be 1-128 characters of letters, digits, underscore, dot or hyphen (the Kinesis stream naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectKinesisStreams statement in configurations/policies/organization/tlz-core-guardrails-1.json DENIES kinesis:Delete*/Update*/Decrease* only for arn:*:kinesis:*:*:stream/tlz-*, so a stream named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

variable "firehose_delivery_stream_name" {
  description = "Name of the Firehose delivery stream that drains the Kinesis stream into the central log bucket (created while the pipeline is enabled). The default is the production name of the delivery stream. A changed value replaces the live delivery stream."
  type        = string
  default     = "tlz-cw-to-s3-delivery"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9_.-]{1,64}$", var.firehose_delivery_stream_name))
      && startswith(var.firehose_delivery_stream_name, "tlz-")
    )
    error_message = "firehose_delivery_stream_name must be 1-64 characters of letters, digits, underscore, dot or hyphen (the Firehose delivery stream naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectKinesisStreams statement in configurations/policies/organization/tlz-core-guardrails-1.json DENIES firehose:Delete*/Update*/Start*/Stop* only for arn:*:firehose:*:*:deliverystream/tlz-*, so a delivery stream named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

variable "cw_to_kinesis_role_name" {
  description = "Name of the IAM role CloudWatch Logs assumes to put subscription records onto the Kinesis stream (created while the pipeline is enabled). The default is the production name of the role."
  type        = string
  default     = "tlz-cw-to-kinesis-role"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.cw_to_kinesis_role_name))
      && startswith(var.cw_to_kinesis_role_name, "tlz-")
    )
    error_message = "cw_to_kinesis_role_name must be 1-64 characters of letters, digits or +=,.@_- (the IAM role naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectIAMRoles statement in configurations/policies/organization/tlz-core-guardrails-2.json DENIES modification and deletion only for arn:*:iam::*:role/tlz-*, so a role named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

variable "cw_to_kinesis_policy_name" {
  description = "Name of the inline policy on the CloudWatch-to-Kinesis role (PutRecord on the stream, GenerateDataKey on the log bucket key). The default is the production name of the policy."
  type        = string
  default     = "tlz-cw-to-kinesis-policy"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]{1,128}$", var.cw_to_kinesis_policy_name))
    error_message = "cw_to_kinesis_policy_name must be 1-128 characters of letters, digits or +=,.@_- — the IAM policy naming rule."
  }
}

variable "firehose_delivery_role_name" {
  description = "Name of the IAM role the Firehose delivery stream assumes to read the Kinesis stream, write the central log bucket and invoke the optional processor (created while the pipeline is enabled). The default is the production name of the role."
  type        = string
  default     = "tlz-firehose-delivery-role"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.firehose_delivery_role_name))
      && startswith(var.firehose_delivery_role_name, "tlz-")
    )
    error_message = "firehose_delivery_role_name must be 1-64 characters of letters, digits or +=,.@_- (the IAM role naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectIAMRoles statement in configurations/policies/organization/tlz-core-guardrails-2.json DENIES modification and deletion only for arn:*:iam::*:role/tlz-*, so a role named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

variable "firehose_delivery_policy_name" {
  description = "Name of the inline policy on the Firehose delivery role. The default is the production name of the policy."
  type        = string
  default     = "tlz-firehose-delivery-policy"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]{1,128}$", var.firehose_delivery_policy_name))
    error_message = "firehose_delivery_policy_name must be 1-128 characters of letters, digits or +=,.@_- — the IAM policy naming rule."
  }
}

variable "firehose_processor_function_name" {
  description = "Name of the optional record-processor Lambda function (created with kinesis_pipeline_config.lambda_processor.enabled). Its CloudWatch log group derives from it as /aws/lambda/<name>, and the function's inline policy scopes its logs grant to that group. The default is the production name of the function. A changed value replaces the live function."
  type        = string
  default     = "tlz-cw-log-processor"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9_-]{1,64}$", var.firehose_processor_function_name))
      && startswith(var.firehose_processor_function_name, "tlz-")
    )
    error_message = "firehose_processor_function_name must be 1-64 characters of letters, digits, underscore or hyphen (the Lambda function naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectLambdaFunctions statement in configurations/policies/organization/tlz-core-guardrails-1.json DENIES code, configuration and permission changes only for arn:*:lambda:*:*:function:tlz-*, and ProtectCloudWatchLogGroups covers the function's log group only as /aws/lambda/tlz-*, so a function named outside that prefix silently loses both protections. This validation is the only enforcement of the pin."
  }
}

variable "firehose_processor_role_name" {
  description = "Name of the IAM role the optional record-processor Lambda runs as (created with kinesis_pipeline_config.lambda_processor.enabled). The default is the production name of the role."
  type        = string
  default     = "tlz-cw-log-processor-role"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.firehose_processor_role_name))
      && startswith(var.firehose_processor_role_name, "tlz-")
    )
    error_message = "firehose_processor_role_name must be 1-64 characters of letters, digits or +=,.@_- (the IAM role naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectIAMRoles statement in configurations/policies/organization/tlz-core-guardrails-2.json DENIES modification and deletion only for arn:*:iam::*:role/tlz-*, so a role named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

variable "firehose_processor_policy_name" {
  description = "Name of the inline policy on the record-processor Lambda role (its CloudWatch Logs grant). The default is the production name of the policy."
  type        = string
  default     = "tlz-cw-log-processor-policy"

  validation {
    condition     = can(regex("^[a-zA-Z0-9+=,.@_-]{1,128}$", var.firehose_processor_policy_name))
    error_message = "firehose_processor_policy_name must be 1-128 characters of letters, digits or +=,.@_- — the IAM policy naming rule."
  }
}

variable "firehose_processor_log_retention_days" {
  description = "Retention of the record-processor Lambda's own execution log group /aws/lambda/<firehose_processor_function_name>, which the module declares (0 = never expire). Lambda would otherwise create that group implicitly on the first invocation, outside the state and without any retention — see README, \"Lambda execution log groups\"."
  type        = number
  default     = 365

  # CloudWatch accepts only this fixed set of retention values; 0 means never
  # expire. Any other number is rejected at apply time.
  validation {
    condition = contains(
      [0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.firehose_processor_log_retention_days
    )
    error_message = "firehose_processor_log_retention_days must be one of the CloudWatch retention values: 0 (never expire), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

variable "firehose_processor_log_kms_key_arn" {
  description = "Optional KMS key ARN for encrypting the record-processor Lambda's execution log group. Empty string keeps the CloudWatch service default encryption; no key is created by this module."
  type        = string
  default     = ""

  validation {
    condition     = var.firehose_processor_log_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.firehose_processor_log_kms_key_arn))
    error_message = "firehose_processor_log_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}

# --- ELB Log Bucket ---

variable "enable_elb_log_bucket" {
  description = "Create a dedicated S3 bucket for ELB access logs with KMS encryption and lifecycle management."
  type        = bool
  default     = false
}

variable "elb_log_bucket_lifecycle" {
  description = "Lifecycle configuration for the ELB log bucket. Controls expiration and optional Glacier transitions."
  type = object({
    retention_days               = optional(number, 365)
    glacier_transition_days      = optional(number, null)
    deep_archive_transition_days = optional(number, null)
  })
  default = {}

  validation {
    condition     = var.elb_log_bucket_lifecycle.retention_days > 0
    error_message = "elb_log_bucket_lifecycle.retention_days must be a positive integer."
  }

  # Same guard as on s3_lifecycle_rules: the ELB log bucket carries
  # access logs and is subject to the same retention period.
  #
  # Bound to enable_elb_log_bucket, because that is what
  # aws_s3_bucket_lifecycle_configuration.elb_logs is bound to: without the
  # bucket there is no lifecycle and nothing that could expire early. The module
  # defaults of both values agree (365 days each), so the guard only fires where
  # a caller raises log_retention_days while leaving the expiry of the ELB bucket
  # short.
  validation {
    condition = (
      !var.enable_elb_log_bucket ||
      var.elb_log_bucket_lifecycle.retention_days >= var.log_retention_days
    )
    error_message = "elb_log_bucket_lifecycle.retention_days must be greater than or equal to log_retention_days — a shorter value expires the ELB access logs before the required retention period ends."
  }
}

# --- Separate Access Logs Bucket ---

variable "enable_separate_access_logs_bucket" {
  description = "Create a separate S3 bucket (SSE-S3) for the S3 server access logs of the central log bucket. Without it the central bucket has no server access logging: it cannot log into itself. Recommended for production deployments."
  type        = bool
  default     = false
}

# --- Per-Account KMS Keys ---

variable "enable_per_account_kms_keys" {
  description = "Enable per-account KMS keys for S3. Enable when deploying via cross-account Terragrunt stacks to member accounts."
  type        = bool
  default     = false
}

# --- Config Recorder Ownership ---

variable "manage_config_recorder" {
  description = "Create the AWS Config recorder, delivery channel and recorder status in this account. An account allows exactly one recorder per region; set false when another owner (a legacy recorder, a Control Tower baseline) holds the slot, so the rest of the module can be applied beside it. false skips only those three resources: the organization aggregator and its role stay, and use_config_service_linked_role / config_recorder_custom_role_arn configure exactly the resources being skipped, so they have no effect while this is false."
  type        = bool
  default     = true
}

# --- Organization Config aggregator names ---
#
# The aggregator is the module's one UPSERT-named resource that is live in the
# management account: PutConfigurationAggregator creates OR updates the
# aggregator of that name, so an apply-test carrying the literal reports a
# clean "create" while silently adopting the live organization-wide aggregator
# — and `terraform test`'s automatic teardown then deletes it, with the test's
# own teardown proof listing the deletion as success. The recorder, delivery
# channel and recorder status are count-gated by manage_config_recorder; this
# name is what remains. Unlike the recorder (one per account and region),
# aggregators are not an account singleton — an account can carry a legacy
# and a tlz- one side by side — so a test-scoped name really does make
# the apply-test safe. Its IAM role collides loudly (CreateRole →
# EntityAlreadyExists), which is the harmless kind, but the test cannot reach
# an assertion either way. Both default to the production names, so a live plan
# stays empty; a changed default is a destroy/create of the live resource.
# See the README, "Fixed resource names".

variable "config_aggregator_name" {
  description = "Name of the organization-wide AWS Config aggregator. The default is the production name of the aggregator. PutConfigurationAggregator is an UPSERT: a live account already carrying this name is silently adopted rather than failing, so a live apply-test must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the real organization-wide aggregator. A changed default replaces the live aggregator, so leave it at the literal in production."
  type        = string
  default     = "tlz-org-config-aggregator"

  # Deliberately NOT pinned to the tlz- namespace, unlike the role below: no
  # organization guardrail names a Config aggregator ARN. ProtectConfigRules
  # (tlz-core-guardrails-1.json, tlz-sandbox-guardrails-1.json) denies on
  # Resource "*" and lists no aggregator action, and no statement carries an
  # arn:*:config:*:*:config-aggregator/tlz-* pattern — so the prefix buys this
  # name no protection that a validation would have to carry.
  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,256}$", var.config_aggregator_name))
    error_message = "config_aggregator_name must be 1-256 characters of letters, digits, underscore or hyphen — the AWS Config aggregator naming rule."
  }
}

variable "config_aggregator_role_name" {
  description = "Name of the IAM role the organization-wide Config aggregator assumes to read the member accounts' recorders (AWSConfigRoleForOrganizations). The default is the production name of the role. CreateRole is create-only, so a live apply-test under the default fails loudly with EntityAlreadyExists rather than adopting the live role — but it fails before the first assertion, so the test must override this with a test-scoped tlz-l4test- name. A changed default replaces the live role."
  type        = string
  default     = "tlz-config-aggregator-role"

  validation {
    condition = (
      can(regex("^[a-zA-Z0-9+=,.@_-]{1,64}$", var.config_aggregator_role_name))
      && startswith(var.config_aggregator_role_name, "tlz-")
    )
    error_message = "config_aggregator_role_name must be 1-64 characters of letters, digits or +=,.@_- (the IAM role naming rule) AND start with 'tlz-'. The namespace is not cosmetic: the ProtectIAMRoles statement in configurations/policies/organization/tlz-core-guardrails-2.json DENIES modification and deletion only for arn:*:iam::*:role/tlz-*, so a role named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

# --- KMS alias names ---
#
# Like kms_key_alias of the bootstrap module, each value is the alias name
# WITHOUT the alias/ prefix; the module prepends it. The defaults are the
# production aliases, so a live plan stays empty.
# CreateAlias is create-only: an apply-test into an account that already holds
# the alias fails with AlreadyExistsException unless it sets its own names.

variable "log_bucket_kms_alias" {
  description = "Alias of the KMS key that encrypts the central log bucket, without the alias/ prefix. The default is the production alias of the key."
  type        = string
  default     = "tlz-central-logs"

  validation {
    condition     = can(regex("^[a-zA-Z0-9/_-]{1,250}$", var.log_bucket_kms_alias)) && !startswith(var.log_bucket_kms_alias, "aws/")
    error_message = "log_bucket_kms_alias must be 1-250 characters of letters, digits, hyphen, underscore or forward slash, and must not start with aws/ (reserved) — the KMS alias naming rule."
  }
}

variable "management_kms_alias" {
  description = "Alias of the dedicated management account KMS key (DynamoDB and SSM encryption), without the alias/ prefix. The default is the production alias of the key."
  type        = string
  default     = "tlz/management/kms"

  validation {
    condition     = can(regex("^[a-zA-Z0-9/_-]{1,250}$", var.management_kms_alias)) && !startswith(var.management_kms_alias, "aws/")
    error_message = "management_kms_alias must be 1-250 characters of letters, digits, hyphen, underscore or forward slash, and must not start with aws/ (reserved) — the KMS alias naming rule."
  }
}

variable "cloudwatch_kms_alias" {
  description = "Alias of the dedicated CloudWatch Logs KMS key, without the alias/ prefix. The default is the production alias of the key."
  type        = string
  default     = "tlz/cloudwatch/kms"

  validation {
    condition     = can(regex("^[a-zA-Z0-9/_-]{1,250}$", var.cloudwatch_kms_alias)) && !startswith(var.cloudwatch_kms_alias, "aws/")
    error_message = "cloudwatch_kms_alias must be 1-250 characters of letters, digits, hyphen, underscore or forward slash, and must not start with aws/ (reserved) — the KMS alias naming rule."
  }
}

variable "per_account_s3_kms_alias" {
  description = "Alias of the per-account S3 KMS key (created with enable_per_account_kms_keys), without the alias/ prefix. The default is the production alias of the key."
  type        = string
  default     = "tlz/s3/kms"

  validation {
    condition     = can(regex("^[a-zA-Z0-9/_-]{1,250}$", var.per_account_s3_kms_alias)) && !startswith(var.per_account_s3_kms_alias, "aws/")
    error_message = "per_account_s3_kms_alias must be 1-250 characters of letters, digits, hyphen, underscore or forward slash, and must not start with aws/ (reserved) — the KMS alias naming rule."
  }
}

# --- Config Service-Linked Role Toggle ---

variable "use_config_service_linked_role" {
  description = "Use the AWS Config Service-Linked Role for the Config Recorder. When false, config_recorder_custom_role_arn is used instead."
  type        = bool
  default     = true
}

variable "config_recorder_custom_role_arn" {
  description = "Custom IAM role ARN for the Config Recorder. Required when use_config_service_linked_role is false."
  type        = string
  default     = ""

  validation {
    condition     = var.config_recorder_custom_role_arn == "" || can(regex("^arn:", var.config_recorder_custom_role_arn))
    error_message = "config_recorder_custom_role_arn must be empty or a valid ARN starting with 'arn:'."
  }
}

# --- CloudWatch Log Data Protection ---

variable "enable_cloudwatch_log_data_protection" {
  description = "Enable CloudWatch Log Data Protection to mask sensitive data (PII, credentials) in log groups."
  type        = bool
  default     = false
}

variable "cloudwatch_log_data_protection_log_groups" {
  description = "Additional log group names to apply data protection policies to. The CloudTrail log group is always included when enabled."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for name in var.cloudwatch_log_data_protection_log_groups : startswith(name, "/")])
    error_message = "Each cloudwatch_log_data_protection_log_groups entry must be a log group name starting with a slash (e.g. /aws/lambda/my-function)."
  }
}

variable "cloudwatch_log_data_protection_identifiers" {
  description = "List of managed data identifiers for CloudWatch Log Data Protection. Use short names (e.g., 'CreditCardNumber') — the module constructs full ARNs using the active partition. Region-dependent identifiers require a country suffix (e.g., 'DriversLicense-DE')."
  type        = list(string)
  default = [
    "CreditCardNumber",
    "CreditCardExpiration",
    "CreditCardSecurityCode",
    "EmailAddress",
    "IpAddress",
    "AwsSecretKey",
    "OpenSshPrivateKey",
    "PgpPrivateKey",
    "PkcsPrivateKey",
  ]

  # The module builds the full ARN from the active partition, so the input must
  # be a short name. A value that already carries "arn:" would produce a
  # doubled ARN and a partition that was not derived dynamically.
  validation {
    condition = alltrue([
      for id in var.cloudwatch_log_data_protection_identifiers :
      can(regex("^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*$", id))
    ])
    error_message = "Each cloudwatch_log_data_protection_identifiers entry must be a short managed data identifier name such as CreditCardNumber or DriversLicense-DE, not a full ARN — the module adds the partition and ARN prefix itself."
  }

  validation {
    condition     = length(distinct(var.cloudwatch_log_data_protection_identifiers)) == length(var.cloudwatch_log_data_protection_identifiers)
    error_message = "cloudwatch_log_data_protection_identifiers must not contain duplicates."
  }
}

# --- SSM Associations ---

variable "ssm_associations" {
  description = "List of SSM State Manager association definitions for automated inventory collection or other SSM documents."
  type = list(object({
    name                = string
    schedule_expression = string
    targets = list(object({
      key    = string
      values = list(string)
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for assoc in var.ssm_associations :
      assoc.name != "" && length(assoc.targets) > 0
    ])
    error_message = "Each ssm_associations entry needs a non-empty name and at least one target — an association without a target applies to nothing."
  }

  validation {
    condition = alltrue([
      for assoc in var.ssm_associations :
      can(regex("^(rate|cron)\\(.+\\)$", assoc.schedule_expression))
    ])
    error_message = "Each ssm_associations schedule_expression must be a rate(...) or cron(...) expression, for example rate(12 hours)."
  }

  validation {
    condition = alltrue(flatten([
      for assoc in var.ssm_associations : [
        for target in assoc.targets : target.key != "" && length(target.values) > 0
      ]
    ]))
    error_message = "Each ssm_associations target needs a non-empty key and at least one value."
  }
}

# --- S3 Object Lock ---

variable "enable_s3_object_lock" {
  description = "Enable S3 Object Lock on the central log bucket for WORM compliance retention. Must be enabled at bucket creation time — cannot be added to existing buckets."
  type        = bool
  default     = false
}

variable "s3_object_lock_config" {
  description = "S3 Object Lock configuration for the central log bucket. Only used when enable_s3_object_lock is true."
  type = object({
    retention_mode = optional(string, "GOVERNANCE")
    retention_days = optional(number, 365)
  })
  default = {}

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.s3_object_lock_config.retention_mode)
    error_message = "s3_object_lock_config.retention_mode must be GOVERNANCE or COMPLIANCE — these are the only valid S3 Object Lock retention modes."
  }

  validation {
    condition     = var.s3_object_lock_config.retention_days > 0
    error_message = "s3_object_lock_config.retention_days must be a positive integer (at least 1 day) for the S3 Object Lock retention period."
  }
}

# --- CloudTrail Lake ---

variable "enable_cloudtrail_lake" {
  description = "Enable CloudTrail Lake event data store for SQL-based event querying."
  type        = bool
  default     = false
}

variable "cloudtrail_lake_config" {
  description = "CloudTrail Lake configuration. Only used when enable_cloudtrail_lake is true. retention_days accepts 7 to 2555 days (about seven years)."
  type = object({
    retention_days       = optional(number, 2555)
    organization_enabled = optional(bool, true)
  })
  default = {}

  validation {
    condition     = var.cloudtrail_lake_config.retention_days >= 7 && var.cloudtrail_lake_config.retention_days <= 2555
    error_message = "cloudtrail_lake_config.retention_days must be between 7 and 2555 (about seven years) — this is the retention range the AWS provider accepts for an event data store."
  }
}

# --- VPC Flow Logs Dedicated S3 Bucket ---

variable "enable_vpc_flow_logs_bucket" {
  description = "Create a dedicated S3 bucket for VPC flow logs with replication to the central log bucket."
  type        = bool
  default     = false
}

variable "vpc_flow_logs_bucket_config" {
  description = "Configuration for the VPC flow logs dedicated bucket. Only used when enable_vpc_flow_logs_bucket is true."
  type = object({
    retention_days = optional(number, 365)
  })
  default = {}

  validation {
    condition     = var.vpc_flow_logs_bucket_config.retention_days > 0
    error_message = "vpc_flow_logs_bucket_config.retention_days must be a positive integer (at least 1 day) for the VPC flow logs bucket lifecycle retention."
  }
}

# --- Configurable S3 Lifecycle Rules ---

variable "central_log_bucket_lifecycle_rules" {
  description = "Lifecycle rules for the central log bucket. Each entry is one S3 rule with a filter, transitions into colder storage classes, an expiration and the handling of noncurrent versions. null keeps the rules the module derives from log_retention_days and s3_lifecycle_rules."
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
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every central_log_bucket_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.central_log_bucket_lifecycle_rules, [])))
    error_message = "Every id in central_log_bucket_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in central_log_bucket_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) : concat(
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
    error_message = "Every day value in central_log_bucket_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every central_log_bucket_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every central_log_bucket_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every central_log_bucket_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every central_log_bucket_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a central_log_bucket_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A central_log_bucket_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every central_log_bucket_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # The lifecycle must not delete a log object before the retention period
  # ends. The same bound as on the other lifecycle settings of the module,
  # applied per rule: a rule with a shorter expiration would silently lower
  # the retention period.
  validation {
    condition = (var.central_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.central_log_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || rule.expiration_days >= var.log_retention_days
    ]))
    error_message = "Every expiration_days in central_log_bucket_lifecycle_rules must be greater than or equal to log_retention_days — a shorter value expires the log objects before the required retention period ends."
  }
}

variable "access_logs_bucket_lifecycle_rules" {
  description = "Lifecycle rules for the separate access logs bucket. null keeps the single rule the module derives from log_retention_days."
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
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every access_logs_bucket_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.access_logs_bucket_lifecycle_rules, [])))
    error_message = "Every id in access_logs_bucket_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in access_logs_bucket_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) : concat(
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
    error_message = "Every day value in access_logs_bucket_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every access_logs_bucket_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every access_logs_bucket_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every access_logs_bucket_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every access_logs_bucket_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a access_logs_bucket_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A access_logs_bucket_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every access_logs_bucket_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_separate_access_logs_bucket, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.access_logs_bucket_lifecycle_rules == null || var.enable_separate_access_logs_bucket)
    error_message = "access_logs_bucket_lifecycle_rules is only read when enable_separate_access_logs_bucket is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
  # The lifecycle must not delete a log object before the retention period
  # ends. The same bound as on the other lifecycle settings of the module,
  # applied per rule: a rule with a shorter expiration would silently lower
  # the retention period.
  validation {
    condition = (var.access_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.access_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || rule.expiration_days >= var.log_retention_days
    ]))
    error_message = "Every expiration_days in access_logs_bucket_lifecycle_rules must be greater than or equal to log_retention_days — a shorter value expires the log objects before the required retention period ends."
  }
}

variable "elb_log_bucket_lifecycle_rules" {
  description = "Lifecycle rules for the load balancer log bucket. null keeps the single rule the module derives from elb_log_bucket_lifecycle."
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
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every elb_log_bucket_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.elb_log_bucket_lifecycle_rules, [])))
    error_message = "Every id in elb_log_bucket_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in elb_log_bucket_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) : concat(
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
    error_message = "Every day value in elb_log_bucket_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every elb_log_bucket_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every elb_log_bucket_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every elb_log_bucket_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every elb_log_bucket_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a elb_log_bucket_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A elb_log_bucket_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every elb_log_bucket_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_elb_log_bucket, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.elb_log_bucket_lifecycle_rules == null || var.enable_elb_log_bucket)
    error_message = "elb_log_bucket_lifecycle_rules is only read when enable_elb_log_bucket is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
  # The lifecycle must not delete a log object before the retention period
  # ends. The same bound as on the other lifecycle settings of the module,
  # applied per rule: a rule with a shorter expiration would silently lower
  # the retention period.
  validation {
    condition = (var.elb_log_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.elb_log_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || rule.expiration_days >= var.log_retention_days
    ]))
    error_message = "Every expiration_days in elb_log_bucket_lifecycle_rules must be greater than or equal to log_retention_days — a shorter value expires the log objects before the required retention period ends."
  }
}

variable "vpc_flow_logs_bucket_lifecycle_rules" {
  description = "Lifecycle rules for the dedicated VPC flow logs bucket. null keeps the single rule the module derives from vpc_flow_logs_bucket_config."
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
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) : trimspace(rule.id) != ""
    ]))
    error_message = "Every vpc_flow_logs_bucket_lifecycle_rules entry needs a non-empty id — the id names the rule in the plan and in the bucket configuration."
  }

  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || length(distinct([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) : rule.id
    ])) == length(coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, [])))
    error_message = "Every id in vpc_flow_logs_bucket_lifecycle_rules must be unique — S3 rejects a lifecycle configuration that carries the same rule id twice."
  }
  # S3 accepts only these storage classes as a transition target. A typo would
  # only surface at apply time, and the rule would have no effect until then.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) : [
        for transition in concat(rule.transitions, rule.noncurrent_version_transitions) :
        contains(["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], transition.storage_class)
      ]
    ])))
    error_message = "Every storage_class in vpc_flow_logs_bucket_lifecycle_rules must be one of STANDARD_IA, ONEZONE_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER, DEEP_ARCHIVE."
  }
  # Day values are whole days. S3 counts from the creation of the object; a
  # fraction of a day has no meaning.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) : concat(
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
    error_message = "Every day value in vpc_flow_logs_bucket_lifecycle_rules must be a whole number: transition days from 0, expiration and abort days from 1."
  }
  # The transitions of a rule must strictly ascend. S3 rejects two transitions
  # on the same day, and a later transition into a warmer class is not
  # archiving.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue(flatten([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) : [
        for list in [rule.transitions, rule.noncurrent_version_transitions] :
        length(list) < 2 || alltrue([
          for index in range(length(list) - 1) :
          list[index + 1].days > list[index].days
        ])
      ]
    ])))
    error_message = "The transitions of every vpc_flow_logs_bucket_lifecycle_rules entry must be ordered by ascending days — S3 rejects two transitions on the same day."
  }
  # An expiration before the last transition deletes the object before it
  # reaches the cold class: the transition then has no effect, and the saving
  # it is meant for never happens.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || length(rule.transitions) == 0 ||
      rule.expiration_days > max([for transition in rule.transitions : transition.days]...)
    ]))
    error_message = "expiration_days of every vpc_flow_logs_bucket_lifecycle_rules entry must be greater than the days of its last transition — otherwise the object expires before it reaches the storage class."
  }

  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) :
      rule.noncurrent_version_expiration_days == null || length(rule.noncurrent_version_transitions) == 0 ||
      rule.noncurrent_version_expiration_days > max([for transition in rule.noncurrent_version_transitions : transition.days]...)
    ]))
    error_message = "noncurrent_version_expiration_days of every vpc_flow_logs_bucket_lifecycle_rules entry must be greater than the days of its last noncurrent version transition."
  }
  # A filter selects by prefix or by tags. Both at once need the `and` block of
  # S3 and make a different rule than the one described here; the setting
  # would silently lose half of itself.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) :
      rule.prefix == null || rule.tags == null
    ]))
    error_message = "Every vpc_flow_logs_bucket_lifecycle_rules entry selects by prefix or by tags, never by both — set only one of the two."
  }

  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) :
      rule.tags == null || length(rule.tags) > 0
    ]))
    error_message = "tags of a vpc_flow_logs_bucket_lifecycle_rules entry must not be empty — leave the attribute unset to select the whole bucket."
  }
  # In the `expiration` block S3 takes either a day value or the clean-up of
  # expired delete markers, never both.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || (rule.expired_object_delete_marker != true)
    ]))
    error_message = "A vpc_flow_logs_bucket_lifecycle_rules entry sets expiration_days or expired_object_delete_marker, never both — S3 rejects the combination."
  }
  # A rule without an action shows in the plan and does nothing. S3 does not
  # reject it, but the setting misses its purpose.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days != null ||
      rule.expired_object_delete_marker != null ||
      rule.noncurrent_version_expiration_days != null ||
      rule.abort_incomplete_multipart_upload_days != null ||
      length(rule.transitions) > 0 ||
      length(rule.noncurrent_version_transitions) > 0
    ]))
    error_message = "Every vpc_flow_logs_bucket_lifecycle_rules entry needs at least one action: an expiration, a transition, a noncurrent version setting or an abort of incomplete uploads."
  }
  # A rule set without its bucket has no reader: the bucket only exists with
  # enable_vpc_flow_logs_bucket, and without the bucket there is no lifecycle
  # the rules could describe.
  validation {
    condition     = (var.vpc_flow_logs_bucket_lifecycle_rules == null || var.enable_vpc_flow_logs_bucket)
    error_message = "vpc_flow_logs_bucket_lifecycle_rules is only read when enable_vpc_flow_logs_bucket is set — without the bucket there is no lifecycle configuration the rules could describe."
  }
  # The lifecycle must not delete a log object before the retention period
  # ends. The same bound as on the other lifecycle settings of the module,
  # applied per rule: a rule with a shorter expiration would silently lower
  # the retention period.
  validation {
    condition = (var.vpc_flow_logs_bucket_lifecycle_rules == null || alltrue([
      for rule in coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, []) :
      rule.expiration_days == null || rule.expiration_days >= var.log_retention_days
    ]))
    error_message = "Every expiration_days in vpc_flow_logs_bucket_lifecycle_rules must be greater than or equal to log_retention_days — a shorter value expires the log objects before the required retention period ends."
  }
}

# --- Bucket and KMS Policy Attachments and Overrides ---
#
# Three inputs of one shape, one per log bucket. Every document is a JSON
# string that the configuration layer reads from a file (the pattern of the
# other policies under configurations/policies/); the module itself reads no
# file. Attachments append their statements to the policy the module
# generates, in list order — the merge is deterministic. An override replaces
# the generated policy entirely and therefore requires the explicit
# confirmation switch allow_bucket_policy_overrides: a full replacement can
# remove the delivery permissions and the transport encryption requirement of
# a log bucket, and a mixed-up field must not do that silently.

variable "guardduty_export_prefix" {
  description = "S3 prefix of the GuardDuty PutObject grant in the central log bucket policy. Must carry the same value as the security module's guardduty_export_prefix — the publishing destination writes where this grant allows."
  type        = string
  default     = "guardduty/"

  validation {
    condition     = var.guardduty_export_prefix == "" || !startswith(var.guardduty_export_prefix, "/")
    error_message = "guardduty_export_prefix must not start with a slash — S3 keys are relative and a leading slash creates an empty path segment."
  }
}

variable "finding_export_source_account_ids" {
  description = "Account ids, besides the deploying account, whose GuardDuty publishing destination and Macie classification export write to the central log bucket — the Audit account when the finding consumers run there. Each id joins the aws:SourceAccount condition of the GuardDuty and Macie grants on the bucket policy and the Macie statement of the bucket key. Empty keeps the deploying account alone and the generated documents unchanged."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for id in var.finding_export_source_account_ids : can(regex("^[0-9]{12}$", id))
    ])
    error_message = "Every finding_export_source_account_ids entry must be a 12-digit AWS account id — the id becomes an aws:SourceAccount condition value of the export grants."
  }

  validation {
    condition     = length(distinct(var.finding_export_source_account_ids)) == length(var.finding_export_source_account_ids)
    error_message = "finding_export_source_account_ids must not contain duplicates."
  }
}

variable "guardduty_root_export_cleanup" {
  description = "Remediation of GuardDuty findings that a broken-export workaround wrote to the central log bucket root (AWSLogs/... instead of guardduty/AWSLogs/...). One lifecycle rule per detector account expires current and noncurrent versions under AWSLogs/<account-id>/GuardDuty/ after retention_days. The /GuardDuty/ path segment is pinned in the literal prefix, so keys of any other writer cannot match — CloudTrail writes AWSLogs/<account>/CloudTrail/..., never a GuardDuty segment. An empty account_ids reads the deploying account, whose detector exported the findings. null sets no rule; remove the variable once the root objects are gone and the rules disappear with it."
  type = object({
    retention_days = number
    account_ids    = optional(list(string), [])
  })
  default = null

  # Expiration counts from object creation, so a retention shorter than the
  # objects' age expires them at the next lifecycle evaluation — that is the
  # point of the remediation. The findings under guardduty/ keep their own
  # retention (security module, guardduty_lifecycle_rules); this value is an
  # independent decision with the same floor.
  validation {
    condition = (var.guardduty_root_export_cleanup == null || (
      var.guardduty_root_export_cleanup.retention_days >= 1 &&
      floor(var.guardduty_root_export_cleanup.retention_days) == var.guardduty_root_export_cleanup.retention_days
    ))
    error_message = "guardduty_root_export_cleanup.retention_days must be a whole number of days, at least 1 — set the whole object to null to skip the cleanup rules."
  }

  # The account id becomes a literal S3 key prefix segment; a malformed id
  # builds a rule that silently matches nothing.
  validation {
    condition = (var.guardduty_root_export_cleanup == null || alltrue([
      for id in coalesce(var.guardduty_root_export_cleanup.account_ids, []) : can(regex("^[0-9]{12}$", id))
    ]))
    error_message = "Every guardduty_root_export_cleanup.account_ids entry must be a 12-digit AWS account id — the id becomes the AWSLogs/<account-id>/GuardDuty/ prefix of one lifecycle rule."
  }

  # Each account id names one rule; S3 rejects a lifecycle configuration that
  # carries the same rule id twice.
  validation {
    condition     = (var.guardduty_root_export_cleanup == null || length(distinct(coalesce(var.guardduty_root_export_cleanup.account_ids, []))) == length(coalesce(var.guardduty_root_export_cleanup.account_ids, [])))
    error_message = "guardduty_root_export_cleanup.account_ids must not contain duplicates — each id names one lifecycle rule and S3 rejects duplicate rule ids."
  }
}

variable "central_log_bucket_policies" {
  description = "Additional and overriding policies of the central log bucket and its KMS key. s3_attachments/kms_attachments append their statements to the generated documents in list order; s3_override/kms_override replace them entirely and require allow_bucket_policy_overrides. Each document is a JSON string. {} keeps the generated policies."
  type = object({
    s3_attachments  = optional(list(string), [])
    s3_override     = optional(string, null)
    kms_attachments = optional(list(string), [])
    kms_override    = optional(string, null)
  })
  default = {}

  # A document that does not decode would only fail at apply time; the plan
  # catches it here.
  validation {
    condition = alltrue([
      for doc in concat(
        var.central_log_bucket_policies.s3_attachments,
        var.central_log_bucket_policies.kms_attachments,
        var.central_log_bucket_policies.s3_override != null ? [var.central_log_bucket_policies.s3_override] : [],
        var.central_log_bucket_policies.kms_override != null ? [var.central_log_bucket_policies.kms_override] : [],
      ) : can(jsondecode(doc))
    ])
    error_message = "Every central_log_bucket_policies document must be a JSON-decodable policy document."
  }

  # Version and Statement as a list: the attachments are merged via concat, so
  # a Statement that is not a list would break the merge; requiring the same
  # form of the overrides keeps one document contract.
  validation {
    condition = alltrue([
      for doc in concat(
        var.central_log_bucket_policies.s3_attachments,
        var.central_log_bucket_policies.kms_attachments,
        var.central_log_bucket_policies.s3_override != null ? [var.central_log_bucket_policies.s3_override] : [],
        var.central_log_bucket_policies.kms_override != null ? [var.central_log_bucket_policies.kms_override] : [],
      ) :
      can(jsondecode(doc).Version) && can(concat(jsondecode(doc).Statement, []))
    ])
    error_message = "Every central_log_bucket_policies document needs the field Version and a Statement list — without them it is no policy document, and a non-list Statement cannot be merged."
  }

  # The override replaces the entire generated policy, including the
  # CloudTrail/Config delivery statements and the transport encryption
  # requirement. The second switch makes that an explicit decision instead of
  # a mixed-up field.
  validation {
    condition = (
      (var.central_log_bucket_policies.s3_override == null && var.central_log_bucket_policies.kms_override == null) ||
      var.allow_bucket_policy_overrides
    )
    error_message = "central_log_bucket_policies overrides require allow_bucket_policy_overrides = true — a full replacement removes the generated delivery and encryption statements and must be confirmed explicitly."
  }
}

variable "access_logs_bucket_policies" {
  description = "Additional and overriding policy of the separate access logs bucket. s3_attachments append their statements to the generated document in list order; s3_override replaces it entirely and requires allow_bucket_policy_overrides. Each document is a JSON string. Requires enable_separate_access_logs_bucket. {} keeps the generated policy."
  type = object({
    s3_attachments = optional(list(string), [])
    s3_override    = optional(string, null)
  })
  default = {}

  validation {
    condition = alltrue([
      for doc in concat(
        var.access_logs_bucket_policies.s3_attachments,
        var.access_logs_bucket_policies.s3_override != null ? [var.access_logs_bucket_policies.s3_override] : [],
      ) : can(jsondecode(doc))
    ])
    error_message = "Every access_logs_bucket_policies document must be a JSON-decodable policy document."
  }

  validation {
    condition = alltrue([
      for doc in concat(
        var.access_logs_bucket_policies.s3_attachments,
        var.access_logs_bucket_policies.s3_override != null ? [var.access_logs_bucket_policies.s3_override] : [],
      ) :
      can(jsondecode(doc).Version) && can(concat(jsondecode(doc).Statement, []))
    ])
    error_message = "Every access_logs_bucket_policies document needs the field Version and a Statement list — without them it is no policy document, and a non-list Statement cannot be merged."
  }

  validation {
    condition = (
      var.access_logs_bucket_policies.s3_override == null ||
      var.allow_bucket_policy_overrides
    )
    error_message = "access_logs_bucket_policies.s3_override requires allow_bucket_policy_overrides = true — a full replacement removes the generated delivery and encryption statements and must be confirmed explicitly."
  }

  # Without the bucket there is no policy the documents could reach; a silent
  # no-op would hide a configuration mistake.
  validation {
    condition = (
      var.enable_separate_access_logs_bucket ||
      (length(var.access_logs_bucket_policies.s3_attachments) == 0 && var.access_logs_bucket_policies.s3_override == null)
    )
    error_message = "access_logs_bucket_policies requires enable_separate_access_logs_bucket = true — without the bucket the documents would silently do nothing."
  }
}

variable "elb_log_bucket_policies" {
  description = "Additional and overriding policy of the load balancer log bucket. s3_attachments append their statements to the generated document in list order; s3_override replaces it entirely and requires allow_bucket_policy_overrides. Each document is a JSON string. Requires enable_elb_log_bucket. {} keeps the generated policy."
  type = object({
    s3_attachments = optional(list(string), [])
    s3_override    = optional(string, null)
  })
  default = {}

  validation {
    condition = alltrue([
      for doc in concat(
        var.elb_log_bucket_policies.s3_attachments,
        var.elb_log_bucket_policies.s3_override != null ? [var.elb_log_bucket_policies.s3_override] : [],
      ) : can(jsondecode(doc))
    ])
    error_message = "Every elb_log_bucket_policies document must be a JSON-decodable policy document."
  }

  validation {
    condition = alltrue([
      for doc in concat(
        var.elb_log_bucket_policies.s3_attachments,
        var.elb_log_bucket_policies.s3_override != null ? [var.elb_log_bucket_policies.s3_override] : [],
      ) :
      can(jsondecode(doc).Version) && can(concat(jsondecode(doc).Statement, []))
    ])
    error_message = "Every elb_log_bucket_policies document needs the field Version and a Statement list — without them it is no policy document, and a non-list Statement cannot be merged."
  }

  validation {
    condition = (
      var.elb_log_bucket_policies.s3_override == null ||
      var.allow_bucket_policy_overrides
    )
    error_message = "elb_log_bucket_policies.s3_override requires allow_bucket_policy_overrides = true — a full replacement removes the generated delivery and encryption statements and must be confirmed explicitly."
  }

  validation {
    condition = (
      var.enable_elb_log_bucket ||
      (length(var.elb_log_bucket_policies.s3_attachments) == 0 && var.elb_log_bucket_policies.s3_override == null)
    )
    error_message = "elb_log_bucket_policies requires enable_elb_log_bucket = true — without the bucket the documents would silently do nothing."
  }
}

variable "allow_bucket_policy_overrides" {
  description = "Explicit confirmation that the *_override documents of the bucket policy inputs are intended. An override replaces the entire generated policy of a log bucket or its KMS key, including delivery permissions and the transport encryption requirement — this switch keeps a mixed-up field from doing that silently."
  type        = bool
  default     = false
}

# --- Bucket namespace: the leading segment of every DERIVED bucket name ---
#
# The five buckets this module can create derive their names from the account
# and region: <prefix>central-logs-<log-archive>-<region>,
# <prefix>central-logs-replica-<log-archive>-<destination-region>,
# <prefix>access-logs-<log-archive>-<region>, <prefix>elb-logs-<account>-<region>
# and <prefix>vpc-flow-logs-<account>-<region>. Because the names are derived,
# no per-bucket name variable could carry the production value as a static
# default — but the prefix can: "tlz-" reproduces every name exactly, so a live
# plan of an existing deployment stays empty. A live apply-test sets
# "tlz-l4test-" and moves the WHOLE family aside at once, including the buckets
# it switches off, so a test that later enables one of them is scoped already. One
# knob for the family is also one thing to assert: a run that sets it can
# check every bucket it creates against the same prefix.
#
# An adoption variable (adopted_*_bucket_name, below) names an EXISTING bucket
# and wins over the derived name, prefix included — the two do different jobs
# and do not compete. The prefix is pinned to the tlz- namespace; the adoption
# variables are deliberately not (taking over a legacy lza-* bucket is their
# purpose).

variable "bucket_name_prefix" {
  description = "Leading segment of every bucket name this module derives (the central log bucket, its replica, the access-logs, ELB-log and VPC-flow-log buckets), hyphen included: <prefix>central-logs-<log-archive>-<region> and so on. The default tlz- reproduces the production bucket names, so a changed value replaces every live bucket of the deployment; leave it in production. A live apply-test sets tlz-l4test- to keep its buckets disjoint from the deployed ones — S3 names are global, and CreateBucket on a name the account already owns does not fail at the S3 API in us-east-1 (the loud BucketAlreadyExists there is a provider-side pre-check, not a service guarantee), so the test's safety must come from the name, not from where it runs. Must start with tlz- (ProtectS3Buckets in configurations/policies/organization/tlz-core-guardrails-2.json denies DeleteBucket, PutBucketPolicy and the other mutations only for arn:*:s3:::tlz-*), must end with a hyphen so the derived name keeps its segment boundary, and may be at most 15 characters so the longest derived name (the replica in a 14-character region) stays within the 63-character S3 limit. An adopted_*_bucket_name names an existing bucket and wins over the derived name regardless of this prefix."
  type        = string
  default     = "tlz-"

  validation {
    condition = (
      can(regex("^[a-z0-9]+(-[a-z0-9]+)*-$", var.bucket_name_prefix))
      && startswith(var.bucket_name_prefix, "tlz-")
      && length(var.bucket_name_prefix) <= 15
    )
    error_message = "bucket_name_prefix must start with 'tlz-', consist of lowercase letters, digits and single hyphens, END with a hyphen (it is the leading segment of a derived name: tlz-l4test- yields tlz-l4test-central-logs-<account>-<region>) and be at most 15 characters (63-character S3 limit minus the longest derived remainder, central-logs-replica-<12-digit account>-<14-character region>). The namespace is not cosmetic: the ProtectS3Buckets statement in configurations/policies/organization/tlz-core-guardrails-2.json DENIES DeleteBucket, DeleteBucketPolicy, PutBucketPolicy, PutBucketVersioning, PutEncryptionConfiguration, PutLifecycleConfiguration and PutReplicationConfiguration only for arn:*:s3:::tlz-*, so a bucket named outside that prefix silently loses its guardrail protection. This validation is the only enforcement of the pin."
  }
}

# --- Resource adoption: names of existing buckets this deployment takes over ---
#
# Empty keeps the derived name of each bucket, so existing deployments keep
# their plan. A non-empty value names an existing bucket that an adoption
# entry (configurations/base/resource-adoptions.json) imports into this
# module's bucket resource; the companion resources (encryption, versioning,
# public access block, bucket policy) then capture the adopted bucket and any
# deviation from the declared posture shows in the plan. See
# docs/resource-adoption.md.

variable "adopted_central_log_bucket_name" {
  description = "Name of an existing bucket to run as the central log bucket. Empty derives tlz-central-logs-<log-archive-account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket"
  type        = string
  default     = ""

  validation {
    condition = (
      var.adopted_central_log_bucket_name == "" ||
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.adopted_central_log_bucket_name))
    )
    error_message = "adopted_central_log_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

variable "adopted_access_logs_bucket_name" {
  description = "Name of an existing bucket to run as the separate access logs bucket. Empty derives tlz-access-logs-<log-archive-account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket"
  type        = string
  default     = ""

  validation {
    condition = (
      var.adopted_access_logs_bucket_name == "" ||
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.adopted_access_logs_bucket_name))
    )
    error_message = "adopted_access_logs_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

variable "adopted_elb_log_bucket_name" {
  description = "Name of an existing bucket to run as the ELB log bucket. Empty derives tlz-elb-logs-<account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket"
  type        = string
  default     = ""

  validation {
    condition = (
      var.adopted_elb_log_bucket_name == "" ||
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.adopted_elb_log_bucket_name))
    )
    error_message = "adopted_elb_log_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

variable "adopted_vpc_flow_logs_bucket_name" {
  description = "Name of an existing bucket to run as the VPC flow logs bucket. Empty derives tlz-vpc-flow-logs-<account>-<region>; a value is meant to be paired with an adoption entry that imports the bucket. Deliberately NOT pinned to the tlz- namespace, unlike names of buckets this module creates: adopting a legacy bucket (an lza-* one, say) is the whole point of the option. Be aware of the consequence — the ProtectS3Buckets statement in configurations/policies/organization/tlz-core-guardrails-2.json denies DeleteBucket, DeleteBucketPolicy and PutBucketLogging only for arn:*:s3:::tlz-*, so an adopted bucket outside that prefix is not covered by that guardrail. The same is true of the three sibling adopted_*_bucket_name options, which predate this one."
  type        = string
  default     = ""

  validation {
    condition = (
      var.adopted_vpc_flow_logs_bucket_name == "" ||
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.adopted_vpc_flow_logs_bucket_name))
    )
    error_message = "adopted_vpc_flow_logs_bucket_name must be empty or a valid S3 bucket name (3-63 lowercase characters, digits, dot or hyphen, starting and ending alphanumeric)."
  }
}

variable "lambda_environment_kms_key_arn" {
  type        = string
  default     = ""
  description = "Customer-managed KMS key that encrypts the environment variables of this module's Lambda function (the Firehose decompression processor). Empty — the default — leaves the variables encrypted with the AWS-managed Lambda key, the module default: the plan is unchanged for anyone who does not set it. When set, the key ARN reaches the function AND the module grants the function's execution role kms:Decrypt on exactly that key, because without it the function cannot read its own variables at cold start and every invocation fails. A customer-managed key carries a monthly charge; the AWS-managed key does not. The deploying identity additionally needs kms:Encrypt on the key at apply time — that grant lives in the key policy, outside this module."

  validation {
    condition     = var.lambda_environment_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.lambda_environment_kms_key_arn))
    error_message = "lambda_environment_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}
