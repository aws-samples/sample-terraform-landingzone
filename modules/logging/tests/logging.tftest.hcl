# =============================================================================
# Logging Module Tests (modules/logging)
# =============================================================================
# Coverage (four mandatory scenarios):
#   1. Toggle-Off      — all enable_* toggles false -> zero optional resources
#   2. Default         — minimal valid input, default values
#   3. Custom          — user-defined configuration with realistic values
#   4. Validation      — invalid input rejected via expect_failures
#
# The module has no single module-level toggle. All seven feature toggles are
# covered by the Toggle-Off scenario:
#   enable_elb_log_bucket, enable_separate_access_logs_bucket,
#   enable_per_account_kms_keys, enable_cloudwatch_log_data_protection,
#   enable_s3_object_lock, enable_cloudtrail_lake, enable_vpc_flow_logs_bucket
# Two further feature switches are value-driven rather than boolean and are
# covered as well: s3_replication_config (destination_region) and
# cloudwatch_log_subscriptions (Kinesis pipeline).
#
# Providers used by the module: aws (single unaliased provider, no
# configuration_aliases), archive (hashicorp/archive for the Firehose
# record-processor Lambda package) and time (hashicorp/time for the bounded IAM
# propagation barriers in front of the resources whose role permissions AWS
# validates during the create call).

mock_provider "archive" {}

mock_provider "time" {}

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111111111111"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }
}

variables {
  log_archive_account_id = "210987654321"
  organization_id        = "o-abcd1234567"
}

# -----------------------------------------------------------------------------
# 1. Toggle-Off — every optional feature disabled
# -----------------------------------------------------------------------------

run "logging_all_toggles_off" {
  command = plan

  variables {
    enable_elb_log_bucket                 = false
    enable_separate_access_logs_bucket    = false
    enable_per_account_kms_keys           = false
    enable_cloudwatch_log_data_protection = false
    enable_s3_object_lock                 = false
    enable_cloudtrail_lake                = false
    enable_vpc_flow_logs_bucket           = false
    s3_replication_config                 = {}
    cloudwatch_log_subscriptions          = []
    cloudtrail_account_trails             = []
    ssm_associations                      = []
    cloudtrail_sns_topic_name             = ""
    cloudwatch_log_group_retention        = null
  }

  assert {
    condition     = length(aws_s3_bucket.elb_logs) == 0
    error_message = "No ELB log bucket must be created when enable_elb_log_bucket is false."
  }

  assert {
    condition     = length(aws_s3_bucket.access_logs) == 0
    error_message = "No separate access logs bucket must be created when enable_separate_access_logs_bucket is false."
  }

  assert {
    condition     = length(aws_kms_key.per_account_s3) == 0
    error_message = "No per-account KMS key must be created when enable_per_account_kms_keys is false."
  }

  assert {
    condition     = length(aws_kms_alias.per_account_s3) == 0
    error_message = "No per-account KMS alias must be created when enable_per_account_kms_keys is false."
  }

  assert {
    condition     = length(aws_cloudwatch_log_data_protection_policy.cloudtrail) == 0
    error_message = "No CloudTrail data protection policy must be created when enable_cloudwatch_log_data_protection is false."
  }

  assert {
    condition     = length(aws_cloudwatch_log_data_protection_policy.additional) == 0
    error_message = "No additional data protection policies must be created when enable_cloudwatch_log_data_protection is false."
  }

  assert {
    condition     = length(aws_s3_bucket_object_lock_configuration.central_logs) == 0
    error_message = "No Object Lock configuration must be created when enable_s3_object_lock is false."
  }

  assert {
    condition     = length(aws_cloudtrail_event_data_store.this) == 0
    error_message = "No CloudTrail Lake event data store must be created when enable_cloudtrail_lake is false."
  }

  assert {
    condition     = length(aws_s3_bucket.vpc_flow_logs) == 0
    error_message = "No VPC flow logs bucket must be created when enable_vpc_flow_logs_bucket is false."
  }

  assert {
    condition     = length(aws_s3_bucket_replication_configuration.central_logs) == 0
    error_message = "No replication configuration must be created when s3_replication_config is empty."
  }

  assert {
    condition     = length(aws_iam_role.replication) == 0
    error_message = "No replication role must be created when replication is disabled."
  }

  assert {
    condition     = length(aws_kinesis_stream.cw_to_s3) == 0
    error_message = "No Kinesis stream must be created without CloudWatch log subscriptions."
  }

  assert {
    condition     = length(aws_kinesis_firehose_delivery_stream.cw_to_s3) == 0
    error_message = "No Firehose delivery stream must be created without CloudWatch log subscriptions."
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 0
    error_message = "No subscription filters must be created when cloudwatch_log_subscriptions is empty."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.cloudtrail) == 0
    error_message = "No CloudWatch Log Group must be created when cloudwatch_log_group_retention is null."
  }

  assert {
    condition     = length(aws_sns_topic.cloudtrail) == 0
    error_message = "No SNS topic must be created when cloudtrail_sns_topic_name is empty."
  }

  assert {
    condition     = length(aws_cloudtrail.account_trails) == 0
    error_message = "No account trails must be created when cloudtrail_account_trails is empty."
  }

  assert {
    condition     = length(aws_ssm_association.this) == 0
    error_message = "No SSM associations must be created when ssm_associations is empty."
  }

  assert {
    condition     = output.elb_log_bucket_name == "" && output.access_logs_bucket_name == ""
    error_message = "Optional bucket outputs must be empty when the corresponding toggles are off."
  }

  assert {
    condition     = output.cloudtrail_lake_event_data_store_arn == "" && output.vpc_flow_logs_bucket_arn == ""
    error_message = "Optional feature outputs must be empty when the corresponding toggles are off."
  }

  # The three resources that local.replication_enabled governs.
  assert {
    condition     = length(aws_s3_bucket_replication_configuration.central_logs) == 0 && length(aws_s3_bucket.replication_dest) == 0 && length(aws_iam_role.replication) == 0
    error_message = "No replication resources must be created when replication is disabled."
  }

  assert {
    condition     = output.per_account_s3_kms_key_arn == "" && output.kinesis_stream_arn == ""
    error_message = "Optional feature outputs must be empty when the corresponding toggles are off."
  }
}

# -----------------------------------------------------------------------------
# 2. Default configuration — base resources with default values
# -----------------------------------------------------------------------------

run "logging_default_config" {
  command = plan

  assert {
    condition     = aws_s3_bucket.central_logs.bucket == "tlz-central-logs-210987654321-eu-central-1"
    error_message = "Central log bucket name must follow the tlz-central-logs-<log-archive-account>-<region> convention."
  }

  assert {
    condition     = aws_s3_bucket.central_logs.object_lock_enabled == false
    error_message = "Object Lock must be disabled on the central bucket by default."
  }

  assert {
    condition     = aws_cloudtrail.org_trail.is_organization_trail == true
    error_message = "The org trail must be an organization trail."
  }

  assert {
    condition     = aws_cloudtrail.org_trail.is_multi_region_trail == true
    error_message = "The org trail must be multi-region."
  }

  assert {
    condition     = aws_cloudtrail.org_trail.enable_log_file_validation == true
    error_message = "The org trail must have log file validation enabled."
  }

  assert {
    condition     = aws_config_configuration_recorder.this[0].name == "tlz-config-recorder"
    error_message = "Config recorder name must match the module convention."
  }

  assert {
    condition     = can(regex("AWSServiceRoleForConfig$", aws_config_configuration_recorder.this[0].role_arn))
    error_message = "Config recorder must use the service-linked role by default."
  }

  assert {
    condition     = output.log_retention_days == 365
    error_message = "Default log_retention_days must be 365."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.cloudtrail) == 0
    error_message = "No CloudWatch Log Group must be created by default."
  }

  assert {
    condition     = output.cloudtrail_s3_data_events == true && output.cloudtrail_lambda_data_events == true
    error_message = "S3 and Lambda data events must be enabled by default."
  }

  assert {
    condition     = length(output.cloudtrail_insights) == 0
    error_message = "No CloudTrail Insights must be enabled by default."
  }

  assert {
    condition     = output.s3_lifecycle_rules == null
    error_message = "s3_lifecycle_rules must default to null (single-rule behavior)."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.central_logs.block_public_acls,
      aws_s3_bucket_public_access_block.central_logs.block_public_policy,
      aws_s3_bucket_public_access_block.central_logs.ignore_public_acls,
      aws_s3_bucket_public_access_block.central_logs.restrict_public_buckets,
    ])
    error_message = "All public access block settings of the central log bucket must be enabled."
  }

  assert {
    condition     = aws_s3_bucket_logging.central_logs.target_prefix == "s3-access-logs/"
    error_message = "Access logs of the central bucket must be written to the s3-access-logs/ prefix."
  }

  assert {
    condition     = aws_kms_key.log_bucket.enable_key_rotation == true
    error_message = "The log bucket KMS key must have rotation enabled."
  }

  assert {
    condition     = aws_kms_alias.management.name == "alias/tlz/management/kms"
    error_message = "Management KMS alias must match the module convention."
  }

  assert {
    condition     = aws_kms_alias.cloudwatch.name == "alias/tlz/cloudwatch/kms"
    error_message = "CloudWatch KMS alias must match the module convention."
  }
}

# -----------------------------------------------------------------------------
# 2b. Default configuration — the central bucket's encryption at rest
# -----------------------------------------------------------------------------
# No other run of this file notices a missing
# aws_s3_bucket_server_side_encryption_configuration.central_logs. This run reads the
# planned encryption configuration and pins the property, not the text: the
# default encryption of the central log bucket is SSE-KMS and names the
# module's own customer-managed key — neither absent, nor SSE-S3, nor the
# AWS-managed aws/s3 key that an aws:kms rule without a key id falls back to.
#
# The key ARN is computed, so it is pinned for the plan the way the other
# plan-time runs of this file pin computed ARNs. The assertion compares the
# rule's key id against the key resource, not against that literal.
run "logging_central_bucket_encryption_names_the_customer_managed_key" {
  command = plan

  override_resource {
    target          = aws_kms_key.log_bucket
    override_during = plan
    values = {
      arn = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000"
    }
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.central_logs.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "The central log bucket's default encryption must be SSE-KMS (aws:kms) — not SSE-S3 (AES256) and not absent."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.central_logs.rule).apply_server_side_encryption_by_default).kms_master_key_id == aws_kms_key.log_bucket.arn
    error_message = "The central log bucket's default encryption must name the module's customer-managed key aws_kms_key.log_bucket — an aws:kms rule without a key id falls back to the AWS-managed aws/s3 key."
  }
}

# -----------------------------------------------------------------------------
# 2c. VPC flow logs and other vended logs can be delivered
# -----------------------------------------------------------------------------
# VPC flow logs to S3 are written by delivery.logs. Unless both the log bucket
# key and the central bucket policy name that principal, delivery into the
# SSE-KMS central bucket (and the dedicated flow log bucket, which uses the
# same key) fails. Both grants are scoped to this account.
run "regression_log_delivery_is_granted_on_key_and_central_bucket" {
  command = plan

  # The bucket ARN is computed; pinned for the plan like the key ARN above.
  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    }
  }

  assert {
    condition = anytrue([
      for s in local.log_bucket_kms_policy.Statement :
      s.Sid == "AllowLogDeliveryEncrypt"
      && s.Principal.Service == "delivery.logs.amazonaws.com"
      && contains(s.Action, "kms:GenerateDataKey*")
      && s.Condition.StringEquals["aws:SourceAccount"] == "111111111111"
      && s.Condition.ArnLike["aws:SourceArn"] == "arn:aws:logs:eu-central-1:111111111111:*"
    ])
    error_message = "The log bucket key must let delivery.logs generate data keys for this account's log deliveries only."
  }

  assert {
    condition = anytrue([
      for s in local.central_log_bucket_base_policy.Statement :
      s.Sid == "AWSLogDeliveryWrite"
      && s.Principal.Service == "delivery.logs.amazonaws.com"
      && s.Action == "s3:PutObject"
      && s.Condition.StringEquals["aws:SourceAccount"] == "111111111111"
      && s.Condition.StringEquals["s3:x-amz-acl"] == "bucket-owner-full-control"
      && s.Condition.ArnLike["aws:SourceArn"] == "arn:aws:logs:eu-central-1:111111111111:*"
      && alltrue([for r in s.Resource : strcontains(r, "AWSLogs/") && strcontains(r, "111111111111/*")])
    ])
    error_message = "The central bucket policy must let delivery.logs write under AWSLogs/<this account>/ only, for this account's log deliveries."
  }

  assert {
    condition = anytrue([
      for s in local.central_log_bucket_base_policy.Statement :
      s.Sid == "AWSLogDeliveryAclCheck"
      && s.Principal.Service == "delivery.logs.amazonaws.com"
      && s.Condition.StringEquals["aws:SourceAccount"] == "111111111111"
    ])
    error_message = "The central bucket policy must let delivery.logs read the bucket ACL for this account's log deliveries."
  }
}

# -----------------------------------------------------------------------------
# 2d. The ELB log bucket uses the encryption ALB logging supports
# -----------------------------------------------------------------------------
# Application Load Balancer access logs support only SSE-S3 on the target
# bucket; with SSE-KMS and the log key every delivery into it fails.
run "regression_elb_log_bucket_uses_sse_s3" {
  command = plan

  variables {
    enable_elb_log_bucket = true
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.elb_logs[0].rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "The ELB log bucket must be encrypted with SSE-S3 (AES256): ALB access logs refuse an SSE-KMS bucket."
  }
}

# -----------------------------------------------------------------------------
# 3. Custom configuration — optional features enabled with realistic values
# -----------------------------------------------------------------------------

run "logging_custom_config" {
  command = plan

  variables {
    force_destroy                  = true
    log_retention_days             = 730
    cloudwatch_log_group_retention = 90
    cloudtrail_insights            = ["ApiCallRateInsight", "ApiErrorRateInsight"]
    cloudtrail_sns_topic_name      = "tlz-cloudtrail-notifications"
    kms_key_administrators         = ["arn:aws:iam::111111111111:role/AdminRole"]

    enable_elb_log_bucket = true
    # retention_days equals log_retention_days = 730: a shorter value would
    # delete the ELB access logs before the retention period ends, and the
    # validation of elb_log_bucket_lifecycle rejects that. The scenario is
    # about the Glacier transition.
    elb_log_bucket_lifecycle = {
      retention_days          = 730
      glacier_transition_days = 30
    }

    enable_separate_access_logs_bucket = true
    enable_per_account_kms_keys        = true

    enable_s3_object_lock = true
    s3_object_lock_config = {
      retention_mode = "COMPLIANCE"
      retention_days = 1095
    }

    enable_cloudtrail_lake = true
    cloudtrail_lake_config = {
      retention_days       = 1095
      organization_enabled = true
    }

    enable_vpc_flow_logs_bucket = true
    vpc_flow_logs_bucket_config = {
      retention_days = 90
    }

    enable_cloudwatch_log_data_protection      = true
    cloudwatch_log_data_protection_log_groups  = ["/aws/lambda/tlz-custom"]
    cloudwatch_log_data_protection_identifiers = ["EmailAddress", "IpAddress"]

    # Three different retention periods per prefix — that is what the scenario
    # covers. access_logs is 730, the shortest value the retention guard
    # allows against log_retention_days = 730: a rule may not expire log
    # objects before the retention period is over.
    s3_lifecycle_rules = {
      cloudtrail = {
        retention_days          = 2557
        glacier_transition_days = 90
      }
      config = {
        retention_days = 1095
      }
      access_logs = {
        retention_days = 730
      }
    }

    s3_replication_config = {
      destination_region = "eu-west-1"
      rules = [
        {
          id       = "replicate-cloudtrail"
          prefix   = "cloudtrail/"
          status   = "Enabled"
          priority = 1
        }
      ]
    }

    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/tlz-org-trail"
        filter_pattern = ""
      },
      {
        name           = "excluded-subscription"
        log_group_name = "/aws/lambda/noisy"
        filter_pattern = ""
      },
    ]
    cloudwatch_log_exclusions = ["/aws/lambda/noisy"]

    cloudtrail_account_trails = [
      {
        name          = "tlz-account-trail"
        s3_key_prefix = "account-trail"
      }
    ]

    ssm_associations = [
      {
        name                = "AWS-GatherSoftwareInventory"
        schedule_expression = "rate(12 hours)"
        targets = [
          {
            key    = "InstanceIds"
            values = ["*"]
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_s3_bucket.elb_logs) == 1
    error_message = "ELB log bucket must be created when enable_elb_log_bucket is true."
  }

  assert {
    condition     = length(aws_s3_bucket.access_logs) == 1
    error_message = "Separate access logs bucket must be created when the toggle is true."
  }

  assert {
    condition     = aws_s3_bucket.access_logs[0].bucket == "tlz-access-logs-210987654321-eu-central-1"
    error_message = "Separate access logs bucket name must follow the tlz-access-logs-<log-archive-account>-<region> convention."
  }

  assert {
    condition     = length(aws_kms_key.per_account_s3) == 1 && length(aws_kms_alias.per_account_s3) == 1
    error_message = "Per-account KMS key and alias must be created when the toggle is true."
  }

  assert {
    condition     = aws_kms_alias.per_account_s3[0].name == "alias/tlz/s3/kms"
    error_message = "Per-account S3 KMS alias must match the module convention."
  }

  assert {
    condition     = length(aws_s3_bucket_object_lock_configuration.central_logs) == 1
    error_message = "Object Lock configuration must be created when enable_s3_object_lock is true."
  }

  assert {
    condition     = aws_s3_bucket.central_logs.object_lock_enabled == true
    error_message = "Central bucket must have object_lock_enabled when the toggle is true."
  }

  assert {
    condition     = length(aws_cloudtrail_event_data_store.this) == 1
    error_message = "CloudTrail Lake event data store must be created when enabled."
  }

  assert {
    condition     = aws_cloudtrail_event_data_store.this[0].retention_period == 1095
    error_message = "CloudTrail Lake retention must match the custom configuration."
  }

  assert {
    condition     = length(aws_s3_bucket.vpc_flow_logs) == 1
    error_message = "VPC flow logs bucket must be created when enabled."
  }

  assert {
    condition     = length(aws_s3_bucket_replication_configuration.central_logs) == 1
    error_message = "Replication configuration must be created when destination_region is set."
  }

  assert {
    condition     = length(aws_s3_bucket.replication_dest) == 1
    error_message = "Replication destination bucket must be auto-created when no destination ARN is given."
  }

  assert {
    condition     = output.replication_dest_bucket_arn == "arn:aws:s3:::tlz-central-logs-replica-210987654321-eu-west-1"
    error_message = "Replication destination bucket ARN must be derived from account ID and destination region."
  }

  # The replica and everything attached to it live in destination_region, not
  # in the deployment region (eu-central-1 in the mock). Before the region
  # argument the bucket carried eu-west-1 in its NAME and eu-central-1 in fact.
  assert {
    condition = alltrue([
      aws_s3_bucket.replication_dest[0].region == "eu-west-1",
      aws_kms_key.replication_dest[0].region == "eu-west-1",
      aws_kms_alias.replication_dest[0].region == "eu-west-1",
      aws_s3_bucket_versioning.replication_dest[0].region == "eu-west-1",
      aws_s3_bucket_server_side_encryption_configuration.replication_dest[0].region == "eu-west-1",
      aws_s3_bucket_public_access_block.replication_dest[0].region == "eu-west-1",
      aws_s3_bucket_lifecycle_configuration.replication_dest[0].region == "eu-west-1",
      aws_s3_bucket_policy.replication_dest[0].region == "eu-west-1",
    ])
    error_message = "The replica bucket, its KMS key/alias and every bucket-configuration sibling must be created in s3_replication_config.destination_region — a replica in the source region is same-region replication wearing a cross-region name."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.cloudtrail) == 1
    error_message = "CloudWatch Log Group must be created when cloudwatch_log_group_retention is set."
  }

  assert {
    condition     = output.cloudwatch_log_group_retention == 90
    error_message = "CloudWatch Log Group retention must match the custom configuration."
  }

  assert {
    condition     = length(aws_cloudwatch_log_data_protection_policy.cloudtrail) == 1
    error_message = "CloudTrail data protection policy must be created when data protection is enabled."
  }

  assert {
    condition     = length(aws_cloudwatch_log_data_protection_policy.additional) == 1
    error_message = "One additional data protection policy must be created for the extra log group."
  }

  # The extra group is created by nothing in this module, so its existence is
  # read at plan time; the name reaches the policy through that read.
  assert {
    condition     = keys(data.aws_cloudwatch_log_group.data_protection_targets) == ["/aws/lambda/tlz-custom"] && aws_cloudwatch_log_data_protection_policy.additional["/aws/lambda/tlz-custom"].log_group_name == "/aws/lambda/tlz-custom"
    error_message = "An additional data-protection log group this module does not create must be read through data.aws_cloudwatch_log_group and still reach the policy by name."
  }

  assert {
    condition     = length(aws_sns_topic.cloudtrail) == 1
    error_message = "SNS topic must be created when cloudtrail_sns_topic_name is set."
  }

  assert {
    condition     = aws_sns_topic.cloudtrail[0].name == "tlz-cloudtrail-notifications"
    error_message = "SNS topic name must match the custom configuration."
  }

  assert {
    condition     = length(aws_cloudtrail.account_trails) == 1
    error_message = "One account-level trail must be created."
  }

  assert {
    condition     = aws_cloudtrail.account_trails["tlz-account-trail"].is_organization_trail == false
    error_message = "Account trails must not be organization trails."
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 1
    error_message = "Excluded log groups must not receive a subscription filter."
  }

  assert {
    condition     = length(aws_kinesis_stream.cw_to_s3) == 1 && length(aws_kinesis_firehose_delivery_stream.cw_to_s3) == 1
    error_message = "Kinesis pipeline must be created when log subscriptions are configured."
  }

  assert {
    condition     = length(aws_ssm_association.this) == 1
    error_message = "One SSM association must be created."
  }

  assert {
    condition     = output.log_retention_days == 730
    error_message = "log_retention_days output must reflect the custom value."
  }

  assert {
    condition     = length(output.cloudtrail_insights) == 2
    error_message = "Both CloudTrail Insight types must be enabled."
  }

  # enable_cloudtrail_lake = true is expected to trip the plan-time warning that
  # CloudTrail Lake is closed to new customers (see cloudtrail-lake.tf). The
  # store is still created (asserted above); the check surfaces the service
  # limitation without failing the plan for a pre-cutoff account.
  expect_failures = [
    check.cloudtrail_lake_new_customer_closure,
  ]
}

# -----------------------------------------------------------------------------
# 3b. Custom configuration — CloudTrail Lake with the module default retention
# -----------------------------------------------------------------------------
# The default retention must lie in the range the provider accepts, so that
# enabling CloudTrail Lake without an explicit value plans.

run "logging_cloudtrail_lake_default_retention" {
  command = plan

  variables {
    enable_cloudtrail_lake = true
  }

  assert {
    condition     = length(aws_cloudtrail_event_data_store.this) == 1
    error_message = "CloudTrail Lake event data store must be created when enabled."
  }

  assert {
    condition     = aws_cloudtrail_event_data_store.this[0].retention_period == 2555
    error_message = "The default CloudTrail Lake retention must be 2555 days — the maximum the AWS provider accepts."
  }

  assert {
    condition     = aws_cloudtrail_event_data_store.this[0].retention_period <= 2555
    error_message = "The default CloudTrail Lake retention must stay within the range the AWS provider accepts (7 to 2555 days)."
  }

  # Enabling the store trips the closed-to-new-customers warning by design; the
  # store is still created and its retention asserted above.
  expect_failures = [
    check.cloudtrail_lake_new_customer_closure,
  ]
}

# -----------------------------------------------------------------------------
# 3c. Custom configuration — replication into an externally provided bucket
# -----------------------------------------------------------------------------
# The replica KMS key must only be indexed under the condition that creates
# it, or an external destination bucket aborts the plan with "Invalid index".

run "logging_replication_external_destination_bucket" {
  command = plan

  variables {
    s3_replication_config = {
      destination_region      = "eu-west-1"
      destination_bucket_arn  = "arn:aws:s3:::external-log-replica-bucket"
      destination_kms_key_arn = "arn:aws:kms:eu-west-1:210987654321:key/11111111-2222-3333-4444-555555555555"
    }
  }

  assert {
    condition     = length(aws_s3_bucket_replication_configuration.central_logs) == 1
    error_message = "Replication must be configured for an externally provided destination bucket."
  }

  assert {
    condition     = length(aws_s3_bucket.replication_dest) == 0 && length(aws_kms_key.replication_dest) == 0
    error_message = "Neither destination bucket nor replica KMS key must be created when both are provided externally."
  }

  assert {
    condition     = length(aws_iam_role.replication) == 1 && length(aws_iam_role_policy.replication) == 1
    error_message = "The replication role and its policy must be created for an external destination bucket."
  }

  assert {
    condition     = output.replication_dest_bucket_arn == "arn:aws:s3:::external-log-replica-bucket"
    error_message = "The destination bucket ARN output must be the externally provided ARN."
  }

  assert {
    condition     = output.replication_dest_kms_key_arn == "arn:aws:kms:eu-west-1:210987654321:key/11111111-2222-3333-4444-555555555555"
    error_message = "The replica KMS key output must be the externally provided key ARN."
  }
}

# -----------------------------------------------------------------------------
# 4. Validation failures — invalid input must be rejected
# -----------------------------------------------------------------------------

run "logging_invalid_organization_id" {
  command = plan

  variables {
    organization_id = "not-an-org-id"
  }

  expect_failures = [
    var.organization_id,
  ]
}

run "logging_custom_guardduty_export_prefix" {
  command = plan

  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    }
  }

  variables {
    guardduty_export_prefix = "security/guardduty/"
  }

  assert {
    condition     = [for s in local.central_log_bucket_base_policy.Statement : s if try(s.Sid, "") == "AWSGuardDutyPutObject"][0].Resource == "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1/security/guardduty/*"
    error_message = "The GuardDuty PutObject grant must follow the configured export prefix."
  }

  assert {
    condition     = aws_s3_object.guardduty_export_marker[0].key == "security/guardduty/"
    error_message = "The GuardDuty export folder marker must carry the same derived prefix key as the PutObject grant."
  }
}

run "logging_empty_guardduty_export_prefix_creates_no_marker" {
  command = plan

  variables {
    guardduty_export_prefix = ""
  }

  # An empty prefix is a supported configuration: the destination is the bare
  # bucket, the grant covers the bucket root, and no folder marker is needed —
  # a zero-length S3 key would also be invalid.
  assert {
    condition     = length(aws_s3_object.guardduty_export_marker) == 0
    error_message = "With an empty export prefix no GuardDuty folder marker object may be created."
  }
}

run "logging_invalid_guardduty_export_prefix" {
  command = plan

  variables {
    guardduty_export_prefix = "/guardduty/"
  }

  expect_failures = [
    var.guardduty_export_prefix,
  ]
}

run "logging_invalid_log_retention_days" {
  command = plan

  variables {
    log_retention_days = 0
  }

  expect_failures = [
    var.log_retention_days,
  ]
}

run "logging_invalid_log_archive_account_id" {
  command = plan

  variables {
    log_archive_account_id = "12345"
  }

  expect_failures = [
    var.log_archive_account_id,
  ]
}

# -----------------------------------------------------------------------------
# Resource adoption — adopted bucket names (docs/resource-adoption.md)
# -----------------------------------------------------------------------------
# An adopted bucket keeps its name: the configured name wins over the derived
# one, so the import of an existing bucket does not plan a replacement, and
# the companion resources (encryption, versioning, public access block,
# bucket policy) capture the adopted bucket.

run "logging_adopted_bucket_names_apply" {
  command = plan

  variables {
    adopted_central_log_bucket_name    = "existing-central-logs"
    adopted_access_logs_bucket_name    = "existing-access-logs"
    adopted_elb_log_bucket_name        = "existing-elb-logs"
    enable_separate_access_logs_bucket = true
    enable_elb_log_bucket              = true
  }

  assert {
    condition     = aws_s3_bucket.central_logs.bucket == "existing-central-logs"
    error_message = "adopted_central_log_bucket_name must win over the derived central bucket name"
  }

  assert {
    condition     = aws_s3_bucket.access_logs[0].bucket == "existing-access-logs"
    error_message = "adopted_access_logs_bucket_name must win over the derived access logs bucket name"
  }

  assert {
    condition     = aws_s3_bucket.elb_logs[0].bucket == "existing-elb-logs"
    error_message = "adopted_elb_log_bucket_name must win over the derived ELB bucket name"
  }

  # The companion resources (encryption, versioning, public access block,
  # bucket policy) reference aws_s3_bucket.central_logs.id and follow the
  # adopted bucket structurally; the resolved id is not known at plan time, so
  # this run cannot assert it.
}

run "logging_adopted_bucket_names_empty_keep_derived_names" {
  command = plan

  variables {
    enable_separate_access_logs_bucket = true
    enable_elb_log_bucket              = true
  }

  assert {
    condition     = aws_s3_bucket.central_logs.bucket == "tlz-central-logs-210987654321-eu-central-1"
    error_message = "empty adopted_central_log_bucket_name must keep the derived central bucket name"
  }

  assert {
    condition     = aws_s3_bucket.access_logs[0].bucket == "tlz-access-logs-210987654321-eu-central-1"
    error_message = "empty adopted_access_logs_bucket_name must keep the derived access logs bucket name"
  }

  assert {
    condition     = aws_s3_bucket.elb_logs[0].bucket == "tlz-elb-logs-111111111111-eu-central-1"
    error_message = "empty adopted_elb_log_bucket_name must keep the derived ELB bucket name"
  }
}

run "logging_invalid_adopted_central_log_bucket_name" {
  command = plan

  variables {
    adopted_central_log_bucket_name = "Not-A-Valid-Bucket-Name!"
  }

  expect_failures = [
    var.adopted_central_log_bucket_name,
  ]
}

# -----------------------------------------------------------------------------
# Fixed resource names — overridable so a live apply-test can scope its own
# -----------------------------------------------------------------------------
# Every name defaults to the production name (asserted by the default scenario
# above: alias/tlz/management/kms, alias/tlz/cloudwatch/kms, alias/tlz/s3/kms).
# Here a non-default value must reach the resource, and the two readers of the
# trail name — its CloudWatch log group and the aws:SourceArn scope of the
# central bucket policy — must follow it, or CreateTrail fails against the
# bucket policy at apply.

run "logging_name_overrides_reach_resources" {
  command = plan

  # The bucket policy local reads the bucket ARN; known at plan only with the
  # override, like logging_custom_guardduty_export_prefix.
  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    }
  }

  variables {
    cloudtrail_org_trail_name         = "l4test-org-trail"
    cloudtrail_cloudwatch_role_name   = "tlz-l4test-cloudtrail-cloudwatch-role"
    cloudtrail_cloudwatch_policy_name = "l4test-cloudtrail-cloudwatch-policy"
    cloudwatch_log_group_retention    = 365
    log_bucket_kms_alias              = "l4test-central-logs"
    management_kms_alias              = "l4test/management/kms"
    cloudwatch_kms_alias              = "l4test/cloudwatch/kms"
    per_account_s3_kms_alias          = "l4test/s3/kms"
    enable_per_account_kms_keys       = true
    adopted_vpc_flow_logs_bucket_name = "existing-vpc-flow-logs"
    enable_vpc_flow_logs_bucket       = true
    config_aggregator_name            = "l4test-org-config-aggregator"
    config_aggregator_role_name       = "tlz-l4test-config-aggregator-role"
  }

  assert {
    condition     = aws_cloudtrail.org_trail.name == "l4test-org-trail"
    error_message = "cloudtrail_org_trail_name must reach aws_cloudtrail.org_trail."
  }

  # PutConfigurationAggregator is an upsert: a test carrying the live name
  # adopts the live organization-wide aggregator and deletes it on teardown.
  # The name must reach the resource, or a test-scoped override is no shield.
  assert {
    condition     = aws_config_configuration_aggregator.org.name == "l4test-org-config-aggregator"
    error_message = "config_aggregator_name must reach aws_config_configuration_aggregator.org."
  }

  assert {
    condition     = aws_iam_role.config_aggregator.name == "tlz-l4test-config-aggregator-role"
    error_message = "config_aggregator_role_name must reach aws_iam_role.config_aggregator."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.config_aggregator.role == "tlz-l4test-config-aggregator-role"
    error_message = "The AWSConfigRoleForOrganizations attachment must follow the overridden aggregator role name."
  }

  assert {
    condition     = aws_cloudwatch_log_group.cloudtrail[0].name == "/aws/cloudtrail/l4test-org-trail"
    error_message = "The trail's CloudWatch log group must derive from cloudtrail_org_trail_name."
  }

  assert {
    condition = alltrue([
      for s in local.central_log_bucket_base_policy.Statement :
      s.Condition.StringEquals["aws:SourceArn"] == "arn:aws:cloudtrail:eu-central-1:111111111111:trail/l4test-org-trail"
      if startswith(try(s.Sid, ""), "AWSCloudTrail")
    ])
    error_message = "Every CloudTrail grant of the central bucket policy must scope aws:SourceArn to the configured trail name — CreateTrail validates it."
  }

  assert {
    condition     = length([for s in local.central_log_bucket_base_policy.Statement : s if startswith(try(s.Sid, ""), "AWSCloudTrail")]) == 3
    error_message = "The central bucket policy must carry the three CloudTrail grants (AclCheck, Write, OrgWrite) — the SourceArn assertion above is empty otherwise."
  }

  assert {
    condition     = aws_iam_role.cloudtrail_cloudwatch[0].name == "tlz-l4test-cloudtrail-cloudwatch-role"
    error_message = "cloudtrail_cloudwatch_role_name must reach aws_iam_role.cloudtrail_cloudwatch."
  }

  assert {
    condition     = aws_iam_role_policy.cloudtrail_cloudwatch[0].name == "l4test-cloudtrail-cloudwatch-policy"
    error_message = "cloudtrail_cloudwatch_policy_name must reach aws_iam_role_policy.cloudtrail_cloudwatch."
  }

  assert {
    condition     = aws_kms_alias.log_bucket.name == "alias/l4test-central-logs"
    error_message = "log_bucket_kms_alias must reach aws_kms_alias.log_bucket with the alias/ prefix prepended."
  }

  assert {
    condition     = aws_kms_alias.management.name == "alias/l4test/management/kms"
    error_message = "management_kms_alias must reach aws_kms_alias.management with the alias/ prefix prepended."
  }

  assert {
    condition     = aws_kms_alias.cloudwatch.name == "alias/l4test/cloudwatch/kms"
    error_message = "cloudwatch_kms_alias must reach aws_kms_alias.cloudwatch with the alias/ prefix prepended."
  }

  assert {
    condition     = aws_kms_alias.per_account_s3[0].name == "alias/l4test/s3/kms"
    error_message = "per_account_s3_kms_alias must reach aws_kms_alias.per_account_s3 with the alias/ prefix prepended."
  }

  assert {
    condition     = aws_s3_bucket.vpc_flow_logs[0].bucket == "existing-vpc-flow-logs"
    error_message = "adopted_vpc_flow_logs_bucket_name must win over the derived flow-log bucket name."
  }
}

run "logging_name_defaults_keep_todays_literals" {
  command = plan

  variables {
    cloudwatch_log_group_retention = 365
    enable_vpc_flow_logs_bucket    = true
  }

  assert {
    condition     = aws_cloudtrail.org_trail.name == "tlz-org-trail"
    error_message = "The default cloudtrail_org_trail_name must stay tlz-org-trail — a changed default replaces the live trail."
  }

  assert {
    condition     = aws_cloudwatch_log_group.cloudtrail[0].name == "/aws/cloudtrail/tlz-org-trail"
    error_message = "The default trail log group must stay /aws/cloudtrail/tlz-org-trail — base.tfvars metric filters reference it."
  }

  assert {
    condition     = aws_iam_role.cloudtrail_cloudwatch[0].name == "tlz-cloudtrail-cloudwatch-role" && aws_iam_role_policy.cloudtrail_cloudwatch[0].name == "tlz-cloudtrail-cloudwatch-policy"
    error_message = "The default delivery role and policy names must stay tlz-cloudtrail-cloudwatch-role / -policy."
  }

  assert {
    condition     = aws_kms_alias.log_bucket.name == "alias/tlz-central-logs"
    error_message = "The default log bucket alias must stay alias/tlz-central-logs."
  }

  assert {
    condition     = aws_s3_bucket.vpc_flow_logs[0].bucket == "tlz-vpc-flow-logs-111111111111-eu-central-1"
    error_message = "empty adopted_vpc_flow_logs_bucket_name must keep the derived flow-log bucket name."
  }

  assert {
    condition     = aws_config_configuration_aggregator.org.name == "tlz-org-config-aggregator"
    error_message = "The default config_aggregator_name must stay tlz-org-config-aggregator — a changed default replaces the live organization-wide aggregator."
  }

  assert {
    condition     = aws_iam_role.config_aggregator.name == "tlz-config-aggregator-role"
    error_message = "The default config_aggregator_role_name must stay tlz-config-aggregator-role — a changed default replaces the live role."
  }
}

run "logging_invalid_config_aggregator_name" {
  command = plan

  variables {
    config_aggregator_name = "has spaces"
  }

  expect_failures = [
    var.config_aggregator_name,
  ]
}

# The role validation carries the tlz- namespace invariant: ProtectIAMRoles in
# tlz-core-guardrails-2.json protects only role/tlz-*, and the static prefix
# guard reads quoted literals only, so a variable name outside the prefix would
# lose its guardrail silently. A syntactically valid IAM name that merely
# leaves the namespace must be refused.
run "logging_invalid_config_aggregator_role_name_outside_namespace" {
  command = plan

  variables {
    config_aggregator_role_name = "l4test-config-aggregator-role"
  }

  expect_failures = [
    var.config_aggregator_role_name,
  ]
}

run "logging_invalid_config_aggregator_role_name_syntax" {
  command = plan

  variables {
    config_aggregator_role_name = "tlz-has spaces"
  }

  expect_failures = [
    var.config_aggregator_role_name,
  ]
}

run "logging_invalid_org_trail_name" {
  command = plan

  variables {
    cloudtrail_org_trail_name = "-starts-with-hyphen"
  }

  expect_failures = [
    var.cloudtrail_org_trail_name,
  ]
}

run "logging_invalid_kms_alias_reserved_prefix" {
  command = plan

  variables {
    cloudwatch_kms_alias = "aws/cloudwatch"
  }

  expect_failures = [
    var.cloudwatch_kms_alias,
  ]
}

run "logging_invalid_cloudwatch_role_name" {
  command = plan

  variables {
    cloudtrail_cloudwatch_role_name = "has spaces"
  }

  expect_failures = [
    var.cloudtrail_cloudwatch_role_name,
  ]
}

run "logging_invalid_adopted_vpc_flow_logs_bucket_name" {
  command = plan

  variables {
    adopted_vpc_flow_logs_bucket_name = "Not-A-Valid-Bucket-Name!"
  }

  expect_failures = [
    var.adopted_vpc_flow_logs_bucket_name,
  ]
}

# A lifecycle rule must not expire log objects before the retention period is
# over. One rule below log_retention_days is enough; the guard covers all three
# prefixes. Without it, choosing cmmc, fedramp-high or hipaa (2555 days) with a
# 1000-day rule would delete the objects 1555 days early.
run "logging_lifecycle_retention_below_log_retention" {
  command = plan

  variables {
    log_retention_days = 2555
    s3_lifecycle_rules = {
      cloudtrail = {
        retention_days = 2555
      }
      config = {
        retention_days = 2555
      }
      access_logs = {
        retention_days = 1000
      }
    }
  }

  expect_failures = [
    var.s3_lifecycle_rules,
  ]
}

# Same guard for the ELB log bucket — it carries access logs and is subject to
# the same retention period.
run "logging_elb_lifecycle_retention_below_log_retention" {
  command = plan

  variables {
    log_retention_days    = 2555
    enable_elb_log_bucket = true
    force_destroy         = true
    elb_log_bucket_lifecycle = {
      retention_days = 1000
    }
  }

  expect_failures = [
    var.elb_log_bucket_lifecycle,
  ]
}

# The counter-example: retention equal to the retention period passes. Without
# this run the guard could be tightened to "strictly greater" unnoticed, which
# would reject the value the loader itself derives.
run "logging_lifecycle_retention_equal_to_log_retention_is_accepted" {
  command = plan

  variables {
    log_retention_days = 2555
    s3_lifecycle_rules = {
      cloudtrail = {
        retention_days = 2555
      }
      config = {
        retention_days = 2555
      }
      access_logs = {
        retention_days = 2555
      }
    }
    enable_elb_log_bucket = true
    force_destroy         = true
    elb_log_bucket_lifecycle = {
      retention_days = 2555
    }
  }

  assert {
    condition     = output.log_retention_days == 2555
    error_message = "log_retention_days output must reflect the retention period the lifecycle rules were checked against."
  }
}

run "logging_invalid_object_lock_retention_mode" {
  command = plan

  variables {
    enable_s3_object_lock = true
    force_destroy         = true
    s3_object_lock_config = {
      retention_mode = "INVALID"
    }
  }

  expect_failures = [
    var.s3_object_lock_config,
  ]
}

# A retention above the range the provider accepts must be rejected by the
# module.
run "logging_invalid_cloudtrail_lake_retention" {
  command = plan

  variables {
    enable_cloudtrail_lake = true
    cloudtrail_lake_config = {
      retention_days = 2557
    }
  }

  expect_failures = [
    var.cloudtrail_lake_config,
    # Enabling the store also trips the closed-to-new-customers warning; both
    # the variable validation and the check fire on this plan.
    check.cloudtrail_lake_new_customer_closure,
  ]
}

# An external destination bucket without its own replica key has no key the
# module could reference.
run "logging_invalid_replication_external_bucket_without_key" {
  command = plan

  variables {
    s3_replication_config = {
      destination_region     = "eu-west-1"
      destination_bucket_arn = "arn:aws:s3:::external-log-replica-bucket"
    }
  }

  expect_failures = [
    var.s3_replication_config,
  ]
}

# destination_region equal to the
# deployment region (eu-central-1 in the mock) is accepted by S3 as same-region
# replication; the check names it so a "cross-region" replica cannot sit next
# to its source unnoticed. Warning, not precondition: same-region replication
# is a legitimate choice and keeps its plan.
run "logging_replication_same_region_destination_warns" {
  command = plan

  variables {
    s3_replication_config = {
      destination_region = "eu-central-1"
    }
  }

  assert {
    condition     = aws_s3_bucket.replication_dest[0].region == "eu-central-1"
    error_message = "The replica bucket must still be planned in the configured destination_region — the check only warns."
  }

  expect_failures = [
    check.replication_destination_is_cross_region,
  ]
}

# -----------------------------------------------------------------------------
# 5. Config recorder role and CloudTrail management events
# -----------------------------------------------------------------------------
# Two subject areas whose inputs the scenarios above do not cover in both
# states:
#
#   a) the pair use_config_service_linked_role / config_recorder_custom_role_arn
#      — config-recorder.tf:11 picks between the two, so both branches are
#      examined plus the invalid combination,
#   b) cloudtrail_management_events — module default true, merged via the
#      _declared_ form of the loader, so that the wiring cannot switch
#      management event logging off by accident.

# 5a. Default branch — the AWS Config Service-Linked Role.
run "logging_config_recorder_service_linked_role" {
  command = plan

  variables {
    use_config_service_linked_role  = true
    config_recorder_custom_role_arn = ""
  }

  assert {
    condition     = aws_config_configuration_recorder.this[0].role_arn == "arn:aws:iam::111111111111:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
    error_message = "With use_config_service_linked_role = true the recorder must use the AWS service linked role of the active partition."
  }

  # A custom ARN that is present but unused must not reach the recorder.
  assert {
    condition     = !strcontains(aws_config_configuration_recorder.this[0].role_arn, "ConfigRecorderRole")
    error_message = "The service linked role must win over a configured custom role ARN."
  }
}

# 5b. Custom role branch — the second half of the pair.
run "logging_config_recorder_custom_role" {
  command = plan

  variables {
    use_config_service_linked_role  = false
    config_recorder_custom_role_arn = "arn:aws:iam::111111111111:role/ConfigRecorderRole"
  }

  assert {
    condition     = aws_config_configuration_recorder.this[0].role_arn == "arn:aws:iam::111111111111:role/ConfigRecorderRole"
    error_message = "With use_config_service_linked_role = false the recorder must use config_recorder_custom_role_arn."
  }

  assert {
    condition     = !strcontains(aws_config_configuration_recorder.this[0].role_arn, "aws-service-role")
    error_message = "The service linked role must not be used once it is switched off."
  }
}

# 5c. The pair without its second half — the recorder would get an empty role.
run "logging_config_recorder_custom_role_missing" {
  command = plan

  variables {
    use_config_service_linked_role  = false
    config_recorder_custom_role_arn = ""
  }

  expect_failures = [
    check.config_custom_role_required,
  ]
}

# 5d. Management events on (module default) and off.
run "logging_cloudtrail_management_events_enabled" {
  command = plan

  variables {
    cloudtrail_management_events  = true
    cloudtrail_s3_data_events     = false
    cloudtrail_lambda_data_events = false
  }

  assert {
    condition     = length(aws_cloudtrail.org_trail.advanced_event_selector) == 1
    error_message = "With management events on and both data event switches off exactly one selector must remain."
  }

  assert {
    condition     = aws_cloudtrail.org_trail.advanced_event_selector[0].name == "ManagementEvents"
    error_message = "The remaining selector must be the management event selector."
  }
}

run "logging_cloudtrail_management_events_disabled" {
  command = plan

  variables {
    cloudtrail_management_events  = false
    cloudtrail_s3_data_events     = true
    cloudtrail_lambda_data_events = false
  }

  assert {
    condition     = length(aws_cloudtrail.org_trail.advanced_event_selector) == 1
    error_message = "With management events off only the S3 data event selector must remain."
  }

  assert {
    condition     = aws_cloudtrail.org_trail.advanced_event_selector[0].name == "S3DataEvents"
    error_message = "The management event selector must disappear when cloudtrail_management_events is false."
  }
}

# 5e. manage_config_recorder — the recorder slot.
# -----------------------------------------------------------------------------
# An account allows one Config recorder per region. When another owner holds
# the slot, the flag skips the recorder, its delivery channel and its status
# and nothing else: the aggregator and its role stay, every output still
# resolves, and the role pair (which configures only the skipped resources)
# raises no check. Default true is pinned first so a live plan cannot move.
run "logging_manage_config_recorder_default_creates_all_three" {
  command = plan

  assert {
    condition     = length(aws_config_configuration_recorder.this) == 1
    error_message = "manage_config_recorder defaults to true: the recorder must be planned."
  }

  assert {
    condition     = length(aws_config_delivery_channel.this) == 1
    error_message = "manage_config_recorder defaults to true: the delivery channel must be planned."
  }

  assert {
    condition     = length(aws_config_configuration_recorder_status.this) == 1
    error_message = "manage_config_recorder defaults to true: the recorder status must be planned."
  }

  assert {
    condition     = aws_config_configuration_recorder_status.this[0].name == aws_config_configuration_recorder.this[0].name
    error_message = "The recorder status must address the module's own recorder."
  }

  assert {
    condition     = aws_config_delivery_channel.this[0].s3_key_prefix == "config"
    error_message = "The delivery channel must keep delivering under the config/ prefix of the central log bucket."
  }
}

run "logging_manage_config_recorder_false_skips_exactly_the_recorder_trio" {
  command = plan

  variables {
    manage_config_recorder = false
  }

  assert {
    condition     = length(aws_config_configuration_recorder.this) == 0
    error_message = "manage_config_recorder = false must plan no recorder."
  }

  assert {
    condition     = length(aws_config_delivery_channel.this) == 0
    error_message = "manage_config_recorder = false must plan no delivery channel."
  }

  assert {
    condition     = length(aws_config_configuration_recorder_status.this) == 0
    error_message = "manage_config_recorder = false must plan no recorder status."
  }

  # The aggregator is independent of the local recorder and must survive.
  assert {
    condition     = aws_config_configuration_aggregator.org.name == "tlz-org-config-aggregator"
    error_message = "The organization aggregator must not be gated by manage_config_recorder."
  }

  assert {
    condition     = aws_iam_role.config_aggregator.name == "tlz-config-aggregator-role"
    error_message = "The aggregator role must not be gated by manage_config_recorder."
  }

  # The rest of the module is untouched by the flag.
  assert {
    condition     = aws_cloudtrail.org_trail.name == "tlz-org-trail"
    error_message = "The organization trail must be unaffected by manage_config_recorder."
  }

  # Every output still resolves — none of them reads the skipped resources. The
  # plan completing is the proof (an output indexing an empty count fails the
  # plan); the two known-at-plan outputs below pin values on top of that.
  assert {
    condition     = output.config_aggregator_name == "tlz-org-config-aggregator"
    error_message = "config_aggregator_name must resolve with the recorder unmanaged."
  }

  assert {
    condition     = output.log_retention_days == 365
    error_message = "log_retention_days must resolve with the recorder unmanaged."
  }
}

# With the recorder unmanaged the role pair configures nothing, so the
# combination that fails the check in 5c must pass here — no expect_failures.
run "logging_manage_config_recorder_false_silences_custom_role_check" {
  command = plan

  variables {
    manage_config_recorder          = false
    use_config_service_linked_role  = false
    config_recorder_custom_role_arn = ""
  }

  assert {
    condition     = length(aws_config_configuration_recorder.this) == 0
    error_message = "manage_config_recorder = false must plan no recorder regardless of the role pair."
  }
}

# =============================================================================
# Configurable S3 lifecycle rules
# =============================================================================
# Without a rule set, the four buckets of this module carry a lifecycle derived
# from log_retention_days, elb_log_bucket_lifecycle and
# vpc_flow_logs_bucket_config; each of them can take a rule set instead. The
# first run below is the load-bearing one: it holds the derived plan of all
# four buckets in place, because that plan is what an existing deployment has.
# -----------------------------------------------------------------------------
# Without a rule set the derived plan stays unchanged.
run "regression_lifecycle_defaults_keep_the_derived_plan" {
  command = plan
  variables {
    log_retention_days                 = 365
    force_destroy                      = true
    enable_separate_access_logs_bucket = true
    enable_elb_log_bucket              = true
    enable_vpc_flow_logs_bucket        = true
  }
  # The central bucket keeps the single whole-bucket rule of log_retention_days.
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.central_logs.rule) == 1
    error_message = "Without a rule set the central bucket must keep exactly the one derived rule."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].id == "log-retention"
    error_message = "The derived rule of the central bucket must keep the id log-retention."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].expiration).days == 365
    error_message = "The derived rule of the central bucket must expire after log_retention_days."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].noncurrent_version_expiration).noncurrent_days == 365
    error_message = "The derived rule of the central bucket must expire noncurrent versions after log_retention_days."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].abort_incomplete_multipart_upload).days_after_initiation == 7
    error_message = "The derived rule of the central bucket must keep aborting incomplete uploads after 7 days."
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].transition) == 0
    error_message = "The derived rule of the central bucket carries no transition — it never did."
  }
  # The access logs bucket keeps its named rule.
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.access_logs[0].rule) == 1
    error_message = "Without a rule set the access logs bucket must keep exactly the one derived rule."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.access_logs[0].rule[0].id == "access-log-retention"
    error_message = "The derived rule of the access logs bucket must keep the id access-log-retention."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.access_logs[0].rule[0].expiration).days == 365
    error_message = "The derived rule of the access logs bucket must expire after log_retention_days."
  }
  # The ELB log bucket keeps its rule including the two archive transitions.
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.elb_logs[0].rule) == 1
    error_message = "Without a rule set the ELB log bucket must keep exactly the one derived rule."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.elb_logs[0].rule[0].id == "elb-log-retention"
    error_message = "The derived rule of the ELB log bucket must keep the id elb-log-retention."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.elb_logs[0].rule[0].expiration).days == 365
    error_message = "The derived rule of the ELB log bucket must expire after elb_log_bucket_lifecycle.retention_days."
  }
  # The flow log bucket keeps its rule.
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.vpc_flow_logs[0].rule) == 1
    error_message = "Without a rule set the flow log bucket must keep exactly the one derived rule."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.vpc_flow_logs[0].rule[0].id == "vpc-flow-logs-retention"
    error_message = "The derived rule of the flow log bucket must keep the id vpc-flow-logs-retention."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.vpc_flow_logs[0].rule[0].expiration).days == 365
    error_message = "The derived rule of the flow log bucket must expire after vpc_flow_logs_bucket_config.retention_days."
  }
}
# The per-prefix form of s3_lifecycle_rules keeps its three rules. It is the
# second derived form of the central bucket and has to stay reachable
# alongside the rule set.
run "regression_per_prefix_lifecycle_stays_reachable" {
  command = plan
  variables {
    log_retention_days = 365
    s3_lifecycle_rules = {
      cloudtrail = {
        retention_days          = 400
        glacier_transition_days = 90
      }
      config      = { retention_days = 400 }
      access_logs = { retention_days = 400 }
    }
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.central_logs.rule) == 3
    error_message = "s3_lifecycle_rules must keep producing one rule per known prefix."
  }
  assert {
    condition     = length([for rule in aws_s3_bucket_lifecycle_configuration.central_logs.rule : rule if rule.id == "cloudtrail"]) == 1
    error_message = "The per-prefix form must keep the rule id cloudtrail."
  }
}
# -----------------------------------------------------------------------------
# Reach: an explicit rule set replaces the derived plan and lands on the bucket
# with every attribute of the shape.
run "logging_lifecycle_rules_reach_the_buckets" {
  command = plan
  variables {
    log_retention_days                 = 365
    force_destroy                      = true
    enable_separate_access_logs_bucket = true
    enable_elb_log_bucket              = true
    enable_vpc_flow_logs_bucket        = true
    central_log_bucket_lifecycle_rules = [
      {
        id              = "cloudtrail-archive"
        prefix          = "cloudtrail/"
        expiration_days = 2555
        transitions = [
          { storage_class = "STANDARD_IA", days = 30 },
          { storage_class = "GLACIER", days = 90 },
          { storage_class = "DEEP_ARCHIVE", days = 365 },
        ]
        noncurrent_version_expiration_days = 400
        noncurrent_version_transitions = [
          { storage_class = "GLACIER", days = 30 },
        ]
        abort_incomplete_multipart_upload_days = 3
      },
      {
        id                           = "clean-delete-markers"
        enabled                      = false
        expired_object_delete_marker = true
      },
    ]
    access_logs_bucket_lifecycle_rules = [
      {
        id              = "access-logs-by-tag"
        tags            = { retention = "short" }
        expiration_days = 365
      },
    ]
    elb_log_bucket_lifecycle_rules = [
      { id = "elb-archive", expiration_days = 400, transitions = [{ storage_class = "GLACIER_IR", days = 30 }] },
    ]
    vpc_flow_logs_bucket_lifecycle_rules = [
      { id = "flow-logs-archive", expiration_days = 400 },
    ]
  }
  # The derived rule of the central bucket is gone and the two given rules stand.
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.central_logs.rule) == 2
    error_message = "An explicit rule set must replace the derived rule, not join it."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].id == "cloudtrail-archive"
    error_message = "The rules must keep the order of the input list."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].status == "Enabled"
    error_message = "enabled = true (the default) must reach the resource as status Enabled."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.central_logs.rule[1].status == "Disabled"
    error_message = "enabled = false must reach the resource as status Disabled."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].filter).prefix == "cloudtrail/"
    error_message = "prefix must reach the filter of the rule."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].expiration).days == 2555
    error_message = "expiration_days must reach the expiration block."
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].transition) == 3
    error_message = "Every transition of the rule must reach the resource."
  }
  assert {
    condition = length([
      for transition in aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].transition :
      transition if transition.storage_class == "DEEP_ARCHIVE" && transition.days == 365
    ]) == 1
    error_message = "storage_class and days of a transition must reach the resource unchanged."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].noncurrent_version_expiration).noncurrent_days == 400
    error_message = "noncurrent_version_expiration_days must reach the noncurrent_version_expiration block."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].noncurrent_version_transition).noncurrent_days == 30
    error_message = "A noncurrent version transition must reach the resource with its days."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].abort_incomplete_multipart_upload).days_after_initiation == 3
    error_message = "abort_incomplete_multipart_upload_days must reach the resource."
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[1].expiration).expired_object_delete_marker == true
    error_message = "expired_object_delete_marker must reach the expiration block."
  }
  # The other three buckets take their own rule sets.
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.access_logs[0].rule[0].id == "access-logs-by-tag"
    error_message = "The access logs bucket must take its own rule set."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.elb_logs[0].rule[0].id == "elb-archive"
    error_message = "The ELB log bucket must take its own rule set."
  }
  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.vpc_flow_logs[0].rule[0].id == "flow-logs-archive"
    error_message = "The flow log bucket must take its own rule set."
  }
}
# An empty rule set is a deliberate "no rules" and has to stay distinguishable
# from null, which means "keep deriving". Without this run the difference could
# be lost by treating the list as empty in one place and as absent in another.
run "logging_empty_lifecycle_rule_set_removes_every_rule" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = []
  }
  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.central_logs.rule) == 0
    error_message = "An empty rule set must remove every rule, including the derived one."
  }
}
# -----------------------------------------------------------------------------
# Validation — one run per check on the rule shape
# -----------------------------------------------------------------------------
run "logging_invalid_lifecycle_rule_empty_id" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "  ", expiration_days = 400 },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_rule_duplicate_id" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "same", expiration_days = 400 },
      { id = "same", expiration_days = 500 },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_storage_class" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "archive", expiration_days = 400, transitions = [{ storage_class = "GLACIER_DEEP", days = 30 }] },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_fractional_day" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "archive", expiration_days = 400.5 },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_transition_days_not_ascending" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      {
        id              = "archive"
        expiration_days = 400
        transitions = [
          { storage_class = "GLACIER", days = 90 },
          { storage_class = "DEEP_ARCHIVE", days = 30 },
        ]
      },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_expiration_before_last_transition" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      {
        id              = "archive"
        expiration_days = 60
        transitions     = [{ storage_class = "DEEP_ARCHIVE", days = 90 }]
      },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_noncurrent_expiration_before_last_transition" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      {
        id                                 = "archive"
        noncurrent_version_expiration_days = 60
        noncurrent_version_transitions     = [{ storage_class = "GLACIER", days = 90 }]
      },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_prefix_and_tags_together" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "both", prefix = "cloudtrail/", tags = { a = "b" }, expiration_days = 400 },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_empty_tag_map" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "empty-tags", tags = {}, expiration_days = 400 },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_expiration_and_delete_marker" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "both-expirations", expiration_days = 400, expired_object_delete_marker = true },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
run "logging_invalid_lifecycle_rule_without_action" {
  command = plan
  variables {
    central_log_bucket_lifecycle_rules = [
      { id = "does-nothing", prefix = "cloudtrail/" },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
# The same guard the derived lifecycle inputs carry, per rule: an expiration
# below the retention period deletes the log objects
# early, and no plan would report the gap.
run "logging_invalid_lifecycle_expiration_below_log_retention" {
  command = plan
  variables {
    log_retention_days = 2555
    central_log_bucket_lifecycle_rules = [
      { id = "too-short", expiration_days = 1000 },
    ]
  }
  expect_failures = [var.central_log_bucket_lifecycle_rules]
}
# The counter-example: an expiration equal to the retention period passes.
# Without it the guard could be tightened to "strictly greater" unnoticed.
run "logging_lifecycle_expiration_equal_to_log_retention_is_accepted" {
  command = plan
  variables {
    log_retention_days = 2555
    central_log_bucket_lifecycle_rules = [
      { id = "exactly-the-retention", expiration_days = 2555 },
    ]
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.central_logs.rule[0].expiration).days == 2555
    error_message = "An expiration equal to log_retention_days must be accepted and reach the resource."
  }
}
# A rule set without its bucket is an input without a reader. Each of the three
# gated buckets carries the same binding, so each gets its own run.
run "logging_invalid_access_logs_rules_without_bucket" {
  command = plan
  variables {
    enable_separate_access_logs_bucket = false
    access_logs_bucket_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }
  expect_failures = [var.access_logs_bucket_lifecycle_rules]
}
run "logging_invalid_elb_log_rules_without_bucket" {
  command = plan
  variables {
    enable_elb_log_bucket = false
    elb_log_bucket_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }
  expect_failures = [var.elb_log_bucket_lifecycle_rules]
}
run "logging_invalid_vpc_flow_logs_rules_without_bucket" {
  command = plan
  variables {
    enable_vpc_flow_logs_bucket = false
    vpc_flow_logs_bucket_lifecycle_rules = [
      { id = "orphan", expiration_days = 400 },
    ]
  }
  expect_failures = [var.vpc_flow_logs_bucket_lifecycle_rules]
}

# -----------------------------------------------------------------------------
# Scenario 6: Bucket and KMS policy attachments and overrides
# -----------------------------------------------------------------------------

# Without the attachment and override inputs, every bucket policy and the key
# policy stay exactly the generated documents — no user statement appears.
run "regression_bucket_policy_defaults_keep_the_generated_documents" {
  command = plan

  # The policy documents interpolate the bucket ARNs, which are unknown in a
  # plan — the overrides pin them so the merged documents are observable.
  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    }
  }
  override_resource {
    target          = aws_s3_bucket.access_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-access-logs-210987654321-eu-central-1"
    }
  }
  override_resource {
    target          = aws_s3_bucket.elb_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-elb-logs-111111111111-eu-central-1"
    }
  }

  variables {
    enable_elb_log_bucket              = true
    enable_separate_access_logs_bucket = true
  }

  assert {
    condition     = length([for s in jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement : s if try(s.Sid, "") == "AWSCloudTrailWrite"]) == 1
    error_message = "The generated central log bucket policy must keep its CloudTrail delivery statement."
  }

  assert {
    condition     = [for s in local.central_log_bucket_base_policy.Statement : s if try(s.Sid, "") == "AWSGuardDutyPutObject"][0].Resource == "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1/guardduty/*"
    error_message = "With the default prefix the GuardDuty grant must stay at guardduty/*."
  }

  assert {
    condition     = aws_s3_object.guardduty_export_marker[0].key == "guardduty/"
    error_message = "With the default prefix the GuardDuty export folder marker must sit at guardduty/."
  }

  assert {
    condition     = length(jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement) == length(local.central_log_bucket_base_policy.Statement)
    error_message = "Without attachments the central log bucket policy must carry exactly the generated statements."
  }

  assert {
    condition     = length(jsondecode(aws_s3_bucket_policy.access_logs[0].policy).Statement) == length(local.access_logs_bucket_base_policy.Statement)
    error_message = "Without attachments the access logs bucket policy must carry exactly the generated statements."
  }

  assert {
    condition     = length(jsondecode(aws_s3_bucket_policy.elb_logs[0].policy).Statement) == length(local.elb_log_bucket_base_policy.Statement)
    error_message = "Without attachments the ELB log bucket policy must carry exactly the generated statements."
  }

  assert {
    condition     = !strcontains(aws_kms_key.log_bucket.policy, "UserSuppliedStatement")
    error_message = "Without attachments the key policy must not carry a user statement."
  }
}

# Attachments reach every document: the user statements land after the
# generated ones, in list order — the merge is deterministic.
run "logging_policy_attachments_reach_the_documents" {
  command = plan

  # Same overrides as the defaults run: pinned bucket ARNs keep the merged
  # documents observable during the plan.
  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    }
  }
  override_resource {
    target          = aws_s3_bucket.access_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-access-logs-210987654321-eu-central-1"
    }
  }
  override_resource {
    target          = aws_s3_bucket.elb_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-elb-logs-111111111111-eu-central-1"
    }
  }

  variables {
    enable_elb_log_bucket              = true
    enable_separate_access_logs_bucket = true
    central_log_bucket_policies = {
      s3_attachments = [
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"ExtraCentralOne\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:DeleteObject\",\"Resource\":\"*\"}]}",
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"ExtraCentralTwo\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutBucketAcl\",\"Resource\":\"*\"}]}",
      ]
      kms_attachments = [
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"ExtraKeyStatement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111111111111:role/Auditor\"},\"Action\":\"kms:DescribeKey\",\"Resource\":\"*\"}]}",
      ]
    }
    access_logs_bucket_policies = {
      s3_attachments = [
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"ExtraAccessLogs\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:DeleteObject\",\"Resource\":\"*\"}]}",
      ]
    }
    elb_log_bucket_policies = {
      s3_attachments = [
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"ExtraElbLogs\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:DeleteObject\",\"Resource\":\"*\"}]}",
      ]
    }
  }

  assert {
    condition     = jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement[length(jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement) - 2].Sid == "ExtraCentralOne"
    error_message = "The first attachment statement must sit directly after the generated statements of the central log bucket policy."
  }

  assert {
    condition     = jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement[length(jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement) - 1].Sid == "ExtraCentralTwo"
    error_message = "The second attachment statement must sit last in the central log bucket policy — list order is the merge order."
  }

  assert {
    condition     = length([for s in jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement : s if try(s.Sid, "") == "AWSCloudTrailWrite"]) == 1
    error_message = "The generated statements must survive the merge unchanged."
  }

  assert {
    condition     = strcontains(aws_kms_key.log_bucket.policy, "ExtraKeyStatement")
    error_message = "The KMS attachment statement must reach the key policy."
  }

  assert {
    condition     = jsondecode(aws_s3_bucket_policy.access_logs[0].policy).Statement[length(jsondecode(aws_s3_bucket_policy.access_logs[0].policy).Statement) - 1].Sid == "ExtraAccessLogs"
    error_message = "The attachment statement must reach the access logs bucket policy."
  }

  assert {
    condition     = jsondecode(aws_s3_bucket_policy.elb_logs[0].policy).Statement[length(jsondecode(aws_s3_bucket_policy.elb_logs[0].policy).Statement) - 1].Sid == "ExtraElbLogs"
    error_message = "The attachment statement must reach the ELB log bucket policy."
  }
}

# An override replaces the generated document entirely — with the explicit
# confirmation switch set.
run "logging_policy_override_replaces_the_generated_document" {
  command = plan

  # The override document is config-known, but the bucket resource still plans
  # with an unknown ARN feeding the generated locals — pinning it keeps every
  # assertion evaluable.
  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    }
  }

  variables {
    allow_bucket_policy_overrides = true
    central_log_bucket_policies = {
      s3_override  = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"TheOnlyStatement\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
      kms_override = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"TheOnlyKeyStatement\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::111111111111:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"}]}"
    }
  }

  assert {
    condition     = length(jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement) == 1
    error_message = "The override must be the whole bucket policy — the generated statements fall away."
  }

  assert {
    condition     = jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement[0].Sid == "TheOnlyStatement"
    error_message = "The override document must reach the bucket policy."
  }

  assert {
    condition     = !strcontains(aws_s3_bucket_policy.central_logs.policy, "AWSCloudTrailWrite")
    error_message = "No generated statement may survive an override."
  }

  assert {
    condition     = length(jsondecode(aws_kms_key.log_bucket.policy).Statement) == 1
    error_message = "The KMS override must be the whole key policy."
  }

  assert {
    condition     = jsondecode(aws_kms_key.log_bucket.policy).Statement[0].Sid == "TheOnlyKeyStatement"
    error_message = "The KMS override document must reach the key policy."
  }
}

# An override without the confirmation switch is rejected in the plan.
run "logging_policy_override_without_confirmation_rejected" {
  command = plan

  variables {
    central_log_bucket_policies = {
      s3_override = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  expect_failures = [var.central_log_bucket_policies]
}

# A document that does not decode is rejected in the plan.
run "logging_policy_attachment_not_json_rejected" {
  command = plan

  variables {
    central_log_bucket_policies = {
      s3_attachments = ["not a json document"]
    }
  }

  expect_failures = [var.central_log_bucket_policies]
}

# A decodable document without a Statement list is rejected in the plan.
run "logging_policy_attachment_without_statement_list_rejected" {
  command = plan

  variables {
    central_log_bucket_policies = {
      kms_attachments = ["{\"Version\":\"2012-10-17\",\"Statement\":{\"Sid\":\"NotAList\"}}"]
    }
  }

  expect_failures = [var.central_log_bucket_policies]
}

# Documents for a bucket whose toggle is off would silently do nothing and are
# rejected — the same binding the lifecycle rule sets carry.
run "logging_access_logs_policies_without_bucket_rejected" {
  command = plan

  variables {
    enable_separate_access_logs_bucket = false
    access_logs_bucket_policies = {
      s3_attachments = ["{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Orphan\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:DeleteObject\",\"Resource\":\"*\"}]}"]
    }
  }

  expect_failures = [var.access_logs_bucket_policies]
}

run "logging_elb_policies_without_bucket_rejected" {
  command = plan

  variables {
    enable_elb_log_bucket = false
    elb_log_bucket_policies = {
      s3_attachments = ["{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Orphan\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:DeleteObject\",\"Resource\":\"*\"}]}"]
    }
  }

  expect_failures = [var.elb_log_bucket_policies]
}

# -----------------------------------------------------------------------------
# Scenario 7: CloudTrail fine-tuning per account trail and org trail scope
# -----------------------------------------------------------------------------

# A trail without the fine-tuning fields keeps its plan — multi-region,
# global service events included, no management selector, no insights, no
# CloudWatch delivery; the org trail keeps its scope with the settings unset.
run "regression_account_trail_defaults_keep_the_plan" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "workload-trail" },
    ]
  }

  assert {
    condition     = aws_cloudtrail.account_trails["workload-trail"].is_multi_region_trail == true
    error_message = "An account trail without multi_region must stay a multi-region trail — the resource default."
  }

  assert {
    condition     = aws_cloudtrail.account_trails["workload-trail"].include_global_service_events == true
    error_message = "An account trail without include_global_service_events must keep including global service events."
  }

  assert {
    condition     = length(aws_cloudtrail.account_trails["workload-trail"].advanced_event_selector) == 0
    error_message = "An account trail without management_events must carry no management event selector — the default."
  }

  assert {
    condition     = length(aws_cloudtrail.account_trails["workload-trail"].insight_selector) == 0
    error_message = "An account trail without insights must carry no insight selector."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.account_trails) == 0
    error_message = "No per-trail log group may exist without send_to_cloudwatch_logs."
  }

  assert {
    condition     = length(aws_iam_role.account_trails_cloudwatch) == 0
    error_message = "No per-trail delivery role may exist without send_to_cloudwatch_logs."
  }

  assert {
    condition     = aws_cloudtrail.org_trail.is_multi_region_trail == true && aws_cloudtrail.org_trail.include_global_service_events == true
    error_message = "The organization trail must keep its region scope while cloudtrail_org_trail_settings is unset."
  }
}

# The fine-tuning fields reach the trail: insights, management scope, region scope and
# the CloudWatch delivery with its own log group and role.
run "logging_account_trail_fine_tuning_reaches_the_trail" {
  command = plan

  variables {
    cloudwatch_log_group_retention = 90
    cloudtrail_account_trails = [
      {
        name                          = "audit-trail"
        s3_key_prefix                 = "audit"
        multi_region                  = false
        include_global_service_events = false
        management_events             = "ReadOnly"
        insights                      = ["ApiCallRateInsight", "ApiErrorRateInsight"]
        send_to_cloudwatch_logs       = true
        cloudwatch_logs_retention     = 30
      },
    ]
  }

  assert {
    condition     = aws_cloudtrail.account_trails["audit-trail"].is_multi_region_trail == false
    error_message = "multi_region = false must reach the trail."
  }

  assert {
    condition     = aws_cloudtrail.account_trails["audit-trail"].include_global_service_events == false
    error_message = "include_global_service_events = false must reach the trail."
  }

  assert {
    condition     = aws_cloudtrail.account_trails["audit-trail"].s3_key_prefix == "audit"
    error_message = "The S3 key prefix must reach the trail."
  }

  assert {
    condition     = length([for s in aws_cloudtrail.account_trails["audit-trail"].advanced_event_selector : s if s.name == "ManagementEvents"]) == 1
    error_message = "management_events must add a management event selector."
  }

  assert {
    condition = anytrue([
      for s in aws_cloudtrail.account_trails["audit-trail"].advanced_event_selector :
      anytrue([for f in s.field_selector : f.field == "readOnly" && tolist(f.equals) == tolist(["true"])])
      if s.name == "ManagementEvents"
    ])
    error_message = "ReadOnly must narrow the management selector via the readOnly field."
  }

  assert {
    condition     = length(aws_cloudtrail.account_trails["audit-trail"].insight_selector) == 2
    error_message = "Both insight types must reach the trail."
  }

  assert {
    condition     = aws_cloudwatch_log_group.account_trails["audit-trail"].name == "/aws/cloudtrail/audit-trail"
    error_message = "The per-trail log group must carry the trail's name."
  }

  assert {
    condition     = aws_cloudwatch_log_group.account_trails["audit-trail"].retention_in_days == 30
    error_message = "The per-trail retention must reach the log group — independent of the org trail's 90 days."
  }

  assert {
    condition     = length(aws_iam_role.account_trails_cloudwatch) == 1 && length(aws_iam_role_policy.account_trails_cloudwatch) == 1
    error_message = "The delivery role and its policy must exist for the opting trail."
  }
}

# The management scope All records both directions — no readOnly narrowing.
run "logging_account_trail_management_all_has_no_readonly_field" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "all-events-trail", management_events = "All" },
    ]
  }

  assert {
    condition = !anytrue([
      for s in aws_cloudtrail.account_trails["all-events-trail"].advanced_event_selector :
      anytrue([for f in s.field_selector : f.field == "readOnly"])
    ])
    error_message = "All must record both directions — a readOnly field would narrow the selector."
  }

  assert {
    condition     = length(aws_cloudtrail.account_trails["all-events-trail"].advanced_event_selector) == 1
    error_message = "All must still add the management event selector."
  }
}

# The org trail scope reaches the resource.
run "logging_org_trail_settings_reach_the_trail" {
  command = plan

  variables {
    cloudtrail_org_trail_settings = {
      multi_region                  = false
      include_global_service_events = false
    }
  }

  assert {
    condition     = aws_cloudtrail.org_trail.is_multi_region_trail == false
    error_message = "cloudtrail_org_trail_settings.multi_region must reach the organization trail."
  }

  assert {
    condition     = aws_cloudtrail.org_trail.include_global_service_events == false
    error_message = "cloudtrail_org_trail_settings.include_global_service_events must reach the organization trail."
  }
}

# An unknown insight type is rejected in the plan.
run "logging_account_trail_invalid_insight_rejected" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "bad-insight", insights = ["ApiVolumeInsight"] },
    ]
  }

  expect_failures = [var.cloudtrail_account_trails]
}

# A duplicate insight type is rejected in the plan.
run "logging_account_trail_duplicate_insight_rejected" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "double-insight", insights = ["ApiCallRateInsight", "ApiCallRateInsight"] },
    ]
  }

  expect_failures = [var.cloudtrail_account_trails]
}

# An unknown management scope is rejected in the plan.
run "logging_account_trail_invalid_management_scope_rejected" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "bad-scope", management_events = "ReadWrite" },
    ]
  }

  expect_failures = [var.cloudtrail_account_trails]
}

# The delivery toggle without its retention is rejected — the pair belongs
# together.
run "logging_account_trail_delivery_without_retention_rejected" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "no-retention", send_to_cloudwatch_logs = true },
    ]
  }

  expect_failures = [var.cloudtrail_account_trails]
}

# A retention without the delivery toggle would silently do nothing and is
# rejected.
run "logging_account_trail_retention_without_delivery_rejected" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "orphan-retention", cloudwatch_logs_retention = 30 },
    ]
  }

  expect_failures = [var.cloudtrail_account_trails]
}

# A retention outside the CloudWatch value set is rejected.
run "logging_account_trail_invalid_retention_rejected" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      { name = "odd-retention", send_to_cloudwatch_logs = true, cloudwatch_logs_retention = 42 },
    ]
  }

  expect_failures = [var.cloudtrail_account_trails]
}

# A delivering trail whose name would push the role past the IAM limit is
# rejected in the plan — the apply would fail on the role otherwise.
run "logging_account_trail_delivery_name_too_long_rejected" {
  command = plan

  variables {
    cloudtrail_account_trails = [
      {
        name                      = "a-trail-name-that-is-far-too-long-for-an-iam-role-suffix"
        send_to_cloudwatch_logs   = true
        cloudwatch_logs_retention = 30
      },
    ]
  }

  expect_failures = [var.cloudtrail_account_trails]
}

# -----------------------------------------------------------------------------
# Scenario 8: Structured log exclusions and the account-wide subscription
# -----------------------------------------------------------------------------
# The mock provider pins account 111111111111, region eu-central-1; the
# variables block pins no organizational unit. Every scope assertion below
# reads against those values.

# Without the exclusion and account-subscription inputs, the subscriptions and
# the pipeline keep their plan and no account policy exists.
run "regression_exclusion_defaults_keep_the_subscriptions" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      { name = "forward-cloudtrail", log_group_name = "/aws/cloudtrail/org", filter_pattern = "" },
    ]
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 1
    error_message = "Without exclusion rules every subscription must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_log_account_policy.subscription) == 0
    error_message = "No account-wide subscription policy may exist while the input is unset."
  }
}

# A rule scoped to this account excludes by name pattern; scope mismatches
# keep the subscription.
run "logging_exclusion_rules_filter_by_scope_and_pattern" {
  command = plan

  variables {
    deployment_organizational_unit = "Security"
    cloudwatch_log_subscriptions = [
      { name = "forward-lambda", log_group_name = "/aws/lambda/ingest", filter_pattern = "" },
      { name = "forward-rds", log_group_name = "/aws/rds/audit", filter_pattern = "" },
      { name = "forward-vpc", log_group_name = "/vpc/flow", filter_pattern = "" },
      { name = "forward-ecs", log_group_name = "/aws/ecs/app", filter_pattern = "" },
    ]
    cloudwatch_log_exclusion_rules = [
      # Applies: this account, prefix pattern — drops forward-lambda.
      { accounts = ["111111111111"], log_group_names = ["/aws/lambda/*"] },
      # Applies: this OU, exact name — drops forward-rds.
      { organizational_units = ["Security"], log_group_names = ["/aws/rds/audit"] },
      # Does not apply: other account.
      { accounts = ["222222222222"], log_group_names = ["/vpc/*"] },
      # Does not apply: other region.
      { regions = ["us-east-1"], exclude_all = true },
    ]
  }

  assert {
    condition     = !contains(keys(aws_cloudwatch_log_subscription_filter.this), "forward-lambda")
    error_message = "A prefix pattern of an applicable rule must drop the matching subscription."
  }

  assert {
    condition     = !contains(keys(aws_cloudwatch_log_subscription_filter.this), "forward-rds")
    error_message = "An exact name of an applicable OU rule must drop the matching subscription."
  }

  assert {
    condition     = contains(keys(aws_cloudwatch_log_subscription_filter.this), "forward-vpc")
    error_message = "A rule scoped to another account must not drop this deployment's subscription."
  }

  assert {
    condition     = contains(keys(aws_cloudwatch_log_subscription_filter.this), "forward-ecs")
    error_message = "A rule scoped to another region must not drop this deployment's subscription."
  }
}

# exclude_all drops every subscription of a matching scope.
run "logging_exclusion_exclude_all_drops_everything_in_scope" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      { name = "forward-one", log_group_name = "/aws/one", filter_pattern = "" },
      { name = "forward-two", log_group_name = "/aws/two", filter_pattern = "" },
    ]
    cloudwatch_log_exclusion_rules = [
      { regions = ["eu-central-1"], exclude_all = true },
    ]
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 0
    error_message = "exclude_all of an applicable rule must drop every subscription."
  }
}

# An OU rule that names another unit leaves this deployment alone.
run "logging_exclusion_other_ou_stays_silent" {
  command = plan

  variables {
    deployment_organizational_unit = "Security"
    cloudwatch_log_subscriptions = [
      { name = "forward-one", log_group_name = "/aws/one", filter_pattern = "" },
    ]
    cloudwatch_log_exclusion_rules = [
      { organizational_units = ["Workloads"], exclude_all = true },
    ]
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 1
    error_message = "A rule scoped to another organizational unit must not drop this deployment's subscriptions."
  }
}

# The account-wide subscription reaches its policy; with an empty destination
# it stands up the module-managed pipeline.
run "logging_account_subscription_reaches_the_policy" {
  command = plan

  variables {
    cloudwatch_log_account_subscription = {
      enabled            = true
      selection_criteria = "LogGroupName NOT IN [\"/aws/lambda/noisy\"]"
    }
  }

  assert {
    condition     = length(aws_cloudwatch_log_account_policy.subscription) == 1
    error_message = "The enabled account-wide subscription must create its policy."
  }

  assert {
    condition     = aws_cloudwatch_log_account_policy.subscription[0].policy_type == "SUBSCRIPTION_FILTER_POLICY"
    error_message = "The account policy must be a subscription filter policy."
  }

  assert {
    condition     = aws_cloudwatch_log_account_policy.subscription[0].selection_criteria == "LogGroupName NOT IN [\"/aws/lambda/noisy\"]"
    error_message = "The selection criteria must reach the policy."
  }

  assert {
    condition     = length(aws_kinesis_stream.cw_to_s3) == 1
    error_message = "An account subscription with an empty destination must stand up the module-managed Kinesis pipeline."
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 0
    error_message = "The account policy replaces no per-log-group filter — none were configured."
  }

  # Default: the literal the module wrote before policy_name existed, so a
  # production plan stays empty.
  assert {
    condition     = aws_cloudwatch_log_account_policy.subscription[0].policy_name == "tlz-account-log-subscription"
    error_message = "Without policy_name the account policy must keep the default name tlz-account-log-subscription."
  }
}

# Reach: PutAccountPolicy is an upsert keyed by the policy name and an account
# holds one subscription filter policy per region, so a live apply-test scopes
# the name — a collision with a live policy then fails loudly (LimitExceeded)
# instead of adopting and deleting it.
run "logging_account_subscription_policy_name_reaches_the_policy" {
  command = plan

  variables {
    cloudwatch_log_account_subscription = {
      enabled     = true
      policy_name = "tlz-l4test-account-log-subscription"
    }
  }

  assert {
    condition     = aws_cloudwatch_log_account_policy.subscription[0].policy_name == "tlz-l4test-account-log-subscription"
    error_message = "cloudwatch_log_account_subscription.policy_name must reach the account policy."
  }
}

# A malformed account ID would silently never match and is rejected.
run "logging_exclusion_invalid_account_rejected" {
  command = plan

  variables {
    cloudwatch_log_exclusion_rules = [
      { accounts = ["Security"], exclude_all = true },
    ]
  }

  expect_failures = [var.cloudwatch_log_exclusion_rules]
}

# A malformed region would silently never match and is rejected.
run "logging_exclusion_invalid_region_rejected" {
  command = plan

  variables {
    cloudwatch_log_exclusion_rules = [
      { regions = ["EU-CENTRAL-1"], exclude_all = true },
    ]
  }

  expect_failures = [var.cloudwatch_log_exclusion_rules]
}

# exclude_all beside name selectors is rejected — one of the two would
# silently win.
run "logging_exclusion_exclude_all_with_names_rejected" {
  command = plan

  variables {
    cloudwatch_log_exclusion_rules = [
      { exclude_all = true, log_group_names = ["/aws/one"] },
    ]
  }

  expect_failures = [var.cloudwatch_log_exclusion_rules]
}

# An entry that excludes nothing is rejected.
run "logging_exclusion_entry_without_effect_rejected" {
  command = plan

  variables {
    cloudwatch_log_exclusion_rules = [
      { accounts = ["111111111111"] },
    ]
  }

  expect_failures = [var.cloudwatch_log_exclusion_rules]
}

# A padded organizational unit would silently never match and is rejected.
run "logging_exclusion_padded_ou_rejected" {
  command = plan

  variables {
    cloudwatch_log_exclusion_rules = [
      { organizational_units = [" Security"], exclude_all = true },
    ]
  }

  expect_failures = [var.cloudwatch_log_exclusion_rules]
}

# A padded deployment OU would silently never match and is rejected.
run "logging_padded_deployment_ou_rejected" {
  command = plan

  variables {
    deployment_organizational_unit = "Security "
  }

  expect_failures = [var.deployment_organizational_unit]
}

# Selection criteria outside the one supported form are rejected.
run "logging_account_subscription_invalid_criteria_rejected" {
  command = plan

  variables {
    cloudwatch_log_account_subscription = {
      enabled            = true
      selection_criteria = "LogGroupNamePrefix IN [\"/aws/\"]"
    }
  }

  expect_failures = [var.cloudwatch_log_account_subscription]
}

# Values on a disabled account subscription would silently do nothing and are
# rejected.
run "logging_account_subscription_criteria_without_enable_rejected" {
  command = plan

  variables {
    cloudwatch_log_account_subscription = {
      selection_criteria = "LogGroupName NOT IN [\"/aws/lambda/noisy\"]"
    }
  }

  expect_failures = [var.cloudwatch_log_account_subscription]
}

run "logging_account_subscription_policy_name_without_enable_rejected" {
  command = plan

  variables {
    cloudwatch_log_account_subscription = {
      policy_name = "tlz-l4test-account-log-subscription"
    }
  }

  expect_failures = [var.cloudwatch_log_account_subscription]
}

# The CloudWatch Logs account-policy naming rule: aws/ is reserved.
run "logging_account_subscription_reserved_policy_name_rejected" {
  command = plan

  variables {
    cloudwatch_log_account_subscription = {
      enabled     = true
      policy_name = "aws/account-log-subscription"
    }
  }

  expect_failures = [var.cloudwatch_log_account_subscription]
}

# -----------------------------------------------------------------------------
# Kinesis/Firehose archive pipeline tuning — defaults, reach and rejection
# -----------------------------------------------------------------------------

# A pipeline without kinesis_pipeline_config keeps the production values —
# 24 h retention, on-demand capacity, 64 MiB/60 s buffer, no compression, no
# file extension, the default error prefix — and
# carries the native decompression chain (Decompression before
# MetadataExtraction, no Lambda): CloudWatch Logs delivers gzip, and without
# a decompressor every record would land under the error prefix.
run "regression_kinesis_pipeline_defaults_keep_the_plan" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].retention_period == 24
    error_message = "The stream retention must default to 24 hours."
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].stream_mode_details[0].stream_mode == "ON_DEMAND"
    error_message = "The stream must default to on-demand capacity mode."
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].shard_count == null
    error_message = "An on-demand stream must not carry a shard count."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].buffering_size == 64 && aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].buffering_interval == 60
    error_message = "The delivery buffer must default to 64 MiB / 60 s."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].compression_format == "UNCOMPRESSED"
    error_message = "The delivery must default to uncompressed output."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].file_extension == null
    error_message = "No file extension must be set by default."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].error_output_prefix == "cloudwatch-logs-errors/!{firehose:error-output-type}/"
    error_message = "The error prefix must keep its default value."
  }

  assert {
    condition     = length(aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors) == 2
    error_message = "The default pipeline must carry exactly the Decompression and MetadataExtraction processors."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[0].type == "Decompression"
    error_message = "The native Decompression processor must run first by default — CloudWatch Logs delivers gzip."
  }

  assert {
    condition = anytrue([
      for p in aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[0].parameters :
      p.parameter_name == "CompressionFormat" && p.parameter_value == "GZIP"
    ])
    error_message = "The Decompression processor must name the GZIP format of CloudWatch Logs subscription records."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[1].type == "MetadataExtraction"
    error_message = "MetadataExtraction must remain the partitioning processor after decompression."
  }

  assert {
    condition = anytrue([
      for p in aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[1].parameters :
      p.parameter_name == "MetadataExtractionQuery" && p.parameter_value == "{account_id:.owner,log_group:.logGroup}"
    ])
    error_message = "The default JQ query must read the CloudWatch Logs envelope fields (owner, logGroup) — the reshaped account_id/log_group fields only exist behind the Lambda processor."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].prefix == "cloudwatch-logs/!{partitionKeyFromQuery:account_id}/eu-central-1/!{partitionKeyFromQuery:log_group}/"
    error_message = "The default archive prefix must pin the deployment region statically — the CloudWatch Logs envelope carries no region field to extract."
  }

  assert {
    condition     = length(aws_lambda_function.firehose_processor) == 0 && length(aws_iam_role.firehose_processor) == 0
    error_message = "No processor Lambda and no processor role must exist by default."
  }
}

# Reach: every tuning attribute lands on its resource.
run "logging_kinesis_pipeline_tuning_reaches_the_resources" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
    kinesis_pipeline_config = {
      kinesis_retention_hours             = 168
      kinesis_stream_mode                 = "PROVISIONED"
      kinesis_shard_count                 = 4
      firehose_buffering_size_mb          = 128
      firehose_buffering_interval_seconds = 300
      firehose_compression_format         = "GZIP"
      firehose_file_extension             = ".json.gz"
      firehose_error_output_prefix        = "archive-errors/!{firehose:error-output-type}/"
    }
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].retention_period == 168
    error_message = "The retention must reach the stream."
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].stream_mode_details[0].stream_mode == "PROVISIONED" && aws_kinesis_stream.cw_to_s3[0].shard_count == 4
    error_message = "Capacity mode and shard count must reach the stream."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].buffering_size == 128 && aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].buffering_interval == 300
    error_message = "The buffering values must reach the delivery stream."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].compression_format == "GZIP"
    error_message = "The compression format must reach the delivery stream."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].file_extension == ".json.gz"
    error_message = "The file extension must reach the delivery stream."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].error_output_prefix == "archive-errors/!{firehose:error-output-type}/"
    error_message = "The error prefix must reach the delivery stream."
  }
}

# A provisioned stream without an explicit shard count gets the smallest
# stream the API accepts.
run "logging_kinesis_provisioned_defaults_to_one_shard" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
    kinesis_pipeline_config = {
      kinesis_stream_mode = "PROVISIONED"
    }
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].shard_count == 1
    error_message = "A provisioned stream without a shard count must default to one shard."
  }
}

# Reach: the record-processor Lambda replaces the native decompression chain
# — it joins the pipeline in front of the MetadataExtraction processor, with
# its tuning as processor parameters, and no Decompression processor remains.
run "logging_kinesis_lambda_processor_reaches_the_stream" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
    kinesis_pipeline_config = {
      lambda_processor = {
        enabled                 = true
        buffer_size_mb          = 1
        buffer_interval_seconds = 120
        retries                 = 5
      }
    }
  }

  assert {
    condition     = length(aws_lambda_function.firehose_processor) == 1 && length(aws_iam_role.firehose_processor) == 1 && length(aws_iam_role_policy.firehose_processor) == 1
    error_message = "Enabling the processor must create the Lambda, its role and its policy."
  }

  assert {
    condition     = length(aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors) == 2
    error_message = "The pipeline must carry the Lambda processor beside MetadataExtraction."
  }

  assert {
    condition = !anytrue([
      for p in aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors :
      p.type == "Decompression"
    ])
    error_message = "The Lambda processor must replace the native Decompression processor — decompressing twice would feed MetadataExtraction a double-processed record."
  }

  assert {
    condition = anytrue([
      for p in aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[1].parameters :
      p.parameter_name == "MetadataExtractionQuery" && p.parameter_value == "{account_id:.account_id,region:.region,log_group:.log_group}"
    ])
    error_message = "With the Lambda processor the JQ query must read the reshaped document fields (account_id, region, log_group)."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].prefix == "cloudwatch-logs/!{partitionKeyFromQuery:account_id}/!{partitionKeyFromQuery:region}/!{partitionKeyFromQuery:log_group}/"
    error_message = "With the Lambda processor the archive prefix must keep the query-based region — the reshaped document carries it."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[0].type == "Lambda"
    error_message = "The Lambda processor must run first — it decompresses what MetadataExtraction reads."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[1].type == "MetadataExtraction"
    error_message = "MetadataExtraction must remain the second processor."
  }

  assert {
    condition = anytrue([
      for p in aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[0].parameters :
      p.parameter_name == "BufferSizeInMBs" && p.parameter_value == "1"
    ])
    error_message = "The processor buffer size must reach the Lambda processor parameters."
  }

  assert {
    condition = anytrue([
      for p in aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[0].parameters :
      p.parameter_name == "BufferIntervalInSeconds" && p.parameter_value == "120"
    ])
    error_message = "The processor buffer interval must reach the Lambda processor parameters."
  }

  assert {
    condition = anytrue([
      for p in aws_kinesis_firehose_delivery_stream.cw_to_s3[0].extended_s3_configuration[0].processing_configuration[0].processors[0].parameters :
      p.parameter_name == "NumberOfRetries" && p.parameter_value == "5"
    ])
    error_message = "The processor retries must reach the Lambda processor parameters."
  }
}

run "logging_kinesis_retention_below_floor_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      kinesis_retention_hours = 12
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_kinesis_invalid_stream_mode_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      kinesis_stream_mode = "PROVISIONED_ON_DEMAND"
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_kinesis_shards_on_demand_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      kinesis_shard_count = 4
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_firehose_buffer_below_floor_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      firehose_buffering_size_mb = 0
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_firehose_interval_below_floor_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      firehose_buffering_interval_seconds = 30
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_firehose_invalid_compression_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      firehose_compression_format = "SNAPPY"
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_firehose_extension_without_dot_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      firehose_file_extension = "json.gz"
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_lambda_processor_tuning_without_enable_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      lambda_processor = {
        retries = 5
      }
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

run "logging_lambda_processor_buffer_above_ceiling_rejected" {
  command = plan

  variables {
    kinesis_pipeline_config = {
      lambda_processor = {
        enabled        = true
        buffer_size_mb = 5
      }
    }
  }

  expect_failures = [var.kinesis_pipeline_config]
}

# -----------------------------------------------------------------------------
# Fixed resource names of the Kinesis pipeline — overridable so a live
# apply-test can scope its own pipeline
# -----------------------------------------------------------------------------
# Nine names, one per create-only resource of kinesis-pipeline.tf: the stream,
# the delivery stream, the processor function and the three role/policy
# pairs. A non-default value must reach its resource — and for the function
# also its inline policy's logs grant, which is scoped to the function's own
# /aws/lambda/<name> log group — the defaults must stay the production names,
# and the six guardrail-class names must refuse a value outside the tlz-
# namespace (no other check reads these names).

run "logging_kinesis_pipeline_name_overrides_reach_resources" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
    kinesis_pipeline_config = {
      lambda_processor = {
        enabled = true
      }
    }
    kinesis_stream_name              = "tlz-l4test-cw-to-s3-stream"
    firehose_delivery_stream_name    = "tlz-l4test-cw-to-s3-delivery"
    cw_to_kinesis_role_name          = "tlz-l4test-cw-to-kinesis-role"
    cw_to_kinesis_policy_name        = "l4test-cw-to-kinesis-policy"
    firehose_delivery_role_name      = "tlz-l4test-firehose-delivery-role"
    firehose_delivery_policy_name    = "l4test-firehose-delivery-policy"
    firehose_processor_function_name = "tlz-l4test-cw-log-processor"
    firehose_processor_role_name     = "tlz-l4test-cw-log-processor-role"
    firehose_processor_policy_name   = "l4test-cw-log-processor-policy"
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].name == "tlz-l4test-cw-to-s3-stream"
    error_message = "kinesis_stream_name must reach aws_kinesis_stream.cw_to_s3."
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].tags["Name"] == "tlz-l4test-cw-to-s3-stream"
    error_message = "The stream's Name tag must follow kinesis_stream_name."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].name == "tlz-l4test-cw-to-s3-delivery"
    error_message = "firehose_delivery_stream_name must reach aws_kinesis_firehose_delivery_stream.cw_to_s3."
  }

  assert {
    condition     = aws_iam_role.cw_to_kinesis[0].name == "tlz-l4test-cw-to-kinesis-role"
    error_message = "cw_to_kinesis_role_name must reach aws_iam_role.cw_to_kinesis."
  }

  assert {
    condition     = aws_iam_role_policy.cw_to_kinesis[0].name == "l4test-cw-to-kinesis-policy"
    error_message = "cw_to_kinesis_policy_name must reach aws_iam_role_policy.cw_to_kinesis."
  }

  assert {
    condition     = aws_iam_role.firehose_delivery[0].name == "tlz-l4test-firehose-delivery-role"
    error_message = "firehose_delivery_role_name must reach aws_iam_role.firehose_delivery."
  }

  assert {
    condition     = aws_iam_role_policy.firehose_delivery[0].name == "l4test-firehose-delivery-policy"
    error_message = "firehose_delivery_policy_name must reach aws_iam_role_policy.firehose_delivery."
  }

  assert {
    condition     = aws_lambda_function.firehose_processor[0].function_name == "tlz-l4test-cw-log-processor"
    error_message = "firehose_processor_function_name must reach aws_lambda_function.firehose_processor."
  }

  assert {
    condition     = aws_iam_role.firehose_processor[0].name == "tlz-l4test-cw-log-processor-role"
    error_message = "firehose_processor_role_name must reach aws_iam_role.firehose_processor."
  }

  assert {
    condition     = aws_iam_role_policy.firehose_processor[0].name == "l4test-cw-log-processor-policy"
    error_message = "firehose_processor_policy_name must reach aws_iam_role_policy.firehose_processor."
  }

  # The processor's logs grant is scoped to its own log group, which Lambda
  # derives from the function name: a renamed function whose policy still
  # named the old group could not write a single log line.
  assert {
    condition = anytrue([
      for s in jsondecode(aws_iam_role_policy.firehose_processor[0].policy).Statement :
      endswith(s.Resource, ":log-group:/aws/lambda/tlz-l4test-cw-log-processor:*")
      if try(s.Sid, "") == "CloudWatchLogsAccess"
    ])
    error_message = "The processor policy's CloudWatchLogsAccess grant must scope to /aws/lambda/<firehose_processor_function_name> — the log group Lambda derives from the configured function name."
  }
}

run "logging_kinesis_pipeline_name_defaults_keep_todays_literals" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
    kinesis_pipeline_config = {
      lambda_processor = {
        enabled = true
      }
    }
  }

  assert {
    condition     = aws_kinesis_stream.cw_to_s3[0].name == "tlz-cw-to-s3-stream" && aws_kinesis_stream.cw_to_s3[0].tags["Name"] == "tlz-cw-to-s3-stream"
    error_message = "The default kinesis_stream_name must stay tlz-cw-to-s3-stream — a changed default replaces the live stream."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.cw_to_s3[0].name == "tlz-cw-to-s3-delivery"
    error_message = "The default firehose_delivery_stream_name must stay tlz-cw-to-s3-delivery — a changed default replaces the live delivery stream."
  }

  assert {
    condition     = aws_iam_role.cw_to_kinesis[0].name == "tlz-cw-to-kinesis-role" && aws_iam_role_policy.cw_to_kinesis[0].name == "tlz-cw-to-kinesis-policy"
    error_message = "The default CloudWatch-to-Kinesis role and policy names must stay tlz-cw-to-kinesis-role / -policy."
  }

  assert {
    condition     = aws_iam_role.firehose_delivery[0].name == "tlz-firehose-delivery-role" && aws_iam_role_policy.firehose_delivery[0].name == "tlz-firehose-delivery-policy"
    error_message = "The default Firehose delivery role and policy names must stay tlz-firehose-delivery-role / -policy."
  }

  assert {
    condition     = aws_lambda_function.firehose_processor[0].function_name == "tlz-cw-log-processor" && aws_iam_role.firehose_processor[0].name == "tlz-cw-log-processor-role" && aws_iam_role_policy.firehose_processor[0].name == "tlz-cw-log-processor-policy"
    error_message = "The default processor function, role and policy names must stay tlz-cw-log-processor / -role / -policy."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_iam_role_policy.firehose_processor[0].policy).Statement :
      endswith(s.Resource, ":log-group:/aws/lambda/tlz-cw-log-processor:*")
      if try(s.Sid, "") == "CloudWatchLogsAccess"
    ])
    error_message = "The default processor policy must keep its grant on /aws/lambda/tlz-cw-log-processor — the template's former literal."
  }
}

# The six guardrail-class names refuse a value outside the tlz- namespace:
# a well-formed name that the guardrail patterns would not cover.
run "logging_kinesis_stream_name_outside_namespace_rejected" {
  command = plan

  variables {
    kinesis_stream_name = "l4test-cw-to-s3-stream"
  }

  expect_failures = [var.kinesis_stream_name]
}

run "logging_firehose_delivery_stream_name_outside_namespace_rejected" {
  command = plan

  variables {
    firehose_delivery_stream_name = "l4test-cw-to-s3-delivery"
  }

  expect_failures = [var.firehose_delivery_stream_name]
}

run "logging_cw_to_kinesis_role_name_outside_namespace_rejected" {
  command = plan

  variables {
    cw_to_kinesis_role_name = "l4test-cw-to-kinesis-role"
  }

  expect_failures = [var.cw_to_kinesis_role_name]
}

run "logging_firehose_delivery_role_name_outside_namespace_rejected" {
  command = plan

  variables {
    firehose_delivery_role_name = "l4test-firehose-delivery-role"
  }

  expect_failures = [var.firehose_delivery_role_name]
}

run "logging_firehose_processor_function_name_outside_namespace_rejected" {
  command = plan

  variables {
    firehose_processor_function_name = "l4test-cw-log-processor"
  }

  expect_failures = [var.firehose_processor_function_name]
}

run "logging_firehose_processor_role_name_outside_namespace_rejected" {
  command = plan

  variables {
    firehose_processor_role_name = "l4test-cw-log-processor-role"
  }

  expect_failures = [var.firehose_processor_role_name]
}

# The naming rules themselves: a stream name with a slash, a delivery stream
# name over 64 characters, a function name with a dot, a policy name with a
# space — each inside the namespace, so only the service rule can reject it.
run "logging_kinesis_stream_name_invalid_character_rejected" {
  command = plan

  variables {
    kinesis_stream_name = "tlz-cw/to/s3"
  }

  expect_failures = [var.kinesis_stream_name]
}

run "logging_firehose_delivery_stream_name_too_long_rejected" {
  command = plan

  variables {
    # 65 characters: tlz- plus 61 x — one over the Firehose ceiling of 64.
    firehose_delivery_stream_name = "tlz-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }

  expect_failures = [var.firehose_delivery_stream_name]
}

run "logging_firehose_processor_function_name_invalid_character_rejected" {
  command = plan

  variables {
    firehose_processor_function_name = "tlz-cw.log.processor"
  }

  expect_failures = [var.firehose_processor_function_name]
}

run "logging_kinesis_pipeline_policy_names_invalid_rejected" {
  command = plan

  variables {
    cw_to_kinesis_policy_name      = "has spaces"
    firehose_delivery_policy_name  = "has spaces"
    firehose_processor_policy_name = "has spaces"
  }

  expect_failures = [
    var.cw_to_kinesis_policy_name,
    var.firehose_delivery_policy_name,
    var.firehose_processor_policy_name,
  ]
}

# -----------------------------------------------------------------------------
# Kinesis pipeline gate
#
# The Kinesis pipeline gate counts the subscriptions that actually need the
# module-managed stream: entries surviving the exclusion lists AND carrying an
# empty destination_arn. A gate on the unfiltered input list would build the
# full pipeline — stream, delivery stream, two roles with policies — with no
# subscription filter feeding it when all subscriptions are excluded (or all
# bring their own destination).
# -----------------------------------------------------------------------------
run "regression_all_subscriptions_excluded_no_pipeline" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      { name = "forward-one", log_group_name = "/aws/one", filter_pattern = "" },
      { name = "forward-two", log_group_name = "/aws/two", filter_pattern = "" },
    ]
    cloudwatch_log_exclusions = ["/aws/one", "/aws/two"]
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 0
    error_message = "The exclusion list must drop both subscriptions."
  }

  assert {
    condition     = length(aws_kinesis_stream.cw_to_s3) == 0
    error_message = "No Kinesis stream may be built when the exclusion list drops every subscription."
  }

  assert {
    condition     = length(aws_kinesis_firehose_delivery_stream.cw_to_s3) == 0
    error_message = "No Firehose delivery stream may be built when the exclusion list drops every subscription."
  }

  assert {
    condition     = length(aws_iam_role.cw_to_kinesis) == 0 && length(aws_iam_role.firehose_delivery) == 0
    error_message = "No pipeline IAM roles may be built when the exclusion list drops every subscription."
  }

  assert {
    condition     = output.kinesis_stream_arn == ""
    error_message = "The stream output must stay empty while the pipeline is not built."
  }
}

run "regression_external_destinations_only_no_pipeline" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name            = "forward-external"
        log_group_name  = "/aws/cloudtrail/org"
        filter_pattern  = ""
        destination_arn = "arn:aws:kinesis:eu-central-1:333333333333:stream/external-stream"
      },
    ]
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 1
    error_message = "The subscription with its own destination must be created."
  }

  assert {
    condition     = aws_cloudwatch_log_subscription_filter.this["forward-external"].destination_arn == "arn:aws:kinesis:eu-central-1:333333333333:stream/external-stream"
    error_message = "The subscription must target its own destination."
  }

  assert {
    condition     = length(aws_kinesis_stream.cw_to_s3) == 0 && length(aws_kinesis_firehose_delivery_stream.cw_to_s3) == 0
    error_message = "No module-managed pipeline may be built when every subscription brings its own destination."
  }
}

# Counterpart: one surviving subscription with an empty destination keeps the
# pipeline, unaffected by excluded neighbours and external destinations.
run "regression_surviving_managed_subscription_keeps_pipeline" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      { name = "forward-managed", log_group_name = "/aws/cloudtrail/org", filter_pattern = "" },
      { name = "forward-excluded", log_group_name = "/aws/lambda/noisy", filter_pattern = "" },
      {
        name            = "forward-external"
        log_group_name  = "/aws/rds/audit"
        filter_pattern  = ""
        destination_arn = "arn:aws:kinesis:eu-central-1:333333333333:stream/external-stream"
      },
    ]
    cloudwatch_log_exclusions = ["/aws/lambda/noisy"]
  }

  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.this) == 2
    error_message = "The managed and the external subscription must survive the exclusion list."
  }

  assert {
    condition     = length(aws_kinesis_stream.cw_to_s3) == 1 && length(aws_kinesis_firehose_delivery_stream.cw_to_s3) == 1
    error_message = "One surviving subscription with an empty destination must keep the module-managed pipeline."
  }
}

# -----------------------------------------------------------------------------
# bucket_name_prefix — one knob moves the whole derived bucket family aside
# -----------------------------------------------------------------------------
# The five buckets the module can create derive their names from account and
# region, so no per-bucket name variable could default to the production
# value; the leading segment can. Four things must hold, each its own run below:
#   1. the DEFAULT "tlz-" reproduces every derived name byte for byte (a
#      changed default renames every live bucket on the next apply — the one
#      way this variable can do damage);
#   2. a non-default value reaches all five buckets AND the resources that
#      read their names (trail delivery, delivery channel, bucket policy,
#      replication destination, outputs) — a reader still holding the old
#      name would point a test at a live bucket;
#   3. an adopted_*_bucket_name wins over prefix + derivation (the adoption
#      variables name existing buckets and stay unpinned);
#   4. the validation refuses a value outside the tlz- namespace, one without
#      the trailing hyphen, and one too long for the 63-character S3 limit.

run "logging_bucket_name_prefix_default_keeps_todays_derived_names" {
  command = plan

  # The VPC flow logs replication rule validates the central bucket's ARN at
  # plan time; the mock provider would hand it a random string. Same override
  # as the other runs that enable that bucket — the ARN of the derived name.
  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    }
  }

  variables {
    enable_separate_access_logs_bucket = true
    enable_elb_log_bucket              = true
    enable_vpc_flow_logs_bucket        = true
    s3_replication_config = {
      destination_region = "eu-west-1"
    }
  }

  assert {
    condition     = var.bucket_name_prefix == "tlz-"
    error_message = "The default bucket_name_prefix must stay exactly tlz- — any other default renames every live bucket of every deployment on the next apply."
  }

  assert {
    condition     = aws_s3_bucket.central_logs.bucket == "tlz-central-logs-210987654321-eu-central-1"
    error_message = "Under the default prefix the central log bucket must keep tlz-central-logs-<log-archive>-<region> — the name the live bucket has."
  }

  assert {
    condition     = aws_s3_bucket.replication_dest[0].bucket == "tlz-central-logs-replica-210987654321-eu-west-1" && output.replication_dest_bucket_arn == "arn:aws:s3:::tlz-central-logs-replica-210987654321-eu-west-1"
    error_message = "Under the default prefix the replica bucket must keep tlz-central-logs-replica-<log-archive>-<destination-region>, and the ARN output must name it."
  }

  assert {
    condition     = aws_s3_bucket.access_logs[0].bucket == "tlz-access-logs-210987654321-eu-central-1"
    error_message = "Under the default prefix the access logs bucket must keep tlz-access-logs-<log-archive>-<region>."
  }

  assert {
    condition     = aws_s3_bucket.elb_logs[0].bucket == "tlz-elb-logs-111111111111-eu-central-1"
    error_message = "Under the default prefix the ELB log bucket must keep tlz-elb-logs-<account>-<region>."
  }

  assert {
    condition     = aws_s3_bucket.vpc_flow_logs[0].bucket == "tlz-vpc-flow-logs-111111111111-eu-central-1"
    error_message = "Under the default prefix the VPC flow logs bucket must keep tlz-vpc-flow-logs-<account>-<region>."
  }
}

run "logging_bucket_name_prefix_reaches_all_five_buckets_and_their_readers" {
  command = plan

  # Same plan-time ARN override as above, under the prefixed name: the
  # replication rule of the VPC flow logs bucket must then point at THIS ARN
  # (asserted below), which is what a scoped live test relies on.
  override_resource {
    target          = aws_s3_bucket.central_logs
    override_during = plan
    values = {
      arn = "arn:aws:s3:::tlz-l4test-central-logs-210987654321-eu-central-1"
    }
  }

  variables {
    bucket_name_prefix                 = "tlz-l4test-"
    enable_separate_access_logs_bucket = true
    enable_elb_log_bucket              = true
    enable_vpc_flow_logs_bucket        = true
    s3_replication_config = {
      destination_region = "eu-west-1"
    }
  }

  assert {
    condition     = aws_s3_bucket.central_logs.bucket == "tlz-l4test-central-logs-210987654321-eu-central-1"
    error_message = "bucket_name_prefix must lead the central log bucket name."
  }

  assert {
    condition     = aws_s3_bucket.replication_dest[0].bucket == "tlz-l4test-central-logs-replica-210987654321-eu-west-1"
    error_message = "bucket_name_prefix must lead the replica bucket name."
  }

  assert {
    condition     = aws_s3_bucket.access_logs[0].bucket == "tlz-l4test-access-logs-210987654321-eu-central-1"
    error_message = "bucket_name_prefix must lead the access logs bucket name."
  }

  assert {
    condition     = aws_s3_bucket.elb_logs[0].bucket == "tlz-l4test-elb-logs-111111111111-eu-central-1"
    error_message = "bucket_name_prefix must lead the ELB log bucket name."
  }

  assert {
    condition     = aws_s3_bucket.vpc_flow_logs[0].bucket == "tlz-l4test-vpc-flow-logs-111111111111-eu-central-1"
    error_message = "bucket_name_prefix must lead the VPC flow logs bucket name."
  }

  # Readers of the derived names follow them — none may still hold the
  # unprefixed literal, or a scoped test would write into a live bucket.
  assert {
    condition     = aws_cloudtrail.org_trail.s3_bucket_name == aws_s3_bucket.central_logs.id && aws_config_delivery_channel.this[0].s3_bucket_name == aws_s3_bucket.central_logs.id
    error_message = "The organization trail and the Config delivery channel must deliver into the prefixed central bucket, not into a literal name."
  }

  # central_log_bucket_name outputs the computed id, which the plan-time
  # override leaves to the mock; the replica ARN derives from the locals and
  # is known at plan.
  assert {
    condition     = output.replication_dest_bucket_arn == "arn:aws:s3:::tlz-l4test-central-logs-replica-210987654321-eu-west-1"
    error_message = "The replica ARN output must carry the prefixed name."
  }

  assert {
    condition     = one([for r in aws_s3_bucket_replication_configuration.central_logs[0].rule : r.destination[0].bucket]) == "arn:aws:s3:::tlz-l4test-central-logs-replica-210987654321-eu-west-1"
    error_message = "The replication rule must target the prefixed replica bucket — a rule still pointing at the unprefixed ARN would replicate a test's objects into a live bucket."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement :
      alltrue([
        for r in flatten([s.Resource]) :
        strcontains(r, "tlz-l4test-central-logs-210987654321-eu-central-1")
      ])
    ])
    error_message = "Every Resource of the central bucket policy must name the prefixed bucket — a statement still granting on the unprefixed ARN would attach a test's policy grants to the live bucket's name."
  }
}

run "logging_bucket_name_prefix_adoption_wins_over_prefix" {
  command = plan

  variables {
    bucket_name_prefix                 = "tlz-l4test-"
    adopted_central_log_bucket_name    = "existing-central-logs"
    enable_separate_access_logs_bucket = true
  }

  assert {
    condition     = aws_s3_bucket.central_logs.bucket == "existing-central-logs"
    error_message = "An adopted_central_log_bucket_name must win over prefix + derivation — the adoption variable names an existing bucket, whatever the prefix."
  }

  assert {
    condition     = aws_s3_bucket.access_logs[0].bucket == "tlz-l4test-access-logs-210987654321-eu-central-1"
    error_message = "A bucket without an adopted name must still take the prefix — adoption is per bucket, the prefix is per family."
  }
}

# The pin, all three parts: namespace, trailing hyphen, length.
run "logging_bucket_name_prefix_outside_namespace_rejected" {
  command = plan

  variables {
    bucket_name_prefix = "l4test-"
  }

  expect_failures = [var.bucket_name_prefix]
}

run "logging_bucket_name_prefix_without_trailing_hyphen_rejected" {
  command = plan

  variables {
    bucket_name_prefix = "tlz-l4test"
  }

  expect_failures = [var.bucket_name_prefix]
}

run "logging_bucket_name_prefix_too_long_rejected" {
  command = plan

  variables {
    # 16 characters: one over the limit that keeps the longest derived name
    # (central-logs-replica-<12 digits>-<14-character region>) within 63.
    bucket_name_prefix = "tlz-abcdefghijk-"
  }

  expect_failures = [var.bucket_name_prefix]
}

# -----------------------------------------------------------------------------
# Central log bucket policy — Macie classification export statements
# -----------------------------------------------------------------------------
# modules/security points aws_macie2_classification_export_configuration at
# the central log bucket (key_prefix macie/classification-results/). The
# export requires the bucket policy to grant the macie service principal
# s3:GetBucketLocation and s3:PutObject, scoped to the enabling account via
# aws:SourceAccount — same shape as the GuardDuty export statements. The
# policy string embeds the computed bucket ARN, so it is known only after
# (mocked) apply.

run "logging_central_bucket_policy_macie_export" {
  command = apply

  # The mock provider fills computed attributes with plain random strings.
  # Two of them feed arguments the AWS provider validates as ARNs at apply
  # time — pin those to well-formed ARNs.
  override_resource {
    target = aws_kms_key.log_bucket
    values = {
      arn = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000"
    }
  }

  override_resource {
    target = aws_iam_role.config_aggregator
    values = {
      arn = "arn:aws:iam::111111111111:role/tlz-config-aggregator"
    }
  }

  # A third computed attribute a postcondition reads: the organization trail
  # pins its returned ARN against the constructed local.org_trail_arn that
  # scopes the SNS topic policy and the bucket policy (cloudtrail.tf). A mock
  # random string would fail that pin for the wrong reason; the real ARN of
  # the default trail name in the mocked partition/region/account is this.
  override_resource {
    target = aws_cloudtrail.org_trail
    values = {
      arn = "arn:aws:cloudtrail:eu-central-1:111111111111:trail/tlz-org-trail"
    }
  }

  assert {
    condition = length([
      for s in jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement :
      s if s.Sid == "AWSMaciePutObject"
      && s.Principal.Service == "macie.amazonaws.com"
      && s.Action == "s3:PutObject"
      && endswith(s.Resource, "/macie/*")
      && s.Condition.StringEquals["aws:SourceAccount"] == "111111111111"
    ]) == 1
    error_message = "The central log bucket policy must grant macie s3:PutObject under the macie/ prefix, scoped to the enabling account via aws:SourceAccount."
  }

  assert {
    condition = length([
      for s in jsondecode(aws_s3_bucket_policy.central_logs.policy).Statement :
      s if s.Sid == "AWSMacieGetBucketLocation"
      && s.Principal.Service == "macie.amazonaws.com"
      && s.Action == "s3:GetBucketLocation"
      && s.Condition.StringEquals["aws:SourceAccount"] == "111111111111"
    ]) == 1
    error_message = "The central log bucket policy must grant macie s3:GetBucketLocation, scoped to the enabling account via aws:SourceAccount."
  }
}

# =============================================================================
# GuardDuty root-export remediation (guardduty_root_export_cleanup)
# =============================================================================
# While the export was broken, a workaround pointed the publishing destination
# at the bare bucket, so findings landed at the bucket root as AWSLogs/...
# outside every guardduty/-prefixed lifecycle rule. The variable builds one
# expiration rule per detector account under AWSLogs/<account-id>/GuardDuty/.
# -----------------------------------------------------------------------------

# Default: the variable is null and no cleanup rule exists — the derived plan
# of regression_lifecycle_defaults_keep_the_derived_plan stays untouched.
run "logging_guardduty_root_cleanup_off_by_default" {
  command = plan

  assert {
    condition = length([
      for r in aws_s3_bucket_lifecycle_configuration.central_logs.rule :
      r if startswith(r.id, "guardduty-root-export-cleanup-")
    ]) == 0
    error_message = "Without guardduty_root_export_cleanup no root-cleanup lifecycle rule may exist."
  }
}

# Explicit account ids: one rule per account, prefix pinned to the /GuardDuty/
# path segment, expiration and noncurrent expiration carry retention_days, and
# the derived log-retention rule stays in place (the cleanup is additive).
run "logging_guardduty_root_cleanup_rules" {
  command = plan

  variables {
    guardduty_root_export_cleanup = {
      retention_days = 30
      account_ids    = ["222222222222", "333333333333"]
    }
  }

  assert {
    condition = [
      for r in aws_s3_bucket_lifecycle_configuration.central_logs.rule :
      one(r.filter).prefix if startswith(r.id, "guardduty-root-export-cleanup-")
    ] == ["AWSLogs/222222222222/GuardDuty/", "AWSLogs/333333333333/GuardDuty/"]
    error_message = "Each account id must build exactly one cleanup rule whose prefix pins the AWSLogs/<account-id>/GuardDuty/ path — the /GuardDuty/ segment is what keeps account-trail keys (AWSLogs/<account>/CloudTrail/...) out of reach."
  }

  assert {
    condition = alltrue([
      for r in aws_s3_bucket_lifecycle_configuration.central_logs.rule :
      one(r.expiration).days == 30 && one(r.noncurrent_version_expiration).noncurrent_days == 30
      if startswith(r.id, "guardduty-root-export-cleanup-")
    ])
    error_message = "Every cleanup rule must expire current versions and noncurrent versions after retention_days — the bucket is versioned, and expiration alone would only hide the objects behind delete markers."
  }

  assert {
    condition = contains([
      for r in aws_s3_bucket_lifecycle_configuration.central_logs.rule : r.id
    ], "log-retention")
    error_message = "The cleanup rules are additive: the derived log-retention rule must stay in place."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.central_logs.rule) == 3
    error_message = "Two cleanup accounts plus the derived rule must yield exactly three rules — no rule may appear beyond the ones the inputs name."
  }
}

# Empty account_ids: the deploying account is the detector account of this
# landing zone (security and logging deploy with the same default provider),
# so its id is the default prefix segment.
run "logging_guardduty_root_cleanup_defaults_to_caller_account" {
  command = plan

  variables {
    guardduty_root_export_cleanup = {
      retention_days = 7
    }
  }

  assert {
    condition = [
      for r in aws_s3_bucket_lifecycle_configuration.central_logs.rule :
      one(r.filter).prefix if startswith(r.id, "guardduty-root-export-cleanup-")
    ] == ["AWSLogs/111111111111/GuardDuty/"]
    error_message = "With empty account_ids the cleanup rule must read the deploying account — the detector that exported the root findings lives there."
  }
}

# The cleanup stays additive even when an explicit rule set describes the
# bucket: it remediates a historical mistake and is driven by its own opt-in
# variable, not derived from the rule-set precedence.
run "logging_guardduty_root_cleanup_additive_to_explicit_rule_set" {
  command = plan

  variables {
    central_log_bucket_lifecycle_rules = [
      {
        id              = "whole-bucket"
        prefix          = ""
        expiration_days = 365
      }
    ]
    guardduty_root_export_cleanup = {
      retention_days = 14
      account_ids    = ["222222222222"]
    }
  }

  assert {
    condition = [
      for r in aws_s3_bucket_lifecycle_configuration.central_logs.rule : r.id
    ] == ["whole-bucket", "guardduty-root-export-cleanup-222222222222"]
    error_message = "The explicit rule set and the cleanup rule must both be present — the cleanup is additive in every lifecycle form of the bucket."
  }
}

# Validation: retention below one day is rejected.
run "logging_invalid_guardduty_root_cleanup_retention" {
  command = plan

  variables {
    guardduty_root_export_cleanup = {
      retention_days = 0
    }
  }

  expect_failures = [
    var.guardduty_root_export_cleanup,
  ]
}

# Validation: an account id that is not 12 digits builds a prefix that matches
# nothing and is rejected at plan time.
run "logging_invalid_guardduty_root_cleanup_account_id" {
  command = plan

  variables {
    guardduty_root_export_cleanup = {
      retention_days = 30
      account_ids    = ["12345"]
    }
  }

  expect_failures = [
    var.guardduty_root_export_cleanup,
  ]
}

# Validation: duplicate account ids would build duplicate rule ids, which S3
# rejects — the plan catches it first.
run "logging_invalid_guardduty_root_cleanup_duplicate_ids" {
  command = plan

  variables {
    guardduty_root_export_cleanup = {
      retention_days = 30
      account_ids    = ["222222222222", "222222222222"]
    }
  }

  expect_failures = [
    var.guardduty_root_export_cleanup,
  ]
}

# -----------------------------------------------------------------------------
# Silent fallback: subscription filter log group names
# -----------------------------------------------------------------------------
# A fallback such as try(aws_cloudwatch_log_group.cloudtrail[0].name, "") —
# with cloudwatch_log_group_retention = null — would swallow the missing log
# group and hand AWS an empty name: a plausible plan, InvalidParameterException
# at apply. Two layers reject that input class at plan time: the variable
# validation (fires first) and the resource precondition (defense in depth,
# pins the invariant if the validation is ever relaxed). This run pins the
# guard class: an empty log_group_name never reaches AWS.

run "logging_invalid_subscription_empty_log_group" {
  command = plan

  variables {
    cloudwatch_log_group_retention = null
    cloudwatch_log_subscriptions = [
      {
        name           = "silent-fallback"
        log_group_name = ""
        filter_pattern = ""
      },
    ]
  }

  expect_failures = [
    var.cloudwatch_log_subscriptions,
  ]
}

# Positive contract: the filter carries exactly the configured log group name —
# there is no fallback rewriting to the org-trail group, even when that group
# exists. A reappearing fallback expression would not change this value, but
# the run documents the contract the precondition enforces: the name comes
# from the entry, never from another resource.

run "logging_subscription_log_group_is_verbatim" {
  command = plan

  variables {
    cloudwatch_log_group_retention = 365
    cloudwatch_log_subscriptions = [
      {
        name           = "verbatim"
        log_group_name = "/aws/cloudtrail/tlz-org-trail"
        filter_pattern = ""
      },
    ]
  }

  assert {
    condition     = aws_cloudwatch_log_subscription_filter.this["verbatim"].log_group_name == "/aws/cloudtrail/tlz-org-trail"
    error_message = "The subscription filter must carry the configured log_group_name verbatim — no fallback substitution."
  }
}

# -----------------------------------------------------------------------------
# Data-protection log groups are resolved at plan time
# -----------------------------------------------------------------------------
# A group this module creates (an account trail's CloudWatch group) is taken
# from its resource and NOT read; every other name is read, so a group that
# does not exist fails the plan instead of PutDataProtectionPolicy at apply.
# The mock provider answers every read — pinned here is the wiring; the
# negative case is a provider error that cannot be shown offline.
run "logging_data_protection_log_groups_are_resolved_not_passed_raw" {
  command = plan

  variables {
    enable_cloudwatch_log_data_protection      = true
    cloudwatch_log_data_protection_identifiers = ["CreditCardNumber"]
    cloudtrail_account_trails = [
      { name = "tlz-account-trail", send_to_cloudwatch_logs = true, cloudwatch_logs_retention = 365 },
    ]
    cloudwatch_log_data_protection_log_groups = [
      "/aws/cloudtrail/tlz-account-trail",
      "/aws/lambda/tlz-custom",
    ]
  }

  assert {
    condition     = keys(data.aws_cloudwatch_log_group.data_protection_targets) == ["/aws/lambda/tlz-custom"]
    error_message = "Exactly the groups this module does not create must be read at plan time — the Lambda group yes, the account trail's group no."
  }

  assert {
    condition     = aws_cloudwatch_log_data_protection_policy.additional["/aws/cloudtrail/tlz-account-trail"].log_group_name == aws_cloudwatch_log_group.account_trails["tlz-account-trail"].name
    error_message = "The policy on an account trail's group must reference that log group resource (ordering), not the raw string."
  }

  assert {
    condition     = length(aws_cloudwatch_log_data_protection_policy.additional) == 2
    error_message = "Both listed groups must receive a policy."
  }
}

# The CloudTrail SNS topic name carries the tlz- namespace invariant like the
# other guardrail-class names of this module: ProtectSNSTopics protects only
# arn:*:sns:*:*:tlz-*, and the static prefix guard reads this validation as the
# pin of a variable-fed name. A well-formed SNS name outside the namespace
# must be refused; the empty string (SNS disabled) stays accepted — see
# logging_all_toggles_off.
run "logging_cloudtrail_sns_topic_name_outside_namespace_rejected" {
  command = plan

  variables {
    cloudtrail_sns_topic_name = "l4test-cloudtrail-notifications"
  }

  expect_failures = [var.cloudtrail_sns_topic_name]
}


# -----------------------------------------------------------------------------
# lambda_environment_kms_key_arn — reaches the processor Lambda's environment,
# grants it exactly kms:Decrypt on exactly that key, and stays inert when empty
# -----------------------------------------------------------------------------

# Empty case: a deployment that does not set the variable keeps its plan — no
# extra policy resource, kms_key_arn left null (not the empty string, which the provider
# would reject) so the function keeps the AWS-managed Lambda key.
run "logging_lambda_env_kms_empty_leaves_plan_unchanged" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
    kinesis_pipeline_config = {
      lambda_processor = {
        enabled = true
      }
    }
    lambda_environment_kms_key_arn = ""
  }

  assert {
    condition     = length(aws_iam_role_policy.firehose_processor_env_kms) == 0
    error_message = "An empty lambda_environment_kms_key_arn must create no extra IAM policy resource."
  }

  assert {
    condition     = aws_lambda_function.firehose_processor[0].kms_key_arn == null
    error_message = "An empty lambda_environment_kms_key_arn must leave kms_key_arn null on the processor Lambda, keeping the AWS-managed key — not the empty string, which the provider rejects."
  }
}

# Named case: the key reaches the function's environment encryption AND the
# execution role is granted exactly kms:Decrypt on exactly that key's ARN.
run "logging_lambda_env_kms_named_reaches_processor_and_grants_decrypt_only" {
  command = plan

  variables {
    cloudwatch_log_subscriptions = [
      {
        name           = "cloudtrail-to-kinesis"
        log_group_name = "/aws/cloudtrail/organization"
        filter_pattern = ""
      },
    ]
    kinesis_pipeline_config = {
      lambda_processor = {
        enabled = true
      }
    }
    lambda_environment_kms_key_arn = "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
  }

  assert {
    condition     = aws_lambda_function.firehose_processor[0].kms_key_arn == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb"
    error_message = "A named lambda_environment_kms_key_arn must reach the processor Lambda's kms_key_arn."
  }

  assert {
    condition     = length(aws_iam_role_policy.firehose_processor_env_kms) == 1
    error_message = "A named lambda_environment_kms_key_arn must create the processor's env-kms grant."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.firehose_processor_env_kms[0].policy).Statement[0].Action == "kms:Decrypt" &&
      jsondecode(aws_iam_role_policy.firehose_processor_env_kms[0].policy).Statement[0].Resource == "arn:aws:kms:eu-central-1:111111111111:key/aaaa-bbbb" &&
      jsondecode(aws_iam_role_policy.firehose_processor_env_kms[0].policy).Statement[0].Effect == "Allow"
    )
    error_message = "The grant must allow ONLY kms:Decrypt, and only on the named key's exact ARN — not a wider resource and not a wider action set."
  }

  assert {
    condition     = length(jsondecode(aws_iam_role_policy.firehose_processor_env_kms[0].policy).Statement) == 1
    error_message = "The grant must carry exactly one statement."
  }
}
