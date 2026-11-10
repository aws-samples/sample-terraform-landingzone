# =============================================================================
# CloudTrail — CloudWatch Log Group, IAM, Organization Trail, SNS, Account Trails
# =============================================================================

# --- Optional CloudWatch Log Group (only when cloudwatch_log_group_retention is set) ---

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count = var.cloudwatch_log_group_retention != null ? 1 : 0

  # Derived from the trail name, like the account trails' groups below: one
  # override moves the trail and its group together.
  name              = "/aws/cloudtrail/${var.cloudtrail_org_trail_name}"
  retention_in_days = var.cloudwatch_log_group_retention
  kms_key_id        = aws_kms_key.cloudwatch.arn
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  count = var.cloudwatch_log_group_retention != null ? 1 : 0

  name = var.cloudtrail_cloudwatch_role_name

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/cloudtrail-cloudwatch-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  count = var.cloudwatch_log_group_retention != null ? 1 : 0

  name = var.cloudtrail_cloudwatch_policy_name
  role = aws_iam_role.cloudtrail_cloudwatch[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/cloudtrail-cloudwatch-policy.json", {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.cloudtrail[0].arn
  })))
}

# --- IAM propagation delay (organization-trail delivery role) ---
# CreateTrail validates the delivery grant during the call, so the ordering edge
# on the trail below is not enough on its own: PutRolePolicy returns before the
# grant is globally visible to CloudTrail. Field evidence for this exact race is
# terraform-provider-aws issue #693, "CloudTrail resource creation failure when
# creating aws_iam_role and aws_iam_role_policy in single run", where the next
# run succeeds unchanged. Same duration as the barriers in control-tower,
# deployment-role and pipeline.
resource "time_sleep" "cloudtrail_cloudwatch_iam_propagation" {
  count = var.cloudwatch_log_group_retention != null ? 1 : 0

  create_duration = "30s"

  depends_on = [aws_iam_role_policy.cloudtrail_cloudwatch]
}

# --- Organization-wide CloudTrail Trail ---

locals {
  # The organization trail's ARN, built from its inputs so a resource whose
  # grant the trail is validated against can name the trail WITHOUT depending
  # on it (the SNS topic policy below, and the key policy's
  # AllowCloudTrailSnsTopicEncrypt statement in main.tf). Same construction as
  # the CloudTrail statements of the bucket policy template; the trail's
  # postcondition pins it to the ARN AWS actually returns.
  org_trail_arn = "${local.arn_prefix}:cloudtrail:${local.region}:${local.account_id}:trail/${var.cloudtrail_org_trail_name}"
}

resource "aws_cloudtrail" "org_trail" {
  name                          = var.cloudtrail_org_trail_name
  s3_bucket_name                = aws_s3_bucket.central_logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = var.cloudtrail_org_trail_settings.include_global_service_events
  is_multi_region_trail         = var.cloudtrail_org_trail_settings.multi_region
  is_organization_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.log_bucket.arn

  # SNS Topic — conditional on cloudtrail_sns_topic_name
  sns_topic_name = var.cloudtrail_sns_topic_name != "" ? aws_sns_topic.cloudtrail[0].arn : null

  # CloudWatch Log Group (conditional)
  cloud_watch_logs_group_arn = var.cloudwatch_log_group_retention != null ? "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*" : null
  cloud_watch_logs_role_arn  = var.cloudwatch_log_group_retention != null ? aws_iam_role.cloudtrail_cloudwatch[0].arn : null

  # Management Events (conditional on var.cloudtrail_management_events)
  dynamic "advanced_event_selector" {
    for_each = var.cloudtrail_management_events ? [1] : []
    content {
      name = "ManagementEvents"

      field_selector {
        field  = "eventCategory"
        equals = ["Management"]
      }
    }
  }

  # Data Events (S3) — conditional on var.cloudtrail_s3_data_events
  dynamic "advanced_event_selector" {
    for_each = var.cloudtrail_s3_data_events ? [1] : []
    content {
      name = "S3DataEvents"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
    }
  }

  # Data Events (Lambda) — conditional on var.cloudtrail_lambda_data_events
  dynamic "advanced_event_selector" {
    for_each = var.cloudtrail_lambda_data_events ? [1] : []
    content {
      name = "LambdaDataEvents"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::Lambda::Function"]
      }
    }
  }

  # Insight Selectors — conditional on var.cloudtrail_insights
  dynamic "insight_selector" {
    for_each = var.cloudtrail_insights
    content {
      insight_type = insight_selector.value
    }
  }

  # Pins local.org_trail_arn — the value the SNS topic policy, the bucket
  # policy template (by the same construction) and the key policy's
  # AllowCloudTrailSnsTopicEncrypt statement scope their CloudTrail grants to —
  # against the ARN AWS returns for this trail. A divergence would leave every
  # aws:SourceArn condition pointing at a trail that does not exist: CloudTrail
  # would then reject the trail on the S3 side and on the SNS side (the key
  # statement is validated by Create/UpdateTrail like the topic policy), and
  # publish nothing while the apply looked clean should only the topic policy
  # be affected. Evaluated after create/update, so a mocked plan cannot observe
  # it; a live apply does.
  lifecycle {
    postcondition {
      condition     = self.arn == local.org_trail_arn
      error_message = "The organization trail's ARN (${self.arn}) differs from the constructed local.org_trail_arn (${local.org_trail_arn}) that scopes the SNS topic policy, the bucket policy and the key policy's AllowCloudTrailSnsTopicEncrypt statement to this trail. Fix the construction; do not loosen the grants."
    }
  }

  # CreateTrail validates the CloudWatch delivery role during the call: it
  # assumes the role and checks the logs:CreateLogStream / PutLogEvents grant on
  # the log group, answering InvalidCloudWatchLogsRoleArnException or
  # InvalidCloudWatchLogsLogGroupArnException ("Access denied. Check the
  # permissions for your role") when the grant is not in place yet.
  # cloud_watch_logs_role_arn orders this after the ROLE, but that grant is the
  # role's inline POLICY — a separate resource above — so without the second edge
  # a fresh apply is free to call CreateTrail first. The provider retries those
  # two exceptions within a bounded propagation window, which is what has hidden
  # the missing edge so far. The bucket-policy edge is the same class for S3, and
  # the barrier covers the propagation delay the ordering edge cannot (see the
  # barrier's comment above for the field evidence).
  #
  # Create/UpdateTrail validates the SNS topic policy the same way — the third
  # instance of this class on one call, one resource type over: sns_topic_name
  # orders this after the TOPIC, but the SNS:Publish grant is the topic's
  # POLICY, aws_sns_topic_policy.cloudtrail below, a separate resource with no
  # edge to it. Unlike the two CloudWatch exceptions above, the provider does
  # NOT retry InsufficientSnsTopicPolicyException, so nothing masked the gap:
  # a live apply failed hard with "SNS Topic does not exist or the topic policy
  # is incorrect!" on the first run that set cloudtrail_sns_topic_name. The
  # edge was not merely missing, it was IMPOSSIBLE until the policy stopped
  # reading aws_cloudtrail.org_trail.arn — see the constructed trail ARN on the
  # policy for why that reference had to go. This is NOT a redundant edge —
  # do not tidy it away.
  #
  # No barrier on this edge, and deliberately: the two barriers above wait out
  # IAM's eventual consistency (PutRolePolicy returns before the grant is
  # visible to the validating service). An SNS topic policy is a RESOURCE
  # policy evaluated by SNS itself, and the only field evidence this class has
  # for it (issue #693 for IAM has no SNS counterpart) is the deterministic
  # reject above, which the ordering edge alone removes. Should a propagation
  # reject ever show up ordered, it is a NEW finding: add a barrier in the form
  # of the two above rather than widening this reasoning. Both SNS edges are
  # no-ops when cloudtrail_sns_topic_name is empty, because the policy then has
  # no instance.
  depends_on = [
    aws_s3_bucket_policy.central_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch,
    time_sleep.cloudtrail_cloudwatch_iam_propagation,
    aws_sns_topic_policy.cloudtrail,
  ]
}

# --- CloudTrail SNS Topic ---

resource "aws_sns_topic" "cloudtrail" {
  count = var.cloudtrail_sns_topic_name != "" ? 1 : 0

  name              = var.cloudtrail_sns_topic_name
  kms_master_key_id = aws_kms_key.log_bucket.arn
}

resource "aws_sns_topic_policy" "cloudtrail" {
  count = var.cloudtrail_sns_topic_name != "" ? 1 : 0

  arn = aws_sns_topic.cloudtrail[0].arn

  # The aws:SourceArn condition names the trail this topic serves. It is
  # CONSTRUCTED from the trail's name, not read from aws_cloudtrail.org_trail.arn:
  # that read would make the policy depend on the trail, while Create/UpdateTrail
  # validates this very policy during the call — so Terraform would have to
  # create the trail before the grant it is validated against, and the cycle
  # would leave no legal place for the ordering edge the trail carries. The bucket
  # policy scopes its CloudTrail grants to the same trail the same way
  # (s3-central-logs-bucket-policy.json, org_trail_name), and AWS's own SNS
  # topic-policy guidance writes the trail ARN out literally. The shape is
  # deterministic — partition, region, account, name — and the trail's
  # postcondition below fails the apply should the constructed value ever
  # diverge from the ARN AWS returns.
  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/sns-cloudtrail-topic-policy.json", {
    dns_suffix     = local.dns_suffix
    sns_topic_arn  = aws_sns_topic.cloudtrail[0].arn
    cloudtrail_arn = local.org_trail_arn
  })))
}

# --- Account-Level CloudTrail Trails ---

# Per-trail CloudWatch delivery: an own log group per trail that opts in, plus
# the delivery role. Group and role follow the pattern of the organization
# trail — the trust and permission documents are the same templates, and the
# role principal stays partition-aware through local.dns_suffix.

resource "aws_cloudwatch_log_group" "account_trails" {
  for_each = { for trail in var.cloudtrail_account_trails : trail.name => trail if trail.send_to_cloudwatch_logs }

  name              = "/aws/cloudtrail/${each.value.name}"
  retention_in_days = each.value.cloudwatch_logs_retention
  kms_key_id        = aws_kms_key.cloudwatch.arn
}

resource "aws_iam_role" "account_trails_cloudwatch" {
  for_each = { for trail in var.cloudtrail_account_trails : trail.name => trail if trail.send_to_cloudwatch_logs }

  name = "tlz-cloudtrail-cw-${each.value.name}"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/cloudtrail-cloudwatch-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "account_trails_cloudwatch" {
  for_each = { for trail in var.cloudtrail_account_trails : trail.name => trail if trail.send_to_cloudwatch_logs }

  name = "tlz-cloudtrail-cw-${each.value.name}"
  role = aws_iam_role.account_trails_cloudwatch[each.key].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/logging/cloudtrail-cloudwatch-policy.json", {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.account_trails[each.key].arn
  })))
}

# --- IAM propagation delay (account-trail delivery roles) ---
# Same call, same race and same duration as the organization trail's barrier
# above. One barrier for all opted-in account trails: they are created in the
# same apply, so a shared wait costs nothing a per-trail wait would save. It
# exists only when at least one trail opts into CloudWatch delivery — the same
# condition that creates the roles and policies it waits for.
resource "time_sleep" "account_trails_cloudwatch_iam_propagation" {
  count = length({ for trail in var.cloudtrail_account_trails : trail.name => trail if trail.send_to_cloudwatch_logs }) > 0 ? 1 : 0

  create_duration = "30s"

  depends_on = [aws_iam_role_policy.account_trails_cloudwatch]
}

resource "aws_cloudtrail" "account_trails" {
  for_each = { for trail in var.cloudtrail_account_trails : trail.name => trail }

  name                          = each.value.name
  s3_bucket_name                = each.value.s3_bucket_name != "" ? each.value.s3_bucket_name : aws_s3_bucket.central_logs.id
  s3_key_prefix                 = each.value.s3_key_prefix
  enable_log_file_validation    = each.value.enable_log_file_validation
  is_organization_trail         = false
  is_multi_region_trail         = each.value.multi_region
  include_global_service_events = each.value.include_global_service_events
  kms_key_id                    = aws_kms_key.log_bucket.arn

  # CloudWatch delivery (conditional per trail) — group and role together,
  # like the organization trail.
  cloud_watch_logs_group_arn = each.value.send_to_cloudwatch_logs ? "${aws_cloudwatch_log_group.account_trails[each.key].arn}:*" : null
  cloud_watch_logs_role_arn  = each.value.send_to_cloudwatch_logs ? aws_iam_role.account_trails_cloudwatch[each.key].arn : null

  # Management events (conditional per trail): All records both directions,
  # ReadOnly/WriteOnly narrow the scope via the readOnly field. null, the
  # default, adds no management event selector.
  dynamic "advanced_event_selector" {
    for_each = each.value.management_events != null ? [each.value.management_events] : []
    content {
      name = "ManagementEvents"

      field_selector {
        field  = "eventCategory"
        equals = ["Management"]
      }

      dynamic "field_selector" {
        for_each = advanced_event_selector.value == "All" ? [] : [advanced_event_selector.value == "ReadOnly" ? "true" : "false"]
        content {
          field  = "readOnly"
          equals = [field_selector.value]
        }
      }
    }
  }

  dynamic "advanced_event_selector" {
    for_each = each.value.advanced_event_selectors
    content {
      name = lookup(advanced_event_selector.value, "name", null)

      dynamic "field_selector" {
        for_each = lookup(advanced_event_selector.value, "field_selectors", [])
        content {
          field           = field_selector.value.field
          equals          = lookup(field_selector.value, "equals", null)
          not_equals      = lookup(field_selector.value, "not_equals", null)
          starts_with     = lookup(field_selector.value, "starts_with", null)
          not_starts_with = lookup(field_selector.value, "not_starts_with", null)
          ends_with       = lookup(field_selector.value, "ends_with", null)
          not_ends_with   = lookup(field_selector.value, "not_ends_with", null)
        }
      }
    }
  }

  # Insight selectors of this trail — the same value set as the organization
  # trail.
  dynamic "insight_selector" {
    for_each = each.value.insights
    content {
      insight_type = insight_selector.value
    }
  }

  # Same synchronous role validation as the organization trail: the per-trail
  # delivery grant lives in aws_iam_role_policy.account_trails_cloudwatch, not in
  # the role the trail references. depends_on is resource-level, so every account
  # trail waits for every delivery policy — harmless, they are created in the same
  # apply, and a trail that does not send to CloudWatch has nothing of its own to
  # wait for. Both edges are no-ops when no trail opts in, because neither the
  # policy nor the barrier then has an instance.
  depends_on = [
    aws_s3_bucket_policy.central_logs,
    aws_iam_role_policy.account_trails_cloudwatch,
    time_sleep.account_trails_cloudwatch_iam_propagation,
  ]
}

# --- CloudWatch Log Subscription Filters ---

resource "aws_cloudwatch_log_subscription_filter" "this" {
  for_each = local.effective_subscriptions

  name            = each.value.name
  log_group_name  = each.value.log_group_name
  filter_pattern  = each.value.filter_pattern
  destination_arn = each.value.destination_arn != "" ? each.value.destination_arn : aws_kinesis_stream.cw_to_s3[0].arn
  role_arn        = each.value.destination_arn != "" ? null : aws_iam_role.cw_to_kinesis[0].arn

  # The variable validation on cloudwatch_log_subscriptions already rejects an
  # empty log_group_name at plan time. This precondition pins the same
  # invariant at the resource: a fallback such as
  # try(aws_cloudwatch_log_group.cloudtrail[0].name, "") — with
  # cloudwatch_log_group_retention = null — would swallow the missing log
  # group and hand AWS an empty name, a plausible-looking plan that answers
  # InvalidParameterException only at apply. If the validation is ever
  # relaxed, this fails the plan instead of letting that through silently.
  lifecycle {
    precondition {
      condition     = each.value.log_group_name != ""
      error_message = "cloudwatch_log_subscriptions entry '${each.value.name}': log_group_name is empty. There is no implicit fallback to the org-trail log group — name the target log group explicitly."
    }
  }

  # PutSubscriptionFilter validates delivery synchronously: CloudWatch Logs
  # assumes role_arn and puts a test record on the stream, answering
  # InvalidParameterException "Could not deliver test message to specified
  # Kinesis stream" when kinesis:PutRecord is not granted yet. role_arn orders
  # this after the ROLE; the grant is aws_iam_role_policy.cw_to_kinesis
  # (kinesis-pipeline.tf), a separate resource, so the edge must be explicit.
  # The provider retries that error, which is what has masked the missing edge
  # here; the account-wide policy below has no such retry and failed live.
  # A filter with an external destination_arn does not use the module-managed
  # role: if another subscription enables the pipeline it still waits for the
  # policy (a harmless ordering on a resource created anyway), and if none
  # does, the policy and the barrier have no instances and both edges are no-ops.
  depends_on = [
    aws_cloudwatch_log_group.cloudtrail,
    aws_iam_role_policy.cw_to_kinesis,
    time_sleep.cw_to_kinesis_iam_propagation,
  ]
}

# --- Account-Wide CloudWatch Log Subscription Filter Policy ---
#
# Where the filters above attach to one named log group each, this policy
# covers every log group of the account, minus what selection_criteria
# excludes. Destination and role follow the same contract: an empty
# destination_arn targets the module-managed Kinesis stream with its delivery
# role; an external destination brings its own permissions.

resource "aws_cloudwatch_log_account_policy" "subscription" {
  count = var.cloudwatch_log_account_subscription.enabled ? 1 : 0

  # Overridable: PutAccountPolicy is an upsert keyed by this name, and an
  # account holds one subscription filter policy per region — see the
  # variable for why a live apply-test must scope this.
  policy_name = var.cloudwatch_log_account_subscription.policy_name
  policy_type = "SUBSCRIPTION_FILTER_POLICY"
  scope       = "ALL"

  policy_document = jsonencode(merge(
    {
      DestinationArn = (
        var.cloudwatch_log_account_subscription.destination_arn != ""
        ? var.cloudwatch_log_account_subscription.destination_arn
        : aws_kinesis_stream.cw_to_s3[0].arn
      )
      FilterPattern = var.cloudwatch_log_account_subscription.filter_pattern
    },
    var.cloudwatch_log_account_subscription.destination_arn == ""
    ? { RoleArn = aws_iam_role.cw_to_kinesis[0].arn }
    : {},
  ))

  selection_criteria = var.cloudwatch_log_account_subscription.selection_criteria

  # PutAccountPolicy VERIFIES delivery synchronously: CloudWatch Logs assumes
  # RoleArn and puts a real test record on DestinationArn during the API call,
  # and rejects the policy when that fails. RoleArn orders this after the ROLE
  # only; the kinesis:PutRecord grant is the role's inline POLICY,
  # aws_iam_role_policy.cw_to_kinesis in kinesis-pipeline.tf, a separate
  # resource — so a fresh apply was free to call PutAccountPolicy first, and a
  # live apply did exactly that: "no identity-based policy allows the
  # kinesis:PutRecord action" while the policy document grants it. Unlike the
  # trail and the filter above, the provider does not retry this call, so the
  # missing edge surfaced here. This is NOT a redundant edge — do not tidy it
  # away. Same class as the sns_forwarder ordering in modules/monitoring.
  #
  # depends_on alone is NOT sufficient here, which is why the barrier is in the
  # list: the grant comes unconditionally from the in-repo policy template
  # whenever the module-managed stream is the destination, but PutAccountPolicy
  # is validated against IAM the moment it is called, and PutRolePolicy returns
  # before the grant is globally visible. An external destination_arn brings its
  # own permissions — the role is then not referenced, and both edges are at most
  # a harmless wait on resources another subscription needs anyway.
  depends_on = [
    aws_iam_role_policy.cw_to_kinesis,
    time_sleep.cw_to_kinesis_iam_propagation,
  ]
}
