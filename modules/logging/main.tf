# Logging module: CloudTrail, Config Recorder/Aggregator, central S3 bucket

# --- Partition Detection ---
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  dns_suffix = data.aws_partition.current.dns_suffix
  arn_prefix = "arn:${local.partition}"

  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  # Adoption (docs/resource-adoption.md): a configured name of an existing
  # bucket wins over the derived name, so an imported bucket keeps its
  # identity and every downstream reader (policies, outputs, delivery
  # channels) follows it. Empty keeps the derived name and the existing plan.
  # The derived name's leading segment is var.bucket_name_prefix (default
  # tlz-, i.e. the production name); a live apply-test moves
  # the whole bucket family aside through it.
  bucket_name = (
    var.adopted_central_log_bucket_name != ""
    ? var.adopted_central_log_bucket_name
    : "${var.bucket_name_prefix}central-logs-${var.log_archive_account_id}-${local.region}"
  )

  # Structured exclusion rules: an entry applies when every given scope
  # matches this deployment — account, organizational unit, region; an unset
  # scope matches. What an applicable entry excludes is decided per log group
  # below.
  applicable_exclusion_rules = [
    for rule in var.cloudwatch_log_exclusion_rules : rule
    if(length(rule.accounts) == 0 || contains(rule.accounts, local.account_id))
    && (length(rule.organizational_units) == 0 || contains(rule.organizational_units, var.deployment_organizational_unit))
    && (length(rule.regions) == 0 || contains(rule.regions, local.region))
  ]

  # CloudWatch Log Exclusions — a subscription is dropped when the flat name
  # list carries its log group, or when an applicable structured rule excludes
  # everything (exclude_all) or names the group: exactly, or by prefix with a
  # trailing *.
  effective_subscriptions = {
    for sub in var.cloudwatch_log_subscriptions :
    sub.name => sub
    if !contains(var.cloudwatch_log_exclusions, sub.log_group_name) &&
    !anytrue([
      for rule in local.applicable_exclusion_rules :
      rule.exclude_all || anytrue([
        for pattern in rule.log_group_names :
        pattern == sub.log_group_name ||
        (endswith(pattern, "*") && startswith(sub.log_group_name, trimsuffix(pattern, "*")))
      ])
    ])
  }

  # The pipeline is built only when something actually flows through it:
  # a subscription that survives the exclusion lists AND
  # targets the module-managed stream (empty destination_arn), or the
  # account-wide subscription doing the same. Counting the unfiltered input
  # list would build the six pipeline resources with no subscription filter
  # left to feed them — infrastructure with running costs and no data flow.
  kinesis_pipeline_enabled = (
    length([
      for name, sub in local.effective_subscriptions : name
      if sub.destination_arn == ""
    ]) > 0 ||
    (var.cloudwatch_log_account_subscription.enabled && var.cloudwatch_log_account_subscription.destination_arn == "")
  )

  # S3 replication — determine if replication is enabled
  replication_enabled = (
    var.s3_replication_config.destination_region != "" &&
    var.s3_replication_config.destination_region != null
  )

  # Destination bucket name: auto-generate if no ARN provided. Same prefix as
  # the central bucket, so a live apply-test scopes the replica with it.
  replication_dest_bucket_name = "${var.bucket_name_prefix}central-logs-replica-${var.log_archive_account_id}-${var.s3_replication_config.destination_region}"

  # Effective destination bucket ARN
  replication_dest_bucket_arn = (
    local.replication_enabled
    ? (var.s3_replication_config.destination_bucket_arn != "" && var.s3_replication_config.destination_bucket_arn != null
      ? var.s3_replication_config.destination_bucket_arn
    : "arn:${local.partition}:s3:::${local.replication_dest_bucket_name}")
    : ""
  )

  # Whether we need to auto-create the destination bucket
  create_replication_dest_bucket = (
    local.replication_enabled &&
    (var.s3_replication_config.destination_bucket_arn == "" || var.s3_replication_config.destination_bucket_arn == null)
  )

  # Effective replica KMS key: an explicitly passed ARN wins, otherwise the key
  # created alongside the auto-created destination bucket. one() keeps the
  # expression valid when no key exists — variables.tf requires
  # destination_kms_key_arn for an externally provided destination bucket.
  replication_dest_kms_key_arn = (
    local.replication_enabled
    ? (var.s3_replication_config.destination_kms_key_arn != "" && var.s3_replication_config.destination_kms_key_arn != null
      ? var.s3_replication_config.destination_kms_key_arn
    : one(aws_kms_key.replication_dest[*].arn))
    : ""
  )

  # Effective replication rules — default to a single catch-all rule if none specified
  replication_rules = (
    local.replication_enabled
    ? (length(var.s3_replication_config.rules) > 0
      ? var.s3_replication_config.rules
    : [{ id = "replicate-all", prefix = "", status = "Enabled", priority = 0 }])
    : []
  )

  # Per-prefix lifecycle rules
  lifecycle_rules = var.s3_lifecycle_rules != null ? {
    for key, cfg in {
      cloudtrail  = { prefix = "cloudtrail/", config = var.s3_lifecycle_rules.cloudtrail }
      config      = { prefix = "config/", config = var.s3_lifecycle_rules.config }
      access_logs = { prefix = "s3-access-logs/", config = var.s3_lifecycle_rules.access_logs }
      } : key => {
      prefix                       = cfg.prefix
      retention_days               = cfg.config != null ? cfg.config.retention_days : null
      glacier_transition_days      = cfg.config != null ? cfg.config.glacier_transition_days : null
      deep_archive_transition_days = cfg.config != null ? cfg.config.deep_archive_transition_days : null
    }
  } : {}
  # --- Configurable lifecycle rule sets ---
  # One derivation per bucket, so every aws_s3_bucket_lifecycle_configuration
  # reads the same shape and the *_explicit_* flag beside it decides whether the
  # derived default rule still applies. A rule set of length zero is a
  # deliberate "no rules" and stays distinguishable from null, which means "keep
  # deriving" — that is why the flag tests for null and not for emptiness.
  explicit_central_log_lifecycle   = var.central_log_bucket_lifecycle_rules != null
  explicit_access_logs_lifecycle   = var.access_logs_bucket_lifecycle_rules != null
  explicit_elb_log_lifecycle       = var.elb_log_bucket_lifecycle_rules != null
  explicit_vpc_flow_logs_lifecycle = var.vpc_flow_logs_bucket_lifecycle_rules != null
  central_log_lifecycle_rules      = coalesce(var.central_log_bucket_lifecycle_rules, [])
  access_logs_lifecycle_rules      = coalesce(var.access_logs_bucket_lifecycle_rules, [])
  elb_log_lifecycle_rules          = coalesce(var.elb_log_bucket_lifecycle_rules, [])
  vpc_flow_logs_lifecycle_rules    = coalesce(var.vpc_flow_logs_bucket_lifecycle_rules, [])

  # --- GuardDuty root-export remediation rules ---
  # One prefix per detector account, each pinning the /GuardDuty/ path segment
  # literally: S3 lifecycle filters know no wildcards, and only the account-id
  # segment varies between deployments. An empty account_ids reads the
  # deploying account — the security module creates its detector with the same
  # default provider, so that is the account whose id GuardDuty wrote into the
  # root keys.
  guardduty_root_cleanup_rules = var.guardduty_root_export_cleanup == null ? {} : {
    for id in(
      length(var.guardduty_root_export_cleanup.account_ids) > 0
      ? var.guardduty_root_export_cleanup.account_ids
      : [local.account_id]
    ) : id => "AWSLogs/${id}/GuardDuty/"
  }

  # --- Accounts whose finding exports write to the central bucket ---
  # The deploying account owns the GuardDuty publishing destination and the
  # Macie classification export unless the finding consumers run in the Audit
  # account; then that account writes too. One list feeds the aws:SourceAccount
  # conditions of the bucket policy and the bucket key policy. A single entry
  # renders as a plain string, more than one as a JSON array, so a deployment
  # without further source accounts keeps its documents byte-identical.
  export_source_accounts      = distinct(concat([local.account_id], var.finding_export_source_account_ids))
  export_source_accounts_json = length(local.export_source_accounts) == 1 ? jsonencode(local.export_source_accounts[0]) : jsonencode(local.export_source_accounts)

  # Macie's KMS calls carry the export configuration or the classification job
  # as aws:SourceArn — the key statement names both forms per account (Macie
  # user guide, "Storing and retaining sensitive data discovery results").
  macie_export_source_arns_json = jsonencode(flatten([
    for id in local.export_source_accounts : [
      "${local.arn_prefix}:macie2:*:${id}:export-configuration:*",
      "${local.arn_prefix}:macie2:*:${id}:classification-job/*",
    ]
  ]))

  # --- KMS Policy Objects (externalized concat wrappers) ---
  #
  # The template carries TWO CloudTrail statements, and they are not a
  # duplicate: CloudTrail reaches this key on two paths that carry different
  # request context, and a condition that fits one deterministically denies the
  # other.
  #
  #   AllowCloudTrailEncrypt (S3 delivery): every GenerateDataKey CloudTrail or
  #   S3 issues for a log/digest object carries the trail ARN as the
  #   aws:cloudtrail:arn encryption context (documented in "How AWS CloudTrail
  #   uses AWS KMS"), so the statement is pinned to that context.
  #
  #   AllowCloudTrailSnsTopicEncrypt (SNS notifications): aws_sns_topic.cloudtrail
  #   is encrypted with this key, and the KMS calls behind a CloudTrail publish
  #   carry no aws:cloudtrail:arn encryption context the S3-side statement
  #   could match — CloudTrail documents that context only for its S3 delivery
  #   calls, and with only the S3-side statement in place a live apply is
  #   rejected by Create/UpdateTrail with InsufficientSnsTopicPolicyException
  #   "The customer-managed key (CMK) associated with this SNS topic ... does
  #   not allow access to CloudTrail" (a mocked plan evaluates no key policy,
  #   so the module tests cannot see that gap).
  #   CloudTrail's SNS guidance requires exactly kms:GenerateDataKey* and
  #   kms:Decrypt for the CloudTrail service principal on the topic's key, and
  #   that is all the statement grants — no DescribeKey, no Encrypt, no kms:*.
  #
  #   Its scope is aws:SourceArn == local.org_trail_arn, the tightest condition
  #   the documentation supports for this path: CloudTrail's key-policy guide
  #   states the value of aws:SourceArn on CloudTrail's KMS requests "is always
  #   the trail ARN" and recommends it as the confused-deputy guard, and SNS's
  #   own guidance for event sources publishing to encrypted topics recommends
  #   the same aws:SourceArn shape on the key statement. The organization trail
  #   is the only trail with an SNS topic (account trails carry none), so the
  #   exact ARN — not trail/* — is the right width; the trail's postcondition in
  #   cloudtrail.tf fails the apply should the constructed value ever diverge
  #   from the ARN AWS returns. Rejected alternatives: kms:ViaService (KMS
  #   documents it for forward-access sessions of a principal in the account,
  #   not for a service-principal publisher — an unsourced deny risk), an SNS
  #   encryption-context key (none is documented), and a bare unconditioned
  #   grant (the documented example, but wider than the source ARN allows).
  #   aws:SourceAccount adds nothing the ARN does not already carry.
  #
  #   Do NOT fold the two statements together or loosen the encryption-context
  #   condition to make the SNS path pass: the S3 narrowing is real and the
  #   second statement is what the SNS path needs.
  log_bucket_kms_policy = {
    Version = "2012-10-17"
    Statement = concat(
      jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-log-bucket-key-policy.json", {
        arn_prefix                    = local.arn_prefix
        account_id                    = local.account_id
        dns_suffix                    = local.dns_suffix
        region                        = local.region
        org_trail_arn                 = local.org_trail_arn
        export_source_accounts_json   = local.export_source_accounts_json
        macie_export_source_arns_json = local.macie_export_source_arns_json
      })).Statement,
      length(var.kms_key_administrators) > 0 ? [
        jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-key-administrators-statement.json", {
          kms_key_administrators_json = jsonencode(var.kms_key_administrators)
        })),
      ] : [],
      # User-supplied statements come last, in list order — the merge is
      # deterministic and the generated statements keep their positions.
      flatten([
        for doc in var.central_log_bucket_policies.kms_attachments :
        jsondecode(doc).Statement
      ]),
    )
  }

  management_kms_policy = {
    Version = "2012-10-17"
    Statement = concat(
      jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-management-key-policy.json", {
        arn_prefix = local.arn_prefix
        account_id = local.account_id
      })).Statement,
      length(var.kms_key_administrators) > 0 ? [
        jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-key-administrators-statement.json", {
          kms_key_administrators_json = jsonencode(var.kms_key_administrators)
        })),
      ] : [],
    )
  }

  cloudwatch_kms_policy = {
    Version = "2012-10-17"
    Statement = concat(
      jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-cloudwatch-key-policy.json", {
        arn_prefix = local.arn_prefix
        account_id = local.account_id
        dns_suffix = local.dns_suffix
        region     = local.region
      })).Statement,
      length(var.kms_key_administrators) > 0 ? [
        jsondecode(templatefile("${path.module}/../../configurations/policies/logging/kms-key-administrators-statement.json", {
          kms_key_administrators_json = jsonencode(var.kms_key_administrators)
        })),
      ] : [],
    )
  }
}

# --- Precondition: log_archive_account_id should be set for real deployments ---

check "log_archive_account_configured" {
  assert {
    condition     = var.log_archive_account_id != ""
    error_message = "log_archive_account_id is empty. Logging resources will use an incomplete bucket name. Set the account ID in env/accounts.hcl or ensure the accounts module has created the Log-Archive account."
  }
}
