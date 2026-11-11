# Logging — CloudTrail, Config Aggregator, central S3 bucket

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

exclude {
  if      = !local.common.locals.enable_logging
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/logging"
}

dependency "accounts" {
  config_path = "../accounts"

  # The placeholder id keeps a plan before the first accounts apply possible:
  # the inputs below refuse an empty Log-Archive id (control-tower convention).
  mock_outputs = {
    account_ids = { "Log-Archive" = "000000000000" }
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "organization" {
  config_path = "../organization"

  # The module validation requires a real o-... id even at plan time, so the
  # mock carries a syntactically valid placeholder (control-tower convention).
  mock_outputs = {
    organization_id = "o-mockorgid12"
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  # Account ID: from env/accounts.hcl or from accounts module output. An empty
  # id is refused (fail closed): the module only warns and
  # would create the central bucket as tlz-central-logs--<region>. The abort
  # is carried by file() on a path that is the message (root.hcl pattern).
  log_archive_account_id = (
    local.accounts.locals.log_archive_account_id != ""
    ? local.accounts.locals.log_archive_account_id
    : lookup(dependency.accounts.outputs.account_ids, "Log-Archive", "") != ""
    ? lookup(dependency.accounts.outputs.account_ids, "Log-Archive", "")
    : !local.common.locals.enable_logging ? ""
    : file("ERROR: management/logging: no Log-Archive account id. The accounts stack output account_ids has no account named \"Log-Archive\" and log_archive_account_id in env/accounts.hcl is empty. Set log_archive_account_id in env/accounts.hcl, or name the account \"Log-Archive\" in the accounts list of env/common.hcl.")
  )
  # Organization ID feeds the CloudTrail delivery path and the SourceOrgID
  # condition of the central log bucket policy — an empty value would break
  # both, and the module validation rejects it. Sourced from the organization
  # stack output like the monitoring stack does.
  organization_id                = dependency.organization.outputs.organization_id
  log_retention_days             = local.compliance.locals.log_retention_days
  cloudwatch_log_group_retention = local.compliance.locals.cloudwatch_log_group_retention

  # CloudTrail: three merged values from the loader, so Insights and the two
  # data event switches follow base.tfvars and the frameworks.
  cloudtrail_insights           = local.compliance.locals.cloudtrail_insights
  cloudtrail_s3_data_events     = local.compliance.locals.cloudtrail_s3_data_events
  cloudtrail_lambda_data_events = local.compliance.locals.cloudtrail_lambda_data_events
  kms_key_administrators        = local.common.locals.kms_key_administrators
  force_destroy                 = local.common.locals.force_destroy

  s3_lifecycle_rules = local.compliance.locals.s3_lifecycle_rules

  # GuardDuty export prefix: same loader value the security stack passes to
  # its publishing destination, so grant and write path cannot drift apart.
  guardduty_export_prefix = local.compliance.locals.guardduty_export_prefix
  # The Audit account holds the GuardDuty publishing destination and the Macie
  # classification export once the finding consumers run there
  # (stacks/audit/security-org-config); the bucket and key grants admit it.
  # Resolved as in stacks/management/security: env/accounts.hcl first, else the
  # accounts stack output. Empty before the first accounts apply (the mock
  # above carries no Audit entry) — the grants then name the management
  # account alone, as before.
  finding_export_source_account_ids = compact([
    local.accounts.locals.audit_account_id != ""
    ? local.accounts.locals.audit_account_id
    : lookup(dependency.accounts.outputs.account_ids, "Audit", "")
  ])
  # Source: compliance loader (base.tfvars → loader.hcl)
  enable_elb_log_bucket    = local.compliance.locals.enable_elb_log_bucket
  elb_log_bucket_lifecycle = local.compliance.locals.elb_log_bucket_lifecycle

  # Full lifecycle rule sets per bucket: optional pass-through, null keeps the
  # derived rules of each bucket (the module distinguishes null from []).
  central_log_bucket_lifecycle_rules   = try(local.common.locals.central_log_bucket_lifecycle_rules, null)
  access_logs_bucket_lifecycle_rules   = try(local.common.locals.access_logs_bucket_lifecycle_rules, null)
  elb_log_bucket_lifecycle_rules       = try(local.common.locals.elb_log_bucket_lifecycle_rules, null)
  vpc_flow_logs_bucket_lifecycle_rules = try(local.common.locals.vpc_flow_logs_bucket_lifecycle_rules, null)

  # Clean-up of GuardDuty findings exported to the bucket root instead of their
  # prefix: optional pass-through, null sets no rule. Remove the value
  # from env/common.hcl once the root objects are gone.
  guardduty_root_export_cleanup = try(local.common.locals.guardduty_root_export_cleanup, null)
  cloudwatch_log_subscriptions  = try(local.common.locals.cloudwatch_log_subscriptions, [])

  # CloudWatch Log Data Protection
  enable_cloudwatch_log_data_protection     = try(local.common.locals.enable_cloudwatch_log_data_protection, false)
  cloudwatch_log_data_protection_log_groups = try(local.common.locals.cloudwatch_log_data_protection_log_groups, [])

  # SSM Associations (Inventory)
  ssm_associations = try(local.common.locals.ssm_associations, [])

  # S3 cross-region replication
  s3_replication_config = try(local.common.locals.s3_replication_config, {})

  # S3 Object Lock
  enable_s3_object_lock = try(local.common.locals.enable_s3_object_lock, false)
  s3_object_lock_config = try(local.common.locals.s3_object_lock_config, {})

  # CloudTrail Lake
  enable_cloudtrail_lake = try(local.common.locals.enable_cloudtrail_lake, false)
  cloudtrail_lake_config = try(local.common.locals.cloudtrail_lake_config, {})

  # VPC Flow Logs Dedicated Bucket
  enable_vpc_flow_logs_bucket = try(local.common.locals.enable_vpc_flow_logs_bucket, false)
  vpc_flow_logs_bucket_config = try(local.common.locals.vpc_flow_logs_bucket_config, {})

  # Nine module inputs from the compliance loader. Each carries the module
  # default there, so passing them on changes no deployment by itself.
  #
  # Separate access logs bucket and per-account KMS keys: merged with OR, so a
  # framework can demand them.
  enable_separate_access_logs_bucket = local.compliance.locals.enable_separate_access_logs_bucket
  enable_per_account_kms_keys        = local.compliance.locals.enable_per_account_kms_keys

  # cloudtrail_management_events has module default true and is therefore merged
  # via the _declared_ form of the loader: without a declaring layer the local
  # yields true, so reading it does not switch management event logging off.
  cloudtrail_management_events = local.compliance.locals.cloudtrail_management_events

  cloudtrail_account_trails = local.compliance.locals.cloudtrail_account_trails
  cloudtrail_sns_topic_name = local.compliance.locals.cloudtrail_sns_topic_name
  cloudwatch_log_exclusions = local.compliance.locals.cloudwatch_log_exclusions

  # Region scope of the organization trail: optional pass-through, {} keeps
  # the multi-region recording and the global service events the trail has
  # always used.
  cloudtrail_org_trail_settings = try(local.common.locals.cloudtrail_org_trail_settings, {})

  # Structured log exclusions and the account-wide subscription policy:
  # optional pass-throughs, [] and {} keep the plan. The organizational unit
  # of this deployment stays empty by default — the management account sits
  # in no organizational unit of the configuration's account list.
  cloudwatch_log_exclusion_rules      = try(local.common.locals.cloudwatch_log_exclusion_rules, [])
  deployment_organizational_unit      = try(local.common.locals.deployment_organizational_unit, "")
  cloudwatch_log_account_subscription = try(local.common.locals.cloudwatch_log_account_subscription, {})

  # Tuning of the CloudWatch-to-S3 archive pipeline (stream capacity and
  # retention, delivery buffering, compression, file extension, error prefix,
  # record-processor Lambda). {} keeps the values the pipeline always wrote.
  kinesis_pipeline_config = try(local.common.locals.kinesis_pipeline_config, {})

  # Customer-managed key for the record-processor Lambda's environment
  # variables. Empty (the loader default) keeps the AWS-managed key and the plan.
  lambda_environment_kms_key_arn = local.compliance.locals.logging_lambda_environment_kms_key_arn

  # Data protection identifiers are merged as a union — every layer may add a
  # category, none may drop one.
  cloudwatch_log_data_protection_identifiers = local.compliance.locals.cloudwatch_log_data_protection_identifiers

  # Recorder slot ownership: false leaves the recorder, delivery channel and
  # status to their current owner and applies the rest of the module beside it.
  # true (the default) manages all three in this stack.
  manage_config_recorder = local.compliance.locals.manage_config_recorder

  # The pair belongs together: config-recorder.tf picks between the AWS service
  # linked role and the custom role, and the custom ARN is only meaningful when
  # the service linked role is switched off.
  use_config_service_linked_role  = local.compliance.locals.use_config_service_linked_role
  config_recorder_custom_role_arn = local.compliance.locals.config_recorder_custom_role_arn

  # Additional and overriding bucket/KMS policies per log bucket: optional
  # pass-through, {} keeps the generated policies. The documents are JSON
  # strings that env/common.hcl reads from files via file(); the overrides
  # additionally require the explicit confirmation switch.
  central_log_bucket_policies   = try(local.common.locals.central_log_bucket_policies, {})
  access_logs_bucket_policies   = try(local.common.locals.access_logs_bucket_policies, {})
  elb_log_bucket_policies       = try(local.common.locals.elb_log_bucket_policies, {})
  allow_bucket_policy_overrides = try(local.common.locals.allow_bucket_policy_overrides, false)

  # Bucket namespace: the leading segment of every derived bucket name of the
  # module. "tlz-" is the name the buckets have always had — a changed value
  # replaces every live bucket, so it stays at the default here; live
  # apply-tests set tlz-l4test- to keep their buckets disjoint from these.
  bucket_name_prefix = try(local.common.locals.bucket_name_prefix, "tlz-")

  # Resource adoption (docs/resource-adoption.md): names of existing buckets
  # this deployment takes over. Empty keeps the derived names and the plan.
  adopted_central_log_bucket_name   = try(local.common.locals.adopted_central_log_bucket_name, "")
  adopted_access_logs_bucket_name   = try(local.common.locals.adopted_access_logs_bucket_name, "")
  adopted_elb_log_bucket_name       = try(local.common.locals.adopted_elb_log_bucket_name, "")
  adopted_vpc_flow_logs_bucket_name = try(local.common.locals.adopted_vpc_flow_logs_bucket_name, "")
}

# Resource adoption: declarative import blocks rendered from the adoption
# list (configurations/base/resource-adoptions.json, loader local
# adoption_imports_by_stack). One import block per entry of this stack; an
# empty adoption list renders no blocks and leaves the plan unchanged.
generate "imports" {
  path      = "adoption-imports.tf"
  if_exists = "overwrite_terragrunt"
  contents = lookup(
    local.compliance.locals.adoption_imports_by_stack,
    "management/logging",
    "# No adoption entries for this stack (configurations/base/resource-adoptions.json).\n",
  )
}
