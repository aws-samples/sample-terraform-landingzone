# Security — GuardDuty, Security Hub, Macie, Access Analyzer, Delegated Admin

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # SecurityHub standards: from the loader, which merges base.tfvars,
  # env/common.hcl and the enabled frameworks and deduplicates by arn_suffix.
  # Reading common.hcl directly here would bypass the union merge and drop
  # every standard a framework adds.
  effective_security_hub_standards = local.compliance.locals.filtered_security_hub_standards
}

exclude {
  if      = !local.common.locals.enable_security
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/security"
}

dependency "logging" {
  config_path = "../logging"

  mock_outputs = {
    central_log_bucket_name = ""
    kms_key_arn             = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "accounts" {
  config_path = "../accounts"

  mock_outputs = {
    # account_ids stays for the Audit lookup below — an identity resolution,
    # not a deployment target, so it reads the unfiltered map.
    account_ids           = {}
    active_account_ids    = {}
    active_account_ou_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# Organization: supplies the OU name map for the SSM document share-target
# resolution (share_targets.organizational_units are resolved to the accounts
# they contain, because the document-sharing API accepts account IDs only).
dependency "organization" {
  config_path = "../organization"

  mock_outputs = {
    ou_name_to_id = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  audit_account_id = (
    local.accounts.locals.audit_account_id != ""
    ? local.accounts.locals.audit_account_id
    : lookup(dependency.accounts.outputs.account_ids, "Audit", "")
  )
  # The finding consumers (GuardDuty export, Macie export, finding aggregator,
  # automation rules) run in the Audit account — stacks/audit/security-org-config
  # — while security_finding_consumers_in_audit (default true) is on and the
  # Audit account resolves; this unit then creates none of its own. On a first
  # plan before the accounts exist, and with the switch false, they stay here.
  manage_finding_consumers = !(
    try(local.common.locals.security_finding_consumers_in_audit, true) && (
      local.accounts.locals.audit_account_id != ""
      ? local.accounts.locals.audit_account_id
      : lookup(dependency.accounts.outputs.account_ids, "Audit", "")
    ) != ""
  )
  # Service switches from the loader (OR across base.tfvars, env/common.hcl and
  # the enabled frameworks). Macie additionally goes through the loader's
  # partition filter, which switches it off in aws-eusc.
  enable_guardduty       = local.compliance.locals.enable_guardduty
  enable_security_hub    = local.compliance.locals.enable_security_hub
  enable_macie           = local.compliance.locals.filtered_enable_macie
  enable_access_analyzer = local.compliance.locals.enable_access_analyzer
  enable_detective       = try(local.common.locals.enable_detective, false)
  enable_audit_manager   = try(local.common.locals.enable_audit_manager, false)
  is_eusc                = local.common.locals.partition == "aws-eusc"
  security_hub_standards = local.effective_security_hub_standards
  password_policy        = local.compliance.locals.password_policy

  # Automation rules from the loader, which leads with the 36-rule baseline
  # JSON and appends base, common and framework contributions.
  security_hub_automation_rules         = local.compliance.locals.security_hub_automation_rules
  security_hub_disabled_controls        = local.compliance.locals.security_hub_disabled_controls
  ssm_documents                         = local.compliance.locals.ssm_documents
  kms_keys                              = local.compliance.locals.kms_keys
  macie_publishing_frequency            = local.compliance.locals.filtered_macie_publishing_frequency
  macie_publish_sensitive_data_findings = local.compliance.locals.filtered_macie_publish_sensitive_data_findings
  guardduty_export_frequency            = local.compliance.locals.guardduty_export_frequency
  guardduty_malware_protection          = local.compliance.locals.guardduty_malware_protection
  enable_session_manager_logging        = local.compliance.locals.enable_session_manager_logging
  # Loader merge (common wins, base is fallback): removing the key from
  # env/common.hcl falls back to the base.tfvars baseline instead of ""
  # (which would silently disable CloudWatch session logging).
  session_manager_cloudwatch_log_group = local.compliance.locals.session_manager_cloudwatch_log_group
  session_manager_excluded_accounts    = try(local.common.locals.session_manager_excluded_accounts, [])

  # Macie policy findings and GuardDuty malware snapshot retention
  macie_publish_policy_findings    = local.compliance.locals.filtered_macie_publish_policy_findings
  guardduty_keep_malware_snapshots = local.compliance.locals.guardduty_keep_malware_snapshots

  # GuardDuty export: bucket name and KMS key from logging module
  central_log_bucket_name      = dependency.logging.outputs.central_log_bucket_name
  guardduty_export_kms_key_arn = dependency.logging.outputs.kms_key_arn

  # GuardDuty S3 Malware Protection — loader merge (base + common + frameworks)
  enable_guardduty_s3_malware_protection = local.compliance.locals.enable_guardduty_s3_malware_protection
  guardduty_s3_malware_configs           = local.compliance.locals.guardduty_s3_malware_configs
  guardduty_eks_manage_agent             = local.compliance.locals.guardduty_eks_manage_agent

  # Per-feature region exclusion lists: each list documents the exclusion next
  # to the configuration it excludes from; a check block in the module reports
  # a plan running in a listed region.
  guardduty_ec2_protection_excluded_regions    = try(local.common.locals.guardduty_ec2_protection_excluded_regions, [])
  guardduty_eks_protection_excluded_regions    = try(local.common.locals.guardduty_eks_protection_excluded_regions, [])
  guardduty_lambda_protection_excluded_regions = try(local.common.locals.guardduty_lambda_protection_excluded_regions, [])
  guardduty_rds_protection_excluded_regions    = try(local.common.locals.guardduty_rds_protection_excluded_regions, [])
  # Macie fine-tuning: automated discovery with its bucket exclusions, and the
  # per-region suspension list (managed but paused, unlike the excluded list).
  macie_automated_discovery                   = try(local.common.locals.macie_automated_discovery, null)
  macie_classification_scope_excluded_buckets = try(local.common.locals.macie_classification_scope_excluded_buckets, [])
  macie_disabled_regions                      = try(local.common.locals.macie_disabled_regions, [])

  # Default VPC/SG cleanup — loader merge (base + common + frameworks)
  enable_delete_default_vpc      = local.compliance.locals.enable_delete_default_vpc
  enable_delete_default_sg_rules = local.compliance.locals.enable_delete_default_sg_rules
  default_vpc_id                 = try(local.common.locals.default_vpc_id, "")

  # FMS Notification Channels
  enable_fms_notification_channel = try(local.common.locals.enable_fms_notification_channel, false)
  fms_notification_sns_topic_arn  = try(local.common.locals.fms_notification_sns_topic_arn, "")
  fms_notification_sns_role_name  = try(local.common.locals.fms_notification_sns_role_name, "FMSNotificationRole")

  # Firewall Config S3 Bucket
  enable_firewall_config_bucket      = try(local.common.locals.enable_firewall_config_bucket, false)
  firewall_config_bucket_name        = try(local.common.locals.firewall_config_bucket_name, "")
  firewall_config_bucket_kms_key_arn = try(local.common.locals.firewall_config_bucket_kms_key_arn, "")

  # Resource Policy Enforcement (Data Perimeter)
  # The document content comes from the loader, which reads the file outside the
  # Terragrunt cache; without it the module creates no document at all.
  resource_policy_enforcement          = try(local.common.locals.resource_policy_enforcement, [])
  resource_policy_enforcement_document = local.compliance.locals.resource_policy_enforcement_document
  # Network perimeter for the enforcement templates: which VPC IDs replace the
  # {{NETWORK_PERIMETER_VPC_IDS}} placeholder. Declared next to
  # resource_policy_enforcement in env/common.hcl; the empty default keeps the
  # perimeter disabled and every template untouched.
  resource_policy_enforcement_network_perimeter = try(local.common.locals.resource_policy_enforcement_network_perimeter, {})

  # Account and OU maps for the SSM document share-target resolution (the
  # pattern of stacks/management/config-rules). Neither value belongs in a
  # configuration file: ou_name_to_id is an output of the organization stack,
  # and the account-to-OU assignment comes from the accounts module, which
  # publishes each account's declared OU as active_account_ou_ids (warm and
  # suspended accounts excluded — they are no deployment targets; a
  # quarantined account keeps its declared OU there). Accounts that this
  # landing zone does not create are not in that output and therefore not
  # resolvable through an OU name.
  account_ids    = dependency.accounts.outputs.active_account_ids
  ou_name_to_id  = dependency.organization.outputs.ou_name_to_id
  account_ou_ids = dependency.accounts.outputs.active_account_ou_ids

  # ---------------------------------------------------------------------------
  # Module features set from the configuration
  # ---------------------------------------------------------------------------
  # Every value below comes from the loader, and every loader default equals the
  # module default, so these entries do not change the deployment on their own;
  # they make the documented configuration options reachable.

  # GuardDuty fine tuning. The four protection plans carry the
  # module default true and travel through the loader's `_declared_` form, so
  # switching one off means setting it to false in env/common.hcl — the entry
  # here alone changes nothing.
  guardduty_s3_protection                  = local.compliance.locals.guardduty_s3_protection
  guardduty_eks_protection                 = local.compliance.locals.guardduty_eks_protection
  guardduty_lambda_protection              = local.compliance.locals.guardduty_lambda_protection
  guardduty_rds_protection                 = local.compliance.locals.guardduty_rds_protection
  guardduty_eks_runtime_monitoring         = local.compliance.locals.guardduty_eks_runtime_monitoring
  guardduty_deployment_targets             = local.compliance.locals.guardduty_deployment_targets
  guardduty_excluded_regions               = local.compliance.locals.guardduty_excluded_regions
  guardduty_s3_protection_excluded_regions = local.compliance.locals.guardduty_s3_protection_excluded_regions
  guardduty_export_prefix                  = local.compliance.locals.guardduty_export_prefix
  guardduty_lifecycle_rules                = local.compliance.locals.guardduty_lifecycle_rules



  # Full lifecycle rule sets per export path: optional pass-through, null keeps
  # the derived rule where one exists and writes nothing where none did (the
  # module distinguishes null from []).
  guardduty_export_lifecycle_rules     = try(local.common.locals.guardduty_export_lifecycle_rules, null)
  audit_manager_bucket_lifecycle_rules = try(local.common.locals.audit_manager_bucket_lifecycle_rules, null)
  macie_export_lifecycle_rules         = try(local.common.locals.macie_export_lifecycle_rules, null)
  session_manager_lifecycle_rules      = try(local.common.locals.session_manager_lifecycle_rules, null)

  # Encryption and key management. enable_ebs_default_encryption is true in
  # configurations/base/base.tfvars and cannot be switched off from
  # env/common.hcl, because the loader merges booleans with OR.
  enable_ebs_default_encryption   = local.compliance.locals.enable_ebs_default_encryption
  enable_lambda_encryption        = local.compliance.locals.enable_lambda_encryption
  enable_sqs_kms_key              = local.compliance.locals.enable_sqs_kms_key
  enable_per_account_kms_keys     = local.compliance.locals.enable_per_account_kms_keys
  ebs_default_kms_key_arn         = local.compliance.locals.ebs_default_kms_key_arn
  lambda_encryption_kms_key_arn   = local.compliance.locals.lambda_encryption_kms_key_arn
  ebs_encryption_excluded_regions = local.compliance.locals.ebs_encryption_excluded_regions

  # Session Manager and SSM. enable_ssm_block_public_sharing is
  # true in base.tfvars and likewise not switchable from env/common.hcl.
  # session_manager_s3_bucket_name deliberately stays on the loader value rather
  # than taking dependency.logging.outputs.central_log_bucket_name: the central
  # log bucket policy in modules/logging grants write access to CloudTrail,
  # Config and the access-log delivery only — it carries no statement for the
  # Session Manager instance role, so pointing sessions at that bucket would
  # produce a configuration AWS rejects at session start. Which bucket receives
  # session transcripts belongs in env/common.hcl next to
  # enable_session_manager_s3_logging.
  enable_ssm_block_public_sharing            = local.compliance.locals.enable_ssm_block_public_sharing
  enable_session_manager_s3_logging          = local.compliance.locals.enable_session_manager_s3_logging
  enable_ssm_resource_data_sync              = local.compliance.locals.enable_ssm_resource_data_sync
  session_manager_s3_bucket_name             = local.compliance.locals.session_manager_s3_bucket_name
  session_manager_s3_key_prefix              = local.compliance.locals.session_manager_s3_key_prefix
  session_manager_kms_key_id                 = local.compliance.locals.session_manager_kms_key_id
  session_manager_attach_policy_to_roles     = local.compliance.locals.session_manager_attach_policy_to_roles
  ssm_document_share_targets                 = local.compliance.locals.ssm_document_share_targets
  ssm_resource_data_sync_prefix              = local.compliance.locals.ssm_resource_data_sync_prefix
  ssm_block_public_sharing_excluded_accounts = local.compliance.locals.ssm_block_public_sharing_excluded_accounts

  # Security Hub and Macie: regions. security_hub_standards_config
  # says *where* a standard applies; security_hub_standards above says *which*
  # standards apply. Both stay side by side.
  enable_security_hub_region_aggregation = local.compliance.locals.enable_security_hub_region_aggregation
  security_hub_standards_config          = local.compliance.locals.security_hub_standards_config
  security_hub_aggregation_regions       = local.compliance.locals.security_hub_aggregation_regions
  security_hub_excluded_regions          = local.compliance.locals.security_hub_excluded_regions
  macie_excluded_regions                 = local.compliance.locals.macie_excluded_regions

  # Audit Manager report storage. The lifecycle is deliberately
  # not coupled to log_retention_days: the module documents 0 as "no lifecycle".
  enable_audit_manager_bucket         = local.compliance.locals.enable_audit_manager_bucket
  audit_manager_bucket_lifecycle_days = local.compliance.locals.audit_manager_bucket_lifecycle_days
  audit_manager_bucket_kms_key_arn    = local.compliance.locals.audit_manager_bucket_kms_key_arn
  audit_manager_reports_destination   = local.compliance.locals.audit_manager_reports_destination

  # S3 public access, root account, Firewall Manager.
  # allow_root_sessions is the only AND-merged switch: the restrictive value is
  # false, so every layer has to agree before root sessions are allowed.
  enable_s3_public_access_block            = local.compliance.locals.enable_s3_public_access_block
  root_credentials_management              = local.compliance.locals.root_credentials_management
  allow_root_sessions                      = local.compliance.locals.allow_root_sessions
  fms_policies                             = local.compliance.locals.fms_policies
  s3_public_access_block_excluded_accounts = local.compliance.locals.s3_public_access_block_excluded_accounts
  resource_policy_enforcement_lambda_arn   = local.compliance.locals.resource_policy_enforcement_lambda_arn

  # Firewall Manager administrator acknowledgement. Deliberately not a loader
  # merge: it attests a fact about this installation (the out-of-band
  # AssociateAdminAccount was done), which no compliance framework may assert.
  fms_admin_account_registered = try(local.common.locals.fms_admin_account_registered, false)
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
    "management/security",
    "# No adoption entries for this stack (configurations/base/resource-adoptions.json).\n",
  )
}
