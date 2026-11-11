# Organization — OUs, SCPs, Tag/Backup Policies

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # ID of the Infrastructure OU the Pipeline SCP is attached to. Empty means
  # "not configured" and leaves the Pipeline SCP out — see the comment at
  # enable_pipeline_scp below.
  pipeline_scp_infrastructure_ou_id = try(local.common.locals.pipeline_scp_infrastructure_ou_id, "")

  # DNS suffix of service principals, keyed by partition — the mapping
  # stacks/management/config-recorder-members already carries.
  # Terragrunt has no data.aws_partition, so the suffix comes from the
  # configured partition value instead of a fixed string.
  dns_suffix = {
    "aws"      = "amazonaws.com"
    "aws-eusc" = "amazonaws.eu"
  }
  suffix = local.dns_suffix[try(local.common.locals.partition, "aws")]
}

exclude {
  if      = !local.common.locals.enable_organization
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/organization"
}

inputs = {
  import_organization_id    = try(local.common.locals.import_organization_id, "")
  organization_root_id      = "" # Resolved via data source in the module
  organizational_units      = local.common.locals.organizational_units
  service_control_policies  = concat(local.compliance.locals.service_control_policies, local.compliance.locals.common_service_control_policies)
  resource_control_policies = concat(local.compliance.locals.resource_control_policies, local.compliance.locals.common_resource_control_policies)
  # RCPs the loader left out for an unresolved @@marker@@; the module warns.
  unresolved_resource_control_policies = local.compliance.locals.unresolved_resource_control_policies

  # Switch for the allow-list strategy: entries with strategy = "allow-list"
  # may detach the AWS default policy (FullAWSAccess / RCPFullAWSAccess) from
  # their targets. Off (the default) only attaches, purely additively.
  enable_allow_list_detach = try(local.common.locals.enable_allow_list_detach, false)
  declarative_policies     = concat(local.compliance.locals.declarative_policies, local.compliance.locals.common_declarative_policies)
  tag_policies             = concat(local.compliance.locals.tag_policies, local.compliance.locals.common_tag_policies)
  backup_policies          = concat(local.compliance.locals.backup_policies, local.compliance.locals.common_backup_policies)

  # The sixth policy type (aws_organizations_policy.chatbot).
  # Only one local is read, not a pair like the five above: the loader local
  # already merges base.tfvars, env/common.hcl and the
  # framework files itself, including the __LOADER_INJECT__ resolution.
  chatbot_policies = local.compliance.locals.chatbot_policies

  # Policy types an adopted organization has enabled beyond the ones the lists
  # above derive (for example AISERVICES_OPT_OUT_POLICY). The module owns the
  # complete list and disables every type it is not given.
  additional_enabled_policy_types = try(local.common.locals.additional_enabled_policy_types, [])

  service_access_principals = local.compliance.locals.filtered_service_access_principals

  # SCP revert detection follows the OR merge of the loader.
  enable_scp_revert_detection = local.compliance.locals.enable_scp_revert_detection
  # Loader merges (base + common + frameworks) — base.tfvars is the baseline.
  enable_scp_auto_revert         = local.compliance.locals.enable_scp_auto_revert
  scp_revert_notification_emails = try(local.common.locals.scp_revert_notification_emails, [])
  enable_quarantine_scp          = try(local.common.locals.enable_quarantine_scp, false)
  enable_quarantine_auto_detach  = local.compliance.locals.enable_quarantine_auto_detach
  opt_in_regions                 = try(local.common.locals.opt_in_regions, [])

  # Principals whose SCP changes the auto-revert function leaves alone.
  scp_revert_exempt_principal_arns = try(local.common.locals.scp_revert_exempt_principal_arns, [])

  # Quarantine SCP: content and targets come from env/common.hcl through the
  # loader. The module fallback reads the same document
  # (tlz-quarantine-guardrails.json), so both paths exempt the tlz-*
  # provisioning roles alongside AWSControlTowerExecution.
  quarantine_scp_content = local.compliance.locals.common_quarantine_scp_content
  quarantine_scp_targets = try(local.common.locals.quarantine_scp.targets, [])
  # OU the quarantine SCP is attached to and that the accounts unit creates
  # accounts marked quarantined = true inside; empty uses the targets only.
  quarantine_ou_name = try(local.common.locals.quarantine_ou_name, "")

  # Pipeline SCP: attached to the Infrastructure OU, whose ID this module
  # creates itself — no dependency can supply it, and AWS Organizations rejects
  # a placeholder literal. The ID is therefore a configuration value, and the SCP is only
  # created once it is set. Role names come from configuration as well; the
  # defaults match those of modules/deployment-role and modules/pipeline.
  enable_pipeline_scp = local.common.locals.enable_deployment_account && local.pipeline_scp_infrastructure_ou_id != ""
  pipeline_scp_config = local.common.locals.enable_deployment_account && local.pipeline_scp_infrastructure_ou_id != "" ? {
    deployment_role_name  = try(local.common.locals.deployment_role_name, "TLZDeploymentRole")
    pipeline_role_name    = try(local.common.locals.pipeline_role_name, "TLZPipelineRole")
    infrastructure_ou_id  = local.pipeline_scp_infrastructure_ou_id
    management_account_id = local.accounts.locals.management_account_id
  } : null

  enable_account_move_automation  = try(local.common.locals.enable_account_move_automation, false)
  account_move_log_retention_days = try(local.common.locals.account_move_log_retention_days, 90)

  # Organization resource: service access principals and feature set
  feature_set = try(local.common.locals.feature_set, "ALL")
  # Service principals carry the partition's DNS suffix (local.suffix)
  # instead of a fixed one, so trusted access names principals
  # that exist in the configured partition.
  # For aws-eusc the loader has ALREADY dropped every sso.* principal from
  # additional_aws_service_access_principals (configurations/loader.hcl, the
  # partition strip after _additional_aws_service_access_principals) before
  # the list arrives here, so this site must not filter it again. Unlike the
  # loader's filtered_* siblings, the name is kept on purpose.
  # The toggle list is followed by the operator's
  # additional_aws_service_access_principals from the loader: the module owns
  # the COMPLETE trusted-access list and refuses [], so this is the one path
  # that fills a toggle combination rendering nothing, or keeps the trusted
  # services of an adopted organization that no toggle knows. compact() wraps
  # ONLY the toggle list: an off toggle renders "" and is dropped here, but a
  # blank entry the operator typed must reach the module unchanged so that its
  # validation refuses it by name instead of the plan succeeding with the
  # intended service silently absent. distinct() because an operator may name
  # a principal a toggle already produces, and the module refuses duplicates.
  aws_service_access_principals = distinct(concat(compact([
    local.common.locals.enable_logging ? "cloudtrail.${local.suffix}" : "",
    local.common.locals.enable_logging ? "config.${local.suffix}" : "",
    local.common.locals.enable_logging ? "config-multiaccountsetup.${local.suffix}" : "",
    local.common.locals.enable_security ? "guardduty.${local.suffix}" : "",
    local.common.locals.enable_security ? "securityhub.${local.suffix}" : "",
    local.common.locals.enable_security ? "access-analyzer.${local.suffix}" : "",
    # Macie reads the loader's OR-merged, EUSC-filtered value — the same
    # expression the security stack feeds into the delegated-admin
    # registration, like enable_central_root_management below. A raw
    # env/common.hcl read would let trusted access and registration disagree:
    # RegisterDelegatedAdministrator fails with ConstraintViolationException
    # when macie.<suffix> is missing here. The security stack is skipped
    # while enable_security is false, so nothing registers Macie then.
    try(local.common.locals.enable_security, false) && local.compliance.locals.filtered_enable_macie ? "macie.${local.suffix}" : "",
    try(local.common.locals.enable_security, false) && try(local.common.locals.enable_detective, false) ? "detective.${local.suffix}" : "",
    try(local.common.locals.enable_security, false) && try(local.common.locals.enable_audit_manager, false) ? "auditmanager.${local.suffix}" : "",
    # Central root user management: iam.<suffix> as service access principal
    # is the effective activation path (modules/security has no toggle of its
    # own for it). The loader's OR-merged value keeps a framework able
    # to switch the capability on.
    local.compliance.locals.enable_central_root_management ? "iam.${local.suffix}" : "",
  ]), local.compliance.locals.additional_aws_service_access_principals))
}
