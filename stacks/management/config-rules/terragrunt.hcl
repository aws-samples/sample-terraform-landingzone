# Config Rules — Org-wide Managed/Custom Rules, Organization Conformance Packs
# Cross-account dependencies are conditional: only enabled when the Audit
# account ID resolves (accounts.hcl or the SSM parameter the recorder stacks
# read; full multi-account deployment). In Org-Only mode, Config Rules and
# conformance packs run with member accounts excluded (they have no Config
# Recorder without cross-account stacks).

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # Cross-account mode: true when the Audit account ID resolves. The
  # resolution is the Audit recorder stack's own file, read here rather than
  # copied, so both stacks see the same value: audit_account_id in
  # accounts.hcl when set, else the SSM parameter /tlz/accounts/Audit/id that
  # modules/accounts writes. ParameterNotFound (no Audit account yet) resolves
  # to "" and keeps every member account excluded below; any other failure of
  # the read aborts the run. Only account_id is taken from that file: this
  # unit runs in the management account and assumes no role.
  audit_account_id      = read_terragrunt_config("${get_repo_root()}/stacks/audit/config-recorder/cross_account.hcl").locals.account_id
  cross_account_enabled = local.audit_account_id != ""

  # Config Recorder Members: single stack deploys recorders to all member accounts
  enable_config_recorder_members = local.common.locals.enable_config_recorder_members

  # ---------------------------------------------------------------------------
  # Placeholder resolution for rules and remediations
  # ---------------------------------------------------------------------------
  # Three values are not known when the configuration is written: the two
  # identities the auto-remediations run with (supplied by env/common.hcl once
  # they exist) and the name of the ELB log bucket (created by the logging
  # stack). The configuration carries them as __PLACEHOLDER__ tokens.
  #
  # A token deployed verbatim breaks the rule: ELB_LOGGING_ENABLED would compare
  # every load balancer against the literal "__ELB_LOG_BUCKET__" and report all
  # of them as non-compliant, and both remediations would point at an IAM role
  # and an instance profile that do not exist. A rule or remediation whose token
  # cannot be resolved is therefore left out — better no rule than a rule that
  # can never pass.
  #
  # Resolution runs in two stages, each where its values are available: the two
  # identity tokens here, the bucket token in the inputs block, because a
  # dependency output cannot be read from locals.
  identity_placeholders = {
    "__REMEDIATION_ASSUME_ROLE_ARN__"  = local.compliance.locals.remediation_assume_role_arn
    "__REMEDIATION_INSTANCE_PROFILE__" = local.compliance.locals.remediation_instance_profile_name
  }
  resolved_identities = {
    for token, value in local.identity_placeholders : token => value if value != ""
  }
  elb_log_bucket_token = "__ELB_LOG_BUCKET__"

  # --- Managed rules: identity tokens resolved, unresolvable rules dropped
  # The loader merges all rule sources (JSON files, base.tfvars,
  # env/common.hcl, frameworks) and applies the EUSC partition filter;
  # filtered_managed_rules is the complete, filtered list. A
  # direct concat of local.common.locals.managed_rules here would bypass that
  # filter.
  _raw_managed_rules = local.compliance.locals.filtered_managed_rules
  managed_rules_identity_resolved = [
    for rule in local._raw_managed_rules : merge(rule, {
      input_parameters = {
        for name, value in try(rule.input_parameters, {}) :
        name => lookup(local.resolved_identities, value, value)
      }
    })
    if alltrue([
      for value in values(try(rule.input_parameters, {})) :
      !contains(keys(local.identity_placeholders), value) || contains(keys(local.resolved_identities), value)
    ])
  ]

  # --- Remediations: same, over the static_values of every parameter
  _raw_remediation_configs = concat(local.compliance.locals.remediation_configs, local.common.locals.remediation_configs)
  remediation_configs_identity_resolved = [
    for config in local._raw_remediation_configs : merge(config, {
      parameters = {
        for name, parameter in try(config.parameters, {}) :
        name => merge(parameter, {
          static_values = [
            for value in try(parameter.static_values, []) :
            lookup(local.resolved_identities, value, value)
          ]
        })
      }
    })
    if alltrue(flatten([
      for parameter in values(try(config.parameters, {})) : [
        for value in try(parameter.static_values, []) :
        !contains(keys(local.identity_placeholders), value) || contains(keys(local.resolved_identities), value)
      ]
    ]))
  ]

  # Diagnostic: identities that are not configured. Read this when an expected
  # remediation does not appear in the plan.
  unresolved_identities = [
    for token, value in local.identity_placeholders : token if value == ""
  ]
}

exclude {
  if      = !local.common.locals.enable_config_rules
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/config-rules"
}

# No ordering dependency on ../iam. The edge would carry nothing:
#
#   1. It read no output (`skip_outputs = true`) — no value flowed.
#   2. modules/config-rules creates five resource types, all of them
#      `aws_config_*`. It declares no IAM resource and no argument that names an
#      IAM identity of its own.
#   3. The only IAM identities in this stack are the remediation parameters
#      `AutomationAssumeRole` and `IamInstanceProfile`. They come from
#      env/common.hcl (`remediation_assume_role_arn`,
#      `remediation_instance_profile_name`), not from the iam stack, and while
#      they are empty the `resolved_identities` filter above drops both
#      remediations before they reach the module. Terraform passes them on as
#      opaque strings; the consumer is AWS Config and SSM at remediation time,
#      not Terraform at apply time.
#   4. Even with both values filled the edge would not help: modules/iam creates
#      roles and instance profiles only in the account its provider points at —
#      the management account. Its `deployment_targets` is accepted for
#      configuration compatibility and does nothing, which the module says itself
#      in four `check` blocks. A remediation, however, needs the identity in the
#      member account where the non-compliant resource lives.
#   5. Three of the 32 managed rules evaluate AWS::IAM::User, ::Group and ::Role,
#      resource types the iam stack creates. An AWS Config rule evaluates
#      continuously and retroactively, so the order in which rule and resource
#      come into being does not change the evaluation.
#
# What the ordering *is* about is expressed: Config rules
# need a Config Recorder in every account, hence the config-recorder
# dependencies below.

dependency "accounts" {
  config_path = "../accounts"

  mock_outputs = {
    account_ids        = {}
    active_account_ids = {}
    # active_account_ou_ids carries the declared OU ID per account, warm and
    # suspended accounts excluded — the accounts module is the only place that
    # knows which OU an account is declared in; see inputs.account_ou_ids.
    active_account_ou_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# Organization: supplies the OU name to OU ID map that resolves an OU *name* in
# a rule's deployment_targets. Without it every OU name falls out of the
# resolution: modules/config-rules then treats the rule as targeting nothing and
# excludes every account, so the rule has nothing left to evaluate.
# Same shape as stacks/management/accounts uses.
dependency "organization" {
  config_path = "../organization"

  mock_outputs = {
    ou_name_to_id = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# Logging: supplies the name of the ELB log bucket that the Config rule
# ELB_LOGGING_ENABLED and its remediation check against. The mock
# value is a valid bucket name, so that validate and plan exercise the resolved
# path instead of the dropped one.
dependency "logging" {
  config_path = "../logging"

  mock_outputs = {
    elb_log_bucket_name = "mock-elb-logs"
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

# Consolidated config-recorder-members dependency — replaces individual cross-account
# dependencies when enable_config_recorder_members is true
dependency "config_recorder_members" {
  config_path  = "../config-recorder-members"
  skip_outputs = true
  enabled      = local.enable_config_recorder_members
}

# Cross-account dependencies — only when member accounts are configured
# AND the consolidated config-recorder-members stack is NOT enabled
dependency "config_recorder_audit" {
  config_path  = "../../audit/config-recorder"
  skip_outputs = true
  enabled      = local.cross_account_enabled && !local.enable_config_recorder_members
}

dependency "config_recorder_log_archive" {
  config_path  = "../../log-archive/config-recorder"
  skip_outputs = true
  enabled      = local.cross_account_enabled && !local.enable_config_recorder_members
}

dependency "config_recorder_workload_dev" {
  config_path  = "../../workload-dev/config-recorder"
  skip_outputs = true
  enabled      = local.cross_account_enabled && !local.enable_config_recorder_members
}

dependency "security_config" {
  config_path  = "../../audit/security-config"
  skip_outputs = true
  enabled      = local.cross_account_enabled
}

inputs = {
  # Second resolution stage: the ELB log bucket token. A rule or remediation
  # that still needs it while the bucket does not exist is left out — see the
  # comment in the locals block.
  managed_rules = [
    for rule in local.managed_rules_identity_resolved : merge(rule, {
      input_parameters = {
        for name, value in rule.input_parameters :
        name => value == local.elb_log_bucket_token ? dependency.logging.outputs.elb_log_bucket_name : value
      }
    })
    if dependency.logging.outputs.elb_log_bucket_name != "" || !contains(values(rule.input_parameters), local.elb_log_bucket_token)
  ]

  remediation_configs = [
    for config in local.remediation_configs_identity_resolved : merge(config, {
      parameters = {
        for name, parameter in config.parameters :
        name => merge(parameter, {
          static_values = [
            for value in parameter.static_values :
            value == local.elb_log_bucket_token ? dependency.logging.outputs.elb_log_bucket_name : value
          ]
        })
      }
    })
    if dependency.logging.outputs.elb_log_bucket_name != "" || !contains(flatten([for parameter in values(config.parameters) : parameter.static_values]), local.elb_log_bucket_token)
  ]

  custom_rules      = concat(local.compliance.locals.custom_rules, local.common.locals.custom_rules)
  conformance_packs = concat(local.compliance.locals.conformance_packs, local.common.locals.conformance_packs)

  # Switch for the module-created evaluator and remediation functions
  # (custom_rules[].lambda, remediation_configs[].target_document_lambda).
  # Off (the default): every function ARN comes from outside.
  enable_custom_rule_lambdas = try(local.common.locals.enable_custom_rule_lambdas, false)

  # Config rules that only exist in the management account (SecurityHub and
  # CloudTrail checks), merged by the loader.
  management_only_rules = local.compliance.locals.management_only_rules

  # When config-recorder-members is enabled, all member accounts have Config Recorders
  # so no accounts need to be excluded. Otherwise:
  # in Org-Only mode (no cross-account stacks), exclude all member accounts.
  # Deliberately the UNFILTERED map: this is an exclusion list, so warm
  # accounts must stay in it — the active pendant would re-include them.
  global_excluded_accounts = local.enable_config_recorder_members ? [] : (
    local.cross_account_enabled ? [] : [
      for name, id in dependency.accounts.outputs.account_ids : id
    ]
  )
  account_ids = dependency.accounts.outputs.active_account_ids

  # OU resolution for deployment_targets (modules/config-rules/main.tf:
  # local.ou_id_to_account_ids and local.target_account_ids). Without these two
  # values an OU name in deployment_targets resolves to the empty list and the
  # rule excludes every account.
  #
  # Neither value belongs in a configuration file: both come from other stacks.
  # ou_name_to_id is an output of the organization stack. The account-to-OU
  # assignment has no stack of its own; the accounts module publishes each
  # account's declared OU as active_account_ou_ids (warm and suspended
  # accounts excluded — they are no deployment targets; a quarantined account
  # keeps its declared OU there). Accounts that this landing zone does not
  # create are not in that output and therefore not resolvable through an OU
  # name.
  ou_name_to_id  = dependency.organization.outputs.ou_name_to_id
  account_ou_ids = dependency.accounts.outputs.active_account_ou_ids
}
