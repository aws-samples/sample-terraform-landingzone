# Config rules module: AWS Config Managed/Custom Rules, Conformance Packs, Auto-Remediation

# Partition and region of the current deployment. The remediation target ARN
# for a document owned by another account is built from them, so the module
# works in every partition (aws and aws-eusc) without a hardcoded prefix.

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  partition = data.aws_partition.current.partition
  region    = data.aws_region.current.region
}

# --- Local variables for for_each maps ---

locals {
  # Managed Rules als Map (Name → Definition)
  managed_rules_map = { for rule in var.managed_rules : rule.name => rule }

  # Custom Rules als Map (Name → Definition)
  custom_rules_map = { for rule in var.custom_rules : rule.name => rule }

  # Conformance Packs als Map (Name → Definition)
  conformance_packs_map = { for pack in var.conformance_packs : pack.name => pack }

  # Remediation configurations as map (rule name → configuration)
  remediation_map = { for r in var.remediation_configs : r.rule_name => r }

  # All known account IDs (the values of the account_ids map)
  all_account_ids = values(var.account_ids)

  # --- deployment_targets resolution ----------------------------------------
  #
  # A deployment target is one of three things, and every form is resolved to
  # the account IDs it stands for:
  #   * a 12-digit account ID   → that account
  #   * an account name         → var.account_ids[<name>]
  #   * an OU name              → every account whose parent OU is
  #                               var.ou_name_to_id[<name>] according to
  #                               var.account_ou_ids
  # Unresolvable targets are rejected by the variable validation, so no target
  # can silently degrade into "exclude every account".

  # Accounts per organizational unit, keyed by OU ID.
  ou_id_to_account_ids = {
    for ou_id in distinct(values(var.account_ou_ids)) : ou_id => [
      for account_name, account_id in var.account_ids : account_id
      if lookup(var.account_ou_ids, account_name, null) == ou_id
    ]
  }

  # Every target used anywhere, resolved once.
  all_deployment_targets = distinct(concat(
    flatten([for rule in var.managed_rules : rule.deployment_targets]),
    flatten([for rule in var.custom_rules : rule.deployment_targets]),
  ))

  target_account_ids = {
    for target in local.all_deployment_targets : target => (
      can(regex("^[0-9]{12}$", target)) ? [target] :
      contains(keys(var.account_ids), target) ? [var.account_ids[target]] :
      contains(keys(var.ou_name_to_id), target) ? lookup(local.ou_id_to_account_ids, var.ou_name_to_id[target], []) :
      []
    )
  }

  managed_rule_targets = {
    for name, rule in local.managed_rules_map : name => distinct(flatten([
      for target in rule.deployment_targets : local.target_account_ids[target]
    ]))
  }

  custom_rule_targets = {
    for name, rule in local.custom_rules_map : name => distinct(flatten([
      for target in rule.deployment_targets : local.target_account_ids[target]
    ]))
  }

  # When deployment_targets is set, all accounts OUTSIDE the resolved targets
  # are excluded.
  managed_rule_excluded = {
    for name, rule in local.managed_rules_map : name => (
      length(rule.deployment_targets) > 0
      ? distinct(concat(
        [for acct_id in local.all_account_ids : acct_id
          if !contains(local.managed_rule_targets[name], acct_id)
        ],
        rule.excluded_accounts,
        var.global_excluded_accounts,
      ))
      : distinct(concat(rule.excluded_accounts, var.global_excluded_accounts))
    )
  }

  custom_rule_excluded = {
    for name, rule in local.custom_rules_map : name => (
      length(rule.deployment_targets) > 0
      ? distinct(concat(
        [for acct_id in local.all_account_ids : acct_id
          if !contains(local.custom_rule_targets[name], acct_id)
        ],
        rule.excluded_accounts,
        var.global_excluded_accounts,
      ))
      : distinct(concat(rule.excluded_accounts, var.global_excluded_accounts))
    )
  }

  # Rules whose targets resolve to no account at all: the rule would exist in
  # the organization and evaluate nothing. Reported by the check below.
  rules_without_resolved_accounts = concat(
    [for name, rule in local.managed_rules_map : name
      if length(rule.deployment_targets) > 0 && length(local.managed_rule_targets[name]) == 0
    ],
    [for name, rule in local.custom_rules_map : name
      if length(rule.deployment_targets) > 0 && length(local.custom_rule_targets[name]) == 0
    ],
  )
}

# A rule that targets an empty set of accounts is almost always a configuration
# mistake (an OU without member accounts, or accounts that the module does not
# know). Report it in the plan instead of silently creating a rule that never
# evaluates anything.
check "deployment_targets_resolve_to_accounts" {
  assert {
    condition     = length(local.rules_without_resolved_accounts) == 0
    error_message = "Config rules with deployment_targets that resolve to no account [${join(", ", local.rules_without_resolved_accounts)}]. The rule would be created organization-wide with every account excluded and would evaluate nothing. Check account_ids, account_ou_ids and ou_name_to_id."
  }
}

# =============================================================================
# AWS managed Config rules — organization-wide deployment
# =============================================================================

resource "aws_config_organization_managed_rule" "this" {
  for_each = local.managed_rules_map

  name                 = each.value.name
  rule_identifier      = each.value.source_identifier
  description          = each.value.description
  input_parameters     = length(each.value.input_parameters) > 0 ? jsonencode(each.value.input_parameters) : null
  excluded_accounts    = local.managed_rule_excluded[each.key]
  resource_types_scope = length(each.value.resource_types_scope) > 0 ? each.value.resource_types_scope : null
}

# =============================================================================
# Management-Account-Only Config Rules
# =============================================================================

locals {
  management_only_rules_map = { for rule in var.management_only_rules : rule.name => rule }
}

resource "aws_config_config_rule" "management_only" {
  for_each = local.management_only_rules_map

  name        = each.value.name
  description = each.value.description
  tags        = length(each.value.tags) > 0 ? each.value.tags : null

  source {
    owner             = "AWS"
    source_identifier = each.value.source_identifier
  }

  input_parameters = length(each.value.input_parameters) > 0 ? jsonencode(each.value.input_parameters) : null
}

# =============================================================================
# Custom Config rules — Lambda-based, organization-wide
# =============================================================================

resource "aws_config_organization_custom_rule" "this" {
  for_each = local.custom_rules_map

  name = each.value.name
  # The evaluator is either the externally supplied ARN or the function the
  # module created from the entry's lambda block (lambda-functions.tf); the
  # variable validation guarantees exactly one source.
  lambda_function_arn = (
    each.value.lambda != null
    ? local.custom_rule_lambda_arns[each.key]
    : each.value.lambda_function_arn
  )
  description                 = each.value.description
  trigger_types               = each.value.trigger_types
  input_parameters            = length(each.value.input_parameters) > 0 ? jsonencode(each.value.input_parameters) : null
  excluded_accounts           = local.custom_rule_excluded[each.key]
  resource_types_scope        = each.value.resource_types_scope
  resource_id_scope           = each.value.resource_id_scope
  tag_key_scope               = each.value.tag_key_scope
  tag_value_scope             = each.value.tag_value_scope
  maximum_execution_frequency = each.value.maximum_execution_frequency

  # Config validates that it may invoke the evaluator when the rule is
  # created, so the resource-based permission has to exist first.
  depends_on = [aws_lambda_permission.config_invoke]
}

# =============================================================================
# Conformance packs — organization-wide compliance monitoring
# =============================================================================
#
# Organization packs, like the rules above: AWS Config deploys each pack to the
# member accounts of the organization, minus the pack's own exclusions and the
# global exclusions. Created from the management account (or a Config
# delegated administrator) in the region the module runs in.

resource "aws_config_organization_conformance_pack" "this" {
  for_each = local.conformance_packs_map

  name              = each.value.name
  excluded_accounts = distinct(concat(each.value.excluded_accounts, var.global_excluded_accounts))

  # Template body or S3 URI (one of the two)
  template_body   = each.value.template_body
  template_s3_uri = each.value.template_s3_uri

  # Optional input parameters
  dynamic "input_parameter" {
    for_each = each.value.input_parameters
    content {
      parameter_name  = input_parameter.key
      parameter_value = input_parameter.value
    }
  }
}

# =============================================================================
# Auto-remediation — optional automatic remediation on non-compliance
# =============================================================================

resource "aws_config_remediation_configuration" "this" {
  for_each = local.remediation_map

  config_rule_name = each.value.rule_name
  # With an owning account the document is addressed by its full ARN — the
  # form AWS requires for a document shared from another account.
  target_id = (
    each.value.target_account_name != null
    ? "arn:${local.partition}:ssm:${local.region}:${var.account_ids[each.value.target_account_name]}:document/${each.value.target_id}"
    : each.value.target_id
  )
  target_type    = each.value.target_type
  target_version = each.value.target_version
  automatic      = each.value.automatic

  maximum_automatic_attempts = each.value.automatic ? each.value.maximum_automatic_attempts : null
  retry_attempt_seconds      = each.value.automatic ? each.value.retry_attempt_seconds : null

  # Dynamic parameter blocks
  dynamic "parameter" {
    for_each = each.value.parameters
    content {
      name = parameter.key

      # Static values or resource value (one of the two). The token
      # __REMEDIATION_LAMBDA_ARN__ resolves to the function the module
      # created from the entry's target_document_lambda block — the variable
      # validation couples token and block, so the lookup cannot miss.
      static_values = length(parameter.value.static_values) > 0 ? [
        for value in parameter.value.static_values :
        value == "__REMEDIATION_LAMBDA_ARN__" ? local.remediation_lambda_arns[each.key] : value
      ] : null
      resource_value = parameter.value.resource_value
    }
  }

  # Remediation depends on the associated managed or custom rule
  depends_on = [
    aws_config_organization_managed_rule.this,
    aws_config_organization_custom_rule.this,
  ]
}
