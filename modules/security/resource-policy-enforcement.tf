# =============================================================================
# Resource Policy Enforcement (G5)
# =============================================================================

locals {
  # aws_config_organization_custom_rule requires the ARN of a Lambda evaluator.
  # Without one the rule cannot be created at all, so the rule set stays empty
  # until an evaluator ARN is supplied instead of planning a resource AWS rejects.
  resource_policy_evaluator_available = var.resource_policy_enforcement_lambda_arn != ""

  configured_resource_policies = {
    for rpe in var.resource_policy_enforcement : rpe.resource_type => rpe
    if rpe.enabled
  }

  enabled_resource_policies = (
    local.resource_policy_evaluator_available
    ? local.configured_resource_policies
    : {}
  )

  resource_policy_has_deployment_targets = anytrue([
    for rpe in var.resource_policy_enforcement : length(rpe.deployment_targets) > 0
  ])

  # Network perimeter: the effective VPC ID set for the template placeholder.
  # managed_vpc_only keeps the perimeter to the VPCs this landing zone manages;
  # otherwise the declared pre-existing VPCs widen it.
  resource_policy_perimeter_vpc_ids = (
    var.resource_policy_enforcement_network_perimeter.enabled
    ? distinct(
      var.resource_policy_enforcement_network_perimeter.managed_vpc_only
      ? var.resource_policy_enforcement_network_perimeter.managed_vpc_ids
      : concat(
        var.resource_policy_enforcement_network_perimeter.managed_vpc_ids,
        var.resource_policy_enforcement_network_perimeter.additional_vpc_ids,
      )
    )
    : []
  )

  # The placeholder is replaced in its quoted form with the JSON array of the
  # perimeter VPC IDs, so the template is valid JSON before the replacement (a
  # string value) and after it (an array value).
  resource_policy_templates = {
    for key, rpe in local.enabled_resource_policies : key => (
      var.resource_policy_enforcement_network_perimeter.enabled
      ? replace(
        rpe.policy_template,
        "\"{{NETWORK_PERIMETER_VPC_IDS}}\"",
        jsonencode(local.resource_policy_perimeter_vpc_ids),
      )
      : rpe.policy_template
    )
  }
}

resource "aws_config_organization_custom_rule" "resource_policy" {
  for_each = local.enabled_resource_policies

  name = "tlz-${each.value.policy_set}-rp-${lower(replace(each.value.resource_type, "::", "-"))}"
  # The entry's own parameters ride along with the template; policyTemplate is
  # merged last so a colliding user key can never displace it (the variable
  # validation rejects that key as well).
  input_parameters = jsonencode(merge(
    each.value.input_parameters,
    { policyTemplate = local.resource_policy_templates[each.key] },
  ))
  lambda_function_arn  = var.resource_policy_enforcement_lambda_arn
  trigger_types        = ["ConfigurationItemChangeNotification"]
  resource_types_scope = [each.value.resource_type]

  depends_on = [aws_securityhub_account.this]
}

check "resource_policy_enforcement_requires_evaluator" {
  assert {
    condition     = length(local.configured_resource_policies) == 0 || local.resource_policy_evaluator_available
    error_message = "resource_policy_enforcement contains enabled entries but resource_policy_enforcement_lambda_arn is empty. aws_config_organization_custom_rule requires the ARN of a Lambda evaluator, so no Config rule and no remediation is created. Deploy the evaluator and pass its ARN to activate the rules."
  }
}

resource "aws_config_remediation_configuration" "resource_policy" {
  for_each = {
    for key, rpe in local.enabled_resource_policies : key => rpe
    if rpe.remediation_action != null
  }

  config_rule_name = aws_config_organization_custom_rule.resource_policy[each.key].name
  target_id        = each.value.remediation_action
  target_type      = "SSM_DOCUMENT"
  automatic        = false
}

check "resource_policy_deployment_targets_warning" {
  assert {
    condition     = !local.resource_policy_has_deployment_targets
    error_message = "One or more resource_policy_enforcement entries have deployment_targets set. Terraform cannot dynamically create providers for cross-account Config rule deployment. Per-account deployment requires Terragrunt per-account stacks or relies on the Config organization rule propagation mechanism."
  }
}
