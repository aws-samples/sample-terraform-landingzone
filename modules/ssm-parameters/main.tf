# modules/ssm-parameters — SSM Parameters for cross-account configuration sharing
# Creates SSM parameters in the Management Account.
# deployment_targets is accepted for configuration compatibility but triggers
# a check block warning since Terraform cannot dynamically create cross-account providers.

resource "aws_ssm_parameter" "this" {
  for_each = { for p in var.ssm_parameters : p.name => p }

  name   = each.value.name
  type   = each.value.type
  value  = each.value.value
  key_id = each.value.key_id

  tags = var.default_tags
}

# --- Cross-account deployment warning ---

locals {
  ssm_params_with_targets = [
    for p in var.ssm_parameters : p.name
    if length(p.deployment_targets) > 0
  ]
}

check "ssm_parameters_cross_account_warning" {
  assert {
    condition     = length(local.ssm_params_with_targets) == 0
    error_message = "ssm_parameters with deployment_targets detected [${join(", ", local.ssm_params_with_targets)}]. Terraform cannot dynamically create providers for cross-account SSM parameter deployment. Parameters will only be created in the Management Account. Use CloudFormation StackSets via the customizations module for multi-account deployment."
  }
}
