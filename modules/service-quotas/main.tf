locals {
  enabled_quotas = {
    for q in var.service_quota_increases :
    "${q.service_code}/${q.quota_code}" => q
    if q.enabled
  }

  has_deployment_targets = anytrue([
    for q in var.service_quota_increases : length(q.deployment_targets) > 0
  ])
}

resource "aws_servicequotas_service_quota" "this" {
  for_each = local.enabled_quotas

  service_code = each.value.service_code
  quota_code   = each.value.quota_code
  value        = each.value.desired_value
}

check "service_quota_deployment_targets_warning" {
  assert {
    condition     = !local.has_deployment_targets
    error_message = "One or more service_quota_increases entries have deployment_targets set. Terraform cannot dynamically create providers for cross-account quota requests. Per-account deployment requires Terragrunt per-account stacks under stacks/workload-*/service-quotas/."
  }
}
