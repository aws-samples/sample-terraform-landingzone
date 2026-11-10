# customizations/cloudformation — User-Defined CloudFormation Stacks and StackSets
#
# Deploys CloudFormation templates from the configuration layer: plain stacks
# into the current account and region, StackSets across the organization.
# SERVICE_MANAGED StackSets target organizational units directly — including
# auto-deployment to accounts that later join the OU and an account exclusion
# filter — which is the one deployment shape the per-account stack layout
# cannot express. SELF_MANAGED StackSets target explicit account lists through
# the StackSet administration/execution roles that modules/iam creates behind
# enable_stackset_roles.
#
# The template always arrives as a string (template_body): the stack layer
# reads it from the configuration — inline or via file path — so the module
# stays free of path assumptions.

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

locals {
  # Use this prefix whenever an ARN is built by hand — never write the
  # partition as a literal (see docs/multi-partition.md).
  arn_prefix = "arn:${data.aws_partition.current.partition}"

  stacks_map     = { for s in var.cloudformation_stacks : s.name => s }
  stack_sets_map = { for s in var.cloudformation_stack_sets : s.name => s }

  # organizational_units entries may be OU names (resolved via the map the
  # organization stack supplies) or raw ou-/r- IDs (passed through).
  stack_set_ou_ids = {
    for name, s in local.stack_sets_map :
    name => [for ou in s.organizational_units : lookup(var.ou_name_to_id, ou, ou)]
  }

  # One stack-set instance per (stack set, region). regions defaults to the
  # deployment region; service-managed and self-managed instances differ in
  # how they address their targets, so they are two resources.
  service_managed_instances = merge([
    for name, s in local.stack_sets_map : {
      for region in coalescelist(s.regions, [var.region]) :
      "${name}:${region}" => { stack_set = name, region = region }
    } if s.permission_model == "SERVICE_MANAGED"
  ]...)

  self_managed_instances = merge([
    for name, s in local.stack_sets_map : {
      for pair in setproduct(s.target_account_ids, coalescelist(s.regions, [var.region])) :
      "${name}:${pair[0]}:${pair[1]}" => {
        stack_set = name
        account   = pair[0]
        region    = pair[1]
      }
    } if s.permission_model == "SELF_MANAGED"
  ]...)
}

# --- Plain stacks: current account, current region ---

resource "aws_cloudformation_stack" "this" {
  for_each = local.stacks_map

  name          = each.value.name
  template_body = each.value.template_body
  parameters    = each.value.parameters
  capabilities  = each.value.capabilities
  # Per-entry stack event notifications (CKV_AWS_124): offered as an input;
  # the deliberately empty default cannot satisfy the static check, which is
  # therefore waived with this justification in .checkov.yaml.
  notification_arns = each.value.notification_arns

  tags = var.default_tags

  lifecycle {
    # An OU name that neither the supplied map nor the ou-/r- ID form covers
    # cannot reach this resource (stacks carry no OU targets) — the check
    # lives on the stack sets below.
    precondition {
      condition     = length(trimspace(each.value.template_body)) > 0
      error_message = "cloudformation_stacks[${each.value.name}].template_body resolved to an empty string — the configuration names a template that was not read."
    }
  }
}

# --- StackSets ---

resource "aws_cloudformation_stack_set" "this" {
  for_each = local.stack_sets_map

  name             = each.value.name
  description      = each.value.description != "" ? each.value.description : null
  template_body    = each.value.template_body
  parameters       = length(each.value.parameters) > 0 ? each.value.parameters : null
  capabilities     = each.value.capabilities
  permission_model = each.value.permission_model

  # Service-managed: CloudFormation deploys through the organization's
  # trusted access — including auto-deployment to accounts that later join a
  # targeted OU. Self-managed: the module names the administration role of
  # modules/iam (enable_stackset_roles) partition-correctly; the execution
  # role of the same pair is the provider default and is pinned explicitly.
  dynamic "auto_deployment" {
    for_each = each.value.permission_model == "SERVICE_MANAGED" ? [1] : []
    content {
      enabled                          = each.value.auto_deployment_enabled
      retain_stacks_on_account_removal = each.value.retain_stacks_on_account_removal
    }
  }

  administration_role_arn = (
    each.value.permission_model == "SELF_MANAGED"
    ? "${local.arn_prefix}:iam::${data.aws_caller_identity.current.account_id}:role/AWSCloudFormationStackSetAdministrationRole"
    : null
  )
  execution_role_name = each.value.permission_model == "SELF_MANAGED" ? "AWSCloudFormationStackSetExecutionRole" : null

  tags = var.default_tags

  lifecycle {
    # Every organizational_units entry must resolve to an ou-/r- ID: either
    # it already is one, or the ou_name_to_id map knows the name. An
    # unresolved name would be handed to the API as a target ID and fail
    # only at deployment time.
    precondition {
      condition = alltrue([
        for ou_id in local.stack_set_ou_ids[each.key] :
        can(regex("^(ou-|r-)", ou_id))
      ])
      error_message = "cloudformation_stack_sets[${each.value.name}].organizational_units contains an entry that is neither an ou-/r- ID nor a name known to ou_name_to_id [${join(", ", [for ou_id in local.stack_set_ou_ids[each.key] : ou_id if !can(regex("^(ou-|r-)", ou_id))])}]."
    }
  }
}

resource "aws_cloudformation_stack_set_instance" "service_managed" {
  for_each = local.service_managed_instances

  stack_set_name            = aws_cloudformation_stack_set.this[each.value.stack_set].name
  stack_set_instance_region = each.value.region

  deployment_targets {
    organizational_unit_ids = local.stack_set_ou_ids[each.value.stack_set]
    # DIFFERENCE removes the excluded accounts from the OU set — the
    # excludedAccounts shape of the configuration, expressed natively.
    account_filter_type = length(local.stack_sets_map[each.value.stack_set].excluded_account_ids) > 0 ? "DIFFERENCE" : null
    accounts            = length(local.stack_sets_map[each.value.stack_set].excluded_account_ids) > 0 ? local.stack_sets_map[each.value.stack_set].excluded_account_ids : null
  }
}

resource "aws_cloudformation_stack_set_instance" "self_managed" {
  for_each = local.self_managed_instances

  stack_set_name            = aws_cloudformation_stack_set.this[each.value.stack_set].name
  stack_set_instance_region = each.value.region
  account_id                = each.value.account
}
