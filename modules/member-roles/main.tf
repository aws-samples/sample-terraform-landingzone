# Member roles module: the roles and customer-managed policies whose
# deployment_targets name one member account, created in that account.
#
# The provider points at the member account (stacks/management/member-roles
# calls this module once per account through a provider that assumes the
# account access role). The module makes no data source call, so an account
# none of the entries targets is never contacted.

locals {
  arn_prefix = "arn:${var.partition}"

  # The names a deployment target may use for this account: its name, its ID
  # and the name of the OU it sits in.
  account_targets = concat(
    [var.account_name, var.account_id],
    [for name, id in var.ou_name_to_id : name if var.account_ou_id != "" && id == var.account_ou_id],
  )

  roles_map = {
    for role in var.roles : role.name => role
    if length(setintersection(role.deployment_targets, local.account_targets)) > 0
  }

  policies_map = {
    for policy in var.customer_managed_policies : policy.name => policy
    if length(setintersection(policy.deployment_targets, local.account_targets)) > 0
  }

  # Managed policy entries are partition-neutral names (optionally with a path
  # such as service-role/...), expanded here; a full ARN passes unchanged.
  # Customer-managed policies are attached by name from policies_map.
  role_policy_attachments = merge([
    for name, role in local.roles_map : merge(
      {
        for entry in role.managed_policy_arns :
        "${name}:${entry}" => {
          role_name  = name
          policy_arn = startswith(entry, "arn:") ? entry : "${local.arn_prefix}:iam::aws:policy/${entry}"
        }
      },
      {
        for policy_name in role.customer_managed_policy_names :
        "${name}:${policy_name}" => {
          role_name  = name
          policy_arn = aws_iam_policy.this[policy_name].arn
        }
        if contains(keys(local.policies_map), policy_name)
      },
    )
  ]...)

  role_inline_policies = merge([
    for name, role in local.roles_map : {
      for inline in role.inline_policies :
      "${name}:${inline.name}" => {
        role_name   = name
        policy_name = inline.name
        policy      = inline.policy
      }
    }
  ]...)

  # A permissions boundary given by name (not by ARN) per role.
  boundary_names = {
    for name, role in local.roles_map : name => [
      for boundary in compact([role.permissions_boundary == null ? "" : role.permissions_boundary]) :
      boundary if !startswith(boundary, "arn:")
    ]
  }

  # Customer-managed policies a role in this account refers to by name that
  # are not created in this account.
  missing_policies = distinct(flatten([
    for name, role in local.roles_map : [
      for policy_name in concat(role.customer_managed_policy_names, local.boundary_names[name]) :
      "${name} -> ${policy_name}"
      if !contains(keys(local.policies_map), policy_name)
    ]
  ]))
}

resource "aws_iam_policy" "this" {
  for_each = local.policies_map

  name   = each.value.name
  policy = each.value.policy
}

resource "aws_iam_role" "this" {
  for_each = local.roles_map

  name                 = each.value.name
  path                 = each.value.path
  max_session_duration = each.value.max_session_duration
  assume_role_policy   = each.value.assume_role_policy
  permissions_boundary = (
    length(local.boundary_names[each.key]) > 0
    ? try(aws_iam_policy.this[local.boundary_names[each.key][0]].arn, null)
    : each.value.permissions_boundary == "" ? null : each.value.permissions_boundary
  )

  lifecycle {
    precondition {
      condition     = length(local.missing_policies) == 0
      error_message = "Roles for account ${var.account_name} refer to customer-managed policies that are not deployed to it [${join(", ", local.missing_policies)}]. Give each such policy deployment_targets that include this account."
    }
  }
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each = local.role_policy_attachments

  role       = aws_iam_role.this[each.value.role_name].name
  policy_arn = each.value.policy_arn
}

resource "aws_iam_role_policy" "this" {
  for_each = local.role_inline_policies

  name   = each.value.policy_name
  role   = aws_iam_role.this[each.value.role_name].id
  policy = each.value.policy
}

resource "aws_iam_instance_profile" "this" {
  for_each = { for name, role in local.roles_map : name => role if role.instance_profile }

  name = each.value.name
  role = aws_iam_role.this[each.key].name
}
