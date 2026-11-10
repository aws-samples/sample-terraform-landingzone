# --- AWS Organization ---
# Manages the Organization. For existing orgs, set var.import_organization_id
# to the org ID (e.g. "o-abc123") — Terraform will import it automatically.
# When empty, a new Organization is created.

import {
  for_each = var.import_organization_id != "" ? toset([var.import_organization_id]) : toset([])
  to       = aws_organizations_organization.this
  id       = each.value
}

resource "aws_organizations_organization" "this" {
  lifecycle {
    # Hard dependency: the OU hierarchy is materialised by five level-bound
    # resources. An OU whose parent chain does not reach the root within five
    # levels — a typo in parent_name, a cycle, a sixth level — is placed by no
    # resource, would silently not be created, and would be missing from
    # ou_name_to_id afterwards.
    precondition {
      condition     = length(local.unplaced_ou_names) == 0
      error_message = "The OU hierarchy does not place [${join(", ", local.unplaced_ou_names)}]. Every organizational_units entry must reach the organization root through at most five parent_name hops, and the chain must not contain a cycle. Declared OUs: [${join(", ", sort([for ou in var.organizational_units : ou.name]))}]."
    }

    # Hard dependency: a policy target must resolve to a target ID.
    precondition {
      condition     = length(local.unresolvable_policy_targets) == 0
      error_message = "Unresolvable policy targets [${join(", ", local.unresolvable_policy_targets)}]. Each target must be \"Root\", the name of a declared organizational unit, or a 12-digit account ID. Known names: [${join(", ", sort(local.known_target_names))}]."
    }
  }

  feature_set = var.feature_set

  # The resource owns the COMPLETE list: a type the organization has enabled
  # and nothing here names is disabled on apply. An adopted organization keeps
  # such a type through additional_enabled_policy_types.
  enabled_policy_types = distinct(concat(compact([
    length(var.service_control_policies) > 0 || var.enable_pipeline_scp || var.enable_quarantine_scp ? "SERVICE_CONTROL_POLICY" : "",
    length(var.tag_policies) > 0 ? "TAG_POLICY" : "",
    length(var.backup_policies) > 0 ? "BACKUP_POLICY" : "",
    length(var.resource_control_policies) > 0 ? "RESOURCE_CONTROL_POLICY" : "",
    length(var.declarative_policies) > 0 ? "DECLARATIVE_POLICY_EC2" : "",
    length(var.chatbot_policies) > 0 ? "CHATBOT_POLICY" : "",
  ]), var.additional_enabled_policy_types))

  aws_service_access_principals = var.aws_service_access_principals
}

# --- Organizational Units (5 levels) ---

resource "aws_organizations_organizational_unit" "level_1" {
  for_each = local.level_1_ous

  name      = each.key
  parent_id = local.resolved_root_id
}

resource "aws_organizations_organizational_unit" "level_2" {
  for_each = local.level_2_ous

  name      = each.key
  parent_id = aws_organizations_organizational_unit.level_1[each.value.parent_name].id
}

resource "aws_organizations_organizational_unit" "level_3" {
  for_each = local.level_3_ous

  name      = each.key
  parent_id = aws_organizations_organizational_unit.level_2[each.value.parent_name].id
}

resource "aws_organizations_organizational_unit" "level_4" {
  for_each = local.level_4_ous

  name      = each.key
  parent_id = aws_organizations_organizational_unit.level_3[each.value.parent_name].id
}

resource "aws_organizations_organizational_unit" "level_5" {
  for_each = local.level_5_ous

  name      = each.key
  parent_id = aws_organizations_organizational_unit.level_4[each.value.parent_name].id
}

# --- Policy types are managed via aws_organizations_organization.this ---

# --- Opt-In Region Auto-Enablement ---
# Enables opt-in regions (e.g. af-south-1, ap-east-1) via the AWS Account API.
# If a region is already enabled, Terraform will detect no drift.

resource "aws_account_region" "this" {
  for_each = toset(var.opt_in_regions)

  region_name = each.value
  enabled     = true
}

# --- Delegated Administrator ---

resource "aws_organizations_delegated_administrator" "this" {
  for_each = {
    for principal in var.service_access_principals :
    "${principal.service_principal}:${principal.account_id}" => principal
  }

  account_id        = each.value.account_id
  service_principal = each.value.service_principal

  # RegisterDelegatedAdministrator fails with AccountNotRegisteredException
  # ("You must enable service access before you can register a delegated
  # administrator") unless the service already has trusted access enabled on
  # the organization. Trusted access is set by aws_service_access_principals on
  # aws_organizations_organization.this, and nothing in the data flow links the
  # two resources — service_principal here is a plain string, not a reference to
  # the org — so Terraform is free to register the administrator first. This
  # ordering hit the org live (RegisterDelegatedAdministrator /
  # AccountNotRegisteredException); depends_on forces the org update to complete
  # before any registration. depends_on alone cannot guarantee the principal is
  # actually IN the trusted-access list — a delegated administrator for a
  # service absent from aws_service_access_principals would still race — so it
  # is paired with the cross-variable validation on var.service_access_principals
  # that requires every service_principal to appear there at plan time.
  depends_on = [aws_organizations_organization.this]
}
