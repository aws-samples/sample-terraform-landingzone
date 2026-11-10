# =============================================================================
# SSM Block Public Document Sharing
# =============================================================================

resource "aws_ssm_service_setting" "public_sharing" {
  count         = var.enable_ssm_block_public_sharing ? 1 : 0
  setting_id    = "arn:${local.partition}:ssm:${local.region}:${local.account_id}:servicesetting/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

check "ssm_block_public_sharing_excluded_account_check" {
  assert {
    condition     = !contains(var.ssm_block_public_sharing_excluded_accounts, local.account_id)
    error_message = "The current account '${local.account_id}' is in ssm_block_public_sharing_excluded_accounts. SSM block public sharing is still created but this account should be excluded from enforcement."
  }
}

# =============================================================================
# SSM Documents
# =============================================================================

locals {
  ssm_docs_with_targets = [
    for d in var.ssm_documents : d.name
    if length(d.deployment_targets) > 0
  ]

  # OU ID -> account IDs, from the declared account-to-OU assignment. The
  # document-sharing API accepts account IDs only, so an OU share target is
  # resolved to the accounts it contains — declaratively from the maps, not
  # by scanning the organization at deployment time.
  ssm_share_ou_id_to_account_ids = {
    for ou_id in distinct(values(var.account_ou_ids)) : ou_id => [
      for account_name, assigned_ou_id in var.account_ou_ids :
      var.account_ids[account_name]
      if assigned_ou_id == ou_id && contains(keys(var.account_ids), account_name)
    ]
  }

  # Effective share list per document: entries without per-document targets
  # keep the global list verbatim, byte for byte;
  # per-document accounts (IDs or resolved names) and resolved OU members are
  # united with the global list and deduplicated.
  ssm_document_share_accounts = {
    for d in var.ssm_documents : d.name => (
      length(d.share_targets.accounts) + length(d.share_targets.organizational_units) == 0
      ? var.ssm_document_share_targets
      : distinct(concat(
        var.ssm_document_share_targets,
        [
          for entry in d.share_targets.accounts :
          can(regex("^[0-9]{12}$", entry)) ? entry : var.account_ids[entry]
        ],
        flatten([
          for ou in d.share_targets.organizational_units :
          lookup(local.ssm_share_ou_id_to_account_ids, var.ou_name_to_id[ou], [])
        ]),
      ))
    )
  }

  # OU share targets that resolve to no account: the name is known (the
  # validation guarantees that), but no declared account is placed in it, so
  # the document reaches fewer accounts than the entry suggests.
  ssm_document_share_empty_ous = distinct(flatten([
    for d in var.ssm_documents : [
      for ou in d.share_targets.organizational_units :
      ou
      if length(lookup(local.ssm_share_ou_id_to_account_ids, lookup(var.ou_name_to_id, ou, ""), [])) == 0
    ]
  ]))
}

check "ssm_document_share_empty_ou_warning" {
  assert {
    condition     = length(local.ssm_document_share_empty_ous) == 0
    error_message = "One or more ssm_documents share_targets organizational units resolve to no account [${join(", ", local.ssm_document_share_empty_ous)}]. The OU name is known, but account_ou_ids places no account in it — the document is shared with fewer accounts than the entry suggests."
  }
}

check "ssm_documents_deployment_targets_warning" {
  assert {
    condition     = length(local.ssm_docs_with_targets) == 0
    error_message = "ssm_documents with deployment_targets detected [${join(", ", local.ssm_docs_with_targets)}]. Terraform cannot dynamically create providers for cross-account SSM document deployment. Documents will only be created in the Management Account."
  }
}

resource "aws_ssm_document" "custom" {
  for_each = { for d in var.ssm_documents : d.name => d }

  name          = each.value.name
  document_type = each.value.document_type
  content       = each.value.content
  target_type   = each.value.target_type

  permissions = length(local.ssm_document_share_accounts[each.value.name]) > 0 ? {
    type        = "Share"
    account_ids = join(",", local.ssm_document_share_accounts[each.value.name])
  } : null
}

# =============================================================================
# Resource Policy Enforcement SSM Document
# =============================================================================

resource "aws_ssm_document" "resource_policy_enforcement" {
  count = length(var.resource_policy_enforcement) > 0 && var.resource_policy_enforcement_document != "" ? 1 : 0

  name            = "tlz-resource-policy-enforcement"
  document_type   = "Automation"
  document_format = "YAML"
  content         = var.resource_policy_enforcement_document

  permissions = length(var.ssm_document_share_targets) > 0 ? {
    type        = "Share"
    account_ids = join(",", var.ssm_document_share_targets)
  } : null
}

# =============================================================================
# SSM Resource Data Sync
# =============================================================================

resource "aws_ssm_resource_data_sync" "this" {
  count = var.enable_ssm_resource_data_sync && var.central_log_bucket_name != "" ? 1 : 0

  name = "tlz-ssm-inventory-sync"

  s3_destination {
    bucket_name = var.central_log_bucket_name
    prefix      = var.ssm_resource_data_sync_prefix
    region      = local.region
  }
}
