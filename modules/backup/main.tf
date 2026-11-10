# modules/backup — AWS Backup Vaults
# Creates AWS Backup Vaults in the Management Account.
# When deployment_targets is specified, an access policy allows those accounts to write backups.
# When kms_key_arn is not provided, a dedicated KMS key is auto-created per vault.

locals {
  # Build a map keyed by vault name for for_each
  backup_vault_map = { for v in var.backup_vaults : v.name => v }

  # Vaults that need an auto-created KMS key (kms_key_arn is null or empty)
  backup_vaults_needing_kms = {
    for name, v in local.backup_vault_map : name => v
    if v.kms_key_arn == null || v.kms_key_arn == ""
  }

  # Resolve deployment_targets to account IDs. A target is either a 12-digit
  # account ID or a key of var.account_ids — both forms are enforced by the
  # variable validation, so the map access below cannot fall back to an
  # unresolved name that would end up in a principal ARN.
  backup_vault_account_ids = {
    for name, v in local.backup_vault_map : name => [
      for target in v.deployment_targets :
      can(regex("^[0-9]{12}$", target)) ? target : var.account_ids[target]
    ]
  }

  arn_prefix = "arn:${data.aws_partition.current.partition}"
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

# =============================================================================
# Auto-Created KMS Keys for Backup Vaults
# =============================================================================

resource "aws_kms_key" "backup" {
  for_each = local.backup_vaults_needing_kms

  description             = "KMS key for AWS Backup vault ${each.key}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/backup/kms-key-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = data.aws_caller_identity.current.account_id
    dns_suffix = data.aws_partition.current.dns_suffix
  })))
}

resource "aws_kms_alias" "backup" {
  for_each = local.backup_vaults_needing_kms

  name          = "alias/tlz/backup/${each.key}"
  target_key_id = aws_kms_key.backup[each.key].key_id
}

resource "aws_backup_vault" "this" {
  for_each = local.backup_vault_map

  name = each.value.name
  kms_key_arn = (
    each.value.kms_key_arn != null && each.value.kms_key_arn != ""
    ? each.value.kms_key_arn
    : aws_kms_key.backup[each.key].arn
  )
}

# The one access policy of a vault, from one of two sources: a full document
# handed in as a JSON string (each.value.policy, read from a file by the
# configuration layer), or the write-access policy the module derives from
# deployment_targets. The variable validation refuses both at once. The
# resource keeps its name: the address is where existing state lives, and a
# rename would demand a state move for a change that changes nothing.
resource "aws_backup_vault_policy" "this" {
  for_each = {
    for name, v in local.backup_vault_map : name => v
    if length(v.deployment_targets) > 0 || v.policy != null
  }

  backup_vault_name = aws_backup_vault.this[each.key].name

  # jsonencode(jsondecode(...)) normalizes both sources the same way the other
  # policies of this repository are normalized.
  policy = (
    each.value.policy != null
    ? jsonencode(jsondecode(each.value.policy))
    : jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/backup/vault-access-policy.json", {
      principal_arns_json = jsonencode([
        for acct_id in local.backup_vault_account_ids[each.key] :
        "${local.arn_prefix}:iam::${acct_id}:root"
      ])
    })))
  )
}
