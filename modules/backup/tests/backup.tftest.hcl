# =============================================================================
# Backup Module Tests (modules/backup)
# =============================================================================
# Mandatory scenarios:
#   1. Toggle-Off — the module has NO enable_* variable. Resource creation is
#      driven solely by the backup_vaults list, so the empty list is the
#      module's creation toggle: backup_vaults = [] => zero resources.
#   2. Default configuration — no inputs at all (all variables defaulted).
#   3. Custom configuration — explicit KMS key, deployment targets, account
#      name resolution via account_ids, multiple vaults.
#   4. Validation failures — invalid vault name, invalid kms_key_arn,
#      unresolvable deployment target.
#
# Providers used directly by the module: aws (default only, no aliases).

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off equivalent — empty vault list => zero resources
# -----------------------------------------------------------------------------
run "backup_vaults_empty_toggle_off" {
  command = plan

  variables {
    backup_vaults = []
  }

  assert {
    condition     = length(aws_backup_vault.this) == 0
    error_message = "No backup vaults must be created when list is empty."
  }

  assert {
    condition     = length(aws_backup_vault_policy.this) == 0
    error_message = "No vault policies must be created when list is empty."
  }

  assert {
    condition     = length(aws_kms_key.backup) == 0
    error_message = "No KMS keys must be created when list is empty."
  }

  assert {
    condition     = length(aws_kms_alias.backup) == 0
    error_message = "No KMS aliases must be created when list is empty."
  }

  assert {
    condition     = length(output.backup_vault_names) == 0
    error_message = "backup_vault_names output must be empty."
  }

  assert {
    condition     = length(output.backup_vault_arns) == 0
    error_message = "backup_vault_arns output must be empty."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — no inputs, all variables defaulted
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  assert {
    condition     = length(aws_backup_vault.this) == 0
    error_message = "Default configuration must create no backup vaults."
  }

  assert {
    condition     = length(aws_kms_key.backup) == 0
    error_message = "Default configuration must create no KMS keys."
  }

  assert {
    condition     = length(output.backup_vault_arns) == 0
    error_message = "Default configuration must yield an empty backup_vault_arns map."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2b: Single vault without KMS key => auto-created key
# -----------------------------------------------------------------------------
run "backup_vaults_single_no_kms" {
  command = plan

  variables {
    backup_vaults = [
      {
        name = "my-vault"
      }
    ]
  }

  assert {
    condition     = length(aws_backup_vault.this) == 1
    error_message = "One backup vault must be created."
  }

  assert {
    condition     = length(output.backup_vault_names) == 1
    error_message = "backup_vault_names must contain one entry."
  }

  assert {
    condition     = aws_backup_vault.this["my-vault"].name == "my-vault"
    error_message = "Vault name must match input."
  }

  assert {
    condition     = length(aws_kms_key.backup) == 1
    error_message = "A dedicated KMS key must be auto-created when kms_key_arn is omitted."
  }

  assert {
    condition     = aws_kms_alias.backup["my-vault"].name == "alias/tlz/backup/my-vault"
    error_message = "Auto-created KMS alias must follow the alias/tlz/backup/<vault> convention."
  }

  assert {
    condition     = aws_kms_key.backup["my-vault"].enable_key_rotation == true
    error_message = "Auto-created KMS keys must have rotation enabled."
  }
}

run "backup_vaults_with_kms" {
  command = plan

  variables {
    backup_vaults = [
      {
        name        = "encrypted-vault"
        kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/test-key-id"
      }
    ]
  }

  assert {
    condition     = length(aws_backup_vault.this) == 1
    error_message = "One backup vault must be created with KMS key."
  }

  assert {
    condition     = aws_backup_vault.this["encrypted-vault"].kms_key_arn == "arn:aws:kms:eu-central-1:123456789012:key/test-key-id"
    error_message = "Vault KMS key ARN must match input."
  }

  assert {
    condition     = length(aws_kms_key.backup) == 0
    error_message = "No KMS key must be auto-created when kms_key_arn is supplied."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — multiple vaults, targets, account_ids
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    account_ids = {
      "Audit"      = "111111111111"
      "LogArchive" = "222222222222"
    }
    backup_vaults = [
      {
        name               = "vault-a"
        deployment_targets = ["Audit", "LogArchive"]
      },
      {
        name        = "vault-b"
        kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/key-b"
      }
    ]
  }

  assert {
    condition     = length(aws_backup_vault.this) == 2
    error_message = "Two backup vaults must be created."
  }

  assert {
    condition     = length(output.backup_vault_names) == 2
    error_message = "backup_vault_names must contain two entries."
  }

  assert {
    condition     = length(aws_kms_key.backup) == 1
    error_message = "Only the vault without an explicit KMS key gets an auto-created key."
  }

  assert {
    condition     = length(aws_backup_vault_policy.this) == 1
    error_message = "Only the vault with deployment_targets gets an access policy."
  }

  assert {
    condition     = strcontains(aws_backup_vault_policy.this["vault-a"].policy, "arn:aws:iam::111111111111:root")
    error_message = "Account names in deployment_targets must be resolved through account_ids."
  }

  assert {
    condition     = strcontains(aws_backup_vault_policy.this["vault-a"].policy, "arn:aws:iam::222222222222:root")
    error_message = "All deployment_targets must appear as principals in the vault policy."
  }

  # --- Resolved principals ---------------------------------------------------
  # An unresolved account name must never be carried into the principal ARN
  # (arn:aws:iam::<name>:root). Only resolved account IDs may appear.
  assert {
    condition     = !strcontains(aws_backup_vault_policy.this["vault-a"].policy, "iam::Audit:root")
    error_message = "An account name must never appear inside a principal ARN."
  }

  assert {
    condition = alltrue([
      for account_id in local.backup_vault_account_ids["vault-a"] :
      can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "Every resolved deployment target must be a 12-digit account ID."
  }
}

run "backup_vaults_with_raw_account_ids" {
  command = plan

  variables {
    backup_vaults = [
      {
        name               = "shared-vault"
        deployment_targets = ["111111111111", "222222222222"]
      }
    ]
  }

  assert {
    condition     = length(aws_backup_vault.this) == 1
    error_message = "One backup vault must be created."
  }

  assert {
    condition     = length(aws_backup_vault_policy.this) == 1
    error_message = "Vault access policy must be created when deployment_targets is specified."
  }
}

run "backup_vaults_no_policy_without_targets" {
  command = plan

  variables {
    backup_vaults = [
      {
        name = "mgmt-only-vault"
      }
    ]
  }

  assert {
    condition     = length(aws_backup_vault_policy.this) == 0
    error_message = "No vault policy must be created when deployment_targets is empty."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "invalid_vault_name_rejected" {
  command = plan

  variables {
    backup_vaults = [
      {
        name = "invalid vault name!"
      }
    ]
  }

  expect_failures = [var.backup_vaults]
}

run "invalid_kms_key_arn_rejected" {
  command = plan

  variables {
    backup_vaults = [
      {
        name        = "vault-with-bad-arn"
        kms_key_arn = "not-an-arn"
      }
    ]
  }

  expect_failures = [var.backup_vaults]
}

# A deployment target that account_ids cannot resolve is rejected at plan
# time instead of becoming arn:<partition>:iam::<name>:root.
run "unresolvable_deployment_target_rejected" {
  command = plan

  variables {
    account_ids = {
      "Audit" = "111111111111"
    }
    backup_vaults = [
      {
        name               = "vault-with-unknown-target"
        deployment_targets = ["Aduit"]
      }
    ]
  }

  expect_failures = [var.backup_vaults]
}

run "deployment_target_without_account_ids_rejected" {
  command = plan

  variables {
    backup_vaults = [
      {
        name               = "vault-without-account-map"
        deployment_targets = ["workloads"]
      }
    ]
  }

  expect_failures = [var.backup_vaults]
}

# -----------------------------------------------------------------------------
# Scenario 5: Vault access policy from a document
# -----------------------------------------------------------------------------
# A vault takes its full access policy as a JSON string (read from a file by
# the configuration layer), as an alternative to the write-access policy the
# module derives from deployment_targets. Both describe the one policy of the
# vault, so the plan refuses the combination.

run "backup_vault_policy_reaches_the_vault" {
  command = plan

  variables {
    backup_vaults = [
      {
        name   = "policy-vault"
        policy = "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"DenyDelete\", \"Effect\": \"Deny\", \"Principal\": \"*\", \"Action\": \"backup:DeleteRecoveryPoint\", \"Resource\": \"*\"}]}"
      }
    ]
  }

  assert {
    condition     = length(aws_backup_vault_policy.this) == 1
    error_message = "A vault with a policy document must get its access policy without deployment_targets."
  }

  assert {
    condition     = strcontains(aws_backup_vault_policy.this["policy-vault"].policy, "DenyDelete")
    error_message = "The handed-in document must reach the vault policy."
  }

  assert {
    condition     = aws_backup_vault_policy.this["policy-vault"].policy == jsonencode(jsondecode("{\"Version\": \"2012-10-17\", \"Statement\": [{\"Sid\": \"DenyDelete\", \"Effect\": \"Deny\", \"Principal\": \"*\", \"Action\": \"backup:DeleteRecoveryPoint\", \"Resource\": \"*\"}]}"))
    error_message = "The document must be normalized the same way the other policies of the repository are."
  }
}

run "backup_vault_policy_and_targets_rejected" {
  command = plan

  variables {
    backup_vaults = [
      {
        name               = "conflicted-vault"
        deployment_targets = ["111111111111"]
        policy             = "{\"Version\": \"2012-10-17\", \"Statement\": []}"
      }
    ]
  }

  expect_failures = [var.backup_vaults]
}

run "backup_vault_policy_not_json_rejected" {
  command = plan

  variables {
    backup_vaults = [
      {
        name   = "broken-vault"
        policy = "not a policy"
      }
    ]
  }

  expect_failures = [var.backup_vaults]
}

run "backup_vault_policy_without_statement_rejected" {
  command = plan

  variables {
    backup_vaults = [
      {
        name   = "half-a-policy-vault"
        policy = "{\"Version\": \"2012-10-17\"}"
      }
    ]
  }

  expect_failures = [var.backup_vaults]
}
