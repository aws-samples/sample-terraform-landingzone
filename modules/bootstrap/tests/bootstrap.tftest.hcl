# =============================================================================
# Bootstrap Module Tests (modules/bootstrap)
# =============================================================================
# Coverage:
#   - Toggle-Off scenario: the module has NO enable_* variable. The optional
#     part of the module is gated by kms_key_alias == "" (empty = no custom
#     key), which is the module's toggle equivalent. The scenario below
#     verifies that zero KMS resources are created in that state.
#   - Default configuration (only the required state_bucket_name is set)
#   - Custom configuration (custom lock table + KMS key alias)
#   - Validation failure scenarios (invalid bucket name, lock table, alias)
#
# Providers used by the module: aws (default only, no aliases).

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }
}

variables {
  state_bucket_name = "tlz-tfstate-123456789012-eu-central-1"
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off equivalent — no KMS key alias => zero KMS resources
# -----------------------------------------------------------------------------
run "kms_disabled_no_kms_resources" {
  command = plan

  variables {
    kms_key_alias = ""
  }

  assert {
    condition     = length(aws_kms_key.state) == 0
    error_message = "No KMS key must be created when kms_key_alias is empty."
  }

  assert {
    condition     = length(aws_kms_alias.state) == 0
    error_message = "No KMS alias must be created when kms_key_alias is empty."
  }

  assert {
    condition     = output.kms_key_arn == ""
    error_message = "kms_key_arn output must be empty when no KMS key is created."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "Bucket encryption must fall back to AES256 when no KMS key is created."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.state.rule).bucket_key_enabled == false
    error_message = "bucket_key_enabled must be false when no KMS key is created."
  }

  # Without an alias the lock table must not declare a
  # server_side_encryption block — the DynamoDB service default (AWS-owned
  # key) applies and no KMS dependency is created.
  assert {
    condition     = length(aws_dynamodb_table.lock.server_side_encryption) == 0
    error_message = "Without a KMS alias the lock table must keep the DynamoDB default encryption (no server_side_encryption block)."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  assert {
    condition     = aws_s3_bucket.state.bucket == "tlz-tfstate-123456789012-eu-central-1"
    error_message = "State bucket name must match the input variable."
  }

  assert {
    condition     = aws_dynamodb_table.lock.name == "terraform-locks"
    error_message = "Lock table name must default to terraform-locks."
  }

  assert {
    condition     = aws_dynamodb_table.lock.billing_mode == "PAY_PER_REQUEST"
    error_message = "Lock table must use on-demand billing."
  }

  assert {
    condition     = aws_dynamodb_table.lock.hash_key == "LockID"
    error_message = "Lock table hash key must be LockID."
  }

  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "State bucket versioning must be enabled."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.block_public_acls == true
    error_message = "State bucket must block public ACLs."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.restrict_public_buckets == true
    error_message = "State bucket must restrict public buckets."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.state.rule[0].noncurrent_version_expiration[0].noncurrent_days == 90
    error_message = "Noncurrent state versions must expire after 90 days."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — custom lock table and KMS key
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    state_bucket_name = "my-custom-state-bucket"
    lock_table_name   = "my-custom-locks"
    kms_key_alias     = "tlz/terraform-state"
  }

  assert {
    condition     = aws_s3_bucket.state.bucket == "my-custom-state-bucket"
    error_message = "State bucket name must match the custom input."
  }

  assert {
    condition     = aws_dynamodb_table.lock.name == "my-custom-locks"
    error_message = "Lock table name must match the custom input."
  }

  assert {
    condition     = length(aws_kms_key.state) == 1
    error_message = "One KMS key must be created when kms_key_alias is set."
  }

  assert {
    condition     = length(aws_kms_alias.state) == 1
    error_message = "One KMS alias must be created when kms_key_alias is set."
  }

  assert {
    condition     = aws_kms_alias.state[0].name == "alias/tlz/terraform-state"
    error_message = "KMS alias must be prefixed with alias/."
  }

  assert {
    condition     = aws_kms_key.state[0].enable_key_rotation == true
    error_message = "KMS key rotation must be enabled."
  }

  assert {
    condition     = aws_kms_key.state[0].deletion_window_in_days == 30
    error_message = "KMS key deletion window must be 30 days."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "Bucket encryption must use aws:kms when a KMS key is created."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.state.rule).bucket_key_enabled == true
    error_message = "bucket_key_enabled must be true when a KMS key is created."
  }

  # With an alias set, the lock table must be encrypted
  # with the same customer-managed key as the state bucket.
  assert {
    condition     = one(aws_dynamodb_table.lock.server_side_encryption).enabled == true
    error_message = "With a KMS alias the lock table must declare server_side_encryption with enabled = true."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "invalid_state_bucket_name_rejected" {
  command = plan

  variables {
    state_bucket_name = "Invalid_Bucket_Name"
  }

  expect_failures = [var.state_bucket_name]
}

run "invalid_lock_table_name_rejected" {
  command = plan

  variables {
    lock_table_name = ""
  }

  expect_failures = [var.lock_table_name]
}

run "invalid_kms_key_alias_rejected" {
  command = plan

  variables {
    kms_key_alias = "invalid alias!"
  }

  expect_failures = [var.kms_key_alias]
}

# -----------------------------------------------------------------------------
# The configured alias reaches the KMS alias
#
# stacks/management/bootstrap and stacks/deployment/bootstrap pass
# var.kms_key_alias from the configuration. The two runs below hold both ends
# of that path: a value coming from the configuration names the alias and
# governs the bucket encryption, and the untouched default (an empty alias,
# no customer managed key) keeps the bucket on AES256.
# -----------------------------------------------------------------------------
run "regression_kms_alias_from_configuration_names_the_alias" {
  command = plan

  variables {
    kms_key_alias = "tlz/tfstate-management"
  }

  assert {
    condition     = aws_kms_alias.state[0].name == "alias/tlz/tfstate-management"
    error_message = "The alias passed in must name the KMS alias, prefixed with alias/."
  }

  assert {
    condition     = length(aws_kms_key.state) == 1
    error_message = "A non-empty alias must create exactly one KMS key."
  }

  # The alias does not only name a key, it switches the bucket to SSE-KMS —
  # without this the alias would be decoration. The key ARN itself is unknown
  # before apply, so the assertion holds the algorithm and the bucket key.
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
    error_message = "The state bucket must switch to SSE-KMS once an alias is configured."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.state.rule).bucket_key_enabled == true
    error_message = "S3 Bucket Keys must be enabled once the bucket runs on SSE-KMS."
  }
}

run "regression_kms_alias_default_keeps_the_bucket_on_aes256" {
  command = plan

  # kms_key_alias deliberately unset: this run asserts the module *default*,
  # which is the value every deployment used before the repair.
  assert {
    condition     = length(aws_kms_key.state) == 0
    error_message = "The module default must not create a KMS key."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "Without an alias the state bucket must stay on AES256."
  }
}
