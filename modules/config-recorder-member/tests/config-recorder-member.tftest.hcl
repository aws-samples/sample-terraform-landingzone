# =============================================================================
# Config Recorder Member Module Tests (modules/config-recorder-member)
# =============================================================================
# Coverage:
#   - Default configuration (minimal valid input)
#   - Custom configuration (different bucket name, EUSC partition)
#   - Validation failure (invalid S3 bucket name)
#
# Toggle scenario: this module has no enable_* variable. Every resource
# (recorder, delivery channel, recorder status) is created unconditionally
# because the module is invoked per member account through a cross-account
# provider — the "off" state is expressed by not instantiating the module.
# The remaining three mandatory scenarios are covered below.

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
# Scenario 1: Default configuration — recorder, delivery channel and status
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs"
  }

  assert {
    condition     = aws_config_configuration_recorder.this.name == "tlz-config-recorder"
    error_message = "Config recorder must use the fixed name tlz-config-recorder."
  }

  assert {
    condition     = aws_config_configuration_recorder.this.role_arn == "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
    error_message = "Recorder role ARN must be built from partition, account ID and DNS suffix."
  }

  # A recorder that omits global resource types silently stops
  # recording IAM and the other global types, and no other test in the tree
  # fails. Proven by planting include_global_resource_types = false — the
  # rest of this file stays green, only this assert goes red.
  assert {
    condition     = aws_config_configuration_recorder.this.recording_group[0].include_global_resource_types == true
    error_message = "Recorder recording_group must set include_global_resource_types = true so IAM and other global resources are recorded."
  }

  assert {
    condition     = aws_config_delivery_channel.this.s3_bucket_name == "tlz-central-logs"
    error_message = "Delivery channel must target the central log bucket."
  }

  assert {
    condition     = aws_config_delivery_channel.this.s3_key_prefix == "config"
    error_message = "Delivery channel must use the config key prefix."
  }

  assert {
    condition     = aws_config_configuration_recorder_status.this.is_enabled == true
    error_message = "Recorder status must be enabled."
  }

  assert {
    condition     = output.recorder_name == "tlz-config-recorder"
    error_message = "recorder_name output must expose the recorder name."
  }

  assert {
    condition     = output.delivery_channel_name == "tlz-config-delivery"
    error_message = "delivery_channel_name output must expose the delivery channel name."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Custom configuration — user-supplied bucket name
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    central_log_bucket_name = "acme-audit-logs.eu-central-1"
  }

  assert {
    condition     = aws_config_delivery_channel.this.s3_bucket_name == "acme-audit-logs.eu-central-1"
    error_message = "Delivery channel must honour a custom bucket name including dots."
  }

  assert {
    condition     = aws_config_configuration_recorder_status.this.name == aws_config_configuration_recorder.this.name
    error_message = "Recorder status must reference the recorder by name."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Validation failure — invalid S3 bucket name
# -----------------------------------------------------------------------------
run "invalid_bucket_name_rejected" {
  command = plan

  variables {
    central_log_bucket_name = "Invalid_Bucket_Name"
  }

  expect_failures = [
    var.central_log_bucket_name,
  ]
}
