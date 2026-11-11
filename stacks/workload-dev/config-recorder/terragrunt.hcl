# Config Recorder in Workload-Dev Account (Cross-Account)
# Template for additional workload accounts (workload-staging, workload-prod)
# Copy directory and adjust account name in SSM path

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  # Cross-account access parameters, shared with stacks/root.hcl. The unit
  # declares no `generate "provider"` block of its own — two blocks of the
  # same name abort the configuration load for every command. The
  # account resolution — including the account name derived from the directory —
  # sits in cross_account.hcl so that root.hcl and this file read the same value.
  cross_account = read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl")
  account_id    = local.cross_account.locals.account_id

  # Read for the exclude condition: management/logging is skipped while
  # enable_logging is false and then has no outputs to read on apply.
  common = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
}

exclude {
  if      = local.account_id == "" || !local.common.locals.enable_logging
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/config-recorder-member"
}

dependency "accounts" {
  config_path  = "../../management/accounts"
  skip_outputs = true
}

dependency "logging" {
  config_path = "../../management/logging"

  mock_outputs = {
    central_log_bucket_name = "mock-central-logs"
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  central_log_bucket_name = dependency.logging.outputs.central_log_bucket_name
}
