# Config Recorder in Audit Account (Cross-Account)

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  # Cross-account access parameters, shared with stacks/root.hcl. The unit
  # declares no `generate "provider"` block of its own — two blocks of the
  # same name abort the configuration load for every command. The
  # account resolution sits in cross_account.hcl so that root.hcl and this file
  # read the same value.
  cross_account = read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl")
  account_id    = local.cross_account.locals.account_id

  # Read for the adoption list only (loader local adoption_imports_by_stack).
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

# Resource adoption: declarative import blocks rendered from the adoption
# list (configurations/base/resource-adoptions.json). One import block per
# entry of this stack — e.g. an existing recorder into
# aws_config_configuration_recorder.this; an empty adoption list renders no
# blocks and leaves the plan unchanged.
generate "imports" {
  path      = "adoption-imports.tf"
  if_exists = "overwrite_terragrunt"
  contents = lookup(
    local.compliance.locals.adoption_imports_by_stack,
    "audit/config-recorder",
    "# No adoption entries for this stack (configurations/base/resource-adoptions.json).\n",
  )
}

exclude {
  if      = local.account_id == ""
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/config-recorder-member"
}

dependency "accounts" {
  config_path  = "../../management/accounts"
  skip_outputs = true
}

# The mock bucket name has to satisfy the validation of
# modules/config-recorder-member: the empty string fails it, so validate and plan
# would abort in exactly the situation mock outputs exist for. Same value as in
# the two sibling stacks.
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
