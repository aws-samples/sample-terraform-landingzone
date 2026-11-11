# CUR — AWS Cost and Usage Report

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
}

exclude {
  if      = !local.common.locals.enable_cost_and_usage_report
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/cur"
}

# CUR API is only available in us-east-1 — override the default provider region
generate "provider_override" {
  path      = "provider_override.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<-EOF
    provider "aws" {
      region  = "us-east-1"
      profile = "${local.common.locals.aws_profile}" != "" ? "${local.common.locals.aws_profile}" : null

      default_tags {
        tags = ${jsonencode(local.common.locals.default_tags)}
      }
    }
  EOF
}

# The report goes to the dedicated bucket this unit creates
# (enable_dedicated_bucket = true), so it needs no bucket of the logging stack
# and no dependency on it: the unit also applies while enable_logging is false.
inputs = {
  enable_cost_and_usage_report = local.common.locals.enable_cost_and_usage_report
  cur_config                   = local.common.locals.cur_config
  s3_bucket_name               = ""
  s3_bucket_region             = "us-east-1" # CUR dedicated bucket is created in us-east-1 (CUR provider region)
  enable_dedicated_bucket      = true
  force_destroy                = local.common.locals.force_destroy

  # The dedicated CUR bucket is created here (enable_dedicated_bucket = true), so
  # its lifecycle and the administrators of its KMS key come from the
  # configuration instead of the module defaults.
  #
  # abort_incomplete_multipart_upload_days is read from the loader local that
  # exists for exactly this access ("Explicit extraction for stack-level
  # access"); that local must stay.
  noncurrent_version_expiration_days     = local.compliance.locals.noncurrent_version_expiration_days
  abort_incomplete_multipart_upload_days = local.compliance.locals.abort_incomplete_multipart_upload_days
  # Full lifecycle rule set of the dedicated CUR bucket: optional pass-through,
  # null keeps the derived rule (the module distinguishes null from []).
  cur_bucket_lifecycle_rules = try(local.common.locals.cur_bucket_lifecycle_rules, null)

  # As in the logging stack, kms_key_administrators is read straight from
  # env/common.hcl — there is nothing to merge.
  kms_key_administrators = local.common.locals.kms_key_administrators
}
