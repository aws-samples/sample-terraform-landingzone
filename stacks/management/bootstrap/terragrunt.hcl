# Bootstrap — creates S3 bucket and DynamoDB for remote state
# No include "root" — uses local state (chicken-and-egg)
# Skipped when state_backend = "local", and when enable_deployment_account = true
# (the state bucket then lives in the deployment account: stacks/deployment/bootstrap)

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # With the deployment account on, stacks/deployment/bootstrap creates the one
  # state bucket of this deployment under the same configured name; this unit
  # would create a second bucket of that global name in the management
  # account. try() keeps a common.hcl without the key on the default path.
  enable_deployment_account = try(local.common.locals.enable_deployment_account, false)

  # Same assignment as stacks/root.hcl, VERBATIM (no include "root", so it is
  # repeated here; a guard test pins the copies to each other). Outside the
  # repo: a repo-anchored gitignored path is what `git clean -xfd` deletes.
  state_dir = get_env("TLZ_STATE_DIR", "${get_env("HOME", "")}/.tlz-state")

  # Same abort pattern as root.hcl, armed only when this unit runs at all
  # (state_backend = "s3" — the exclude below mirrors this condition).
  _state_dir_guard = (
    local.common.locals.state_backend != "s3"
    || (substr(local.state_dir, 0, 1) == "/" && local.state_dir != "/.tlz-state")
    ) ? "ok" : file(
    "ERROR: the local state directory is not a usable absolute path. Set TLZ_STATE_DIR to an absolute directory outside the repository, or ensure HOME is set for the ~/.tlz-state default. A relative path resolves against the .terragrunt-cache generation and orphans the state."
  )
}

exclude {
  if      = local.common.locals.state_backend != "s3" || local.enable_deployment_account
  actions = ["all"]
}

# Local state (the S3 bucket does not exist yet). No include "root", so the
# stable-absolute-out-of-repo rule from stacks/root.hcl is repeated here: an
# empty config lets Terraform's local backend write the state INSIDE the
# .terragrunt-cache generation, where the next config edit orphans it, and a
# repo-anchored path puts live state where `git clean -xfd` deletes it. The
# path must be absolute (a relative one resolves against the cache dir) and
# mirrors root.hcl's <state_dir>/<unit> keying.
remote_state {
  backend = "local"
  config = {
    path = "${local.state_dir}/management/bootstrap/terraform.tfstate"
  }
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<-EOF
    provider "aws" {
      region  = "${local.common.locals.region}"
      profile = "${local.common.locals.aws_profile}" != "" ? "${local.common.locals.aws_profile}" : null

      default_tags {
        tags = ${jsonencode(local.common.locals.default_tags)}
      }
    }
  EOF
}

generate "versions" {
  path      = "versions.tf"
  if_exists = "skip"
  contents  = <<-EOF
    terraform {
      required_version = ">= 1.14"
      required_providers {
        aws = {
          source  = "hashicorp/aws"
          version = "~> 6.0"
        }
      }
    }
  EOF
}

# Refuses a DIRECT `terragrunt plan`/`init`/`apply` here while env/common.hcl's
# state_backend is not "s3" (such a call would create the lock table and try
# the placeholder bucket). A hook, not a file()-abort local:
# terragrunt evaluates a unit's locals while discovering `run --all`, before
# `exclude` applies, so an abort local breaks the whole all-mode run on the
# shipped default; a before_hook only runs when this unit actually executes.
# `test` is listed because a warm cache plus `--no-auto-init` skips the init hook.
terraform {
  source = "${get_repo_root()}//modules/bootstrap"

  before_hook "refuse_non_s3_backend" {
    commands = ["init", "plan", "apply", "destroy", "import", "validate", "refresh", "test"]
    execute  = local.common.locals.state_backend == "s3" ? ["true"] : ["sh", "-c", "echo 'ERROR: stacks/management/bootstrap creates the S3 bucket and the DynamoDB lock table for state_backend = \"s3\", but env/common.hcl sets another backend. Set state_backend = \"s3\" with the real bucket and lock table names first (docs/operations.md, Switching the backend from local to S3), then run this unit.' >&2; exit 1"]
  }

  # Same mechanism for the deployment account: `exclude` keeps this unit out of
  # `run --all`, the hook refuses a direct call that would create the second
  # bucket of the same name in the management account.
  before_hook "refuse_deployment_account_mode" {
    commands = ["init", "plan", "apply", "destroy", "import", "validate", "refresh", "test"]
    execute  = local.enable_deployment_account ? ["sh", "-c", "echo 'ERROR: stacks/management/bootstrap is not the state backend of this deployment: enable_deployment_account = true puts the state bucket in the deployment account; run stacks/deployment/bootstrap.' >&2; exit 1"] : ["true"]
  }
}

# No dependencies — Bootstrap is the first step
inputs = {
  state_bucket_name = local.common.locals.state_bucket_name
  lock_table_name   = local.common.locals.lock_table_name

  # The alias of the state bucket's KMS key. Without it the module default
  # applies — an empty alias, which means "no customer managed key, encrypt
  # with AES256". The loader local
  # carries the bootstrap_ prefix because kms_key_alias is a variable name
  # several modules use; the key in env/common.hcl is kms_key_alias.
  kms_key_alias = local.compliance.locals.bootstrap_kms_key_alias
}
