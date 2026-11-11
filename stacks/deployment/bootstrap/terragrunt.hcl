# Deployment Bootstrap — creates S3 bucket + DynamoDB lock table in Deployment Account
# No include "root" — uses local state (chicken-and-egg pattern, same as management/bootstrap)
# Excluded when enable_deployment_account=false OR state_backend != "s3"

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # env/accounts.hcl ships empty. An empty deployment_account_id would reach
  # the provider's assume_role ARN below as an empty account segment, and AWS
  # would reject the malformed ARN long after the actual mistake.
  # Reject the value here by name instead, but only when this unit runs at
  # all — the first two terms mirror the exclude condition, so a disabled
  # deployment account never trips the guard. The abort is carried by file():
  # the function fails on a non-existent path, and the "path" is the message
  # (same pattern as configurations/ou-membership.hcl).
  _deployment_account_id_guard = (
    !local.common.locals.enable_deployment_account
    || local.common.locals.state_backend != "s3"
    || can(regex("^[0-9]{12}$", local.accounts.locals.deployment_account_id))
    ) ? "ok" : file(
    "ERROR: deployment_account_id in env/accounts.hcl is empty or not a 12-digit account ID. The deployment bootstrap assumes a role in that account and cannot build its ARN. Record the deployment account's ID in env/accounts.hcl first."
  )

  # Same assignment as stacks/root.hcl, VERBATIM (no include "root", so it is
  # repeated here; a guard test pins the copies to each other). Outside the
  # repo: a repo-anchored gitignored path is what `git clean -xfd` deletes.
  state_dir = get_env("TLZ_STATE_DIR", "${get_env("HOME", "")}/.tlz-state")

  # Same abort pattern as root.hcl, armed only when this unit runs at all
  # (the first two terms mirror the exclude condition below).
  _state_dir_guard = (
    !local.common.locals.enable_deployment_account
    || local.common.locals.state_backend != "s3"
    || (substr(local.state_dir, 0, 1) == "/" && local.state_dir != "/.tlz-state")
    ) ? "ok" : file(
    "ERROR: the local state directory is not a usable absolute path. Set TLZ_STATE_DIR to an absolute directory outside the repository, or ensure HOME is set for the ~/.tlz-state default. A relative path resolves against the .terragrunt-cache generation and orphans the state."
  )
}

exclude {
  if      = !local.common.locals.enable_deployment_account || local.common.locals.state_backend != "s3"
  actions = ["all"]
}

# Local state (S3 bucket does not exist yet). No include "root", so the
# stable-absolute-out-of-repo rule from stacks/root.hcl is repeated here: an
# empty config lets Terraform's local backend write the state INSIDE the
# .terragrunt-cache generation, where the next config edit orphans it, and a
# repo-anchored path puts live state where `git clean -xfd` deletes it. The
# path must be absolute (a relative one resolves against the cache dir) and
# mirrors root.hcl's <state_dir>/<unit> keying.
remote_state {
  backend = "local"
  config = {
    path = "${local.state_dir}/deployment/bootstrap/terraform.tfstate"
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
      assume_role {
        role_arn = "arn:${local.common.locals.partition}:iam::${local.accounts.locals.deployment_account_id}:role/${local.common.locals.account_access_role_name}"
      }
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

terraform {
  source = "${get_repo_root()}//modules/bootstrap"

  # Refuses a DIRECT `terragrunt plan`/`init`/`apply` here while the deployment
  # account is off or the backend is not "s3": such a call would assume a role
  # in an account this deployment does not use, or create a bucket no unit's
  # backend points at. A hook, not a file()-abort local, for the reason given
  # in stacks/management/bootstrap: `exclude` protects `run --all` only, and a
  # local is evaluated before `exclude` applies.
  before_hook "refuse_without_deployment_account" {
    commands = ["init", "plan", "apply", "destroy", "import", "validate", "refresh", "test"]
    execute  = local.common.locals.enable_deployment_account && local.common.locals.state_backend == "s3" ? ["true"] : ["sh", "-c", "echo 'ERROR: stacks/deployment/bootstrap creates the state bucket and the lock table in the deployment account for enable_deployment_account = true with state_backend = \"s3\", but env/common.hcl sets another configuration. With the deployment account off, stacks/management/bootstrap is the state backend of this deployment.' >&2; exit 1"]
  }
}

inputs = {
  state_bucket_name = local.common.locals.state_bucket_name
  lock_table_name   = local.common.locals.lock_table_name

  # Same alias as in stacks/management/bootstrap: both state buckets are
  # created from modules/bootstrap, and one configuration key governs both.
  kms_key_alias = local.compliance.locals.bootstrap_kms_key_alias
}
