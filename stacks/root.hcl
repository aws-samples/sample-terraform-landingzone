# Root Terragrunt configuration
# Common settings for all units: Remote State, Provider, Retry, Versions

locals {
  # Load environment variables
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))

  region    = local.common.locals.region
  profile   = local.common.locals.aws_profile
  tags      = local.common.locals.default_tags
  partition = local.common.locals.partition

  # --- Deployment Account ---
  # Use try() for backward compatibility — defaults to safe values if not set in common.hcl
  enable_deployment_account = try(local.common.locals.enable_deployment_account, false)
  enable_pipeline           = try(local.common.locals.enable_pipeline, false)
  deployment_account_id     = try(local.accounts.locals.deployment_account_id, "")
  management_account_id     = try(local.accounts.locals.management_account_id, "")
  account_access_role_name  = local.common.locals.account_access_role_name

  # Validation notes:
  # - Pipeline requires S3 state backend and deployment account
  # - These are checked at apply time by Terraform variable validations
  # - Terragrunt 1.0 evaluates both branches of a ternary, so no run_cmd
  #   validation is wrapped in one; the only run_cmd is the clone guard below (deliberate, unconditional)

  # --- Local state backend location ---
  # With state_backend = "local", state lives OUTSIDE the repository:
  # $TLZ_STATE_DIR when set, otherwise ~/.tlz-state. Two hard requirements:
  #   * ABSOLUTE — Terraform's local backend resolves a relative path against
  #     its working directory, which under Terragrunt is the .terragrunt-cache
  #     generation; any env/*.hcl edit re-hashes the unit and orphans the
  #     state.
  #   * OUTSIDE THE REPO — a gitignored path such as <repo>/.state/ is exactly
  #     what `git clean -xfd` deletes. Live state must never sit where a
  #     routine git command removes it (and the clean-root check rejects
  #     `.state` in the repository root).
  # One machine, several TLZ deployments: set TLZ_STATE_DIR per clone — the
  # default is shared per user, and two deployments would collide on the
  # same per-unit keys; the clone guard below refuses that collision. The two
  # bootstrap units do not include this file and repeat this assignment
  # VERBATIM (they run only with state_backend = "s3", so the clone guard
  # does not apply there).
  state_dir = get_env("TLZ_STATE_DIR", "${get_env("HOME", "")}/.tlz-state")

  # Usable means absolute and not the "/.tlz-state" an unset HOME would
  # silently produce in the root filesystem. Both guards below read it.
  _state_dir_usable = substr(local.state_dir, 0, 1) == "/" && local.state_dir != "/.tlz-state"

  # Abort unless the resolved directory is usable and absolute (file() on a
  # non-existent path carries the message — same pattern as the deployment
  # bootstrap's account-id guard). Catches a relative TLZ_STATE_DIR and an
  # unset HOME. Only armed when the local backend is actually in use.
  _state_dir_guard = (
    local.common.locals.state_backend != "local"
    || local._state_dir_usable
    ) ? "ok" : file(
    "ERROR: the local state directory is not a usable absolute path. Set TLZ_STATE_DIR to an absolute directory outside the repository, or ensure HOME is set for the ~/.tlz-state default. A relative path resolves against the .terragrunt-cache generation and orphans the state."
  )

  # --- State clone guard ---
  # Two clones of this repository sharing one local state directory would read
  # and write the SAME per-unit state files without any warning. So a
  # state directory is bound to ONE clone: the first run writes
  # <state_dir>/.tlz-clone carrying this clone's absolute repository path,
  # every later run compares, and a different clone is refused here, at parse
  # time, before any backend is initialised. Fail closed, no migration: the
  # operator either gives the second clone its own TLZ_STATE_DIR or removes
  # the marker of a clone that is gone.
  #
  # The record has to be left as a side effect of parsing, which only run_cmd
  # can do; a before_hook does not fire on `terragrunt render`. Terragrunt
  # evaluates BOTH branches of a ternary, so the call is not wrapped in one:
  # the script receives the backend and is a no-op (no marker, no output) for
  # anything but "local", and likewise for a directory _state_dir_guard is
  # about to refuse. Its one output line is the path the marker holds — the
  # path it just wrote on a first run, so a single clone always compares
  # equal. --terragrunt-global-cache: identical arguments in every unit of a
  # `run --all`, so one call serves them all.
  _clone_marker   = "${local.state_dir}/.tlz-clone"
  _clone_recorded = run_cmd("--terragrunt-quiet", "--terragrunt-global-cache", "${get_repo_root()}/tools/state-clone-guard.sh", local.state_dir, get_repo_root(), local.common.locals.state_backend)
  # One line on purpose: the security scanner's HCL parser (checkov, python-hcl2)
  # does not read a multi-line boolean whose continuation starts with `|| !`,
  # and a file it cannot parse silently leaves the scan (.checkov.yaml: target
  # state Parsing errors: 0). Terraform reads both forms the same.
  _state_clone_ok = local.common.locals.state_backend != "local" || local._state_dir_usable == false || local._clone_recorded == get_repo_root()
  _state_clone_guard = local._state_clone_ok ? "ok" : file(
    "ERROR: the local state directory ${local.state_dir} belongs to another clone of this repository: its marker ${local._clone_marker} names ${local._clone_recorded}, this clone is ${get_repo_root()}. Two clones sharing one state directory read and write the same per-unit state files, so this run is refused. Either give this clone a directory of its own — export TLZ_STATE_DIR=<absolute directory outside the repository>, in every session — or, if the clone at ${local._clone_recorded} is gone for good, remove ${local._clone_marker} and run again."
  )

  # --- Cross-Account Provider (per unit) ---
  # A unit that has to reach into another account must not declare a `generate
  # "provider"` block of its own: two generate blocks of the same name abort the
  # configuration load ("Detected generate blocks with the same name:
  # [provider]") for every command including apply. The role assumption is
  # therefore parameterized here instead: the unit drops a `cross_account.hcl`
  # next to its terragrunt.hcl and this file is the only place that writes
  # provider.tf.
  #
  # get_terragrunt_dir() resolves to the *including* unit's directory, not to
  # stacks/ — that is what get_parent_terragrunt_dir() is for. The second
  # argument of read_terragrunt_config is the value for a missing file, so every
  # unit without a sidecar keeps the management-account provider unchanged.
  _cross_account = read_terragrunt_config(
    "${get_terragrunt_dir()}/cross_account.hcl",
    { locals = { assume_role_arn = "" } }
  )
  cross_account_role_arn = try(local._cross_account.locals.assume_role_arn, "")

  # Pre-compute provider contents (Terragrunt 1.0 can't do ternary with heredocs inline)
  _provider_deployment = <<-EOF
    provider "aws" {
      region = "${local.region}"

      assume_role {
        role_arn = "arn:${local.partition}:iam::${local.management_account_id}:role/TLZDeploymentRole"
      }

      default_tags {
        tags = ${jsonencode(local.tags)}
      }
    }
  EOF

  _provider_direct = <<-EOF
    provider "aws" {
      region  = "${local.region}"
      profile = "${local.profile}" != "" ? "${local.profile}" : null

      default_tags {
        tags = ${jsonencode(local.tags)}
      }
    }
  EOF

  # Local profile plus assume_role into the target account. Deliberately not
  # chained through TLZDeploymentRole — the AWS provider takes one assume_role,
  # and chaining would change the access path of these units.
  _provider_cross_account = <<-EOF
    provider "aws" {
      region  = "${local.region}"
      profile = "${local.profile}" != "" ? "${local.profile}" : null

      default_tags {
        tags = ${jsonencode(local.tags)}
      }

      assume_role {
        role_arn = "${local.cross_account_role_arn}"
      }
    }
  EOF

  # A cross-account unit keeps its own access path; the deployment-account
  # branch applies to the units that run in the management account.
  _provider_contents = (local.cross_account_role_arn != ""
    ? local._provider_cross_account
    : (local.enable_deployment_account ? local._provider_deployment : local._provider_direct)
  )
}

# Remote State: S3 + DynamoDB or local (controlled via state_backend in env/common.hcl)
#
# -----------------------------------------------------------------------------
# ONE-TIME MIGRATION of pre-existing local state (state_backend = "local")
# -----------------------------------------------------------------------------
# Full operator procedure: docs/operations.md, "Migrating local state out of
# the repository". Two starting points, one destination
# ($TLZ_STATE_DIR or ~/.tlz-state):
#
#   * State at <repo>/.state/<unit>/terraform.tfstate: copy the whole tree —
#     the per-unit keying is identical — then delete every
#     stacks/*/.terragrunt-cache so no stale backend record survives.
#     NEVER accept `terraform init`'s offer to migrate/copy state
#     (-migrate-state / -force-copy): both overwrite the destination with the
#     cache-recorded file, which can replace a hand-reconciled state.
#
#   * State still inside stacks/<u>/.terragrunt-cache/*/*/terraform.tfstate:
#     select the authoritative file by CONTENT, never
#     by mtime — a non-empty "resources" array first, then the highest
#     "serial" within the same "lineage". A re-hashed cache means the NEWEST
#     generation often holds the EMPTY state, so mtime picks exactly the
#     wrong file. Copy it to <state_dir>/<unit-path>/terraform.tfstate
#     (unit-path relative to stacks/, e.g. management/security).
#
# In both cases: `terragrunt state list` per unit and confirm the expected
# resources BEFORE trusting any plan/apply — 0 resources means the wrong
# file or the wrong TLZ_STATE_DIR. Delete old copies only after that.
# -----------------------------------------------------------------------------
remote_state {
  backend = local.common.locals.state_backend

  config = local.common.locals.state_backend == "s3" ? merge(
    {
      bucket         = local.common.locals.state_bucket_name
      key            = "${path_relative_to_include()}/terraform.tfstate"
      region         = local.region
      encrypt        = true
      dynamodb_table = local.common.locals.lock_table_name
    },
    # State bucket and lock table live in the deployment account, so the backend
    # has to assume a role there: the cross-account role that every member
    # account already has and that stacks/deployment/bootstrap uses to create
    # the bucket in the first place. No module creates a dedicated state-access
    # role, so naming one would break backend initialization for every unit.
    local.enable_deployment_account ? {
      role_arn = "arn:${local.partition}:iam::${local.deployment_account_id}:role/${local.account_access_role_name}"
      } : {
      profile = local.profile
    }
    ) : {
    # With state_backend = "local" this MUST be set, MUST be absolute, and
    # MUST point outside the repository — see the state_dir local above for
    # the reasons behind those rules. Keyed per unit by
    # path_relative_to_include() exactly like the S3 key above. The two
    # bootstrap units do not include this file and repeat the same shape
    # locally.
    path = "${local.state_dir}/${path_relative_to_include()}/terraform.tfstate"
  }

  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

# Default Provider (Management Account)
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = local._provider_contents
}

# Terraform and provider versions
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
        time = {
          source  = "hashicorp/time"
          version = "~> 0.13"
        }
      }
    }
  EOF
}

# Retry on transient AWS API errors (Terragrunt v1.0 syntax)
errors {
  retry "aws_throttling" {
    retryable_errors = [
      "(?s).*RequestLimitExceeded.*",
      "(?s).*ThrottlingException.*",
      "(?s).*Throttling.*",
      "(?s).*TooManyRequestsException.*",
    ]
    max_attempts       = 5
    sleep_interval_sec = 30
  }

  retry "aws_create_errors" {
    retryable_errors = [
      "(?s).*Error creating.*",
    ]
    max_attempts       = 3
    sleep_interval_sec = 15
  }
}
