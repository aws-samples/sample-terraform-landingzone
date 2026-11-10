# Cross-account provider parameters for this unit.
#
# A unit must not carry a `generate "provider"` block of its own: two generate
# blocks of the same name abort the configuration load ("Detected generate
# blocks with the same name: [provider]") for every command including apply.
# stacks/root.hcl is the only place that writes provider.tf; it reads this file via
# read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl") and adds an
# assume_role block for `assume_role_arn`.
#
# The account resolution lives here and not in terragrunt.hcl because root.hcl
# is evaluated without access to the unit's locals. terragrunt.hcl reads the
# same file, so `account_id` has exactly one source per unit.
locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))

  # Determine which account holds SSM parameters
  ssm_source_account = local.common.locals.enable_deployment_account ? local.accounts.locals.deployment_account_id : ""
  # Reading from the deployment account needs a role hop. The AWS CLI has no
  # per-call role option, so the hop is an explicit `aws sts assume-role`
  # whose temporary credentials are exported for the get-parameter call in
  # the same shell (pattern from docs/getting-started.md). The operator
  # profile authenticates only the assume-role call; the exported keys take
  # precedence for the parameter read. A failing assume-role short-circuits
  # the chain and its stderr feeds the classification below unchanged.
  ssm_profile_arg = local.common.locals.aws_profile != "" ? " --profile ${local.common.locals.aws_profile}" : ""
  # --region: modules/accounts writes the parameter in the home region (the
  # stacks' provider region); the CLI's own profile or AWS_REGION may name
  # another one, where the read answers ParameterNotFound and drops the unit.
  ssm_get_cmd = "aws ssm get-parameter --name /tlz/accounts/Log-Archive/id --region ${local.common.locals.region} --query Parameter.Value --output text"
  ssm_command = (
    local.ssm_source_account != ""
    ? "creds=$(aws sts assume-role --role-arn arn:${local.common.locals.partition}:iam::${local.ssm_source_account}:role/${local.common.locals.account_access_role_name} --role-session-name tlz-ssm-discovery --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text${local.ssm_profile_arg}) && export $(printf 'AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s' $creds) && ${local.ssm_get_cmd}"
    : "${local.ssm_get_cmd}${local.ssm_profile_arg}"
  )

  # Account-ID resolution (priority: accounts.hcl override → SSM parameter).
  # The parameter is the plain-ID discovery contract written by
  # modules/accounts (/tlz/accounts/<AccountName>/id). stderr is captured
  # (2>&1) and `|| true` only prevents the run_cmd hard-fail so the output
  # can be classified below.
  override_id = local.accounts.locals.log_archive_account_id
  # Terragrunt evaluates both branches of a ternary, so a run_cmd in the
  # unselected branch still executes and only its result is discarded. The
  # override condition therefore also lives inside the command string: with
  # a set override the call degenerates to a no-op `true` instead of firing
  # the AWS CLI on every terragrunt command.
  ssm_raw = local.override_id != "" ? local.override_id : run_cmd(
    "--terragrunt-global-cache", "--terragrunt-quiet",
    "bash", "-c",
    local.override_id != "" ? "true" : "(${local.ssm_command}) 2>&1 || true"
  )

  # Error classification (no silent fallbacks): a twelve-digit ID is used;
  # ParameterNotFound is the one legitimate empty case (bootstrap — the
  # parameter does not exist yet, so the unit's exclude block takes it out
  # of the run). Every other output (expired credentials, AccessDenied,
  # missing role, network failure) aborts the run. The abort is carried by
  # file(): the function fails on a path that does not exist, and the "path"
  # is the error message (pattern from configurations/ou-membership.hcl).
  unit_name = "${basename(dirname(get_terragrunt_dir()))}/${basename(get_terragrunt_dir())}"
  account_id = (
    can(regex("^[0-9]{12}$", trimspace(local.ssm_raw))) ? trimspace(local.ssm_raw)
    : can(regex("ParameterNotFound", local.ssm_raw)) ? ""
    : file("ERROR: ${local.unit_name}: SSM account resolution via /tlz/accounts/Log-Archive/id failed: ${trimspace(local.ssm_raw)}")
  )

  role_name  = local.common.locals.account_access_role_name
  partition  = local.common.locals.partition
  arn_prefix = "arn:${local.partition}"

  # Without an account ID there is no role to assume. The ARN stays empty, so
  # root.hcl keeps the default provider — and the unit's own `exclude` block
  # takes it out of the run in exactly that case.
  assume_role_arn = local.account_id != "" ? "${local.arn_prefix}:iam::${local.account_id}:role/${local.role_name}" : ""
}
