# Cross-account provider parameters for this unit.
#
# A unit must not carry a `generate "provider"` block of its own: two generate
# blocks of the same name abort the configuration load ("Detected generate
# blocks with the same name: [provider]") for every command including apply.
# stacks/root.hcl is the only place that writes provider.tf; it reads this file via
# read_terragrunt_config("${get_terragrunt_dir()}/cross_account.hcl") and adds an
# assume_role block for `assume_role_arn`.
#
# The pipeline runs in the DEPLOYMENT account (modules/pipeline names its bucket
# and roles after the account it runs in), and that account's id is a
# precondition recorded in env/accounts.hcl -- like the management account,
# never discovered through an SSM parameter. So, unlike the member-account
# sidecars, this file makes no lookup and no CLI call: the role ARN is built
# from the configuration alone, and the same access role the state backend
# assumes (stacks/root.hcl) is assumed here.
#
# The ARN stays empty while the pipeline is off, so root.hcl keeps the default
# provider for a unit that `exclude` takes out of the run anyway.
locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))

  assume_role_arn = (
    local.common.locals.enable_pipeline
    ? "arn:${local.common.locals.partition}:iam::${local.accounts.locals.deployment_account_id}:role/${local.common.locals.account_access_role_name}"
    : ""
  )
}
