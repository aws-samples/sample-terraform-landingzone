# =============================================================================
# Account warming runbook
# =============================================================================
# The warm-account lifecycle marks new accounts (var.accounts[].warm) and
# keeps them out of downstream configuration; this file covers the warming
# itself — the reference procedure launches a temporary EC2 instance in the
# NEW account, keeps it running for ~15 minutes, terminates it and flags the
# account as pre-warmed, so the first production workload does not hit
# cold-account throttling.
#
# What is deliberately NOT here, and why: an aws_instance in this module
# would run in the management account (the module's provider), not in the
# new account, and a resource that must be created AND destroyed within one
# run contradicts Terraform's model of converging on a declared state — the
# no-execution convention rules out local-exec, and an apply cannot wait 15
# minutes to destroy its own resource. The declarative equivalent is the
# runbook itself: an SSM Automation document carrying the exact procedure
# (throwaway VPC + subnet, small instance from the current AL2023 AMI
# parameter of the target partition, ISO-8601 warm duration, removal of
# everything it created, pre-warmed flag under <SsmPrefix>/account/pre-warmed
# set to true only at the successful end — a run that fails midway aborts
# and leaves the flag false), shared to every warm-marked account. The one
# step that stays operational by nature is STARTING the run — once per new
# account, in that account (README, section Account warming).

resource "aws_ssm_document" "account_warming" {
  count = var.enable_account_warming ? 1 : 0

  name            = "tlz-account-warming"
  document_type   = "Automation"
  document_format = "JSON"
  content         = file("${path.module}/../../configurations/ssm-documents/account-warming.json")

  # Shared to the warm-marked accounts: the runbook is available in the
  # target account the moment the account exists, without any code change.
  permissions = length(local.warm_account_ids) > 0 ? {
    type        = "Share"
    account_ids = join(",", local.warm_account_ids)
  } : null

  tags = {
    ManagedBy = "TLZ"
  }
}
