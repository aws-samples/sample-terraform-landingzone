# OU Deployment

Deploy a capability into every account of an organizational unit (OU) from a
single configuration entry, with an exclusion list for individual accounts.
New accounts join the deployment by being recorded in the configuration — no
per-account stack has to be written by hand.

## How It Works

Three pieces cooperate, all in the Terragrunt layer; the Terraform modules
stay unchanged:

1. **Target entries** — `ou_deployments` in `env/common.hcl` names, per
   capability, the target OUs, additional explicit accounts, an exclusion
   list, and the capability payload (`inputs`). The schema is documented in
   `env/common.hcl.example`.
2. **Resolution** — `configurations/ou-membership.hcl` derives the OU
   membership (OU name → account IDs) from the account declarations in
   `env/common.hcl` (`accounts[].organizational_unit_name`) joined with the
   recorded IDs in `env/accounts.hcl` (`workload_accounts`). Nested OUs roll
   up to their ancestors: an account in `Dev` is also a member of
   `Workloads`. An account declared in an OU marked `ignore = true` (or
   below one) joins no membership. Per entry the effective account set is
   `distinct(union(OU members, accounts)) minus excluded_accounts`.
3. **Generator stacks** — `stacks/management/ou-deployment/<capability>/`
   generates, per resolved account, an `aws` provider alias that assumes the
   cross-account role and one module instantiation (or, for the event bus
   policy, the resource itself) with a static provider assignment. The
   pattern follows `stacks/management/config-recorder-members`.

```
env/common.hcl          configurations/           stacks/management/
ou_deployments   ──►    ou-membership.hcl   ──►   ou-deployment/<capability>
(targets, inputs)       (effective accounts)      (provider + module per account)
```

## Available Capabilities

| Capability | Stack | Switch | inputs key |
|---|---|---|---|
| Backup vaults | `ou-deployment/backup-vaults` | `enable_ou_deployment_backup_vaults` | `vaults` (per `modules/backup`) |
| Default event bus policy | `ou-deployment/event-bus-policy` | `enable_ou_deployment_event_bus_policy` | `policy` (JSON document) |
| Service quota requests | `ou-deployment/service-quotas` | `enable_ou_deployment_service_quotas` | `quota_increases` (per `modules/service-quotas`) |
| SSM parameters | `ou-deployment/ssm-parameters` | `enable_ou_deployment_ssm_parameters` | `parameters` (per `modules/ssm-parameters`) |

Every capability has its own switch (default off). A switch that is off, or
an entry that resolves to an empty account set, produces zero resources.

Further capabilities follow the same recipe: copy one of the module-backed
stacks, point it at the receiving module, give it a switch and an
`ou_deployments` entry key. The resolution layer needs no change.

## Configuration Example

```hcl
# env/common.hcl
enable_ou_deployment_backup_vaults = true

ou_deployments = {
  backup_vaults = {
    organizational_units = ["Workloads"]     # nested OUs roll up
    accounts             = []                # additional explicit account IDs
    excluded_accounts    = ["111111111111"]  # never targeted, even as OU member
    inputs = {
      vaults = [{ name = "workload-backup" }]
    }
  }
}
```

## Error Handling

There are no silent fallbacks:

- An entry naming an OU that `organizational_units` does not declare aborts
  the run with a message naming the entry and the unknown OU.
- An account declaration pointing at an undeclared OU aborts the run naming
  the account and the OU.
- OU nesting deeper than five levels aborts the run naming the affected OU.
- An enabled event bus policy entry with resolved targets but an empty
  `policy` document aborts the run.

At plan time a `lifecycle` precondition aborts the run when a resolved
account ID is not among the active account IDs of the accounts unit — warm
or suspended accounts (declared in an OU marked `ignore = true`) stay excluded
from deployment targets. Before the first accounts
apply the outputs are mocked; the mock carries a sentinel key, and only that
mock lets the precondition pass, so bootstrap validate/plan keeps working. A
real, empty set of active accounts (every account warm, or targets the
accounts unit does not create) is refused like any other missing target.

## Boundary: Resolution at Generate Time

The resolution reads the **configured** mapping, not the live OU membership
at apply time. The effective account set is computed when Terragrunt
generates the stack:

- A new account becomes a deployment target the moment it is declared in
  `env/common.hcl` (`accounts`, with its OU) **and** its ID is recorded in
  `env/accounts.hcl` (`workload_accounts`). The map key is the account NAME
  as declared in `accounts[].name` (e.g. `"Workload-Dev"`, not the stack
  directory name `workload-dev`); the workload sidecars
  (`stacks/workload-dev/*/cross_account.hcl`) read the same key form, so one
  entry serves both consumers. An account created outside this
  configuration does not join automatically.
- Moving an account between OUs in the AWS console does not change the
  resolved set until the configuration is updated.
- Terraform providers are static: a module cannot multiply its providers
  over an account list at apply time. That is why this capability lives in
  the Terragrunt layer as a generator and is not a module attribute.

Accounts recorded only by ID (the core accounts in `env/accounts.hcl`) carry
no name-to-OU declaration and therefore stay outside the OU membership; they
can be targeted through the explicit `accounts` list of an entry.

## Further reading

- [Getting Started](getting-started.md) — Step-by-step setup and first deployment
- [Operations](operations.md) — Day-2 operations, adding accounts
- [Configuration Reference](configuration-reference.md) — Full variable reference
- [Architecture](architecture.md) — Module design and dependency graph
