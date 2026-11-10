# =============================================================================
# OU Membership and Deployment Target Resolution
# =============================================================================
# Resolves the `ou_deployments` entries of env/common.hcl into effective
# account sets. Read by the generator stacks under
# stacks/management/ou-deployment/:
#
#   ou = read_terragrunt_config("${get_repo_root()}/configurations/ou-membership.hcl")
#   ... local.ou.locals.effective_accounts["<entry>"] ...
#
# Data sources (both static, resolved at generate time — see
# docs/ou-deployment.md for the boundary this implies):
#
#   * env/common.hcl  — the OU tree (`organizational_units`: name +
#     parent_name) and the account declarations (`accounts`: name +
#     organizational_unit_name).
#   * env/accounts.hcl — the name-keyed account IDs (`workload_accounts`).
#     Only entries with a non-empty ID join the membership: an account
#     becomes an OU-deployment target the moment its ID is recorded there.
#
# Resolution rule per `ou_deployments` entry (see env/common.hcl.example):
#
#   effective = distinct( union(OU members incl. nested OUs, accounts) )
#               minus excluded_accounts
#
# Error handling (no silent fallbacks): an entry naming an OU that the
# configured tree does not contain aborts the run with a message that names
# the unknown OU and the entry. The same applies to an account declaration
# pointing at an undeclared OU and to OU nesting deeper than the supported
# five levels. The abort is carried by `file()`: the function fails on a
# non-existent path, and the "path" is the diagnostic text.
# =============================================================================

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))

  # ---------------------------------------------------------------------------
  # OU tree from the configuration: name -> parent name ("__root__" for roots)
  # ---------------------------------------------------------------------------
  ou_parent = {
    for ou in local.common.locals.organizational_units : ou.name => ou.parent_name
  }

  # Ancestor chains, unrolled to five levels. chain[name] = [name, parent,
  # grandparent, ...] without "__root__". The configured tree is two levels
  # deep; the depth guard below rejects a sixth level instead of silently
  # truncating a chain.
  _p1 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, name, "__root__") }
  _p2 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, local._p1[name], "__root__") }
  _p3 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, local._p2[name], "__root__") }
  _p4 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, local._p3[name], "__root__") }
  _p5 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, local._p4[name], "__root__") }

  ou_chain = {
    for name, _ in local.ou_parent : name => [
      for link in [name, local._p1[name], local._p2[name], local._p3[name], local._p4[name]] :
      link if link != "__root__"
    ]
  }

  _too_deep = [for name, p5 in local._p5 : name if p5 != "__root__"]
  _depth_guard = length(local._too_deep) == 0 ? "ok" : file(
    "ERROR: organizational_units nesting deeper than five levels is not supported; affected OU(s): ${join(", ", local._too_deep)}"
  )

  # ---------------------------------------------------------------------------
  # Account -> OU (declarations) and name -> ID (recorded IDs)
  # ---------------------------------------------------------------------------
  account_ou = {
    for account in local.common.locals.accounts :
    account.name => account.organizational_unit_name
  }

  # An account declaration naming an OU outside the configured tree would
  # silently fall out of every membership list — reject it by name instead.
  _unknown_account_ous = sort(distinct([
    for name, ou in local.account_ou : "${name} -> ${ou}"
    if !contains(keys(local.ou_parent), ou)
  ]))
  _account_ou_guard = length(local._unknown_account_ous) == 0 ? "ok" : file(
    "ERROR: accounts declare organizational_unit_name values missing from organizational_units: ${join(", ", local._unknown_account_ous)}"
  )

  # Name-keyed account IDs. Only env/accounts.hcl:workload_accounts carries
  # names; entries with an empty ID are not created yet and stay outside the
  # membership until their ID is recorded (generate-time boundary).
  account_ids = {
    for name, id in local.accounts.locals.workload_accounts : name => id
    if id != ""
  }

  # ---------------------------------------------------------------------------
  # Membership: OU name -> sorted account IDs (nested OUs roll up to ancestors)
  # ---------------------------------------------------------------------------
  ou_membership = {
    for ou_name, _ in local.ou_parent : ou_name => sort([
      for account_name, id in local.account_ids :
      id if contains(lookup(local.ou_chain, lookup(local.account_ou, account_name, ""), []), ou_name)
    ])
  }

  # ---------------------------------------------------------------------------
  # Resolution of the ou_deployments entries (env/common.hcl.example documents
  # the schema). A missing ou_deployments map means: no OU deployments — the
  # generator stacks then produce zero resources.
  # ---------------------------------------------------------------------------
  ou_deployments = try(local.common.locals.ou_deployments, {})

  # effective = distinct(union(OU members, explicit accounts)) minus exclusions.
  # The OU lookup is guarded, not try-wrapped: an unknown OU aborts with a
  # message naming the entry and the OU.
  effective_accounts = {
    for entry_name, entry in local.ou_deployments : entry_name => sort(distinct([
      for id in concat(
        flatten([
          for ou in entry.organizational_units :
          contains(keys(local.ou_membership), ou)
          ? local.ou_membership[ou]
          : tolist([file(
            "ERROR: ou_deployments['${entry_name}'] names the unknown OU '${ou}'; known OUs: ${join(", ", sort(keys(local.ou_membership)))}"
          )])
        ]),
        entry.accounts,
      ) : id
      if !contains(entry.excluded_accounts, id)
    ]))
  }
}
