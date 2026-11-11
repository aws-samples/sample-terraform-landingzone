# Organization module: OUs, SCPs, Tag Policies, Backup Policies, Delegated Admin

# --- Partition Detection ---
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition         = data.aws_partition.current.partition
  dns_suffix        = data.aws_partition.current.dns_suffix
  arn_prefix        = "arn:${local.partition}"
  region            = data.aws_region.current.region
  account_id        = data.aws_caller_identity.current.account_id
  organization_id   = aws_organizations_organization.this.id
  master_account_id = aws_organizations_organization.this.master_account_id

  # Root ID: explicitly passed or resolved from the Organization resource
  resolved_root_id = var.organization_root_id != "" ? var.organization_root_id : aws_organizations_organization.this.roots[0].id

  # OU hierarchy: Level 1 (Parent = Root)
  level_1_ous = {
    for ou in var.organizational_units :
    ou.name => ou if ou.parent_name == "__root__"
  }

  # OU hierarchy: Level 2 (Parent = Level-1 OU)
  level_2_ous = {
    for ou in var.organizational_units :
    ou.name => ou if contains(keys(local.level_1_ous), ou.parent_name)
  }

  # OU hierarchy: Level 3 (Parent = Level-2 OU)
  level_3_ous = {
    for ou in var.organizational_units :
    ou.name => ou if contains(keys(local.level_2_ous), ou.parent_name)
  }

  # OU hierarchy: Level 4 (Parent = Level-3 OU)
  level_4_ous = {
    for ou in var.organizational_units :
    ou.name => ou if contains(keys(local.level_3_ous), ou.parent_name)
  }

  # OU hierarchy: Level 5 (Parent = Level-4 OU)
  level_5_ous = {
    for ou in var.organizational_units :
    ou.name => ou if contains(keys(local.level_4_ous), ou.parent_name)
  }

  # Every OU name the five level maps place. An OU whose parent chain does not
  # reach the root within five levels — or forms a cycle — appears in none of
  # them and would be created by no resource. The precondition on
  # aws_organizations_organization.this rejects that instead of dropping it.
  placed_ou_names = setunion(
    keys(local.level_1_ous),
    keys(local.level_2_ous),
    keys(local.level_3_ous),
    keys(local.level_4_ous),
    keys(local.level_5_ous),
  )

  unplaced_ou_names = sort(setsubtract(
    toset([for ou in var.organizational_units : ou.name]),
    local.placed_ou_names,
  ))

  # Complete OU name → ID map (all levels)
  ou_name_to_id = merge(
    { for name, ou in aws_organizations_organizational_unit.level_1 : name => ou.id },
    { for name, ou in aws_organizations_organizational_unit.level_2 : name => ou.id },
    { for name, ou in aws_organizations_organizational_unit.level_3 : name => ou.id },
    { for name, ou in aws_organizations_organizational_unit.level_4 : name => ou.id },
    { for name, ou in aws_organizations_organizational_unit.level_5 : name => ou.id },
  )

  # Name → ID map for policy target resolution.
  # Supports OU names, "Root", and raw 12-digit account IDs.
  # To attach a policy to a specific account, use the account ID directly
  # in the targets list (e.g. "123456789012") — no account_name_to_id needed.
  target_name_to_id = merge(
    { "Root" = local.resolved_root_id },
    local.ou_name_to_id,
  )

  # Names a policy target may carry, derived from the inputs alone: the
  # organization root plus every declared OU. Raw 12-digit account IDs are
  # matched separately. Deriving this from var.organizational_units instead of
  # from local.target_name_to_id keeps the check free of any dependency on the
  # OU resources, which are themselves parented to the Organization resource.
  known_target_names = setunion(
    ["Root"],
    [for ou in var.organizational_units : ou.name],
  )

  # Policy targets that name neither the root, nor a declared OU, nor an
  # account ID. Such a value would be handed to the Organizations API as a
  # target ID; the precondition on aws_organizations_organization.this rejects
  # it at plan time.
  policy_targets = distinct(concat(
    [for att in local.scp_attachments : att.target],
    [for att in local.tag_policy_attachments : att.target],
    [for att in local.backup_policy_attachments : att.target],
    [for att in local.rcp_attachments : att.target],
    [for att in local.declarative_policy_attachments : att.target],
    [for att in local.chatbot_policy_attachments : att.target],
    var.enable_quarantine_scp ? local.quarantine_scp_attachment_targets : [],
  ))

  unresolvable_policy_targets = sort([
    for target in local.policy_targets : target
    if !contains(local.known_target_names, target) && !can(regex("^[0-9]{12}$", target))
  ])

  # OU name → parent name, for the ancestor walk below.
  ou_parent = { for ou in var.organizational_units : ou.name => ou.parent_name }

  # Ancestor chains, unrolled to the five supported levels (the same unroll
  # the OU-membership resolution of the stacks uses): ou_chain[name] =
  # [name, parent, grandparent, ...] without "__root__".
  ou_parent_1 = { for name, parent in local.ou_parent : name => parent }
  ou_parent_2 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, local.ou_parent_1[name], "__root__") }
  ou_parent_3 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, local.ou_parent_2[name], "__root__") }
  ou_parent_4 = { for name, _ in local.ou_parent : name => lookup(local.ou_parent, local.ou_parent_3[name], "__root__") }

  ou_chain = {
    for name, _ in local.ou_parent : name => [
      for link in [name, local.ou_parent_1[name], local.ou_parent_2[name], local.ou_parent_3[name], local.ou_parent_4[name]] :
      link if link != "__root__"
    ]
  }

  # Ignored OU names: every OU with ignore = true and every OU below one.
  # Accounts declared there are no deployment targets (the accounts module
  # leaves them out of its active_* outputs, the stacks generate no provider
  # for them). Policy attachments are unaffected.
  directly_ignored_ou_names = toset([
    for ou in var.organizational_units : ou.name if ou.ignore
  ])

  ignored_ou_names = toset([
    for name, chain in local.ou_chain : name
    if length(setintersection(toset(chain), local.directly_ignored_ou_names)) > 0
  ])

  # Ignored OU IDs — resolved after OU creation
  ignored_ou_ids = [
    for name in local.ignored_ou_names : local.ou_name_to_id[name]
    if contains(keys(local.ou_name_to_id), name)
  ]

  # SCP attachments: Flatten targets per SCP. aws_managed marks entries whose
  # policy is attached by its well-known ID instead of a created resource.
  scp_attachments = flatten([
    for scp in var.service_control_policies : [
      for target in scp.targets : {
        key         = "${scp.name}:${target}"
        policy      = scp.name
        target      = target
        aws_managed = scp.type == "aws-managed"
      }
    ]
  ])

  # Tag policy attachments
  tag_policy_attachments = flatten([
    for policy in var.tag_policies : [
      for target in policy.targets : {
        key    = "${policy.name}:${target}"
        policy = policy.name
        target = target
      }
    ]
  ])

  # Backup policy attachments
  backup_policy_attachments = flatten([
    for policy in var.backup_policies : [
      for target in policy.targets : {
        key    = "${policy.name}:${target}"
        policy = policy.name
        target = target
      }
    ]
  ])

  # RCP attachments
  rcp_attachments = flatten([
    for policy in var.resource_control_policies : [
      for target in policy.targets : {
        key    = "${policy.name}:${target}"
        policy = policy.name
        target = target
      }
    ]
  ])

  # Declarative policy attachments
  declarative_policy_attachments = flatten([
    for policy in var.declarative_policies : [
      for target in policy.targets : {
        key    = "${policy.name}:${target}"
        policy = policy.name
        target = target
      }
    ]
  ])

  # Chatbot policy attachments
  chatbot_policy_attachments = flatten([
    for policy in var.chatbot_policies : [
      for target in policy.targets : {
        key    = "${policy.name}:${target}"
        policy = policy.name
        target = target
      }
    ]
  ])
}
