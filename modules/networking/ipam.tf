# =============================================================================
# VPC IPAM (conditional)
# =============================================================================

locals {
  # Pool map keyed by name
  ipam_pool_map = var.ipam.enabled ? {
    for pool in var.ipam.pools : pool.name => pool
  } : {}

  # Hierarchy levels: a resource must not reference itself in its own for_each,
  # so each nesting level gets its own resource and sources the level above.
  # Level 1 — pools without a parent, provisioned from the IPAM default scope
  ipam_root_pool_map = {
    for name, pool in local.ipam_pool_map : name => pool
    if pool.parent_pool_name == null
  }

  # Level 2 — pools whose parent is a root pool
  ipam_child_pool_map = {
    for name, pool in local.ipam_pool_map : name => pool
    if pool.parent_pool_name != null && contains(keys(local.ipam_root_pool_map), pool.parent_pool_name)
  }

  # Level 3 — pools whose parent is a child pool
  ipam_grandchild_pool_map = {
    for name, pool in local.ipam_pool_map : name => pool
    if pool.parent_pool_name != null && contains(keys(local.ipam_child_pool_map), pool.parent_pool_name)
  }

  # Pool lookup across all levels: pool_name → pool resource ID
  ipam_pool_ids = merge(
    { for name, pool in aws_vpc_ipam_pool.this : name => pool.id },
    { for name, pool in aws_vpc_ipam_pool.child : name => pool.id },
    { for name, pool in aws_vpc_ipam_pool.grandchild : name => pool.id },
  )

  # Scopes a pool can name: the two the IPAM brings itself under their reserved
  # names, plus every declared scope under its own name.
  ipam_scope_map = var.ipam.enabled ? {
    for scope in var.ipam.scopes : scope.name => scope
  } : {}

  ipam_scope_ids = var.ipam.enabled ? merge(
    {
      "private-default" = aws_vpc_ipam.this[0].private_default_scope_id
      "public-default"  = aws_vpc_ipam.this[0].public_default_scope_id
    },
    { for name, scope in aws_vpc_ipam_scope.this : name => scope.id },
  ) : {}

  # Further ranges of a pool: "pool_name.idx" → { pool_name, cidr }. The first
  # range keeps its own resource, keyed by the pool name.
  ipam_pool_additional_cidr_map = merge([
    for pool in var.ipam.enabled ? var.ipam.pools : [] : {
      for idx, cidr in pool.additional_cidrs : "${pool.name}.${idx}" => {
        pool_name = pool.name
        cidr      = cidr
      }
    }
  ]...)
}

resource "aws_vpc_ipam" "this" {
  count = var.ipam.enabled ? 1 : 0

  description = var.ipam.description

  dynamic "operating_regions" {
    for_each = length(var.ipam.regions) > 0 ? var.ipam.regions : [local.region]
    content {
      region_name = operating_regions.value
    }
  }

  tags = merge(var.ipam.tags, {
    Name = "tlz-ipam"
  })
}

# --- IPAM Scopes (beyond the private and public default scope of the IPAM) ---
resource "aws_vpc_ipam_scope" "this" {
  for_each = local.ipam_scope_map

  ipam_id     = aws_vpc_ipam.this[0].id
  description = each.value.description

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- IPAM Pools, level 1 (no parent: provisioned from the named scope) ---
resource "aws_vpc_ipam_pool" "this" {
  for_each = local.ipam_root_pool_map

  address_family = each.value.address_family
  ipam_scope_id  = local.ipam_scope_ids[each.value.scope != null ? each.value.scope : "private-default"]
  description    = each.value.description
  locale         = each.value.locale

  # null writes nothing and leaves the AWS default in place.
  auto_import           = each.value.auto_import
  publicly_advertisable = each.value.publicly_advertisable
  public_ip_source      = each.value.public_ip_source

  allocation_default_netmask_length = each.value.allocation_default_netmask_length
  allocation_min_netmask_length     = each.value.allocation_min_netmask_length
  allocation_max_netmask_length     = each.value.allocation_max_netmask_length
  allocation_resource_tags          = each.value.allocation_resource_tags

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- IPAM Pools, level 2 (parent is a level 1 pool) ---
resource "aws_vpc_ipam_pool" "child" {
  for_each = local.ipam_child_pool_map

  address_family = each.value.address_family
  ipam_scope_id  = local.ipam_scope_ids[each.value.scope != null ? each.value.scope : "private-default"]
  description    = each.value.description
  locale         = each.value.locale

  auto_import           = each.value.auto_import
  publicly_advertisable = each.value.publicly_advertisable
  public_ip_source      = each.value.public_ip_source

  allocation_default_netmask_length = each.value.allocation_default_netmask_length
  allocation_min_netmask_length     = each.value.allocation_min_netmask_length
  allocation_max_netmask_length     = each.value.allocation_max_netmask_length
  allocation_resource_tags          = each.value.allocation_resource_tags

  source_ipam_pool_id = aws_vpc_ipam_pool.this[each.value.parent_pool_name].id

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- IPAM Pools, level 3 (parent is a level 2 pool) ---
resource "aws_vpc_ipam_pool" "grandchild" {
  for_each = local.ipam_grandchild_pool_map

  address_family = each.value.address_family
  ipam_scope_id  = local.ipam_scope_ids[each.value.scope != null ? each.value.scope : "private-default"]
  description    = each.value.description
  locale         = each.value.locale

  auto_import           = each.value.auto_import
  publicly_advertisable = each.value.publicly_advertisable
  public_ip_source      = each.value.public_ip_source

  allocation_default_netmask_length = each.value.allocation_default_netmask_length
  allocation_min_netmask_length     = each.value.allocation_min_netmask_length
  allocation_max_netmask_length     = each.value.allocation_max_netmask_length
  allocation_resource_tags          = each.value.allocation_resource_tags

  source_ipam_pool_id = aws_vpc_ipam_pool.child[each.value.parent_pool_name].id

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- IPAM Pool CIDRs (the first range of each pool, any level) ---
resource "aws_vpc_ipam_pool_cidr" "this" {
  for_each = local.ipam_pool_map

  ipam_pool_id = local.ipam_pool_ids[each.key]
  cidr         = each.value.cidr
}

# --- Further ranges of the same pool ---
resource "aws_vpc_ipam_pool_cidr" "additional" {
  for_each = local.ipam_pool_additional_cidr_map

  ipam_pool_id = local.ipam_pool_ids[each.value.pool_name]
  cidr         = each.value.cidr
}

# --- IPAM Delegated Admin (conditional on delegated_admin_account_id) ---
resource "aws_vpc_ipam_organization_admin_account" "this" {
  count = var.ipam.enabled && var.ipam.delegated_admin_account_id != "" ? 1 : 0

  delegated_admin_account_id = var.ipam.delegated_admin_account_id
}

# =============================================================================
# IPAM Pool RAM Sharing
# =============================================================================

locals {
  # Pool ARN lookup across all levels: pool_name → pool ARN
  ipam_pool_arns = merge(
    { for name, pool in aws_vpc_ipam_pool.this : name => pool.arn },
    { for name, pool in aws_vpc_ipam_pool.child : name => pool.arn },
    { for name, pool in aws_vpc_ipam_pool.grandchild : name => pool.arn },
  )

  # Pools that have share_targets: pool_name → pool definition
  ipam_pool_share_map = var.enable_ram_sharing && var.ipam.enabled ? {
    for pool in var.ipam.pools : pool.name => pool
    if length(pool.share_targets) > 0
  } : {}

  # Flattened principal associations: "pool_name.target" → { pool_name, principal }
  ipam_pool_share_principal_map = var.enable_ram_sharing && var.ipam.enabled ? merge([
    for pool in var.ipam.pools : {
      for target in pool.share_targets : "${pool.name}.${target}" => {
        pool_name = pool.name
        principal = lookup(var.account_ids, target, target)
      }
    } if length(pool.share_targets) > 0
  ]...) : {}
}

resource "aws_ram_resource_share" "ipam_pool" {
  for_each = local.ipam_pool_share_map

  name                      = "${each.key}-ipam-pool-share"
  allow_external_principals = false

  tags = {
    Name = "${each.key}-ipam-pool-share"
  }
}

resource "aws_ram_resource_association" "ipam_pool" {
  for_each = local.ipam_pool_share_map

  resource_arn       = local.ipam_pool_arns[each.key]
  resource_share_arn = aws_ram_resource_share.ipam_pool[each.key].arn
}

resource "aws_ram_principal_association" "ipam_pool" {
  for_each = local.ipam_pool_share_principal_map

  principal          = each.value.principal
  resource_share_arn = aws_ram_resource_share.ipam_pool[each.value.pool_name].arn
}
