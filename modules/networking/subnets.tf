# =============================================================================
# Subnets — flat across all VPCs
# =============================================================================

resource "aws_subnet" "this" {
  for_each = local.subnet_map

  vpc_id = aws_vpc.this[each.value.vpc_name].id

  # Placement: a regional Availability Zone or a Local Zone — the variable
  # validation guarantees exactly one of the two is set.
  availability_zone = each.value.local_zone != null ? each.value.local_zone : each.value.availability_zone

  # Static CIDR (when no IPAM)
  cidr_block = each.value.ipam_pool_name == null ? each.value.cidr : null

  # IPAM-based CIDR (when IPAM pool is referenced)
  ipv4_ipam_pool_id   = each.value.ipam_pool_name != null ? local.ipam_pool_ids[each.value.ipam_pool_name] : null
  ipv4_netmask_length = each.value.ipam_pool_name != null ? each.value.ipam_netmask_length : null

  # Explicit switch wins; null keeps the derivation from the subnet type.
  map_public_ip_on_launch = each.value.map_public_ip_on_launch != null ? each.value.map_public_ip_on_launch : each.value.type == "public"

  # Outpost placement: a name reference resolves to the declared Outpost's
  # ARN, a raw ARN passes through unchanged.
  outpost_arn = each.value.outpost_name != null ? local.outpost_arn_map["${each.value.vpc_name}.${each.value.outpost_name}"] : each.value.outpost_arn

  # IPv6: explicit switch wins; null keeps the derivation — assign addresses
  # on creation when the subnet has an ipv6_cidr_suffix in an IPv6-enabled VPC.
  assign_ipv6_address_on_creation = each.value.assign_ipv6_on_creation != null ? each.value.assign_ipv6_on_creation : (lookup(local.ipv6_subnet_map, each.key, null) != null ? true : false)

  # DNS64: null writes nothing and leaves the AWS default (off) in place.
  enable_dns64 = each.value.enable_dns64

  # Private DNS naming of launched instances; null writes nothing.
  private_dns_hostname_type_on_launch            = each.value.private_dns_options != null ? each.value.private_dns_options.hostname_type : null
  enable_resource_name_dns_a_record_on_launch    = each.value.private_dns_options != null ? each.value.private_dns_options.enable_dns_a_record : null
  enable_resource_name_dns_aaaa_record_on_launch = each.value.private_dns_options != null ? each.value.private_dns_options.enable_dns_aaaa_record : null

  # IPv6: cut the subnet's /64 out of the VPC's first IPv6 range. The number of
  # added bits follows that range's prefix (local.ipv6_subnet_newbits): 8 for
  # the /56 an Amazon-provided range always is, and the matching number for an
  # explicit or IPAM-requested prefix.
  ipv6_cidr_block = lookup(local.ipv6_subnet_map, each.key, null) != null ? cidrsubnet(
    aws_vpc_ipv6_cidr_block_association.this[each.value.vpc_name].ipv6_cidr_block,
    local.ipv6_subnet_newbits[each.value.vpc_name],
    tonumber(each.value.ipv6_cidr_suffix)
  ) : null

  tags = merge(each.value.tags, {
    Name = each.key
    Type = each.value.type
  })
}

# =============================================================================
# Route tables — one per subnet
# =============================================================================

resource "aws_route_table" "this" {
  for_each = local.subnet_map

  vpc_id = aws_vpc.this[each.value.vpc_name].id

  tags = merge(each.value.route_table_tags, {
    Name = "${each.key}-rt"
    Type = each.value.type
  })
}

resource "aws_route_table_association" "this" {
  for_each = local.subnet_map

  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.this[each.key].id
}

# =============================================================================
# Custom Routes — Flattened across all subnets
# =============================================================================

locals {
  # Flattened custom routes: "vpc_name.subnet_name.idx" → route definition +
  # subnet_key. Routes of target_type "tgw" are intersected with
  # var.transit_gateway.enabled; var.vpcs rejects such routes at
  # plan time while the Transit Gateway is off, so the filter never silently
  # drops a configured route.
  custom_route_map = merge([
    for key, s in local.subnet_map : {
      for idx, route in s.custom_routes : "${key}.${idx}" => {
        subnet_key                   = key
        vpc_name                     = s.vpc_name
        destination_cidr_block       = route.destination_cidr_block
        destination_ipv6_cidr_block  = route.destination_ipv6_cidr_block
        destination_prefix_list_name = route.destination_prefix_list_name
        target_type                  = route.target_type
        target_name                  = route.target_name
      } if route.target_type != "tgw" || var.transit_gateway.enabled
    }
  ]...)

  # Set of subnet keys that have a custom route covering 0.0.0.0/0 (conflicts with default route)
  subnets_with_custom_default_route = toset([
    for key, route in local.custom_route_map : route.subnet_key
    if route.destination_cidr_block == "0.0.0.0/0"
  ])
}

resource "aws_route" "custom" {
  for_each = local.custom_route_map

  route_table_id = aws_route_table.this[each.value.subnet_key].id

  # Destination — exactly one of the three (enforced by the variable
  # validation): an IPv4 CIDR, an IPv6 CIDR, or a named managed prefix list.
  destination_cidr_block      = each.value.destination_cidr_block
  destination_ipv6_cidr_block = each.value.destination_ipv6_cidr_block
  destination_prefix_list_id  = each.value.destination_prefix_list_name != null ? aws_ec2_managed_prefix_list.this[each.value.destination_prefix_list_name].id : null

  # Target resolution based on target_type. igw and vgw share the provider's
  # gateway_id argument; eigw and local_gateway carry their own.
  # network_firewall targets index local.nfw_endpoint_id_map directly: a
  # lookup() with a fallback would pass an unknown availability zone through
  # as a vpc_endpoint_id for AWS to reject late. var.vpcs validates the AZ form at plan time; an AZ the
  # firewall does not cover fails here instead of reaching the API.
  transit_gateway_id        = each.value.target_type == "tgw" ? aws_ec2_transit_gateway.this[0].id : null
  nat_gateway_id            = each.value.target_type == "nat" ? aws_nat_gateway.this[each.value.target_name].id : null
  vpc_endpoint_id           = each.value.target_type == "vpc_endpoint" ? aws_vpc_endpoint.gateway[each.value.target_name].id : each.value.target_type == "network_firewall" ? local.nfw_endpoint_id_map[each.value.target_name] : each.value.target_type == "gwlb_endpoint" ? aws_vpc_endpoint.gwlb_consumer[each.value.target_name].id : null
  network_interface_id      = each.value.target_type == "eni" ? each.value.target_name : null
  vpc_peering_connection_id = each.value.target_type == "peering" ? each.value.target_name : null
  gateway_id                = each.value.target_type == "igw" ? aws_internet_gateway.this[each.value.vpc_name].id : each.value.target_type == "vgw" ? aws_vpn_gateway.this[each.value.vpc_name].id : null
  egress_only_gateway_id    = each.value.target_type == "eigw" ? aws_egress_only_internet_gateway.this[each.value.vpc_name].id : null
  local_gateway_id          = each.value.target_type == "local_gateway" ? local.lgw_id_map["${each.value.vpc_name}.${each.value.target_name}"] : null
}

# =============================================================================
# Gateway Route Tables — edge routing on the IGW or VGW
# =============================================================================

locals {
  # "vpc_name.table_name" → table definition. Associated with the named
  # gateway instead of a subnet: traffic entering the VPC through that gateway
  # follows these routes (e.g. through a firewall or GWLB endpoint).
  gateway_route_table_map = merge([
    for vpc in var.vpcs : {
      for g in vpc.gateway_route_tables : "${vpc.name}.${g.name}" => {
        vpc_name     = vpc.name
        gateway_type = g.gateway_type
        tags         = g.tags
        routes       = g.routes
      }
    }
  ]...)

  # Flattened gateway route table routes: "vpc_name.table_name.idx" → route.
  # "tgw" routes carry the same Transit Gateway guard as custom_route_map.
  gateway_route_map = merge([
    for table_key, g in local.gateway_route_table_map : {
      for idx, route in g.routes : "${table_key}.${idx}" => {
        table_key                    = table_key
        vpc_name                     = g.vpc_name
        destination_cidr_block       = route.destination_cidr_block
        destination_ipv6_cidr_block  = route.destination_ipv6_cidr_block
        destination_prefix_list_name = route.destination_prefix_list_name
        target_type                  = route.target_type
        target_name                  = route.target_name
      } if route.target_type != "tgw" || var.transit_gateway.enabled
    }
  ]...)
}

resource "aws_route_table" "gateway" {
  for_each = local.gateway_route_table_map

  vpc_id = aws_vpc.this[each.value.vpc_name].id

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# Edge association: the table is bound to the gateway, not to a subnet.
resource "aws_route_table_association" "gateway" {
  for_each = local.gateway_route_table_map

  gateway_id     = each.value.gateway_type == "internet_gateway" ? aws_internet_gateway.this[each.value.vpc_name].id : aws_vpn_gateway.this[each.value.vpc_name].id
  route_table_id = aws_route_table.gateway[each.key].id
}

resource "aws_route" "gateway_custom" {
  for_each = local.gateway_route_map

  route_table_id = aws_route_table.gateway[each.value.table_key].id

  destination_cidr_block      = each.value.destination_cidr_block
  destination_ipv6_cidr_block = each.value.destination_ipv6_cidr_block
  destination_prefix_list_id  = each.value.destination_prefix_list_name != null ? aws_ec2_managed_prefix_list.this[each.value.destination_prefix_list_name].id : null

  # Same target resolution as aws_route.custom, including the direct
  # nfw_endpoint_id_map index.
  transit_gateway_id        = each.value.target_type == "tgw" ? aws_ec2_transit_gateway.this[0].id : null
  nat_gateway_id            = each.value.target_type == "nat" ? aws_nat_gateway.this[each.value.target_name].id : null
  vpc_endpoint_id           = each.value.target_type == "vpc_endpoint" ? aws_vpc_endpoint.gateway[each.value.target_name].id : each.value.target_type == "network_firewall" ? local.nfw_endpoint_id_map[each.value.target_name] : each.value.target_type == "gwlb_endpoint" ? aws_vpc_endpoint.gwlb_consumer[each.value.target_name].id : null
  network_interface_id      = each.value.target_type == "eni" ? each.value.target_name : null
  vpc_peering_connection_id = each.value.target_type == "peering" ? each.value.target_name : null
  gateway_id                = each.value.target_type == "igw" ? aws_internet_gateway.this[each.value.vpc_name].id : each.value.target_type == "vgw" ? aws_vpn_gateway.this[each.value.vpc_name].id : null
  egress_only_gateway_id    = each.value.target_type == "eigw" ? aws_egress_only_internet_gateway.this[each.value.vpc_name].id : null
  local_gateway_id          = each.value.target_type == "local_gateway" ? local.lgw_id_map["${each.value.vpc_name}.${each.value.target_name}"] : null
}

# =============================================================================
# Virtual Private Gateway route propagation
# =============================================================================

locals {
  # Subnets that propagate the VGW routes into their route table. The gateway
  # is attached by the customer_gateways entry that terminates on the VPC.
  vgw_propagation_subnets = {
    for key, s in local.subnet_map : key => s
    if s.enable_route_propagation
  }
}

resource "aws_vpn_gateway_route_propagation" "this" {
  for_each = local.vgw_propagation_subnets

  vpn_gateway_id = aws_vpn_gateway.this[each.value.vpc_name].id
  route_table_id = aws_route_table.this[each.key].id
}

# =============================================================================
# Default routes — IGW for public, NAT for private
# =============================================================================

# Public Subnets → Internet Gateway (skip if custom route covers 0.0.0.0/0)
resource "aws_route" "public_igw" {
  for_each = {
    for key, s in local.public_subnets : key => s
    if !contains(local.subnets_with_custom_default_route, key)
  }

  route_table_id         = aws_route_table.this[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[each.value.vpc_name].id
}

# Private subnets → NAT gateway (only when the VPC has a NAT gateway, skip if custom route covers 0.0.0.0/0)
resource "aws_route" "private_nat" {
  for_each = {
    for key, s in local.private_subnets : key => s
    if contains(keys(local.nat_gw_per_vpc), s.vpc_name) && !contains(local.subnets_with_custom_default_route, key)
  }

  route_table_id         = aws_route_table.this[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[local.nat_gw_per_vpc[each.value.vpc_name]].id
}

# Isolated subnets: no default route (by design)

# =============================================================================
# AWS RAM resource share (VPC sharing placeholder)
# =============================================================================

resource "aws_ram_resource_share" "vpc_sharing" {
  for_each = var.enable_ram_sharing ? {
    for vpc_name, vpc in local.vpc_map : vpc_name => vpc
    if vpc.account_name != "" && length(var.account_ids) > 0
  } : {}

  name                      = "${each.key}-vpc-share"
  allow_external_principals = false

  tags = {
    Name = "${each.key}-vpc-share"
  }
}

# =============================================================================
# Subnet RAM Sharing
# =============================================================================

locals {
  # Flattened subnet share targets: "vpc_name.subnet_name" → { subnet_key, share_targets }
  subnet_share_map = var.enable_ram_sharing ? {
    for key, s in local.subnet_map : key => s
    if length(s.share_targets) > 0
  } : {}

  # Flattened principal associations: "vpc_name.subnet_name.account_name" → { subnet_key, account_id }
  subnet_share_principal_map = var.enable_ram_sharing ? merge([
    for key, s in local.subnet_map : {
      for target in s.share_targets : "${key}.${target}" => {
        subnet_key = key
        account_id = lookup(var.account_ids, target, target)
      }
    } if length(s.share_targets) > 0
  ]...) : {}
}

# NOTE: RAM subnet sharing propagates the subnet resource itself to consumer
# accounts, but does NOT propagate custom tags applied in the sharing account.
# Tags set on aws_ram_resource_share.subnet apply to the share resource only,
# not to the shared subnet as seen by consumer accounts. The receiving side's
# answer is enable_shared_subnet_tagging + shared_subnet_tags in the consumer
# account's networking stack (shared-subnet-tags.tf), which materialises the
# tags there as aws_ec2_tag resources.
resource "aws_ram_resource_share" "subnet" {
  for_each = local.subnet_share_map

  name                      = "${each.key}-subnet-share"
  allow_external_principals = false

  # Tags apply to the RAM share resource itself; they are NOT propagated to the
  # shared subnet in consumer accounts. See check "subnet_tag_propagation_limitation".
  tags = {
    Name = "${each.key}-subnet-share"
  }
}

resource "aws_ram_resource_association" "subnet" {
  for_each = local.subnet_share_map

  resource_arn       = aws_subnet.this[each.key].arn
  resource_share_arn = aws_ram_resource_share.subnet[each.key].arn
}

resource "aws_ram_principal_association" "subnet" {
  for_each = local.subnet_share_principal_map

  principal          = each.value.account_id
  resource_share_arn = aws_ram_resource_share.subnet[each.value.subnet_key].arn
}

# -----------------------------------------------------------------------------
# Subnet Tag Propagation Limitation — RAM does not propagate custom tags
# -----------------------------------------------------------------------------
check "subnet_tag_propagation_limitation" {
  assert {
    condition     = length(local.subnet_share_map) == 0
    error_message = "Subnets are shared via RAM, but custom tags are NOT propagated to consumer accounts. RAM shares the subnet resource without replicating tags. Declare enable_shared_subnet_tagging + shared_subnet_tags in each consumer account's networking stack to materialise the tags there (see README, Shared subnet tags in recipient accounts)."
  }
}

# -----------------------------------------------------------------------------
# Private-subnet-only intent — advisory warning from the compliance layer
# -----------------------------------------------------------------------------
locals {
  # VPCs that declare at least one public subnet while the compliance layer
  # asks for private subnets only. Empty unless private_subnet_only is set.
  public_subnet_vpcs_against_intent = var.private_subnet_only ? [
    for vpc in var.vpcs : vpc.name
    if length([for s in vpc.subnets : s if s.type == "public"]) > 0
  ] : []
}

check "private_subnet_only_intent" {
  assert {
    condition     = length(local.public_subnet_vpcs_against_intent) == 0
    error_message = "private_subnet_only is set (networking_defaults of an active compliance framework), but these VPCs declare public subnets: [${join(", ", local.public_subnet_vpcs_against_intent)}]. The subnets are still created — the warning documents the deviation from the framework's intent."
  }
}

# =============================================================================
# Network ACLs
# =============================================================================

locals {
  # Flattened NACL map: "vpc_name.nacl_name" → { vpc_name, nacl definition }
  nacl_map = merge([
    for vpc in var.vpcs : {
      for nacl in vpc.nacls : "${vpc.name}.${nacl.name}" => {
        vpc_name     = vpc.name
        name         = nacl.name
        subnet_names = nacl.subnet_names
        tags         = nacl.tags
        inbound      = nacl.inbound
        outbound     = nacl.outbound
      }
    }
  ]...)

  # Flattened inbound rules: "vpc_name.nacl_name.in.rule_number" → rule.
  # `selector` carries the structured source (subnet selector) of the rule;
  # the resource resolves it through aws_subnet.this, so IPAM-assigned CIDRs
  # resolve as well.
  nacl_inbound_rules = merge([
    for nacl_key, nacl in local.nacl_map : {
      for rule in nacl.inbound : "${nacl_key}.in.${rule.rule_number}" => {
        nacl_key        = nacl_key
        rule_number     = rule.rule_number
        protocol        = rule.protocol
        action          = rule.action
        cidr_block      = rule.cidr_block
        ipv6_cidr_block = rule.ipv6_cidr_block
        selector        = rule.source
        from_port       = rule.from_port
        to_port         = rule.to_port
        icmp            = rule.icmp
      }
    }
  ]...)

  # Flattened outbound rules: "vpc_name.nacl_name.out.rule_number" → rule.
  # `selector` carries the structured destination of the rule.
  nacl_outbound_rules = merge([
    for nacl_key, nacl in local.nacl_map : {
      for rule in nacl.outbound : "${nacl_key}.out.${rule.rule_number}" => {
        nacl_key        = nacl_key
        rule_number     = rule.rule_number
        protocol        = rule.protocol
        action          = rule.action
        cidr_block      = rule.cidr_block
        ipv6_cidr_block = rule.ipv6_cidr_block
        selector        = rule.destination
        from_port       = rule.from_port
        to_port         = rule.to_port
        icmp            = rule.icmp
      }
    }
  ]...)

  # Flattened NACL-to-subnet associations: "vpc_name.nacl_name.subnet_name" → { nacl_key, subnet_key }
  nacl_subnet_associations = merge([
    for nacl_key, nacl in local.nacl_map : {
      for sn in nacl.subnet_names : "${nacl_key}.${sn}" => {
        nacl_key   = nacl_key
        subnet_key = "${nacl.vpc_name}.${sn}"
      }
    }
  ]...)
}

resource "aws_network_acl" "this" {
  for_each = local.nacl_map

  vpc_id = aws_vpc.this[each.value.vpc_name].id

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# Each rule carries exactly one traffic source (validated on var.vpcs): a
# literal IPv4/IPv6 CIDR or a subnet selector resolved to the referenced
# subnet's CIDR through the subnet resource.
resource "aws_network_acl_rule" "inbound" {
  for_each = local.nacl_inbound_rules

  network_acl_id = aws_network_acl.this[each.value.nacl_key].id
  rule_number    = each.value.rule_number
  egress         = false
  protocol       = each.value.protocol
  rule_action    = each.value.action
  cidr_block = each.value.selector != null ? (
    each.value.selector.ipv6 ? null : aws_subnet.this["${each.value.selector.vpc}.${each.value.selector.subnet}"].cidr_block
  ) : each.value.cidr_block
  ipv6_cidr_block = each.value.selector != null ? (
    each.value.selector.ipv6 ? aws_subnet.this["${each.value.selector.vpc}.${each.value.selector.subnet}"].ipv6_cidr_block : null
  ) : each.value.ipv6_cidr_block
  from_port = each.value.from_port
  to_port   = each.value.to_port
  icmp_type = each.value.icmp != null ? each.value.icmp.type : null
  icmp_code = each.value.icmp != null ? each.value.icmp.code : null
}

resource "aws_network_acl_rule" "outbound" {
  for_each = local.nacl_outbound_rules

  network_acl_id = aws_network_acl.this[each.value.nacl_key].id
  rule_number    = each.value.rule_number
  egress         = true
  protocol       = each.value.protocol
  rule_action    = each.value.action
  cidr_block = each.value.selector != null ? (
    each.value.selector.ipv6 ? null : aws_subnet.this["${each.value.selector.vpc}.${each.value.selector.subnet}"].cidr_block
  ) : each.value.cidr_block
  ipv6_cidr_block = each.value.selector != null ? (
    each.value.selector.ipv6 ? aws_subnet.this["${each.value.selector.vpc}.${each.value.selector.subnet}"].ipv6_cidr_block : null
  ) : each.value.ipv6_cidr_block
  from_port = each.value.from_port
  to_port   = each.value.to_port
  icmp_type = each.value.icmp != null ? each.value.icmp.type : null
  icmp_code = each.value.icmp != null ? each.value.icmp.code : null
}

resource "aws_network_acl_association" "this" {
  for_each = local.nacl_subnet_associations

  network_acl_id = aws_network_acl.this[each.value.nacl_key].id
  subnet_id      = aws_subnet.this[each.value.subnet_key].id
}


