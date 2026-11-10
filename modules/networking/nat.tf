# =============================================================================
# Elastic IPs for NAT Gateways
# =============================================================================
# Only for the NAT gateways whose address the module allocates: a private NAT
# gateway has none, and a public one that names an allocation ID or an entry of
# var.elastic_ips brings its own.

resource "aws_eip" "nat" {
  for_each = local.nat_gateway_own_address_subnets

  domain = "vpc"

  # The address belongs to the NAT gateway of this subnet, so it carries the
  # subnet's nat_gateway_tags together with the two resources' own names.
  tags = merge(each.value.nat_gateway_tags, {
    Name = "${local.nat_gateway_names[each.key]}-eip"
  })
}

# =============================================================================
# NAT gateways — on public subnets with nat_gateway = true
# =============================================================================

locals {
  # Name of each NAT gateway: the subnet's nat_gateway_name, else the key the
  # module derives. The resource stays keyed by the subnet, so the
  # name changes the tags and nothing else.
  nat_gateway_names = {
    for key, s in local.nat_gateway_subnets : key => s.nat_gateway_name != null ? s.nat_gateway_name : "${key}-nat"
  }
}

resource "aws_nat_gateway" "this" {
  for_each = local.nat_gateway_subnets

  # A private NAT gateway translates between private ranges and takes no
  # address; a public one uses the module's address unless the subnet names an
  # existing one — raw allocation ID or an entry of var.elastic_ips.
  connectivity_type = each.value.nat_gateway_private ? "private" : "public"

  allocation_id = each.value.nat_gateway_private ? null : (
    each.value.nat_gateway_allocation_id != null ? each.value.nat_gateway_allocation_id : (
      each.value.nat_gateway_eip_name != null ? aws_eip.this[each.value.nat_gateway_eip_name].id : aws_eip.nat[each.key].id
    )
  )

  subnet_id = aws_subnet.this[each.key].id

  tags = merge(each.value.nat_gateway_tags, {
    Name = local.nat_gateway_names[each.key]
  })

  depends_on = [aws_internet_gateway.this]
}
