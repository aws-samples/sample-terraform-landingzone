# =============================================================================
# Direct Connect Gateways
# =============================================================================

locals {
  # A Direct Connect gateway exists in this module solely to be associated
  # with the Transit Gateway, so the set is intersected with
  # var.transit_gateway.enabled — the same guard the peering attachments and
  # TGW route tables carry. var.dx_gateways additionally rejects
  # entries at plan time while the Transit Gateway is off, so this ternary
  # never silently drops a configured gateway.
  dx_gateway_map = var.transit_gateway.enabled ? {
    for dxg in var.dx_gateways : dxg.name => dxg
  } : {}
}

resource "aws_dx_gateway" "this" {
  for_each = local.dx_gateway_map

  name            = each.value.name
  amazon_side_asn = each.value.amazon_asn

  tags = {
    Name = each.key
  }
}

resource "aws_dx_gateway_association" "this" {
  for_each = local.dx_gateway_map

  dx_gateway_id         = aws_dx_gateway.this[each.key].id
  associated_gateway_id = aws_ec2_transit_gateway.this[0].id

  # Prefixes advertised over the association; empty keeps the AWS default
  # (all connected routes).
  allowed_prefixes = length(each.value.allowed_prefixes) > 0 ? each.value.allowed_prefixes : null

  depends_on = [aws_ec2_transit_gateway.this]
}

# =============================================================================
# DX Gateway Attachment — TGW Route Table Wiring
# =============================================================================

locals {
  # DX gateways whose TGW attachment must be looked up for route table wiring.
  # No association resource exports the attachment ID, so the lookup runs as a
  # read deferred until the association exists.
  dx_wiring_lookup_gateways = toset([
    for dxg in var.dx_gateways : dxg.name
    if(length(dxg.route_table_associations) > 0 || length(dxg.route_table_propagations) > 0) && var.transit_gateway.enabled
  ])

  # "dxg_name.route_table_name" → wiring definition, per direction. Gated like
  # local.dx_gateway_map above.
  dx_rt_association_map = var.transit_gateway.enabled ? merge([
    for dxg in var.dx_gateways : {
      for rt in dxg.route_table_associations : "${dxg.name}.${rt}" => {
        dxg_name         = dxg.name
        route_table_name = rt
      }
    }
  ]...) : {}

  dx_rt_propagation_map = var.transit_gateway.enabled ? merge([
    for dxg in var.dx_gateways : {
      for rt in dxg.route_table_propagations : "${dxg.name}.${rt}" => {
        dxg_name         = dxg.name
        route_table_name = rt
      }
    }
  ]...) : {}
}

data "aws_ec2_transit_gateway_dx_gateway_attachment" "wiring" {
  for_each = local.dx_wiring_lookup_gateways

  transit_gateway_id = aws_ec2_transit_gateway.this[0].id
  dx_gateway_id      = aws_dx_gateway.this[each.value].id

  depends_on = [aws_dx_gateway_association.this]
}

resource "aws_ec2_transit_gateway_route_table_association" "dx" {
  for_each = local.dx_rt_association_map

  transit_gateway_attachment_id  = data.aws_ec2_transit_gateway_dx_gateway_attachment.wiring[each.value.dxg_name].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "dx" {
  for_each = local.dx_rt_propagation_map

  transit_gateway_attachment_id  = data.aws_ec2_transit_gateway_dx_gateway_attachment.wiring[each.value.dxg_name].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
}

# =============================================================================
# DX Virtual Interfaces
# =============================================================================

locals {
  # Flattened virtual interfaces: "dxg_name.vif_name" → vif definition + dxg_name
  dx_vif_map = merge([
    for dxg in var.dx_gateways : {
      for vif in dxg.virtual_interfaces : "${dxg.name}.${vif.name}" => {
        dxg_name         = dxg.name
        name             = vif.name
        type             = vif.type
        vlan             = vif.vlan
        bgp_asn          = vif.bgp_asn
        connection_id    = vif.connection_id
        address_family   = vif.address_family
        amazon_address   = vif.amazon_address
        customer_address = vif.customer_address
        auth_key         = vif.auth_key
        mtu              = vif.mtu
        sitelink_enabled = vif.sitelink_enabled
        tags             = vif.tags
      }
    }
  ]...)

  dx_private_vif_map = {
    for key, vif in local.dx_vif_map : key => vif
    if vif.type == "private"
  }

  dx_transit_vif_map = {
    for key, vif in local.dx_vif_map : key => vif
    if vif.type == "transit"
  }
}

resource "aws_dx_private_virtual_interface" "this" {
  for_each = local.dx_private_vif_map

  name           = each.value.name
  connection_id  = each.value.connection_id
  dx_gateway_id  = aws_dx_gateway.this[each.value.dxg_name].id
  vlan           = each.value.vlan
  bgp_asn        = each.value.bgp_asn
  address_family = each.value.address_family

  # BGP peering details; null leaves the AWS defaults in place.
  amazon_address   = each.value.amazon_address
  customer_address = each.value.customer_address
  bgp_auth_key     = each.value.auth_key
  mtu              = each.value.mtu
  sitelink_enabled = each.value.sitelink_enabled

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

resource "aws_dx_transit_virtual_interface" "this" {
  for_each = local.dx_transit_vif_map

  name           = each.value.name
  connection_id  = each.value.connection_id
  dx_gateway_id  = aws_dx_gateway.this[each.value.dxg_name].id
  vlan           = each.value.vlan
  bgp_asn        = each.value.bgp_asn
  address_family = each.value.address_family

  # BGP peering details; null leaves the AWS defaults in place.
  amazon_address   = each.value.amazon_address
  customer_address = each.value.customer_address
  bgp_auth_key     = each.value.auth_key
  mtu              = each.value.mtu
  sitelink_enabled = each.value.sitelink_enabled

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# =============================================================================
# DX Cross-Account Association Proposals
# =============================================================================

locals {
  # Flattened association proposals: "dxg_name.proposal_name" → proposal definition
  dx_association_proposal_map = merge([
    for dxg in var.dx_gateways : {
      for proposal in dxg.association_proposals : "${dxg.name}.${proposal.name}" => {
        dxg_name                    = dxg.name
        name                        = proposal.name
        associated_gateway_id       = proposal.associated_gateway_id
        dx_gateway_owner_account_id = proposal.dx_gateway_owner_account_id
        allowed_prefixes            = proposal.allowed_prefixes
      }
    }
  ]...)
}

resource "aws_dx_gateway_association_proposal" "this" {
  for_each = local.dx_association_proposal_map

  dx_gateway_id               = aws_dx_gateway.this[each.value.dxg_name].id
  associated_gateway_id       = each.value.associated_gateway_id
  dx_gateway_owner_account_id = each.value.dx_gateway_owner_account_id
  allowed_prefixes            = each.value.allowed_prefixes
}

check "dx_association_proposal_cross_account" {
  assert {
    condition     = length(local.dx_association_proposal_map) == 0
    error_message = "DX association proposals have been created. Proposal acceptance requires a separate Terraform configuration or manual action in the DX gateway owning account, because Terraform cannot dynamically create cross-account providers."
  }
}
