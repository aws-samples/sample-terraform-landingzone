# =============================================================================
# Transit Gateway
# =============================================================================

resource "aws_ec2_transit_gateway" "this" {
  count = var.transit_gateway.enabled ? 1 : 0

  amazon_side_asn                 = var.transit_gateway.amazon_asn
  auto_accept_shared_attachments  = var.transit_gateway.auto_accept_shared_attachments
  default_route_table_association = var.transit_gateway.default_route_table_association
  default_route_table_propagation = var.transit_gateway.default_route_table_propagation
  dns_support                     = var.transit_gateway.dns_support

  # Gateway options; null leaves the AWS default in place.
  vpn_ecmp_support                   = var.transit_gateway.vpn_ecmp_support
  multicast_support                  = var.transit_gateway.multicast_support
  security_group_referencing_support = var.transit_gateway.security_group_referencing_support

  # IPv4 and IPv6 CIDR blocks assigned to the gateway; empty writes nothing.
  transit_gateway_cidr_blocks = length(var.transit_gateway.cidr_blocks) > 0 ? var.transit_gateway.cidr_blocks : null

  tags = merge(var.transit_gateway.tags, {
    Name = "tlz-transit-gateway"
  })
}

# TGW Route Tables
resource "aws_ec2_transit_gateway_route_table" "this" {
  for_each = var.transit_gateway.enabled ? toset(var.transit_gateway.route_tables) : toset([])

  transit_gateway_id = aws_ec2_transit_gateway.this[0].id

  # route_tables carries names only, so the tags of a route table come from
  # route_table_tags under that name.
  tags = merge(lookup(var.transit_gateway.route_table_tags, each.value, {}), {
    Name = each.value
  })
}

# TGW VPC Attachments
resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  for_each = local.tgw_vpc_attachments

  transit_gateway_id = aws_ec2_transit_gateway.this[0].id
  vpc_id             = aws_vpc.this[each.key].id

  # Explicitly named subnets win; without them the module derives the
  # attachment subnets — one per AZ (subnets with "tgw" in the name).
  subnet_ids = length(each.value.subnet_names) > 0 ? [
    for name in each.value.subnet_names :
    aws_subnet.this["${each.key}.${name}"].id
    ] : [
    for key, s in local.subnet_map :
    aws_subnet.this[key].id
    if s.vpc_name == each.key && can(regex("tgw", s.name))
  ]

  appliance_mode_support = each.value.appliance_mode_support

  # Attachment options; null leaves the AWS default in place.
  dns_support                        = each.value.dns_support
  ipv6_support                       = each.value.ipv6_support
  security_group_referencing_support = each.value.security_group_referencing_support

  tags = merge(each.value.tags, {
    Name = "${each.key}-tgw-attachment"
  })

  depends_on = [aws_ec2_transit_gateway.this]
}

# TGW Route Table Associations
resource "aws_ec2_transit_gateway_route_table_association" "this" {
  for_each = local.tgw_vpc_attachments

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.this[each.key].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
}

# TGW Peering (Multi-Region)
locals {
  # Peering map: "<peer_region>-<peer_transit_gateway_id>" → peering entry.
  # The key is the name static_routes and route_table_propagations use to
  # address a peering attachment.
  tgw_peering_map = var.transit_gateway.enabled ? {
    for p in var.transit_gateway.peering : "${p.peer_region}-${p.peer_transit_gateway_id}" => p
  } : {}
}

resource "aws_ec2_transit_gateway_peering_attachment" "this" {
  for_each = local.tgw_peering_map

  transit_gateway_id      = aws_ec2_transit_gateway.this[0].id
  peer_region             = each.value.peer_region
  peer_transit_gateway_id = each.value.peer_transit_gateway_id

  # Account of the peer gateway. null leaves the requester account in place,
  # which is what AWS assumes for a peering inside one account.
  peer_account_id = try(each.value.accepter.account, null) != null ? lookup(var.account_ids, each.value.accepter.account, each.value.accepter.account) : null

  tags = merge(each.value.tags, {
    Name = "tgw-peering-${each.value.peer_region}"
  })
}

# Requester-side route table association of a peering attachment: an
# attachment carries one association per gateway it spans, and this is the one
# of the gateway the module owns. The accepter's association belongs to the
# peer gateway and is created by the module instance that owns it — through
# transit_gateway.peering_accepters below.
resource "aws_ec2_transit_gateway_route_table_association" "peering" {
  for_each = local.tgw_peering_map

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.this[each.key].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
}

# =============================================================================
# TGW Static Routes
# =============================================================================

locals {
  # CIDR destinations keep their original keys; prefix list destinations are a
  # separate resource type and get their own map.
  tgw_static_route_map = var.transit_gateway.enabled ? {
    for idx, route in var.transit_gateway.static_routes :
    "${route.route_table_name}.${route.destination_cidr_block}" => route
    if route.destination_cidr_block != null
  } : {}

  tgw_prefix_list_route_map = var.transit_gateway.enabled ? {
    for idx, route in var.transit_gateway.static_routes :
    "${route.route_table_name}.${route.destination_prefix_list_name}" => route
    if route.destination_prefix_list_name != null
  } : {}

  # DX gateways named as next hop of a static route: their TGW attachment ID
  # is not exported by any resource, so it is looked up once per gateway.
  tgw_route_dx_gateways = toset([
    for route in var.transit_gateway.static_routes : route.attachment_name
    if route.attachment_type == "dx-gateway" && !route.blackhole
  ])
}

data "aws_ec2_transit_gateway_dx_gateway_attachment" "route" {
  for_each = local.tgw_route_dx_gateways

  transit_gateway_id = aws_ec2_transit_gateway.this[0].id
  dx_gateway_id      = aws_dx_gateway.this[each.value].id

  depends_on = [aws_dx_gateway_association.this]
}

resource "aws_ec2_transit_gateway_route" "static" {
  for_each = local.tgw_static_route_map

  destination_cidr_block         = each.value.destination_cidr_block
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
  transit_gateway_attachment_id = each.value.blackhole ? null : (
    each.value.attachment_type == "vpn" ? aws_vpn_connection.this[each.value.attachment_name].transit_gateway_attachment_id :
    each.value.attachment_type == "dx-gateway" ? data.aws_ec2_transit_gateway_dx_gateway_attachment.route[each.value.attachment_name].id :
    each.value.attachment_type == "peering" ? aws_ec2_transit_gateway_peering_attachment.this[each.value.attachment_name].id :
    aws_ec2_transit_gateway_vpc_attachment.this[each.value.attachment_name].id
  )
  blackhole = each.value.blackhole
}

# Prefix list destinations are their own route entry type on the route table.
resource "aws_ec2_transit_gateway_prefix_list_reference" "static" {
  for_each = local.tgw_prefix_list_route_map

  prefix_list_id                 = aws_ec2_managed_prefix_list.this[each.value.destination_prefix_list_name].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
  transit_gateway_attachment_id = each.value.blackhole ? null : (
    each.value.attachment_type == "vpn" ? aws_vpn_connection.this[each.value.attachment_name].transit_gateway_attachment_id :
    each.value.attachment_type == "dx-gateway" ? data.aws_ec2_transit_gateway_dx_gateway_attachment.route[each.value.attachment_name].id :
    each.value.attachment_type == "peering" ? aws_ec2_transit_gateway_peering_attachment.this[each.value.attachment_name].id :
    aws_ec2_transit_gateway_vpc_attachment.this[each.value.attachment_name].id
  )
  blackhole = each.value.blackhole
}

# =============================================================================
# TGW RAM Sharing
# =============================================================================

locals {
  tgw_share_target_map = var.enable_ram_sharing && var.transit_gateway.enabled && length(var.transit_gateway.share_targets) > 0 ? {
    for target in var.transit_gateway.share_targets : target => lookup(var.account_ids, target, target)
  } : {}
}

resource "aws_ram_resource_share" "tgw" {
  count = var.enable_ram_sharing && var.transit_gateway.enabled && length(var.transit_gateway.share_targets) > 0 ? 1 : 0

  name                      = "tlz-tgw-share"
  allow_external_principals = false

  tags = {
    Name = "tlz-tgw-share"
  }
}

resource "aws_ram_resource_association" "tgw" {
  count = var.enable_ram_sharing && var.transit_gateway.enabled && length(var.transit_gateway.share_targets) > 0 ? 1 : 0

  resource_arn       = aws_ec2_transit_gateway.this[0].arn
  resource_share_arn = aws_ram_resource_share.tgw[0].arn
}

resource "aws_ram_principal_association" "tgw" {
  for_each = local.tgw_share_target_map

  principal          = each.value
  resource_share_arn = aws_ram_resource_share.tgw[0].arn
}

# =============================================================================
# TGW Route Table Propagations
# =============================================================================

locals {
  tgw_propagation_map = var.transit_gateway.enabled ? {
    for idx, prop in var.transit_gateway.route_table_propagations :
    "${prop.route_table_name}.${prop.attachment_name}" => prop
  } : {}
}

resource "aws_ec2_transit_gateway_route_table_propagation" "this" {
  for_each = local.tgw_propagation_map

  transit_gateway_attachment_id = (
    each.value.attachment_type == "peering"
    ? aws_ec2_transit_gateway_peering_attachment.this[each.value.attachment_name].id
    : aws_ec2_transit_gateway_vpc_attachment.this[each.value.attachment_name].id
  )
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
}

# =============================================================================
# TGW Peering Attachment Accepter
# =============================================================================

locals {
  tgw_peering_accepter_map = {
    for key, p in local.tgw_peering_map : key => p
    if p.auto_accept
  }

  # Peering attachments of another account or region that this gateway
  # accepts, keyed by their name.
  tgw_peering_accepted_map = {
    for accepter in var.transit_gateway.peering_accepters : accepter.name => accepter
  }

  # Those of them that name a route table of this gateway.
  tgw_peering_accepted_association_map = {
    for name, accepter in local.tgw_peering_accepted_map : name => accepter
    if accepter.route_table_name != null
  }
}

resource "aws_ec2_transit_gateway_peering_attachment_accepter" "this" {
  for_each = local.tgw_peering_accepter_map

  transit_gateway_attachment_id = aws_ec2_transit_gateway_peering_attachment.this[each.key].id

  # apply_tags_from_requester copies the tags of the peering entry onto the
  # accepter attachment, accepter.tags adds accepter-only tags; the module's
  # Name comes last and wins (see README, section "Tagging").
  tags = merge(
    try(each.value.accepter.apply_tags_from_requester, false) ? each.value.tags : {},
    try(each.value.accepter.tags, {}),
    {
      Name = "tgw-peering-accepter-${each.value.peer_region}"
    }
  )
}

# Accepter role: the peering was requested by another account or region, and
# this module instance owns the accepting gateway. The attachment ID comes from
# the requesting side (its tgw_peering_attachment_ids output).
resource "aws_ec2_transit_gateway_peering_attachment_accepter" "accepted" {
  for_each = local.tgw_peering_accepted_map

  transit_gateway_attachment_id = each.value.transit_gateway_attachment_id

  tags = merge(each.value.tags, {
    Name = each.key
  })

  lifecycle {
    precondition {
      condition     = var.transit_gateway.enabled
      error_message = "Transit Gateway must be enabled to accept peering attachments — transit_gateway.peering_accepters associates them with the route tables of this gateway."
    }
  }
}

# Accepter-side route table association: the association of the gateway this
# module instance owns, on the attachment it just accepted.
resource "aws_ec2_transit_gateway_route_table_association" "peering_accepted" {
  for_each = local.tgw_peering_accepted_association_map

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment_accepter.accepted[each.key].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.route_table_name].id
}

# =============================================================================
# TGW Connect Attachments
# =============================================================================

locals {
  # Connect attachment map: name → definition. Intersected with
  # var.transit_gateway.enabled: a Connect attachment transports
  # over the Transit Gateway, and var.tgw_connect_attachments rejects entries
  # at plan time while the Transit Gateway is off.
  tgw_connect_map = var.transit_gateway.enabled ? {
    for ca in var.tgw_connect_attachments : ca.name => ca
  } : {}

  # Direct Connect gateways named as the transport of a Connect attachment:
  # their TGW attachment ID is not exported by any resource, so it is looked up
  # once per gateway — the same lookup the static routes use for their next hop.
  tgw_connect_dx_gateways = toset([
    for ca in var.tgw_connect_attachments : ca.transport_attachment
    if ca.transport_attachment_type == "dx-gateway" && var.transit_gateway.enabled
  ])

  # Flattened peer map: "connect_name.peer_name" → peer definition + connect_name
  tgw_connect_peer_map = var.transit_gateway.enabled ? merge([
    for ca in var.tgw_connect_attachments : {
      for peer in ca.peers : "${ca.name}.${peer.name}" => {
        connect_name            = ca.name
        name                    = peer.name
        peer_address            = peer.peer_address
        transit_gateway_address = peer.transit_gateway_address
        bgp_asn                 = peer.bgp_asn
        inside_cidr_blocks      = peer.inside_cidr_blocks
      }
    }
  ]...) : {}
}

data "aws_ec2_transit_gateway_dx_gateway_attachment" "connect" {
  for_each = local.tgw_connect_dx_gateways

  transit_gateway_id = aws_ec2_transit_gateway.this[0].id
  dx_gateway_id      = aws_dx_gateway.this[each.value].id

  depends_on = [aws_dx_gateway_association.this]
}

resource "aws_ec2_transit_gateway_connect" "this" {
  for_each = local.tgw_connect_map

  transport_attachment_id = (
    each.value.transport_attachment_type == "dx-gateway"
    ? data.aws_ec2_transit_gateway_dx_gateway_attachment.connect[each.value.transport_attachment].id
    : aws_ec2_transit_gateway_vpc_attachment.this[each.value.transport_attachment].id
  )
  transit_gateway_id = aws_ec2_transit_gateway.this[0].id
  protocol           = each.value.protocol

  tags = merge(each.value.tags, {
    Name = each.key
  })

  # No lifecycle precondition on var.transit_gateway.enabled here: it would
  # evaluate after the transit_gateway_id expression had already failed with
  # "Invalid index". The variable validation on tgw_connect_attachments
  # rejects the configuration first.
}

resource "aws_ec2_transit_gateway_connect_peer" "this" {
  for_each = local.tgw_connect_peer_map

  transit_gateway_attachment_id = aws_ec2_transit_gateway_connect.this[each.value.connect_name].id
  peer_address                  = each.value.peer_address
  transit_gateway_address       = each.value.transit_gateway_address
  bgp_asn                       = each.value.bgp_asn
  inside_cidr_blocks            = each.value.inside_cidr_blocks

  tags = {
    Name = each.key
  }
}

# =============================================================================
# TGW Flow Logs
# =============================================================================

locals {
  # "both" delivers to S3 and CloudWatch at the same time.
  tgw_flow_logs_to_s3         = var.enable_tgw_flow_logs && contains(["s3", "both"], var.tgw_flow_logs_destination)
  tgw_flow_logs_to_cloudwatch = var.enable_tgw_flow_logs && contains(["cloudwatch", "both"], var.tgw_flow_logs_destination)
}

# CloudWatch Log Group for TGW Flow Logs (destination cloudwatch or both)
resource "aws_cloudwatch_log_group" "tgw_flow_logs" {
  count = local.tgw_flow_logs_to_cloudwatch ? 1 : 0

  name = "/tgw/flow-logs"
  # The default of 365 days matches the retention baseline the project applies
  # to its other log groups (configurations/base/base.tfvars); long-term
  # storage beyond that lives in the central S3 log bucket.
  retention_in_days = var.tgw_flow_logs_retention_days
  kms_key_id        = var.cloudwatch_logs_kms_key_arn != "" ? var.cloudwatch_logs_kms_key_arn : null

  tags = {
    Name = "tgw-flow-logs"
  }
}

# IAM role for TGW Flow Logs (CloudWatch destination)
resource "aws_iam_role" "tgw_flow_logs" {
  count = local.tgw_flow_logs_to_cloudwatch ? 1 : 0

  name = "tlz-tgw-flow-logs-role"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/networking/vpc-flow-logs-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))

  tags = {
    Name = "tlz-tgw-flow-logs-role"
  }
}

resource "aws_iam_role_policy" "tgw_flow_logs" {
  count = local.tgw_flow_logs_to_cloudwatch ? 1 : 0

  name = "tlz-tgw-flow-logs-policy"
  role = aws_iam_role.tgw_flow_logs[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/networking/tgw-flow-logs-policy.json", {
    arn_prefix = local.arn_prefix
    region     = local.region
    account_id = data.aws_caller_identity.current.account_id
  })))
}

# TGW Flow Log — S3 destination
resource "aws_flow_log" "tgw_s3" {
  count = local.tgw_flow_logs_to_s3 ? 1 : 0

  transit_gateway_id   = aws_ec2_transit_gateway.this[0].id
  log_destination      = "${local.arn_prefix}:s3:::${var.central_log_bucket_name}/${var.tgw_flow_logs_s3_path}/"
  log_destination_type = "s3"
  traffic_type         = "ALL"

  tags = {
    Name = "tgw-flow-log-s3"
  }

  lifecycle {
    precondition {
      condition     = var.transit_gateway.enabled
      error_message = "Transit Gateway must be enabled to create TGW flow logs."
    }
    precondition {
      condition     = var.central_log_bucket_name != ""
      error_message = "central_log_bucket_name must not be empty when TGW S3 flow logs are enabled."
    }
  }
}

# =============================================================================
# TGW Flow-Log Drain Window
# =============================================================================

# Same barrier as time_sleep.flow_log_drain in flow-logs.tf, for the Transit
# Gateway flow log: deleting a flow log does not stop delivery at
# once, and a publish that lands after the destination group is gone makes the
# flow-logs service RECREATE the group under the role this module builds
# (aws_iam_role.tgw_flow_logs). The recreated group is outside Terraform's
# state, so every destroy leaves /tgw/flow-logs behind and the next apply of
# the same configuration dies with CreateLogGroup ... already exists.
#
# DURATION DERIVED FROM THIS FLOW LOG'S OWN WINDOW, not copied from the VPC
# one: aws_flow_log.tgw_cloudwatch sets no max_aggregation_interval, so AWS
# applies its own default of 600 s -- that is the window it publishes on, and
# the barrier is that plus a 60 s margin. A wait under the interval would be
# self-deception.
resource "time_sleep" "tgw_flow_log_drain" {
  count = local.tgw_flow_logs_to_cloudwatch ? 1 : 0

  # No wait on the way up — only on the way down.
  destroy_duration = "660s"

  # This barrier must be torn down BEFORE the log group, so it depends on the
  # group. Chain on destroy: aws_flow_log.tgw_cloudwatch -> this -> log group.
  depends_on = [aws_cloudwatch_log_group.tgw_flow_logs]
}

# TGW Flow Log — CloudWatch destination
resource "aws_flow_log" "tgw_cloudwatch" {
  count = local.tgw_flow_logs_to_cloudwatch ? 1 : 0

  transit_gateway_id = aws_ec2_transit_gateway.this[0].id
  iam_role_arn       = aws_iam_role.tgw_flow_logs[0].arn
  log_destination    = aws_cloudwatch_log_group.tgw_flow_logs[0].arn
  traffic_type       = "ALL"

  tags = {
    Name = "tgw-flow-log-cw"
  }

  # The drain window below must be TORN DOWN AFTER this flow log, so this flow
  # log depends on it: on destroy Terraform removes the dependent first.
  depends_on = [time_sleep.tgw_flow_log_drain]

  lifecycle {
    precondition {
      condition     = var.transit_gateway.enabled
      error_message = "Transit Gateway must be enabled to create TGW flow logs."
    }
  }
}

# =============================================================================
# TGW Multicast Domains — Deferred
# =============================================================================

check "tgw_multicast_domains_deferred" {
  assert {
    condition     = length(var.tgw_multicast_domains) == 0
    error_message = "TGW Multicast domains are deferred. Implement when multicast traffic distribution is required."
  }
}
