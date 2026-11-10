# =============================================================================
# Site-to-Site VPN — Customer Gateways + VPN Connections
# =============================================================================

locals {
  # A connection without vpc_name terminates on the Transit
  # Gateway, so those entries are intersected with var.transit_gateway.enabled;
  # VPC-terminated connections (vpc_name set) stay independent of the TGW.
  # var.customer_gateways additionally rejects TGW-terminated entries at plan
  # time while the Transit Gateway is off, so this filter never silently drops
  # a configured connection.
  customer_gateway_map = {
    for cgw in var.customer_gateways : cgw.name => cgw
    if cgw.vpc_name != null || var.transit_gateway.enabled
  }

  # VPCs with a virtual private gateway: those that declare one themselves and
  # those a VPN connection terminates on. vpc_name → the declared ASN of the
  # Amazon side (null keeps the AWS default), so a VPC that only receives a
  # connection keeps the gateway it had.
  vpn_gateway_vpcs = merge(
    {
      for cgw in var.customer_gateways : cgw.vpc_name => null
      if cgw.vpc_name != null
    },
    {
      for vpc in var.vpcs : vpc.name => vpc.virtual_private_gateway.asn
      if vpc.virtual_private_gateway != null
    },
  )

  # Tunnels with logging enabled: "cgw_name.tunnelN" → log group definition.
  # The module creates the log group so the connection can reference its ARN
  # without constructing one.
  vpn_tunnel_log_map = merge([
    for cgw in var.customer_gateways : {
      for idx, t in cgw.tunnel_options : "${cgw.name}.tunnel${idx + 1}" => {
        cgw_name       = cgw.name
        log_group_name = t.logging.log_group_name != null ? t.logging.log_group_name : "/vpn/${cgw.name}/tunnel${idx + 1}"
        output_format  = t.logging.output_format
      }
      if t.logging != null && t.logging.enable
    }
    # Same guard as customer_gateway_map: no orphaned log group for a
    # connection the Transit Gateway gate excludes.
    if cgw.vpc_name != null || var.transit_gateway.enabled
  ]...)
}

resource "aws_customer_gateway" "this" {
  for_each = local.customer_gateway_map

  bgp_asn    = each.value.bgp_asn
  ip_address = each.value.ip_address
  type       = "ipsec.1"

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# Virtual private gateway: declared on a vpcs entry, or created for a
# connection that terminates on a VPC instead of the Transit Gateway.
resource "aws_vpn_gateway" "this" {
  for_each = local.vpn_gateway_vpcs

  vpc_id = aws_vpc.this[each.key].id

  # ASN of the Amazon side. null writes nothing and leaves the AWS default
  # (64512) in place; the provider takes the number as a string.
  amazon_side_asn = each.value != null ? tostring(each.value) : null

  tags = {
    Name = "${each.key}-vgw"
  }
}

# CloudWatch log group per tunnel with logging enabled. Retention follows the
# project's 365-day baseline; long-term storage lives in the central S3 log
# bucket.
resource "aws_cloudwatch_log_group" "vpn_tunnel" {
  for_each = local.vpn_tunnel_log_map

  name              = each.value.log_group_name
  retention_in_days = 365
  kms_key_id        = var.cloudwatch_logs_kms_key_arn != "" ? var.cloudwatch_logs_kms_key_arn : null

  tags = {
    Name = each.value.log_group_name
  }
}

resource "aws_vpn_connection" "this" {
  for_each = local.customer_gateway_map

  customer_gateway_id = aws_customer_gateway.this[each.key].id
  transit_gateway_id  = each.value.vpc_name == null ? aws_ec2_transit_gateway.this[0].id : null
  vpn_gateway_id      = each.value.vpc_name == null ? null : aws_vpn_gateway.this[each.value.vpc_name].id
  type                = "ipsec.1"

  # Connection-level options; null leaves the AWS default in place.
  static_routes_only       = each.value.static_routes_only
  enable_acceleration      = each.value.enable_acceleration
  outside_ip_address_type  = each.value.outside_ip_address_type
  tunnel_inside_ip_version = each.value.tunnel_inside_ip_version

  # Traffic filters: which ranges may talk over the tunnel, per side and
  # address family. "local" is the customer side, "remote" the AWS side.
  local_ipv4_network_cidr  = each.value.customer_ipv4_network_cidr
  local_ipv6_network_cidr  = each.value.customer_ipv6_network_cidr
  remote_ipv4_network_cidr = each.value.amazon_ipv4_network_cidr
  remote_ipv6_network_cidr = each.value.amazon_ipv6_network_cidr

  # Tunnel 1 options
  tunnel1_inside_cidr         = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].tunnel_inside_cidr : null
  tunnel1_preshared_key       = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].pre_shared_key : null
  tunnel1_dpd_timeout_seconds = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].dpd_timeout_seconds : null

  # Tunnel 1 advanced options
  tunnel1_ike_versions                 = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].ike_versions : null
  tunnel1_phase1_encryption_algorithms = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase1_encryption_algorithms : null
  tunnel1_phase2_encryption_algorithms = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase2_encryption_algorithms : null
  tunnel1_phase1_integrity_algorithms  = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase1_integrity_algorithms : null
  tunnel1_phase2_integrity_algorithms  = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase2_integrity_algorithms : null
  tunnel1_phase1_dh_group_numbers      = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase1_dh_group_numbers : null
  tunnel1_phase2_dh_group_numbers      = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase2_dh_group_numbers : null
  tunnel1_startup_action               = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].startup_action : null
  tunnel1_dpd_timeout_action           = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].dpd_timeout_action : null
  tunnel1_rekey_margin_time_seconds    = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].rekey_margin_time_seconds : null
  tunnel1_rekey_fuzz_percentage        = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].rekey_fuzz_percentage : null
  tunnel1_replay_window_size           = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].replay_window_size : null

  # Tunnel 1 lifetimes, inside IPv6 range, lifecycle control
  tunnel1_phase1_lifetime_seconds         = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase1_lifetime_seconds : null
  tunnel1_phase2_lifetime_seconds         = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].phase2_lifetime_seconds : null
  tunnel1_inside_ipv6_cidr                = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].tunnel_inside_ipv6_cidr : null
  tunnel1_enable_tunnel_lifecycle_control = length(each.value.tunnel_options) >= 1 ? each.value.tunnel_options[0].enable_tunnel_lifecycle_control : null

  # Tunnel 1 activity logging
  dynamic "tunnel1_log_options" {
    for_each = contains(keys(local.vpn_tunnel_log_map), "${each.key}.tunnel1") ? [1] : []
    content {
      cloudwatch_log_options {
        log_enabled       = true
        log_group_arn     = aws_cloudwatch_log_group.vpn_tunnel["${each.key}.tunnel1"].arn
        log_output_format = local.vpn_tunnel_log_map["${each.key}.tunnel1"].output_format
      }
    }
  }

  # Tunnel 2 options
  tunnel2_inside_cidr         = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].tunnel_inside_cidr : null
  tunnel2_preshared_key       = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].pre_shared_key : null
  tunnel2_dpd_timeout_seconds = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].dpd_timeout_seconds : null

  # Tunnel 2 advanced options
  tunnel2_ike_versions                 = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].ike_versions : null
  tunnel2_phase1_encryption_algorithms = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase1_encryption_algorithms : null
  tunnel2_phase2_encryption_algorithms = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase2_encryption_algorithms : null
  tunnel2_phase1_integrity_algorithms  = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase1_integrity_algorithms : null
  tunnel2_phase2_integrity_algorithms  = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase2_integrity_algorithms : null
  tunnel2_phase1_dh_group_numbers      = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase1_dh_group_numbers : null
  tunnel2_phase2_dh_group_numbers      = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase2_dh_group_numbers : null
  tunnel2_startup_action               = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].startup_action : null
  tunnel2_dpd_timeout_action           = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].dpd_timeout_action : null
  tunnel2_rekey_margin_time_seconds    = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].rekey_margin_time_seconds : null
  tunnel2_rekey_fuzz_percentage        = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].rekey_fuzz_percentage : null
  tunnel2_replay_window_size           = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].replay_window_size : null

  # Tunnel 2 lifetimes, inside IPv6 range, lifecycle control
  tunnel2_phase1_lifetime_seconds         = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase1_lifetime_seconds : null
  tunnel2_phase2_lifetime_seconds         = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].phase2_lifetime_seconds : null
  tunnel2_inside_ipv6_cidr                = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].tunnel_inside_ipv6_cidr : null
  tunnel2_enable_tunnel_lifecycle_control = length(each.value.tunnel_options) >= 2 ? each.value.tunnel_options[1].enable_tunnel_lifecycle_control : null

  # Tunnel 2 activity logging
  dynamic "tunnel2_log_options" {
    for_each = contains(keys(local.vpn_tunnel_log_map), "${each.key}.tunnel2") ? [1] : []
    content {
      cloudwatch_log_options {
        log_enabled       = true
        log_group_arn     = aws_cloudwatch_log_group.vpn_tunnel["${each.key}.tunnel2"].arn
        log_output_format = local.vpn_tunnel_log_map["${each.key}.tunnel2"].output_format
      }
    }
  }

  tags = merge(each.value.vpn_connection_tags, {
    Name = "${each.key}-vpn"
  })

  depends_on = [aws_ec2_transit_gateway.this]
}
