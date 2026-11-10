# Networking module outputs

output "vpc_ids" {
  description = "Map VPC-Name → VPC-ID"
  value = {
    for name, vpc in aws_vpc.this : name => vpc.id
  }
}

output "subnet_ids" {
  description = "Map vpc_name.subnet_name → Subnet-ID"
  value = {
    for key, subnet in aws_subnet.this : key => subnet.id
  }
}

output "transit_gateway_id" {
  description = "Transit Gateway ID (empty when the TGW is disabled)"
  value       = var.transit_gateway.enabled ? aws_ec2_transit_gateway.this[0].id : ""
}

output "transit_gateway_route_table_ids" {
  description = "Map Route-Table-Name → Route-Table-ID"
  value = {
    for name, rt in aws_ec2_transit_gateway_route_table.this : name => rt.id
  }
}

output "tgw_peering_attachment_ids" {
  description = "Map peering key (<peer_region>-<peer_transit_gateway_id>) → peering attachment ID"
  value = {
    for key, pa in aws_ec2_transit_gateway_peering_attachment.this : key => pa.id
  }
}

output "prefix_list_ids" {
  description = "Map Prefix-List-Name → Prefix-List-ID"
  value = {
    for name, pl in aws_ec2_managed_prefix_list.this : name => pl.id
  }
}

output "flow_log_ids" {
  description = "Map of VPC name → flow log ID (S3 and CloudWatch)"
  value = merge(
    { for name, fl in aws_flow_log.s3 : name => fl.id },
    { for name, fl in aws_flow_log.cloudwatch : name => fl.id },
  )
}

output "vpc_flow_log_ids_by_destination" {
  description = "Map of vpc_name.destination (s3, cloudwatch) → flow log ID; lists both flow logs of a VPC with destination = both"
  value = merge(
    { for name, fl in aws_flow_log.s3 : "${name}.s3" => fl.id },
    { for name, fl in aws_flow_log.cloudwatch : "${name}.cloudwatch" => fl.id },
  )
}

output "dx_gateway_ids" {
  description = "Map of DX gateway name to DX gateway ID"
  value = {
    for key, dxg in aws_dx_gateway.this : key => dxg.id
  }
}

output "customer_gateway_ids" {
  description = "Map of customer gateway name to customer gateway ID"
  value = {
    for key, cgw in aws_customer_gateway.this : key => cgw.id
  }
}

output "vpn_connection_ids" {
  description = "Map of customer gateway name to VPN connection ID"
  value = {
    for key, vpn in aws_vpn_connection.this : key => vpn.id
  }
}

output "dns_firewall_rule_group_ids" {
  description = "Map of DNS firewall rule group name to rule group ID"
  value = {
    for key, rg in aws_route53_resolver_firewall_rule_group.this : key => rg.id
  }
}

output "route53_query_log_config_id" {
  description = "Route53 Resolver query log config ID (empty if disabled)"
  value       = local.dns_query_logging_enabled ? aws_route53_resolver_query_log_config.this[0].id : ""
}

output "gwlb_ids" {
  description = "Map of GWLB name to GWLB ID"
  value = {
    for key, lb in aws_lb.gwlb : key => lb.id
  }
}

output "gwlb_target_group_arns" {
  description = "Map of GWLB name to the ARN of its target group (the registration target for firewall appliances)"
  value = {
    for key, tg in aws_lb_target_group.gwlb : key => tg.arn
  }
}

output "security_group_ids" {
  description = "Map vpc_name.sg_name to security group ID"
  value = {
    for key, sg in aws_security_group.this : key => sg.id
  }
}

output "gwlb_consumer_endpoint_ids" {
  description = "Map of gwlb_name.consumer_vpc_name to VPC endpoint ID"
  value = {
    for key, ep in aws_vpc_endpoint.gwlb_consumer : key => ep.id
  }
}

output "resolver_endpoint_ids" {
  description = "Map of resolver endpoint name to endpoint ID"
  value = {
    for name, ep in aws_route53_resolver_endpoint.this : name => ep.id
  }
}

output "vpc_template_expanded_keys" {
  description = "List of expanded VPC template keys (account_name.template_name) for documentation/intent"
  value       = keys(local.vpc_template_expanded)
}

output "firewall_endpoint_ids" {
  description = "Map of Availability Zone to Network Firewall endpoint ID"
  value = var.network_firewall.enabled ? {
    for state in try(aws_networkfirewall_firewall.this[0].firewall_status[0].sync_states, []) :
    state.availability_zone => try(state.attachment[0].endpoint_id, "")
  } : {}
}

output "firewall_endpoint_ids_by_firewall" {
  description = "Map of firewall name to a map of Availability Zone to Network Firewall endpoint ID, for the firewalls of network_firewall.firewalls"
  value = {
    for name, firewall in aws_networkfirewall_firewall.additional : name => {
      for state in try(firewall.firewall_status[0].sync_states, []) :
      state.availability_zone => try(state.attachment[0].endpoint_id, "")
    }
  }
}

output "firewall_policy_arns" {
  description = "Map of firewall policy name to policy ARN, for the policies of network_firewall.policies"
  value = {
    for name, policy in aws_networkfirewall_firewall_policy.named : name => policy.arn
  }
}

# --- Elastic IPs ---

output "eip_allocation_ids" {
  description = "Map of EIP name to allocation ID"
  value = {
    for name, eip in aws_eip.this : name => eip.id
  }
}


# --- Standalone Resolver Rule IDs ---

output "standalone_resolver_rule_ids" {
  description = "Map of standalone resolver rule name to rule ID"
  value = {
    for name, rule in aws_route53_resolver_rule.standalone : name => rule.id
  }
}

# --- ALB/NLB ---

output "load_balancer_arns" {
  description = "Map of load balancer name to LB ARN"
  value = {
    for name, lb in aws_lb.this : name => lb.arn
  }
}

# --- Target Groups ---

output "target_group_arns" {
  description = "Map of target group name to target group ARN"
  value = {
    for name, tg in aws_lb_target_group.this : name => tg.arn
  }
}

# --- DHCP Options Sets ---

output "dhcp_options_set_ids" {
  description = "Map of DHCP options set name to DHCP options set ID"
  value = {
    for name, dhcp in aws_vpc_dhcp_options.this : name => dhcp.id
  }
}

# --- TGW Flow Logs ---

output "tgw_flow_log_id" {
  description = "TGW flow log ID (empty if disabled)"
  value = (
    var.enable_tgw_flow_logs
    ? (var.tgw_flow_logs_destination == "s3"
      ? aws_flow_log.tgw_s3[0].id
    : aws_flow_log.tgw_cloudwatch[0].id)
    : ""
  )
}

# --- TGW Connect ---

output "tgw_connect_attachment_ids" {
  description = "Map of TGW Connect attachment name to attachment ID"
  value = {
    for name, ca in aws_ec2_transit_gateway_connect.this : name => ca.id
  }
}

output "tgw_connect_peer_ids" {
  description = "Map of connect_name.peer_name to TGW Connect peer ID"
  value = {
    for key, peer in aws_ec2_transit_gateway_connect_peer.this : key => peer.id
  }
}
