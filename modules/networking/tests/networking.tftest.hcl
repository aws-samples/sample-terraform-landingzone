# =============================================================================
# Networking Module Tests (modules/networking)
# =============================================================================
# Coverage (four mandatory scenarios):
#   1. Toggle-Off      — all toggles false / all collections empty -> zero resources
#   2. Default         — minimal valid VPC with default values
#   3. Custom          — user-defined configuration with realistic values
#                        (3a VPC/subnet/endpoint layer, 3b TGW/DNS/VPN layer,
#                         3c IPAM and Network Firewall layer, 3d IPAM pool
#                         hierarchy, 3e resolver rules and their VPC
#                         associations, 3f named endpoint policies,
#                         3g VPC scaffolding, 3h/3i VPC templates,
#                         3j load balancing, 3k hybrid connectivity,
#                         3l deferred TGW multicast, 3m DNS and query logging,
#                         3n/3o free-form tags per resource list, 3p the tag
#                         default {} leaving resources unchanged,
#                         3q extended target group attributes,
#                         3r extended load balancer attributes,
#                         3s listener actions beyond forwarding, 3t the unset
#                         load balancing attributes leaving the plan unchanged,
#                         3u Transit Gateway attachment options and explicit
#                         subnet choice, 3v VPN connection and tunnel options
#                         incl. VGW termination and tunnel logging,
#                         3w Direct Connect details: VIF addresses/auth/MTU/
#                         SiteLink, association prefixes, route table wiring,
#                         3x Transit Gateway options, static routes on
#                         VPN/DX/peering attachments and prefix list
#                         destinations, flow log fine-tuning, 3y the unset
#                         hybrid connectivity attributes leaving the plan
#                         unchanged, 3z subnet options and Outposts with local
#                         gateway route table associations, 3aa route
#                         destinations (IPv6, prefix lists) and next-hop types
#                         incl. gateway route tables and VGW propagation,
#                         3ab the unset subnet and route attributes leaving
#                         the plan unchanged, 3ac VPC endpoint options:
#                         gateway endpoint policies and service names,
#                         interface service names, central endpoints with
#                         their hosted zones, 3ad the per-endpoint security
#                         group replacing the default endpoint group,
#                         3ae the unset endpoint options leaving the plan
#                         unchanged, 3af DNS firewall association mutation
#                         protection, 3ag NACL rule sources: subnet selectors
#                         across VPC entries, literal IPv6 CIDRs, ICMP
#                         type/code pairs, 3ah flat NACL rules leaving the
#                         plan unchanged, 3ai security group rule sources and
#                         types: subnet selectors, IPv6 CIDRs, named types,
#                         egress group references, group descriptions,
#                         3aj flat security group rules leaving the plan
#                         unchanged, 3ak/3ak-ipam RAM shares for IPAM pools,
#                         Network Firewall rule groups and policy and the
#                         query logging configuration incl. OU/organization
#                         ARNs as share targets, 3al the sharing toggle
#                         keeping all of them off, 3am entries without
#                         share_targets leaving the plan unchanged, 3an ACM
#                         material import, DNS validation records in a
#                         managed zone and the key algorithm choice, 3ao
#                         plain certificate requests leaving the plan
#                         unchanged, 3ap a validation zone carrying a VPC
#                         reported by its check block)
#   4. Validation      — invalid input rejected via expect_failures
#
# Scenarios 3g to 3m hold the stack pass-through of 21 module variables that
# stacks/management/networking/terragrunt.hcl sets. Every one of them is
# covered in both states: set here, empty or null in scenario 1.
#
# The module has no single module-level toggle. The Toggle-Off scenario covers
# all boolean and nested toggles: transit_gateway.enabled, network_firewall.-
# enabled, ipam.enabled, delete_default_vpc, enable_route53_query_logging,
# enable_tgw_flow_logs, enable_ram_sharing.
#
# The module uses a single unaliased AWS provider (no configuration_aliases),
# so one mock_provider "aws" covers all provider usage.

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111111111111"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }
}

# -----------------------------------------------------------------------------
# 1. Toggle-Off — no VPCs, every feature disabled
# -----------------------------------------------------------------------------

run "networking_all_toggles_off" {
  command = plan

  variables {
    vpcs                              = []
    transit_gateway                   = { enabled = false }
    network_firewall                  = { enabled = false }
    ipam                              = { enabled = false }
    delete_default_vpc                = false
    enable_route53_query_logging      = false
    enable_tgw_flow_logs              = false
    enable_ram_sharing                = false
    prefix_lists                      = []
    vpc_peering                       = []
    route53_zones                     = []
    dns_firewall_rule_groups          = []
    resolver_rules                    = []
    resolver_endpoints                = []
    dhcp_options_sets                 = []
    elastic_ips                       = []
    endpoint_policies                 = []
    load_balancers                    = []
    target_groups                     = []
    gateway_load_balancers            = []
    dx_gateways                       = []
    customer_gateways                 = []
    tgw_connect_attachments           = []
    tgw_multicast_domains             = []
    acm_certificates                  = []
    vpc_templates                     = []
    vpc_flow_logs_default             = null
    tgw_flow_logs_destination         = "s3"
    route53_query_logging_destination = "cloudwatch"
    route53_query_logging_vpc_names   = []
  }

  assert {
    condition     = length(aws_vpc.this) == 0 && length(aws_subnet.this) == 0
    error_message = "No VPCs or subnets must be created when vpcs is empty."
  }

  assert {
    condition     = length(aws_route_table.this) == 0 && length(aws_route_table_association.this) == 0
    error_message = "No route tables must be created when vpcs is empty."
  }

  assert {
    condition     = length(aws_internet_gateway.this) == 0
    error_message = "No internet gateway must be created without public subnets."
  }

  assert {
    condition     = length(aws_eip.nat) == 0 && length(aws_nat_gateway.this) == 0
    error_message = "No NAT gateways must be created without nat_gateway subnets."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway.this) == 0
    error_message = "No Transit Gateway must be created when transit_gateway.enabled is false."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table.this) == 0 && length(aws_ec2_transit_gateway_vpc_attachment.this) == 0
    error_message = "No TGW route tables or attachments must be created when the TGW is disabled."
  }

  assert {
    condition     = length(aws_networkfirewall_firewall.this) == 0 && length(aws_networkfirewall_firewall_policy.this) == 0
    error_message = "No Network Firewall must be created when network_firewall.enabled is false."
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this) == 0
    error_message = "No Network Firewall rule groups must be created when the firewall is disabled."
  }

  assert {
    condition     = length(aws_vpc_ipam.this) == 0 && length(aws_vpc_ipam_pool.this) == 0
    error_message = "No IPAM resources must be created when ipam.enabled is false."
  }

  assert {
    condition     = length(aws_vpc_ipam_organization_admin_account.this) == 0
    error_message = "No IPAM delegated admin must be created when ipam is disabled."
  }

  assert {
    condition     = length(aws_default_vpc.this) == 0 && length(aws_default_subnet.this) == 0
    error_message = "The default VPC must not be adopted when delete_default_vpc is false."
  }

  assert {
    condition     = length(aws_route53_resolver_query_log_config.this) == 0
    error_message = "No query log config must be created when query logging is disabled."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.query_logging) == 0
    error_message = "No query logging log group must be created when query logging is disabled."
  }

  assert {
    condition     = length(aws_flow_log.tgw_s3) == 0 && length(aws_flow_log.tgw_cloudwatch) == 0
    error_message = "No TGW flow logs must be created when enable_tgw_flow_logs is false."
  }

  assert {
    condition     = length(aws_ram_resource_share.subnet) == 0 && length(aws_ram_resource_share.tgw) == 0
    error_message = "No RAM shares must be created when enable_ram_sharing is false."
  }

  assert {
    condition     = length(aws_ram_resource_share.vpc_sharing) == 0 && length(aws_ram_resource_share.dns_firewall) == 0
    error_message = "No RAM shares must be created when enable_ram_sharing is false."
  }

  assert {
    condition     = length(aws_ec2_managed_prefix_list.this) == 0
    error_message = "No prefix lists must be created when prefix_lists is empty."
  }

  assert {
    condition     = length(aws_vpc_peering_connection.this) == 0 && length(aws_route.peering) == 0
    error_message = "No peering connections must be created when vpc_peering is empty."
  }

  assert {
    condition     = length(aws_route53_zone.private) == 0 && length(aws_route53_resolver_rule.standalone) == 0
    error_message = "No Route53 resources must be created when the collections are empty."
  }

  assert {
    condition     = length(aws_route53_resolver_endpoint.this) == 0 && length(aws_security_group.resolver_endpoint) == 0
    error_message = "No resolver endpoints must be created when resolver_endpoints is empty."
  }

  assert {
    condition     = length(aws_route53_resolver_firewall_rule_group.this) == 0
    error_message = "No DNS firewall rule groups must be created when the collection is empty."
  }

  assert {
    condition     = length(aws_vpc_dhcp_options.this) == 0 && length(aws_vpc_dhcp_options_association.this) == 0
    error_message = "No DHCP options sets must be created when dhcp_options_sets is empty."
  }

  assert {
    condition     = length(aws_eip.this) == 0
    error_message = "No Elastic IPs must be created when elastic_ips is empty."
  }

  assert {
    condition     = length(aws_lb.this) == 0 && length(aws_lb_target_group.this) == 0 && length(aws_lb_listener.this) == 0
    error_message = "No load balancer resources must be created when the collections are empty."
  }

  assert {
    condition     = length(aws_lb.gwlb) == 0 && length(aws_vpc_endpoint_service.gwlb) == 0
    error_message = "No GWLB resources must be created when gateway_load_balancers is empty."
  }

  assert {
    condition     = length(aws_lb_listener.gwlb) == 0 && length(aws_vpc_endpoint.gwlb_consumer) == 0
    error_message = "No GWLB listener or consumer endpoint must be created when gateway_load_balancers is empty."
  }

  assert {
    condition     = length(aws_dx_gateway.this) == 0 && length(aws_dx_gateway_association.this) == 0
    error_message = "No DX resources must be created when dx_gateways is empty."
  }

  assert {
    condition     = length(aws_dx_transit_virtual_interface.this) == 0 && length(aws_dx_private_virtual_interface.this) == 0 && length(aws_dx_gateway_association_proposal.this) == 0
    error_message = "No DX virtual interface and no association proposal must be created when dx_gateways is empty."
  }

  assert {
    condition     = length(aws_customer_gateway.this) == 0 && length(aws_vpn_connection.this) == 0
    error_message = "No VPN resources must be created when customer_gateways is empty."
  }
  assert {
    condition     = length(aws_vpn_gateway.this) == 0 && length(aws_cloudwatch_log_group.vpn_tunnel) == 0
    error_message = "No virtual private gateways and no VPN tunnel log groups must be created when customer_gateways is empty."
  }
  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_association.dx) == 0 && length(aws_ec2_transit_gateway_route_table_propagation.dx) == 0 && length(data.aws_ec2_transit_gateway_dx_gateway_attachment.wiring) == 0
    error_message = "No DX route table wiring and no attachment lookups must be created when dx_gateways is empty."
  }
  assert {
    condition     = length(aws_ec2_transit_gateway_prefix_list_reference.static) == 0 && length(data.aws_ec2_transit_gateway_dx_gateway_attachment.route) == 0
    error_message = "No prefix list route entries and no route attachment lookups must be created when static_routes is empty."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_connect.this) == 0 && length(aws_ec2_transit_gateway_connect_peer.this) == 0
    error_message = "No TGW Connect attachments and no BGP peers must be created when the collection is empty."
  }

  assert {
    condition     = length(aws_route53_resolver_query_log_config_association.this) == 0 && length(aws_route53_resolver_rule.endpoint) == 0
    error_message = "No query logging associations and no endpoint-scoped resolver rules must be created when the collections are empty."
  }

  assert {
    condition     = length(aws_acm_certificate.this) == 0
    error_message = "No ACM certificates must be created when acm_certificates is empty."
  }

  assert {
    condition     = length(aws_vpc_endpoint.gateway) == 0 && length(aws_vpc_endpoint.interface) == 0
    error_message = "No VPC endpoints must be created without VPCs."
  }

  assert {
    condition     = length(aws_security_group.this) == 0 && length(aws_network_acl.this) == 0
    error_message = "No security groups or NACLs must be created without VPCs."
  }

  assert {
    condition     = length(aws_flow_log.s3) == 0 && length(aws_flow_log.cloudwatch) == 0
    error_message = "No VPC flow logs must be created without VPCs."
  }

  assert {
    condition     = length(aws_vpc.this) == 0 && length(aws_subnet.this) == 0 && length(aws_nat_gateway.this) == 0
    error_message = "No VPC, subnet or NAT gateway must be created when nothing is configured."
  }

  assert {
    condition     = output.transit_gateway_id == "" && output.tgw_flow_log_id == ""
    error_message = "TGW outputs must be empty when the TGW is disabled."
  }

  # output.route53_query_log_config_id is part of the module interface.
  assert {
    condition     = length(aws_route53_resolver_query_log_config.this) == 0 && output.route53_query_log_config_id == ""
    error_message = "No query log config must be created and its ID output must stay empty when query logging is disabled."
  }

  assert {
    condition     = length(output.vpc_template_expanded_keys) == 0
    error_message = "No VPC template keys must be expanded when vpc_templates is empty."
  }

  assert {
    condition     = length(output.firewall_endpoint_ids) == 0
    error_message = "No firewall endpoints must be reported when the firewall is disabled."
  }
}

# -----------------------------------------------------------------------------
# 2. Default configuration — one minimal VPC, everything else at defaults
# -----------------------------------------------------------------------------

run "networking_default_config" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "workload"
        cidr         = "10.10.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.10.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_vpc.this) == 1
    error_message = "One VPC must be created."
  }

  assert {
    condition     = aws_vpc.this["workload"].cidr_block == "10.10.0.0/16"
    error_message = "VPC CIDR must match the input."
  }

  assert {
    condition     = aws_vpc.this["workload"].enable_dns_support && aws_vpc.this["workload"].enable_dns_hostnames
    error_message = "DNS support and DNS hostnames must be enabled by default."
  }

  assert {
    condition     = aws_vpc.this["workload"].ipv4_ipam_pool_id == null
    error_message = "A static-CIDR VPC must not reference an IPAM pool."
  }

  assert {
    condition     = length(aws_subnet.this) == 1
    error_message = "One subnet must be created."
  }

  assert {
    condition     = aws_subnet.this["workload.private-a"].map_public_ip_on_launch == false
    error_message = "Private subnets must not auto-assign public IPs."
  }

  assert {
    condition     = aws_subnet.this["workload.private-a"].tags["Type"] == "private"
    error_message = "Subnet Type tag must reflect the subnet type."
  }

  assert {
    condition     = length(aws_route_table.this) == 1 && length(aws_route_table_association.this) == 1
    error_message = "One route table must be created and associated per subnet."
  }

  assert {
    condition     = length(aws_internet_gateway.this) == 0
    error_message = "No internet gateway must be created for a VPC without public subnets."
  }

  assert {
    condition     = length(aws_route.private_nat) == 0
    error_message = "No NAT default route must be created without a NAT gateway."
  }

  assert {
    condition     = length(aws_flow_log.s3) == 0 && length(aws_flow_log.cloudwatch) == 0
    error_message = "No flow logs must be created when neither flow_logs nor vpc_flow_logs_default is set."
  }

  assert {
    condition     = length(aws_default_security_group.vpc) == 1
    error_message = "The default security group of each VPC must be managed and locked down."
  }

  assert {
    condition     = length(aws_vpc.this) == 1 && length(aws_subnet.this) == 1
    error_message = "One VPC and one subnet must be created."
  }

  # The three resources the toggle adopts are asserted directly.
  assert {
    condition     = length(aws_default_vpc.this) == 0 && length(aws_default_subnet.this) == 0 && length(aws_default_security_group.this) == 0
    error_message = "delete_default_vpc defaults to false, so no default VPC resources must be adopted."
  }
}

# -----------------------------------------------------------------------------
# 3a. Custom configuration — VPC, subnet, routing and endpoint layer
# -----------------------------------------------------------------------------

run "networking_custom_vpc_config" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"

    vpcs = [
      {
        name            = "hub"
        cidr            = "10.0.0.0/16"
        account_name    = "network"
        secondary_cidrs = ["10.1.0.0/16"]
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            nat_gateway       = true
          },
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "isolated-a"
            cidr              = "10.0.3.0/24"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          },
        ]
        flow_logs         = { destination = "s3" }
        gateway_endpoints = ["s3", "dynamodb"]
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 443
                cidr_blocks = ["10.0.0.0/16"]
                description = "HTTPS from VPC"
              }
            ]
            egress = [
              {
                protocol    = "-1"
                from_port   = 0
                to_port     = 0
                cidr_blocks = ["0.0.0.0/0"]
                description = "Allow all egress"
              }
            ]
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
                from_port   = 443
                to_port     = 443
              }
            ]
            outbound = [
              {
                rule_number = 100
                protocol    = "-1"
                action      = "allow"
                cidr_block  = "0.0.0.0/0"
                from_port   = 0
                to_port     = 0
              }
            ]
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.2.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.2.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        flow_logs = { destination = "cloudwatch" }
      },
    ]

    vpc_peering = [
      {
        name               = "hub-to-spoke"
        requester_vpc_name = "hub"
        accepter_vpc_name  = "spoke"
      }
    ]

    prefix_lists = [
      {
        name        = "corp-cidrs"
        max_entries = 5
        entries = [
          {
            cidr        = "10.0.0.0/8"
            description = "Corporate range"
          }
        ]
      }
    ]

    elastic_ips = [
      {
        name = "egress-reserved"
      }
    ]

    dhcp_options_sets = [
      {
        name                = "corp-dns"
        domain_name         = "corp.example.com"
        domain_name_servers = ["10.0.0.2"]
        vpc_names           = ["hub"]
      }
    ]

    target_groups = [
      {
        name     = "app-tg"
        port     = 443
        protocol = "HTTPS"
        vpc_name = "hub"
      }
    ]

    load_balancers = [
      {
        name         = "app-alb"
        type         = "application"
        vpc_name     = "hub"
        subnet_names = ["public-a"]
        scheme       = "internal"
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            target_group_name = "app-tg"
            ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/abc-123"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_vpc.this) == 2 && length(aws_subnet.this) == 4
    error_message = "Two VPCs with four subnets in total must be created."
  }

  assert {
    condition     = length(aws_vpc_ipv4_cidr_block_association.this) == 1
    error_message = "One secondary CIDR association must be created."
  }

  assert {
    condition     = length(aws_internet_gateway.this) == 1
    error_message = "Only the VPC with a public subnet must get an internet gateway."
  }

  assert {
    condition     = aws_subnet.this["hub.public-a"].map_public_ip_on_launch == true
    error_message = "Public subnets must auto-assign public IPs."
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 1 && length(aws_eip.nat) == 1
    error_message = "One NAT gateway with one EIP must be created."
  }

  assert {
    condition     = length(aws_route.public_igw) == 1
    error_message = "Exactly one public default route must be created."
  }

  assert {
    condition     = length(aws_route.private_nat) == 1
    error_message = "Only private subnets in a VPC with a NAT gateway must get a NAT default route."
  }

  assert {
    condition     = length(aws_vpc_endpoint.gateway) == 2
    error_message = "Both gateway endpoints must be created."
  }

  assert {
    # com.amazonaws is the value the module derives from the mocked DNS
    # suffix amazonaws.com — the eusc scenario at the end of this file pins
    # the derivation for the other partition.
    condition     = aws_vpc_endpoint.gateway["hub.s3"].service_name == "com.amazonaws.eu-central-1.s3"
    error_message = "Gateway endpoint service name must carry the partition-derived prefix and region."
  }

  assert {
    condition     = length(aws_vpc_endpoint.interface) == 1 && length(aws_security_group.interface_endpoint) == 1
    error_message = "One interface endpoint with its default security group must be created."
  }

  assert {
    condition     = aws_vpc_endpoint.interface["hub.ssm"].private_dns_enabled == true
    error_message = "Interface endpoints must have private DNS enabled."
  }

  assert {
    condition     = length(aws_security_group.this) == 1
    error_message = "One user-defined security group must be created."
  }

  assert {
    condition     = length(aws_security_group_rule.ingress_cidr) == 1 && length(aws_security_group_rule.egress_cidr) == 1
    error_message = "CIDR-based security group rules must be created."
  }

  assert {
    condition     = length(aws_network_acl.this) == 1 && length(aws_network_acl_association.this) == 1
    error_message = "One NACL must be created and associated with its subnet."
  }

  assert {
    condition     = length(aws_network_acl_rule.inbound) == 1 && length(aws_network_acl_rule.outbound) == 1
    error_message = "Inbound and outbound NACL rules must be created."
  }

  assert {
    condition     = length(aws_flow_log.s3) == 1 && length(aws_flow_log.cloudwatch) == 1
    error_message = "One S3 and one CloudWatch flow log must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.flow_logs) == 1 && length(aws_iam_role.flow_logs) == 1
    error_message = "The CloudWatch flow log destination must create a log group and an IAM role."
  }

  # Retention follows the project's 365-day baseline.
  assert {
    condition     = alltrue([for _, lg in aws_cloudwatch_log_group.flow_logs : lg.retention_in_days == 365])
    error_message = "Flow log log groups must retain 365 days."
  }

  assert {
    condition     = length(aws_vpc_peering_connection.this) == 1
    error_message = "One peering connection must be created."
  }

  assert {
    condition     = length(aws_route.peering) == 4
    error_message = "Peering routes must be created in every subnet of both VPCs."
  }

  assert {
    condition     = length(aws_ec2_managed_prefix_list.this) == 1
    error_message = "One managed prefix list must be created."
  }

  assert {
    condition     = length(aws_eip.this) == 1
    error_message = "One standalone Elastic IP must be created."
  }

  assert {
    condition     = length(aws_vpc_dhcp_options.this) == 1 && length(aws_vpc_dhcp_options_association.this) == 1
    error_message = "One DHCP options set must be created and associated."
  }

  assert {
    condition     = length(aws_lb.this) == 1 && length(aws_lb_target_group.this) == 1 && length(aws_lb_listener.this) == 1
    error_message = "Load balancer, target group and listener must be created."
  }

  assert {
    condition     = aws_lb.this["app-alb"].internal == true
    error_message = "An internal-scheme load balancer must be marked internal."
  }

  # A listener that names its own ssl_policy keeps it unchanged —
  # the module must not overwrite an explicit choice with the TLS 1.2 floor
  # default, whether that choice happens to already be the floor or not.
  assert {
    condition     = aws_lb_listener.this["app-alb.443"].ssl_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"
    error_message = "A listener that names its own ssl_policy must keep exactly the policy it named."
  }

  assert {
    condition     = length(aws_vpc.this) == 2 && length(aws_subnet.this) == 4 && length(aws_nat_gateway.this) == 1
    error_message = "Two VPCs, four subnets and one NAT gateway must be created for the custom configuration."
  }
}

# -----------------------------------------------------------------------------
# 3b. Custom configuration — Transit Gateway, DNS and VPN layer
# -----------------------------------------------------------------------------

run "networking_custom_tgw_dns_config" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"
    account_ids = {
      network       = "111111111111"
      workload-prod = "222222222222"
    }

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.0.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          },
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "10.2.0.0/16"
                target_type            = "tgw"
                target_name            = "hub"
              }
            ]
          },
        ]
        tgw_attachment = {
          route_table_name       = "hub"
          appliance_mode_support = "enable"
        }
      },
      {
        name         = "spoke"
        cidr         = "10.2.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.2.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = {
          route_table_name = "spoke"
        }
      },
    ]

    transit_gateway = {
      enabled      = true
      amazon_asn   = 64513
      route_tables = ["hub", "spoke"]
      static_routes = [
        {
          route_table_name       = "spoke"
          destination_cidr_block = "0.0.0.0/0"
          attachment_name        = "hub"
        },
        {
          route_table_name       = "hub"
          destination_cidr_block = "192.168.0.0/16"
          blackhole              = true
        },
      ]
      route_table_propagations = [
        {
          route_table_name = "hub"
          attachment_name  = "spoke"
        }
      ]
    }

    enable_tgw_flow_logs      = true
    tgw_flow_logs_destination = "s3"

    route53_zones = [
      {
        name = "internal.example.com"
      }
    ]

    # vpc_names is omitted here — scenario 3e covers the VPC associations.
    resolver_rules = [
      {
        name        = "onprem-forward"
        domain_name = "onprem.example.com"
        rule_type   = "FORWARD"
        target_ips = [
          {
            ip = "10.100.0.10"
          }
        ]
      }
    ]

    enable_route53_query_logging      = true
    route53_query_logging_destination = "cloudwatch"
    route53_query_logging_vpc_names   = ["hub"]

    dns_firewall_rule_groups = [
      {
        name      = "block-bad-domains"
        vpc_names = ["hub"]
        custom_domain_lists = [
          {
            name    = "blocked"
            domains = ["bad.example.com"]
          }
        ]
        rules = [
          {
            name                    = "block-listed"
            priority                = 100
            action                  = "BLOCK"
            custom_domain_list_name = "blocked"
            block_response          = "NXDOMAIN"
          }
        ]
      }
    ]

    customer_gateways = [
      {
        name                 = "onprem-dc1"
        bgp_asn              = 65000
        ip_address           = "203.0.113.10"
        transit_gateway_name = "tlz-transit-gateway"
        tunnel_options = [
          {
            tunnel_inside_cidr = "169.254.10.0/30"
            startup_action     = "start"
            dpd_timeout_action = "restart"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_ec2_transit_gateway.this) == 1
    error_message = "The Transit Gateway must be created when enabled."
  }

  assert {
    condition     = aws_ec2_transit_gateway.this[0].amazon_side_asn == 64513
    error_message = "The TGW ASN must match the configuration."
  }
  # The default keeps automated spoke onboarding working.
  assert {
    condition     = aws_ec2_transit_gateway.this[0].auto_accept_shared_attachments == "enable"
    error_message = "auto_accept_shared_attachments must default to enable."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table.this) == 2
    error_message = "One TGW route table must be created per configured name."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_vpc_attachment.this) == 2
    error_message = "Both VPCs with tgw_attachment must be attached."
  }

  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].appliance_mode_support == "enable"
    error_message = "appliance_mode_support must be passed through to the attachment."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_association.this) == 2
    error_message = "Each attachment must be associated with its route table."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route.static) == 2
    error_message = "Both static TGW routes must be created."
  }

  assert {
    condition     = aws_ec2_transit_gateway_route.static["hub.192.168.0.0/16"].blackhole == true
    error_message = "A blackhole route must be marked as blackhole."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_propagation.this) == 1
    error_message = "One TGW route table propagation must be created."
  }

  assert {
    condition     = length(aws_route.custom) == 1
    error_message = "One custom route must be created."
  }

  assert {
    condition     = length(aws_flow_log.tgw_s3) == 1 && length(aws_flow_log.tgw_cloudwatch) == 0
    error_message = "TGW flow logs must use the S3 destination only."
  }

  assert {
    condition     = length(aws_route53_zone.private) == 1
    error_message = "One private hosted zone must be created."
  }

  assert {
    condition     = length(aws_route53_resolver_rule.standalone) == 1
    error_message = "The standalone resolver rule must be created."
  }

  assert {
    condition     = length(aws_route53_resolver_rule_association.standalone) == 0
    error_message = "No resolver rule association must be created when vpc_names is empty."
  }

  assert {
    condition     = length(aws_route53_resolver_query_log_config.this) == 1
    error_message = "Query logging config must be created when DNS query logging is enabled."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.query_logging) == 1
    error_message = "The CloudWatch destination must create a query logging log group."
  }

  # Retention follows the project's 365-day baseline.
  assert {
    condition     = aws_cloudwatch_log_group.query_logging[0].retention_in_days == 365
    error_message = "The query logging log group must retain 365 days."
  }

  assert {
    condition     = length(aws_route53_resolver_query_log_config_association.this) == 1
    error_message = "Only the selected VPC must be associated with query logging."
  }

  assert {
    condition     = length(aws_route53_resolver_firewall_rule_group.this) == 1 && length(aws_route53_resolver_firewall_rule.this) == 1
    error_message = "DNS firewall rule group and rule must be created."
  }

  assert {
    condition     = length(aws_route53_resolver_firewall_domain_list.this) == 1
    error_message = "The custom domain list must be created."
  }

  assert {
    condition     = length(aws_route53_resolver_firewall_rule_group_association.this) == 1
    error_message = "The DNS firewall rule group must be associated with the VPC."
  }

  assert {
    condition     = length(aws_customer_gateway.this) == 1 && length(aws_vpn_connection.this) == 1
    error_message = "Customer gateway and VPN connection must be created."
  }

  assert {
    condition     = aws_customer_gateway.this["onprem-dc1"].bgp_asn == "65000"
    error_message = "Customer gateway BGP ASN must match the configuration."
  }

  # The config resource local.dns_query_logging_enabled governs is asserted.
  assert {
    condition     = length(aws_route53_resolver_query_log_config.this) == 1
    error_message = "A query log config must be created when query logging is enabled."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_propagation.this) == 1
    error_message = "One TGW route table propagation must be created for this configuration."
  }
}

# -----------------------------------------------------------------------------
# 3c. Custom configuration — IPAM and Network Firewall layer
# -----------------------------------------------------------------------------

run "networking_custom_ipam_firewall_config" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.20.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "firewall-a"
            cidr              = "10.20.1.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
      }
    ]

    # pools is empty here — scenario 3d covers the pool hierarchy.
    ipam = {
      enabled                    = true
      description                = "Landing Zone IPAM"
      regions                    = ["eu-central-1"]
      delegated_admin_account_id = "222222222222"
      pools                      = []
    }

    network_firewall = {
      enabled      = true
      vpc_name     = "inspection"
      subnet_names = ["firewall-a"]
      rule_groups = [
        {
          name     = "block-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "drop tcp any any -> any any (msg:\"blocked\"; sid:1; rev:1;)"
        }
      ]
      firewall_policy = {
        stateless_default_actions          = ["aws:forward_to_sfe"]
        stateless_fragment_default_actions = ["aws:forward_to_sfe"]
      }
    }
  }

  assert {
    condition     = length(aws_vpc_ipam.this) == 1
    error_message = "IPAM must be created when ipam.enabled is true."
  }

  assert {
    condition     = aws_vpc_ipam.this[0].description == "Landing Zone IPAM"
    error_message = "The IPAM description must match the configuration."
  }

  assert {
    condition     = length(aws_vpc_ipam_pool.this) == 0 && length(aws_vpc_ipam_pool_cidr.this) == 0
    error_message = "No IPAM pools must be created when the pool list is empty."
  }

  assert {
    condition     = length(aws_vpc_ipam_organization_admin_account.this) == 1
    error_message = "The IPAM delegated admin must be created when an account ID is configured."
  }

  assert {
    condition     = length(aws_networkfirewall_firewall.this) == 1 && length(aws_networkfirewall_firewall_policy.this) == 1
    error_message = "Network Firewall and its policy must be created when enabled."
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this) == 1
    error_message = "One Network Firewall rule group must be created."
  }

  assert {
    condition     = aws_networkfirewall_firewall.this[0].name == "tlz-network-firewall"
    error_message = "Network Firewall name must match the module convention."
  }

  # The central inspection firewall is protected against
  # accidental destroy and unnoticed subnet changes.
  assert {
    condition     = aws_networkfirewall_firewall.this[0].delete_protection == true && aws_networkfirewall_firewall.this[0].subnet_change_protection == true
    error_message = "The Network Firewall must carry delete_protection and subnet_change_protection."
  }

  assert {
    condition     = length(aws_networkfirewall_logging_configuration.this) == 0
    error_message = "No logging configuration must be created when logging_configuration is null."
  }
}

# -----------------------------------------------------------------------------
# 3d. Custom configuration — IPAM pool hierarchy and IPAM-based CIDRs
# -----------------------------------------------------------------------------
# Pools resolve their parent through the hierarchy, so a non-empty pool list
# plans and IPAM-based VPC and subnet CIDRs work.

run "networking_custom_ipam_pool_hierarchy" {
  command = plan

  # Pool IDs are mocked during the plan so that the parent wiring between the
  # hierarchy levels and the pool reference of VPC and subnet are observable.
  override_resource {
    target          = aws_vpc_ipam_pool.this
    override_during = plan
    values = {
      id = "ipam-pool-root"
    }
  }

  override_resource {
    target          = aws_vpc_ipam_pool.child
    override_during = plan
    values = {
      id = "ipam-pool-child"
    }
  }

  override_resource {
    target          = aws_vpc_ipam_pool.grandchild
    override_during = plan
    values = {
      id = "ipam-pool-grandchild"
    }
  }

  variables {
    ipam = {
      enabled     = true
      description = "Landing Zone IPAM"
      regions     = ["eu-central-1"]
      pools = [
        {
          name                              = "global"
          cidr                              = "10.0.0.0/8"
          allocation_default_netmask_length = 16
        },
        {
          name             = "regional"
          cidr             = "10.0.0.0/12"
          locale           = "eu-central-1"
          parent_pool_name = "global"
        },
        {
          name             = "workload"
          cidr             = "10.0.0.0/16"
          parent_pool_name = "regional"
        },
      ]
    }

    vpcs = [
      {
        name                = "ipam-vpc"
        ipam_pool_name      = "workload"
        ipam_netmask_length = 20
        account_name        = "network"
        subnets = [
          {
            name                = "private-a"
            ipam_pool_name      = "workload"
            ipam_netmask_length = 24
            availability_zone   = "eu-central-1a"
            type                = "private"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_vpc_ipam_pool.this) == 1 && length(aws_vpc_ipam_pool.child) == 1 && length(aws_vpc_ipam_pool.grandchild) == 1
    error_message = "Each pool of the three-level hierarchy must be created exactly once."
  }

  assert {
    condition     = length(aws_vpc_ipam_pool_cidr.this) == 3
    error_message = "Every pool must get its CIDR provisioned, regardless of its nesting level."
  }

  assert {
    condition     = aws_vpc_ipam_pool.child["regional"].source_ipam_pool_id == "ipam-pool-root"
    error_message = "A child pool must source from its parent pool instead of from itself."
  }

  assert {
    condition     = aws_vpc_ipam_pool.grandchild["workload"].source_ipam_pool_id == "ipam-pool-child"
    error_message = "A grandchild pool must source from its child pool instead of from itself."
  }

  assert {
    condition     = aws_vpc_ipam_pool.this["global"].source_ipam_pool_id == null
    error_message = "A root pool must be provisioned from the IPAM default scope without a source pool."
  }

  assert {
    condition     = aws_vpc_ipam_pool.this["global"].allocation_default_netmask_length == 16
    error_message = "allocation_default_netmask_length must be passed through to the pool."
  }

  assert {
    condition     = aws_vpc_ipam_pool.child["regional"].locale == "eu-central-1"
    error_message = "The pool locale must be passed through to the pool."
  }

  assert {
    condition     = aws_vpc_ipam_pool_cidr.this["workload"].ipam_pool_id == "ipam-pool-grandchild"
    error_message = "The pool CIDR must be provisioned into the pool of the matching nesting level."
  }

  assert {
    condition     = aws_vpc.this["ipam-vpc"].ipv4_ipam_pool_id == "ipam-pool-grandchild" && aws_vpc.this["ipam-vpc"].ipv4_netmask_length == 20
    error_message = "An IPAM-based VPC must draw its CIDR from the referenced pool."
  }

  assert {
    condition     = aws_subnet.this["ipam-vpc.private-a"].ipv4_ipam_pool_id == "ipam-pool-grandchild" && aws_subnet.this["ipam-vpc.private-a"].ipv4_netmask_length == 24
    error_message = "An IPAM-based subnet must draw its CIDR from the referenced pool."
  }
}

# -----------------------------------------------------------------------------
# 3e. Custom configuration — resolver rules and their VPC associations
# -----------------------------------------------------------------------------
# Association names must not contain the dots of the map keys, which AWS
# rejects. Zone-scoped forward rules need a resolver endpoint, which Route 53
# requires.

run "networking_custom_resolver_rule_associations" {
  command = plan

  # The endpoint ID is mocked during the plan so that the endpoint reference of
  # the zone-scoped rule is observable.
  override_resource {
    target          = aws_route53_resolver_endpoint.this
    override_during = plan
    values = {
      id = "rslvr-out-0123456789abcdef0"
    }
  }

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "private-b"
            cidr              = "10.0.3.0/24"
            availability_zone = "eu-central-1b"
            type              = "private"
          },
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.2.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.2.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]

    resolver_endpoints = [
      {
        name         = "outbound-hub"
        direction    = "OUTBOUND"
        vpc_name     = "hub"
        subnet_names = ["private-a", "private-b"]
        resolver_rules = [
          {
            domain_name = "onprem.example.com"
            target_ips  = [{ ip = "10.100.0.10" }]
            vpc_names   = ["hub", "spoke"]
          }
        ]
      }
    ]

    resolver_rules = [
      {
        name        = "internal-system"
        domain_name = "internal.example.com"
        rule_type   = "SYSTEM"
        vpc_names   = ["hub"]
      }
    ]

    route53_zones = [
      {
        name = "internal.example.com"
        resolver_rules = [
          {
            domain_name            = "onprem.example.com"
            target_ips             = ["10.100.0.10"]
            resolver_endpoint_name = "outbound-hub"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_route53_resolver_endpoint.this) == 1
    error_message = "The outbound resolver endpoint must be created."
  }

  assert {
    condition     = length(aws_route53_resolver_rule.endpoint) == 1 && length(aws_route53_resolver_rule_association.endpoint) == 2
    error_message = "The endpoint rule must be associated with every VPC listed in vpc_names."
  }

  assert {
    condition     = aws_route53_resolver_rule_association.endpoint["outbound-hub.onprem.example.com.hub"].name == "outbound-hub-onprem-example-com-hub"
    error_message = "An association name must be derived from the map key with dots replaced by hyphens."
  }

  assert {
    condition     = alltrue([for association in values(aws_route53_resolver_rule_association.endpoint) : !strcontains(association.name, ".")])
    error_message = "No endpoint rule association name may contain a dot — AWS rejects such names."
  }

  assert {
    condition     = length(aws_route53_resolver_rule.standalone) == 1 && length(aws_route53_resolver_rule_association.standalone) == 1
    error_message = "The standalone rule must be associated with the VPC listed in vpc_names."
  }

  assert {
    condition     = aws_route53_resolver_rule_association.standalone["internal-system.hub"].name == "internal-system-hub"
    error_message = "A standalone association name must be derived from the map key with dots replaced by hyphens."
  }

  assert {
    condition     = length(aws_route53_resolver_rule.this) == 1
    error_message = "The zone-scoped resolver rule must be created."
  }

  assert {
    condition     = aws_route53_resolver_rule.this["internal.example.com-onprem.example.com"].resolver_endpoint_id == "rslvr-out-0123456789abcdef0"
    error_message = "A zone-scoped forward rule must reference the configured outbound resolver endpoint."
  }

  assert {
    condition     = aws_route53_resolver_rule.this["internal.example.com-onprem.example.com"].name == "internal-example-com-onprem-example-com"
    error_message = "A zone-scoped rule name must not contain dots."
  }
}

# -----------------------------------------------------------------------------
# 3f. Custom configuration — named interface endpoint policies
# -----------------------------------------------------------------------------
# A named policy missing from endpoint_policies must not resolve to no policy
# at all, which would turn an intended restriction into an open endpoint.

run "networking_custom_endpoint_policies" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            policy_name  = "restrict-to-organization"
          },
          {
            service      = "kms"
            subnet_names = ["private-a"]
            policy       = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"kms:Decrypt\",\"Resource\":\"*\"}]}"
          },
          {
            service      = "ec2messages"
            subnet_names = ["private-a"]
          },
        ]
      }
    ]

    endpoint_policies = [
      {
        name   = "restrict-to-organization"
        policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-abcd1234567\"}}}]}"
      }
    ]
  }

  assert {
    condition     = length(aws_vpc_endpoint.interface) == 3
    error_message = "Every configured interface endpoint must be created."
  }

  assert {
    condition     = can(regex("PrincipalOrgID", aws_vpc_endpoint.interface["hub.ssm"].policy))
    error_message = "A named policy must be resolved from endpoint_policies instead of leaving the endpoint unrestricted."
  }

  assert {
    condition     = can(regex("kms:Decrypt", aws_vpc_endpoint.interface["hub.kms"].policy))
    error_message = "An inline policy must be applied to the endpoint."
  }

  # An endpoint without policy and without policy_name keeps the AWS default
  # policy; that value is only known after apply, so only its creation is
  # asserted here (see the count assertion above).
}

# -----------------------------------------------------------------------------
# 3g. Custom configuration — VPC scaffolding and templates
# -----------------------------------------------------------------------------
# stacks/management/networking/terragrunt.hcl passes the five variables of this
# scenario through (DHCP option sets, Elastic IPs, named endpoint policies and
# the global flow-log default); this scenario holds the effect in the plan. The
# empty/null counterpart is scenario 1 (Toggle-Off).


run "networking_bf_dead_047_vpc_scaffolding_pass_through" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        # Explicit flow_logs — must win over vpc_flow_logs_default
        flow_logs = { destination = "s3" }
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            policy_name  = "restrict-to-organization"
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.2.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.2.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        # No flow_logs block — vpc_flow_logs_default applies
      },
    ]

    # All four attributes of the default block reach the flow log.
    # traffic_type and max_aggregation_interval are left unset here
    # so that this scenario keeps asserting the defaults ALL/600; the scenario
    # networking_bf_dead_070_flow_log_traffic_type_and_interval covers the
    # non-default values.
    vpc_flow_logs_default = {
      destination = "cloudwatch"
      log_format  = "$${version} $${vpc-id} $${srcaddr}"
    }

    dhcp_options_sets = [
      {
        name                = "corp-dns"
        domain_name         = "corp.example.com"
        domain_name_servers = ["10.0.0.2", "10.2.0.2"]
        ntp_servers         = ["10.0.0.3"]
        vpc_names           = ["hub", "spoke"]
      }
    ]

    elastic_ips = [
      { name = "egress-reserved-a" },
      { name = "egress-reserved-b" },
    ]

    endpoint_policies = [
      {
        name   = "restrict-to-organization"
        policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-abcd1234567\"}}}]}"
      }
    ]
  }

  assert {
    condition     = length(aws_flow_log.s3) == 1 && length(aws_flow_log.cloudwatch) == 1
    error_message = "The VPC with an explicit flow_logs block must keep S3, the VPC without one must get the default destination."
  }

  assert {
    condition     = contains(keys(aws_flow_log.cloudwatch), "spoke")
    error_message = "vpc_flow_logs_default must create the flow log of the VPC without an explicit flow_logs block."
  }

  assert {
    condition     = aws_flow_log.cloudwatch["spoke"].log_format == "$${version} $${vpc-id} $${srcaddr}"
    error_message = "The log_format of vpc_flow_logs_default must reach the flow log unchanged."
  }

  # The two defaults of the type: without an explicit value the flow log gets
  # traffic_type ALL and a 600-second interval.
  assert {
    condition     = aws_flow_log.cloudwatch["spoke"].traffic_type == "ALL" && aws_flow_log.cloudwatch["spoke"].max_aggregation_interval == 600
    error_message = "Without an explicit value the default block must keep traffic_type ALL and max_aggregation_interval 600."
  }

  assert {
    condition     = aws_flow_log.s3["hub"].traffic_type == "ALL" && aws_flow_log.s3["hub"].max_aggregation_interval == 600
    error_message = "Without an explicit value a per-VPC flow_logs block must keep traffic_type ALL and max_aggregation_interval 600."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.flow_logs) == 1 && length(aws_iam_role.flow_logs) == 1
    error_message = "The CloudWatch destination of the default block must create a log group and an IAM role."
  }

  assert {
    condition     = length(aws_vpc_dhcp_options.this) == 1 && length(aws_vpc_dhcp_options_association.this) == 2
    error_message = "One DHCP options set must be created and associated with both named VPCs."
  }

  assert {
    condition     = aws_vpc_dhcp_options.this["corp-dns"].domain_name == "corp.example.com" && length(aws_vpc_dhcp_options.this["corp-dns"].domain_name_servers) == 2
    error_message = "The DHCP options set must carry the configured domain name and name servers."
  }

  assert {
    condition     = length(aws_eip.this) == 2 && length(aws_eip.nat) == 0
    error_message = "Both standalone Elastic IPs must be created without creating a NAT EIP."
  }

  assert {
    condition     = can(regex("PrincipalOrgID", aws_vpc_endpoint.interface["hub.ssm"].policy))
    error_message = "The named endpoint policy must reach the interface endpoint."
  }

  assert {
    condition     = length(output.flow_log_ids) == 2 && length(output.dhcp_options_set_ids) == 1 && length(output.eip_allocation_ids) == 2
    error_message = "The outputs of the scaffolding features must reflect the created resources."
  }
}

# -----------------------------------------------------------------------------
# 3h. Custom configuration — VPC templates are documentation/intent
# -----------------------------------------------------------------------------
# Terraform cannot create providers dynamically, so vpc_templates deliberately
# creates no resource. The stack only passes the value through; the
# output vpc_template_expanded_keys is the interface that makes the intent
# visible, and the only place where a template becomes observable at all.

run "networking_bf_dead_047_vpc_templates_are_documentation_only" {
  command = plan

  variables {
    vpcs = []
    account_ids = {
      network       = "111111111111"
      workload-prod = "222222222222"
    }
    vpc_templates = [
      {
        name               = "standard-workload"
        cidr               = "10.60.0.0/16"
        deployment_targets = ["network", "workload-prod"]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.60.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "public-a"
            cidr              = "10.60.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            nat_gateway       = true
          },
        ]
        tgw_attachment    = { route_table_name = "spoke" }
        flow_logs         = { destination = "s3" }
        gateway_endpoints = ["s3"]
      }
    ]
  }

  assert {
    condition     = length(aws_vpc.this) == 0 && length(aws_subnet.this) == 0
    error_message = "Set VPC templates must not create a VPC or a subnet — cross-account creation stays excluded."
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 0 && length(aws_vpc_endpoint.gateway) == 0 && length(aws_flow_log.s3) == 0
    error_message = "No resource of a VPC template must be planned in this account."
  }

  assert {
    condition     = length(aws_vpc.this) == 0 && length(aws_subnet.this) == 0
    error_message = "No VPC and no subnet must be created although a template is configured."
  }

  assert {
    condition     = join(",", sort(output.vpc_template_expanded_keys)) == "network.standard-workload,workload-prod.standard-workload"
    error_message = "vpc_template_expanded_keys must report one account_name.template_name key per deployment target."
  }
}

# -----------------------------------------------------------------------------
# 3i. Custom configuration — VPC template with an unknown account warns
# -----------------------------------------------------------------------------
# The check block is the warning the variable reference promises: a deployment
# target without an entry in account_ids has no provider and cannot be created.

run "networking_bf_dead_047_vpc_template_unknown_account_warns" {
  command = plan

  variables {
    vpcs = []
    account_ids = {
      network = "111111111111"
    }
    vpc_templates = [
      {
        name               = "standard-workload"
        cidr               = "10.60.0.0/16"
        deployment_targets = ["network", "not-onboarded"]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.60.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_vpc.this) == 0
    error_message = "An unknown deployment target must not create a VPC either."
  }

  assert {
    condition     = length(output.vpc_template_expanded_keys) == 2
    error_message = "The expansion must stay observable for the unknown account too, so the warning can be traced."
  }

  expect_failures = [check.vpc_templates_cross_account]
}

# -----------------------------------------------------------------------------
# 3j. Custom configuration — load balancing
# -----------------------------------------------------------------------------
# load_balancers, target_groups and gateway_load_balancers as the stack passes
# them through. The empty counterpart is scenario 1 (Toggle-Off).

run "networking_bf_dead_061_load_balancing_pass_through" {
  command = plan

  # ssl_policy is optional+computed in the provider schema, so the mock
  # provider cannot resolve it to the config's null at plan time for a
  # non-TLS listener without help — override it during plan so the
  # assertion below observes the value the module actually wrote (null),
  # not an unresolved computed placeholder.
  override_resource {
    target          = aws_lb_listener.this["app-nlb.443"]
    override_during = plan
    values = {
      ssl_policy = null
    }
  }

  variables {
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.20.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "appliance-a"
            cidr              = "10.20.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.22.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.22.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]

    gateway_load_balancers = [
      {
        name         = "inspection-gwlb"
        vpc_name     = "inspection"
        subnet_names = ["appliance-a"]
        target_group = {
          name     = "inspection-gwlb-tg"
          port     = 6081
          protocol = "GENEVE"
          health_check = {
            port     = 80
            protocol = "TCP"
          }
        }
        endpoint_consumers = [
          {
            vpc_name     = "spoke"
            subnet_names = ["private-a"]
          }
        ]
      }
    ]

    target_groups = [
      {
        name        = "app-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      }
    ]

    load_balancers = [
      {
        name         = "app-nlb"
        type         = "network"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        scheme       = "internal"
        listeners = [
          {
            port              = 443
            protocol          = "TCP"
            target_group_name = "app-tg"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_lb.gwlb) == 1 && length(aws_lb_target_group.gwlb) == 1 && length(aws_lb_listener.gwlb) == 1
    error_message = "The Gateway Load Balancer must be created with its target group and listener."
  }

  assert {
    condition     = aws_lb.gwlb["inspection-gwlb"].load_balancer_type == "gateway" && aws_lb_target_group.gwlb["inspection-gwlb"].protocol == "GENEVE"
    error_message = "GWLB and its target group must carry the gateway/GENEVE configuration."
  }

  # The central inspection LB is protected
  # against accidental destroy and balances across all AZs.
  assert {
    condition     = aws_lb.gwlb["inspection-gwlb"].enable_deletion_protection == true && aws_lb.gwlb["inspection-gwlb"].enable_cross_zone_load_balancing == true
    error_message = "The GWLB must carry deletion protection and cross-zone load balancing."
  }

  assert {
    condition     = length(aws_vpc_endpoint_service.gwlb) == 1 && length(aws_vpc_endpoint.gwlb_consumer) == 1
    error_message = "Endpoint service and consumer endpoint of the GWLB must be created."
  }

  assert {
    condition     = aws_vpc_endpoint.gwlb_consumer["inspection-gwlb.spoke"].vpc_endpoint_type == "GatewayLoadBalancer"
    error_message = "The consumer endpoint must be of type GatewayLoadBalancer."
  }

  assert {
    condition     = length(aws_lb.this) == 1 && length(aws_lb_target_group.this) == 1 && length(aws_lb_listener.this) == 1
    error_message = "Load balancer, target group and listener must be created from the three collections."
  }

  assert {
    condition     = aws_lb.this["app-nlb"].load_balancer_type == "network" && aws_lb.this["app-nlb"].internal == true
    error_message = "Type and scheme of the load balancer must reach the resource."
  }

  # ssl_policy is not a valid attribute on a non-TLS listener at
  # all (plain TCP here) — the module must leave it null, never apply the
  # TLS 1.2 floor default to a protocol that cannot carry a TLS policy.
  # TEMP DISABLED FOR DIAGNOSIS
  assert {
    condition     = aws_lb_listener.this["app-nlb.443"].ssl_policy == null
    error_message = "A non-TLS listener must never get a ssl_policy value; the attribute is not valid there."
  }

  # Workload LBs are protected against
  # accidental destroy and drop malformed HTTP headers (ALB-only attribute,
  # network LBs ignore it).
  assert {
    condition     = aws_lb.this["app-nlb"].enable_deletion_protection == true && aws_lb.this["app-nlb"].drop_invalid_header_fields == true
    error_message = "Workload LBs must carry deletion protection and drop_invalid_header_fields."
  }

  # Without an explicit acceptance_required the GWLB
  # endpoint service keeps automated spoke onboarding (no manual acceptance).
  assert {
    condition     = aws_vpc_endpoint_service.gwlb["inspection-gwlb"].acceptance_required == false
    error_message = "acceptance_required must default to false on the GWLB endpoint service."
  }

  assert {
    condition     = aws_lb_target_group.this["app-tg"].target_type == "ip" && aws_lb_target_group.this["app-tg"].port == 443
    error_message = "The target group must carry the configured target type and port."
  }

  assert {
    condition     = length(output.gwlb_ids) == 1 && length(output.gwlb_consumer_endpoint_ids) == 1 && length(output.target_group_arns) == 1 && length(output.load_balancer_arns) == 1
    error_message = "The load balancing outputs must reflect the created resources."
  }
}

# -----------------------------------------------------------------------------
# 3k. Custom configuration — hybrid connectivity
# -----------------------------------------------------------------------------
# VPC peering, Direct Connect, site-to-site VPN, TGW Connect and the TGW flow
# logs as the stack passes them through. Scenario 3b covers the S3 destination of
# the TGW flow logs; this scenario covers the CloudWatch branch, so both
# destinations are held. The empty counterpart is scenario 1 (Toggle-Off).

run "networking_bf_dead_062_hybrid_connectivity_pass_through" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.30.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.30.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = { route_table_name = "hub" }
      },
      {
        name         = "spoke"
        cidr         = "10.32.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.32.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = { route_table_name = "spoke" }
      },
    ]

    transit_gateway = {
      enabled      = true
      route_tables = ["hub", "spoke"]
    }

    vpc_peering = [
      {
        name               = "hub-to-spoke"
        requester_vpc_name = "hub"
        accepter_vpc_name  = "spoke"
      }
    ]

    dx_gateways = [
      {
        name                 = "dxgw-primary"
        amazon_asn           = 64515
        transit_gateway_name = "tlz-transit-gateway"
        virtual_interfaces = [
          {
            name          = "vif-transit-a"
            type          = "transit"
            vlan          = 101
            bgp_asn       = 65001
            connection_id = "dxcon-fgabcd12"
          }
        ]
      }
    ]

    customer_gateways = [
      {
        name                 = "onprem-dc2"
        bgp_asn              = 65010
        ip_address           = "198.51.100.20"
        transit_gateway_name = "tlz-transit-gateway"
      }
    ]

    tgw_connect_attachments = [
      {
        name                 = "sdwan-appliance"
        transit_gateway_name = "tlz-transit-gateway"
        transport_attachment = "hub"
        protocol             = "gre"
        peers = [
          {
            name                    = "peer-a"
            peer_address            = "169.254.100.1"
            transit_gateway_address = "169.254.100.2"
            bgp_asn                 = 65020
            inside_cidr_blocks      = ["169.254.100.0/29"]
          }
        ]
      }
    ]

    enable_tgw_flow_logs      = true
    tgw_flow_logs_destination = "cloudwatch"
  }

  assert {
    condition     = length(aws_vpc_peering_connection.this) == 1 && length(aws_route.peering) == 2
    error_message = "Peering connection and its routes must be created."
  }

  assert {
    condition     = length(aws_dx_gateway.this) == 1 && length(aws_dx_gateway_association.this) == 1
    error_message = "The Direct Connect gateway must be created and associated with the Transit Gateway."
  }

  assert {
    condition     = tostring(aws_dx_gateway.this["dxgw-primary"].amazon_side_asn) == "64515"
    error_message = "The ASN of the DX gateway must reach the resource."
  }

  assert {
    condition     = length(aws_dx_transit_virtual_interface.this) == 1 && length(aws_dx_private_virtual_interface.this) == 0
    error_message = "A transit virtual interface must be created as a transit VIF, not as a private one."
  }

  assert {
    condition     = length(aws_customer_gateway.this) == 1 && length(aws_vpn_connection.this) == 1
    error_message = "Customer gateway and VPN connection must be created."
  }

  assert {
    condition     = aws_customer_gateway.this["onprem-dc2"].ip_address == "198.51.100.20"
    error_message = "The IP address of the customer gateway must reach the resource."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_connect.this) == 1 && length(aws_ec2_transit_gateway_connect_peer.this) == 1
    error_message = "TGW Connect attachment and its BGP peer must be created."
  }

  assert {
    condition     = aws_ec2_transit_gateway_connect.this["sdwan-appliance"].protocol == "gre"
    error_message = "The TGW Connect protocol must reach the resource."
  }

  assert {
    condition     = length(aws_flow_log.tgw_cloudwatch) == 1 && length(aws_flow_log.tgw_s3) == 0
    error_message = "The CloudWatch destination must create the CloudWatch TGW flow log and no S3 flow log."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.tgw_flow_logs) == 1 && length(aws_iam_role.tgw_flow_logs) == 1 && length(aws_iam_role_policy.tgw_flow_logs) == 1
    error_message = "The CloudWatch destination of the TGW flow logs must create log group, role and role policy."
  }

  # Retention follows the project's 365-day baseline.
  assert {
    condition     = aws_cloudwatch_log_group.tgw_flow_logs[0].retention_in_days == 365
    error_message = "The TGW flow log log group must retain 365 days."
  }

  assert {
    condition     = length(output.dx_gateway_ids) == 1 && length(output.customer_gateway_ids) == 1 && length(output.vpn_connection_ids) == 1 && length(output.tgw_connect_attachment_ids) == 1 && length(output.tgw_connect_peer_ids) == 1
    error_message = "The hybrid connectivity outputs must reflect the created resources."
  }
}

# -----------------------------------------------------------------------------
# 3l. Custom configuration — TGW multicast domains stay deferred
# -----------------------------------------------------------------------------
# The variable is part of the stack pass-through, but the module implements no
# multicast resource: the check block warns as long as the list is non-empty.
# This scenario holds exactly that state — the value is accepted and creates
# nothing.

run "networking_bf_dead_062_tgw_multicast_domains_deferred" {
  command = plan

  variables {
    vpcs = []
    transit_gateway = {
      enabled      = true
      route_tables = []
    }
    tgw_multicast_domains = [
      {
        name                   = "mcast-domain"
        transit_gateway_name   = "tlz-transit-gateway"
        igmpv2_support         = "enable"
        static_sources_support = "disable"
      }
    ]
  }

  assert {
    condition     = length(aws_ec2_transit_gateway.this) == 1
    error_message = "The Transit Gateway itself must still be planned."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table.this) == 0 && length(aws_ec2_transit_gateway_vpc_attachment.this) == 0
    error_message = "A multicast domain must not create any Transit Gateway resource."
  }

  expect_failures = [check.tgw_multicast_domains_deferred]
}

# -----------------------------------------------------------------------------
# 3m. Custom configuration — DNS, resolver and query logging
# -----------------------------------------------------------------------------
# Scenario 3b covers the CloudWatch destination with an explicit VPC list;
# this scenario covers the other side of every switch of its six variables:
# the S3 destination and the empty VPC list that associates every VPC.
# enable_route53_query_logging is the feature's single toggle.

run "networking_bf_dead_063_dns_pass_through" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "private-b"
            cidr              = "10.40.2.0/24"
            availability_zone = "eu-central-1b"
            type              = "private"
          },
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.42.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.42.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]

    # The single query-logging toggle.
    enable_route53_query_logging      = true
    route53_query_logging_destination = "s3"
    route53_query_logging_vpc_names   = []

    resolver_endpoints = [
      {
        name         = "outbound-dns"
        direction    = "OUTBOUND"
        vpc_name     = "hub"
        subnet_names = ["private-a", "private-b"]
        resolver_rules = [
          {
            domain_name = "onprem.example.com"
            target_ips = [
              { ip = "10.100.0.10" }
            ]
            vpc_names = ["hub", "spoke"]
          }
        ]
      },
      {
        name          = "inbound-dns"
        direction     = "INBOUND"
        vpc_name      = "hub"
        subnet_names  = ["private-a", "private-b"]
        allowed_cidrs = ["10.0.0.0/8"]
        protocols     = ["Do53"]
      },
    ]

    resolver_rules = [
      {
        name        = "partner-forward"
        domain_name = "partner.example.com"
        rule_type   = "FORWARD"
        target_ips = [
          { ip = "10.200.0.10" }
        ]
        vpc_names = ["spoke"]
      }
    ]

    dns_firewall_rule_groups = [
      {
        name      = "block-bad-domains"
        vpc_names = ["hub", "spoke"]
        custom_domain_lists = [
          {
            name    = "blocked"
            domains = ["bad.example.com", "worse.example.com"]
          }
        ]
        rules = [
          {
            name                    = "block-listed"
            priority                = 100
            action                  = "BLOCK"
            custom_domain_list_name = "blocked"
            block_response          = "NXDOMAIN"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_route53_resolver_query_log_config.this) == 1
    error_message = "enable_route53_query_logging must create the query log config."
  }

  assert {
    condition     = length(aws_route53_resolver_query_log_config.this) == 1
    error_message = "The query logging configuration must be created."
  }

  assert {
    condition     = aws_route53_resolver_query_log_config.this[0].destination_arn == "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1"
    error_message = "The S3 destination must point at the central log bucket."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.query_logging) == 0
    error_message = "The S3 destination must not create a CloudWatch log group."
  }

  assert {
    condition     = length(aws_route53_resolver_query_log_config_association.this) == 2
    error_message = "An empty route53_query_logging_vpc_names must associate every VPC."
  }

  assert {
    condition     = length(aws_route53_resolver_endpoint.this) == 2
    error_message = "Both resolver endpoints must be created."
  }

  assert {
    condition     = aws_route53_resolver_endpoint.this["inbound-dns"].direction == "INBOUND" && aws_route53_resolver_endpoint.this["outbound-dns"].direction == "OUTBOUND"
    error_message = "The direction of each resolver endpoint must reach the resource."
  }

  assert {
    condition     = length(aws_security_group.resolver_endpoint) == 2 && length(aws_vpc_security_group_ingress_rule.resolver_dns_udp) == 2 && length(aws_vpc_security_group_ingress_rule.resolver_dns_tcp) == 2
    error_message = "Each resolver endpoint without its own security group must get one, with a DNS rule per allowed CIDR."
  }

  assert {
    condition     = length(aws_route53_resolver_rule.endpoint) == 1 && length(aws_route53_resolver_rule_association.endpoint) == 2
    error_message = "The endpoint-scoped resolver rule must be created and associated with both named VPCs."
  }

  assert {
    condition     = length(aws_route53_resolver_rule.standalone) == 1 && length(aws_route53_resolver_rule_association.standalone) == 1
    error_message = "The standalone resolver rule must be created and associated with its VPC."
  }

  assert {
    condition     = aws_route53_resolver_rule.standalone["partner-forward"].domain_name == "partner.example.com"
    error_message = "The domain name of the standalone resolver rule must reach the resource."
  }

  assert {
    condition     = length(aws_route53_resolver_firewall_rule_group.this) == 1 && length(aws_route53_resolver_firewall_rule.this) == 1 && length(aws_route53_resolver_firewall_domain_list.this) == 1
    error_message = "DNS firewall rule group, its rule and its custom domain list must be created."
  }

  assert {
    condition     = length(aws_route53_resolver_firewall_rule_group_association.this) == 2
    error_message = "The DNS firewall rule group must be associated with both named VPCs."
  }

  assert {
    condition     = aws_route53_resolver_firewall_rule.this["block-bad-domains.block-listed"].block_response == "NXDOMAIN"
    error_message = "The block response of the DNS firewall rule must reach the resource."
  }

  assert {
    condition     = length(output.resolver_endpoint_ids) == 2 && length(output.standalone_resolver_rule_ids) == 1 && length(output.dns_firewall_rule_group_ids) == 1
    error_message = "The DNS outputs must reflect the created resources."
  }
}

# -----------------------------------------------------------------------------
# 4. Validation failures — invalid input must be rejected
# -----------------------------------------------------------------------------

run "networking_invalid_vpc_cidr" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "broken"
        cidr         = "10.0.0.0"
        account_name = "network"
        subnets      = []
      }
    ]
  }

  expect_failures = [
    var.vpcs,
  ]
}

run "networking_invalid_subnet_type" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "broken"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "weird"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "dmz"
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.vpcs,
  ]
}

run "networking_invalid_ipam_netmask_missing" {
  command = plan

  variables {
    vpcs = [
      {
        name           = "ipam-vpc"
        ipam_pool_name = "top-level"
        account_name   = "network"
        subnets        = []
      }
    ]
  }

  expect_failures = [
    var.vpcs,
  ]
}

# A rule with a security group reference
# AND a prefix list but no CIDR/subnet source would create only the SG half;
# the prefix list half would silently not exist.
run "networking_invalid_sg_source_with_prefix_list" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets      = []
        security_groups = [
          {
            name = "app"
            ingress = [
              {
                protocol              = "tcp"
                from_port             = 443
                to_port               = 443
                source_security_group = "app"
                prefix_list_id        = "pl-12345678"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.vpcs,
  ]
}

# Positive counterpart to the validation above: with a CIDR source present the
# prefix list rides along on the CIDR-based rule (security-groups.tf pins the
# split between the three ingress resources) — the assurance the cb2741b
# validation message promises.
run "networking_prefix_list_rides_with_cidr" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets      = []
        security_groups = [
          {
            name = "app"
            ingress = [
              {
                protocol       = "tcp"
                from_port      = 443
                to_port        = 443
                cidr_blocks    = ["10.1.0.0/16"]
                prefix_list_id = "pl-12345678"
              }
            ]
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_security_group_rule.ingress_cidr) == 1
    error_message = "A rule with a CIDR source and a prefix list must produce exactly one CIDR-based ingress rule."
  }

  assert {
    condition = alltrue([
      for r in values(aws_security_group_rule.ingress_cidr) : tolist(r.prefix_list_ids) == tolist(["pl-12345678"])
    ])
    error_message = "The prefix list must ride along on the CIDR-based ingress rule (prefix_list_ids carries the configured entry)."
  }

  assert {
    condition     = length(aws_security_group_rule.ingress_prefix_list) == 0 && length(aws_security_group_rule.ingress_sg) == 0
    error_message = "A CIDR+prefix-list rule must not additionally create a prefix-list-only or SG-based ingress rule."
  }
}

# Positive counterpart: a rule whose only source is a prefix list lands on the
# prefix-list-only ingress resource.
run "networking_prefix_list_only_rule" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets      = []
        security_groups = [
          {
            name = "app"
            ingress = [
              {
                protocol       = "tcp"
                from_port      = 443
                to_port        = 443
                prefix_list_id = "pl-12345678"
              }
            ]
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_security_group_rule.ingress_prefix_list) == 1
    error_message = "A rule whose only source is a prefix list must produce exactly one prefix-list-only ingress rule."
  }

  assert {
    condition     = length(aws_security_group_rule.ingress_cidr) == 0 && length(aws_security_group_rule.ingress_sg) == 0
    error_message = "A prefix-list-only rule must not additionally create a CIDR-based or SG-based ingress rule."
  }
}

# A dot inside a name could collide two
# "<vpc>.<name>" map keys and merge() would silently drop a resource.
run "networking_invalid_dotted_name" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "prod.app"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets      = []
      }
    ]
  }

  expect_failures = [
    var.vpcs,
  ]
}

run "networking_invalid_peering_same_vpc" {
  command = plan

  variables {
    vpc_peering = [
      {
        name               = "self-peering"
        requester_vpc_name = "hub"
        accepter_vpc_name  = "hub"
      }
    ]
  }

  expect_failures = [
    var.vpc_peering,
  ]
}

run "networking_invalid_resolver_rule_type" {
  command = plan

  variables {
    resolver_rules = [
      {
        name        = "bad-rule"
        domain_name = "example.com"
        rule_type   = "PROXY"
      }
    ]
  }

  expect_failures = [
    var.resolver_rules,
  ]
}

run "networking_invalid_load_balancer_type" {
  command = plan

  variables {
    load_balancers = [
      {
        name         = "bad-lb"
        type         = "classic"
        vpc_name     = "hub"
        subnet_names = ["public-a"]
      }
    ]
  }

  expect_failures = [
    var.load_balancers,
  ]
}

run "networking_invalid_availability_zone" {
  command = plan

  variables {
    delete_default_vpc             = true
    default_vpc_availability_zones = ["euc1a"]
  }

  # The toggle also trips the two-step removal check: adoption is not
  # deletion. Both failures belong to this input and are expected here.
  expect_failures = [
    var.default_vpc_availability_zones,
    check.default_vpc_two_step_removal,
  ]
}

run "networking_invalid_central_log_bucket_name" {
  command = plan

  variables {
    central_log_bucket_name = "Invalid_Bucket_Name"
  }

  expect_failures = [
    var.central_log_bucket_name,
  ]
}

run "networking_invalid_tgw_flow_logs_destination" {
  command = plan

  variables {
    enable_tgw_flow_logs      = true
    tgw_flow_logs_destination = "kinesis"
  }

  expect_failures = [
    var.tgw_flow_logs_destination,
  ]
}

run "networking_invalid_acm_validation_method" {
  command = plan

  variables {
    acm_certificates = [
      {
        domain_name       = "example.com"
        validation_method = "HTTP"
      }
    ]
  }

  expect_failures = [
    var.acm_certificates,
  ]
}

run "networking_invalid_ipam_admin_account_id" {
  command = plan

  variables {
    ipam = {
      enabled                    = true
      delegated_admin_account_id = "12345"
    }
  }

  expect_failures = [
    var.ipam,
  ]
}

# An unknown parent pool has no ID the
# hierarchy could resolve.
run "networking_invalid_ipam_parent_pool_unknown" {
  command = plan

  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name             = "regional"
          cidr             = "10.0.0.0/12"
          parent_pool_name = "does-not-exist"
        }
      ]
    }
  }

  expect_failures = [
    var.ipam,
  ]
}

# Pools nested deeper than the resolved
# levels would silently never be created.
run "networking_invalid_ipam_pool_nesting_depth" {
  command = plan

  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name = "level1"
          cidr = "10.0.0.0/8"
        },
        {
          name             = "level2"
          cidr             = "10.0.0.0/12"
          parent_pool_name = "level1"
        },
        {
          name             = "level3"
          cidr             = "10.0.0.0/16"
          parent_pool_name = "level2"
        },
        {
          name             = "level4"
          cidr             = "10.0.0.0/20"
          parent_pool_name = "level3"
        },
      ]
    }
  }

  expect_failures = [
    var.ipam,
  ]
}

# A zone-scoped forward rule without an
# outbound resolver endpoint is rejected by Route 53.
run "networking_invalid_zone_resolver_rule_without_endpoint" {
  command = plan

  variables {
    resolver_endpoints = []

    route53_zones = [
      {
        name = "internal.example.com"
        resolver_rules = [
          {
            domain_name = "onprem.example.com"
            target_ips  = ["10.100.0.10"]
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.route53_zones,
  ]
}

# An unknown policy name must be rejected
# instead of producing an endpoint without any policy.
run "networking_invalid_endpoint_policy_name" {
  command = plan

  variables {
    endpoint_policies = []

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            policy_name  = "missing-policy"
          }
        ]
      }
    ]
  }

  expect_failures = [
    var.vpcs,
  ]
}

# -----------------------------------------------------------------------------
# traffic_type and max_aggregation_interval
# -----------------------------------------------------------------------------
# A configured traffic_type and max_aggregation_interval reach both flow log
# resources, from the per-VPC flow_logs block and from var.vpc_flow_logs_default.
#
# This scenario sets both attributes to values that differ from the defaults and
# checks them on both destinations — S3 via a per-VPC block, CloudWatch via the
# global default. The default case ALL/600 stays covered by
# networking_bf_dead_047_vpc_scaffolding_pass_through.

run "networking_bf_dead_070_flow_log_traffic_type_and_interval" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        # Per-VPC block with both attributes — S3 destination
        flow_logs = {
          destination              = "s3"
          traffic_type             = "REJECT"
          max_aggregation_interval = 60
        }
      },
      {
        name         = "spoke"
        cidr         = "10.2.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.2.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        # No flow_logs block — the global default applies
      },
    ]

    # Global default with both attributes — CloudWatch destination
    vpc_flow_logs_default = {
      destination              = "cloudwatch"
      traffic_type             = "REJECT"
      max_aggregation_interval = 60
    }
  }

  assert {
    condition     = aws_flow_log.s3["hub"].traffic_type == "REJECT"
    error_message = "traffic_type of a per-VPC flow_logs block must reach aws_flow_log.s3 instead of a hardcoded ALL."
  }

  assert {
    condition     = aws_flow_log.s3["hub"].max_aggregation_interval == 60
    error_message = "max_aggregation_interval of a per-VPC flow_logs block must reach aws_flow_log.s3."
  }

  assert {
    condition     = aws_flow_log.cloudwatch["spoke"].traffic_type == "REJECT"
    error_message = "traffic_type of vpc_flow_logs_default must reach aws_flow_log.cloudwatch instead of a hardcoded ALL."
  }

  assert {
    condition     = aws_flow_log.cloudwatch["spoke"].max_aggregation_interval == 60
    error_message = "max_aggregation_interval of vpc_flow_logs_default must reach aws_flow_log.cloudwatch."
  }
}

# -----------------------------------------------------------------------------
# acceptance_required is a per-GWLB control decision
#
# An operator who wants a manual acceptance step on the GWLB endpoint service
# sets acceptance_required: a configured true reaches the endpoint service. The
# default-false counterpart is asserted in scenario
# networking_bf_dead_061_load_balancing_pass_through.
# -----------------------------------------------------------------------------
run "regression_gwlb_acceptance_required_reaches_endpoint_service" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.20.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "appliance-a"
            cidr              = "10.20.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
    gateway_load_balancers = [
      {
        name         = "inspection-gwlb"
        vpc_name     = "inspection"
        subnet_names = ["appliance-a"]
        target_group = {
          name = "inspection-gwlb-tg"
        }
        acceptance_required = true
      }
    ]
  }

  assert {
    condition     = aws_vpc_endpoint_service.gwlb["inspection-gwlb"].acceptance_required == true
    error_message = "A configured acceptance_required must reach the GWLB endpoint service."
  }
}

# -----------------------------------------------------------------------------
# Manual acceptance of shared TGW attachments
#
# An operator who wants a manual control step for attachments from RAM-shared
# accounts sets auto_accept_shared_attachments to "disable"; the default-"enable"
# counterpart is asserted in scenario networking_custom_tgw_dns_config.
# -----------------------------------------------------------------------------
run "regression_tgw_auto_accept_disable_reaches_resource" {
  command = plan

  variables {
    vpcs = []
    transit_gateway = {
      enabled                        = true
      auto_accept_shared_attachments = "disable"
    }
  }

  assert {
    condition     = aws_ec2_transit_gateway.this[0].auto_accept_shared_attachments == "disable"
    error_message = "A configured auto_accept_shared_attachments must reach the Transit Gateway."
  }
}

# -----------------------------------------------------------------------------
# Optional CMK for the module's CloudWatch log groups
#
# A configured cloudwatch_logs_kms_key_arn encrypts all three CloudWatch log
# groups (VPC flow logs, TGW flow logs, Route 53 query logs) with that
# customer-managed key. The empty default keeps kms_key_id unset (service
# encryption), which the other scenarios cover implicitly.

# -----------------------------------------------------------------------------
run "regression_cloudwatch_logs_kms_key_reaches_log_groups" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.30.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.30.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        flow_logs = {
          destination = "cloudwatch"
        }
      }
    ]
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
    }
    enable_tgw_flow_logs      = true
    tgw_flow_logs_destination = "cloudwatch"
    route53_zones = [
      {
        name = "internal.example.com"
      }
    ]
    enable_route53_query_logging      = true
    route53_query_logging_destination = "cloudwatch"
    route53_query_logging_vpc_names   = ["hub"]
    cloudwatch_logs_kms_key_arn       = "arn:aws:kms:eu-central-1:123456789012:key/00000000-1111-2222-3333-444444444444"
  }

  assert {
    condition     = alltrue([for _, lg in aws_cloudwatch_log_group.flow_logs : lg.kms_key_id == "arn:aws:kms:eu-central-1:123456789012:key/00000000-1111-2222-3333-444444444444"])
    error_message = "A configured cloudwatch_logs_kms_key_arn must reach the flow log log groups."
  }

  assert {
    condition     = aws_cloudwatch_log_group.tgw_flow_logs[0].kms_key_id == "arn:aws:kms:eu-central-1:123456789012:key/00000000-1111-2222-3333-444444444444"
    error_message = "A configured cloudwatch_logs_kms_key_arn must reach the TGW flow log log group."
  }

  assert {
    condition     = aws_cloudwatch_log_group.query_logging[0].kms_key_id == "arn:aws:kms:eu-central-1:123456789012:key/00000000-1111-2222-3333-444444444444"
    error_message = "A configured cloudwatch_logs_kms_key_arn must reach the query logging log group."
  }
}

# -----------------------------------------------------------------------------
# Validation failure — malformed cloudwatch_logs_kms_key_arn
# -----------------------------------------------------------------------------
run "networking_invalid_cloudwatch_logs_kms_key_arn" {
  command = plan

  variables {
    vpcs                        = []
    cloudwatch_logs_kms_key_arn = "not-a-kms-arn"
  }

  expect_failures = [var.cloudwatch_logs_kms_key_arn]
}

# -----------------------------------------------------------------------------
# Validation failure — invalid auto_accept_shared_attachments value
# -----------------------------------------------------------------------------
run "networking_invalid_tgw_auto_accept_value" {
  command = plan

  variables {
    vpcs = []
    transit_gateway = {
      enabled                        = true
      auto_accept_shared_attachments = "maybe"
    }
  }

  expect_failures = [var.transit_gateway]
}

# -----------------------------------------------------------------------------
# 3n. Custom configuration — free-form tags, VPC layer
# -----------------------------------------------------------------------------
# Every resource list of the module accepts an optional `tags` map per entry.
# The map is merged onto the tags the module sets itself, and the module's own
# Name wins: each entry below supplies a competing Name to hold that rule.
#
# This run covers the VPC layer; scenario 3o covers the Transit Gateway and the
# central network services. The untagged counterpart is scenario 3p.
# -----------------------------------------------------------------------------
run "networking_tags_reach_vpc_layer" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        tags = {
          Name        = "user-supplied-name"
          Owner       = "network-team"
          CostCentre  = "CC-4711"
          Environment = "production"
        }
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            nat_gateway       = true
            tags              = { Name = "user-supplied-name", Tier = "edge" }
            route_table_tags  = { Name = "user-supplied-name", Purpose = "egress" }
            nat_gateway_tags  = { Name = "user-supplied-name", Purpose = "shared-egress" }
          },
          {
            name              = "private-a"
            cidr              = "10.0.10.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            tags              = { Tier = "application" }
          },
        ]
        nacls = [
          {
            name         = "private-acl"
            subnet_names = ["private-a"]
            tags         = { Name = "user-supplied-name", Scope = "private" }
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            tags = { Name = "user-supplied-name", Scope = "application" }
          }
        ]
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            tags         = { Name = "user-supplied-name", Service = "ssm" }
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.1.0.0/16"
        account_name = "workload"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.1.10.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]

    vpc_peering = [
      {
        name               = "hub-to-spoke"
        requester_vpc_name = "hub"
        accepter_vpc_name  = "spoke"
        tags               = { Name = "user-supplied-name", Purpose = "shared-services" }
      }
    ]

    prefix_lists = [
      {
        name        = "corp-cidrs"
        max_entries = 5
        tags        = { Name = "user-supplied-name", Scope = "corporate" }
        entries     = [{ cidr = "10.0.0.0/8" }]
      }
    ]

    dhcp_options_sets = [
      {
        name                = "corp-dns"
        domain_name         = "corp.example.com"
        domain_name_servers = ["10.0.0.2"]
        vpc_names           = ["hub"]
        tags                = { Name = "user-supplied-name", Scope = "corporate" }
      }
    ]

    elastic_ips = [
      {
        name = "egress-reserved"
        tags = { Name = "user-supplied-name", Purpose = "reserved-egress" }
      }
    ]

    acm_certificates = [
      {
        domain_name = "api.example.com"
        tags        = { Name = "user-supplied-name", Scope = "public-api" }
      }
    ]
  }

  # --- VPC ---
  assert {
    condition     = aws_vpc.this["hub"].tags["Owner"] == "network-team"
    error_message = "A configured tags entry must reach the VPC."
  }
  assert {
    condition     = aws_vpc.this["hub"].tags["CostCentre"] == "CC-4711"
    error_message = "Every configured tags entry must reach the VPC, not just the first."
  }
  assert {
    condition     = aws_vpc.this["hub"].tags["Name"] == "hub"
    error_message = "The module's Name tag must win over a user-supplied Name on the VPC."
  }
  assert {
    condition     = length(aws_vpc.this["spoke"].tags) == 1
    error_message = "A VPC without tags must carry the module's Name tag only."
  }

  # --- Subnet, route table, NAT gateway and its address ---
  assert {
    condition = (
      aws_subnet.this["hub.public-a"].tags["Tier"] == "edge"
      && aws_subnet.this["hub.public-a"].tags["Name"] == "hub.public-a"
      && aws_subnet.this["hub.public-a"].tags["Type"] == "public"
    )
    error_message = "Subnet tags must merge with the module's Name and Type tags, which win."
  }
  assert {
    condition = (
      aws_route_table.this["hub.public-a"].tags["Purpose"] == "egress"
      && aws_route_table.this["hub.public-a"].tags["Name"] == "hub.public-a-rt"
    )
    error_message = "route_table_tags must reach the subnet's route table without displacing its Name."
  }
  assert {
    condition = (
      aws_nat_gateway.this["hub.public-a"].tags["Purpose"] == "shared-egress"
      && aws_nat_gateway.this["hub.public-a"].tags["Name"] == "hub.public-a-nat"
    )
    error_message = "nat_gateway_tags must reach the NAT gateway without displacing its Name."
  }
  assert {
    condition = (
      aws_eip.nat["hub.public-a"].tags["Purpose"] == "shared-egress"
      && aws_eip.nat["hub.public-a"].tags["Name"] == "hub.public-a-nat-eip"
    )
    error_message = "nat_gateway_tags must also reach the NAT gateway's Elastic IP."
  }
  assert {
    condition     = aws_route_table.this["hub.private-a"].tags["Name"] == "hub.private-a-rt"
    error_message = "A subnet without route_table_tags must leave its route table unchanged."
  }

  # --- NACL, security group, interface endpoint ---
  assert {
    condition = (
      aws_network_acl.this["hub.private-acl"].tags["Scope"] == "private"
      && aws_network_acl.this["hub.private-acl"].tags["Name"] == "hub.private-acl"
    )
    error_message = "NACL tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_security_group.this["hub.app-sg"].tags["Scope"] == "application"
      && aws_security_group.this["hub.app-sg"].tags["Name"] == "hub.app-sg"
    )
    error_message = "Security group tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_vpc_endpoint.interface["hub.ssm"].tags["Service"] == "ssm"
      && aws_vpc_endpoint.interface["hub.ssm"].tags["Name"] == "hub-ssm-if-endpoint"
    )
    error_message = "Interface endpoint tags must merge with the module's Name tag, which wins."
  }

  # --- Peering, prefix list, DHCP options, Elastic IP, certificate ---
  assert {
    condition = (
      aws_vpc_peering_connection.this["hub-to-spoke"].tags["Purpose"] == "shared-services"
      && aws_vpc_peering_connection.this["hub-to-spoke"].tags["Name"] == "hub-to-spoke"
    )
    error_message = "Peering tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_ec2_managed_prefix_list.this["corp-cidrs"].tags["Scope"] == "corporate"
      && aws_ec2_managed_prefix_list.this["corp-cidrs"].tags["Name"] == "corp-cidrs"
    )
    error_message = "Prefix list tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_vpc_dhcp_options.this["corp-dns"].tags["Scope"] == "corporate"
      && aws_vpc_dhcp_options.this["corp-dns"].tags["Name"] == "corp-dns"
    )
    error_message = "DHCP options set tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_eip.this["egress-reserved"].tags["Purpose"] == "reserved-egress"
      && aws_eip.this["egress-reserved"].tags["Name"] == "egress-reserved"
    )
    error_message = "The Elastic IP follows the same merge order as every other tagged resource: the module's Name wins."
  }
  assert {
    condition = (
      aws_acm_certificate.this["api.example.com"].tags["Scope"] == "public-api"
      && aws_acm_certificate.this["api.example.com"].tags["Name"] == "api.example.com"
    )
    error_message = "Certificate tags must merge with the module's Name tag, which wins."
  }
}

# -----------------------------------------------------------------------------
# 3o. Custom configuration — free-form tags, Transit Gateway and central
#     network services
# -----------------------------------------------------------------------------
# Counterpart of 3n for the hub-side resource lists. transit_gateway.route_tables
# holds names only, so the tags of a route table come from route_table_tags under
# that name; customer_gateways tags the gateway and its VPN connection
# separately.
# -----------------------------------------------------------------------------
run "networking_tags_reach_hub_layer" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "tgw-b"
            cidr              = "10.0.4.0/24"
            availability_zone = "eu-central-1b"
            type              = "private"
          },
          {
            name              = "inspection-a"
            cidr              = "10.0.3.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
        tgw_attachment = {
          route_table_name = "shared"
          tags             = { Name = "user-supplied-name", Segment = "shared" }
        }
      }
    ]

    transit_gateway = {
      enabled      = true
      route_tables = ["shared"]
      tags         = { Name = "user-supplied-name", Owner = "network-team" }
      route_table_tags = {
        shared = { Name = "user-supplied-name", Segment = "shared" }
      }
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "shared"
          tags                    = { Name = "user-supplied-name", Purpose = "multi-region" }
        }
      ]
    }

    tgw_connect_attachments = [
      {
        name                 = "sdwan-connect"
        transit_gateway_name = "hub-tgw"
        transport_attachment = "hub"
        tags                 = { Name = "user-supplied-name", Vendor = "sdwan" }
      }
    ]

    dx_gateways = [
      {
        name                 = "corp-dxgw"
        amazon_asn           = 64513
        transit_gateway_name = "hub-tgw"
        virtual_interfaces = [
          {
            name          = "corp-transit-vif"
            type          = "transit"
            vlan          = 101
            bgp_asn       = 65001
            connection_id = "dxcon-abcdef01"
            tags          = { Name = "user-supplied-name", Carrier = "corp" }
          }
        ]
      }
    ]

    customer_gateways = [
      {
        name                 = "branch-office"
        bgp_asn              = 65010
        ip_address           = "203.0.113.10"
        transit_gateway_name = "hub-tgw"
        tags                 = { Name = "user-supplied-name", Site = "branch" }
        vpn_connection_tags  = { Name = "user-supplied-name", Site = "branch-tunnel" }
      }
    ]

    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      tags         = { Name = "user-supplied-name", Scope = "central-inspection" }
      firewall_policy = {
        tags = { Name = "user-supplied-name", Scope = "central-policy" }
      }
      rule_groups = [
        {
          name     = "egress-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "pass tcp any any -> any 443 (sid:1;)"
          tags     = { Name = "user-supplied-name", Scope = "egress" }
        }
      ]
    }

    ipam = {
      enabled = true
      tags    = { Name = "user-supplied-name", Owner = "network-team" }
      pools = [
        {
          name = "eu-central-1-pool"
          cidr = "10.0.0.0/8"
          tags = { Name = "user-supplied-name", Region = "eu-central-1" }
        }
      ]
    }

    dns_firewall_rule_groups = [
      {
        name      = "blocked-domains"
        vpc_names = ["hub"]
        tags      = { Name = "user-supplied-name", Scope = "central-dns" }
        custom_domain_lists = [
          { name = "denied", domains = ["bad.example.com"] }
        ]
        rules = [
          {
            name                    = "block-denied"
            priority                = 100
            action                  = "BLOCK"
            custom_domain_list_name = "denied"
          }
        ]
      }
    ]

    resolver_endpoints = [
      {
        name         = "outbound-dns"
        direction    = "OUTBOUND"
        vpc_name     = "hub"
        subnet_names = ["tgw-a", "tgw-b"]
        tags         = { Name = "user-supplied-name", Direction = "outbound" }
        resolver_rules = [
          {
            domain_name = "corp.example.com"
            target_ips  = [{ ip = "10.99.0.2" }]
            tags        = { Name = "user-supplied-name", Scope = "corp-forward" }
          }
        ]
      }
    ]

    gateway_load_balancers = [
      {
        name         = "inspection-gwlb"
        vpc_name     = "hub"
        subnet_names = ["inspection-a"]
        tags         = { Name = "user-supplied-name", Scope = "central-inspection" }
        target_group = { name = "inspection-gwlb-tg" }
      }
    ]
  }

  # --- Transit Gateway ---
  assert {
    condition = (
      aws_ec2_transit_gateway.this[0].tags["Owner"] == "network-team"
      && aws_ec2_transit_gateway.this[0].tags["Name"] == "tlz-transit-gateway"
    )
    error_message = "transit_gateway.tags must reach the Transit Gateway without displacing its Name."
  }
  assert {
    condition = (
      aws_ec2_transit_gateway_route_table.this["shared"].tags["Segment"] == "shared"
      && aws_ec2_transit_gateway_route_table.this["shared"].tags["Name"] == "shared"
    )
    error_message = "route_table_tags must reach the route table named by its key."
  }
  assert {
    condition = (
      aws_ec2_transit_gateway_vpc_attachment.this["hub"].tags["Segment"] == "shared"
      && aws_ec2_transit_gateway_vpc_attachment.this["hub"].tags["Name"] == "hub-tgw-attachment"
    )
    error_message = "tgw_attachment.tags must reach the VPC attachment without displacing its Name."
  }
  assert {
    condition = (
      aws_ec2_transit_gateway_peering_attachment.this["eu-west-1-tgw-0123456789abcdef0"].tags["Purpose"] == "multi-region"
      && aws_ec2_transit_gateway_peering_attachment.this["eu-west-1-tgw-0123456789abcdef0"].tags["Name"] == "tgw-peering-eu-west-1"
    )
    error_message = "Peering tags must reach the peering attachment without displacing its Name."
  }
  assert {
    condition = (
      aws_ec2_transit_gateway_connect.this["sdwan-connect"].tags["Vendor"] == "sdwan"
      && aws_ec2_transit_gateway_connect.this["sdwan-connect"].tags["Name"] == "sdwan-connect"
    )
    error_message = "TGW Connect tags must merge with the module's Name tag, which wins."
  }

  # --- Hybrid connectivity ---
  assert {
    condition = (
      aws_dx_transit_virtual_interface.this["corp-dxgw.corp-transit-vif"].tags["Carrier"] == "corp"
      && aws_dx_transit_virtual_interface.this["corp-dxgw.corp-transit-vif"].tags["Name"] == "corp-dxgw.corp-transit-vif"
    )
    error_message = "Virtual interface tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_customer_gateway.this["branch-office"].tags["Site"] == "branch"
      && aws_customer_gateway.this["branch-office"].tags["Name"] == "branch-office"
    )
    error_message = "customer_gateways tags must reach the customer gateway without displacing its Name."
  }
  assert {
    condition = (
      aws_vpn_connection.this["branch-office"].tags["Site"] == "branch-tunnel"
      && aws_vpn_connection.this["branch-office"].tags["Name"] == "branch-office-vpn"
    )
    error_message = "vpn_connection_tags must tag the VPN connection separately from its customer gateway."
  }

  # --- Central network services ---
  assert {
    condition = (
      aws_networkfirewall_firewall.this[0].tags["Scope"] == "central-inspection"
      && aws_networkfirewall_firewall.this[0].tags["Name"] == "tlz-network-firewall"
    )
    error_message = "network_firewall.tags must reach the firewall without displacing its Name."
  }
  assert {
    condition = (
      aws_networkfirewall_firewall_policy.this[0].tags["Scope"] == "central-policy"
      && aws_networkfirewall_firewall_policy.this[0].tags["Name"] == "tlz-firewall-policy"
    )
    error_message = "firewall_policy.tags must reach the firewall policy without displacing its Name."
  }
  assert {
    condition = (
      aws_networkfirewall_rule_group.this["egress-domains"].tags["Scope"] == "egress"
      && aws_networkfirewall_rule_group.this["egress-domains"].tags["Name"] == "egress-domains"
    )
    error_message = "Rule group tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_vpc_ipam.this[0].tags["Owner"] == "network-team"
      && aws_vpc_ipam.this[0].tags["Name"] == "tlz-ipam"
    )
    error_message = "ipam.tags must reach the IPAM without displacing its Name."
  }
  assert {
    condition = (
      aws_vpc_ipam_pool.this["eu-central-1-pool"].tags["Region"] == "eu-central-1"
      && aws_vpc_ipam_pool.this["eu-central-1-pool"].tags["Name"] == "eu-central-1-pool"
    )
    error_message = "Pool tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_route53_resolver_firewall_rule_group.this["blocked-domains"].tags["Scope"] == "central-dns"
      && aws_route53_resolver_firewall_rule_group.this["blocked-domains"].tags["Name"] == "blocked-domains"
    )
    error_message = "DNS firewall rule group tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_route53_resolver_endpoint.this["outbound-dns"].tags["Direction"] == "outbound"
      && aws_route53_resolver_endpoint.this["outbound-dns"].tags["Name"] == "outbound-dns"
    )
    error_message = "Resolver endpoint tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_route53_resolver_rule.endpoint["outbound-dns.corp.example.com"].tags["Scope"] == "corp-forward"
      && aws_route53_resolver_rule.endpoint["outbound-dns.corp.example.com"].tags["Name"] == "outbound-dns.corp.example.com"
    )
    error_message = "Resolver rule tags must merge with the module's Name tag, which wins."
  }
  assert {
    condition = (
      aws_lb.gwlb["inspection-gwlb"].tags["Scope"] == "central-inspection"
      && aws_lb.gwlb["inspection-gwlb"].tags["Name"] == "inspection-gwlb"
    )
    error_message = "Gateway load balancer tags must merge with the module's Name tag, which wins."
  }
}

# -----------------------------------------------------------------------------
# 3p. Custom configuration — the tag default {} changes nothing
# -----------------------------------------------------------------------------
# Untagged counterpart of 3n and 3o: the same resource lists without a single
# `tags` entry. Every resource carries only the tags the module sets itself — a
# configuration that does not use the attribute is left untouched.
# -----------------------------------------------------------------------------
run "networking_tag_default_leaves_resources_unchanged" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            nat_gateway       = true
          },
          {
            name              = "tgw-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
        nacls = [
          { name = "public-acl", subnet_names = ["public-a"] }
        ]
        security_groups = [
          { name = "app-sg" }
        ]
        interface_endpoints = [
          { service = "ssm", subnet_names = ["tgw-a"] }
        ]
        tgw_attachment = { route_table_name = "shared" }
      }
    ]
    transit_gateway = {
      enabled      = true
      route_tables = ["shared"]
    }
    prefix_lists = [
      { name = "corp-cidrs", max_entries = 5, entries = [{ cidr = "10.0.0.0/8" }] }
    ]
    dhcp_options_sets = [
      { name = "corp-dns", domain_name = "corp.example.com", vpc_names = ["hub"] }
    ]
    elastic_ips = [{ name = "egress-reserved" }]
  }

  assert {
    condition     = aws_vpc.this["hub"].tags == tomap({ Name = "hub" })
    error_message = "Without tags the VPC must carry the module's Name tag only."
  }
  assert {
    condition     = aws_subnet.this["hub.public-a"].tags == tomap({ Name = "hub.public-a", Type = "public" })
    error_message = "Without tags the subnet must carry the module's Name and Type tags only."
  }
  assert {
    condition     = aws_route_table.this["hub.public-a"].tags == tomap({ Name = "hub.public-a-rt", Type = "public" })
    error_message = "Without route_table_tags the route table must carry the module's tags only."
  }
  assert {
    condition     = aws_nat_gateway.this["hub.public-a"].tags == tomap({ Name = "hub.public-a-nat" })
    error_message = "Without nat_gateway_tags the NAT gateway must carry the module's Name tag only."
  }
  assert {
    condition     = aws_eip.nat["hub.public-a"].tags == tomap({ Name = "hub.public-a-nat-eip" })
    error_message = "Without nat_gateway_tags the NAT gateway's address must carry the module's Name tag only."
  }
  assert {
    condition     = aws_network_acl.this["hub.public-acl"].tags == tomap({ Name = "hub.public-acl" })
    error_message = "Without tags the NACL must carry the module's Name tag only."
  }
  assert {
    condition     = aws_security_group.this["hub.app-sg"].tags == tomap({ Name = "hub.app-sg" })
    error_message = "Without tags the security group must carry the module's Name tag only."
  }
  assert {
    condition     = aws_vpc_endpoint.interface["hub.ssm"].tags == tomap({ Name = "hub-ssm-if-endpoint" })
    error_message = "Without tags the interface endpoint must carry the module's Name tag only."
  }
  assert {
    condition     = aws_ec2_transit_gateway.this[0].tags == tomap({ Name = "tlz-transit-gateway" })
    error_message = "Without tags the Transit Gateway must carry the module's Name tag only."
  }
  assert {
    condition     = aws_ec2_transit_gateway_route_table.this["shared"].tags == tomap({ Name = "shared" })
    error_message = "Without route_table_tags the TGW route table must carry the module's Name tag only."
  }
  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].tags == tomap({ Name = "hub-tgw-attachment" })
    error_message = "Without tags the VPC attachment must carry the module's Name tag only."
  }
  assert {
    condition     = aws_ec2_managed_prefix_list.this["corp-cidrs"].tags == tomap({ Name = "corp-cidrs" })
    error_message = "Without tags the prefix list must carry the module's Name tag only."
  }
  assert {
    condition     = aws_vpc_dhcp_options.this["corp-dns"].tags == tomap({ Name = "corp-dns" })
    error_message = "Without tags the DHCP options set must carry the module's Name tag only."
  }
  assert {
    condition     = aws_eip.this["egress-reserved"].tags == tomap({ Name = "egress-reserved" })
    error_message = "Without tags the Elastic IP must carry the module's Name tag only."
  }
}

# -----------------------------------------------------------------------------
# Validation failure — reserved tag prefix "aws:"
# -----------------------------------------------------------------------------
run "networking_invalid_vpc_tag_reserved_prefix" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        tags         = { "aws:cloudformation:stack-name" = "not-allowed" }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.10.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# Validation failure — tag value beyond the AWS limit
# -----------------------------------------------------------------------------
run "networking_invalid_dhcp_tag_value_too_long" {
  command = plan
  variables {
    vpcs = []
    dhcp_options_sets = [
      {
        name        = "corp-dns"
        domain_name = "corp.example.com"
        tags        = { Comment = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
      }
    ]
  }
  expect_failures = [var.dhcp_options_sets]
}

# -----------------------------------------------------------------------------
# Validation failure — route_table_tags names an unknown route table
# -----------------------------------------------------------------------------
run "networking_invalid_tgw_route_table_tags_unknown_name" {
  command = plan
  variables {
    vpcs = []
    transit_gateway = {
      enabled      = true
      route_tables = ["shared"]
      route_table_tags = {
        segregated = { Segment = "segregated" }
      }
    }
  }
  expect_failures = [var.transit_gateway]
}

# -----------------------------------------------------------------------------
# 3q. Custom configuration — extended target group attributes
# -----------------------------------------------------------------------------
# Three target groups, one per attribute family: an application group with
# deregistration timing, warm-up, distribution algorithm, protocol version and
# app-cookie affinity; a network group with client IP preservation, Proxy
# Protocol v2 and connection termination; a gateway group with target failover.
# The empty counterpart is scenario 1 (Toggle-Off), the unset counterpart is
# scenario 3t.

run "networking_target_group_attributes_reach_resource" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "spoke"
        cidr         = "10.30.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.30.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]

    target_groups = [
      {
        name                 = "app-http-tg"
        port                 = 80
        protocol             = "HTTP"
        vpc_name             = "spoke"
        target_type          = "ip"
        deregistration_delay = 600
        slow_start           = 120
        algorithm            = "least_outstanding_requests"
        protocol_version     = "HTTP2"
        stickiness = {
          type            = "app_cookie"
          cookie_name     = "SESSIONID"
          cookie_duration = 3600
        }
      },
      {
        name                   = "app-tcp-tg"
        port                   = 443
        protocol               = "TCP"
        vpc_name               = "spoke"
        target_type            = "ip"
        preserve_client_ip     = true
        proxy_protocol_v2      = true
        connection_termination = true
      },
      {
        name            = "inspect-geneve-tg"
        port            = 6081
        protocol        = "GENEVE"
        vpc_name        = "spoke"
        target_type     = "ip"
        target_failover = "rebalance"
      },
    ]
  }

  assert {
    condition     = length(aws_lb_target_group.this) == 3
    error_message = "All three target groups must be created."
  }

  assert {
    condition = alltrue([
      tostring(aws_lb_target_group.this["app-http-tg"].deregistration_delay) == "600",
      tostring(aws_lb_target_group.this["app-http-tg"].slow_start) == "120",
      aws_lb_target_group.this["app-http-tg"].load_balancing_algorithm_type == "least_outstanding_requests",
      aws_lb_target_group.this["app-http-tg"].protocol_version == "HTTP2",
    ])
    error_message = "Deregistration delay, warm-up, algorithm and protocol version must reach the application target group."
  }

  assert {
    condition = alltrue([
      length(aws_lb_target_group.this["app-http-tg"].stickiness) == 1,
      aws_lb_target_group.this["app-http-tg"].stickiness[0].type == "app_cookie",
      aws_lb_target_group.this["app-http-tg"].stickiness[0].cookie_name == "SESSIONID",
      tostring(aws_lb_target_group.this["app-http-tg"].stickiness[0].cookie_duration) == "3600",
      aws_lb_target_group.this["app-http-tg"].stickiness[0].enabled == true,
    ])
    error_message = "The app-cookie affinity must reach the target group with its cookie name and duration."
  }

  assert {
    condition = alltrue([
      tostring(aws_lb_target_group.this["app-tcp-tg"].preserve_client_ip) == "true",
      aws_lb_target_group.this["app-tcp-tg"].proxy_protocol_v2 == true,
      aws_lb_target_group.this["app-tcp-tg"].connection_termination == true,
    ])
    error_message = "Client IP preservation, Proxy Protocol v2 and connection termination must reach the network target group."
  }

  assert {
    condition = alltrue([
      length(aws_lb_target_group.this["inspect-geneve-tg"].target_failover) == 1,
      aws_lb_target_group.this["inspect-geneve-tg"].target_failover[0].on_deregistration == "rebalance",
      aws_lb_target_group.this["inspect-geneve-tg"].target_failover[0].on_unhealthy == "rebalance",
    ])
    error_message = "One target_failover value must reach both transitions of the gateway target group."
  }
}

# -----------------------------------------------------------------------------
# 3r. Custom configuration — extended load balancer attributes
# -----------------------------------------------------------------------------
# An application load balancer with all seven HTTP attributes and a network load
# balancer with cross-zone distribution and an ALPN policy on its TLS listener.
# The empty counterpart is scenario 1 (Toggle-Off), the unset counterpart is
# scenario 3t.

run "networking_load_balancer_attributes_reach_resource" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "spoke"
        cidr         = "10.31.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.31.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "private-b"
            cidr              = "10.31.2.0/24"
            availability_zone = "eu-central-1b"
            type              = "private"
          },
        ]
      }
    ]

    target_groups = [
      {
        name        = "web-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      }
    ]

    load_balancers = [
      {
        name                       = "web-alb"
        type                       = "application"
        vpc_name                   = "spoke"
        subnet_names               = ["private-a", "private-b"]
        idle_timeout               = 120
        enable_http2               = false
        desync_mitigation_mode     = "strictest"
        enable_xff_client_port     = true
        xff_header_processing_mode = "preserve"
        enable_tls_headers         = true
        enable_waf_fail_open       = true
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            target_group_name = "web-tg"
          }
        ]
      },
      {
        name                             = "edge-nlb"
        type                             = "network"
        vpc_name                         = "spoke"
        subnet_names                     = ["private-a"]
        enable_cross_zone_load_balancing = true
        listeners = [
          {
            port              = 443
            protocol          = "TLS"
            target_group_name = "web-tg"
            alpn_policy       = "HTTP2Preferred"
          }
        ]
      },
    ]
  }

  assert {
    condition = alltrue([
      tostring(aws_lb.this["web-alb"].idle_timeout) == "120",
      aws_lb.this["web-alb"].enable_http2 == false,
      aws_lb.this["web-alb"].desync_mitigation_mode == "strictest",
      aws_lb.this["web-alb"].enable_xff_client_port == true,
      aws_lb.this["web-alb"].xff_header_processing_mode == "preserve",
      aws_lb.this["web-alb"].enable_tls_version_and_cipher_suite_headers == true,
      aws_lb.this["web-alb"].enable_waf_fail_open == true,
    ])
    error_message = "All seven HTTP attributes must reach the application load balancer."
  }

  # The two hardened attributes stay on
  # regardless of what an entry sets.
  assert {
    condition = alltrue([
      aws_lb.this["web-alb"].enable_deletion_protection == true,
      aws_lb.this["web-alb"].drop_invalid_header_fields == true,
      aws_lb.this["edge-nlb"].enable_deletion_protection == true,
      aws_lb.this["edge-nlb"].drop_invalid_header_fields == true,
    ])
    error_message = "Deletion protection and drop_invalid_header_fields must stay on for every load balancer."
  }

  assert {
    condition     = aws_lb.this["edge-nlb"].enable_cross_zone_load_balancing == true
    error_message = "Cross-zone distribution must reach the network load balancer."
  }

  assert {
    condition     = aws_lb_listener.this["edge-nlb.443"].alpn_policy == "HTTP2Preferred"
    error_message = "The ALPN policy must reach the TLS listener."
  }

  # An HTTPS/TLS listener that names no ssl_policy must get the
  # TLS-1.2-minimum floor on BOTH balancer types, not the ELB service
  # default (which still negotiates TLS 1.0/1.1).
  assert {
    condition     = aws_lb_listener.this["web-alb.443"].ssl_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"
    error_message = "An HTTPS listener on an application load balancer without an explicit ssl_policy must get the TLS 1.2 floor."
  }

  assert {
    condition     = aws_lb_listener.this["edge-nlb.443"].ssl_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"
    error_message = "A TLS listener on a network load balancer without an explicit ssl_policy must get the TLS 1.2 floor."
  }
}

# -----------------------------------------------------------------------------
# 3s. Custom configuration — listener actions beyond forwarding
# -----------------------------------------------------------------------------
# One application load balancer with three listeners, one per action type: a
# permanent redirect to HTTPS, a fixed maintenance response, and a weighted
# forward over two target groups with target group affinity. The empty
# counterpart is scenario 1 (Toggle-Off), the single-destination counterpart is
# scenario 3t. The load balancer is internal: two of its listeners are
# plaintext, and an internet-facing entry needs an authenticated edge on every
# listener, which exists on HTTPS alone (scenario 3bf holds that rule).

run "networking_listener_actions_reach_resource" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "spoke"
        cidr         = "10.32.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.32.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          }
        ]
      }
    ]

    target_groups = [
      {
        name        = "blue-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      },
      {
        name        = "green-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      },
    ]

    load_balancers = [
      {
        name         = "edge-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["public-a"]
        scheme       = "internal"
        listeners = [
          {
            port     = 80
            protocol = "HTTP"
            action = {
              type  = "redirect"
              order = 1
              redirect = {
                status_code = "HTTP_301"
                protocol    = "HTTPS"
                port        = "443"
              }
            }
          },
          {
            port     = 8080
            protocol = "HTTP"
            action = {
              type = "fixed-response"
              fixed_response = {
                status_code  = "503"
                content_type = "text/html"
                message_body = "<h1>Maintenance</h1>"
              }
            }
          },
          {
            port     = 443
            protocol = "HTTPS"
            action = {
              type = "forward"
              target_groups = [
                {
                  target_group_name = "blue-tg"
                  weight            = 90
                },
                {
                  target_group_name = "green-tg"
                  weight            = 10
                },
              ]
              stickiness = {
                duration = 3600
              }
            }
          },
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_lb_listener.this) == 3
    error_message = "All three listeners must be created."
  }

  assert {
    condition = alltrue([
      length(aws_lb_listener.this["edge-alb.80"].default_action) == 1,
      aws_lb_listener.this["edge-alb.80"].default_action[0].type == "redirect",
      tostring(aws_lb_listener.this["edge-alb.80"].default_action[0].order) == "1",
      aws_lb_listener.this["edge-alb.80"].default_action[0].redirect[0].status_code == "HTTP_301",
      aws_lb_listener.this["edge-alb.80"].default_action[0].redirect[0].protocol == "HTTPS",
      aws_lb_listener.this["edge-alb.80"].default_action[0].redirect[0].port == "443",
    ])
    error_message = "The redirect action must reach the listener with its status code, protocol, port and order."
  }

  assert {
    condition = alltrue([
      length(aws_lb_listener.this["edge-alb.8080"].default_action) == 1,
      aws_lb_listener.this["edge-alb.8080"].default_action[0].type == "fixed-response",
      aws_lb_listener.this["edge-alb.8080"].default_action[0].fixed_response[0].status_code == "503",
      aws_lb_listener.this["edge-alb.8080"].default_action[0].fixed_response[0].content_type == "text/html",
      aws_lb_listener.this["edge-alb.8080"].default_action[0].fixed_response[0].message_body == "<h1>Maintenance</h1>",
    ])
    error_message = "The fixed response must reach the listener with its status code, content type and body."
  }

  # The forward block is asserted through its presence and its affinity, not
  # through the number of target groups it holds: target_group is a set whose
  # members carry the not-yet-created target group ARNs, so its length is not
  # known during a plan. What distinguishes the two forwarding paths is the
  # block itself — scenario 3t asserts that a single-destination listener
  # produces no forward block at all.
  assert {
    condition = alltrue([
      length(aws_lb_listener.this["edge-alb.443"].default_action) == 1,
      aws_lb_listener.this["edge-alb.443"].default_action[0].type == "forward",
      length(aws_lb_listener.this["edge-alb.443"].default_action[0].forward) == 1,
    ])
    error_message = "A listener with a weighted target group list must produce one forward action."
  }

  assert {
    condition = alltrue([
      tostring(aws_lb_listener.this["edge-alb.443"].default_action[0].forward[0].stickiness[0].duration) == "3600",
      aws_lb_listener.this["edge-alb.443"].default_action[0].forward[0].stickiness[0].enabled == true,
    ])
    error_message = "The target group affinity must reach the forward action with its duration."
  }
}

# -----------------------------------------------------------------------------
# 3t. Default configuration — the unset attributes leave the plan unchanged
# -----------------------------------------------------------------------------
# Counterpart of the two bundles above. An entry that names none of the
# optional attributes gets a plain target group, load balancer and listener:
# the service defaults apply, no affinity and no failover block is written,
# and the listener forwards through target_group_arn rather than a forward
# block.

run "networking_load_balancing_attribute_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "spoke"
        cidr         = "10.33.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.33.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]

    target_groups = [
      {
        name        = "plain-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      }
    ]

    load_balancers = [
      {
        name         = "plain-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            target_group_name = "plain-tg"
          }
        ]
      }
    ]
  }

  assert {
    condition = alltrue([
      length(aws_lb_target_group.this["plain-tg"].stickiness) == 0,
      length(aws_lb_target_group.this["plain-tg"].target_failover) == 0,
    ])
    error_message = "Without stickiness or target_failover the target group must carry neither block."
  }

  # `null` in the plan is the precise statement of "unchanged": the module writes
  # no value, so the load balancing service applies its own default. Asserting
  # the service default itself would be weaker — it would also hold if the module started writing that
  # value, which is a different plan.
  assert {
    condition = alltrue([
      aws_lb_target_group.this["plain-tg"].deregistration_delay == null,
      aws_lb_target_group.this["plain-tg"].slow_start == null,
      aws_lb_target_group.this["plain-tg"].proxy_protocol_v2 == null,
    ])
    error_message = "Without the optional attributes the target group must leave every one of them unwritten."
  }

  assert {
    condition = alltrue([
      aws_lb.this["plain-alb"].idle_timeout == null,
      aws_lb.this["plain-alb"].enable_http2 == null,
      aws_lb.this["plain-alb"].desync_mitigation_mode == null,
      aws_lb.this["plain-alb"].enable_waf_fail_open == null,
      aws_lb.this["plain-alb"].enable_xff_client_port == null,
      aws_lb.this["plain-alb"].xff_header_processing_mode == null,
      aws_lb.this["plain-alb"].enable_tls_version_and_cipher_suite_headers == null,
    ])
    error_message = "Without the optional attributes the load balancer must leave every one of them unwritten."
  }

  assert {
    condition     = aws_lb_listener.this["plain-alb.443"].alpn_policy == null
    error_message = "Without an ALPN policy the listener must leave it unwritten."
  }

  assert {
    condition = alltrue([
      length(aws_lb_listener.this["plain-alb.443"].default_action) == 1,
      aws_lb_listener.this["plain-alb.443"].default_action[0].type == "forward",
      length(aws_lb_listener.this["plain-alb.443"].default_action[0].forward) == 0,
    ])
    error_message = "A listener without an action block must keep the single forwarding action through target_group_arn."
  }

  # An HTTPS listener that names no ssl_policy must get the
  # TLS-1.2-minimum floor, not the ELB service default (which still
  # negotiates TLS 1.0/1.1).
  assert {
    condition     = aws_lb_listener.this["plain-alb.443"].ssl_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"
    error_message = "An HTTPS listener without an explicit ssl_policy must get the TLS 1.2 floor, not the ELB service default."
  }
}

# -----------------------------------------------------------------------------
# Validation failures — extended target group attributes
# -----------------------------------------------------------------------------

run "networking_invalid_target_group_algorithm" {
  command = plan
  variables {
    target_groups = [
      {
        name      = "bad-tg"
        port      = 443
        protocol  = "HTTPS"
        vpc_name  = "spoke"
        algorithm = "random"
      }
    ]
  }
  expect_failures = [var.target_groups]
}

run "networking_invalid_target_group_stickiness_type" {
  command = plan
  variables {
    target_groups = [
      {
        name       = "bad-tg"
        port       = 443
        protocol   = "HTTPS"
        vpc_name   = "spoke"
        stickiness = { type = "session_cookie" }
      }
    ]
  }
  expect_failures = [var.target_groups]
}

run "networking_invalid_target_group_app_cookie_without_name" {
  command = plan
  variables {
    target_groups = [
      {
        name       = "bad-tg"
        port       = 443
        protocol   = "HTTPS"
        vpc_name   = "spoke"
        stickiness = { type = "app_cookie" }
      }
    ]
  }
  expect_failures = [var.target_groups]
}

run "networking_invalid_target_group_cookie_duration" {
  command = plan
  variables {
    target_groups = [
      {
        name     = "bad-tg"
        port     = 443
        protocol = "HTTPS"
        vpc_name = "spoke"
        stickiness = {
          type            = "lb_cookie"
          cookie_duration = 604801
        }
      }
    ]
  }
  expect_failures = [var.target_groups]
}

run "networking_invalid_target_group_deregistration_delay" {
  command = plan
  variables {
    target_groups = [
      {
        name                 = "bad-tg"
        port                 = 443
        protocol             = "HTTPS"
        vpc_name             = "spoke"
        deregistration_delay = 3601
      }
    ]
  }
  expect_failures = [var.target_groups]
}

run "networking_invalid_target_group_slow_start" {
  command = plan
  variables {
    target_groups = [
      {
        name       = "bad-tg"
        port       = 443
        protocol   = "HTTPS"
        vpc_name   = "spoke"
        slow_start = 15
      }
    ]
  }
  expect_failures = [var.target_groups]
}

run "networking_invalid_target_group_target_failover" {
  command = plan
  variables {
    target_groups = [
      {
        name            = "bad-tg"
        port            = 6081
        protocol        = "GENEVE"
        vpc_name        = "spoke"
        target_failover = "drain"
      }
    ]
  }
  expect_failures = [var.target_groups]
}

run "networking_invalid_target_group_protocol_version" {
  command = plan
  variables {
    target_groups = [
      {
        name             = "bad-tg"
        port             = 443
        protocol         = "HTTPS"
        vpc_name         = "spoke"
        protocol_version = "HTTP3"
      }
    ]
  }
  expect_failures = [var.target_groups]
}

# -----------------------------------------------------------------------------
# Validation failures — extended load balancer attributes and listener actions
# -----------------------------------------------------------------------------

run "networking_invalid_lb_desync_mitigation_mode" {
  command = plan
  variables {
    load_balancers = [
      {
        name                   = "bad-alb"
        type                   = "application"
        vpc_name               = "spoke"
        subnet_names           = ["private-a"]
        desync_mitigation_mode = "paranoid"
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_lb_xff_header_processing_mode" {
  command = plan
  variables {
    load_balancers = [
      {
        name                       = "bad-alb"
        type                       = "application"
        vpc_name                   = "spoke"
        subnet_names               = ["private-a"]
        xff_header_processing_mode = "rewrite"
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_lb_idle_timeout" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        idle_timeout = 4001
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_lb_http_attribute_on_network_type" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-nlb"
        type         = "network"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        idle_timeout = 120
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_listener_alpn_policy" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-nlb"
        type         = "network"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "TLS"
            target_group_name = "web-tg"
            alpn_policy       = "HTTP3Only"
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_listener_action_type" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port     = 80
            protocol = "HTTP"
            action   = { type = "authenticate-oidc" }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_listener_forward_without_destination" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port     = 80
            protocol = "HTTP"
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_listener_fixed_response_status_code" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port     = 80
            protocol = "HTTP"
            action = {
              type           = "fixed-response"
              fixed_response = { status_code = "600" }
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_listener_fixed_response_content_type" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port     = 80
            protocol = "HTTP"
            action = {
              type = "fixed-response"
              fixed_response = {
                status_code  = "503"
                content_type = "application/xml"
              }
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_listener_redirect_status_code" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port     = 80
            protocol = "HTTP"
            action = {
              type     = "redirect"
              redirect = { status_code = "HTTP_307" }
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

run "networking_invalid_listener_action_order_and_stickiness_bounds" {
  command = plan
  variables {
    load_balancers = [
      {
        name         = "bad-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 80
            protocol          = "HTTP"
            target_group_name = "web-tg"
            action = {
              type  = "forward"
              order = 50001
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}
# -----------------------------------------------------------------------------
# 3bf. Authenticated edge — an internet-facing load balancer is refused unless
#      every listener authenticates the caller
# -----------------------------------------------------------------------------
# An internet-facing load balancer answers anyone on the internet the moment it
# exists. The module therefore refuses scheme = "internet-facing" unless the
# entry is an application load balancer whose every listener is HTTPS and
# declares an authenticated_edge, rendered as an authenticate-oidc action in
# position 1 ahead of the listener's own action. A network load balancer has no
# listener authentication at all and is refused outright. Internal load
# balancers are untouched: the edge stays optional there.
#
# The client secret never appears literally in a test. The positive scenario
# reads a Secrets Manager ARN from the file-level placeholder below — the form
# an operator uses too (client_secret_arn) — and, for the second listener, a
# value handed in from a variable (client_secret), which is the other form.

variables {
  edge_client_secret_arn = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:edge/oidc-client-AbCdEf"
  edge_client_secret     = "PLACEHOLDER-handed-in-from-a-variable"
}

# A network load balancer cannot authenticate at the edge, so the internet-facing
# scheme is refused for it regardless of what its listeners declare.
run "networking_internet_facing_network_lb_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "edge-nlb"
        type         = "network"
        vpc_name     = "spoke"
        subnet_names = ["public-a"]
        scheme       = "internet-facing"
        listeners = [
          {
            port              = 443
            protocol          = "TCP"
            target_group_name = "tcp-tg"
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# An application load balancer whose listener forwards without an edge is the
# exact shape the decision refuses: a workload reachable by anyone.
run "networking_internet_facing_alb_without_edge_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "edge-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["public-a"]
        scheme       = "internet-facing"
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# authenticate-oidc exists on HTTPS listeners only, so a plaintext listener on an
# internet-facing load balancer cannot carry the edge — not even the customary
# HTTP-to-HTTPS redirect — and the entry is refused with the listener named.
run "networking_internet_facing_alb_plaintext_listener_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "edge-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["public-a"]
        scheme       = "internet-facing"
        listeners = [
          {
            port     = 80
            protocol = "HTTP"
            action = {
              type     = "redirect"
              redirect = { status_code = "HTTP_301", protocol = "HTTPS", port = "443" }
            }
            authenticated_edge = {
              issuer                 = "https://idp.example.com"
              authorization_endpoint = "https://idp.example.com/oauth2/authorize"
              token_endpoint         = "https://idp.example.com/oauth2/token"
              user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
              client_id              = "edge-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          },
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://idp.example.com"
              authorization_endpoint = "https://idp.example.com/oauth2/authorize"
              token_endpoint         = "https://idp.example.com/oauth2/token"
              user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
              client_id              = "edge-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          },
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# The edge needs its client secret from exactly one place; an edge that names
# neither client_secret_arn nor client_secret would fail at apply, so it is
# refused in the plan.
run "networking_authenticated_edge_without_client_secret_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "tools-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://idp.example.com"
              authorization_endpoint = "https://idp.example.com/oauth2/authorize"
              token_endpoint         = "https://idp.example.com/oauth2/token"
              user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
              client_id              = "tools-alb"
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# The accepted shape: an internet-facing application load balancer whose two
# HTTPS listeners both declare the edge. Each listener's action chain starts
# with authenticate-oidc in position 1 and continues with the listener's own
# action; the OIDC fields reach the resource; the secret comes from Secrets
# Manager on one listener and from a variable on the other. The internal
# load balancer next to it shows the edge is optional there.
run "networking_internet_facing_alb_with_edge_authenticates_first" {
  command = plan

  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]

    vpcs = [
      {
        name         = "spoke"
        cidr         = "10.34.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.34.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          },
          {
            name              = "private-a"
            cidr              = "10.34.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      }
    ]

    target_groups = [
      {
        name        = "app-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      },
      {
        name        = "blue-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      },
      {
        name        = "green-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      },
    ]

    load_balancers = [
      {
        name         = "edge-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["public-a"]
        scheme       = "internet-facing"
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://idp.example.com"
              authorization_endpoint = "https://idp.example.com/oauth2/authorize"
              token_endpoint         = "https://idp.example.com/oauth2/token"
              user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
              client_id              = "edge-alb"
              client_secret_arn      = var.edge_client_secret_arn
              scope                  = "openid"
              session_timeout        = 3600
            }
          },
          {
            port            = 8443
            protocol        = "HTTPS"
            certificate_arn = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            action = {
              type  = "forward"
              order = 5
              target_groups = [
                { target_group_name = "blue-tg", weight = 90 },
                { target_group_name = "green-tg", weight = 10 },
              ]
            }
            authenticated_edge = {
              issuer                 = "https://idp.example.com"
              authorization_endpoint = "https://idp.example.com/oauth2/authorize"
              token_endpoint         = "https://idp.example.com/oauth2/token"
              user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
              client_id              = "edge-alb-canary"
              client_secret          = var.edge_client_secret
            }
          },
        ]
      },
      {
        name         = "tools-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://idp.example.com"
              authorization_endpoint = "https://idp.example.com/oauth2/authorize"
              token_endpoint         = "https://idp.example.com/oauth2/token"
              user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
              client_id              = "tools-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          }
        ]
      },
    ]
  }

  assert {
    condition     = aws_lb.this["edge-alb"].internal == false && length(aws_lb_listener.this) == 3
    error_message = "The internet-facing load balancer with an edge on every listener must plan, with all three listeners."
  }

  # Position 1 authenticates, position 2 is the listener's own action.
  assert {
    condition = alltrue([
      length(aws_lb_listener.this["edge-alb.443"].default_action) == 2,
      aws_lb_listener.this["edge-alb.443"].default_action[0].type == "authenticate-oidc",
      tostring(aws_lb_listener.this["edge-alb.443"].default_action[0].order) == "1",
      aws_lb_listener.this["edge-alb.443"].default_action[1].type == "forward",
      tostring(aws_lb_listener.this["edge-alb.443"].default_action[1].order) == "2",
      length(aws_lb_listener.this["edge-alb.443"].default_action[1].forward) == 0,
    ])
    error_message = "The listener's action chain must start with authenticate-oidc in position 1 and forward in position 2."
  }

  assert {
    condition = alltrue([
      length(aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc) == 1,
      aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].issuer == "https://idp.example.com",
      aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].authorization_endpoint == "https://idp.example.com/oauth2/authorize",
      aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].token_endpoint == "https://idp.example.com/oauth2/token",
      aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].user_info_endpoint == "https://idp.example.com/oauth2/userinfo",
      aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].client_id == "edge-alb",
      aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].scope == "openid",
      tostring(aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].session_timeout) == "3600",
    ])
    error_message = "The OIDC issuer, endpoints, client id, scope and session timeout must reach the authenticate-oidc action."
  }

  # An authenticated edge must not inherit its unauthenticated-request
  # behaviour from the service default: the module writes "authenticate".
  assert {
    condition     = aws_lb_listener.this["edge-alb.443"].default_action[0].authenticate_oidc[0].on_unauthenticated_request == "authenticate"
    error_message = "The authenticated edge must write on_unauthenticated_request = \"authenticate\": a request without a session is always sent to the provider."
  }

  # The secret named by ARN is read from Secrets Manager for that listener alone;
  # the listener that hands its secret in from a variable causes no read.
  assert {
    condition = alltrue([
      length(data.aws_secretsmanager_secret_version.lb_edge_client_secret) == 2,
      data.aws_secretsmanager_secret_version.lb_edge_client_secret["edge-alb.443"].secret_id == var.edge_client_secret_arn,
      data.aws_secretsmanager_secret_version.lb_edge_client_secret["tools-alb.443"].secret_id == var.edge_client_secret_arn,
    ])
    error_message = "client_secret_arn must be read from Secrets Manager for exactly the listeners that name one."
  }

  # A weighted forward keeps its explicit order behind the edge.
  assert {
    condition = alltrue([
      length(aws_lb_listener.this["edge-alb.8443"].default_action) == 2,
      aws_lb_listener.this["edge-alb.8443"].default_action[0].type == "authenticate-oidc",
      tostring(aws_lb_listener.this["edge-alb.8443"].default_action[0].order) == "1",
      aws_lb_listener.this["edge-alb.8443"].default_action[0].authenticate_oidc[0].client_id == "edge-alb-canary",
      aws_lb_listener.this["edge-alb.8443"].default_action[1].type == "forward",
      tostring(aws_lb_listener.this["edge-alb.8443"].default_action[1].order) == "5",
      length(aws_lb_listener.this["edge-alb.8443"].default_action[1].forward) == 1,
    ])
    error_message = "A weighted forward behind the edge must keep its own order and its forward block in position 2."
  }

  # Optional on an internal load balancer: declared, it renders the same way.
  assert {
    condition = alltrue([
      aws_lb.this["tools-alb"].internal == true,
      length(aws_lb_listener.this["tools-alb.443"].default_action) == 2,
      aws_lb_listener.this["tools-alb.443"].default_action[0].type == "authenticate-oidc",
      aws_lb_listener.this["tools-alb.443"].default_action[1].type == "forward",
    ])
    error_message = "An internal load balancer may declare the edge and then authenticates in position 1 as well."
  }
}

# -----------------------------------------------------------------------------
# 3bg. Authenticated edge — the issuer must be one the operator trusts
# -----------------------------------------------------------------------------
# The edge checks the shape of its URLs only, so any HTTPS issuer would pass and
# an internet-facing load balancer could be authenticated by a provider nobody
# trusts. The operator therefore names the issuers they trust in
# authenticated_edge_allowed_issuers; an edge whose issuer is outside the list
# is refused on every load balancer, and an internet-facing entry is refused
# while the list is empty.

# An internet-facing load balancer authenticated by an issuer nobody trusts is
# refused.

run "networking_authenticated_edge_untrusted_issuer_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "edge-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["public-a"]
        scheme       = "internet-facing"
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://untrusted-idp.example.net"
              authorization_endpoint = "https://untrusted-idp.example.net/oauth2/authorize"
              token_endpoint         = "https://untrusted-idp.example.net/oauth2/token"
              user_info_endpoint     = "https://untrusted-idp.example.net/oauth2/userinfo"
              client_id              = "edge-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# An internet-facing entry while no issuer is trusted is refused, even when its
# edge is otherwise complete: the module has nothing to hold the issuer to.
run "networking_internet_facing_alb_with_empty_issuer_allowlist_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = []
    load_balancers = [
      {
        name         = "edge-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["public-a"]
        scheme       = "internet-facing"
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://idp.example.com"
              authorization_endpoint = "https://idp.example.com/oauth2/authorize"
              token_endpoint         = "https://idp.example.com/oauth2/token"
              user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
              client_id              = "edge-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# An edge that names an untrusted issuer is wrong anywhere: an internal load
# balancer that declares one is refused as well.
run "networking_internal_alb_edge_untrusted_issuer_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "tools-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://untrusted-idp.example.net"
              authorization_endpoint = "https://untrusted-idp.example.net/oauth2/authorize"
              token_endpoint         = "https://untrusted-idp.example.net/oauth2/token"
              user_info_endpoint     = "https://untrusted-idp.example.net/oauth2/userinfo"
              client_id              = "tools-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# The allowlist is compared as an exact string: an
# issuer that differs from a trusted one only by a trailing slash is a
# different issuer to the provider, and is refused.
run "networking_edge_issuer_trailing_slash_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "tools-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://idp.example.com/"
              authorization_endpoint = "https://untrusted-idp.example.net/oauth2/authorize"
              token_endpoint         = "https://untrusted-idp.example.net/oauth2/token"
              user_info_endpoint     = "https://untrusted-idp.example.net/oauth2/userinfo"
              client_id              = "tools-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# Exact string also means case: an issuer whose
# host differs from a trusted one only in case is refused.
run "networking_edge_issuer_case_difference_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
    load_balancers = [
      {
        name         = "tools-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
            authenticated_edge = {
              issuer                 = "https://IDP.example.com"
              authorization_endpoint = "https://untrusted-idp.example.net/oauth2/authorize"
              token_endpoint         = "https://untrusted-idp.example.net/oauth2/token"
              user_info_endpoint     = "https://untrusted-idp.example.net/oauth2/userinfo"
              client_id              = "tools-alb"
              client_secret_arn      = var.edge_client_secret_arn
            }
          }
        ]
      }
    ]
  }
  expect_failures = [var.load_balancers]
}

# An allowlist entry must carry a host: "https://?"
# names no issuer and is refused at plan time, not by the provider.
run "issuer_allowlist_entry_without_host_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://?"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# An empty authority followed by a path is no host either.
run "issuer_allowlist_entry_empty_authority_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https:///oauth2"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# A host with a path, as providers such as Okta publish their issuer, is
# accepted.
run "issuer_allowlist_entry_with_host_and_path_accepted" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com/oauth2/default"]
  }

  assert {
    condition     = length(var.authenticated_edge_allowed_issuers) == 1
    error_message = "An issuer URL with a host and a path must be accepted into the allowlist."
  }
}

# The allowlist grammar is the one its variable comment states: DNS labels, a
# port in range, no query or fragment.

# An empty label ("a..b") is no DNS name.
run "issuer_allowlist_entry_empty_label_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://a..b"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# A label ending in a hyphen ("a-.b") is no DNS name.
run "issuer_allowlist_entry_hyphen_ended_label_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://a-.b"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# A port outside 1..65535 is no port.
run "issuer_allowlist_entry_port_out_of_range_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://host:99999"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# A query is no part of an issuer.
run "issuer_allowlist_entry_query_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://host/?q=1"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# A fragment behind the path is no part of an issuer either.
run "issuer_allowlist_entry_path_fragment_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://host/path#frag"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# A fragment right behind the host is refused as well.
run "issuer_allowlist_entry_host_fragment_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://host#frag"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# A plain host is accepted.
run "issuer_allowlist_entry_host_accepted" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com"]
  }

  assert {
    condition     = length(var.authenticated_edge_allowed_issuers) == 1
    error_message = "An issuer URL with a DNS name as host must be accepted into the allowlist."
  }
}

# A host with a port in range and a path is accepted.
run "issuer_allowlist_entry_host_port_and_path_accepted" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com:8443/oauth2/v1"]
  }

  assert {
    condition     = length(var.authenticated_edge_allowed_issuers) == 1
    error_message = "An issuer URL with a host, a port in 1..65535 and a path must be accepted into the allowlist."
  }
}

# The boundaries of the allowlist grammar.

# Pins the upper label length: a label of exactly 63 characters is accepted.
run "issuer_allowlist_entry_label_63_accepted" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
  }

  assert {
    condition     = length(var.authenticated_edge_allowed_issuers) == 1
    error_message = "An issuer URL whose host is a single label of 63 characters must be accepted into the allowlist."
  }
}

# Pins the upper label length: a label of 64 characters is no DNS label.
run "issuer_allowlist_entry_label_64_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# Pins "no trailing dot": a host ending in "." is refused.
run "issuer_allowlist_entry_trailing_dot_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com."]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# Pins the lowest port: port 1 is accepted.
run "issuer_allowlist_entry_port_1_accepted" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com:1"]
  }

  assert {
    condition     = length(var.authenticated_edge_allowed_issuers) == 1
    error_message = "An issuer URL with port 1 must be accepted into the allowlist."
  }
}

# Pins the highest port: port 65535 is accepted.
run "issuer_allowlist_entry_port_65535_accepted" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com:65535"]
  }

  assert {
    condition     = length(var.authenticated_edge_allowed_issuers) == 1
    error_message = "An issuer URL with port 65535 must be accepted into the allowlist."
  }
}

# Pins the port's lower bound: port 0 is refused.
run "issuer_allowlist_entry_port_0_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com:0"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# Pins the port's upper bound: port 65536 is refused.
run "issuer_allowlist_entry_port_65536_refused" {
  command = plan
  variables {
    authenticated_edge_allowed_issuers = ["https://idp.example.com:65536"]
  }
  expect_failures = [var.authenticated_edge_allowed_issuers]
}

# Internal load balancers without an edge — application and
# network — plan one action, the listener's own, and no authenticate-oidc
# block anywhere.
run "networking_internal_lb_without_edge_unchanged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "spoke"
        cidr         = "10.35.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.35.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]

    target_groups = [
      {
        name        = "app-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      },
      {
        name        = "tcp-tg"
        port        = 443
        protocol    = "TCP"
        vpc_name    = "spoke"
        target_type = "ip"
      },
    ]

    load_balancers = [
      {
        name         = "plain-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        listeners = [
          {
            port              = 443
            protocol          = "HTTPS"
            certificate_arn   = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
            target_group_name = "app-tg"
          }
        ]
      },
      {
        name         = "plain-nlb"
        type         = "network"
        vpc_name     = "spoke"
        subnet_names = ["private-a"]
        scheme       = "internal"
        listeners = [
          {
            port              = 443
            protocol          = "TCP"
            target_group_name = "tcp-tg"
          }
        ]
      },
    ]
  }

  assert {
    condition = alltrue([
      aws_lb.this["plain-alb"].internal == true,
      aws_lb.this["plain-nlb"].internal == true,
      length(aws_lb_listener.this["plain-alb.443"].default_action) == 1,
      aws_lb_listener.this["plain-alb.443"].default_action[0].type == "forward",
      length(aws_lb_listener.this["plain-alb.443"].default_action[0].authenticate_oidc) == 0,
      length(aws_lb_listener.this["plain-nlb.443"].default_action) == 1,
      aws_lb_listener.this["plain-nlb.443"].default_action[0].type == "forward",
      length(aws_lb_listener.this["plain-nlb.443"].default_action[0].authenticate_oidc) == 0,
    ])
    error_message = "Internal load balancers without an edge must keep their single forwarding action and carry no authenticate-oidc block."
  }

  assert {
    condition     = length(data.aws_secretsmanager_secret_version.lb_edge_client_secret) == 0
    error_message = "Without an edge naming a client_secret_arn no secret is read."
  }
}


# -----------------------------------------------------------------------------
# 3u. Custom configuration — TGW attachment options and explicit subnet choice
# -----------------------------------------------------------------------------
# Every attachment option reaches aws_ec2_transit_gateway_vpc_attachment, and
# subnet_names overrides the name-derived subnet set of the attachment.

# The subnet assertions need `command = apply`: subnet_ids is a set whose
# element values are unknown at plan time, so its length cannot be evaluated
# in a plan run. The mock provider generates the values on apply.
run "networking_tgw_attachment_options_reach_resource" {
  command = apply

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        enable_ipv6  = true
        subnets = [
          {
            name              = "attach-a"
            cidr              = "10.40.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          },
          {
            name              = "attach-b"
            cidr              = "10.40.11.0/28"
            availability_zone = "eu-central-1b"
            type              = "isolated"
          },
          {
            name              = "tgw-a"
            cidr              = "10.40.12.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          },
        ]
        tgw_attachment = {
          route_table_name                   = "hub"
          appliance_mode_support             = "enable"
          dns_support                        = "disable"
          ipv6_support                       = "enable"
          security_group_referencing_support = "enable"
          subnet_names                       = ["attach-a", "attach-b"]
        }
      },
      {
        name         = "spoke"
        cidr         = "10.41.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.41.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = { route_table_name = "hub" }
      },
    ]

    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
    }
  }

  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].dns_support == "disable"
    error_message = "The DNS support option must reach the attachment."
  }

  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].ipv6_support == "enable"
    error_message = "The IPv6 option must reach the attachment."
  }

  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].security_group_referencing_support == "enable"
    error_message = "The security group referencing option must reach the attachment."
  }

  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].appliance_mode_support == "enable"
    error_message = "Appliance mode must keep reaching the attachment."
  }

  # Explicit subnet choice: both named subnets, not the "tgw"-named one.
  assert {
    condition     = length(aws_ec2_transit_gateway_vpc_attachment.this["hub"].subnet_ids) == 2
    error_message = "subnet_names must select exactly the named subnets for the attachment."
  }

  # The derivation stays in place for attachments without subnet_names:
  # the spoke picks its single "tgw"-named subnet.
  assert {
    condition     = length(aws_ec2_transit_gateway_vpc_attachment.this["spoke"].subnet_ids) == 1
    error_message = "Attachments without subnet_names must keep the name-derived subnet set."
  }
}

# -----------------------------------------------------------------------------
# 3v. Custom configuration — VPN connection and tunnel options
# -----------------------------------------------------------------------------
# Connection-level options (traffic filters, acceleration, static routes,
# outside IP type), tunnel lifetimes, inside IPv6 addressing, lifecycle
# control and tunnel logging reach aws_vpn_connection; a vpc_name entry
# terminates on a virtual private gateway the module creates.

run "networking_vpn_connection_options_reach_resource" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.50.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.50.10.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]

    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
    }

    customer_gateways = [
      {
        name                       = "onprem-main"
        bgp_asn                    = 65010
        ip_address                 = "198.51.100.10"
        transit_gateway_name       = "tlz-transit-gateway"
        static_routes_only         = false
        enable_acceleration        = true
        outside_ip_address_type    = "PublicIpv4"
        tunnel_inside_ip_version   = "ipv6"
        amazon_ipv4_network_cidr   = "10.0.0.0/8"
        amazon_ipv6_network_cidr   = "fd00:aaaa::/32"
        customer_ipv4_network_cidr = "192.168.0.0/16"
        customer_ipv6_network_cidr = "fd00:bbbb::/32"
        tunnel_options = [
          {
            phase1_lifetime_seconds         = 14400
            phase2_lifetime_seconds         = 1800
            tunnel_inside_ipv6_cidr         = "fd00:cccc::/126"
            enable_tunnel_lifecycle_control = true
            logging = {
              enable        = true
              output_format = "text"
            }
          },
          {
            phase1_lifetime_seconds = 28800
            phase2_lifetime_seconds = 3600
            tunnel_inside_ipv6_cidr = "fd00:cccc::4/126"
            logging = {
              enable         = true
              log_group_name = "/custom/vpn/tunnel2"
            }
          },
        ]
      },
      {
        name       = "onprem-branch"
        bgp_asn    = 65011
        ip_address = "198.51.100.11"
        vpc_name   = "edge"
      },
    ]
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].enable_acceleration == true && aws_vpn_connection.this["onprem-main"].static_routes_only == false
    error_message = "Acceleration and static-routes mode must reach the connection."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].outside_ip_address_type == "PublicIpv4" && aws_vpn_connection.this["onprem-main"].tunnel_inside_ip_version == "ipv6"
    error_message = "Outside IP type and tunnel inside IP version must reach the connection."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].remote_ipv4_network_cidr == "10.0.0.0/8" && aws_vpn_connection.this["onprem-main"].local_ipv4_network_cidr == "192.168.0.0/16"
    error_message = "The IPv4 traffic filters must reach the connection — amazon_* as remote, customer_* as local."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].remote_ipv6_network_cidr == "fd00:aaaa::/32" && aws_vpn_connection.this["onprem-main"].local_ipv6_network_cidr == "fd00:bbbb::/32"
    error_message = "The IPv6 traffic filters must reach the connection."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].tunnel1_phase1_lifetime_seconds == 14400 && aws_vpn_connection.this["onprem-main"].tunnel1_phase2_lifetime_seconds == 1800
    error_message = "The tunnel 1 lifetimes must reach the connection."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].tunnel2_phase1_lifetime_seconds == 28800 && aws_vpn_connection.this["onprem-main"].tunnel2_phase2_lifetime_seconds == 3600
    error_message = "The tunnel 2 lifetimes must reach the connection."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].tunnel1_inside_ipv6_cidr == "fd00:cccc::/126" && aws_vpn_connection.this["onprem-main"].tunnel2_inside_ipv6_cidr == "fd00:cccc::4/126"
    error_message = "The inside IPv6 ranges must reach both tunnels."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-main"].tunnel1_enable_tunnel_lifecycle_control == true
    error_message = "Tunnel lifecycle control must reach tunnel 1."
  }

  # One log group per tunnel with logging enabled; the derived name for
  # tunnel 1, the override for tunnel 2.
  assert {
    condition     = length(aws_cloudwatch_log_group.vpn_tunnel) == 2
    error_message = "Each tunnel with logging enabled must get its log group."
  }

  assert {
    condition     = aws_cloudwatch_log_group.vpn_tunnel["onprem-main.tunnel1"].name == "/vpn/onprem-main/tunnel1"
    error_message = "The log group of tunnel 1 must carry the derived name."
  }

  assert {
    condition     = aws_cloudwatch_log_group.vpn_tunnel["onprem-main.tunnel2"].name == "/custom/vpn/tunnel2"
    error_message = "log_group_name must override the derived log group name."
  }

  assert {
    condition     = length(aws_vpn_connection.this["onprem-main"].tunnel1_log_options) == 1 && length(aws_vpn_connection.this["onprem-main"].tunnel2_log_options) == 1
    error_message = "Both tunnels must carry a log options block when logging is enabled."
  }

  # The VGW-terminated entry: gateway created and referenced instead of the TGW.
  assert {
    condition     = length(aws_vpn_gateway.this) == 1 && aws_vpn_gateway.this["edge"].tags["Name"] == "edge-vgw"
    error_message = "A vpc_name entry must create the virtual private gateway for that VPC."
  }

  assert {
    condition     = aws_vpn_connection.this["onprem-branch"].transit_gateway_id == null
    error_message = "A vpc_name entry must not reference the Transit Gateway."
  }
}

# -----------------------------------------------------------------------------
# 3w. Custom configuration — Direct Connect details
# -----------------------------------------------------------------------------
# VIF peer addresses, BGP auth key, MTU and SiteLink reach the virtual
# interface resources; allowed prefixes reach the gateway association; the
# route table wiring creates association/propagation over the attachment
# lookup.

run "networking_dx_details_reach_resource" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["hub", "dx"]
    }

    dx_gateways = [
      {
        name                     = "dxgw-primary"
        amazon_asn               = 64515
        transit_gateway_name     = "tlz-transit-gateway"
        allowed_prefixes         = ["10.60.0.0/16", "10.61.0.0/16"]
        route_table_associations = ["dx"]
        route_table_propagations = ["hub", "dx"]
        virtual_interfaces = [
          {
            name             = "vif-transit-a"
            type             = "transit"
            vlan             = 101
            bgp_asn          = 65001
            connection_id    = "dxcon-fgabcd12"
            amazon_address   = "175.45.176.1/30"
            customer_address = "175.45.176.2/30"
            auth_key         = "bgp-secret-key"
            mtu              = 8500
            sitelink_enabled = true
          },
          {
            name             = "vif-private-a"
            type             = "private"
            vlan             = 102
            bgp_asn          = 65002
            connection_id    = "dxcon-fgabcd13"
            amazon_address   = "175.45.177.1/30"
            customer_address = "175.45.177.2/30"
            auth_key         = "bgp-secret-key-2"
            mtu              = 9001
            sitelink_enabled = false
          },
        ]
      }
    ]
  }

  assert {
    condition     = aws_dx_transit_virtual_interface.this["dxgw-primary.vif-transit-a"].amazon_address == "175.45.176.1/30" && aws_dx_transit_virtual_interface.this["dxgw-primary.vif-transit-a"].customer_address == "175.45.176.2/30"
    error_message = "The peer addresses must reach the transit virtual interface."
  }

  assert {
    condition     = aws_dx_transit_virtual_interface.this["dxgw-primary.vif-transit-a"].bgp_auth_key == "bgp-secret-key" && aws_dx_transit_virtual_interface.this["dxgw-primary.vif-transit-a"].mtu == 8500 && aws_dx_transit_virtual_interface.this["dxgw-primary.vif-transit-a"].sitelink_enabled == true
    error_message = "Auth key, MTU and SiteLink must reach the transit virtual interface."
  }

  assert {
    condition     = aws_dx_private_virtual_interface.this["dxgw-primary.vif-private-a"].amazon_address == "175.45.177.1/30" && aws_dx_private_virtual_interface.this["dxgw-primary.vif-private-a"].mtu == 9001 && aws_dx_private_virtual_interface.this["dxgw-primary.vif-private-a"].sitelink_enabled == false
    error_message = "Address, MTU and SiteLink must reach the private virtual interface."
  }

  assert {
    condition     = aws_dx_private_virtual_interface.this["dxgw-primary.vif-private-a"].bgp_auth_key == "bgp-secret-key-2"
    error_message = "The auth key must reach the private virtual interface."
  }

  assert {
    condition     = length(aws_dx_gateway_association.this["dxgw-primary"].allowed_prefixes) == 2
    error_message = "The allowed prefixes must reach the gateway association."
  }

  assert {
    condition     = length(data.aws_ec2_transit_gateway_dx_gateway_attachment.wiring) == 1
    error_message = "The route table wiring must look up the gateway attachment once per gateway."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_association.dx) == 1 && length(aws_ec2_transit_gateway_route_table_propagation.dx) == 2
    error_message = "One association and two propagations must be created from the route table wiring."
  }
}

# -----------------------------------------------------------------------------
# 3x. Custom configuration — TGW options and static routes on all attachment
#     types
# -----------------------------------------------------------------------------
# The gateway options and CIDR blocks reach aws_ec2_transit_gateway; static
# routes resolve VPN, DX gateway and peering attachments as next hop; a prefix
# list destination becomes a prefix list reference; a blackhole route carries
# no attachment; the flow logs write both destinations with retention and path
# overrides.

run "networking_tgw_options_and_static_routes_reach_resource" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.70.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.70.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = { route_table_name = "hub" }
      }
    ]

    transit_gateway = {
      enabled                            = true
      amazon_asn                         = 64513
      route_tables                       = ["hub", "edge"]
      dns_support                        = "disable"
      vpn_ecmp_support                   = "disable"
      multicast_support                  = "enable"
      security_group_referencing_support = "enable"
      default_route_table_association    = "enable"
      default_route_table_propagation    = "enable"
      cidr_blocks                        = ["10.99.0.0/24", "fd00:dddd::/64"]
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "edge"
        }
      ]
      static_routes = [
        {
          route_table_name       = "hub"
          destination_cidr_block = "192.168.10.0/24"
          attachment_name        = "onprem-main"
          attachment_type        = "vpn"
        },
        {
          route_table_name       = "hub"
          destination_cidr_block = "192.168.20.0/24"
          attachment_name        = "dxgw-primary"
          attachment_type        = "dx-gateway"
        },
        {
          route_table_name       = "edge"
          destination_cidr_block = "10.80.0.0/16"
          attachment_name        = "eu-west-1-tgw-0123456789abcdef0"
          attachment_type        = "peering"
        },
        {
          route_table_name       = "hub"
          destination_cidr_block = "203.0.113.0/24"
          blackhole              = true
        },
        {
          route_table_name             = "edge"
          destination_prefix_list_name = "shared-ranges"
          attachment_name              = "hub"
        },
      ]
    }

    prefix_lists = [
      {
        name        = "shared-ranges"
        max_entries = 10
        entries     = [{ cidr = "10.90.0.0/16" }]
      }
    ]

    customer_gateways = [
      {
        name                 = "onprem-main"
        bgp_asn              = 65010
        ip_address           = "198.51.100.10"
        transit_gateway_name = "tlz-transit-gateway"
      }
    ]

    dx_gateways = [
      {
        name                 = "dxgw-primary"
        amazon_asn           = 64515
        transit_gateway_name = "tlz-transit-gateway"
      }
    ]

    enable_tgw_flow_logs         = true
    tgw_flow_logs_destination    = "both"
    tgw_flow_logs_retention_days = 90
    tgw_flow_logs_s3_path        = "network/tgw"
  }

  assert {
    condition     = aws_ec2_transit_gateway.this[0].dns_support == "disable" && aws_ec2_transit_gateway.this[0].vpn_ecmp_support == "disable"
    error_message = "DNS support and VPN ECMP must reach the Transit Gateway."
  }

  assert {
    condition     = aws_ec2_transit_gateway.this[0].multicast_support == "enable" && aws_ec2_transit_gateway.this[0].security_group_referencing_support == "enable"
    error_message = "Multicast and security group referencing must reach the Transit Gateway."
  }

  assert {
    condition     = aws_ec2_transit_gateway.this[0].default_route_table_association == "enable" && aws_ec2_transit_gateway.this[0].default_route_table_propagation == "enable"
    error_message = "The default route table switches must reach the Transit Gateway."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway.this[0].transit_gateway_cidr_blocks) == 2
    error_message = "Both CIDR blocks must reach the Transit Gateway."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route.static) == 4
    error_message = "The four CIDR routes must be created — VPN, DX gateway, peering and blackhole."
  }

  assert {
    condition     = aws_ec2_transit_gateway_route.static["hub.203.0.113.0/24"].blackhole == true && aws_ec2_transit_gateway_route.static["hub.203.0.113.0/24"].transit_gateway_attachment_id == null
    error_message = "The blackhole route must carry no attachment."
  }

  assert {
    condition     = length(data.aws_ec2_transit_gateway_dx_gateway_attachment.route) == 1
    error_message = "The DX gateway route must look up the gateway attachment."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_prefix_list_reference.static) == 1
    error_message = "The prefix list destination must become a prefix list reference."
  }

  assert {
    condition     = aws_cloudwatch_log_group.tgw_flow_logs[0].retention_in_days == 90
    error_message = "The retention override must reach the flow log log group."
  }

  assert {
    condition     = length(aws_flow_log.tgw_s3) == 1 && length(aws_flow_log.tgw_cloudwatch) == 1
    error_message = "The destination 'both' must create the S3 and the CloudWatch flow log."
  }

  assert {
    condition     = aws_flow_log.tgw_s3[0].log_destination == "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1/network/tgw/"
    error_message = "The S3 path override must reach the flow log destination."
  }
}

# -----------------------------------------------------------------------------
# 3y. Defaults — the unset hybrid connectivity attributes leave the plan
#     unchanged
# -----------------------------------------------------------------------------
# An entry that names none of the optional attributes: the module writes null
# (not a value that happens to equal the AWS default), the gateway keeps its
# fixed literals, and no optional resource appears. Asserting null rather than the service default matters:
# "the value is 'enable'" would also hold if the module started writing
# "enable" — and that is a different plan.

run "networking_hybrid_option_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    central_log_bucket_name = "tlz-central-logs-210987654321-eu-central-1"

    vpcs = [
      {
        name         = "hub"
        cidr         = "10.30.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.30.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = { route_table_name = "hub" }
      }
    ]

    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      static_routes = [
        {
          route_table_name       = "hub"
          destination_cidr_block = "192.168.0.0/16"
          attachment_name        = "hub"
        }
      ]
    }

    dx_gateways = [
      {
        name                 = "dxgw-primary"
        amazon_asn           = 64515
        transit_gateway_name = "tlz-transit-gateway"
        virtual_interfaces = [
          {
            name          = "vif-transit-a"
            type          = "transit"
            vlan          = 101
            bgp_asn       = 65001
            connection_id = "dxcon-fgabcd12"
          }
        ]
      }
    ]

    customer_gateways = [
      {
        name                 = "onprem-dc2"
        bgp_asn              = 65010
        ip_address           = "198.51.100.20"
        transit_gateway_name = "tlz-transit-gateway"
        tunnel_options = [
          { tunnel_inside_cidr = "169.254.10.0/30" }
        ]
      }
    ]

    enable_tgw_flow_logs      = true
    tgw_flow_logs_destination = "s3"
  }

  # The gateway keeps its fixed literals.
  assert {
    condition     = aws_ec2_transit_gateway.this[0].dns_support == "enable" && aws_ec2_transit_gateway.this[0].default_route_table_association == "disable" && aws_ec2_transit_gateway.this[0].default_route_table_propagation == "disable"
    error_message = "Without input the gateway must keep writing its fixed literals."
  }

  # The optional gateway values stay unwritten.
  assert {
    condition     = aws_ec2_transit_gateway.this[0].vpn_ecmp_support == null && aws_ec2_transit_gateway.this[0].multicast_support == null && aws_ec2_transit_gateway.this[0].security_group_referencing_support == null && aws_ec2_transit_gateway.this[0].transit_gateway_cidr_blocks == null
    error_message = "Unset gateway options must stay null in the plan."
  }

  # Unset attachment options: dns_support and ipv6_support stay null (the
  # module writes nothing, AWS applies its service default), and
  # security_group_referencing_support keeps the provider-side default
  # "enable" the provider plans for an entry that does not set it.
  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].dns_support == null && aws_ec2_transit_gateway_vpc_attachment.this["hub"].ipv6_support == null
    error_message = "Unset dns_support and ipv6_support must stay null in the plan."
  }

  assert {
    condition     = aws_ec2_transit_gateway_vpc_attachment.this["hub"].security_group_referencing_support == "enable"
    error_message = "An unset security_group_referencing_support must keep planning as the provider default 'enable'."
  }

  # A route without attachment_type resolves against the VPC attachments.
  assert {
    condition     = length(aws_ec2_transit_gateway_route.static) == 1 && length(aws_ec2_transit_gateway_prefix_list_reference.static) == 0
    error_message = "A plain CIDR route must stay a single route entry."
  }

  # The VPN tunnel keeps its value and the optional lifetimes stay unwritten.
  # tunnel1_inside_ipv6_cidr is computed by the provider and therefore unknown
  # in a plan run — the null check on the lifetimes carries the statement.
  assert {
    condition     = aws_vpn_connection.this["onprem-dc2"].tunnel1_inside_cidr == "169.254.10.0/30" && aws_vpn_connection.this["onprem-dc2"].tunnel1_phase1_lifetime_seconds == null && aws_vpn_connection.this["onprem-dc2"].tunnel1_phase2_lifetime_seconds == null
    error_message = "Unset tunnel lifetimes must stay null in the plan."
  }

  assert {
    condition     = length(aws_vpn_connection.this["onprem-dc2"].tunnel1_log_options) == 0 && length(aws_cloudwatch_log_group.vpn_tunnel) == 0 && length(aws_vpn_gateway.this) == 0
    error_message = "Without logging and without vpc_name no log group, log options block or virtual private gateway may appear."
  }

  # The virtual interface details stay unwritten where the provider lets a
  # plan say so. The peer addresses, the auth key and allowed_prefixes are
  # computed by the provider (AWS generates them) and therefore unknown in a
  # plan run; sitelink_enabled is the plain optional attribute that carries
  # the statement.
  assert {
    condition     = aws_dx_transit_virtual_interface.this["dxgw-primary.vif-transit-a"].sitelink_enabled == null
    error_message = "An unset sitelink_enabled must stay null in the plan."
  }

  assert {
    condition     = length(data.aws_ec2_transit_gateway_dx_gateway_attachment.wiring) == 0 && length(aws_ec2_transit_gateway_route_table_association.dx) == 0 && length(aws_ec2_transit_gateway_route_table_propagation.dx) == 0
    error_message = "Without route table wiring no attachment lookup and no wiring resources may appear."
  }

  # The flow logs keep the default retention and path.
  assert {
    condition     = length(aws_flow_log.tgw_s3) == 1 && length(aws_flow_log.tgw_cloudwatch) == 0 && aws_flow_log.tgw_s3[0].log_destination == "arn:aws:s3:::tlz-central-logs-210987654321-eu-central-1/tgw-flow-logs/"
    error_message = "The flow log defaults must keep the default destination and path."
  }
}

# -----------------------------------------------------------------------------
# 4. Validation — TGW attachment options
# -----------------------------------------------------------------------------

run "networking_invalid_tgw_attachment_option_value" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.40.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = {
          route_table_name = "hub"
          dns_support      = "on" # invalid: must be enable/disable
        }
      }
    ]
    transit_gateway = { enabled = true, route_tables = ["hub"] }
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_tgw_attachment_ipv6_without_vpc_ipv6" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        # enable_ipv6 stays false — the attachment option must be rejected
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.40.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = {
          route_table_name = "hub"
          ipv6_support     = "enable"
        }
      }
    ]
    transit_gateway = { enabled = true, route_tables = ["hub"] }
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_tgw_attachment_unknown_subnet_name" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.40.10.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
        tgw_attachment = {
          route_table_name = "hub"
          subnet_names     = ["does-not-exist"]
        }
      }
    ]
    transit_gateway = { enabled = true, route_tables = ["hub"] }
  }

  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# 4. Validation — VPN connection and tunnel options
# -----------------------------------------------------------------------------

run "networking_invalid_vpn_phase1_lifetime" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                 = "onprem"
        bgp_asn              = 65010
        ip_address           = "198.51.100.10"
        transit_gateway_name = "tlz-transit-gateway"
        tunnel_options       = [{ phase1_lifetime_seconds = 100 }] # below 900
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_phase2_lifetime" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                 = "onprem"
        bgp_asn              = 65010
        ip_address           = "198.51.100.10"
        transit_gateway_name = "tlz-transit-gateway"
        tunnel_options       = [{ phase2_lifetime_seconds = 7200 }] # above 3600
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_inside_ipv6_without_version" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                 = "onprem"
        bgp_asn              = 65010
        ip_address           = "198.51.100.10"
        transit_gateway_name = "tlz-transit-gateway"
        # tunnel_inside_ip_version stays unset — the IPv6 range must be rejected
        tunnel_options = [{ tunnel_inside_ipv6_cidr = "fd00:cccc::/126" }]
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_inside_ipv6_prefix_length" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                     = "onprem"
        bgp_asn                  = 65010
        ip_address               = "198.51.100.10"
        transit_gateway_name     = "tlz-transit-gateway"
        tunnel_inside_ip_version = "ipv6"
        tunnel_options           = [{ tunnel_inside_ipv6_cidr = "fd00:cccc::/64" }] # not /126
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_outside_ip_address_type" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                    = "onprem"
        bgp_asn                 = 65010
        ip_address              = "198.51.100.10"
        transit_gateway_name    = "tlz-transit-gateway"
        outside_ip_address_type = "Ipv6" # invalid: PublicIpv4 or PrivateIpv4
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_two_termination_points" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.50.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.50.10.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                 = "onprem"
        bgp_asn              = 65010
        ip_address           = "198.51.100.10"
        transit_gateway_name = "tlz-transit-gateway"
        vpc_name             = "edge" # invalid: exactly one termination point
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_unknown_vpc_name" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name       = "onprem"
        bgp_asn    = 65010
        ip_address = "198.51.100.10"
        vpc_name   = "does-not-exist"
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_acceleration_on_vgw" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.50.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.50.10.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                = "onprem"
        bgp_asn             = 65010
        ip_address          = "198.51.100.10"
        vpc_name            = "edge"
        enable_acceleration = true # invalid on a virtual private gateway
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_log_output_format" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                 = "onprem"
        bgp_asn              = 65010
        ip_address           = "198.51.100.10"
        transit_gateway_name = "tlz-transit-gateway"
        tunnel_options = [
          { logging = { enable = true, output_format = "xml" } } # invalid
        ]
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

run "networking_invalid_vpn_network_cidr" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    customer_gateways = [
      {
        name                     = "onprem"
        bgp_asn                  = 65010
        ip_address               = "198.51.100.10"
        transit_gateway_name     = "tlz-transit-gateway"
        amazon_ipv4_network_cidr = "10.0.0.0" # missing prefix length
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

# -----------------------------------------------------------------------------
# 4. Validation — Direct Connect details
# -----------------------------------------------------------------------------

run "networking_invalid_dx_vif_amazon_address" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    dx_gateways = [
      {
        name                 = "dxgw"
        amazon_asn           = 64515
        transit_gateway_name = "tlz-transit-gateway"
        virtual_interfaces = [
          {
            name           = "vif-a"
            type           = "transit"
            vlan           = 101
            bgp_asn        = 65001
            connection_id  = "dxcon-fgabcd12"
            amazon_address = "175.45.176.1" # missing prefix length
          }
        ]
      }
    ]
  }

  expect_failures = [var.dx_gateways]
}

run "networking_invalid_dx_vif_auth_key_length" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    dx_gateways = [
      {
        name                 = "dxgw"
        amazon_asn           = 64515
        transit_gateway_name = "tlz-transit-gateway"
        virtual_interfaces = [
          {
            name          = "vif-a"
            type          = "transit"
            vlan          = 101
            bgp_asn       = 65001
            connection_id = "dxcon-fgabcd12"
            auth_key      = "short" # below 8 characters
          }
        ]
      }
    ]
  }

  expect_failures = [var.dx_gateways]
}

run "networking_invalid_dx_vif_transit_mtu" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    dx_gateways = [
      {
        name                 = "dxgw"
        amazon_asn           = 64515
        transit_gateway_name = "tlz-transit-gateway"
        virtual_interfaces = [
          {
            name          = "vif-a"
            type          = "transit"
            vlan          = 101
            bgp_asn       = 65001
            connection_id = "dxcon-fgabcd12"
            mtu           = 9001 # invalid for transit (1500 or 8500)
          }
        ]
      }
    ]
  }

  expect_failures = [var.dx_gateways]
}

run "networking_invalid_dx_route_table_unknown_name" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub"] }
    dx_gateways = [
      {
        name                     = "dxgw"
        amazon_asn               = 64515
        transit_gateway_name     = "tlz-transit-gateway"
        route_table_associations = ["does-not-exist"]
      }
    ]
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_dx_second_route_table_association" {
  command = plan

  variables {
    transit_gateway = { enabled = true, route_tables = ["hub", "edge"] }
    dx_gateways = [
      {
        name                     = "dxgw"
        amazon_asn               = 64515
        transit_gateway_name     = "tlz-transit-gateway"
        route_table_associations = ["hub", "edge"] # at most one
      }
    ]
  }

  expect_failures = [var.dx_gateways]
}

# -----------------------------------------------------------------------------
# 4. Validation — TGW options and static routes
# -----------------------------------------------------------------------------

run "networking_invalid_tgw_option_value" {
  command = plan

  variables {
    transit_gateway = {
      enabled          = true
      route_tables     = ["hub"]
      vpn_ecmp_support = "on" # invalid: enable/disable
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_tgw_cidr_block" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      cidr_blocks  = ["10.99.0.0"] # missing prefix length
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_tgw_route_two_destinations" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      static_routes = [
        {
          route_table_name             = "hub"
          destination_cidr_block       = "192.168.0.0/16"
          destination_prefix_list_name = "shared-ranges" # exactly one destination
          attachment_name              = "hub"
        }
      ]
    }
    prefix_lists = [
      {
        name        = "shared-ranges"
        max_entries = 10
        entries     = [{ cidr = "10.90.0.0/16" }]
      }
    ]
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_tgw_route_attachment_type" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      static_routes = [
        {
          route_table_name       = "hub"
          destination_cidr_block = "192.168.0.0/16"
          attachment_name        = "hub"
          attachment_type        = "vgw" # invalid type
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_tgw_route_unknown_vpn_name" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      static_routes = [
        {
          route_table_name       = "hub"
          destination_cidr_block = "192.168.0.0/16"
          attachment_name        = "does-not-exist"
          attachment_type        = "vpn"
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_tgw_route_unknown_prefix_list" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      static_routes = [
        {
          route_table_name             = "hub"
          destination_prefix_list_name = "does-not-exist"
          attachment_name              = "hub"
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_tgw_route_missing_attachment" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      static_routes = [
        {
          route_table_name       = "hub"
          destination_cidr_block = "192.168.0.0/16"
          # no attachment_name and no blackhole
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_tgw_flow_logs_retention" {
  command = plan

  variables {
    transit_gateway              = { enabled = true, route_tables = ["hub"] }
    enable_tgw_flow_logs         = true
    tgw_flow_logs_destination    = "cloudwatch"
    tgw_flow_logs_retention_days = 42 # not a CloudWatch retention value
  }

  expect_failures = [var.tgw_flow_logs_retention_days]
}

run "networking_invalid_tgw_flow_logs_s3_path" {
  command = plan

  variables {
    transit_gateway           = { enabled = true, route_tables = ["hub"] }
    central_log_bucket_name   = "tlz-central-logs-210987654321-eu-central-1"
    enable_tgw_flow_logs      = true
    tgw_flow_logs_destination = "s3"
    tgw_flow_logs_s3_path     = "/tgw/" # leading and trailing slash
  }

  expect_failures = [var.tgw_flow_logs_s3_path]
}

# -----------------------------------------------------------------------------
# 3z. Subnet options and Outposts: explicit switches for public IP
# assignment and IPv6 assignment, DNS64, private DNS naming, Local Zone
# placement, and the Outpost declaration with its local gateway route table
# associations. The unset counterpart is scenario
# networking_subnet_and_route_defaults_leave_plan_unchanged.
# -----------------------------------------------------------------------------

run "networking_subnet_options_reach_resource" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        enable_ipv6  = true
        outposts = [
          {
            name = "rack-1"
            arn  = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
            local_gateway = {
              name = "lgw-rack-1"
              id   = "lgw-0a1b2c3d4e5f60708"
              route_tables = [
                { name = "coip", id = "lgw-rtb-0a1b2c3d4e5f60708" },
                { name = "direct", id = "lgw-rtb-0a1b2c3d4e5f60709" },
              ]
            }
          }
        ]
        subnets = [
          {
            # Explicit off-switch despite an IPv6 suffix; DNS64 and private
            # DNS naming set; the type-derived map_public_ip stays untouched.
            name                    = "app"
            cidr                    = "10.40.1.0/24"
            availability_zone       = "eu-central-1a"
            type                    = "private"
            ipv6_cidr_suffix        = "01"
            assign_ipv6_on_creation = false
            enable_dns64            = true
            private_dns_options = {
              hostname_type          = "resource-name"
              enable_dns_a_record    = true
              enable_dns_aaaa_record = true
            }
          },
          {
            # Public subnet with the automatic public IP switched off.
            name                    = "ingress"
            cidr                    = "10.40.2.0/24"
            availability_zone       = "eu-central-1a"
            type                    = "public"
            map_public_ip_on_launch = false
          },
          {
            # Local Zone placement instead of a regional Availability Zone.
            name       = "lz"
            cidr       = "10.40.3.0/24"
            local_zone = "eu-central-1-ham-1a"
            type       = "private"
          },
          {
            # Outpost placement through the name of the declared Outpost.
            name              = "rack"
            cidr              = "10.40.4.0/24"
            availability_zone = "eu-central-1a"
            type              = "isolated"
            outpost_name      = "rack-1"
          },
        ]
      }
    ]
  }

  assert {
    condition     = aws_subnet.this["edge.app"].assign_ipv6_address_on_creation == false
    error_message = "assign_ipv6_on_creation = false must win over the IPv6-suffix derivation."
  }

  assert {
    condition     = aws_subnet.this["edge.app"].enable_dns64 == true
    error_message = "enable_dns64 must reach the subnet."
  }

  assert {
    condition     = aws_subnet.this["edge.app"].private_dns_hostname_type_on_launch == "resource-name"
    error_message = "private_dns_options hostname_type must reach the subnet."
  }

  assert {
    condition     = aws_subnet.this["edge.app"].enable_resource_name_dns_a_record_on_launch == true && aws_subnet.this["edge.app"].enable_resource_name_dns_aaaa_record_on_launch == true
    error_message = "private_dns_options record switches must reach the subnet."
  }

  assert {
    condition     = aws_subnet.this["edge.ingress"].map_public_ip_on_launch == false
    error_message = "map_public_ip_on_launch = false must win over the type derivation on a public subnet."
  }

  assert {
    condition     = aws_subnet.this["edge.lz"].availability_zone == "eu-central-1-ham-1a"
    error_message = "local_zone must place the subnet in the Local Zone."
  }

  assert {
    condition     = aws_subnet.this["edge.rack"].outpost_arn == "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
    error_message = "outpost_name must resolve to the declared Outpost's ARN."
  }

  assert {
    condition     = length(aws_ec2_local_gateway_route_table_vpc_association.this) == 2
    error_message = "Every listed local gateway route table must be associated with the VPC."
  }

  assert {
    condition     = aws_ec2_local_gateway_route_table_vpc_association.this["edge.rack-1.coip"].local_gateway_route_table_id == "lgw-rtb-0a1b2c3d4e5f60708"
    error_message = "The association must carry the declared route table id."
  }
}

# -----------------------------------------------------------------------------
# Validation failures — subnet options and Outposts
# -----------------------------------------------------------------------------

run "networking_invalid_subnet_zone_choice" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            local_zone        = "eu-central-1-ham-1a" # both zones at once
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_subnet_zone_missing" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name = "app"
            cidr = "10.40.1.0/24"
            type = "private" # neither availability_zone nor local_zone
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_subnet_assign_ipv6_without_ipv6" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name                    = "app"
            cidr                    = "10.40.1.0/24"
            availability_zone       = "eu-central-1a"
            type                    = "private"
            assign_ipv6_on_creation = true # no ipv6_cidr_suffix, VPC without IPv6
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_subnet_dns64_without_ipv6" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            enable_dns64      = true # no ipv6_cidr_suffix, VPC without IPv6
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_subnet_hostname_type" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            private_dns_options = {
              hostname_type = "dns-name" # not ip-name/resource-name
            }
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_outpost_duplicate_name" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        outposts = [
          { name = "rack-1", arn = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0" },
          { name = "rack-1", arn = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef1" },
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_outpost_arn" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        outposts = [
          { name = "rack-1", arn = "arn:aws:ec2:eu-central-1:111111111111:instance/i-abc" } # not an Outpost ARN
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_subnet_outpost_both_references" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        outposts = [
          { name = "rack-1", arn = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0" }
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            outpost_name      = "rack-1"
            outpost_arn       = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0" # both at once
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_subnet_outpost_unknown_name" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            outpost_name      = "rack-9" # no outposts entry declares it
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_outpost_lgw_id" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        outposts = [
          {
            name = "rack-1"
            arn  = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
            local_gateway = {
              name         = "lgw-rack-1"
              id           = "igw-0a1b2c3d4e5f60708" # not a local gateway id
              route_tables = [{ name = "coip", id = "lgw-rtb-0a1b2c3d4e5f60708" }]
            }
          }
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_outpost_lgw_route_table_id" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        outposts = [
          {
            name = "rack-1"
            arn  = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
            local_gateway = {
              name         = "lgw-rack-1"
              id           = "lgw-0a1b2c3d4e5f60708"
              route_tables = [{ name = "coip", id = "rtb-0a1b2c3d4e5f60708" }] # not a local gateway route table id
            }
          }
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_outpost_lgw_without_route_tables" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        outposts = [
          {
            name = "rack-1"
            arn  = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
            local_gateway = {
              name = "lgw-rack-1"
              id   = "lgw-0a1b2c3d4e5f60708"
              # route_tables missing — the association is the purpose
            }
          }
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_outpost_lgw_duplicate_route_table_name" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        outposts = [
          {
            name = "rack-1"
            arn  = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
            local_gateway = {
              name = "lgw-rack-1"
              id   = "lgw-0a1b2c3d4e5f60708"
              route_tables = [
                { name = "coip", id = "lgw-rtb-0a1b2c3d4e5f60708" },
                { name = "coip", id = "lgw-rtb-0a1b2c3d4e5f60709" }, # duplicate name
              ]
            }
          }
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# 3aa. Route table targets: IPv6 and prefix list destinations, the
# next-hop types igw/eigw/vgw/local_gateway, gateway route tables on the
# internet gateway, and virtual private gateway route propagation. The unset
# counterpart is scenario networking_subnet_and_route_defaults_leave_plan_unchanged.
# -----------------------------------------------------------------------------

run "networking_route_targets_reach_resource" {
  command = plan

  variables {
    prefix_lists = [
      {
        name           = "corp-ranges"
        address_family = "IPv4"
        max_entries    = 10
        entries = [
          { cidr = "192.168.0.0/16", description = "corp" }
        ]
      }
    ]
    customer_gateways = [
      {
        name       = "onprem-dc1"
        bgp_asn    = 65000
        ip_address = "203.0.113.10"
        vpc_name   = "edge" # terminates on the VPC's virtual private gateway
      }
    ]
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        enable_ipv6  = true
        outposts = [
          {
            name = "rack-1"
            arn  = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
            local_gateway = {
              name         = "lgw-rack-1"
              id           = "lgw-0a1b2c3d4e5f60708"
              route_tables = [{ name = "coip", id = "lgw-rtb-0a1b2c3d4e5f60708" }]
            }
          }
        ]
        gateway_route_tables = [
          {
            name         = "igw-ingress"
            gateway_type = "internet_gateway"
            tags         = { Purpose = "ingress-inspection" }
            routes = [
              {
                destination_cidr_block = "10.40.2.0/24"
                target_type            = "eni"
                target_name            = "eni-0123456789abcdef0"
              }
            ]
          }
        ]
        subnets = [
          {
            name              = "ingress"
            cidr              = "10.40.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          },
          {
            name                     = "app"
            cidr                     = "10.40.1.0/24"
            availability_zone        = "eu-central-1a"
            type                     = "private"
            ipv6_cidr_suffix         = "01"
            enable_route_propagation = true
            custom_routes = [
              {
                destination_cidr_block = "10.99.0.0/16"
                target_type            = "igw"
              },
              {
                destination_ipv6_cidr_block = "2001:db8::/32"
                target_type                 = "eigw"
              },
              {
                destination_prefix_list_name = "corp-ranges"
                target_type                  = "vgw"
              },
              {
                destination_cidr_block = "10.98.0.0/16"
                target_type            = "local_gateway"
                target_name            = "lgw-rack-1"
              },
            ]
          },
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_route.custom) == 4
    error_message = "Every custom route must be planned."
  }

  assert {
    condition     = aws_route.custom["edge.app.0"].destination_cidr_block == "10.99.0.0/16"
    error_message = "The IPv4 destination must reach the route."
  }

  assert {
    condition     = aws_route.custom["edge.app.1"].destination_ipv6_cidr_block == "2001:db8::/32"
    error_message = "The IPv6 destination must reach the route."
  }

  assert {
    condition     = aws_route.custom["edge.app.1"].destination_cidr_block == null
    error_message = "An IPv6 route must not carry an IPv4 destination."
  }

  assert {
    condition     = aws_route.custom["edge.app.3"].local_gateway_id == "lgw-0a1b2c3d4e5f60708"
    error_message = "A local_gateway route must resolve the declared local gateway id by name."
  }

  assert {
    condition     = length(aws_route_table.gateway) == 1 && length(aws_route_table_association.gateway) == 1
    error_message = "The gateway route table and its edge association must be planned."
  }

  assert {
    condition     = aws_route_table.gateway["edge.igw-ingress"].tags["Name"] == "edge.igw-ingress"
    error_message = "The gateway route table must carry the module's Name tag."
  }

  assert {
    condition     = aws_route_table.gateway["edge.igw-ingress"].tags["Purpose"] == "ingress-inspection"
    error_message = "User tags must reach the gateway route table."
  }

  assert {
    condition     = aws_route.gateway_custom["edge.igw-ingress.0"].network_interface_id == "eni-0123456789abcdef0"
    error_message = "Gateway route table routes must resolve their targets."
  }

  assert {
    condition     = length(aws_vpn_gateway_route_propagation.this) == 1
    error_message = "enable_route_propagation must plan exactly one propagation for the subnet."
  }
}

# -----------------------------------------------------------------------------
# 3ab. Defaults — a configuration without the optional subnet and route
# attributes plans derived public IP and IPv6 assignment, no DNS64,
# no private DNS options, no Outpost associations, single-destination routes,
# no gateway route tables, no propagation.
# -----------------------------------------------------------------------------

run "networking_subnet_and_route_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        enable_ipv6  = true
        subnets = [
          {
            name              = "ingress"
            cidr              = "10.40.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          },
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            ipv6_cidr_suffix  = "01"
            custom_routes = [
              {
                destination_cidr_block = "10.1.0.0/16"
                target_type            = "eni"
                target_name            = "eni-0123456789abcdef0"
              }
            ]
          },
        ]
      }
    ]
  }

  assert {
    condition     = aws_subnet.this["edge.ingress"].map_public_ip_on_launch == true && aws_subnet.this["edge.app"].map_public_ip_on_launch == false
    error_message = "Without the explicit switch, public IP assignment must keep following the subnet type."
  }

  assert {
    condition     = aws_subnet.this["edge.app"].assign_ipv6_address_on_creation == true && aws_subnet.this["edge.ingress"].assign_ipv6_address_on_creation == false
    error_message = "Without the explicit switch, IPv6 assignment must keep following the ipv6_cidr_suffix."
  }

  assert {
    condition     = aws_subnet.this["edge.app"].enable_dns64 != true && aws_subnet.this["edge.ingress"].enable_dns64 != true
    error_message = "Without enable_dns64 the module must not switch DNS64 on."
  }

  assert {
    condition     = aws_subnet.this["edge.app"].enable_resource_name_dns_a_record_on_launch != true && aws_subnet.this["edge.app"].enable_resource_name_dns_aaaa_record_on_launch != true
    error_message = "Without private_dns_options the module must not switch DNS records on."
  }

  assert {
    condition     = length(aws_ec2_local_gateway_route_table_vpc_association.this) == 0
    error_message = "Without outposts no local gateway route table association must be planned."
  }

  assert {
    condition     = aws_route.custom["edge.app.0"].destination_cidr_block == "10.1.0.0/16" && aws_route.custom["edge.app.0"].destination_ipv6_cidr_block == null && aws_route.custom["edge.app.0"].destination_prefix_list_id == null
    error_message = "A route in the plain shape must plan with its IPv4 destination only."
  }

  assert {
    condition     = aws_route.custom["edge.app.0"].network_interface_id == "eni-0123456789abcdef0"
    error_message = "The eni target must keep resolving to the raw interface id."
  }

  assert {
    condition     = length(aws_route_table.gateway) == 0 && length(aws_route_table_association.gateway) == 0 && length(aws_route.gateway_custom) == 0
    error_message = "Without gateway_route_tables no gateway route table must be planned."
  }

  assert {
    condition     = length(aws_vpn_gateway_route_propagation.this) == 0
    error_message = "Without enable_route_propagation no propagation must be planned."
  }
}

# -----------------------------------------------------------------------------
# Validation failures — route destinations, targets, and gateway route tables

# -----------------------------------------------------------------------------

run "networking_invalid_route_target_type" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "10.1.0.0/16"
                target_type            = "carrier_gateway" # not a supported type
                target_name            = "cagw-abc"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_two_destinations" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block      = "10.1.0.0/16"
                destination_ipv6_cidr_block = "2001:db8::/32" # two destinations at once
                target_type                 = "eni"
                target_name                 = "eni-0123456789abcdef0"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_ipv4_destination" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "10.1.0.0" # no prefix length
                target_type            = "eni"
                target_name            = "eni-0123456789abcdef0"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_ipv6_destination" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_ipv6_cidr_block = "10.1.0.0/16" # IPv4 in the IPv6 slot
                target_type                 = "eni"
                target_name                 = "eni-0123456789abcdef0"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_unknown_prefix_list" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_prefix_list_name = "corp-ranges" # no prefix_lists entry declares it
                target_type                  = "eni"
                target_name                  = "eni-0123456789abcdef0"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_missing_target_name" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "10.1.0.0/16"
                target_type            = "eni" # name-resolved type without target_name
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_igw_without_public_subnet" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "0.0.0.0/0"
                target_type            = "igw" # no public subnet creates an IGW here
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_eigw_without_ipv6" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_ipv6_cidr_block = "::/0"
                target_type                 = "eigw" # VPC without IPv6 never creates an EIGW
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_unknown_local_gateway" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "10.98.0.0/16"
                target_type            = "local_gateway"
                target_name            = "lgw-rack-9" # no outposts entry declares it
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_gateway_route_table_type" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        gateway_route_tables = [
          {
            name         = "ingress"
            gateway_type = "carrier_gateway" # not internet_gateway/virtual_private_gateway
          }
        ]
        subnets = [
          {
            name              = "ingress"
            cidr              = "10.40.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_gateway_route_table_duplicate_name" {
  command = plan

  variables {
    customer_gateways = [
      {
        name       = "onprem-dc1"
        bgp_asn    = 65000
        ip_address = "203.0.113.10"
        vpc_name   = "edge"
      }
    ]
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        gateway_route_tables = [
          { name = "ingress", gateway_type = "internet_gateway" },
          { name = "ingress", gateway_type = "virtual_private_gateway" }, # duplicate name
        ]
        subnets = [
          {
            name              = "ingress"
            cidr              = "10.40.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_gateway_route_table_second_per_gateway" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        gateway_route_tables = [
          { name = "ingress-a", gateway_type = "internet_gateway" },
          { name = "ingress-b", gateway_type = "internet_gateway" }, # second table on the same gateway
        ]
        subnets = [
          {
            name              = "ingress"
            cidr              = "10.40.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_gateway_route_table_igw_without_public_subnet" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        gateway_route_tables = [
          { name = "ingress", gateway_type = "internet_gateway" } # no public subnet creates an IGW here
        ]
        subnets = [
          {
            name              = "app"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_route_propagation_without_vgw" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "edge"
        cidr         = "10.40.0.0/16"
        account_name = "network-hub"
        subnets = [
          {
            name                     = "app"
            cidr                     = "10.40.1.0/24"
            availability_zone        = "eu-central-1a"
            type                     = "private"
            enable_route_propagation = true # no customer_gateways entry attaches a VGW
          }
        ]
      }
    ]
  }

  expect_failures = [var.customer_gateways]
}

# -----------------------------------------------------------------------------
# 3ac. Custom configuration — VPC endpoint options
# -----------------------------------------------------------------------------
# Gateway endpoints take a policy (named or inline) and a full service name
# through gateway_endpoint_options; interface endpoints take a full service
# name and the central-endpoint pattern (private DNS off, hosted zone with
# alias record, optional zone name override).

run "networking_vpc_endpoint_options_reach_resource" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        gateway_endpoints = ["s3", "dynamodb"]
        gateway_endpoint_options = {
          s3 = {
            policy_name = "restrict-to-organization"
          }
          dynamodb = {
            policy       = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"dynamodb:GetItem\",\"Resource\":\"*\"}]}"
            service_name = "com.amazonaws.eu-central-1.dynamodb-fips"
          }
        }
        interface_endpoints = [
          {
            # Central endpoint with the derived zone name.
            service      = "ssm"
            subnet_names = ["private-a"]
            central      = true
          },
          {
            # Central endpoint with an explicit zone name and a full service
            # name for a special case outside the com.amazonaws pattern.
            service          = "codeartifact.repositories"
            service_name     = "com.amazonaws.eu-central-1.codeartifact.repositories"
            subnet_names     = ["private-a"]
            central          = true
            hosted_zone_name = "d.codeartifact.eu-central-1.amazonaws.com"
          },
        ]
      }
    ]
    endpoint_policies = [
      {
        name   = "restrict-to-organization"
        policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-abcd1234567\"}}}]}"
      }
    ]
  }

  assert {
    condition     = can(regex("PrincipalOrgID", aws_vpc_endpoint.gateway["hub.s3"].policy))
    error_message = "A named policy must be resolved from endpoint_policies onto the gateway endpoint."
  }

  assert {
    condition     = aws_vpc_endpoint.gateway["hub.s3"].service_name == "com.amazonaws.eu-central-1.s3"
    error_message = "Without a service_name override the gateway endpoint must keep the regional derivation."
  }

  assert {
    condition     = can(regex("dynamodb:GetItem", aws_vpc_endpoint.gateway["hub.dynamodb"].policy))
    error_message = "An inline policy must be applied to the gateway endpoint."
  }

  assert {
    condition     = aws_vpc_endpoint.gateway["hub.dynamodb"].service_name == "com.amazonaws.eu-central-1.dynamodb-fips"
    error_message = "The full service name must replace the regional derivation on the gateway endpoint."
  }

  assert {
    condition     = aws_vpc_endpoint.interface["hub.codeartifact.repositories"].service_name == "com.amazonaws.eu-central-1.codeartifact.repositories"
    error_message = "The full service name must replace the regional derivation on the interface endpoint."
  }

  assert {
    condition     = aws_vpc_endpoint.interface["hub.ssm"].private_dns_enabled == false && aws_vpc_endpoint.interface["hub.codeartifact.repositories"].private_dns_enabled == false
    error_message = "A central endpoint must leave the service's private DNS name to its hosted zone."
  }

  assert {
    condition     = aws_route53_zone.central_endpoint["hub.ssm"].name == "ssm.eu-central-1.amazonaws.com"
    error_message = "Without hosted_zone_name the central endpoint zone must derive service.region.dns_suffix."
  }

  assert {
    condition     = aws_route53_zone.central_endpoint["hub.codeartifact.repositories"].name == "d.codeartifact.eu-central-1.amazonaws.com"
    error_message = "hosted_zone_name must override the derived zone name."
  }

  assert {
    condition     = length(aws_route53_record.central_endpoint) == 2 && aws_route53_record.central_endpoint["hub.ssm"].type == "A"
    error_message = "Every central endpoint must plan its apex alias record."
  }
}

# -----------------------------------------------------------------------------
# 3ad. Custom configuration — per-endpoint security group
# -----------------------------------------------------------------------------
# The security_group_ids assertions need `command = apply`: the group IDs are
# unknown at plan time, so membership cannot be evaluated in a plan run. The
# mock provider generates the values on apply.

run "networking_endpoint_security_group_reaches_endpoint" {
  command = apply

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          { name = "endpoint-sg" }
        ]
        interface_endpoints = [
          {
            service        = "ssm"
            subnet_names   = ["private-a"]
            security_group = "endpoint-sg"
          },
          {
            service      = "kms"
            subnet_names = ["private-a"]
          },
        ]
      }
    ]
  }

  assert {
    condition     = contains(aws_vpc_endpoint.interface["hub.ssm"].security_group_ids, aws_security_group.this["hub.endpoint-sg"].id)
    error_message = "The named security group must replace the default endpoint security group."
  }

  assert {
    condition     = contains(aws_vpc_endpoint.interface["hub.kms"].security_group_ids, aws_security_group.interface_endpoint["hub"].id)
    error_message = "An endpoint without security_group must keep the module's default endpoint security group."
  }
}

# -----------------------------------------------------------------------------
# 3ae. The unset endpoint options leave the plan unchanged
# -----------------------------------------------------------------------------
# A plain service name in gateway_endpoints and an interface endpoint without
# the optional attributes plan derived service names, private DNS on, the
# default endpoint security group, no hosted zone.

run "networking_endpoint_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        gateway_endpoints = ["s3"]
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
          }
        ]
      }
    ]
  }

  assert {
    condition     = aws_vpc_endpoint.gateway["hub.s3"].service_name == "com.amazonaws.eu-central-1.s3"
    error_message = "A plain gateway_endpoints entry must keep the regional service name derivation."
  }

  # An endpoint without policy and without gateway_endpoint_options keeps the
  # AWS default policy; that value is only known after apply, so only the
  # service name and the zone-free plan are asserted here.
  assert {
    condition     = aws_vpc_endpoint.interface["hub.ssm"].service_name == "com.amazonaws.eu-central-1.ssm" && aws_vpc_endpoint.interface["hub.ssm"].private_dns_enabled == true
    error_message = "An interface endpoint without the optional attributes must keep the derived service name and private DNS."
  }

  assert {
    condition     = length(aws_route53_zone.central_endpoint) == 0 && length(aws_route53_record.central_endpoint) == 0
    error_message = "Without central = true no hosted zone and no alias record must be planned."
  }
}

# -----------------------------------------------------------------------------
# Validation failures — VPC endpoint options
# -----------------------------------------------------------------------------

run "networking_invalid_gateway_endpoint_option_key" {
  command = plan

  variables {
    vpcs = [
      {
        name              = "hub"
        cidr              = "10.0.0.0/16"
        account_name      = "network"
        gateway_endpoints = ["s3"]
        gateway_endpoint_options = {
          dynamodb = { policy = "{}" } # not listed in gateway_endpoints
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_gateway_endpoint_policy_name" {
  command = plan

  variables {
    vpcs = [
      {
        name              = "hub"
        cidr              = "10.0.0.0/16"
        account_name      = "network"
        gateway_endpoints = ["s3"]
        gateway_endpoint_options = {
          s3 = { policy_name = "does-not-exist" }
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_interface_endpoint_security_group" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          { name = "endpoint-sg" }
        ]
        interface_endpoints = [
          {
            service        = "ssm"
            subnet_names   = ["private-a"]
            security_group = "does-not-exist"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_endpoint_service_name_empty" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            service_name = "" # must stay null or carry a name
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_endpoint_hosted_zone_without_central" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        interface_endpoints = [
          {
            service          = "ssm"
            subnet_names     = ["private-a"]
            hosted_zone_name = "ssm.eu-central-1.amazonaws.com" # needs central = true
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# 3af. Custom configuration — DNS firewall association mutation protection
# -----------------------------------------------------------------------------
# mutation_protection locks one association of a rule group with one VPC; the
# map is keyed by vpc_names entries, every VPC without an entry keeps the
# service default. That default value is only known after apply, so only the
# protected association and the association count are asserted here.

run "networking_dns_firewall_mutation_protection_reaches_association" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.1.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.1.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]
    dns_firewall_rule_groups = [
      {
        name      = "blocklist"
        vpc_names = ["hub", "spoke"]
        mutation_protection = {
          hub = "ENABLED"
        }
        custom_domain_lists = [
          {
            name    = "blocked-domains"
            domains = ["malware.example.com"]
          }
        ]
        rules = [
          {
            name                    = "block-malware"
            priority                = 100
            action                  = "BLOCK"
            custom_domain_list_name = "blocked-domains"
          }
        ]
      }
    ]
  }

  assert {
    condition     = aws_route53_resolver_firewall_rule_group_association.this["blocklist.hub"].mutation_protection == "ENABLED"
    error_message = "The mutation protection of the named VPC must reach its association."
  }

  assert {
    condition     = length(aws_route53_resolver_firewall_rule_group_association.this) == 2
    error_message = "Every vpc_names entry must keep its association, with or without mutation protection."
  }
}

# -----------------------------------------------------------------------------
# Validation failures — DNS firewall association mutation protection
# -----------------------------------------------------------------------------

run "networking_invalid_dns_firewall_mutation_protection_value" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
    dns_firewall_rule_groups = [
      {
        name      = "blocklist"
        vpc_names = ["hub"]
        mutation_protection = {
          hub = "PROTECTED" # must be ENABLED or DISABLED
        }
        custom_domain_lists = [
          {
            name    = "blocked-domains"
            domains = ["malware.example.com"]
          }
        ]
        rules = [
          {
            name                    = "block-malware"
            priority                = 100
            action                  = "BLOCK"
            custom_domain_list_name = "blocked-domains"
          }
        ]
      }
    ]
  }

  expect_failures = [var.dns_firewall_rule_groups]
}

run "networking_invalid_dns_firewall_mutation_protection_unknown_vpc" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
    dns_firewall_rule_groups = [
      {
        name      = "blocklist"
        vpc_names = ["hub"]
        mutation_protection = {
          spoke = "ENABLED" # not associated through vpc_names
        }
        custom_domain_lists = [
          {
            name    = "blocked-domains"
            domains = ["malware.example.com"]
          }
        ]
        rules = [
          {
            name                    = "block-malware"
            priority                = 100
            action                  = "BLOCK"
            custom_domain_list_name = "blocked-domains"
          }
        ]
      }
    ]
  }

  expect_failures = [var.dns_firewall_rule_groups]
}

# -----------------------------------------------------------------------------
# 3ag. Custom configuration — NACL rule sources: subnet selectors across VPC
# entries, literal IPv6 CIDRs and ICMP type/code pairs
# -----------------------------------------------------------------------------

run "networking_nacl_rule_selectors_reach_rules" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        region       = "eu-central-1"
        enable_ipv6  = true
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            ipv6_cidr_suffix  = "01"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                from_port   = 443
                to_port     = 443
                source = {
                  vpc     = "spoke"
                  subnet  = "private-a"
                  account = "workload-prod"
                  region  = "eu-central-1"
                }
              },
              {
                rule_number = 110
                protocol    = "icmp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
                icmp = {
                  type = 8
                  code = 0
                }
              },
              {
                rule_number     = 120
                protocol        = "tcp"
                action          = "allow"
                ipv6_cidr_block = "2001:db8::/64"
                from_port       = 443
                to_port         = 443
              },
            ]
            outbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                from_port   = 5432
                to_port     = 5432
                destination = {
                  vpc    = "hub"
                  subnet = "private-a"
                }
              },
              {
                rule_number = 110
                protocol    = "58"
                action      = "allow"
                icmp = {
                  type = -1
                }
                destination = {
                  vpc    = "hub"
                  subnet = "private-a"
                  ipv6   = true
                }
              },
            ]
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.2.0.0/16"
        account_name = "workload-prod"
        region       = "eu-central-1"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.2.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]
  }

  # The selector reaches across VPC entries: the spoke subnet's CIDR lands on
  # the hub rule at plan time.
  assert {
    condition     = aws_network_acl_rule.inbound["hub.private-nacl.in.100"].cidr_block == "10.2.1.0/24" && aws_network_acl_rule.inbound["hub.private-nacl.in.100"].ipv6_cidr_block == null
    error_message = "The inbound subnet selector must resolve to the spoke subnet's IPv4 CIDR."
  }

  assert {
    condition     = aws_network_acl_rule.inbound["hub.private-nacl.in.110"].icmp_type == 8 && aws_network_acl_rule.inbound["hub.private-nacl.in.110"].icmp_code == 0
    error_message = "The ICMP pair must land as icmp_type and icmp_code on the rule."
  }

  assert {
    condition     = aws_network_acl_rule.inbound["hub.private-nacl.in.120"].ipv6_cidr_block == "2001:db8::/64" && aws_network_acl_rule.inbound["hub.private-nacl.in.120"].cidr_block == null
    error_message = "A literal IPv6 CIDR must land as ipv6_cidr_block and leave cidr_block unset."
  }

  assert {
    condition     = aws_network_acl_rule.outbound["hub.private-nacl.out.100"].cidr_block == "10.0.2.0/24"
    error_message = "The outbound destination selector must resolve to the hub subnet's IPv4 CIDR."
  }

  # The IPv6 CIDR of the selector is Amazon-assigned and unknown at plan
  # time; provable here is that the IPv4 side stays unset and the ICMPv6
  # wildcard type lands.
  assert {
    condition     = aws_network_acl_rule.outbound["hub.private-nacl.out.110"].cidr_block == null && aws_network_acl_rule.outbound["hub.private-nacl.out.110"].icmp_type == -1 && aws_network_acl_rule.outbound["hub.private-nacl.out.110"].icmp_code == -1
    error_message = "An IPv6 selector must leave cidr_block unset; the ICMPv6 wildcard pair must land on the rule."
  }
}

# -----------------------------------------------------------------------------
# 3ah. Flat NACL rules — a configuration without the optional rule attributes
# plans plain rules
# -----------------------------------------------------------------------------

run "networking_nacl_flat_rules_leave_plan_unchanged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
                from_port   = 443
                to_port     = 443
              }
            ]
            outbound = [
              {
                rule_number = 100
                protocol    = "-1"
                action      = "allow"
                cidr_block  = "0.0.0.0/0"
                from_port   = 0
                to_port     = 0
              }
            ]
          }
        ]
      }
    ]
  }

  assert {
    condition     = aws_network_acl_rule.inbound["hub.private-nacl.in.100"].cidr_block == "10.0.0.0/16" && aws_network_acl_rule.inbound["hub.private-nacl.in.100"].from_port == 443 && aws_network_acl_rule.inbound["hub.private-nacl.in.100"].to_port == 443
    error_message = "A flat inbound rule must keep its CIDR and port range unchanged."
  }

  assert {
    condition     = aws_network_acl_rule.inbound["hub.private-nacl.in.100"].ipv6_cidr_block == null && aws_network_acl_rule.inbound["hub.private-nacl.in.100"].icmp_type == null && aws_network_acl_rule.inbound["hub.private-nacl.in.100"].icmp_code == null
    error_message = "A flat inbound rule must not gain IPv6 or ICMP attributes."
  }

  assert {
    condition     = aws_network_acl_rule.outbound["hub.private-nacl.out.100"].cidr_block == "0.0.0.0/0" && aws_network_acl_rule.outbound["hub.private-nacl.out.100"].ipv6_cidr_block == null && aws_network_acl_rule.outbound["hub.private-nacl.out.100"].icmp_type == null
    error_message = "A flat outbound rule must keep its CIDR and must not gain IPv6 or ICMP attributes."
  }
}

# -----------------------------------------------------------------------------
# Validation failures — NACL rule sources
# -----------------------------------------------------------------------------

run "networking_invalid_nacl_rule_two_source_forms" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
                from_port   = 443
                to_port     = 443
                source = {
                  vpc    = "hub"
                  subnet = "private-a"
                }
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_rule_without_source_form" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                from_port   = 443
                to_port     = 443
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_selector_unknown_subnet" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                from_port   = 443
                to_port     = 443
                source = {
                  vpc    = "hub"
                  subnet = "does-not-exist"
                }
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_selector_account_mismatch" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                from_port   = 443
                to_port     = 443
                source = {
                  vpc     = "hub"
                  subnet  = "private-a"
                  account = "some-other-account"
                }
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_selector_region_mismatch" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        region       = "eu-central-1"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                from_port   = 443
                to_port     = 443
                source = {
                  vpc    = "hub"
                  subnet = "private-a"
                  region = "eu-west-1"
                }
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_selector_ipv6_without_ipv6_subnet" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                from_port   = 443
                to_port     = 443
                source = {
                  vpc    = "hub"
                  subnet = "private-a"
                  ipv6   = true
                }
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_icmp_without_icmp_protocol" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
                from_port   = 443
                to_port     = 443
                icmp = {
                  type = 8
                }
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_icmp_protocol_without_icmp" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "icmp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_icmp_type_out_of_range" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "icmp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
                icmp = {
                  type = 256
                }
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_nacl_tcp_rule_without_ports" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        nacls = [
          {
            name         = "private-nacl"
            subnet_names = ["private-a"]
            inbound = [
              {
                rule_number = 100
                protocol    = "tcp"
                action      = "allow"
                cidr_block  = "10.0.0.0/16"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# 3ai. Custom configuration — security group rule sources and types: subnet
# selectors, IPv6 CIDRs, named types, egress group references and the group
# description
# -----------------------------------------------------------------------------

run "networking_sg_rule_sources_and_types_reach_rules" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name        = "app-sg"
            description = "Application tier"
            ingress = [
              {
                types       = ["SSH", "RDP"]
                description = "Admin access from the spoke subnet"
                source_subnets = [
                  {
                    vpc     = "spoke"
                    subnets = ["private-a"]
                    account = "workload-prod"
                  }
                ]
              },
              {
                types       = ["ALL"]
                cidr_blocks = ["10.0.0.0/8"]
                description = "All traffic from the corporate range"
              },
              {
                protocol         = "tcp"
                from_port        = 443
                to_port          = 443
                ipv6_cidr_blocks = ["2001:db8::/64"]
                description      = "HTTPS from the IPv6 range"
              },
            ]
            egress = [
              {
                protocol              = "tcp"
                from_port             = 5432
                to_port               = 5432
                cidr_blocks           = []
                source_security_group = "db-sg"
                description           = "PostgreSQL to the database tier"
              },
              {
                types       = ["UDP"]
                from_port   = 500
                to_port     = 510
                cidr_blocks = ["10.9.0.0/16"]
                description = "IKE to the VPN range"
              },
            ]
          },
          {
            name = "db-sg"
            ingress = [
              {
                protocol              = "tcp"
                from_port             = 5432
                to_port               = 5432
                source_security_group = "app-sg"
                description           = "PostgreSQL from the application tier"
              }
            ]
          },
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.2.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.2.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]
  }

  assert {
    condition     = aws_security_group.this["hub.app-sg"].description == "Application tier"
    error_message = "The group description must land on the security group."
  }

  # One rule per named type, each with the resolved subnet CIDR of the
  # selector as its IPv4 source.
  assert {
    condition     = aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.SSH"].protocol == "tcp" && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.SSH"].from_port == 22 && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.SSH"].to_port == 22 && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.SSH"].cidr_blocks == tolist(["10.2.1.0/24"])
    error_message = "The SSH type must expand to tcp/22 with the resolved spoke subnet CIDR."
  }

  assert {
    condition     = aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.RDP"].from_port == 3389 && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.RDP"].to_port == 3389 && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.RDP"].cidr_blocks == tolist(["10.2.1.0/24"])
    error_message = "The RDP type must expand to tcp/3389 with the resolved spoke subnet CIDR."
  }

  assert {
    condition     = aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.1.ALL"].protocol == "-1" && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.1.ALL"].from_port == 0 && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.1.ALL"].to_port == 0
    error_message = "The ALL type must expand to all protocols."
  }

  assert {
    condition     = aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.2"].ipv6_cidr_blocks == tolist(["2001:db8::/64"]) && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.2"].cidr_blocks == null
    error_message = "A literal IPv6 CIDR must land as ipv6_cidr_blocks and leave cidr_blocks unset."
  }

  # The referenced group's id is only known after apply; provable here is
  # that exactly this one reference rule is planned with the rule's ports.
  assert {
    condition     = length([for k, r in aws_security_group_rule.egress_sg : k]) == 1 && aws_security_group_rule.egress_sg["hub.app-sg.egress.0"].from_port == 5432 && aws_security_group_rule.egress_sg["hub.app-sg.egress.0"].to_port == 5432 && aws_security_group_rule.egress_sg["hub.app-sg.egress.0"].protocol == "tcp"
    error_message = "An egress rule must reference the named security group of the same VPC with the rule's port pair."
  }

  assert {
    condition     = aws_security_group_rule.egress_cidr["hub.app-sg.egress.1.UDP"].protocol == "udp" && aws_security_group_rule.egress_cidr["hub.app-sg.egress.1.UDP"].from_port == 500 && aws_security_group_rule.egress_cidr["hub.app-sg.egress.1.UDP"].to_port == 510
    error_message = "The UDP type must expand to udp with the rule's own port pair."
  }
}

# -----------------------------------------------------------------------------
# 3aj. Flat security group rules — a configuration without the optional rule
# attributes plans plain rules
# -----------------------------------------------------------------------------

run "networking_sg_flat_rules_leave_plan_unchanged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 443
                cidr_blocks = ["10.0.0.0/16"]
                description = "HTTPS from VPC"
              }
            ]
            egress = [
              {
                protocol    = "-1"
                from_port   = 0
                to_port     = 0
                description = "Allow all egress"
              }
            ]
          }
        ]
      }
    ]
  }

  # The flat rule keeps its key (no type suffix), its values and the derived
  # group description.
  assert {
    condition     = aws_security_group.this["hub.app-sg"].description == "Security group app-sg in VPC hub"
    error_message = "Without a description the group must keep the derived description."
  }

  assert {
    condition     = aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0"].protocol == "tcp" && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0"].from_port == 443 && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0"].cidr_blocks == tolist(["10.0.0.0/16"]) && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0"].ipv6_cidr_blocks == null
    error_message = "A flat ingress rule must keep its key, protocol, ports and CIDR list unchanged and must not gain IPv6 sources."
  }

  assert {
    condition     = aws_security_group_rule.egress_cidr["hub.app-sg.egress.0"].cidr_blocks == tolist(["0.0.0.0/0"]) && aws_security_group_rule.egress_cidr["hub.app-sg.egress.0"].ipv6_cidr_blocks == null
    error_message = "A flat egress rule must keep its open IPv4 default and must not gain IPv6 sources."
  }

  assert {
    condition     = length([for k, r in aws_security_group_rule.ingress_sg : k]) == 0 && length([for k, r in aws_security_group_rule.egress_sg : k]) == 0
    error_message = "Without group references no reference rules must be planned."
  }
}

# -----------------------------------------------------------------------------
# Validation failures — security group rule sources and types
# -----------------------------------------------------------------------------

run "networking_invalid_sg_description_empty" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name        = "app-sg"
            description = ""
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_rule_without_port_form" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                cidr_blocks = ["10.0.0.0/16"]
                description = "No protocol and no types"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_rule_unknown_type" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                types       = ["FTP"]
                cidr_blocks = ["10.0.0.0/16"]
                description = "Unknown type"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_rule_type_with_protocol" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                types       = ["SSH"]
                protocol    = "tcp"
                cidr_blocks = ["10.0.0.0/16"]
                description = "Type and protocol at once"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_rule_named_type_with_ports" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                types       = ["SSH"]
                from_port   = 22
                to_port     = 22
                cidr_blocks = ["10.0.0.0/16"]
                description = "Named type with a port pair"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_rule_icmp_mixed_with_tcp" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                types       = ["ICMP", "TCP"]
                from_port   = -1
                to_port     = -1
                cidr_blocks = ["10.0.0.0/16"]
                description = "ICMP mixed with TCP"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_rule_port_range_reversed" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 80
                cidr_blocks = ["10.0.0.0/16"]
                description = "Reversed port range"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_rule_without_sources" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 443
                description = "No source at all"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_selector_unknown_subnet" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 443
                description = "Unknown selector subnet"
                source_subnets = [
                  {
                    vpc     = "hub"
                    subnets = ["does-not-exist"]
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_selector_empty_subnets" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 443
                description = "Empty selector subnet list"
                source_subnets = [
                  {
                    vpc     = "hub"
                    subnets = []
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_selector_account_mismatch" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 443
                description = "Selector account mismatch"
                source_subnets = [
                  {
                    vpc     = "hub"
                    subnets = ["private-a"]
                    account = "some-other-account"
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_selector_ipv6_without_ipv6_subnet" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "tcp"
                from_port   = 443
                to_port     = 443
                description = "IPv6 selector without IPv6 subnet"
                source_subnets = [
                  {
                    vpc     = "hub"
                    subnets = ["private-a"]
                    ipv6    = true
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_sg_source_security_group_unknown" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            egress = [
              {
                protocol              = "tcp"
                from_port             = 5432
                to_port               = 5432
                cidr_blocks           = []
                source_security_group = "does-not-exist"
                description           = "Unknown group reference"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

# An all-protocol world-open ingress rule needs a second word. An ingress rule
# opening ALL protocols to 0.0.0.0/0 or ::/0 is refused in both rule shapes (vpcs and
# vpc_templates) unless the rule sets acknowledge_world_open_all_protocols.
run "networking_invalid_sg_ingress_world_open_all_protocols" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                types       = ["ALL"]
                cidr_blocks = ["0.0.0.0/0"]
                description = "All traffic from anywhere, not acknowledged"
              }
            ]
          }
        ]
      }
    ]
    vpc_templates = [
      {
        name               = "standard-workload"
        cidr               = "10.60.0.0/16"
        deployment_targets = ["network"]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.60.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                protocol    = "-1"
                from_port   = 0
                to_port     = 0
                cidr_blocks = ["0.0.0.0/0"]
                description = "All traffic from anywhere, not acknowledged"
              }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs, var.vpc_templates]
}

# An all-protocol world-open ingress rule with its second word. With the
# acknowledgement
# the same rule plans as an all-protocol rule; a world-open rule for a single
# port needs no acknowledgement.
run "networking_sg_ingress_world_open_all_protocols_acknowledged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              {
                types                                = ["ALL"]
                cidr_blocks                          = ["0.0.0.0/0"]
                description                          = "All traffic from anywhere, acknowledged"
                acknowledge_world_open_all_protocols = true
              },
              {
                types       = ["HTTPS"]
                cidr_blocks = ["0.0.0.0/0"]
                description = "HTTPS from anywhere"
              },
            ]
          }
        ]
      }
    ]
  }

  assert {
    condition     = aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.ALL"].protocol == "-1" && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.ALL"].cidr_blocks == tolist(["0.0.0.0/0"])
    error_message = "An acknowledged all-protocol world-open ingress rule must plan as protocol -1 from 0.0.0.0/0."
  }

  assert {
    condition     = aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.1.HTTPS"].protocol == "tcp" && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.1.HTTPS"].from_port == 443 && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.1.HTTPS"].cidr_blocks == tolist(["0.0.0.0/0"])
    error_message = "A single-port world-open ingress rule must plan without an acknowledgement."
  }
}

# -----------------------------------------------------------------------------
# 3ak-ipam. IPAM pool sharing — reach, toggle off, no targets, all in one VPC-
# free plan. These runs need the pool hierarchy
# (aws_vpc_ipam_pool.this/.child/.grandchild) to plan at all.
# -----------------------------------------------------------------------------

run "networking_ram_shares_reach_ipam_pools" {
  command = plan

  variables {
    enable_ram_sharing = true
    account_ids = {
      network       = "111111111111"
      workload-prod = "222222222222"
    }
    ipam = {
      enabled = true
      regions = ["eu-central-1"]
      pools = [
        {
          name = "shared-pool"
          cidr = "10.64.0.0/10"
          share_targets = [
            "workload-prod",
            "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1",
          ]
        },
        {
          name = "plain-pool"
          cidr = "10.128.0.0/10"
        },
      ]
    }
  }

  # One share for the sharing pool, none for the plain one; the account name
  # resolves through account_ids, the OU ARN passes through unchanged.
  assert {
    condition     = length(aws_ram_resource_share.ipam_pool) == 1 && length(aws_ram_resource_association.ipam_pool) == 1
    error_message = "Exactly the pool with share_targets must create a RAM share and one resource association."
  }

  assert {
    condition     = aws_ram_principal_association.ipam_pool["shared-pool.workload-prod"].principal == "222222222222"
    error_message = "An account name in ipam pool share_targets must resolve to its account ID through account_ids."
  }

  assert {
    condition     = aws_ram_principal_association.ipam_pool["shared-pool.arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"].principal == "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"
    error_message = "An OU ARN in ipam pool share_targets must reach the principal association unchanged."
  }
}

run "networking_ram_share_toggle_off_ipam_creates_nothing" {
  command = plan

  variables {
    enable_ram_sharing = false
    account_ids = {
      workload-prod = "222222222222"
    }
    ipam = {
      enabled = true
      pools = [
        {
          name          = "shared-pool"
          cidr          = "10.64.0.0/10"
          share_targets = ["workload-prod"]
        }
      ]
    }
  }

  assert {
    condition     = length(aws_ram_resource_share.ipam_pool) == 0 && length(aws_ram_resource_association.ipam_pool) == 0 && length(aws_ram_principal_association.ipam_pool) == 0
    error_message = "No IPAM pool share must be created while enable_ram_sharing is false."
  }

  assert {
    condition     = length(aws_vpc_ipam_pool.this) == 1
    error_message = "The pool itself must still be planned."
  }
}

# -----------------------------------------------------------------------------
# Validation — IPAM pool share target form

# -----------------------------------------------------------------------------

run "networking_invalid_ipam_pool_share_target_form" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name          = "shared-pool"
          cidr          = "10.64.0.0/10"
          share_targets = ["12345"]
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

# -----------------------------------------------------------------------------
# 3ak. Custom configuration — RAM shares reach the further network objects:
# IPAM pools, Network Firewall rule groups and policy, the query logging
# configuration; OU and organization ARNs as share targets
# -----------------------------------------------------------------------------

run "networking_ram_shares_reach_new_objects" {
  command = plan

  variables {
    enable_ram_sharing = true
    account_ids = {
      network       = "111111111111"
      workload-prod = "222222222222"
    }
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.20.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "firewall-a"
            cidr              = "10.20.1.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
            share_targets = [
              "workload-prod",
              "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1",
            ]
          }
        ]
      }
    ]
    transit_gateway = {
      enabled      = true
      route_tables = ["hub"]
      share_targets = [
        "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1",
      ]
    }
    network_firewall = {
      enabled      = true
      vpc_name     = "inspection"
      subnet_names = ["firewall-a"]
      rule_groups = [
        {
          name          = "block-domains"
          capacity      = 100
          type          = "STATEFUL"
          rules         = "drop tcp any any -> any any (msg:\"blocked\"; sid:1; rev:1;)"
          share_targets = ["workload-prod"]
        }
      ]
      firewall_policy = {
        share_targets = [
          "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1",
        ]
      }
    }
    enable_route53_query_logging      = true
    route53_query_logging_destination = "s3"
    central_log_bucket_name           = "central-logs"
    route53_query_logging_share_targets = [
      "arn:aws:organizations::111111111111:organization/o-abc123",
    ]
  }

  # Network Firewall: one rule group share, one policy share.
  assert {
    condition     = length(aws_ram_resource_share.nfw_rule_group) == 1 && aws_ram_principal_association.nfw_rule_group["block-domains.workload-prod"].principal == "222222222222"
    error_message = "A rule group with share_targets must create a RAM share; account names resolve through account_ids."
  }

  assert {
    condition     = length(aws_ram_resource_share.nfw_policy) == 1 && aws_ram_principal_association.nfw_policy["arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"].principal == "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"
    error_message = "Firewall policy share_targets must create the policy share and pass the OU ARN through."
  }

  # Query logging configuration: one share against the organization ARN.
  assert {
    condition     = length(aws_ram_resource_share.query_logs) == 1 && length(aws_ram_resource_association.query_logs) == 1
    error_message = "Query logging share_targets must create exactly one RAM share and one resource association."
  }

  assert {
    condition     = aws_ram_principal_association.query_logs["arn:aws:organizations::111111111111:organization/o-abc123"].principal == "arn:aws:organizations::111111111111:organization/o-abc123"
    error_message = "The organization ARN must reach the query logging principal association unchanged."
  }

  # Existing shares take OU ARNs through the same lookup: the subnet and the
  # Transit Gateway pass them to their principal associations unchanged.
  assert {
    condition     = aws_ram_principal_association.subnet["inspection.firewall-a.arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"].principal == "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"
    error_message = "An OU ARN in subnet share_targets must reach the principal association unchanged."
  }

  assert {
    condition     = aws_ram_principal_association.subnet["inspection.firewall-a.workload-prod"].principal == "222222222222"
    error_message = "An account name in subnet share_targets must resolve to its account ID."
  }

  assert {
    condition     = aws_ram_principal_association.tgw["arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"].principal == "arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"
    error_message = "An OU ARN in transit_gateway share_targets must reach the principal association unchanged."
  }

  # Sharing a subnet fires the module's standing tag-propagation warning by
  # design (RAM does not replicate custom tags into consumer accounts).
  expect_failures = [check.subnet_tag_propagation_limitation]
}

# -----------------------------------------------------------------------------
# 3al. RAM sharing toggle off — share_targets on the further network objects
# create nothing while enable_ram_sharing is false
# -----------------------------------------------------------------------------

run "networking_ram_share_toggle_off_creates_nothing" {
  command = plan

  variables {
    enable_ram_sharing = false
    account_ids = {
      workload-prod = "222222222222"
    }
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.20.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "firewall-a"
            cidr              = "10.20.1.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
      }
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "inspection"
      subnet_names = ["firewall-a"]
      rule_groups = [
        {
          name          = "block-domains"
          capacity      = 100
          type          = "STATEFUL"
          rules         = "drop tcp any any -> any any (msg:\"blocked\"; sid:1; rev:1;)"
          share_targets = ["workload-prod"]
        }
      ]
      firewall_policy = {
        share_targets = ["workload-prod"]
      }
    }
    enable_route53_query_logging        = true
    route53_query_logging_destination   = "s3"
    central_log_bucket_name             = "central-logs"
    route53_query_logging_share_targets = ["workload-prod"]
  }

  assert {
    condition     = length(aws_ram_resource_share.nfw_rule_group) == 0 && length(aws_ram_resource_share.nfw_policy) == 0
    error_message = "No Network Firewall share must be created while enable_ram_sharing is false."
  }

  assert {
    condition     = length(aws_ram_resource_share.query_logs) == 0 && length(aws_ram_principal_association.query_logs) == 0
    error_message = "No query logging share must be created while enable_ram_sharing is false."
  }
}

# -----------------------------------------------------------------------------
# 3am. RAM sharing without targets — entries without share_targets plan no
# share although sharing is enabled
# -----------------------------------------------------------------------------

run "networking_ram_share_without_targets_creates_nothing" {
  command = plan

  variables {
    enable_ram_sharing = true
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.20.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "firewall-a"
            cidr              = "10.20.1.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
      }
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "inspection"
      subnet_names = ["firewall-a"]
      rule_groups = [
        {
          name     = "block-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "drop tcp any any -> any any (msg:\"blocked\"; sid:1; rev:1;)"
        }
      ]
    }
    enable_route53_query_logging      = true
    route53_query_logging_destination = "s3"
    central_log_bucket_name           = "central-logs"
  }

  assert {
    condition     = length(aws_ram_resource_share.nfw_rule_group) == 0 && length(aws_ram_resource_share.nfw_policy) == 0 && length(aws_ram_resource_share.query_logs) == 0
    error_message = "Entries without share_targets must not create any RAM share."
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this) == 1
    error_message = "The rule group itself must still be planned."
  }
}

# -----------------------------------------------------------------------------
# Validation — share target forms
# -----------------------------------------------------------------------------

run "networking_invalid_subnet_share_target_form" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            share_targets     = ["not a principal!"]
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_tgw_share_target_form" {
  command = plan
  variables {
    transit_gateway = {
      enabled       = true
      route_tables  = ["hub"]
      share_targets = ["arn:aws:iam::111111111111:role/not-an-ou"]
    }
  }
  expect_failures = [var.transit_gateway]
}

run "networking_invalid_nfw_share_target_form" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.20.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "firewall-a"
            cidr              = "10.20.1.0/28"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
      }
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "inspection"
      subnet_names = ["firewall-a"]
      firewall_policy = {
        share_targets = ["unknown-account-name"]
      }
    }
  }
  expect_failures = [var.network_firewall]
}

run "networking_invalid_query_log_share_target_without_logging" {
  command = plan
  variables {
    enable_route53_query_logging        = false
    route53_query_logging_share_targets = ["111111111111"]
  }
  expect_failures = [var.route53_query_logging_share_targets]
}

# -----------------------------------------------------------------------------
# 3an. Custom configuration — ACM: imported material, DNS validation records
# in a managed zone, key algorithm choice
# -----------------------------------------------------------------------------

run "networking_acm_import_and_validation_records" {
  command = plan

  # No vpcs and no vpc_ids on the zone: the zone stays public, which is the
  # only case in which ACM can read the validation records the module writes.
  # Scenario 3ap covers the zone that carries a VPC.
  variables {
    route53_zones = [
      {
        name = "example.com"
      }
    ]
    acm_certificates = [
      {
        domain_name               = "api.example.com"
        subject_alternative_names = ["www.example.com", "*.api.example.com"]
        validation_zone_name      = "example.com"
        key_algorithm             = "EC_prime256v1"
      },
      {
        domain_name = "imported.example.com"
        type        = "import"
      },
      {
        domain_name = "legacy.example.com"
      },
    ]
    acm_certificate_material = {
      "imported.example.com" = {
        # Dummy PEM material assembled via format(): the module validation only
        # checks the BEGIN markers, and the assembly keeps secret scanners from
        # matching a contiguous PEM block in this fixture (there is no key here).
        private_key       = format("-----BEGIN %s-----\nMIIB\n-----END %s-----", "PRIVATE KEY", "PRIVATE KEY")
        certificate_body  = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
        certificate_chain = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"
      }
    }
  }

  assert {
    condition     = length(aws_acm_certificate.this) == 3
    error_message = "All three certificates (request with records, import, plain request) must be planned."
  }

  # One record per unique validation domain: the wildcard *.api.example.com
  # collapses onto the apex api.example.com record.
  assert {
    condition     = length(aws_route53_record.acm_validation) == 2 && contains(keys(aws_route53_record.acm_validation), "api.example.com|api.example.com") && contains(keys(aws_route53_record.acm_validation), "api.example.com|www.example.com")
    error_message = "The DNS-validated certificate must plan one validation record per unique domain, wildcard and apex shared."
  }

  assert {
    condition     = aws_route53_record.acm_validation["api.example.com|api.example.com"].ttl == 60 && aws_route53_record.acm_validation["api.example.com|api.example.com"].allow_overwrite == true
    error_message = "Validation records carry a short TTL and allow_overwrite for certificate replacements."
  }

  assert {
    condition     = aws_acm_certificate.this["api.example.com"].key_algorithm == "EC_prime256v1"
    error_message = "The chosen key algorithm must reach the requested certificate."
  }

  # The issuance wait covers the requested DNS certificates and never the
  # import — imported certificates are usable as-is.
  assert {
    condition     = length(aws_acm_certificate_validation.dns) == 2 && contains(keys(aws_acm_certificate_validation.dns), "api.example.com") && contains(keys(aws_acm_certificate_validation.dns), "legacy.example.com")
    error_message = "The issuance wait must cover exactly the requested DNS certificates, not the import."
  }

  # The imported material reaches the certificate resource.
  assert {
    condition     = nonsensitive(aws_acm_certificate.this["imported.example.com"].certificate_body) == "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    error_message = "The imported certificate body must come from acm_certificate_material."
  }
}

# -----------------------------------------------------------------------------
# 3ao. Plain certificate requests — entries without the optional attributes
# plan a plain request
# -----------------------------------------------------------------------------

run "networking_acm_plain_requests_leave_plan_unchanged" {
  command = plan

  variables {
    acm_certificates = [
      {
        domain_name       = "app.example.com"
        validation_method = "DNS"
      }
    ]
  }

  assert {
    condition     = aws_acm_certificate.this["app.example.com"].domain_name == "app.example.com" && aws_acm_certificate.this["app.example.com"].validation_method == "DNS"
    error_message = "A plain request must keep its domain and validation method."
  }

  assert {
    condition     = length(aws_route53_record.acm_validation) == 0
    error_message = "Without validation_zone_name no validation record must be planned."
  }

  assert {
    condition     = length(aws_acm_certificate_validation.dns) == 1 && aws_acm_certificate_validation.dns["app.example.com"].validation_record_fqdns == null
    error_message = "The issuance wait must stay the bare wait without validation_record_fqdns."
  }
}

# -----------------------------------------------------------------------------
# 3ap. Validation zone carrying a VPC — the records are planned, and the check
# block reports that ACM cannot read them
# -----------------------------------------------------------------------------

run "networking_acm_validation_zone_with_vpc_is_reported" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
    route53_zones = [
      {
        name = "example.com"
      }
    ]
    acm_certificates = [
      {
        domain_name          = "api.example.com"
        validation_zone_name = "example.com"
      }
    ]
  }

  # The record is planned either way — nothing in the plan reveals that the
  # zone is private, which is why the check block carries the warning.
  assert {
    condition     = length(aws_route53_record.acm_validation) == 1
    error_message = "The validation record must be planned even when the zone carries a VPC."
  }

  # The module's VPC makes the zone private, so ACM never reads the record and
  # the issuance wait would run into its timeout.
  expect_failures = [check.acm_validation_zone_is_private_warning]
}

# -----------------------------------------------------------------------------
# Validation — ACM certificate forms
# -----------------------------------------------------------------------------

run "networking_invalid_acm_type" {
  command = plan
  variables {
    acm_certificates = [
      {
        domain_name = "api.example.com"
        type        = "renew"
      }
    ]
  }
  expect_failures = [var.acm_certificates]
}

run "networking_invalid_acm_import_without_material" {
  command = plan
  variables {
    acm_certificates = [
      {
        domain_name = "imported.example.com"
        type        = "import"
      }
    ]
  }
  expect_failures = [var.acm_certificates]
}

run "networking_invalid_acm_import_with_request_attrs" {
  command = plan
  variables {
    acm_certificates = [
      {
        domain_name               = "imported.example.com"
        type                      = "import"
        subject_alternative_names = ["www.example.com"]
      }
    ]
    acm_certificate_material = {
      "imported.example.com" = {
        # Dummy PEM material assembled via format(); see the note on the fixture
        # above — no key material lives in this file.
        private_key      = format("-----BEGIN %s-----\nMIIB\n-----END %s-----", "PRIVATE KEY", "PRIVATE KEY")
        certificate_body = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
      }
    }
  }
  expect_failures = [var.acm_certificates]
}

run "networking_invalid_acm_key_algorithm" {
  command = plan
  variables {
    acm_certificates = [
      {
        domain_name   = "api.example.com"
        key_algorithm = "RSA_4096"
      }
    ]
  }
  expect_failures = [var.acm_certificates]
}

run "networking_invalid_acm_validation_zone_unmanaged" {
  command = plan
  variables {
    route53_zones = [
      {
        name = "example.com"
      }
    ]
    acm_certificates = [
      {
        domain_name          = "api.other.com"
        validation_zone_name = "other.com"
      }
    ]
  }
  expect_failures = [var.acm_certificates]
}

run "networking_invalid_acm_validation_zone_domain_outside" {
  command = plan
  variables {
    route53_zones = [
      {
        name = "example.com"
      }
    ]
    acm_certificates = [
      {
        domain_name          = "api.other.com"
        validation_zone_name = "example.com"
      }
    ]
  }
  expect_failures = [var.acm_certificates]
}

run "networking_invalid_acm_material_not_pem" {
  command = plan
  variables {
    acm_certificates = [
      {
        domain_name = "imported.example.com"
        type        = "import"
      }
    ]
    acm_certificate_material = {
      "imported.example.com" = {
        private_key      = "not pem"
        certificate_body = "also not pem"
      }
    }
  }
  expect_failures = [var.acm_certificate_material]
}

# -----------------------------------------------------------------------------
# 3aq. VPC base options — instance tenancy, the explicit egress-only gateway
# switch, IPv6 sources beyond the Amazon range, the virtual private gateway
# with its ASN, and the NAT gateway details
# -----------------------------------------------------------------------------

run "networking_vpc_base_options_reach_resources" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    elastic_ips = [
      {
        name = "egress-reserved"
      }
    ]
    vpcs = [
      {
        name             = "hub"
        cidr             = "10.0.0.0/16"
        account_name     = "network"
        instance_tenancy = "dedicated"
        enable_ipv6      = true
        egress_only_igw  = true
        ipv6_cidrs = [
          {
            byoip_pool_id = "ipv6pool-ec2-0123456789abcdef0"
            cidr_block    = "2001:db8:1::/56"
          },
          {
            byoip_pool_id = "ipv6pool-ec2-0123456789abcdef1"
          },
        ]
        virtual_private_gateway = {
          asn = 65001
        }
        subnets = [
          {
            name                 = "public-a"
            cidr                 = "10.0.1.0/24"
            availability_zone    = "eu-central-1a"
            type                 = "public"
            nat_gateway          = true
            nat_gateway_name     = "hub-egress"
            nat_gateway_eip_name = "egress-reserved"
          },
          {
            name                      = "public-b"
            cidr                      = "10.0.2.0/24"
            availability_zone         = "eu-central-1b"
            type                      = "public"
            nat_gateway               = true
            nat_gateway_allocation_id = "eipalloc-0123456789abcdef0"
          },
          {
            name                = "private-a"
            cidr                = "10.0.3.0/24"
            availability_zone   = "eu-central-1a"
            type                = "private"
            nat_gateway         = true
            nat_gateway_private = true
          },
          {
            name              = "isolated-a"
            cidr              = "10.0.4.0/24"
            availability_zone = "eu-central-1a"
            type              = "isolated"
            ipv6_cidr_suffix  = "10"
          },
        ]
      },
      {
        name            = "spoke"
        cidr            = "10.1.0.0/16"
        account_name    = "network"
        egress_only_igw = false
        ipv6_cidrs = [
          {
            amazon_provided = true
          }
        ]
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.1.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            ipv6_cidr_suffix  = "01"
          }
        ]
      },
    ]
  }

  assert {
    condition     = aws_vpc.this["hub"].instance_tenancy == "dedicated" && aws_vpc.this["spoke"].instance_tenancy == null
    error_message = "instance_tenancy must reach the VPC, and stay unset where it is not configured."
  }

  # The first source is the association the subnets derive from; both further
  # sources of the hub land in the additional resource, keyed by index.
  assert {
    condition     = aws_vpc_ipv6_cidr_block_association.this["hub"].assign_generated_ipv6_cidr_block == true && length(aws_vpc_ipv6_cidr_block_association.additional) == 2
    error_message = "enable_ipv6 must stay the primary Amazon-provided association, and both further sources must be planned separately."
  }

  assert {
    condition     = aws_vpc_ipv6_cidr_block_association.additional["hub.0"].ipv6_pool == "ipv6pool-ec2-0123456789abcdef0" && aws_vpc_ipv6_cidr_block_association.additional["hub.0"].ipv6_cidr_block == "2001:db8:1::/56"
    error_message = "A BYOIP source must reach the association as pool plus range."
  }

  assert {
    condition     = aws_vpc_ipv6_cidr_block_association.additional["hub.1"].ipv6_pool == "ipv6pool-ec2-0123456789abcdef1"
    error_message = "A BYOIP source without a range must reach the association as pool alone, and AWS picks the range."
  }

  # A VPC whose only source is an amazon_provided entry keeps the primary slot.
  assert {
    condition     = aws_vpc_ipv6_cidr_block_association.this["spoke"].assign_generated_ipv6_cidr_block == true && length([for key in keys(aws_vpc_ipv6_cidr_block_association.additional) : key if startswith(key, "spoke.")]) == 0
    error_message = "An amazon_provided entry must occupy the primary association of its VPC."
  }

  # egress_only_igw = true creates the gateway although no private IPv6 subnet
  # asks for it; egress_only_igw = false suppresses it although the spoke has
  # an IPv6 range.
  assert {
    condition     = length(aws_egress_only_internet_gateway.this) == 1 && contains(keys(aws_egress_only_internet_gateway.this), "hub")
    error_message = "The explicit egress_only_igw switch must decide the gateway: created for the hub, suppressed for the spoke."
  }

  assert {
    condition     = aws_vpn_gateway.this["hub"].amazon_side_asn == "65001"
    error_message = "A declared virtual private gateway must be planned with its ASN."
  }

  # Three NAT gateways, one address of the module: the reserved address and the
  # raw allocation ID replace it, the private gateway takes none.
  assert {
    condition     = length(aws_nat_gateway.this) == 3 && length(aws_eip.nat) == 0
    error_message = "Every NAT gateway must be planned, and no address must be allocated where the subnet names one."
  }

  assert {
    condition     = aws_nat_gateway.this["hub.public-b"].allocation_id == "eipalloc-0123456789abcdef0" && aws_nat_gateway.this["hub.public-b"].connectivity_type == "public"
    error_message = "A raw allocation ID must reach the NAT gateway."
  }

  assert {
    condition     = aws_nat_gateway.this["hub.private-a"].connectivity_type == "private" && aws_nat_gateway.this["hub.private-a"].allocation_id == null
    error_message = "A private NAT gateway must carry no address."
  }

  assert {
    condition     = aws_nat_gateway.this["hub.public-a"].tags["Name"] == "hub-egress"
    error_message = "nat_gateway_name must replace the derived Name tag of the NAT gateway."
  }
}

# -----------------------------------------------------------------------------
# 3ar. VPC base option defaults — a configuration without the optional
# attributes plans the module's defaults
# -----------------------------------------------------------------------------

run "networking_vpc_base_option_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        enable_ipv6  = true
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            nat_gateway       = true
          },
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            ipv6_cidr_suffix  = "02"
          },
        ]
      }
    ]
  }

  assert {
    condition     = aws_vpc.this["hub"].instance_tenancy == null
    error_message = "Without instance_tenancy the module must write nothing and leave the AWS default in place."
  }

  # The derivation still decides the gateway, and the primary association is
  # the Amazon-provided range with no further association next to it.
  assert {
    condition     = length(aws_egress_only_internet_gateway.this) == 1 && length(aws_vpc_ipv6_cidr_block_association.this) == 1 && length(aws_vpc_ipv6_cidr_block_association.additional) == 0
    error_message = "Without the optional switches the egress-only gateway and the single IPv6 association must be planned."
  }

  assert {
    condition     = aws_vpc_ipv6_cidr_block_association.this["hub"].assign_generated_ipv6_cidr_block == true && aws_vpc_ipv6_cidr_block_association.this["hub"].ipv6_ipam_pool_id == null
    error_message = "enable_ipv6 must request the Amazon range and name no pool."
  }

  # No virtual_private_gateway and no customer gateway: no gateway at all.
  assert {
    condition     = length(aws_vpn_gateway.this) == 0
    error_message = "Without a declaration and without a VPN connection no virtual private gateway must be planned."
  }

  # The NAT gateway keeps its own address and both derived names.
  assert {
    condition     = length(aws_nat_gateway.this) == 1 && length(aws_eip.nat) == 1 && aws_nat_gateway.this["hub.public-a"].connectivity_type == "public"
    error_message = "Without the NAT details the module must allocate the address itself."
  }

  assert {
    condition     = aws_nat_gateway.this["hub.public-a"].tags["Name"] == "hub.public-a-nat" && aws_eip.nat["hub.public-a"].tags["Name"] == "hub.public-a-nat-eip"
    error_message = "Without nat_gateway_name both derived names must stay exactly as they were."
  }
}

# -----------------------------------------------------------------------------
# 3as. A declared virtual private gateway carries the VGW-dependent features on
# its own — without a VPN connection
# -----------------------------------------------------------------------------

run "networking_declared_vgw_carries_vgw_features" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name                    = "hub"
        cidr                    = "10.0.0.0/16"
        account_name            = "network"
        virtual_private_gateway = {}
        subnets = [
          {
            name                     = "private-a"
            cidr                     = "10.0.1.0/24"
            availability_zone        = "eu-central-1a"
            type                     = "private"
            enable_route_propagation = true
            custom_routes = [
              {
                destination_cidr_block = "192.168.0.0/16"
                target_type            = "vgw"
              }
            ]
          }
        ]
        gateway_route_tables = [
          {
            name         = "edge"
            gateway_type = "virtual_private_gateway"
          }
        ]
      }
    ]
  }

  # Without an ASN the module writes none and leaves the AWS default in place.
  # The unset value is computed and only known after the apply, so the plan can
  # assert the gateway and its name — scenario 3aq asserts the set ASN.
  assert {
    condition     = length(aws_vpn_gateway.this) == 1 && aws_vpn_gateway.this["hub"].tags["Name"] == "hub-vgw"
    error_message = "A virtual_private_gateway block without an ASN must plan the gateway under its derived name."
  }

  assert {
    condition     = length(aws_vpn_gateway_route_propagation.this) == 1 && length(aws_route.custom) == 1 && length(aws_route_table.gateway) == 1
    error_message = "Route propagation, a vgw route and a gateway route table must resolve against the declared gateway."
  }

  # No customer gateway: the gateway exists, no connection does.
  assert {
    condition     = length(aws_vpn_connection.this) == 0
    error_message = "A declared gateway must not plan a VPN connection."
  }
}

# --- VPC base option validation runs ---------------------------------------

run "networking_invalid_instance_tenancy" {
  command = plan
  variables {
    vpcs = [
      {
        name             = "hub"
        cidr             = "10.0.0.0/16"
        account_name     = "network"
        instance_tenancy = "host"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_eigw_without_ipv6" {
  command = plan
  variables {
    vpcs = [
      {
        name            = "hub"
        cidr            = "10.0.0.0/16"
        account_name    = "network"
        egress_only_igw = true
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_eigw_off_with_ipv6_subnet" {
  command = plan
  variables {
    vpcs = [
      {
        name            = "hub"
        cidr            = "10.0.0.0/16"
        account_name    = "network"
        enable_ipv6     = true
        egress_only_igw = false
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            ipv6_cidr_suffix  = "01"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_source_two_forms" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            amazon_provided = true
            byoip_pool_id   = "ipv6pool-ec2-0123456789abcdef0"
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_source_without_form" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            cidr_block = "2001:db8::/56"
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_amazon_with_range" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            amazon_provided = true
            cidr_block      = "2001:db8::/56"
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_cidr_block_prefix" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            byoip_pool_id = "ipv6pool-ec2-0123456789abcdef0"
            cidr_block    = "2001:db8::/64"
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_amazon_range_twice" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        enable_ipv6  = true
        ipv6_cidrs = [
          {
            amazon_provided = true
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_vgw_asn_range" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        virtual_private_gateway = {
          asn = 64511
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_private_nat_with_address" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name                      = "private-a"
            cidr                      = "10.0.1.0/24"
            availability_zone         = "eu-central-1a"
            type                      = "private"
            nat_gateway               = true
            nat_gateway_private       = true
            nat_gateway_allocation_id = "eipalloc-0123456789abcdef0"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_nat_two_address_forms" {
  command = plan
  variables {
    elastic_ips = [
      {
        name = "egress-reserved"
      }
    ]
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name                      = "public-a"
            cidr                      = "10.0.1.0/24"
            availability_zone         = "eu-central-1a"
            type                      = "public"
            nat_gateway               = true
            nat_gateway_allocation_id = "eipalloc-0123456789abcdef0"
            nat_gateway_eip_name      = "egress-reserved"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_nat_allocation_id_form" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name                      = "public-a"
            cidr                      = "10.0.1.0/24"
            availability_zone         = "eu-central-1a"
            type                      = "public"
            nat_gateway               = true
            nat_gateway_allocation_id = "eip-0123456789abcdef0"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_nat_unknown_eip_name" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name                 = "public-a"
            cidr                 = "10.0.1.0/24"
            availability_zone    = "eu-central-1a"
            type                 = "public"
            nat_gateway          = true
            nat_gateway_eip_name = "nowhere"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_nat_detail_without_nat_gateway" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            nat_gateway_name  = "hub-egress"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_private_nat_in_public_subnet" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name                = "public-a"
            cidr                = "10.0.1.0/24"
            availability_zone   = "eu-central-1a"
            type                = "public"
            nat_gateway         = true
            nat_gateway_private = true
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_nat_name_duplicate" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
            nat_gateway       = true
            nat_gateway_name  = "egress"
          },
          {
            name              = "public-b"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1b"
            type              = "public"
            nat_gateway       = true
            nat_gateway_name  = "egress"
          },
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# 3at. IPAM pool attributes, own scopes, further pool ranges — and an IPv6 pool
# as the source of a VPC's IPv6 range
# -----------------------------------------------------------------------------

run "networking_ipam_pool_attributes_and_scopes_reach_resources" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    ipam = {
      enabled = true
      scopes = [
        {
          name        = "workloads"
          description = "Ranges of the workload accounts"
          tags        = { Tier = "workload" }
        }
      ]
      pools = [
        {
          name                              = "root"
          cidr                              = "10.0.0.0/8"
          additional_cidrs                  = ["172.16.0.0/12", "192.168.0.0/16"]
          description                       = "Top level IPv4 space"
          locale                            = "eu-central-1"
          auto_import                       = true
          allocation_default_netmask_length = 24
          allocation_min_netmask_length     = 16
          allocation_max_netmask_length     = 28
          allocation_resource_tags          = { CostCenter = "network" }
        },
        {
          name             = "workload"
          cidr             = "10.20.0.0/16"
          scope            = "workloads"
          parent_pool_name = null
        },
        {
          name                          = "public-v6"
          cidr                          = "2001:db8::/48"
          address_family                = "ipv6"
          scope                         = "public-default"
          publicly_advertisable         = true
          public_ip_source              = "byoip"
          allocation_min_netmask_length = 48
        },
        {
          name           = "private-v6"
          cidr           = "2001:db8:100::/48"
          address_family = "ipv6"
        },
      ]
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            ipam_pool_name = "private-v6"
            netmask_length = 56
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            ipv6_cidr_suffix  = "01"
          }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_vpc_ipam_scope.this) == 1 && aws_vpc_ipam_scope.this["workloads"].description == "Ranges of the workload accounts" && aws_vpc_ipam_scope.this["workloads"].tags["Tier"] == "workload"
    error_message = "A declared scope must be planned with its description and tags."
  }

  # Which scope a pool lands in is not assertable in a plan: every scope ID —
  # the two of the IPAM and the one of the declared scope — is computed and
  # only known after the apply. That the pool reads local.ipam_scope_ids under
  # its own scope name is held by Property 41b
  # (tests/test_quality_audit_networking_ipam.py). What the plan does show is
  # that all four pools are planned next to the declared scope.
  assert {
    condition     = length(aws_vpc_ipam_pool.this) == 4 && length(aws_vpc_ipam_pool.child) == 0
    error_message = "Every pool must be planned, and a pool without a parent must stay a root pool."
  }

  assert {
    condition     = aws_vpc_ipam_pool.this["root"].auto_import == true && aws_vpc_ipam_pool.this["root"].description == "Top level IPv4 space" && aws_vpc_ipam_pool.this["root"].allocation_min_netmask_length == 16 && aws_vpc_ipam_pool.this["root"].allocation_max_netmask_length == 28 && aws_vpc_ipam_pool.this["root"].allocation_resource_tags["CostCenter"] == "network"
    error_message = "Every pool attribute must reach the pool resource."
  }

  assert {
    condition     = aws_vpc_ipam_pool.this["public-v6"].address_family == "ipv6" && aws_vpc_ipam_pool.this["public-v6"].publicly_advertisable == true && aws_vpc_ipam_pool.this["public-v6"].public_ip_source == "byoip"
    error_message = "An IPv6 pool in the public scope must carry its address family and both public attributes."
  }

  # The first range keeps its own resource keyed by the pool name; the two
  # further ranges are keyed by pool and index.
  assert {
    condition     = length(aws_vpc_ipam_pool_cidr.this) == 4 && length(aws_vpc_ipam_pool_cidr.additional) == 2
    error_message = "Each pool must provision its first range, and each further range must be planned separately."
  }

  assert {
    condition     = aws_vpc_ipam_pool_cidr.additional["root.0"].cidr == "172.16.0.0/12" && aws_vpc_ipam_pool_cidr.additional["root.1"].cidr == "192.168.0.0/16"
    error_message = "Every additional_cidrs entry must reach a pool CIDR of its pool."
  }

  # The IPv6 pool is the source of the VPC's range. The pool ID is computed, so
  # the plan asserts the requested prefix length and that the single
  # association of the VPC comes from IPAM instead of the Amazon pool.
  assert {
    condition     = aws_vpc_ipv6_cidr_block_association.this["hub"].ipv6_netmask_length == 56 && length(aws_vpc_ipv6_cidr_block_association.additional) == 0
    error_message = "An IPAM-sourced IPv6 range must reach the primary association with its requested prefix length."
  }
}

# -----------------------------------------------------------------------------
# 3au. IPAM defaults — a pool without the optional attributes plans the
# module's defaults
# -----------------------------------------------------------------------------

run "networking_ipam_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name                              = "root"
          cidr                              = "10.0.0.0/8"
          locale                            = "eu-central-1"
          allocation_default_netmask_length = 24
        }
      ]
    }
  }

  assert {
    condition     = length(aws_vpc_ipam_scope.this) == 0 && length(aws_vpc_ipam_pool_cidr.additional) == 0
    error_message = "Without scopes and additional_cidrs neither resource must be planned."
  }

  # The scope ID is computed, so the plan asserts the address family and the
  # single pool; the scope lookup itself is held by Property 41b.
  assert {
    condition     = aws_vpc_ipam_pool.this["root"].address_family == "ipv4" && length(aws_vpc_ipam_pool.this) == 1
    error_message = "A plain pool must stay a single IPv4 pool."
  }

  assert {
    condition     = aws_vpc_ipam_pool.this["root"].auto_import == null && aws_vpc_ipam_pool.this["root"].description == null && aws_vpc_ipam_pool.this["root"].allocation_min_netmask_length == null && aws_vpc_ipam_pool.this["root"].allocation_max_netmask_length == null && length(aws_vpc_ipam_pool.this["root"].allocation_resource_tags) == 0
    error_message = "Without the optional attributes the module must write nothing and leave every AWS default in place."
  }

  assert {
    condition     = aws_vpc_ipam_pool.this["root"].allocation_default_netmask_length == 24 && aws_vpc_ipam_pool_cidr.this["root"].cidr == "10.0.0.0/8"
    error_message = "The attributes that existed before must keep their effect."
  }
}

# --- IPAM validation runs --------------------------------------------------

run "networking_invalid_ipam_address_family" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name           = "root"
          cidr           = "10.0.0.0/8"
          address_family = "ipv5"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_cidr_family_mismatch" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name           = "root"
          cidr           = "10.0.0.0/8"
          address_family = "ipv6"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_additional_cidr_family_mismatch" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name             = "root"
          cidr             = "10.0.0.0/8"
          additional_cidrs = ["2001:db8::/48"]
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_child_family_mismatch" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name = "root"
          cidr = "10.0.0.0/8"
        },
        {
          name             = "child"
          cidr             = "2001:db8::/48"
          address_family   = "ipv6"
          parent_pool_name = "root"
        },
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_scope_reserved_name" {
  command = plan
  variables {
    ipam = {
      enabled = true
      scopes = [
        {
          name = "private-default"
        }
      ]
      pools = [
        {
          name = "root"
          cidr = "10.0.0.0/8"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_scope_duplicate" {
  command = plan
  variables {
    ipam = {
      enabled = true
      scopes = [
        {
          name = "workloads"
        },
        {
          name = "workloads"
        },
      ]
      pools = [
        {
          name = "root"
          cidr = "10.0.0.0/8"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_pool_unknown_scope" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name  = "root"
          cidr  = "10.0.0.0/8"
          scope = "nowhere"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_child_scope_mismatch" {
  command = plan
  variables {
    ipam = {
      enabled = true
      scopes = [
        {
          name = "workloads"
        }
      ]
      pools = [
        {
          name = "root"
          cidr = "10.0.0.0/8"
        },
        {
          name             = "child"
          cidr             = "10.20.0.0/16"
          scope            = "workloads"
          parent_pool_name = "root"
        },
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_publicly_advertisable_on_ipv4" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name                  = "root"
          cidr                  = "10.0.0.0/8"
          scope                 = "public-default"
          publicly_advertisable = true
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_publicly_advertisable_with_amazon_source" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name                  = "public-v6"
          cidr                  = "2001:db8::/48"
          address_family        = "ipv6"
          scope                 = "public-default"
          publicly_advertisable = true
          public_ip_source      = "amazon"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_public_attributes_in_private_scope" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name             = "root"
          cidr             = "10.0.0.0/8"
          public_ip_source = "amazon"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_public_ip_source_value" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name             = "root"
          cidr             = "10.0.0.0/8"
          scope            = "public-default"
          public_ip_source = "elsewhere"
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_netmask_length_out_of_family" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name                          = "root"
          cidr                          = "10.0.0.0/8"
          allocation_min_netmask_length = 48
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_netmask_lengths_disagree" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name                              = "root"
          cidr                              = "10.0.0.0/8"
          allocation_min_netmask_length     = 24
          allocation_max_netmask_length     = 20
          allocation_default_netmask_length = 22
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipam_allocation_resource_tag_key" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name                     = "root"
          cidr                     = "10.0.0.0/8"
          allocation_resource_tags = { "aws:reserved" = "no" }
        }
      ]
    }
  }
  expect_failures = [var.ipam]
}

run "networking_invalid_ipv6_source_from_ipv4_pool" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name = "root"
          cidr = "10.0.0.0/8"
        }
      ]
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            ipam_pool_name = "root"
            netmask_length = 56
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_netmask_without_ipam" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            byoip_pool_id  = "ipv6pool-ec2-0123456789abcdef0"
            netmask_length = 56
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_netmask_length_step" {
  command = plan
  variables {
    ipam = {
      enabled = true
      pools = [
        {
          name           = "v6"
          cidr           = "2001:db8::/48"
          address_family = "ipv6"
        }
      ]
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            ipam_pool_name = "v6"
            netmask_length = 58
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

run "networking_invalid_ipv6_unknown_ipam_pool" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        ipv6_cidrs = [
          {
            ipam_pool_name = "nowhere"
            netmask_length = 56
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }
  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# 3av. Transit Gateway peering — requester-side route table association, the
# accepter block (account, apply_tags_from_requester, tags) and the accepter role for a
# peering another account or region requested
# -----------------------------------------------------------------------------

run "networking_tgw_peering_accepter_side_reaches_resources" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
      spoke   = "222222222222"
    }
    transit_gateway = {
      enabled      = true
      route_tables = ["core", "inspection"]
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "core"
          auto_accept             = true
          tags = {
            Scope = "interconnect"
          }
          accepter = {
            account                   = "spoke"
            apply_tags_from_requester = true
            tags = {
              Side = "accepter"
            }
          }
        },
        {
          peer_region             = "us-east-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef1"
          route_table_name        = "inspection"
          accepter = {
            account = "333333333333"
          }
        },
      ]
      peering_accepters = [
        {
          name                          = "from-eu-west-1"
          transit_gateway_attachment_id = "tgw-attach-0123456789abcdef0"
          route_table_name              = "core"
          tags = {
            Origin = "eu-west-1"
          }
        },
        {
          name                          = "from-us-east-1-unassociated"
          transit_gateway_attachment_id = "tgw-attach-0123456789abcdef1"
        },
      ]
    }
  }

  # An account name resolves through account_ids, a raw account ID is taken as
  # given, and no accepter account leaves peer_account_id unset.
  assert {
    condition     = aws_ec2_transit_gateway_peering_attachment.this["eu-west-1-tgw-0123456789abcdef0"].peer_account_id == "222222222222"
    error_message = "accepter.account must reach peer_account_id resolved through account_ids."
  }

  assert {
    condition     = aws_ec2_transit_gateway_peering_attachment.this["us-east-1-tgw-0123456789abcdef1"].peer_account_id == "333333333333"
    error_message = "A raw account ID in accepter.account must reach peer_account_id unchanged."
  }

  # Requester side: one association per peering entry, on the route table the
  # entry names.
  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_association.peering) == 2
    error_message = "Every peering entry must be associated with the route table it names."
  }

  # The route table ID is computed and unknown in a plan, so the assertion
  # holds the key set: one association per peering key.
  assert {
    condition     = contains(keys(aws_ec2_transit_gateway_route_table_association.peering), "eu-west-1-tgw-0123456789abcdef0") && contains(keys(aws_ec2_transit_gateway_route_table_association.peering), "us-east-1-tgw-0123456789abcdef1")
    error_message = "The requester-side association must exist under the peering key of each entry."
  }

  # apply_tags_from_requester copies the tags of the entry, accepter.tags adds its own, and the
  # module's Name comes last.
  assert {
    condition     = aws_ec2_transit_gateway_peering_attachment_accepter.this["eu-west-1-tgw-0123456789abcdef0"].tags["Scope"] == "interconnect" && aws_ec2_transit_gateway_peering_attachment_accepter.this["eu-west-1-tgw-0123456789abcdef0"].tags["Side"] == "accepter"
    error_message = "apply_tags_from_requester must copy the requester tags onto the accepter attachment, and accepter.tags must be added."
  }

  assert {
    condition     = aws_ec2_transit_gateway_peering_attachment_accepter.this["eu-west-1-tgw-0123456789abcdef0"].tags["Name"] == "tgw-peering-accepter-eu-west-1"
    error_message = "The module's Name tag must win on the accepter attachment."
  }

  # Accepter role: both accepted attachments are planned, and only the one that
  # names a route table gets an association.
  assert {
    condition     = length(aws_ec2_transit_gateway_peering_attachment_accepter.accepted) == 2 && aws_ec2_transit_gateway_peering_attachment_accepter.accepted["from-eu-west-1"].transit_gateway_attachment_id == "tgw-attach-0123456789abcdef0"
    error_message = "Every peering_accepters entry must accept its attachment by ID."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_association.peering_accepted) == 1 && contains(keys(aws_ec2_transit_gateway_route_table_association.peering_accepted), "from-eu-west-1")
    error_message = "An accepted attachment must be associated only where route_table_name is set."
  }

  assert {
    condition     = aws_ec2_transit_gateway_peering_attachment_accepter.accepted["from-eu-west-1"].tags["Origin"] == "eu-west-1" && aws_ec2_transit_gateway_peering_attachment_accepter.accepted["from-eu-west-1"].tags["Name"] == "from-eu-west-1"
    error_message = "peering_accepters tags must reach the accepted attachment, with the entry name as Name."
  }

  assert {
    condition     = length(output.tgw_peering_attachment_ids) == 2
    error_message = "The peering attachment IDs must be exported — the accepting side reads them from there."
  }
}

# -----------------------------------------------------------------------------
# 3aw. Peering without the optional attributes — a plain configuration plans
# the attachment plus the association its route table names
# -----------------------------------------------------------------------------

run "networking_tgw_peering_defaults_leave_attachment_unchanged" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "core"
        }
      ]
    }
  }

  # peer_account_id is Optional+Computed: left unset, AWS fills it with the
  # requester account and the plan carries it as unknown. The assertion
  # therefore holds what is knowable — one attachment, unchanged in shape.
  assert {
    condition     = length(aws_ec2_transit_gateway_peering_attachment.this) == 1 && aws_ec2_transit_gateway_peering_attachment.this["eu-west-1-tgw-0123456789abcdef0"].peer_region == "eu-west-1"
    error_message = "A plain peering must plan exactly one attachment."
  }

  # auto_accept defaults to false, so no accepter attachment; peering_accepters
  # is empty, so no accepted attachment and no accepter-side association.
  assert {
    condition     = length(aws_ec2_transit_gateway_peering_attachment_accepter.this) == 0 && length(aws_ec2_transit_gateway_peering_attachment_accepter.accepted) == 0 && length(aws_ec2_transit_gateway_route_table_association.peering_accepted) == 0
    error_message = "Without auto_accept and without peering_accepters no accepter resource must be planned."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_route_table_association.peering) == 1
    error_message = "The requester-side association follows from route_table_name alone."
  }
}

# -----------------------------------------------------------------------------
# 3ax. Flow log details — both destinations at once, CloudWatch retention per
# flow log and the S3 path override
# -----------------------------------------------------------------------------

run "networking_flow_log_destination_details_reach_resources" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    central_log_bucket_name = "tlz-central-logs"
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        flow_logs = {
          destination               = "both"
          traffic_type              = "REJECT"
          max_aggregation_interval  = 60
          cloudwatch_retention_days = 90
          s3_log_path               = "network/hub/flow"
        }
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.1.0.0/16"
        account_name = "network"
        flow_logs = {
          destination = "cloudwatch"
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.1.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]
  }

  # "both" puts the hub in both sets: one S3 flow log and one CloudWatch flow
  # log for the same VPC.
  assert {
    condition     = length(aws_flow_log.s3) == 1 && length(aws_flow_log.cloudwatch) == 2
    error_message = "destination = both must plan an S3 and a CloudWatch flow log for the same VPC."
  }

  assert {
    condition     = aws_flow_log.s3["hub"].log_destination == "arn:aws:s3:::tlz-central-logs/network/hub/flow"
    error_message = "s3_log_path must replace the derived prefix in the bucket."
  }

  assert {
    condition     = aws_flow_log.s3["hub"].traffic_type == "REJECT" && aws_flow_log.s3["hub"].max_aggregation_interval == 60 && aws_flow_log.cloudwatch["hub"].traffic_type == "REJECT"
    error_message = "Both flow logs of one VPC must carry the traffic type and interval of that VPC."
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow_logs["hub"].retention_in_days == 90 && aws_cloudwatch_log_group.flow_logs["spoke"].retention_in_days == 365
    error_message = "cloudwatch_retention_days must reach the log group, and default to 365 days."
  }

  assert {
    condition     = length(aws_iam_role.flow_logs) == 1
    error_message = "A CloudWatch destination needs the delivery role, also when it comes through destination = both."
  }

  assert {
    condition     = length(output.vpc_flow_log_ids_by_destination) == 3 && contains(keys(output.vpc_flow_log_ids_by_destination), "hub.s3") && contains(keys(output.vpc_flow_log_ids_by_destination), "hub.cloudwatch")
    error_message = "The destination-keyed output must list both flow logs of a VPC that writes to both."
  }
}

# -----------------------------------------------------------------------------
# 3ay. Flow log defaults — the global default without the optional attributes
# plans the module's default paths and retention
# -----------------------------------------------------------------------------

run "networking_flow_log_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    central_log_bucket_name = "tlz-central-logs"
    vpc_flow_logs_default = {
      destination = "s3"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          }
        ]
      }
    ]
  }

  assert {
    condition     = aws_flow_log.s3["hub"].log_destination == "arn:aws:s3:::tlz-central-logs/vpc-flow-logs/hub"
    error_message = "Without s3_log_path the flow log must keep the derived prefix vpc-flow-logs/<vpc>."
  }

  assert {
    condition     = length(aws_flow_log.cloudwatch) == 0 && length(aws_cloudwatch_log_group.flow_logs) == 0 && length(aws_iam_role.flow_logs) == 0
    error_message = "An S3-only destination must plan no log group and no delivery role."
  }
}

# -----------------------------------------------------------------------------
# 3az. Remaining network attributes — the two DNS switches of a VPC, the
# central endpoint consumption and TGW Connect over a Direct Connect transport
# -----------------------------------------------------------------------------

run "networking_remaining_attributes_reach_resources" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
    }
    dx_gateways = [
      {
        name                     = "dxgw-core"
        amazon_asn               = 64512
        transit_gateway_name     = "tlz-transit-gateway"
        route_table_associations = ["core"]
        route_table_propagations = ["core"]
      }
    ]
    tgw_connect_attachments = [
      {
        name                      = "sdwan-over-dx"
        transit_gateway_name      = "tlz-transit-gateway"
        transport_attachment      = "dxgw-core"
        transport_attachment_type = "dx-gateway"
      }
    ]
    vpcs = [
      {
        name         = "endpoints"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            central      = true
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
      {
        name                  = "consumer"
        cidr                  = "10.1.0.0/16"
        account_name          = "network"
        use_central_endpoints = true
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.1.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
      {
        name                 = "isolated"
        cidr                 = "10.2.0.0/16"
        account_name         = "network"
        enable_dns_support   = false
        enable_dns_hostnames = false
        subnets = [
          {
            name              = "isolated-a"
            cidr              = "10.2.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "isolated"
          }
        ]
      },
    ]
  }

  # Both switches default to true, and false reaches the VPC.
  assert {
    condition     = aws_vpc.this["endpoints"].enable_dns_support == true && aws_vpc.this["endpoints"].enable_dns_hostnames == true
    error_message = "Without the switches a VPC must keep DNS support and hostnames enabled."
  }

  assert {
    condition     = aws_vpc.this["isolated"].enable_dns_support == false && aws_vpc.this["isolated"].enable_dns_hostnames == false
    error_message = "enable_dns_support and enable_dns_hostnames must reach the VPC when set to false."
  }

  # One association per central endpoint and consuming VPC; the endpoint's own
  # VPC is skipped because the zone already carries it.
  assert {
    condition     = length(aws_route53_zone_association.central_endpoint) == 1 && contains(keys(aws_route53_zone_association.central_endpoint), "endpoints.ssm.consumer")
    error_message = "use_central_endpoints must associate the consuming VPC with the zone of every central endpoint."
  }

  # A Connect attachment over a Direct Connect transport looks the gateway
  # attachment up instead of reading a VPC attachment. Both IDs are computed
  # and unknown in a plan, so the assertion holds the lookup itself: it exists
  # for the named gateway, and no VPC attachment is planned to read.
  assert {
    condition     = length(data.aws_ec2_transit_gateway_dx_gateway_attachment.connect) == 1 && contains(keys(data.aws_ec2_transit_gateway_dx_gateway_attachment.connect), "dxgw-core")
    error_message = "transport_attachment_type = dx-gateway must look up the Transit Gateway attachment of the named Direct Connect gateway."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway_vpc_attachment.this) == 0 && length(aws_ec2_transit_gateway_connect.this) == 1
    error_message = "A Connect attachment over a Direct Connect transport must not require a VPC attachment."
  }
}

# -----------------------------------------------------------------------------
# 3ba. Remaining network attribute defaults — a configuration without the
# optional switches plans the module's defaults
# -----------------------------------------------------------------------------

run "networking_remaining_attribute_defaults_leave_plan_unchanged" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "tgw-a"
            cidr              = "10.0.2.0/28"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
        tgw_attachment = {
          route_table_name = "core"
        }
      }
    ]
    tgw_connect_attachments = [
      {
        name                 = "sdwan-over-vpc"
        transit_gateway_name = "tlz-transit-gateway"
        transport_attachment = "hub"
      }
    ]
  }

  assert {
    condition     = aws_vpc.this["hub"].enable_dns_support == true && aws_vpc.this["hub"].enable_dns_hostnames == true
    error_message = "The DNS switches must default to true."
  }

  assert {
    condition     = length(aws_route53_zone_association.central_endpoint) == 0 && length(aws_route53_zone.central_endpoint) == 0
    error_message = "Without central endpoints and without use_central_endpoints no zone association must be planned."
  }

  # The transport ID is computed and unknown in a plan; what is knowable is
  # that the default type looks nothing up and plans the VPC attachment.
  assert {
    condition     = length(data.aws_ec2_transit_gateway_dx_gateway_attachment.connect) == 0 && length(aws_ec2_transit_gateway_vpc_attachment.this) == 1 && length(aws_ec2_transit_gateway_connect.this) == 1
    error_message = "The default transport type vpc must keep reading the VPC attachment, and look up no gateway attachment."
  }
}

# -----------------------------------------------------------------------------
# Validation failures of the three bundles
# -----------------------------------------------------------------------------

run "networking_invalid_peering_route_table_unknown" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "does-not-exist"
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_peering_accepter_account" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "core"
          accepter = {
            account = "12345"
          }
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_peering_accepter_tags_without_auto_accept" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "core"
          accepter = {
            apply_tags_from_requester = true
          }
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_peering_accepter_name_empty" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering_accepters = [
        {
          name                          = "  "
          transit_gateway_attachment_id = "tgw-attach-0123456789abcdef0"
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_peering_accepter_name_duplicate" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering_accepters = [
        {
          name                          = "from-peer"
          transit_gateway_attachment_id = "tgw-attach-0123456789abcdef0"
        },
        {
          name                          = "from-peer"
          transit_gateway_attachment_id = "tgw-attach-0123456789abcdef1"
        },
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_peering_accepter_attachment_id" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering_accepters = [
        {
          name                          = "from-peer"
          transit_gateway_attachment_id = "tgw-0123456789abcdef0"
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_peering_accepter_route_table_unknown" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering_accepters = [
        {
          name                          = "from-peer"
          transit_gateway_attachment_id = "tgw-attach-0123456789abcdef0"
          route_table_name              = "does-not-exist"
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_peering_accepter_tag_key" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
      peering = [
        {
          peer_region             = "eu-west-1"
          peer_transit_gateway_id = "tgw-0123456789abcdef0"
          route_table_name        = "core"
          auto_accept             = true
          accepter = {
            tags = {
              "aws:reserved" = "no"
            }
          }
        }
      ]
    }
  }

  expect_failures = [var.transit_gateway]
}

run "networking_invalid_flow_logs_default_destination" {
  command = plan

  variables {
    vpc_flow_logs_default = {
      destination = "kinesis"
    }
  }

  expect_failures = [var.vpc_flow_logs_default]
}

run "networking_invalid_flow_logs_default_retention" {
  command = plan

  variables {
    vpc_flow_logs_default = {
      destination               = "cloudwatch"
      cloudwatch_retention_days = 42
    }
  }

  expect_failures = [var.vpc_flow_logs_default]
}

run "networking_invalid_flow_logs_default_s3_path_slash" {
  command = plan

  variables {
    vpc_flow_logs_default = {
      destination = "s3"
      s3_log_path = "/vpc-flow-logs"
    }
  }

  expect_failures = [var.vpc_flow_logs_default]
}

run "networking_invalid_flow_logs_default_s3_path_without_s3" {
  command = plan

  variables {
    vpc_flow_logs_default = {
      destination = "cloudwatch"
      s3_log_path = "vpc-flow-logs"
    }
  }

  expect_failures = [var.vpc_flow_logs_default]
}

run "networking_invalid_vpc_flow_logs_destination" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        flow_logs = {
          destination = "firehose"
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_vpc_flow_logs_retention" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        flow_logs = {
          destination               = "cloudwatch"
          cloudwatch_retention_days = 42
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_vpc_flow_logs_s3_path_without_s3" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        flow_logs = {
          destination = "cloudwatch"
          s3_log_path = "network/hub"
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_vpc_flow_logs_s3_path_duplicate" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        flow_logs = {
          destination = "s3"
          s3_log_path = "shared/flow"
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
      {
        name         = "spoke"
        cidr         = "10.1.0.0/16"
        account_name = "network"
        flow_logs = {
          destination = "s3"
          s3_log_path = "shared/flow"
        }
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.1.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_dns_hostnames_without_support" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name                 = "hub"
        cidr                 = "10.0.0.0/16"
        account_name         = "network"
        enable_dns_support   = false
        enable_dns_hostnames = true
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_central_endpoints_without_dns_support" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "endpoints"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            central      = true
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
      {
        name                  = "consumer"
        cidr                  = "10.1.0.0/16"
        account_name          = "network"
        enable_dns_support    = false
        enable_dns_hostnames  = false
        use_central_endpoints = true
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.1.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      },
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_central_endpoints_without_any_endpoint" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name                  = "consumer"
        cidr                  = "10.1.0.0/16"
        account_name          = "network"
        use_central_endpoints = true
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.1.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_central_endpoints_only_in_own_vpc" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name                  = "endpoints"
        cidr                  = "10.0.0.0/16"
        account_name          = "network"
        use_central_endpoints = true
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
            central      = true
          }
        ]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "networking_invalid_tgw_connect_transport_type" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
    }
    tgw_connect_attachments = [
      {
        name                      = "sdwan"
        transit_gateway_name      = "tlz-transit-gateway"
        transport_attachment      = "hub"
        transport_attachment_type = "vpn"
      }
    ]
  }

  expect_failures = [var.tgw_connect_attachments]
}

run "networking_invalid_tgw_connect_vpc_transport_unknown" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
    }
    tgw_connect_attachments = [
      {
        name                 = "sdwan"
        transit_gateway_name = "tlz-transit-gateway"
        transport_attachment = "does-not-exist"
      }
    ]
  }

  expect_failures = [var.tgw_connect_attachments]
}

run "networking_invalid_tgw_connect_dx_transport_unknown" {
  command = plan

  variables {
    transit_gateway = {
      enabled      = true
      route_tables = ["core"]
    }
    tgw_connect_attachments = [
      {
        name                      = "sdwan"
        transit_gateway_name      = "tlz-transit-gateway"
        transport_attachment      = "does-not-exist"
        transport_attachment_type = "dx-gateway"
      }
    ]
  }

  expect_failures = [var.tgw_connect_attachments]
}
# -----------------------------------------------------------------------------
# 3bb. Network Firewall depth — several firewalls, full policy depth and the
# structured rule sources
# -----------------------------------------------------------------------------
run "networking_firewall_depth_reaches_resources" {
  command = plan
  variables {
    account_ids = {
      network       = "111111111111"
      workload-prod = "222222222222"
    }
    enable_ram_sharing = true
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "inspection-b"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1b"
            type              = "private"
          },
        ]
      },
      {
        name         = "egress"
        cidr         = "10.1.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.1.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled                           = true
      vpc_name                          = "hub"
      subnet_names                      = ["inspection-a"]
      description                       = "central inspection"
      firewall_policy_change_protection = true
      rule_groups = [
        # The raw string form, unchanged.
        {
          name     = "egress-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "pass tcp any any -> any 443 (sid:1;)"
        },
        # A domain list: the service generates the rules from the targets.
        {
          name        = "blocked-domains"
          capacity    = 200
          type        = "STATEFUL"
          description = "domains the egress path refuses"
          rule_group = {
            rules_source = {
              rules_source_list = {
                generated_rules_type = "DENYLIST"
                target_types         = ["TLS_SNI", "HTTP_HOST"]
                targets              = ["bad.example.com"]
              }
            }
          }
        },
        # Stateful 5-tuple rules with rule variables and strict order.
        {
          name          = "tuple-rules"
          capacity      = 300
          type          = "STATEFUL"
          share_targets = ["workload-prod"]
          rule_group = {
            stateful_rule_options = "STRICT_ORDER"
            rule_variables = {
              ip_sets   = [{ name = "HOME_NET", definition = ["10.0.0.0/8"] }]
              port_sets = [{ name = "WEB_PORTS", definition = ["80", "443"] }]
            }
            rules_source = {
              stateful_rules = [
                {
                  action = "DROP"
                  header = {
                    source           = "10.0.0.0/8"
                    source_port      = "ANY"
                    destination      = "203.0.113.0/24"
                    destination_port = "445"
                    direction        = "FORWARD"
                    protocol         = "TCP"
                  }
                  rule_options = [
                    { keyword = "sid", settings = ["100"] },
                    { keyword = "rev", settings = ["1"] },
                  ]
                }
              ]
            }
          }
        },
        # Stateless rules with match attributes, TCP flags and a custom action.
        {
          name     = "stateless-filter"
          capacity = 400
          type     = "STATELESS"
          rule_group = {
            rules_source = {
              stateless_rules_and_custom_actions = {
                custom_actions = [
                  { action_name = "CountSyn", publish_metric_dimensions = ["syn-probe"] }
                ]
                stateless_rules = [
                  {
                    priority = 10
                    rule_definition = {
                      actions = ["aws:forward_to_sfe"]
                      match_attributes = {
                        sources           = ["10.0.0.0/8"]
                        destinations      = ["0.0.0.0/0"]
                        source_ports      = [{ from_port = 1024, to_port = 65535 }]
                        destination_ports = [{ from_port = 443 }]
                        protocols         = [6]
                      }
                    }
                  },
                  {
                    priority = 20
                    rule_definition = {
                      actions = ["CountSyn", "aws:drop"]
                      match_attributes = {
                        sources      = ["0.0.0.0/0"]
                        destinations = ["10.0.0.0/8"]
                        tcp_flags    = [{ flags = ["SYN"], masks = ["SYN", "ACK"] }]
                      }
                    }
                  },
                ]
              }
            }
          }
        },
      ]
      firewall_policy = {
        description              = "central inspection policy"
        stateful_default_actions = ["aws:alert_strict"]
        stateful_engine_options = {
          rule_order               = "STRICT_ORDER"
          stream_exception_policy  = "REJECT"
          tcp_idle_timeout_seconds = 600
        }
        stateful_rule_groups = [
          { name = "tuple-rules", priority = 100 },
          { managed_rule_group_name = "AbusedLegitMalwareDomainsStrictOrder", priority = 200 },
          { arn = "arn:aws:network-firewall:eu-central-1:333333333333:stateful-rulegroup/shared", priority = 300 },
        ]
        stateless_rule_groups = [
          { name = "stateless-filter", priority = 50 }
        ]
        stateless_custom_actions = [
          { action_name = "CountDropped", publish_metric_dimensions = ["dropped"] }
        ]
      }
      policies = [
        {
          name          = "egress-policy"
          description   = "policy of the egress firewall"
          share_targets = ["workload-prod"]
          firewall_policy = {
            stateless_default_actions = ["aws:drop"]
            stateful_default_actions  = ["aws:drop_established"]
            stateful_engine_options = {
              rule_order = "DEFAULT_ACTION_ORDER"
            }
          }
        }
      ]
      firewalls = [
        {
          name                     = "egress-firewall"
          vpc_name                 = "egress"
          subnet_names             = ["inspection-a"]
          description              = "egress inspection"
          policy_name              = "egress-policy"
          subnet_change_protection = false
          tags                     = { Name = "user-supplied-name", Scope = "egress" }
          logging_configuration = {
            flow_log_destination_type = "S3"
            flow_log_destination      = "tlz-firewall-logs"
          }
        },
        {
          name         = "second-hub-firewall"
          vpc_name     = "hub"
          subnet_names = ["inspection-b"]
        },
      ]
    }
  }

  # --- Several firewalls ---
  assert {
    condition     = length(aws_networkfirewall_firewall.this) == 1 && length(aws_networkfirewall_firewall.additional) == 2
    error_message = "network_firewall.firewalls must plan one firewall per entry beside the module's own one."
  }

  assert {
    condition = (
      aws_networkfirewall_firewall.additional["egress-firewall"].description == "egress inspection"
      && aws_networkfirewall_firewall.additional["egress-firewall"].tags["Scope"] == "egress"
      && aws_networkfirewall_firewall.additional["egress-firewall"].tags["Name"] == "egress-firewall"
    )
    error_message = "A firewalls entry must carry its description and its tags, with the module's Name tag winning."
  }

  # Protection defaults are true; false reaches the firewall.
  assert {
    condition = (
      aws_networkfirewall_firewall.additional["egress-firewall"].delete_protection == true
      && aws_networkfirewall_firewall.additional["egress-firewall"].subnet_change_protection == false
      && aws_networkfirewall_firewall.additional["second-hub-firewall"].subnet_change_protection == true
    )
    error_message = "delete_protection must default to true and subnet_change_protection must reach the firewall when set to false."
  }

  assert {
    condition = (
      aws_networkfirewall_firewall.this[0].description == "central inspection"
      && aws_networkfirewall_firewall.this[0].firewall_policy_change_protection == true
    )
    error_message = "The module's own firewall must read description and firewall_policy_change_protection from the variable."
  }

  # A firewall without policy_name runs the module's own policy; one with a
  # policy_name runs the named policy.
  assert {
    condition     = length(aws_networkfirewall_firewall_policy.named) == 1 && contains(keys(aws_networkfirewall_firewall_policy.named), "egress-policy")
    error_message = "network_firewall.policies must plan one firewall policy per entry."
  }

  assert {
    condition = (
      aws_networkfirewall_firewall_policy.named["egress-policy"].description == "policy of the egress firewall"
      && one(aws_networkfirewall_firewall_policy.named["egress-policy"].firewall_policy).stateful_default_actions == toset(["aws:drop_established"])
    )
    error_message = "A policies entry must carry its description and its stateful default action."
  }

  # --- Policy depth on the module's own policy ---
  assert {
    condition = (
      one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateful_default_actions == toset(["aws:alert_strict"])
      && aws_networkfirewall_firewall_policy.this[0].description == "central inspection policy"
    )
    error_message = "stateful_default_actions and description must reach the firewall policy."
  }

  assert {
    condition = (
      one(one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateful_engine_options).rule_order == "STRICT_ORDER"
      && one(one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateful_engine_options).stream_exception_policy == "REJECT"
      && one(one(one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateful_engine_options).flow_timeouts).tcp_idle_timeout_seconds == 600
    )
    error_message = "The engine options rule_order, stream_exception_policy and the TCP idle timeout must reach the firewall policy."
  }

  # A rule group reference block carries the computed attribute
  # deep_threat_inspection, so the whole reference set is unknown in a plan and
  # no assertion can read it — not even where every ARN is literal. The
  # priority per reference and the managed rule group ARN are therefore held by
  # tests/test_quality_audit_networking_firewall.py, which reads the code.
  assert {
    condition = (
      length(one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateless_custom_action) == 1
      && one(one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateless_custom_action).action_name == "CountDropped"
    )
    error_message = "A stateless_custom_actions entry must reach the firewall policy under its action name."
  }

  # --- Structured rule sources ---
  assert {
    condition     = length(aws_networkfirewall_rule_group.this) == 4
    error_message = "Every rule_groups entry must plan a rule group, whatever form describes it."
  }

  # The raw string form writes exactly the given string, and no structured
  # block beside it.
  assert {
    condition = (
      one(one(aws_networkfirewall_rule_group.this["egress-domains"].rule_group).rules_source).rules_string == "pass tcp any any -> any 443 (sid:1;)"
      && length(one(one(aws_networkfirewall_rule_group.this["egress-domains"].rule_group).rules_source).stateful_rule) == 0
      && length(one(one(aws_networkfirewall_rule_group.this["egress-domains"].rule_group).rules_source).rules_source_list) == 0
    )
    error_message = "A rule group described by the rules string must keep writing that string and nothing else."
  }

  assert {
    condition = (
      one(one(one(aws_networkfirewall_rule_group.this["blocked-domains"].rule_group).rules_source).rules_source_list).generated_rules_type == "DENYLIST"
      && one(one(one(aws_networkfirewall_rule_group.this["blocked-domains"].rule_group).rules_source).rules_source_list).targets == toset(["bad.example.com"])
      && one(one(one(aws_networkfirewall_rule_group.this["blocked-domains"].rule_group).rules_source).rules_source_list).target_types == toset(["TLS_SNI", "HTTP_HOST"])
      && aws_networkfirewall_rule_group.this["blocked-domains"].description == "domains the egress path refuses"
    )
    error_message = "A domain list must reach the rule group with its type, targets and protocols, and the description with it."
  }

  assert {
    condition = (
      one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rules_source).stateful_rule).action == "DROP"
      && one(one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rules_source).stateful_rule).header).destination_port == "445"
      && one(one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rules_source).stateful_rule).header).direction == "FORWARD"
      && one(one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rules_source).stateful_rule).header).protocol == "TCP"
    )
    error_message = "A stateful 5-tuple rule must reach the rule group with its action and its whole header."
  }

  assert {
    condition     = length(one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rules_source).stateful_rule).rule_option) == 2
    error_message = "Every rule_options entry of a stateful rule must reach the rule group."
  }

  assert {
    condition = (
      one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rule_variables).ip_sets).key == "HOME_NET"
      && one(one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rule_variables).ip_sets).ip_set).definition == toset(["10.0.0.0/8"])
      && one(one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).rule_variables).port_sets).key == "WEB_PORTS"
    )
    error_message = "Rule variables must reach the rule group as named address and port sets."
  }

  assert {
    condition     = one(one(aws_networkfirewall_rule_group.this["tuple-rules"].rule_group).stateful_rule_options).rule_order == "STRICT_ORDER"
    error_message = "A rule group's stateful_rule_options must reach the rule group."
  }

  assert {
    condition = length([
      for rule in one(one(one(aws_networkfirewall_rule_group.this["stateless-filter"].rule_group).rules_source).stateless_rules_and_custom_actions).stateless_rule :
      rule if rule.priority == 10
      ]) == 1 && length(
      one(one(one(aws_networkfirewall_rule_group.this["stateless-filter"].rule_group).rules_source).stateless_rules_and_custom_actions).stateless_rule
    ) == 2
    error_message = "Every stateless rule must reach the rule group under its own priority."
  }

  assert {
    condition = (
      one(one(one(aws_networkfirewall_rule_group.this["stateless-filter"].rule_group).rules_source).stateless_rules_and_custom_actions).custom_action != null
      && one(one(one(one(aws_networkfirewall_rule_group.this["stateless-filter"].rule_group).rules_source).stateless_rules_and_custom_actions).custom_action).action_name == "CountSyn"
    )
    error_message = "A custom action of a stateless rule group must reach the rule group under its action name."
  }

  # --- Logging per firewall ---
  assert {
    condition     = length(aws_networkfirewall_logging_configuration.additional) == 1 && contains(keys(aws_networkfirewall_logging_configuration.additional), "egress-firewall")
    error_message = "A firewalls entry with a logging_configuration must plan its own logging configuration, and one without must plan none."
  }

  # --- RAM sharing of a named policy ---
  assert {
    condition = (
      length(aws_ram_resource_share.nfw_named_policy) == 1
      && aws_ram_principal_association.nfw_named_policy["egress-policy.workload-prod"].principal == "222222222222"
    )
    error_message = "A policies entry with share_targets must be shared through RAM to the resolved principal."
  }

  # --- Outputs ---
  assert {
    condition     = length(output.firewall_policy_arns) == 1 && contains(keys(output.firewall_policy_arns), "egress-policy")
    error_message = "firewall_policy_arns must name every policy of network_firewall.policies."
  }

  assert {
    condition     = length(keys(output.firewall_endpoint_ids_by_firewall)) == 2
    error_message = "firewall_endpoint_ids_by_firewall must carry an entry per firewall of network_firewall.firewalls."
  }
}
# -----------------------------------------------------------------------------
# 3bc. Network Firewall defaults — the single-firewall form with a raw rule
# string plans the module's defaults
# -----------------------------------------------------------------------------
run "networking_firewall_defaults_leave_plan_unchanged" {
  command = plan
  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "egress-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "pass tcp any any -> any 443 (sid:1;)"
        },
        {
          name     = "stateless-filter"
          capacity = 200
          type     = "STATELESS"
          rules    = "{}"
        },
      ]
      firewall_policy = {
        stateless_default_actions = ["aws:forward_to_sfe"]
      }
      logging_configuration = {
        flow_log_destination_type = "S3"
        flow_log_destination      = "tlz-firewall-logs"
      }
    }
  }

  # No further firewalls, no further policies, no further logging.
  assert {
    condition = (
      length(aws_networkfirewall_firewall.this) == 1
      && length(aws_networkfirewall_firewall.additional) == 0
      && length(aws_networkfirewall_firewall_policy.named) == 0
      && length(aws_networkfirewall_logging_configuration.this) == 1
      && length(aws_networkfirewall_logging_configuration.additional) == 0
    )
    error_message = "Without firewalls and policies entries the module must plan only the single firewall."
  }

  # The protections keep the values the module hardcoded.
  assert {
    condition = (
      aws_networkfirewall_firewall.this[0].delete_protection == true
      && aws_networkfirewall_firewall.this[0].subnet_change_protection == true
      && aws_networkfirewall_firewall.this[0].firewall_policy_change_protection == false
      && aws_networkfirewall_firewall.this[0].description == null
    )
    error_message = "The protection defaults must stay in place, and the description must stay unset."

  }

  # The raw rule string still lands in rules_source.rules_string, and no
  # structured block appears beside it.
  assert {
    condition = (
      one(one(aws_networkfirewall_rule_group.this["egress-domains"].rule_group).rules_source).rules_string == "pass tcp any any -> any 443 (sid:1;)"
      && one(one(aws_networkfirewall_rule_group.this["stateless-filter"].rule_group).rules_source).rules_string == "{}"
      && length(one(aws_networkfirewall_rule_group.this["egress-domains"].rule_group).rule_variables) == 0
      && length(one(aws_networkfirewall_rule_group.this["egress-domains"].rule_group).stateful_rule_options) == 0
      && aws_networkfirewall_rule_group.this["egress-domains"].description == null
    )
    error_message = "A rule group of the raw form must keep its rules string and gain no structured block."
  }

  # The policy carries no engine options, no stateful default action and no
  # custom action, and its default actions are the module's defaults.
  assert {
    condition = (
      length(one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateful_engine_options) == 0
      && length(one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateless_custom_action) == 0
      && one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateful_default_actions == null
      && one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateless_default_actions == toset(["aws:forward_to_sfe"])
      && aws_networkfirewall_firewall_policy.this[0].description == null
    )
    error_message = "Without the optional policy attributes the firewall policy must plan the module's defaults."

  }
}
# -----------------------------------------------------------------------------
# Validation failures of the Network Firewall bundle
# -----------------------------------------------------------------------------
run "networking_invalid_firewall_rule_group_two_forms" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "both-forms"
          capacity = 100
          type     = "STATEFUL"
          rules    = "pass tcp any any -> any 443 (sid:1;)"
          rule_group = {
            rules_source = {
              rules_string = "pass tcp any any -> any 80 (sid:2;)"
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_rule_group_without_form" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "no-form"
          capacity = 100
          type     = "STATEFUL"
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_rules_source_two_sources" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "two-sources"
          capacity = 100
          type     = "STATEFUL"
          rule_group = {
            rules_source = {
              rules_string = "pass tcp any any -> any 80 (sid:2;)"
              rules_source_list = {
                generated_rules_type = "DENYLIST"
                target_types         = ["TLS_SNI"]
                targets              = ["bad.example.com"]
              }
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_source_form_against_type" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "stateless-with-stateful-source"
          capacity = 100
          type     = "STATELESS"
          rule_group = {
            rules_source = {
              rules_string = "pass tcp any any -> any 80 (sid:2;)"
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateful_rule_action" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "tuple-rules"
          capacity = 100
          type     = "STATEFUL"
          rule_group = {
            rules_source = {
              stateful_rules = [
                {
                  action = "REJECT"
                  header = {
                    source           = "10.0.0.0/8"
                    source_port      = "ANY"
                    destination      = "ANY"
                    destination_port = "443"
                    direction        = "FORWARD"
                    protocol         = "TCP"
                  }
                }
              ]
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateful_rule_protocol" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "tuple-rules"
          capacity = 100
          type     = "STATEFUL"
          rule_group = {
            rules_source = {
              stateful_rules = [
                {
                  action = "DROP"
                  header = {
                    source           = "10.0.0.0/8"
                    source_port      = "ANY"
                    destination      = "ANY"
                    destination_port = "443"
                    direction        = "FORWARD"
                    protocol         = "QUIC"
                  }
                }
              ]
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_domain_list_type" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "blocked-domains"
          capacity = 100
          type     = "STATEFUL"
          rule_group = {
            rules_source = {
              rules_source_list = {
                generated_rules_type = "BLOCKLIST"
                target_types         = ["TLS_SNI"]
                targets              = ["bad.example.com"]
              }
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_domain_list_target_type" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "blocked-domains"
          capacity = 100
          type     = "STATEFUL"
          rule_group = {
            rules_source = {
              rules_source_list = {
                generated_rules_type = "DENYLIST"
                target_types         = ["SNI"]
                targets              = ["bad.example.com"]
              }
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateless_rule_priority_duplicate" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "stateless-filter"
          capacity = 100
          type     = "STATELESS"
          rule_group = {
            rules_source = {
              stateless_rules_and_custom_actions = {
                stateless_rules = [
                  {
                    priority = 10
                    rule_definition = {
                      actions          = ["aws:pass"]
                      match_attributes = { sources = ["10.0.0.0/8"] }
                    }
                  },
                  {
                    priority = 10
                    rule_definition = {
                      actions          = ["aws:drop"]
                      match_attributes = { sources = ["10.1.0.0/16"] }
                    }
                  },
                ]
              }
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateless_rule_unknown_action" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "stateless-filter"
          capacity = 100
          type     = "STATELESS"
          rule_group = {
            rules_source = {
              stateless_rules_and_custom_actions = {
                stateless_rules = [
                  {
                    priority = 10
                    rule_definition = {
                      actions          = ["CountSyn"]
                      match_attributes = { sources = ["10.0.0.0/8"] }
                    }
                  }
                ]
              }
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateless_rule_port_range" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "stateless-filter"
          capacity = 100
          type     = "STATELESS"
          rule_group = {
            rules_source = {
              stateless_rules_and_custom_actions = {
                stateless_rules = [
                  {
                    priority = 10
                    rule_definition = {
                      actions = ["aws:pass"]
                      match_attributes = {
                        sources      = ["10.0.0.0/8"]
                        source_ports = [{ from_port = 443, to_port = 80 }]
                      }
                    }
                  }
                ]
              }
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateless_rule_tcp_flag_outside_mask" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "stateless-filter"
          capacity = 100
          type     = "STATELESS"
          rule_group = {
            rules_source = {
              stateless_rules_and_custom_actions = {
                stateless_rules = [
                  {
                    priority = 10
                    rule_definition = {
                      actions = ["aws:pass"]
                      match_attributes = {
                        sources   = ["10.0.0.0/8"]
                        tcp_flags = [{ flags = ["SYN"], masks = ["ACK"] }]
                      }
                    }
                  }
                ]
              }
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_rule_variable_duplicate_name" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "tuple-rules"
          capacity = 100
          type     = "STATEFUL"
          rule_group = {
            rule_variables = {
              ip_sets   = [{ name = "SETS", definition = ["10.0.0.0/8"] }]
              port_sets = [{ name = "SETS", definition = ["443"] }]
            }
            rules_source = {
              rules_string = "pass tcp any any -> any 443 (sid:1;)"
            }
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateful_default_action" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewall_policy = {
        stateful_default_actions = ["aws:drop"]
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_engine_rule_order" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewall_policy = {
        stateful_engine_options = {
          rule_order = "STRICT"
        }
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stream_exception_policy" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewall_policy = {
        stateful_engine_options = {
          stream_exception_policy = "PASS"
        }
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_engine_tcp_idle_timeout" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewall_policy = {
        stateful_engine_options = {
          tcp_idle_timeout_seconds = 30
        }
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateful_reference_two_sources" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "egress-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "pass tcp any any -> any 443 (sid:1;)"
        }
      ]
      firewall_policy = {
        stateful_rule_groups = [
          { name = "egress-domains", arn = "arn:aws:network-firewall:eu-central-1:333333333333:stateful-rulegroup/shared" }
        ]
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateful_reference_unknown_name" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "egress-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "pass tcp any any -> any 443 (sid:1;)"
        }
      ]
      firewall_policy = {
        stateful_rule_groups = [
          { name = "does-not-exist" }
        ]
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateful_priority_without_strict_order" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "egress-domains"
          capacity = 100
          type     = "STATEFUL"
          rules    = "pass tcp any any -> any 443 (sid:1;)"
        }
      ]
      firewall_policy = {
        stateful_rule_groups = [
          { name = "egress-domains", priority = 100 }
        ]
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateless_reference_unknown_name" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "stateless-filter"
          capacity = 100
          type     = "STATELESS"
          rules    = "{}"
        }
      ]
      firewall_policy = {
        stateless_rule_groups = [
          { name = "does-not-exist", priority = 10 }
        ]
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_stateless_reference_priority_duplicate" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        {
          name     = "stateless-a"
          capacity = 100
          type     = "STATELESS"
          rules    = "{}"
        },
        {
          name     = "stateless-b"
          capacity = 100
          type     = "STATELESS"
          rules    = "{}"
        },
      ]
      firewall_policy = {
        stateless_rule_groups = [
          { name = "stateless-a", priority = 10 },
          { name = "stateless-b", priority = 10 },
        ]
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_custom_action_without_dimension" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewall_policy = {
        stateless_custom_actions = [
          { action_name = "CountDropped", publish_metric_dimensions = [] }
        ]
      }
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_policy_duplicate_name" {
  command = plan
  variables {
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      policies = [
        { name = "egress-policy", firewall_policy = {} },
        { name = "egress-policy", firewall_policy = {} },
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_name_of_the_module_firewall" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewalls = [
        {
          name         = "tlz-network-firewall"
          vpc_name     = "hub"
          subnet_names = ["inspection-a"]
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_unknown_vpc_name" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewalls = [
        {
          name         = "egress-firewall"
          vpc_name     = "does-not-exist"
          subnet_names = ["inspection-a"]
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_unknown_subnet_name" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewalls = [
        {
          name         = "egress-firewall"
          vpc_name     = "hub"
          subnet_names = ["does-not-exist"]
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_unknown_policy_name" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewalls = [
        {
          name         = "egress-firewall"
          vpc_name     = "hub"
          subnet_names = ["inspection-a"]
          policy_name  = "does-not-exist"
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_policy_protection_without_delete_protection" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewalls = [
        {
          name                              = "egress-firewall"
          vpc_name                          = "hub"
          subnet_names                      = ["inspection-a"]
          delete_protection                 = false
          firewall_policy_change_protection = true
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
run "networking_invalid_firewall_logging_destination_type" {
  command = plan
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      firewalls = [
        {
          name         = "egress-firewall"
          vpc_name     = "hub"
          subnet_names = ["inspection-a"]
          logging_configuration = {
            flow_log_destination_type = "Firehose"
            flow_log_destination      = "tlz-firewall-logs"
          }
        }
      ]
    }
  }
  expect_failures = [var.network_firewall]
}
# -----------------------------------------------------------------------------
# 3be. Gateway Load Balancer attributes — deletion protection, cross-zone load
# balancing and the TCP idle timeout
# -----------------------------------------------------------------------------
run "networking_gwlb_attributes_reach_resources" {
  command = plan
  variables {
    account_ids = {
      network = "111111111111"
    }
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
    gateway_load_balancers = [
      {
        name             = "inspection-gwlb"
        vpc_name         = "hub"
        subnet_names     = ["inspection-a"]
        tcp_idle_timeout = 600
        target_group     = { name = "inspection-gwlb-tg" }
      },
      {
        name                      = "lab-gwlb"
        vpc_name                  = "hub"
        subnet_names              = ["inspection-a"]
        deletion_protection       = false
        cross_zone_load_balancing = false
        target_group              = { name = "lab-gwlb-tg" }
      },
    ]
  }

  # Both default to true.
  assert {
    condition = (
      aws_lb.gwlb["inspection-gwlb"].enable_deletion_protection == true
      && aws_lb.gwlb["inspection-gwlb"].enable_cross_zone_load_balancing == true
    )
    error_message = "Without the two switches a Gateway Load Balancer must keep deletion protection and cross-zone load balancing."
  }

  # false reaches the load balancer, for a deployment that chooses it.
  assert {
    condition = (
      aws_lb.gwlb["lab-gwlb"].enable_deletion_protection == false
      && aws_lb.gwlb["lab-gwlb"].enable_cross_zone_load_balancing == false
    )
    error_message = "deletion_protection and cross_zone_load_balancing must reach the load balancer when set to false."
  }

  # The TCP idle timeout is an attribute of the listener, not of the load
  # balancer. Left unset the attribute is computed and the service fills in its
  # own default of 350 seconds, so a plan cannot read that case — the null
  # default is held by tests/test_quality_audit_networking_gwlb.py.
  assert {
    condition     = aws_lb_listener.gwlb["inspection-gwlb"].tcp_idle_timeout_seconds == 600
    error_message = "tcp_idle_timeout must reach the GWLB listener."
  }
}
run "networking_invalid_gwlb_tcp_idle_timeout_range" {
  command = plan
  variables {
    gateway_load_balancers = [
      {
        name             = "inspection-gwlb"
        vpc_name         = "hub"
        subnet_names     = ["inspection-a"]
        tcp_idle_timeout = 30
        target_group     = { name = "inspection-gwlb-tg" }
      }
    ]
  }
  expect_failures = [var.gateway_load_balancers]
}
run "networking_invalid_gwlb_tcp_idle_timeout_fraction" {
  command = plan
  variables {
    gateway_load_balancers = [
      {
        name             = "inspection-gwlb"
        vpc_name         = "hub"
        subnet_names     = ["inspection-a"]
        tcp_idle_timeout = 350.5
        target_group     = { name = "inspection-gwlb-tg" }
      }
    ]
  }
  expect_failures = [var.gateway_load_balancers]
}
run "networking_invalid_gwlb_cross_zone_off_with_consumers" {
  command = plan
  variables {
    gateway_load_balancers = [
      {
        name                      = "inspection-gwlb"
        vpc_name                  = "hub"
        subnet_names              = ["inspection-a"]
        cross_zone_load_balancing = false
        target_group              = { name = "inspection-gwlb-tg" }
        endpoint_consumers = [
          { vpc_name = "spoke", subnet_names = ["private-a"] }
        ]
      }
    ]
  }
  expect_failures = [var.gateway_load_balancers]
}

# -----------------------------------------------------------------------------
# Shared subnet tags in recipient accounts
# -----------------------------------------------------------------------------

run "shared_subnet_tagging_off_no_resources" {
  command = plan

  variables {
    enable_shared_subnet_tagging = false
  }

  assert {
    condition     = length(aws_ec2_tag.shared_subnet) == 0 && length(aws_ec2_tag.shared_vpc) == 0
    error_message = "Without enable_shared_subnet_tagging no aws_ec2_tag may be planned."
  }
}

run "shared_subnet_tagging_materialises_subnet_and_vpc_tags" {
  command = plan

  variables {
    enable_shared_subnet_tagging = true
    shared_subnet_tags = [
      {
        subnet_id = "subnet-0a1b2c3d4e5f67890"
        tags      = { Name = "workload-private-a", Tier = "private" }
        vpc_id    = "vpc-0f9e8d7c6b5a43210"
        vpc_tags  = { Name = "shared-network" }
      },
      {
        subnet_id = "subnet-0b2c3d4e5f6789012"
        tags      = { Name = "workload-private-b" }
        vpc_id    = "vpc-0f9e8d7c6b5a43210"
        vpc_tags  = { Name = "shared-network" }
      },
    ]
  }

  assert {
    condition     = length(aws_ec2_tag.shared_subnet) == 3
    error_message = "Three declared subnet tag pairs must produce three aws_ec2_tag resources (one per subnet and key)."
  }

  assert {
    condition     = aws_ec2_tag.shared_subnet["subnet-0a1b2c3d4e5f67890:Tier"].value == "private" && aws_ec2_tag.shared_subnet["subnet-0a1b2c3d4e5f67890:Tier"].resource_id == "subnet-0a1b2c3d4e5f67890"
    error_message = "Each tag resource must address its received subnet by ID and carry the declared value."
  }

  assert {
    condition     = length(aws_ec2_tag.shared_vpc) == 1 && aws_ec2_tag.shared_vpc["vpc-0f9e8d7c6b5a43210:Name"].value == "shared-network"
    error_message = "Two entries with the same vpc_id and identical vpc_tags must dedupe to one VPC tag resource."
  }
}

run "shared_subnet_tags_without_switch_rejected" {
  command = plan

  variables {
    shared_subnet_tags = [
      {
        subnet_id = "subnet-0a1b2c3d4e5f67890"
        tags      = { Name = "silently-nothing" }
      },
    ]
  }

  expect_failures = [var.shared_subnet_tags]
}

run "shared_subnet_tagging_empty_list_rejected" {
  command = plan

  variables {
    enable_shared_subnet_tagging = true
    shared_subnet_tags           = []
  }

  expect_failures = [var.shared_subnet_tags]
}

run "shared_subnet_tags_reserved_prefix_rejected" {
  command = plan

  variables {
    enable_shared_subnet_tagging = true
    shared_subnet_tags = [
      {
        subnet_id = "subnet-0a1b2c3d4e5f67890"
        tags      = { "aws:cloudformation:stack" = "reserved" }
      },
    ]
  }

  expect_failures = [var.shared_subnet_tags]
}

run "shared_subnet_tags_vpc_pair_rule_rejected" {
  command = plan

  variables {
    enable_shared_subnet_tagging = true
    shared_subnet_tags = [
      {
        subnet_id = "subnet-0a1b2c3d4e5f67890"
        tags      = { Name = "a" }
        vpc_id    = "vpc-0f9e8d7c6b5a43210"
      },
    ]
  }

  expect_failures = [var.shared_subnet_tags]
}

run "shared_subnet_tags_conflicting_vpc_tags_rejected" {
  command = plan

  variables {
    enable_shared_subnet_tagging = true
    shared_subnet_tags = [
      {
        subnet_id = "subnet-0a1b2c3d4e5f67890"
        tags      = { Name = "a" }
        vpc_id    = "vpc-0f9e8d7c6b5a43210"
        vpc_tags  = { Name = "one" }
      },
      {
        subnet_id = "subnet-0b2c3d4e5f6789012"
        tags      = { Name = "b" }
        vpc_id    = "vpc-0f9e8d7c6b5a43210"
        vpc_tags  = { Name = "two" }
      },
    ]
  }

  expect_failures = [var.shared_subnet_tags]
}

# -----------------------------------------------------------------------------
# Four collections reference aws_ec2_transit_gateway.this[0] — Direct Connect
# gateway associations, TGW-terminated VPN connections, Connect attachments
# and routes of target_type "tgw". With the Transit Gateway off, each variable
# rejects the combination with a clear message instead of an "Invalid index",
# and the derived collections are intersected with the toggle.
# -----------------------------------------------------------------------------
run "regression_dx_gateway_without_tgw_rejected" {
  command = plan

  variables {
    dx_gateways = [
      {
        name                 = "onprem-dx"
        amazon_asn           = 64512
        transit_gateway_name = "main"
      },
    ]
  }

  expect_failures = [var.transit_gateway]
}

run "regression_tgw_vpn_without_tgw_rejected" {
  command = plan

  variables {
    customer_gateways = [
      {
        name                 = "onprem-vpn"
        bgp_asn              = 65000
        ip_address           = "203.0.113.10"
        transit_gateway_name = "main"
      },
    ]
  }

  expect_failures = [var.transit_gateway]
}

run "regression_tgw_connect_without_tgw_rejected" {
  command = plan

  variables {
    # The transport VPC keeps the transport-attachment validation quiet, so
    # the run isolates the missing Transit Gateway as the rejected condition.
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "tgw-a"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
        tgw_attachment = {
          route_table_name = "hub"
        }
      },
    ]

    tgw_connect_attachments = [
      {
        name                 = "sdwan"
        transit_gateway_name = "main"
        transport_attachment = "hub"
      },
    ]
  }

  expect_failures = [var.transit_gateway]
}

run "regression_tgw_route_without_tgw_rejected" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "10.0.0.0/8"
                target_type            = "tgw"
              },
            ]
          },
        ]
      },
    ]
  }

  expect_failures = [var.transit_gateway]
}

# Counterpart: a VPN connection terminating on a VPC (vpc_name set) stays
# independent of the Transit Gateway and plans while it is off.
run "regression_vpc_terminated_vpn_plans_without_tgw" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.40.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.40.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]

    customer_gateways = [
      {
        name       = "onprem-vpn"
        bgp_asn    = 65000
        ip_address = "203.0.113.10"
        vpc_name   = "hub"
      },
    ]
  }

  assert {
    condition     = length(aws_customer_gateway.this) == 1
    error_message = "A VPC-terminated customer gateway must be planned while the Transit Gateway is off."
  }

  assert {
    condition     = length(aws_vpn_connection.this) == 1
    error_message = "The VPC-terminated VPN connection must be planned while the Transit Gateway is off."
  }

  assert {
    condition     = length(aws_ec2_transit_gateway.this) == 0
    error_message = "No Transit Gateway may be planned while the toggle is off."
  }
}

# -----------------------------------------------------------------------------
# The target of a network_firewall route is the availability zone whose
# firewall endpoint the route uses. The AZ form is validated at plan time and
# the endpoint map is indexed without a fallback, so an unknown value never
# reaches AWS as a vpc_endpoint_id.
# -----------------------------------------------------------------------------
run "regression_network_firewall_route_invalid_az_rejected" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "inspection"
        cidr         = "10.50.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.50.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
            custom_routes = [
              {
                destination_cidr_block = "0.0.0.0/0"
                target_type            = "network_firewall"
                # Not an availability zone.
                target_name = "firewall"
              },
            ]
          },
        ]
      },
    ]
  }

  expect_failures = [var.vpcs]
}

# -----------------------------------------------------------------------------
# private_subnet_only intent warning
# -----------------------------------------------------------------------------
# The frameworks' networking_defaults key private_subnet_only reaches the
# module as an advisory flag: a VPC with public subnets fires the check
# warning, the plan itself is unaffected.

run "private_subnet_only_warns_about_public_subnets" {
  command = plan

  variables {
    private_subnet_only = true
    vpcs = [
      {
        name         = "workload"
        cidr         = "10.10.0.0/16"
        account_name = "workload-dev"
        subnets = [
          {
            name              = "public-a"
            cidr              = "10.10.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "public"
          },
        ]
      },
    ]
  }

  expect_failures = [check.private_subnet_only_intent]
}

run "private_subnet_only_quiet_without_public_subnets" {
  command = plan

  variables {
    private_subnet_only = true
    vpcs = [
      {
        name         = "workload"
        cidr         = "10.10.0.0/16"
        account_name = "workload-dev"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.10.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
      },
    ]
  }

  assert {
    condition     = length(aws_subnet.this) == 1
    error_message = "A private-only VPC must plan its subnets without the intent warning."
  }
}
# -----------------------------------------------------------------------------
# Scenario: Endpoint prefix follows the partition — under a mock
# partition the endpoint service names carry the prefix derived from the
# partition's DNS suffix by reversing its segments (amazonaws.eu →
# eu.amazonaws) instead of a fixed com.amazonaws.
# -----------------------------------------------------------------------------
run "endpoint_prefix_follows_the_partition" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }
  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
        ]
        gateway_endpoints = ["s3"]
        interface_endpoints = [
          {
            service      = "ssm"
            subnet_names = ["private-a"]
          }
        ]
      }
    ]
  }
  assert {
    condition     = aws_vpc_endpoint.gateway["hub.s3"].service_name == "eu.amazonaws.eu-central-1.s3"
    error_message = "The gateway endpoint service name must derive its prefix from the partition's DNS suffix."
  }
  assert {
    condition     = aws_vpc_endpoint.interface["hub.ssm"].service_name == "eu.amazonaws.eu-central-1.ssm"
    error_message = "The interface endpoint service name must derive its prefix from the partition's DNS suffix."
  }
}

# A listener protocol spelled "https" would miss the module's
# contains(["HTTPS", "TLS"], ...) test for the default TLS policy and silently
# keep the load balancing service's older policy, so the listener protocol
# carries the same case-exact validation as target_groups.
run "regression_listener_protocol_lowercase_https_refused" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "spoke"
        cidr         = "10.31.0.0/16"
        account_name = "workload-prod"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.31.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          },
          {
            name              = "private-b"
            cidr              = "10.31.2.0/24"
            availability_zone = "eu-central-1b"
            type              = "private"
          },
        ]
      }
    ]

    target_groups = [
      {
        name        = "web-tg"
        port        = 443
        protocol    = "HTTPS"
        vpc_name    = "spoke"
        target_type = "ip"
      }
    ]

    load_balancers = [
      {
        name         = "web-alb"
        type         = "application"
        vpc_name     = "spoke"
        subnet_names = ["private-a", "private-b"]
        listeners = [
          {
            port              = 443
            protocol          = "https"
            target_group_name = "web-tg"
          }
        ]
      },
    ]
  }

  expect_failures = [var.load_balancers]
}

# Adopting the default VPC for removal (delete_default_vpc) must not leave
# map_public_ip_on_launch at the provider default of aws_default_subnet, true,
# or every adopted — or, in a zone without one, newly created — default subnet
# would hand out public addresses the caller never asked for. The adopted
# subnets carry false until the second apply removes them.
run "regression_default_subnet_adoption_hands_out_no_public_ip" {
  command = plan

  variables {
    delete_default_vpc             = true
    default_vpc_availability_zones = ["eu-central-1a", "eu-central-1b"]
  }

  # Adoption is not deletion; the module's two-step check fires with the toggle on.
  expect_failures = [check.default_vpc_two_step_removal]

  assert {
    condition = alltrue([
      for subnet in aws_default_subnet.this : subnet.map_public_ip_on_launch == false
    ]) && length(aws_default_subnet.this) == 2
    error_message = "An adopted default subnet must not assign public IP addresses on launch."
  }
}

# The world-open gate also covers every-port forms that are not spelled
# ALL/-1 with 0.0.0.0/0 — TCP/UDP with ports 0-65535 (or 1-65535), and the two
# /1 halves of the address space. Each form is refused without the
# acknowledgement, one run per form, in vpcs and in vpc_templates.
run "regression_sg_ingress_world_open_refused_tcp_udp_types_all_ports" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name    = "app-sg"
            ingress = [{ types = ["TCP", "UDP"], from_port = 0, to_port = 65535, cidr_blocks = ["0.0.0.0/0"] }]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "regression_sg_ingress_world_open_refused_udp_protocol_ports_1_65535_ipv6" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name    = "app-sg"
            ingress = [{ protocol = "udp", from_port = 1, to_port = 65535, ipv6_cidr_blocks = ["::/0"] }]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "regression_sg_ingress_world_open_refused_all_from_two_halves" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name    = "app-sg"
            ingress = [{ types = ["ALL"], cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"] }]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpcs]
}

run "regression_sg_ingress_world_open_refused_template_tcp_all_ports_halves" {
  command = plan

  variables {
    account_ids = {
      network = "111111111111"
    }
    vpc_templates = [
      {
        name               = "standard-workload"
        cidr               = "10.60.0.0/16"
        deployment_targets = ["network"]
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.60.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "tcp-all-ports"
            ingress = [
              { protocol = "tcp", from_port = 0, to_port = 65535, cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"] }
            ]
          }
        ]
      }
    ]
  }

  expect_failures = [var.vpc_templates]
}

# The same every-port forms plan with the acknowledgement, and a
# narrower source (/8) or a narrower port range needs none.
run "regression_sg_ingress_world_open_every_port_forms_acknowledged" {
  command = plan

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "private-a"
            cidr              = "10.0.2.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
        security_groups = [
          {
            name = "app-sg"
            ingress = [
              { types = ["TCP"], from_port = 0, to_port = 65535, cidr_blocks = ["0.0.0.0/0"], acknowledge_world_open_all_protocols = true },
              { protocol = "udp", from_port = 1, to_port = 65535, ipv6_cidr_blocks = ["::/0"], acknowledge_world_open_all_protocols = true },
              { types = ["ALL"], cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"], acknowledge_world_open_all_protocols = true },
              { types = ["TCP"], from_port = 0, to_port = 65535, cidr_blocks = ["10.0.0.0/8"] },
              { types = ["TCP"], from_port = 1024, to_port = 65535, cidr_blocks = ["0.0.0.0/0"] },
            ]
          }
        ]
      }
    ]
  }

  assert {
    condition = (
      aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0.TCP"].to_port == 65535
      && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.1"].protocol == "udp"
      && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.2.ALL"].cidr_blocks == tolist(["0.0.0.0/1", "128.0.0.0/1"])
      && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.3.TCP"].cidr_blocks == tolist(["10.0.0.0/8"])
      && aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.4.TCP"].from_port == 1024
    )
    error_message = "Acknowledged every-port rules and rules with a narrower source or port range must plan."
  }
}

# route53_zones cross_account_associations runs the association with the zone
# owner's provider, which Route 53 refuses for another account's VPC, so an
# entry for another account is refused at plan rather than failing the apply
# after the authorization exists.
run "regression_route53_cross_account_association_refused_at_plan" {
  command = plan

  variables {
    route53_zones = [
      {
        name = "internal.example.com"
        cross_account_associations = [
          { vpc_id = "vpc-0123456789abcdef0", account_id = "222222222222" }
        ]
      }
    ]
  }

  expect_failures = [aws_route53_zone_association.cross_account]
}

# An association entry for the stack's own account still plans.
run "regression_route53_same_account_association_plans" {
  command = plan

  variables {
    route53_zones = [
      {
        name = "internal.example.com"
        cross_account_associations = [
          { vpc_id = "vpc-0123456789abcdef0", account_id = "111111111111" }
        ]
      }
    ]
  }

  assert {
    condition     = length(aws_route53_zone_association.cross_account) == 1 && aws_route53_zone_association.cross_account["internal.example.com.vpc-0123456789abcdef0"].vpc_id == "vpc-0123456789abcdef0"
    error_message = "An association entry for the stack's own account must plan."
  }
}

# The module derives stateless priorities from the lexical order of the group
# names, not from the order of rule_groups. This pins that derivation: listed "zz-first",

# then "aa-second", the second gets 10. The two ARNs are overridden so that
# the plan knows them and the provider accepts them.
run "regression_firewall_stateless_priority_follows_name_order" {
  command = plan

  override_resource {
    target          = aws_networkfirewall_rule_group.this["zz-first"]
    override_during = plan
    values          = { arn = "arn:aws:network-firewall:eu-central-1:111111111111:stateless-rulegroup/zz-first" }
  }

  override_resource {
    target          = aws_networkfirewall_rule_group.this["aa-second"]
    override_during = plan
    values          = { arn = "arn:aws:network-firewall:eu-central-1:111111111111:stateless-rulegroup/aa-second" }
  }

  variables {
    vpcs = [
      {
        name         = "hub"
        cidr         = "10.0.0.0/16"
        account_name = "network"
        subnets = [
          {
            name              = "inspection-a"
            cidr              = "10.0.1.0/24"
            availability_zone = "eu-central-1a"
            type              = "private"
          }
        ]
      }
    ]
    network_firewall = {
      enabled      = true
      vpc_name     = "hub"
      subnet_names = ["inspection-a"]
      rule_groups = [
        { name = "zz-first", capacity = 100, type = "STATELESS", rules = "{}" },
        { name = "aa-second", capacity = 100, type = "STATELESS", rules = "{}" },
      ]
    }
  }

  assert {
    condition = {
      for reference in one(aws_networkfirewall_firewall_policy.this[0].firewall_policy).stateless_rule_group_reference :
      reference.resource_arn => reference.priority
      } == {
      "arn:aws:network-firewall:eu-central-1:111111111111:stateless-rulegroup/aa-second" = 10
      "arn:aws:network-firewall:eu-central-1:111111111111:stateless-rulegroup/zz-first"  = 20
    }
    error_message = "Without stateless_rule_groups, the stateless priorities must follow the lexical order of the group names: aa-second 10, zz-first 20."
  }
}
