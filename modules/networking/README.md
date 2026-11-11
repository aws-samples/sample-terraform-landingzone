# Networking Module

Central network management: VPCs, Subnets, NAT Gateways, Transit Gateway, Route 53, Network Firewall, IPAM, Prefix Lists, and VPC Flow Logs.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `vpcs` | VPC definitions with subnets, TGW attachment, flow logs. Every level carries an optional `tags` map; subnets additionally carry `route_table_tags` and `nat_gateway_tags` for the resources derived from them — see [Tagging](#tagging). The `tgw_attachment` block optionally carries `dns_support`, `ipv6_support`, `security_group_referencing_support` and an explicit `subnet_names` choice — see [Transit Gateway attachments](#transit-gateway-attachments). Subnets optionally carry placement and addressing switches (`local_zone`, `map_public_ip_on_launch`, `assign_ipv6_on_creation`, `enable_dns64`, `private_dns_options`, `outpost_name` against the VPC's `outposts` list) — see [Subnet options and Outposts](#subnet-options-and-outposts). Routes take an IPv4 CIDR, an IPv6 CIDR or a named prefix list as destination and the next-hop types `igw`, `eigw`, `vgw` and `local_gateway`; `gateway_route_tables` and `enable_route_propagation` cover edge routing and VGW route propagation — see [Route destinations and gateway route tables](#route-destinations-and-gateway-route-tables). Gateway endpoints optionally take per-service options (`gateway_endpoint_options`: policy, full service name); interface endpoints optionally take `service_name`, `security_group`, `central` and `hosted_zone_name` — see [VPC endpoint options](#vpc-endpoint-options). NACL rules name their traffic through an IPv4 CIDR, an IPv6 CIDR or a subnet selector resolved at plan time, and take ICMP type/code pairs — see [Network ACL rule sources](#network-acl-rule-sources). Security group rules combine IPv4/IPv6 CIDRs, subnet selectors, group references (ingress and egress) and prefix lists, and take named port types (`types`); groups take a `description` — see [Security group rule sources and types](#security-group-rule-sources-and-types). Subnet `share_targets` take account names, account IDs, OU or organization ARNs — see [Resource sharing](#resource-sharing). Each entry optionally carries `instance_tenancy`, the explicit `egress_only_igw` switch, further IPv6 ranges (`ipv6_cidrs`) and a `virtual_private_gateway` block with its ASN; subnets carry the NAT gateway details `nat_gateway_name`, `nat_gateway_private`, `nat_gateway_allocation_id` and `nat_gateway_eip_name` — see [VPC base options](#vpc-base-options). The `flow_logs` block additionally takes `destination = "both"`, `cloudwatch_retention_days` and `s3_log_path` — see [Flow log destinations](#flow-log-destinations). Each entry optionally carries `enable_dns_support`, `enable_dns_hostnames` and `use_central_endpoints` — see [VPC DNS and central endpoints](#vpc-dns-and-central-endpoints) | `list(object)` | `[]` | no |
| `transit_gateway` | TGW configuration (ASN, route tables, peering). `auto_accept_shared_attachments` (default `"enable"`) controls whether attachments from RAM-shared accounts connect without a manual acceptance step — `"disable"` adds that control step but automated spoke onboarding then waits in pendingAcceptance. Optional gateway options (`dns_support`, `vpn_ecmp_support`, `multicast_support`, `security_group_referencing_support`, the default route table switches) and `cidr_blocks`; static routes take a CIDR block or a named prefix list as destination and a VPC, VPN, DX gateway or peering attachment as next hop — see [Transit Gateway options and static routes](#transit-gateway-options-and-static-routes). `tags` applies to the gateway, `route_table_tags` per route table name, `peering[].tags` per peering attachment. `share_targets` take account names, account IDs, OU or organization ARNs — see [Resource sharing](#resource-sharing). A peering entry additionally carries an `accepter` block (`account`, `apply_tags_from_requester`, `tags`), and `peering_accepters` accepts a peering another account or region requested — see [Transit Gateway peering](#transit-gateway-peering) | `object` | `{}` | no |
| `route53_zones` | Private hosted zones and resolver rules. Each zone-scoped rule is associated with the VPCs the zone is attached to: the zone's `vpc_ids` (VPCs of the account the stack runs in) or, with `vpc_ids` empty, every VPC of the module; a check warns when another rule of the module already forwards the same domain in one of those VPCs. `cross_account_associations` creates the association authorization and the association with the module's one provider, in the zone owner's account; Route 53 takes the association of another account's VPC only from that account, so an entry whose `account_id` is not the stack's own account is refused at plan | `list(object)` | `[]` | no |
| `network_firewall` | Network Firewall configuration. `tags` applies to the firewall, `firewall_policy.tags` to the policy and `rule_groups[].tags` per rule group. Rule groups and the policy optionally carry `share_targets` — see [Resource sharing](#resource-sharing). Further firewalls and policies stand in `firewalls` and `policies`, the policy takes stateful default actions, engine options, rule group references with priorities and custom actions, and a rule group takes a structured `rule_group` instead of the `rules` string — see [Network Firewall policies, firewalls and rule sources](#network-firewall-policies-firewalls-and-rule-sources) | `object` | `{}` | no |
| `ipam` | IPAM configuration. `tags` applies to the IPAM, `pools[].tags` per pool. Pools optionally carry `share_targets` — see [Resource sharing](#resource-sharing). Pools optionally carry `description`, `address_family`, `additional_cidrs`, `auto_import`, the three allocation netmask lengths, `allocation_resource_tags`, `publicly_advertisable`/`public_ip_source` and a `scope`; `scopes` declares scopes beyond the two the IPAM brings itself — see [IPAM pools and scopes](#ipam-pools-and-scopes) | `object` | `{}` | no |
| `prefix_lists` | Managed Prefix Lists, each with an optional `tags` map | `list(object)` | `[]` | no |
| `vpc_peering` | Peering connections between two of the module's VPCs, including the routes for both CIDRs. Each entry carries an optional `tags` map | `list(object)` | `[]` | no |
| `load_balancers` | Application and network load balancers to create, with their listeners. A listener whose `protocol` is `HTTPS`/`TLS` and names no `ssl_policy` gets `ELBSecurityPolicy-TLS13-1-2-2021-06` (TLS 1.2 minimum) by default — see [Migrating to the New TLS Listener Floor](../../docs/operations.md#migrating-to-the-new-tls-listener-floor). Optional per entry: the HTTP behaviour of an application load balancer (`idle_timeout`, `enable_http2`, `desync_mitigation_mode`, `enable_xff_client_port`, `xff_header_processing_mode`, `enable_tls_headers`, `enable_waf_fail_open`) and `enable_cross_zone_load_balancing`. Optional per listener: `alpn_policy`, an `action` block for forwarding to several weighted target groups, a fixed response, or a redirect, and an `authenticated_edge` block (authenticate-oidc ahead of the action). An entry with `scheme = "internet-facing"` is refused unless it is an application load balancer whose every listener is `HTTPS` and declares `authenticated_edge`; a network load balancer can only be internal — see [Load balancing](#load-balancing) | `list(object)` | `[]` | no |
| `authenticated_edge_allowed_issuers` | OIDC issuer URLs an `authenticated_edge` may name, each a full `https://` URL with a host (`https://<host>[:port][/path]`), compared as an exact string. An edge whose `issuer` is not listed is refused on every load balancer, and an internet-facing entry is refused while the list is empty — see [Trusted issuers](#trusted-issuers) | `list(string)` | `[]` | no |
| `target_groups` | Target groups to create. Optional per entry: `deregistration_delay`, `slow_start`, `algorithm`, `stickiness`, `preserve_client_ip`, `proxy_protocol_v2`, `connection_termination`, `target_failover` and `protocol_version` — see [Load balancing](#load-balancing) | `list(object)` | `[]` | no |
| `account_ids` | Account name → account ID map | `map(string)` | `{}` | no |
| `delete_default_vpc` | Take the default VPC of the current account and region into Terraform state together with the listed default subnets and the default security group, and remove every rule of that security group. Disabling the toggle again deletes the listed default subnets but not the default VPC; a `check` block says so — see [Default VPC removal](#default-vpc-removal) | `bool` | `false` | no |
| `default_vpc_availability_zones` | Availability zones whose default subnets are removed. Required when `delete_default_vpc` is set | `list(string)` | `[]` | no |
| `dx_gateways` | Direct Connect gateways with their Transit Gateway association, virtual interfaces and cross-account association proposals. Optional per entry: `allowed_prefixes` on the association and the route table wiring `route_table_associations`/`route_table_propagations`; optional per virtual interface: `amazon_address`, `customer_address`, `auth_key`, `mtu` and `sitelink_enabled` — see [Direct Connect details](#direct-connect-details). `virtual_interfaces[].tags` tags a virtual interface. See [Direct Connect Association Proposals](#direct-connect-association-proposals) | `list(object)` | `[]` | no |
| `customer_gateways` | Customer gateways with the VPN connection to the Transit Gateway, or — with `vpc_name` — to a virtual private gateway the module attaches to that VPC. Optional per entry: traffic filters (`amazon_*`/`customer_*_network_cidr`), `enable_acceleration`, `static_routes_only`, `outside_ip_address_type`, `tunnel_inside_ip_version`; optional per tunnel: IKE lifetimes, `tunnel_inside_ipv6_cidr`, `enable_tunnel_lifecycle_control` and a `logging` block — see [Site-to-Site VPN](#site-to-site-vpn). `tags` applies to the gateway, `vpn_connection_tags` to the VPN connection created for it | `list(object)` | `[]` | no |
| `dns_firewall_rule_groups` | DNS firewall rule groups with their domain lists, VPC associations and optional sharing (`share_targets` — see [Resource sharing](#resource-sharing)). Each entry carries an optional `tags` map and an optional `mutation_protection` map locking single associations — see [DNS firewall associations](#dns-firewall-associations) | `list(object)` | `[]` | no |
| `enable_route53_query_logging` | Log the resolver's DNS queries. The single toggle of the feature | `bool` | `false` | no |
| `route53_query_logging_destination` | Where the query log is written: `cloudwatch` or `s3`. With `s3` the target is `central_log_bucket_name` | `string` | `"cloudwatch"` | no |
| `route53_query_logging_vpc_names` | VPCs the query log covers. Empty covers every VPC of the module | `list(string)` | `[]` | no |
| `route53_query_logging_share_targets` | RAM sharing targets for the query logging configuration: account names, account IDs, OU or organization ARNs — see [Resource sharing](#resource-sharing). Requires `enable_ram_sharing` and enabled query logging | `list(string)` | `[]` | no |
| `gateway_load_balancers` | Gateway load balancers with their target group, endpoint service and consumer endpoints. `acceptance_required` (default `false`) controls whether endpoint requests to the endpoint service need manual acceptance. `tags` applies to the load balancer. `deletion_protection`, `cross_zone_load_balancing` and `tcp_idle_timeout` tune the load balancer — see [Gateway Load Balancer attributes](#gateway-load-balancer-attributes) | `list(object)` | `[]` | no |
| `vpc_templates` | VPC layout that identical workload accounts are to receive. Intent only, see [VPC Templates](#vpc-templates) | `list(object)` | `[]` | no |
| `elastic_ips` | Elastic IP addresses to allocate in the current region, each with an optional `tags` map | `list(object)` | `[]` | no |
| `endpoint_policies` | Named endpoint policies that `interface_endpoints` entries reference through `policy_name` | `list(object)` | `[]` | no |
| `resolver_rules` | Resolver rules that stand on their own, independent of `route53_zones`, with their VPC associations and optional `share_targets` — see [Resource sharing](#resource-sharing) | `list(object)` | `[]` | no |
| `central_log_bucket_name` | S3 bucket for VPC Flow Logs | `string` | `""` | no |
| `cloudwatch_logs_kms_key_arn` | Optional KMS key ARN for the module's CloudWatch log groups (flow logs, TGW flow logs, Route 53 query logs). Empty keeps the CloudWatch service default encryption; the module creates no key | `string` | `""` | no |
| `vpc_flow_logs_default` | Flow log settings for every VPC without its own `flow_logs` block. `null` leaves those VPCs without a flow log. Carries the same attribute set as the per-VPC block, including `destination = "both"`, `cloudwatch_retention_days` and `s3_log_path` — see [Flow log destinations](#flow-log-destinations) | `object` | `null` | no |
| `private_subnet_only` | Advisory intent flag from the compliance layer (`networking_defaults.private_subnet_only`): when `true`, a `check` warns about every VPC that declares public subnets. The warning does not block the plan | `bool` | `false` | no |
| `resolver_endpoints` | Resolver endpoints with their security group and one address per subnet. `tags` applies to the endpoint, `resolver_rules[].tags` per forwarding rule; rules optionally carry `share_targets` — see [Resource sharing](#resource-sharing) | `list(object)` | `[]` | no |
| `dhcp_options_sets` | DHCP options sets and the VPCs they are associated with, each with an optional `tags` map | `list(object)` | `[]` | no |
| `tgw_connect_attachments` | Transit Gateway Connect attachments over a VPC or Direct Connect transport attachment (`transport_attachment_type`), with the BGP peers for GRE-based appliances. Each entry carries an optional `tags` map — see [VPC DNS and central endpoints](#vpc-dns-and-central-endpoints) | `list(object)` | `[]` | no |
| `enable_tgw_flow_logs` | Log the traffic of the Transit Gateway | `bool` | `false` | no |
| `tgw_flow_logs_destination` | Where the Transit Gateway flow log is written: `s3`, `cloudwatch`, or `both` for simultaneous delivery to both destinations | `string` | `"s3"` | no |
| `tgw_flow_logs_retention_days` | Retention in days for the CloudWatch log group of the TGW flow logs. Only the values CloudWatch Logs accepts are valid | `number` | `365` | no |
| `tgw_flow_logs_s3_path` | Key prefix inside the central log bucket for the TGW flow logs, without leading or trailing slash | `string` | `"tgw-flow-logs"` | no |
| `tgw_multicast_domains` | Transit Gateway multicast domains. Not implemented — a `check` block reports every entry, so a configured domain does not pass silently | `list(object)` | `[]` | no |
| `enable_ram_sharing` | Share subnets, the Transit Gateway, DNS firewall rule groups, resolver rules, IPAM pools, Network Firewall rule groups and policy, and the query logging configuration through Resource Access Manager. Without it no share is created — see [Resource sharing](#resource-sharing) | `bool` | `false` | no |
| `enable_shared_subnet_tagging` | Materialise the `shared_subnet_tags` entries on RAM-shared subnets this account **received** — see [Shared subnet tags in recipient accounts](#shared-subnet-tags-in-recipient-accounts) | `bool` | `false` | no |
| `shared_subnet_tags` | One entry per received subnet: `subnet_id` plus the `tags` to hold there; `vpc_id`/`vpc_tags` (as a pair) optionally tag the owning VPC the share made visible | `list(object)` | `[]` | no |
| `acm_certificates` | Certificates to request (`type = "request"`: domain, SANs, validation method, `key_algorithm`) or to import (`type = "import"`: material from `acm_certificate_material`), each with an optional `tags` map. With `validation_zone_name` the module writes the DNS validation records into that zone and waits for issuance; the zone has to be free of VPCs, because ACM cannot read a private hosted zone. Email validation has to be completed by hand — see [ACM certificates](#acm-certificates) | `list(object)` | `[]` | no |
| `acm_certificate_material` | PEM material for imported certificates, keyed by `domain_name`: `private_key`, `certificate_body`, optional `certificate_chain`. Sensitive; hand the values in as variable values, never as files — see [ACM certificates](#acm-certificates) | `map(object)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| `vpc_ids` | Map of VPC name → VPC ID |
| `subnet_ids` | Map of vpc_name.subnet_name → subnet ID |
| `transit_gateway_id` | TGW ID (empty when disabled) |
| `transit_gateway_route_table_ids` | Map of RT name → RT ID |
| `tgw_peering_attachment_ids` | Map of peering key (`<peer_region>-<peer_transit_gateway_id>`) → peering attachment ID |
| `prefix_list_ids` | Map of prefix list name → ID |
| `flow_log_ids` | Map of VPC name → flow log ID |
| `vpc_flow_log_ids_by_destination` | Map of `vpc_name.destination` (`s3`, `cloudwatch`) → flow log ID |
| `dhcp_options_set_ids` | Map of DHCP options set name → DHCP options set ID |
| `eip_allocation_ids` | Map of EIP name → allocation ID |
| `vpc_template_expanded_keys` | Expanded VPC template keys (`account_name.template_name`) — see the note below |
| `load_balancer_arns` | Map of load balancer name → LB ARN |
| `target_group_arns` | Map of target group name → target group ARN |
| `gwlb_ids` | Map of GWLB name → GWLB ID |
| `gwlb_target_group_arns` | Map of GWLB name → ARN of its target group (the registration target for firewall appliances) |
| `security_group_ids` | Map `vpc_name.sg_name` → security group ID |
| `gwlb_consumer_endpoint_ids` | Map of gwlb_name.consumer_vpc_name → VPC endpoint ID |
| `customer_gateway_ids` | Map of customer gateway name → customer gateway ID |
| `vpn_connection_ids` | Map of customer gateway name → VPN connection ID |
| `dx_gateway_ids` | Map of DX gateway name → DX gateway ID |
| `tgw_connect_attachment_ids` | Map of TGW Connect attachment name → attachment ID |
| `tgw_connect_peer_ids` | Map of connect_name.peer_name → TGW Connect peer ID |
| `tgw_flow_log_id` | TGW flow log ID (empty when disabled) |
| `route53_query_log_config_id` | Route53 Resolver query log config ID (empty when disabled) |
| `resolver_endpoint_ids` | Map of resolver endpoint name → endpoint ID |
| `standalone_resolver_rule_ids` | Map of standalone resolver rule name → rule ID |
| `dns_firewall_rule_group_ids` | Map of DNS firewall rule group name → rule group ID |
| `firewall_endpoint_ids` | Map of Availability Zone → Network Firewall endpoint ID |
| `firewall_endpoint_ids_by_firewall` | Map of firewall name → Availability Zone → endpoint ID, for the firewalls of `network_firewall.firewalls` |
| `firewall_policy_arns` | Map of firewall policy name → policy ARN, for the policies of `network_firewall.policies` |

The identifiers above are the module's interface for downstream stacks: a
Terragrunt `dependency` block reads them to reach a load balancer, a VPN
connection, a resolver endpoint or a firewall endpoint that this module created.
One of them needs a note of its own:

- `vpc_template_expanded_keys` — the evidence interface of the VPC template
  expansion. It lists one `account_name.template_name` key per entry of
  `deployment_targets` and is the only place where a configured VPC template
  becomes observable, because the templates themselves create no resources (see
  *VPC Templates* below). An empty list means: no template configured.

## Resources

The module creates the resource types below. They are grouped by the file that declares them, so the grouping doubles as a map of the module. A type appears in more than one row when several files create it for their own purpose. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

| File | Resource types |
|---|---|
| `direct-connect.tf` | `aws_dx_gateway`, `aws_dx_gateway_association`, `aws_dx_private_virtual_interface`, `aws_dx_transit_virtual_interface`, `aws_dx_gateway_association_proposal` |
| `endpoints.tf` | `aws_ec2_managed_prefix_list`, `aws_vpc_endpoint`, `aws_security_group`, `aws_vpc_security_group_ingress_rule`, `aws_lb`, `aws_lb_target_group`, `aws_lb_listener`, `aws_vpc_endpoint_service`, `aws_route53_zone`, `aws_route53_record`, `aws_route53_zone_association` |
| `flow-logs.tf` | `aws_cloudwatch_log_group`, `aws_iam_role`, `aws_iam_role_policy`, `aws_flow_log` |
| `ipam.tf` | `aws_vpc_ipam`, `aws_vpc_ipam_scope`, `aws_vpc_ipam_pool`, `aws_vpc_ipam_pool_cidr`, `aws_vpc_ipam_organization_admin_account`, `aws_ram_resource_share`, `aws_ram_resource_association`, `aws_ram_principal_association` |
| `nat.tf` | `aws_eip`, `aws_nat_gateway` |
| `network-firewall.tf` | `aws_networkfirewall_rule_group`, `aws_networkfirewall_firewall_policy`, `aws_networkfirewall_firewall`, `aws_networkfirewall_logging_configuration`, `aws_ram_resource_share`, `aws_ram_resource_association`, `aws_ram_principal_association` |
| `route53.tf` | `aws_route53_zone`, `aws_route53_resolver_rule`, `aws_route53_resolver_firewall_rule_group`, `aws_route53_resolver_firewall_rule`, `aws_route53_resolver_firewall_rule_group_association`, `aws_route53_resolver_firewall_domain_list`, `aws_ram_resource_share`, `aws_ram_resource_association`, `aws_ram_principal_association`, `aws_cloudwatch_log_group`, `aws_route53_resolver_query_log_config`, `aws_route53_resolver_query_log_config_association`, `aws_security_group`, `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`, `aws_route53_resolver_endpoint`, `aws_route53_resolver_rule_association`, `aws_route53_vpc_association_authorization`, `aws_route53_zone_association` |
| `security-groups.tf` | `aws_security_group`, `aws_security_group_rule`, `aws_default_security_group` |
| `shared-subnet-tags.tf` | `aws_ec2_tag` |
| `subnets.tf` | `aws_subnet`, `aws_route_table`, `aws_route_table_association`, `aws_route`, `aws_ram_resource_share`, `aws_ram_resource_association`, `aws_ram_principal_association`, `aws_network_acl`, `aws_network_acl_rule`, `aws_network_acl_association` |
| `transit-gateway.tf` | `aws_ec2_transit_gateway`, `aws_ec2_transit_gateway_route_table`, `aws_ec2_transit_gateway_vpc_attachment`, `aws_ec2_transit_gateway_route_table_association`, `aws_ec2_transit_gateway_peering_attachment`, `aws_ec2_transit_gateway_route`, `aws_ram_resource_share`, `aws_ram_resource_association`, `aws_ram_principal_association`, `aws_ec2_transit_gateway_route_table_propagation`, `aws_ec2_transit_gateway_peering_attachment_accepter`, `aws_ec2_transit_gateway_connect`, `aws_ec2_transit_gateway_connect_peer`, `aws_cloudwatch_log_group`, `aws_iam_role`, `aws_iam_role_policy`, `aws_flow_log` |
| `vpc.tf` | `aws_vpc`, `aws_vpc_ipv4_cidr_block_association`, `aws_internet_gateway`, `aws_vpc_peering_connection`, `aws_route`, `aws_default_vpc`, `aws_default_subnet`, `aws_default_security_group`, `aws_vpc_dhcp_options`, `aws_vpc_dhcp_options_association`, `aws_eip`, `aws_vpc_ipv6_cidr_block_association`, `aws_egress_only_internet_gateway`, `aws_acm_certificate`, `aws_route53_record`, `aws_acm_certificate_validation` |
| `vpn.tf` | `aws_customer_gateway`, `aws_vpn_gateway`, `aws_cloudwatch_log_group`, `aws_vpn_connection` |

## Tagging

Three layers of tags reach a network resource, and they are set in three
different places:

1. **Organization-wide tags** — the provider's `default_tags`, configured once in
   `stacks/root.hcl` from `env/common.hcl`. They apply to every resource of
   every module and are the right place for cost centre, environment and owner
   of the whole landing zone.
2. **The module's own tags** — `Name` on every resource, plus `Type` on subnets
   and route tables. The module derives them from the entry name and needs them
   to stay stable: it keys its resources by that name and its outputs address
   them through it.
3. **Free-form tags per entry** — an optional `tags` map on each entry of the
   module's resource lists. Use them where a single VPC, subnet, firewall rule
   group or VPN connection needs a tag that the rest of the landing zone does
   not: an application identifier, a data classification, a maintenance window,
   an exception a policy checks for.

### Merge order: the module's `Name` wins

The per-entry map is merged **first**, the module's own tags **last**:

```hcl
tags = merge(each.value.tags, { Name = each.key })
```

A `Name` supplied in `tags` therefore has no effect — the resource keeps the
name the module derived. This is deliberate. The module addresses its resources
by that name in state keys, in cross-resource references and in its outputs; a
resource whose console name says one thing while every reference says another is
a trap during an incident, and Terraform would not report the divergence. Every
other key passes through unchanged.

Tags are validated at plan time: a key must be 1 to 128 characters long, a value
at most 256, and the prefix `aws:` is reserved by AWS. Without that check AWS
rejects the tag when the resource is applied — after it has been created.

### Where a derived resource takes its tags from

Some resources have no entry of their own because the module derives them:

| Resource | Tag source |
|---|---|
| Route table of a subnet | `vpcs[].subnets[].route_table_tags` |
| NAT gateway and its Elastic IP | `vpcs[].subnets[].nat_gateway_tags` |
| Transit Gateway route table | `transit_gateway.route_table_tags["<route table name>"]` |
| VPN connection of a customer gateway | `customer_gateways[].vpn_connection_tags` |
| Firewall policy | `network_firewall.firewall_policy.tags` |

`transit_gateway.route_tables` holds names, not objects, so the tags of a route
table are addressed by that name. A key that names no entry of `route_tables` is
rejected at plan time — misplaced tags would otherwise be silently missing.

Resources the module creates for its own bookkeeping — RAM shares, default
security groups, log groups, IAM roles for flow logs — are not tagged per entry.
They exist per landing zone, not per configuration entry, and `default_tags`
covers them.

### Example

```hcl
vpcs = [
  {
    name         = "shared-services"
    cidr         = "10.0.0.0/16"
    account_name = "SharedServices"
    tags         = { DataClassification = "internal", Application = "platform" }
    subnets = [
      {
        name              = "public-a"
        cidr              = "10.0.1.0/24"
        availability_zone = "eu-central-1a"
        type              = "public"
        nat_gateway       = true
        tags              = { Tier = "edge" }
        route_table_tags  = { Purpose = "egress" }
        nat_gateway_tags  = { MaintenanceWindow = "sun-03:00-05:00" }
      },
    ]
    security_groups = [
      { name = "app-sg", tags = { Application = "orders" } },
    ]
  },
]

transit_gateway = {
  enabled          = true
  route_tables     = ["shared", "segregated"]
  tags             = { Purpose = "hub" }
  route_table_tags = { shared = { Segment = "shared" } }
}
```

## Direct Connect Association Proposals

A `dx_gateways` entry may carry `association_proposals`. Each proposal creates an
`aws_dx_gateway_association_proposal` that offers a gateway in another account
the association with this Direct Connect gateway. The offer is where the module
stops: accepting it happens in the owning account, either through a separate
Terraform configuration that holds credentials for that account or by hand, since
this module cannot create a provider for an account it does not know at plan
time. Until the offer is accepted the proposal stays in state `requested` and no
traffic flows.

Every configured proposal is therefore reported by the `check` block
`dx_association_proposal_cross_account` — the message is a reminder of the open
step, not a defect. The proposal IDs the owning account needs in order to accept
are shown in the plan output of that resource.

## VPC Templates

`vpc_templates` describes the VPC layout that identical workload accounts are
supposed to receive. It is documentation and intent, not a creation path:
Terraform cannot create providers dynamically, and a VPC in another account
needs a static provider alias. The module therefore creates no resource from a
template. Instead it

- expands every template into `vpc_template_expanded_keys`, and
- warns through a `check` block when a `deployment_targets` entry has no
  matching key in `account_ids` — such an account has no provider, so the
  template could not be created there even manually.

Cross-account rollout happens through per-account Terragrunt stacks that pass
the layout as `vpcs`. Both states are held by the module tests
(`tests/networking.tftest.hcl`, scenarios 3h and 3i): a set template creates no
VPC but reports its keys, and an unknown deployment target triggers the warning.

## Deletion protection

Central network resources are protected against an accidental `terraform
destroy` or a misdirected plan. The workload load balancer (`aws_lb.this`) is
created with `enable_deletion_protection = true` as a fixed value. Where the
protection is an attribute instead, its default keeps the protection on, and a
deployment that needs to tear the resource down — a lab, an integration test environment — can say so in its configuration
instead of reaching for the console.

Operational consequence: destroying a protected resource is a two-step process.
The protection has to be turned off first — by setting its attribute to `false`
and applying, or for a fixed value through console/API — only then does the
destroy succeed. Runbooks and automated teardown (for example integration test
environments) must account for this extra step.

### Network firewall

| Attribute | Default | Resource |
|---|---|---|
| `network_firewall.delete_protection` | `true` | the module's own firewall |
| `network_firewall.subnet_change_protection` | `true` | the module's own firewall |
| `network_firewall.firewall_policy_change_protection` | `false` | the module's own firewall |
| `network_firewall.firewalls[].delete_protection` | `true` | that firewall |
| `network_firewall.firewalls[].subnet_change_protection` | `true` | that firewall |
| `network_firewall.firewalls[].firewall_policy_change_protection` | `false` | that firewall |

`firewall_policy_change_protection` keeps the service default `false`. A
`firewalls` entry may not combine it with
`delete_protection = false` — protecting the policy of a firewall that any plan
may destroy protects nothing.

### Gateway Load Balancer

| Attribute | Default | Resource |
|---|---|---|
| `gateway_load_balancers[].deletion_protection` | `true` | `aws_lb.gwlb` |
| `gateway_load_balancers[].cross_zone_load_balancing` | `true` | `aws_lb.gwlb` |

`cross_zone_load_balancing = false` is refused on a load balancer that has
`endpoint_consumers`: cross-zone is what keeps the traffic path of an
Availability Zone alive when its last healthy appliance fails, and switching it
off takes that from every consumer at once.

## Load balancing

`load_balancers` and `target_groups` describe the entry point of a workload:
where a request arrives, what the load balancer does with it, and how it is
spread over the targets. The name, type, subnets, listeners and health check are
the required part. Everything below is optional and, left unset, writes nothing
— the load balancing service applies its own default, so adding one of these
attributes to a configuration is the only thing that changes its plan. The one
exception is `ssl_policy` on an `HTTPS`/`TLS` listener: left unset, the module
writes its own TLS-1.2-minimum default rather than leaving the attribute out —
see [Migrating to the New TLS Listener Floor](../../docs/operations.md#migrating-to-the-new-tls-listener-floor).

Two attributes are not configurable: `enable_deletion_protection` and
`drop_invalid_header_fields` are always on, see [Deletion
protection](#deletion-protection).

An application load balancer names at least one group in `security_groups`
(entries of the same VPC's `security_groups`, with ingress on the listener
ports and egress to the targets); the plan refuses an entry without one.
Without a group AWS attaches the VPC's default security group, and this module
removes every rule of that group, so the load balancer would pass no traffic.

### Target group attributes

| Attribute | Purpose | Values |
|---|---|---|
| `deregistration_delay` | How long a target that is being removed keeps draining open connections | 0-3600 seconds |
| `slow_start` | Ramp traffic up to a freshly registered target instead of sending it a full share at once | 0 (off) or 30-900 seconds |
| `algorithm` | How requests are spread over healthy targets | `round_robin`, `least_outstanding_requests`, `weighted_random` |
| `stickiness` | Keep a client on the target it first reached | `type` plus `cookie_duration`; `app_cookie` additionally needs `cookie_name` |
| `preserve_client_ip` | Targets see the client address instead of the load balancer address | `true` / `false` |
| `proxy_protocol_v2` | Prefix each connection with the Proxy Protocol v2 header, so the target learns the original addresses over a plain TCP stream | `true` / `false` |
| `connection_termination` | Close established connections when a target deregisters instead of letting them drain | `true` / `false` |
| `target_failover` | What happens to existing flows when a gateway target deregisters or turns unhealthy | `no_rebalance`, `rebalance` |
| `protocol_version` | Application protocol the targets speak | `HTTP1`, `HTTP2`, `GRPC` |

`stickiness.type` picks the mechanism, and the mechanism depends on the kind of
target group: `lb_cookie` and `app_cookie` for application target groups,
`source_ip` for network target groups, `source_ip_dest_ip` and
`source_ip_dest_ip_proto` for gateway target groups. `lb_cookie` lets the load
balancer issue the cookie; `app_cookie` follows a cookie the application sets,
which is why it needs the cookie name.

### Load balancer attributes

The first seven apply to `type = "application"` only. Set on a network load
balancer they are rejected in the plan, because the interface knows them for
application load balancers alone and the entry would otherwise read as if the
setting had taken effect.

| Attribute | Purpose | Values |
|---|---|---|
| `idle_timeout` | How long a connection may sit idle before it is closed | 1-4000 seconds |
| `enable_http2` | Answer HTTP/2 requests | `true` / `false` |
| `desync_mitigation_mode` | How strictly a request whose length is ambiguous is treated | `defensive`, `strictest`, `monitor` |
| `enable_xff_client_port` | Record the client port alongside the address in `X-Forwarded-For` | `true` / `false` |
| `xff_header_processing_mode` | What happens to an `X-Forwarded-For` header that arrives with the request | `append`, `preserve`, `remove` |
| `enable_tls_headers` | Pass the negotiated TLS version and cipher to the target as `x-amzn-tls-*` headers | `true` / `false` |
| `enable_waf_fail_open` | Forward a request when the web application firewall cannot be reached, instead of rejecting it | `true` / `false` |
| `enable_cross_zone_load_balancing` | Spread traffic over targets in every availability zone, not only the zone the request arrived in | `true` / `false` |

Application load balancers always balance across zones; for a network load
balancer `enable_cross_zone_load_balancing` is a decision between the resilience
of a zone whose own targets are unhealthy and the cost of cross-zone traffic.

### Listener actions

A listener without an `action` block forwards to `target_group_name` — the
behaviour of every listener written before the block existed. With an `action`
block a listener can do three things:

| `action.type` | What the listener does | Required |
|---|---|---|
| `forward` | Send the request to one target group (`target_group_name`) or spread it over several with `target_groups` and their `weight` | a destination |
| `fixed-response` | Answer directly, without a target: a maintenance page, a health endpoint, a deliberate rejection | `fixed_response.status_code` |
| `redirect` | Send the client elsewhere; every part not set is taken from the original request | — (`status_code` defaults to `HTTP_302`) |

`action.order` places the action within the listener. `action.stickiness` keeps a
client on the target group it first reached for the given number of seconds,
which is what makes a weighted forward usable for a gradual rollout: without it
a client would hop between the two versions on every request.

`alpn_policy` on a TLS listener of a network load balancer states which protocol
is negotiated during the handshake (`HTTP1Only`, `HTTP2Only`, `HTTP2Optional`,
`HTTP2Preferred`, `None`).

#### The authenticated edge — enforced on every internet-facing load balancer

An internet-facing load balancer answers anyone on the internet the moment it
exists, and this project's rule is that nothing public is anonymous: every
internet-facing endpoint sits behind the organization's OpenID Connect (OIDC)
identity provider. The module enforces that rule rather than describing it.
`scheme = "internet-facing"` is **refused at plan time**
unless the entry is an application load balancer whose every listener is
`HTTPS` and declares an `authenticated_edge`:

| Entry | Plan |
|---|---|
| `type = "network"`, `scheme = "internet-facing"` | refused — a network load balancer passes TCP/TLS/UDP flows through and has no listener authentication at all |
| `type = "application"`, `scheme = "internet-facing"`, a listener without `authenticated_edge` — or no listener at all | refused, naming the entry, its scheme and the listener port |
| any listener with `authenticated_edge` that is not `HTTPS` on an application load balancer | refused — the load balancing service offers `authenticate-oidc` on HTTPS listeners only, so a plaintext listener cannot carry the edge, not even a redirect to HTTPS |
| `scheme = "internal"` (the default) | allowed: the edge is optional |

A gateway load balancer (`gateway_load_balancers`) has no scheme — the API
knows none for that type, its traffic arrives through endpoints — and
`load_balancers.type` does not offer `"gateway"`, so the question does not
arise there.

`authenticated_edge` sits on the listener, because that is where the load
balancing API keeps it: each listener has its own action chain, its own client
registration at the provider and its own redirect URL
(`https://<dns name>/oauth2/idpresponse`). Declared, it renders as an
`authenticate-oidc` action in position 1 of the listener's default action
chain, ahead of the listener's own forward, redirect or fixed response, whose
`order` becomes 2 when the entry sets none (an explicit `action.order` is kept
and must be 2 or more). The module writes `on_unauthenticated_request =
"authenticate"` itself rather than leaving it to the service default, so a
request without a session is always sent to the provider to log in; an edge
that let anonymous callers through would be no edge.

| `authenticated_edge` | Purpose |
|---|---|
| `type` | `"oidc"` (default and only value — the edge speaks OpenID Connect) |
| `issuer`, `authorization_endpoint`, `token_endpoint`, `user_info_endpoint` | the provider's endpoints, full `https://` URLs |
| `client_id` | the client registered at the provider for this listener |
| `client_secret_arn` **or** `client_secret` | exactly one: the ARN of a Secrets Manager secret whose secret string is the client secret — the module reads it, so the value never appears in configuration — or the value itself, handed in from a sensitive variable, never as a literal in a file |
| `scope` | OAuth scopes requested; unset keeps the service default `openid` |
| `session_timeout` | seconds a session cookie stays valid (1-604800); unset keeps the service default of 7 days |

With `client_secret_arn` the identity that plans needs
`secretsmanager:GetSecretValue` on that ARN. Either way Terraform state stores
what the load balancing API receives, so the state backend's encryption is the
protection boundary — the same statement the module makes for
`acm_certificate_material`.

`action.type = "authenticate-oidc"` is still refused (*Each listener action
type must be forward, fixed-response or redirect.*, held by
`networking_invalid_listener_action_type`): the edge is not one of the
listener's actions but the block ahead of them. Scenario 3bf of
`tests/networking.tftest.hcl` holds the four refusals above red and the
accepted form green: the chain starts with `authenticate-oidc` in position 1,
the OIDC fields reach the action, and the secret is read from Secrets Manager
for exactly the listeners that name an ARN.

#### Trusted issuers

The checks above hold the *shape* of an edge: four `https://` URLs and a
client. They say nothing about who runs the provider, so on their own any HTTPS
issuer would authenticate a public entry point. The module therefore holds
every edge to the issuers the operator trusts, named in `authenticated_edge_allowed_issuers`. The module hard-codes
no issuer and the list is empty by default, so nothing is trusted until the
operator says so:

| Entry | Plan |
|---|---|
| a listener whose `authenticated_edge.issuer` is not in `authenticated_edge_allowed_issuers` (exact string) — on any load balancer, internal ones included | refused, naming the entry, the listener port and the issuer |
| `scheme = "internet-facing"` while `authenticated_edge_allowed_issuers` is empty | refused, naming the entry, with the remedy to name the trusted issuers |
| `scheme = "internal"` without an edge | allowed |

The operator's step, before the first internet-facing load balancer: ask your
identity team for the OIDC issuer URL of your identity provider as they publish it,
and set it in `env/common.hcl` exactly as published — the comparison is an
exact string, so a trailing slash or a different host is a different issuer:

```hcl
# env/common.hcl, locals: the value comes from your identity team, not from here
authenticated_edge_allowed_issuers = ["<your identity provider's OIDC issuer URL>"]
```

`configurations/loader.hcl` reads the list (default `[]`) and
`stacks/management/networking` passes it to the module. Scenario 3bg of
`tests/networking.tftest.hcl` holds the three refusals red: an internet-facing
edge with an untrusted issuer, an internet-facing entry with an empty list,
and an internal entry whose edge names an untrusted issuer.

### Example

A weighted rollout behind an internal application load balancer, with HTTP
redirected to HTTPS and a maintenance port that answers without any target.
The load balancer is internal because two of its listeners are plaintext — an
internet-facing entry would be refused for them (see the next example):

```hcl
target_groups = [
  {
    name                 = "app-blue-tg"
    port                 = 443
    protocol             = "HTTPS"
    vpc_name             = "workload"
    target_type          = "ip"
    protocol_version     = "HTTP2"
    deregistration_delay = 60
    slow_start           = 60
    algorithm            = "least_outstanding_requests"
    stickiness           = { type = "app_cookie", cookie_name = "SESSIONID", cookie_duration = 3600 }
  },
  {
    name        = "app-green-tg"
    port        = 443
    protocol    = "HTTPS"
    vpc_name    = "workload"
    target_type = "ip"
  },
]

load_balancers = [
  {
    name                       = "app-alb"
    type                       = "application"
    vpc_name                   = "workload"
    subnet_names               = ["private-a", "private-b"]
    security_groups            = ["app-alb-sg"]
    scheme                     = "internal"
    idle_timeout               = 120
    desync_mitigation_mode     = "strictest"
    xff_header_processing_mode = "preserve"
    listeners = [
      {
        port     = 80
        protocol = "HTTP"
        action = {
          type     = "redirect"
          redirect = { status_code = "HTTP_301", protocol = "HTTPS", port = "443" }
        }
      },
      {
        port     = 8080
        protocol = "HTTP"
        action = {
          type           = "fixed-response"
          fixed_response = { status_code = "503", content_type = "text/html", message_body = "<h1>Maintenance</h1>" }
        }
      },
      {
        port            = 443
        protocol        = "HTTPS"
        ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
        certificate_arn = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
        action = {
          type = "forward"
          target_groups = [
            { target_group_name = "app-blue-tg", weight = 90 },
            { target_group_name = "app-green-tg", weight = 10 },
          ]
          stickiness = { duration = 3600 }
        }
      },
    ]
  },
]
```

Shifting the rollout is then a change of the two `weight` values.

The same workload on the internet: the load balancer is `internet-facing`, so
it has HTTPS listeners only and each of them declares the edge. The client
secret is a Secrets Manager secret the module reads by ARN — no secret value
in the configuration. There is no port-80 redirect: a plaintext listener
cannot authenticate, and the module refuses it on an internet-facing entry.
The edge's issuer is listed in `authenticated_edge_allowed_issuers` — without
that entry the plan refuses the load balancer (see [Trusted
issuers](#trusted-issuers)).

```hcl
authenticated_edge_allowed_issuers = ["https://idp.example.com"]

load_balancers = [
  {
    name            = "app-edge-alb"
    type            = "application"
    vpc_name        = "workload"
    subnet_names    = ["public-a", "public-b"]
    security_groups = ["app-edge-sg"]
    scheme          = "internet-facing"
    listeners = [
      {
        port            = 443
        protocol        = "HTTPS"
        certificate_arn = "arn:aws:acm:eu-central-1:111111111111:certificate/00000000-0000-0000-0000-000000000000"
        action = {
          type = "forward"
          target_groups = [
            { target_group_name = "app-blue-tg", weight = 90 },
            { target_group_name = "app-green-tg", weight = 10 },
          ]
          stickiness = { duration = 3600 }
        }
        authenticated_edge = {
          # the provider's published OIDC endpoints — the provider hands them
          # out with the client registration
          issuer                 = "https://idp.example.com"
          authorization_endpoint = "https://idp.example.com/oauth2/authorize"
          token_endpoint         = "https://idp.example.com/oauth2/token"
          user_info_endpoint     = "https://idp.example.com/oauth2/userinfo"
          client_id              = "app-edge-alb"
          client_secret_arn      = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:app-edge-alb/oidc-client-secret-AbCdEf"
          session_timeout        = 28800
        }
      },
    ]
  },
]
```

Register `https://<the load balancer's DNS name>/oauth2/idpresponse` — and the
alias the users type, if there is one — as the redirect URL of that client at
the provider; the provider's endpoints must be resolvable and reachable from
the load balancer's subnets (an internal load balancer reaches them through a
NAT gateway).

## Transit Gateway attachments

The `tgw_attachment` block of a VPC controls how the VPC connects to the
Transit Gateway. Beyond the route table and the appliance mode it carries the
attachment options and an explicit subnet choice:

| Attribute | Values | Effect |
|---|---|---|
| `dns_support` | `"enable"`, `"disable"`, `null` | DNS resolution across the attachment. `null` leaves the AWS default (enabled) |
| `ipv6_support` | `"enable"`, `"disable"`, `null` | IPv6 traffic across the attachment. `"enable"` requires `enable_ipv6 = true` on the VPC — the module rejects the mismatch at plan time, AWS only at apply |
| `security_group_referencing_support` | `"enable"`, `"disable"`, `null` | Security group references across VPC boundaries through the attachment |
| `subnet_names` | list of subnet names | Exactly these subnets carry the attachment. Empty keeps the module's derivation: one subnet per availability zone whose name contains `tgw`. A VPC with neither is refused at plan time while `transit_gateway.enabled` is true |

Every option defaults to writing nothing, so an attachment that names none of
them keeps the AWS defaults.

```hcl
tgw_attachment = {
  route_table_name = "spoke"
  dns_support      = "disable"
  subnet_names     = ["attach-a", "attach-b"]
}
```

## Site-to-Site VPN

Each `customer_gateways` entry creates a customer gateway and one VPN
connection. The connection terminates on the module's Transit Gateway
(`transit_gateway_name`) or, with `vpc_name`, on a virtual private gateway the
module creates and attaches to that VPC — exactly one of the two must be set.

Connection-level options (all optional, `null` keeps the AWS default):

| Attribute | Purpose |
|---|---|
| `static_routes_only` | `true` for devices that do not speak BGP |
| `enable_acceleration` | Carries the tunnels over the AWS global network. Transit Gateway connections only — the module rejects it on a virtual private gateway at plan time |
| `outside_ip_address_type` | `"PublicIpv4"` or `"PrivateIpv4"` for the outside interface of the customer gateway device |
| `tunnel_inside_ip_version` | `"ipv4"` or `"ipv6"` for the addresses inside the tunnel |
| `amazon_ipv4_network_cidr`, `customer_ipv4_network_cidr` | Which IPv4 ranges may talk over the connection, per side |
| `amazon_ipv6_network_cidr`, `customer_ipv6_network_cidr` | The same per IPv6; requires `tunnel_inside_ip_version = "ipv6"` |

Per tunnel (`tunnel_options`, at most two entries):

| Attribute | Purpose |
|---|---|
| `phase1_lifetime_seconds` | IKE phase 1 lifetime, 900-28800 seconds |
| `phase2_lifetime_seconds` | IKE phase 2 lifetime, 900-3600 seconds |
| `tunnel_inside_ipv6_cidr` | The /126 inside range of the tunnel; requires `tunnel_inside_ip_version = "ipv6"` |
| `enable_tunnel_lifecycle_control` | Control over the schedule of tunnel endpoint replacements |
| `logging` | Tunnel activity logging to CloudWatch Logs: `enable`, optional `log_group_name` (default `/vpn/<gateway>/tunnel<n>`), `output_format` `"json"` or `"text"` |

The module creates the log group for each tunnel with logging enabled —
retention 365 days, encrypted with `cloudwatch_logs_kms_key_arn` when set —
and passes its ARN to the connection.

```hcl
customer_gateways = [{
  name                 = "onprem-main"
  bgp_asn              = 65010
  ip_address           = "198.51.100.10"
  transit_gateway_name = "tlz-transit-gateway"
  tunnel_options = [{
    phase1_lifetime_seconds = 14400
    logging                 = { enable = true }
  }]
}]
```

## Direct Connect details

Each virtual interface of a `dx_gateways` entry optionally carries its BGP
peering details. Unset values stay with what AWS assigns:

| Attribute | Purpose |
|---|---|
| `amazon_address`, `customer_address` | The peer IP of each side as an interface address with prefix length (e.g. `175.45.176.1/30`) |
| `auth_key` | The BGP MD5 authentication key, 8-80 characters. The value ends up in the Terraform state — treat the state accordingly |
| `mtu` | `1500` or `9001` on a private interface, `1500` or `8500` on a transit interface. The module rejects the wrong pairing at plan time |
| `sitelink_enabled` | Site-to-site traffic between Direct Connect locations over the shortest path |

At the gateway, `allowed_prefixes` restricts which CIDR prefixes the
Transit Gateway association advertises, and the route table wiring connects
the gateway attachment to named route tables:

| Attribute | Purpose |
|---|---|
| `allowed_prefixes` | CIDR prefixes advertised over the association. Empty keeps the AWS default (all connected routes) |
| `route_table_associations` | The route table the gateway attachment is associated with — at most one, enforced at plan time |
| `route_table_propagations` | Route tables the attachment propagates its routes into |

No resource exports the attachment ID of a gateway association, so the module
looks it up once per wired gateway; gateways without wiring stay without the
lookup.

## Transit Gateway options and static routes

`transit_gateway` carries the gateway options. The defaults are
`dns_support` `"enable"` and both default route table switches `"disable"`:

| Attribute | Values | Effect |
|---|---|---|
| `dns_support` | `"enable"` (default), `"disable"` | DNS resolution between attached VPCs |
| `vpn_ecmp_support` | `"enable"`, `"disable"`, `null` | Equal-cost multipath routing across VPN tunnels |
| `multicast_support` | `"enable"`, `"disable"`, `null` | Multicast on the gateway; the domains stay a separate concern |
| `security_group_referencing_support` | `"enable"`, `"disable"`, `null` | Security group references across the gateway |
| `default_route_table_association` / `default_route_table_propagation` | `"enable"`, `"disable"` (default) | Whether new attachments automatically associate with / propagate into the default route table. The module manages explicit associations, so the default stays off |
| `cidr_blocks` | list of IPv4/IPv6 CIDR blocks | Address blocks assigned to the gateway, e.g. for Connect peers |

A static route names its destination as a CIDR block **or** a managed prefix
list of the module (exactly one), and its next hop as a named attachment:

```hcl
static_routes = [
  { route_table_name = "hub", destination_cidr_block = "192.168.10.0/24",
    attachment_name = "onprem-main", attachment_type = "vpn" },
  { route_table_name = "hub", destination_cidr_block = "192.168.20.0/24",
    attachment_name = "dxgw-primary", attachment_type = "dx-gateway" },
  { route_table_name = "edge", destination_cidr_block = "10.80.0.0/16",
    attachment_name = "eu-west-1-tgw-0123456789abcdef0", attachment_type = "peering" },
  { route_table_name = "edge", destination_prefix_list_name = "shared-ranges",
    attachment_name = "hub" },
  { route_table_name = "hub", destination_cidr_block = "203.0.113.0/24",
    blackhole = true },
]
```

`attachment_type` selects the namespace of `attachment_name`: `vpc` (default)
names a VPC with a `tgw_attachment`, `vpn` a customer gateway, `dx-gateway` a
Direct Connect gateway, `peering` a peering key
`<peer_region>-<peer_transit_gateway_id>`. A blackhole route drops the traffic
and carries no attachment. Unknown names, a missing next hop and a route with
two destinations are rejected at plan time.

The Transit Gateway flow logs take three settings: `tgw_flow_logs_destination`
(`s3`, `cloudwatch`, or `both` for simultaneous delivery),
`tgw_flow_logs_retention_days` for the CloudWatch log group (only values
CloudWatch Logs accepts), and `tgw_flow_logs_s3_path` for the key prefix
inside the central log bucket.

## Subnet options and Outposts

Each subnet optionally overrides the module's derivations and controls its DNS
behaviour. Every switch defaults to writing nothing, so a subnet that names
none of them keeps the module's derivations and the AWS defaults:

| Attribute | Values | Effect |
|---|---|---|
| `map_public_ip_on_launch` | `true`, `false`, `null` | Automatic public IP assignment. `null` keeps the derivation: on for type `public`, off otherwise |
| `assign_ipv6_on_creation` | `true`, `false`, `null` | IPv6 address assignment on interface creation. `null` keeps the derivation: on when the subnet carries an `ipv6_cidr_suffix` in an IPv6-enabled VPC. `true` requires `enable_ipv6` on the VPC and a suffix on the subnet — rejected at plan time otherwise |
| `enable_dns64` | `true`, `false`, `null` | The Amazon resolver answers IPv4-only destinations with synthetic IPv6 addresses. Requires the same IPv6 prerequisites |
| `private_dns_options` | block, `null` | Private DNS naming of launched instances: `hostname_type` (`"ip-name"` or `"resource-name"`) and the record switches `enable_dns_a_record`, `enable_dns_aaaa_record` |
| `local_zone` | zone name, `null` | Places the subnet in a Local Zone instead of a regional Availability Zone — exactly one of `availability_zone` and `local_zone` per subnet |
| `outpost_name` / `outpost_arn` | name or ARN, `null` | Outpost placement: `outpost_name` resolves against the VPC's `outposts` list, `outpost_arn` passes an ARN through unchanged — at most one of the two |

The `outposts` list of a VPC declares the Outposts its subnets may land on,
and optionally each Outpost's local gateway. Every route table listed there is
associated with the VPC, which is what lets Outpost subnets route to the
on-premises network; the local gateway's name doubles as a route target (see
the route section below):

```hcl
vpcs = [{
  name         = "edge"
  cidr         = "10.40.0.0/16"
  account_name = "network-hub"
  outposts = [{
    name = "rack-1"
    arn  = "arn:aws:outposts:eu-central-1:111111111111:outpost/op-0123456789abcdef0"
    local_gateway = {
      name         = "lgw-rack-1"
      id           = "lgw-0a1b2c3d4e5f60708"
      route_tables = [{ name = "coip", id = "lgw-rtb-0a1b2c3d4e5f60708" }]
    }
  }]
  subnets = [{
    name              = "rack"
    cidr              = "10.40.4.0/24"
    availability_zone = "eu-central-1a"
    type              = "isolated"
    outpost_name      = "rack-1"
  }]
}]
```

## Route destinations and gateway route tables

A route names exactly one destination and a typed next hop; the same shape
applies in a subnet's `custom_routes` and in the routes of a gateway route
table:

| Attribute | Purpose |
|---|---|
| `destination_cidr_block` | IPv4 CIDR destination |
| `destination_ipv6_cidr_block` | IPv6 CIDR destination (e.g. `::/0`) |
| `destination_prefix_list_name` | The name of an entry in `prefix_lists` |
| `target_type` | `tgw`, `nat`, `vpc_endpoint`, `eni`, `peering`, `network_firewall`, `gwlb_endpoint`, `igw`, `eigw`, `vgw`, `local_gateway` |
| `target_name` | Names the module object for the types that need one; `tgw`, `igw`, `eigw` and `vgw` resolve within the VPC, `local_gateway` names the local gateway of an `outposts` entry. For `network_firewall` it is the availability zone (e.g. `eu-central-1a`) whose firewall endpoint the route uses — the module validates the AZ form and rejects an unknown zone instead of passing it through |

Routes of type `tgw` — like `dx_gateways`, `tgw_connect_attachments` and
`customer_gateways` entries without `vpc_name` — require
`transit_gateway.enabled = true`; the module rejects the configuration at plan
time while the Transit Gateway is off.

`gateway_route_tables` binds a route table to the VPC's internet gateway or
virtual private gateway instead of a subnet (edge routing): traffic entering
through that gateway follows the listed routes, for example through a firewall
endpoint. AWS allows one route table per gateway, and the module rejects a
second one at plan time.

A route takes an optional `name`, in `custom_routes` and in the routes of a
gateway route table alike. Without it the route is keyed by its list position,
so removing or reordering an earlier route rewrites the routes after it; with
it the key stays put — see [Stable keys for rules and
routes](#stable-keys-for-rules-and-routes).

`enable_route_propagation` on a subnet propagates the routes of the VPC's
virtual private gateway into that subnet's route table. Everything that leans
on the virtual private gateway (routes of type `vgw`, tables of type
`virtual_private_gateway`, the propagation) requires a `customer_gateways`
entry terminating on the VPC (`vpc_name`), because that is what attaches the
gateway; the module rejects the missing wiring at plan time.

```hcl
subnets = [{
  name                     = "app"
  cidr                     = "10.40.1.0/24"
  availability_zone        = "eu-central-1a"
  type                     = "private"
  enable_route_propagation = true
  custom_routes = [
    { destination_ipv6_cidr_block = "::/0", target_type = "eigw" },
    { destination_prefix_list_name = "corp-ranges", target_type = "vgw" },
    { destination_cidr_block = "10.98.0.0/16",
      target_type = "local_gateway", target_name = "lgw-rack-1" },
  ]
}]

gateway_route_tables = [{
  name         = "igw-ingress"
  gateway_type = "internet_gateway"
  routes = [{
    destination_cidr_block = "10.40.2.0/24"
    target_type            = "eni"
    target_name            = "eni-0123456789abcdef0"
  }]
}]
```

## VPC endpoint options

Gateway endpoints stay a plain list of service names; per-service options
attach through `gateway_endpoint_options`, a map keyed by an entry of
`gateway_endpoints`. A service without an options entry gets a plain
endpoint:

| Attribute | Purpose |
|---|---|
| `policy_name` | A named policy from `endpoint_policies`, checked at plan time |
| `policy` | An inline JSON policy; `policy_name` wins when both are set. Both empty keeps the endpoint without a policy, which is the same as applying none |
| `service_name` | Full service name replacing the regional derivation `com.amazonaws.<region>.<service>` — for special cases such as partner services |

Interface endpoints take the same `service_name` override per entry, plus:

| Attribute | Purpose |
|---|---|
| `security_group` | The name of a `security_groups` entry of the same VPC that replaces the module's default endpoint security group (HTTPS from the VPC CIDR) for this endpoint |
| `central` | Declares a centralized endpoint: the endpoint stops claiming the service's private DNS name, and the module creates a private hosted zone with an apex alias record pointing at the endpoint instead |
| `hosted_zone_name` | Overrides the zone name of a central endpoint; without it the zone derives `<service>.<region>.<dns suffix>`. Needs `central = true` |

Consumer VPCs resolve the service to a central endpoint once they are
associated with its zone — in the same account through additional zone
associations, across accounts through the association authorization pattern
of `route53_zones`:

```hcl
vpcs = [{
  name              = "endpoints"
  cidr              = "10.20.0.0/16"
  account_name      = "network-hub"
  gateway_endpoints = ["s3", "dynamodb"]
  gateway_endpoint_options = {
    s3 = { policy_name = "restrict-to-organization" }
  }
  interface_endpoints = [{
    service        = "ssm"
    subnet_names   = ["private-a"]
    central        = true
    security_group = "endpoint-sg"
  }]
}]
```

## DNS firewall associations

A DNS firewall rule group associates with every VPC named in its `vpc_names`;
the association priority is 100 plus the VPC's position in that list, and each
earlier rule group on the same VPC adds 100, so two groups on one VPC never
share a priority and the earlier group is evaluated first. `mutation_protection`
optionally locks single associations against modification and removal: a map
keyed by an entry of `vpc_names` whose value `ENABLED` or `DISABLED` reaches
exactly that association. A VPC without an entry keeps the service default
(`DISABLED`), so a rule group without the map locks no association:

```hcl
dns_firewall_rule_groups = [{
  name      = "blocklist"
  vpc_names = ["hub", "spoke"]
  mutation_protection = {
    hub = "ENABLED" # the hub association cannot be altered or removed
  }
  custom_domain_lists = [{ name = "blocked", domains = ["malware.example.com"] }]
  rules = [{
    name                    = "block-malware"
    priority                = 100
    action                  = "BLOCK"
    custom_domain_list_name = "blocked"
  }]
}]
```

## Network ACL rule sources

Each NACL rule in `vpcs[].nacls` names its traffic through exactly one of
three source forms — a validation rejects both a rule with two forms and a
rule with none:

| Form | Attribute | Meaning |
|------|-----------|---------|
| IPv4 CIDR | `cidr_block` | The literal IPv4 range (the existing flat form) |
| IPv6 CIDR | `ipv6_cidr_block` | The literal IPv6 range |
| Subnet selector | `source` (inbound) / `destination` (outbound) | A subnet of `vpcs` — the same or another VPC entry — resolved to its CIDR at plan time |

The selector names the subnet by `vpc` and `subnet`; `account` and `region`
optionally document where the referenced subnet lives and must match the
referenced VPC entry's `account_name` and `region`. `ipv6 = true` resolves
the subnet's IPv6 CIDR instead of its IPv4 CIDR and requires a subnet with
an `ipv6_cidr_suffix` in a VPC with `enable_ipv6 = true`. Because the
resolution runs through the subnet resource, IPAM-assigned CIDRs resolve as
well; an unknown VPC, subnet, account or region is rejected at plan time.

Ports are optional so that all-protocol (`"-1"`) and ICMP rules can leave
them unset; TCP and UDP rules must set both. The `icmp` pair carries type
and code (`-1` = all) and is bound to the ICMP protocols: it requires
protocol `"1"`/`"icmp"` or `"58"`/`"icmpv6"`, and those protocols require
it. A rule in the flat form without these fields stays valid.

```hcl
nacls = [{
  name         = "private-nacl"
  subnet_names = ["private-a"]
  inbound = [
    { rule_number = 100, protocol = "tcp", action = "allow", from_port = 443, to_port = 443,
      source = { vpc = "spoke", subnet = "private-a" } },       # resolved to 10.2.1.0/24
    { rule_number = 110, protocol = "icmp", action = "allow",
      cidr_block = "10.0.0.0/16", icmp = { type = 8, code = 0 } }, # ICMP echo request
  ]
  outbound = [
    { rule_number = 100, protocol = "tcp", action = "allow", from_port = 5432, to_port = 5432,
      destination = { vpc = "hub", subnet = "private-a", ipv6 = true } }, # the subnet's IPv6 CIDR
  ]
}]
```

## Security group rule sources and types

A rule in `vpcs[].security_groups[].ingress`/`egress` combines its sources
freely; each source lands on the matching rule resource:

| Source | Attribute | Meaning |
|--------|-----------|---------|
| IPv4 CIDRs | `cidr_blocks` | Literal IPv4 ranges (the existing flat form) |
| IPv6 CIDRs | `ipv6_cidr_blocks` | Literal IPv6 ranges |
| Subnet selectors | `source_subnets` | Subnets of `vpcs`, resolved to their CIDRs at plan time: `vpc`, `subnets`, optional `account` (must match the VPC entry), optional `ipv6 = true` for the subnets' IPv6 CIDRs |
| Security group | `source_security_group` | A group of the same VPC — on ingress and egress rules |
| Prefix list | `prefix_list_id` | A managed prefix list id |

A rule must carry at least one source. An egress rule keeps its open IPv4
default (`cidr_blocks = ["0.0.0.0/0"]`) — set `cidr_blocks = []` to scope an
egress rule to the other sources.

The port/protocol pair comes either from the explicit form (`protocol`,
`from_port`, `to_port` — the existing flat form, unchanged keys and plans)
or from `types`, one rule per entry:

| Type | Expands to |
|------|-----------|
| `RDP`, `SSH`, `HTTP`, `HTTPS`, `MSSQL`, `MYSQL/AURORA`, `REDSHIFT`, `POSTGRESQL`, `ORACLE-RDS` | TCP with the type's fixed port (3389, 22, 80, 443, 1433, 3306, 5439, 5432, 1521) |
| `TCP`, `UDP`, `ICMP` | That protocol with the rule's own `from_port`/`to_port` pair |
| `ALL` | All protocols |

A rule with `types` leaves `protocol` null and sets the port pair exactly
when a `TCP`, `UDP` or `ICMP` entry is listed; `ICMP` does not combine with
`TCP`/`UDP` in one rule. The group itself takes an optional `description`
(immutable in AWS — a change replaces the group); null keeps the derived
`Security group <name> in VPC <vpc>`.

An ingress rule that opens every port to the whole internet is refused at
plan time; the message names the VPC, the group and the rule index. Every
port means all protocols (`types = ["ALL"]`, or `protocol = "-1"` / `"all"`),
or TCP/UDP (a `TCP`/`UDP` type, or `protocol = "tcp"`/`"6"`/`"udp"`/`"17"`)
with the port range `0`-`65535` or `1`-`65535`. The whole internet means a
source with prefix length 0 or 1: `0.0.0.0/0`, `::/0`, or a half of the
address space such as `0.0.0.0/1` or `128.0.0.0/1` (two halves together are
the world). This catches operator mistakes; it is not a security boundary
against someone who wants to open the group. Narrow the rule to the protocol and ports it needs or to
narrower sources, or keep it and set `acknowledge_world_open_all_protocols =
true` on that rule (default `false`). The same holds for the ingress rules of
`vpc_templates[].security_groups`. A world-open rule for a single protocol or
port — a public HTTPS endpoint — needs no acknowledgement.

```hcl
security_groups = [
  {
    name        = "app-sg"
    description = "Application tier"
    ingress = [
      { types = ["SSH", "RDP"], description = "Admin access from the spoke subnet",
        source_subnets = [{ vpc = "spoke", subnets = ["private-a"] }] },
      { protocol = "tcp", from_port = 443, to_port = 443,
        ipv6_cidr_blocks = ["2001:db8::/64"], description = "HTTPS from the IPv6 range" },
    ]
    egress = [
      { protocol = "tcp", from_port = 5432, to_port = 5432, cidr_blocks = [],
        source_security_group = "db-sg", description = "PostgreSQL to the database tier" },
    ]
  },
  { name = "db-sg", ingress = [{ protocol = "tcp", from_port = 5432, to_port = 5432,
    source_security_group = "app-sg", description = "PostgreSQL from the application tier" }] },
]
```

### Stable keys for rules and routes

A security group rule (`ingress`/`egress`) and a route (`custom_routes`,
gateway route table `routes`) are keyed by their list position unless they
carry the optional `name`. With position keys, removing or reordering an
entry moves every later entry to a new key: Terraform replaces those rules or
routes, and because AWS refuses a duplicate rule or route while the old one
still exists, such an apply can fail half way and leave a rule missing until
the next apply. A `name` (a letter first, then letters, digits, `-` or `_`;
unique within its list) keys the entry by name instead. Entries without a name
keep their position key, so an existing configuration plans unchanged.

Naming an entry that already exists changes its key once. Move it in the state
before that apply, so Terraform keeps the rule instead of replacing it (under
Terragrunt, `terragrunt state mv` in the stack's directory):

```bash
terraform state mv \
  'aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.0"]' \
  'aws_security_group_rule.ingress_cidr["hub.app-sg.ingress.https"]'
```

The rule resources are `ingress_cidr`, `ingress_sg`, `ingress_prefix_list`
and their `egress_` counterparts; a rule with `types` carries a `.<type>`
suffix after the name or position. Routes are `aws_route.custom["<vpc>.<subnet>.<name>"]`
and `aws_route.gateway_custom["<vpc>.<table>.<name>"]`. A plan after the move
shows no replacement.

## Resource sharing

The module shares network objects with other accounts of the organization
through AWS Resource Access Manager (RAM). `enable_ram_sharing` is the common
gate: while it is `false`, no share exists. Each shareable object carries its
own target list, so switching the gate on shares nothing until an object names
targets.

| Object | Target list |
|---|---|
| Subnet | `vpcs[].subnets[].share_targets` |
| Transit Gateway | `transit_gateway.share_targets` |
| DNS firewall rule group | `dns_firewall_rule_groups[].share_targets` |
| Resolver rule (standalone) | `resolver_rules[].share_targets` |
| Resolver rule (per endpoint) | `resolver_endpoints[].resolver_rules[].share_targets` |
| IPAM pool | `ipam.pools[].share_targets` |
| Network Firewall rule group | `network_firewall.rule_groups[].share_targets` |
| Network Firewall policy | `network_firewall.firewall_policy.share_targets` |
| Network Firewall policy (further) | `network_firewall.policies[].share_targets` |
| Query logging configuration | `route53_query_logging_share_targets` |

A target takes one of four forms, checked at plan time: an account name from
`account_ids` (resolved to its ID), a raw 12-digit account ID, an
organizational unit ARN
(`arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...`) or
the organization ARN (`.../organization/o-...`). OU and organization targets
follow membership: an account that later joins the OU receives the share
without a configuration change. Every share is created with
`allow_external_principals = false`, so principals outside the organization
never qualify. Do not list the sharing account itself — RAM rejects
self-sharing, asynchronously and after the share exists.

The targets must cover the accounts or OUs that consume the object — for
example the accounts whose VPCs a shared resolver rule or DNS firewall rule
group is associated with.

Two load-balancing objects deliberately have no target list: RAM does not
share target groups or load balancers (of the Elastic Load Balancing types it
covers only trust stores). An account that needs its own load balancer or
target group defines it in its own stack through `load_balancers` and
`target_groups`.

```hcl
enable_ram_sharing = true

ipam = {
  enabled = true
  pools = [
    {
      name          = "workloads"
      cidr          = "10.64.0.0/10"
      share_targets = ["arn:aws:organizations::111111111111:ou/o-abc123/ou-workloads-1"]
    }
  ]
}

network_firewall = {
  # ... firewall configuration ...
  rule_groups = [
    {
      name          = "block-domains"
      capacity      = 100
      type          = "STATEFUL"
      rules         = "..."
      share_targets = ["workload-prod"]
    }
  ]
}
```

## Shared subnet tags in recipient accounts

AWS RAM shares the subnet resource, not its tags: EC2 tags are account-local
views, so a shared subnet arrives untagged in every recipient account. The
receiving side's answer is `enable_shared_subnet_tagging` (default `false`)
plus `shared_subnet_tags` in the **recipient account's** networking stack:
each entry names one received `subnet_id` with the tags to hold there, and
optionally the owning VPC (`vpc_id`/`vpc_tags` as a pair) the share made
visible. The module materialises them as `aws_ec2_tag` resources
(`shared-subnet-tags.tf`) — created on apply, corrected on drift, removed
when the entry goes.

Deliberately independent of `enable_ram_sharing`: that switch shares subnets
*out of* the current account, this capability tags subnets received *into*
it — the typical recipient shares nothing itself. The subnet IDs come from
the sharing account's stack outputs (`subnet_ids`), for example through a
Terragrunt `dependency` on the hub's networking stack. Entries naming the
same `vpc_id` must carry identical `vpc_tags`, tag keys must not start with
the reserved `aws:` prefix, and entries behind a disabled switch are rejected
— declared tags that never materialise would misstate the deployed state.

```hcl
enable_shared_subnet_tagging = true
shared_subnet_tags = [
  {
    subnet_id = "subnet-0a1b2c3d4e5f67890" # received via RAM from the hub
    tags      = { Name = "workload-private-a", Tier = "private" }
    vpc_id    = "vpc-0f9e8d7c6b5a43210"
    vpc_tags  = { Name = "shared-network" }
  }
]
```

## ACM certificates

`acm_certificates` covers two paths, chosen per entry through `type`:

| Type | What happens | Needs |
|---|---|---|
| `request` (default) | ACM issues a new certificate for `domain_name` and the `subject_alternative_names`, validated through DNS or email | `validation_method`, optionally `key_algorithm` |
| `import` | The module uploads existing material to ACM | An `acm_certificate_material` entry under the same `domain_name` |

For a requested DNS-validated certificate whose zone this module manages,
`validation_zone_name` names the `route53_zones` entry: the module then writes
the validation records itself (one per unique domain — a wildcard and its apex
share one record) and waits until the certificate is issued. Without
`validation_zone_name` the module only requests and waits; the records must be
created wherever the domain is hosted. Every domain of the entry must lie
inside the named zone — checked at plan time.

The named zone has to be a public one. A `route53_zones` entry becomes a
private hosted zone as soon as a VPC is attached — through its own `vpc_ids`
or, when that list is empty, through every VPC of this module. ACM validates a
public certificate against public DNS and
[cannot validate a private hosted zone](https://docs.aws.amazon.com/acm/latest/userguide/domain-ownership-validation.html),
so a record written there never completes the issuance and the wait runs into
its timeout. The check block `acm_validation_zone_is_private_warning` names
every certificate in that situation in the plan. Two ways out: keep the zone
free of VPCs (a DNS-only stack), or leave `validation_zone_name` unset and
create the records in the public DNS of the domain.

`key_algorithm` picks what ACM issues: `RSA_2048` (the default when unset),
`EC_prime256v1` or `EC_secp384r1`.

Imported material is handed in through `acm_certificate_material`, keyed by
the certificate's `domain_name`: `private_key`, `certificate_body` and
optionally `certificate_chain` as PEM strings. The variable is marked
`sensitive`, so plans never print it. Hand the values in as variable values —
for example from an encrypted tfvars source — never as files in the
repository. Terraform state stores what ACM receives; the state backend's
encryption is the protection boundary. ACM reads domains and algorithm from
the certificate itself, so an import entry carries neither
`subject_alternative_names` nor `key_algorithm` nor `validation_zone_name`.

Email validation (`validation_method = "EMAIL"`) always requires manual
action; a `check` warning reports every such entry.

```hcl
route53_zones = [{ name = "example.com" }]

acm_certificates = [
  {
    domain_name               = "api.example.com"
    subject_alternative_names = ["*.api.example.com"]
    validation_zone_name      = "example.com"
    key_algorithm             = "EC_prime256v1"
  },
  {
    domain_name = "imported.example.com"
    type        = "import"
  },
]

acm_certificate_material = {
  "imported.example.com" = {
    private_key      = var.imported_cert_key # from an encrypted source
    certificate_body = var.imported_cert_body
  }
}
```

## VPC base options

Four options at the VPC entry itself, and four NAT gateway details at its
subnets. All of them are optional, and left unset each adds nothing to the
plan.

| Option | Purpose | Values |
|---|---|---|
| `instance_tenancy` | Hardware the instances of this VPC run on | `"default"` (shared), `"dedicated"`; unset leaves the AWS default (`default`) |
| `egress_only_igw` | Decides the egress-only internet gateway instead of deriving it | `true` creates it, `false` suppresses it, unset keeps the derivation |
| `ipv6_cidrs` | IPv6 ranges beyond the Amazon-provided /56 | one source per entry, see below |
| `virtual_private_gateway` | Declares the virtual private gateway of the VPC | `{ asn = <number> }`, or `{}` for the AWS default ASN |

### Egress-only internet gateway

Without the switch the module derives the gateway: it exists when a VPC with an
IPv6 range has at least one private or isolated subnet carrying an
`ipv6_cidr_suffix`, because those subnets get their `::/0` route to it. The
switch replaces that derivation in both directions — `true` creates the gateway
before any such subnet exists (useful when the subnets follow in a later
change), `false` keeps it away from a VPC that has an IPv6 range but no IPv6
egress. Two plan-time checks guard the ends: `true` needs an IPv6 range to be
of any use, and `false` is refused while a private or isolated IPv6 subnet
exists, because that subnet's route would point at a gateway that is never
created.

### IPv6 ranges

`enable_ipv6 = true` requests the Amazon-provided /56 and stays the short form
for the common case. `ipv6_cidrs` adds ranges from a BYOIP pool; each entry
names exactly one source:

| Source | Fields | Result |
|---|---|---|
| Amazon pool | `amazon_provided = true` | The /56 AWS assigns — the same thing `enable_ipv6` asks for, so a VPC uses one of the two forms, not both |
| BYOIP pool | `byoip_pool_id`, optionally `cidr_block` | The named range from the pool, or a range AWS picks from it |

A VPC's **first** range — `enable_ipv6` if set, otherwise the first list entry
— is the one the subnets cut their `/64` out of, following
`ipv6_cidr_suffix`. The module computes how many bits that cut adds from the
range's own prefix, so a `/48` from a BYOIP pool yields `/64` subnets just like
the Amazon `/56` does. Every further range is associated with the VPC and
available to routes and rules, but no subnet is derived from it. A `cidr_block`
carries a prefix between /44 and /60, the sizes AWS associates with a VPC.

### NAT gateway details

`nat_gateway = true` on a subnet keeps its meaning: the module creates the
gateway, allocates an address for it and routes the VPC's private subnets to
it. With several public NAT gateways in one VPC, a private subnet routes
through the first one in its own zone (Availability Zone or Local Zone), and
through the VPC's first one when its zone has none. The four details change
what that gateway is:

| Detail | Purpose |
|---|---|
| `nat_gateway_name` | Replaces the derived `Name` tag of the gateway and its address. Unique across `vpcs` |
| `nat_gateway_private` | A private NAT gateway: it translates between private ranges, carries no public address, and belongs in a **private** subnet |
| `nat_gateway_allocation_id` | An existing Elastic IP by allocation ID (`eipalloc-...`) instead of the address the module allocates |
| `nat_gateway_eip_name` | An entry of `elastic_ips` instead of the address the module allocates |

A public NAT gateway needs a public subnet, a private one a private subnet —
checked at plan time, so a gateway in the wrong kind of subnet is refused
rather than dropped without a word. The two address references exclude each other and both
exclude `nat_gateway_private`; a detail without `nat_gateway = true` is refused
rather than ignored.

### Virtual private gateway

A `virtual_private_gateway` block creates the gateway for the VPC on its own,
so the three features that need it — routes of `target_type` `"vgw"`,
`gateway_route_tables` of `gateway_type` `"virtual_private_gateway"`, and
`enable_route_propagation` on a subnet — do not require a VPN connection. A
`customer_gateways` entry with `vpc_name` creates the gateway as well. Both
origins produce the same gateway: a VPC that declares one and also receives a connection gets one
gateway, and `asn` sets the ASN of the Amazon side (private ranges
64512-65534 or 4200000000-4294967294).

```hcl
elastic_ips = [{ name = "egress-reserved" }]

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
    ]
    virtual_private_gateway = { asn = 65001 }
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
        name                = "private-a"
        cidr                = "10.0.2.0/24"
        availability_zone   = "eu-central-1a"
        type                = "private"
        nat_gateway         = true
        nat_gateway_private = true
      },
    ]
  }
]
```

## IPAM pools and scopes

`ipam` describes the address management the accounts allocate their ranges
from. A pool needs a name and a range; everything below is optional and,
left unset, adds nothing to the plan.

### Pool attributes

| Attribute | Purpose |
|---|---|
| `description` | Free text on the pool |
| `address_family` | `"ipv4"` (default) or `"ipv6"`. Every range of the pool follows that family, and so does a child pool |
| `additional_cidrs` | Further ranges of the same pool. `cidr` stays the first one |
| `auto_import` | Continuously import resources that already use a range of the pool as allocations |
| `allocation_default_netmask_length` | Prefix length a request gets without asking for one |
| `allocation_min_netmask_length` / `allocation_max_netmask_length` | The two ends of the permitted range. Minimum at most maximum, default inside both — checked at plan time |
| `allocation_resource_tags` | Tags a resource must carry to receive an allocation from this pool |
| `publicly_advertisable` / `public_ip_source` | Public address space, see below |

### Scopes

An IPAM brings two scopes of its own: a private and a public one. `scopes`
declares further private scopes, and a pool names the scope it lives in through
`scope`:

| `scope` value | Meaning |
|---|---|
| unset | The IPAM's private default scope |
| `"private-default"` | The same scope, named explicitly |
| `"public-default"` | The IPAM's public scope, for ranges that are advertised to the internet |
| a `scopes` name | The declared scope of that name |

The two reserved names are refused as `scopes` names, so a declared scope can
never shadow one of the IPAM's own. A child pool lives in its parent's scope and
carries its parent's address family — both checked at plan time, because IPAM
rejects the mismatch only once the parent pool exists.

`publicly_advertisable` and `public_ip_source` describe public address space and
therefore require `scope = "public-default"`. AWS states the rest as one rule: a
pool may advertise its ranges only when `address_family = "ipv6"` and the ranges
come from BYOIP (`public_ip_source = "byoip"`, which is also the default).

### IPv6 pools as a source for a VPC

An `ipv6` pool is what a `vpcs` entry's `ipv6_cidrs` names through
`ipam_pool_name`: the VPC then takes its IPv6 range from the pool instead of
from the Amazon pool or a BYOIP pool — see
[VPC base options](#vpc-base-options). The pool has to be an IPv6 one, checked
at plan time.

```hcl
ipam = {
  enabled = true
  scopes = [
    { name = "workloads", description = "Ranges of the workload accounts" }
  ]
  pools = [
    {
      name                              = "root"
      cidr                              = "10.0.0.0/8"
      additional_cidrs                  = ["172.16.0.0/12"]
      locale                            = "eu-central-1"
      auto_import                       = true
      allocation_default_netmask_length = 24
      allocation_min_netmask_length     = 16
      allocation_max_netmask_length     = 28
      allocation_resource_tags          = { CostCenter = "network" }
    },
    {
      name  = "workload"
      cidr  = "10.20.0.0/16"
      scope = "workloads"
    },
    {
      name           = "private-v6"
      cidr           = "2001:db8:100::/48"
      address_family = "ipv6"
    },
  ]
}
```

## Transit Gateway peering

A peering attachment spans two Transit Gateways, and each of them carries its
own route table association for that attachment. The two gateways usually live
in different accounts or regions, so the module covers the two roles
separately — one instance requests the peering, another accepts it.

### Requester side

`peering` describes the request. `route_table_name` is the association on the
gateway this instance owns:

```hcl
transit_gateway = {
  enabled      = true
  route_tables = ["hub", "edge"]
  peering = [
    {
      peer_region             = "eu-west-1"
      peer_transit_gateway_id = "tgw-0123456789abcdef0"
      route_table_name        = "edge"
      auto_accept             = true
      tags                    = { Scope = "interconnect" }
      accepter = {
        account    = "network-secondary"
        apply_tags_from_requester = true
        tags       = { Side = "accepter" }
      }
    },
  ]
}
```

| Attribute | Purpose |
|---|---|
| `route_table_name` | Route table of **this** gateway the attachment is associated with |
| `accepter.account` | Account that owns the peer gateway — an account name from `account_ids` or a raw account ID. Becomes `peer_account_id`; unset leaves the requester account, which is what AWS assumes inside one account |
| `accepter.apply_tags_from_requester` | Copies the `tags` of this entry onto the accepter attachment |
| `accepter.tags` | Accepter-only tags, on top of the copied ones |

`apply_tags_from_requester` and `accepter.tags` need `auto_accept = true`, because that is
what makes this instance create an accepter attachment to tag. The module's
`Name` tag comes last and wins, as everywhere else — see
[Tagging](#tagging).

### Accepter side

The accepter's association belongs to the accepter's gateway, so it is created
by the module instance that owns it. `peering_accepters` is that side: it
accepts an attachment another account or region requested and associates it
with one of its own route tables.

```hcl
# In the stack of the accepting account and region
transit_gateway = {
  enabled      = true
  route_tables = ["hub"]
  peering_accepters = [
    {
      name                          = "from-eu-central-1"
      transit_gateway_attachment_id = "tgw-attach-0123456789abcdef0"
      route_table_name              = "hub"
      tags                          = { Origin = "eu-central-1" }
    },
  ]
}
```

The attachment ID comes from the requesting side: its
`tgw_peering_attachment_ids` output is keyed by
`<peer_region>-<peer_transit_gateway_id>`. Leaving `route_table_name` unset
accepts the attachment without associating it, which is the state directly
after acceptance.

Both route table names, the account form, the attachment ID form and the
uniqueness of the accepter names are checked at plan time.

## Flow log destinations

A VPC flow log is described either by the `flow_logs` block of its `vpcs` entry
or by `vpc_flow_logs_default`, which applies to every VPC without its own
block. Both forms carry the same attribute set, so which one is in use does not
change what an attribute does:

| Attribute | Values | Effect |
|---|---|---|
| `destination` | `"s3"` (default per VPC), `"cloudwatch"`, `"both"` | `"both"` delivers to S3 **and** CloudWatch at the same time: the VPC gets two flow logs |
| `traffic_type` | `"ALL"` (default), `"ACCEPT"`, `"REJECT"` | Which packets are recorded |
| `max_aggregation_interval` | `60`, `600` (default) | Aggregation window in seconds |
| `log_format` | format string | Custom field selection; unset keeps the AWS default format |
| `cloudwatch_retention_days` | a value CloudWatch Logs accepts, `365` (default) | Retention of the log group this flow log writes to |
| `s3_log_path` | key prefix without leading or trailing slash | Replaces the derived prefix `vpc-flow-logs/<vpc name>` inside `central_log_bucket_name` |

```hcl
vpcs = [
  {
    name         = "hub"
    cidr         = "10.0.0.0/16"
    account_name = "network"
    flow_logs = {
      destination               = "both"
      traffic_type              = "REJECT"
      cloudwatch_retention_days = 90
      s3_log_path               = "network/hub/flow"
    }
    subnets = [/* … */]
  },
]
```

A VPC that writes to both destinations appears once in `flow_log_ids` and twice
in `vpc_flow_log_ids_by_destination`, keyed `<vpc name>.s3` and
`<vpc name>.cloudwatch`. The path is checked for its form, for pointing at a
destination that writes to S3 at all, and for being unique across the VPCs —
two VPCs sharing a prefix would interleave their objects.

## VPC DNS and central endpoints

Three switches at the VPC entry, and one at the Connect attachments. Left
unset, each adds nothing to the plan.

| Switch | Default | Effect |
|---|---|---|
| `enable_dns_support` | `true` | The Amazon resolver at the VPC's second address. `false` also switches off private hosted zones, interface endpoint private DNS and the resolver endpoints of this module, so it belongs to isolated networks that carry their own resolver |
| `enable_dns_hostnames` | `true` | Whether instances receive a public DNS name. Needs `enable_dns_support` — AWS rejects the other combination |
| `use_central_endpoints` | `false` | Associates the VPC with the private hosted zone of every interface endpoint declared `central = true`, so the service resolves to that endpoint here as well |

`use_central_endpoints` is the consumer side of the central endpoint pattern
described under [VPC endpoint options](#vpc-endpoint-options): the endpoint's
own VPC already carries the zone and is skipped. A consumer in another
account needs the association made from that account; this module cannot
make it (its `route53_zones` `cross_account_associations` refuse another
account at plan, see the inputs table). The switch is refused without DNS support, without any central
endpoint, and when the only central endpoint is in the VPC itself — in each of
those cases it would be set and change nothing.

### Connect over a Direct Connect transport

A Transit Gateway Connect attachment runs over a transport attachment.
`transport_attachment_type` selects the namespace of `transport_attachment`:

| Type | `transport_attachment` names | Transport |
|---|---|---|
| `"vpc"` (default) | a `vpcs` entry with a `tgw_attachment` | That VPC attachment |
| `"dx-gateway"` | an entry of `dx_gateways` | The Transit Gateway attachment of that Direct Connect gateway, looked up because no resource exports it |

### Default VPC removal

`delete_default_vpc` adopts the default VPC of the current account and region
into Terraform state, together with its default subnets
(`default_vpc_availability_zones`) and its default security group. The first
apply with the toggle on changes the account:

* it removes every ingress and egress rule of the default security group;
* where the region has no default VPC, or a listed zone no default subnet, the
  provider creates one instead of adopting it;
* the adopted default subnets assign no public IP address on launch
  (`map_public_ip_on_launch = false`; the provider default for a default
  subnet is `true`).

Setting the toggle back to `false` (or destroying the stack) deletes the
default subnets of the listed zones and then tries to delete the default VPC.
AWS refuses that (`DependencyViolation`): the VPC's internet gateway and the
default subnets of zones not listed are managed by nobody here, so the default
VPC stays and the apply ends in an error. The security group keeps no rules.
This is the intended behaviour, not a
removal path. A `check` block reports it on every plan that has the toggle on,
and each further account and region needs its own apply of this module.

## Network Firewall policies, firewalls and rule sources

`network_firewall` describes the central inspection path: the rule groups that
hold the rules, the policy that orders them, and the firewall that runs the
policy in a set of subnets. The variable is a single object with `vpc_name`,
`subnet_names`, one `firewall_policy` and a list of `rule_groups`. Everything
below is optional and, left unset, writes nothing.

### More than one firewall and more than one policy

The single-firewall form is not replaced. Two lists join it:

* `policies` — further firewall policies, each with a `name` and the same
  `firewall_policy` shape the module's own policy has.
* `firewalls` — further firewalls, each naming the VPC and subnets it runs in
  and, through `policy_name`, one of those policies. Without `policy_name` a
  firewall runs the module's own policy.

The module's own firewall keeps the name `tlz-network-firewall` and its own
policy the name `tlz-firewall-policy`; a `firewalls` entry may not reuse the
former. Endpoint IDs of the further firewalls come out of
`firewall_endpoint_ids_by_firewall`, keyed by firewall name and then
Availability Zone; `firewall_endpoint_ids` still carries the module's own
firewall alone. `firewall_policy_arns` names the policies.

```hcl
network_firewall = {
  enabled      = true
  vpc_name     = "hub"           # the module's own firewall, unchanged
  subnet_names = ["inspection-a"]

  policies = [
    {
      name = "egress-policy"
      firewall_policy = {
        stateless_default_actions = ["aws:drop"]
        stateful_default_actions  = ["aws:drop_established"]
      }
    }
  ]

  firewalls = [
    {
      name         = "egress-firewall"
      vpc_name     = "egress"
      subnet_names = ["inspection-a"]
      policy_name  = "egress-policy"
      logging_configuration = {
        flow_log_destination_type = "S3"
        flow_log_destination      = "tlz-firewall-logs"
      }
    }
  ]
}
```

Each firewall carries its own `logging_configuration`, its own `description` and
its own three protection switches — see [Deletion
protection](#deletion-protection).

### Policy depth

Both policy forms take the same attributes:

| Attribute | Purpose | Values |
|---|---|---|
| `stateful_default_actions` | What happens to a packet the stateful rules did not match | `aws:drop_strict`, `aws:drop_established`, `aws:drop_established_app_layer`, `aws:alert_strict`, `aws:alert_established`, `aws:alert_established_app_layer` |
| `stateful_engine_options.rule_order` | Whether the stateful rules are evaluated by action or by priority | `DEFAULT_ACTION_ORDER`, `STRICT_ORDER` |
| `stateful_engine_options.stream_exception_policy` | What happens to a flow the engine loses track of | `DROP`, `CONTINUE`, `REJECT` |
| `stateful_engine_options.tcp_idle_timeout_seconds` | How long an idle TCP flow is kept | 60-6000 seconds |
| `stateful_rule_groups` | One reference per entry, with the priority strict ordering needs | see below |
| `stateless_rule_groups` | An explicit priority per stateless rule group | `name` plus `priority` 1-65535 |
| `stateless_custom_actions` | A named action that publishes its own CloudWatch metric dimension | `action_name` plus `publish_metric_dimensions` |

A `stateful_rule_groups` entry names exactly one source:

* `name` — a `rule_groups` entry of this module of type `STATEFUL`.
* `managed_rule_group_name` — an AWS managed rule group. The module builds the
  ARN from the caller's partition and region and the fixed owner `aws-managed`,
  so the same configuration resolves in every partition.
* `arn` — a rule group outside this module, for example one shared into the
  account through RAM.

A `priority` on such an entry requires `rule_order = "STRICT_ORDER"`: outside
strict ordering the service ignores it, and the entry would read as if the order
had been set. A rule group named by a `stateful_rule_groups` entry does not
appear a second time as a bare ARN reference — the same ARN twice in one policy
is rejected.

`stateless_rule_groups` replaces the derived priorities. Left empty, the module
assigns `(index + 1) * 10`. The index
is the position of the group's `name` among the names of the STATELESS rule
groups sorted lexically, not its position in `rule_groups`: groups `b`, `a` get
`a` = 10 and `b` = 20. To set the evaluation order yourself, list the groups in
`stateless_rule_groups`.

### Rule sources

A rule group is described either by the `rules` string — a Suricata rule set or
a JSON rule definition — or by the

structured `rule_group` block. Exactly one of the two, and a validation says so.

```hcl
rule_groups = [
  # The string form, unchanged. A Suricata rules file is read at the call
  # site; the module itself reads no files.
  {
    name     = "egress-domains"
    capacity = 100
    type     = "STATEFUL"
    rules    = file("${path.module}/rules/egress.rules")
  },
  # A domain list: the service generates the rules from the targets.
  {
    name     = "blocked-domains"
    capacity = 200
    type     = "STATEFUL"
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
  # Stateful rules in 5-tuple form, with rule variables a rule can name.
  {
    name     = "tuple-rules"
    capacity = 300
    type     = "STATEFUL"
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
            rule_options = [{ keyword = "sid", settings = ["100"] }]
          }
        ]
      }
    }
  },
  # Stateless rules with match attributes and a custom action.
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
                  destination_ports = [{ from_port = 443 }]
                  protocols         = [6]
                }
              }
            }
          ]
        }
      }
    }
  },
]
```

`rules_source` names exactly one source: `rules_string`, `rules_source_list`,
`stateful_rules` or `stateless_rules_and_custom_actions`. The form has to match
the rule group type — stateless rules belong to a `STATELESS` group, every other
form to a `STATEFUL` one.

Value sets and ranges are checked in the plan: the action, direction and
protocol of a stateful rule; the type and protocols of a domain list; the
priority range and uniqueness of stateless rules; port ranges, IP protocol
numbers and TCP flags, where every inspected flag has to be part of the mask;
and the name and uniqueness of every rule variable.

`rule_groups[].description` and `policies[].description` reach their resource,
and a `policies` entry takes `share_targets` the same way the module's own
policy does — see [Resource sharing](#resource-sharing).

## Gateway Load Balancer attributes

`gateway_load_balancers` creates the load balancer, its target group, the
endpoint service and the consumer endpoints. Three attributes tune the load
balancer itself:

| Attribute | Purpose | Default |
|---|---|---|
| `deletion_protection` | Refuse a destroy of the load balancer | `true` |
| `cross_zone_load_balancing` | Spread traffic over healthy targets in other Availability Zones | `true` |
| `tcp_idle_timeout` | How long a TCP flow may sit idle before the load balancer forgets it | `null` — the service keeps its own 350 seconds |

See [Deletion protection](#deletion-protection) for the operational consequence and
for the rule that ties cross-zone to the consumers.

`tcp_idle_timeout` is an attribute of the load balancer's *listener*, not of the
load balancer: `aws_lb` carries no idle timeout for a Gateway Load Balancer, and
the module writes the value to `aws_lb_listener.gwlb` as
`tcp_idle_timeout_seconds`. It has to be a whole number of seconds between 60
and 6000, and the plan says so before the listener attribute is written.

## Usage Example

```hcl
module "networking" {
  source = "./modules/networking"

  vpcs = [
    {
      name         = "shared-services"
      cidr         = "10.0.0.0/16"
      account_name = "SharedServices"
      tags         = { Application = "platform" }
      subnets = [
        { name = "public-a",  cidr = "10.0.1.0/24",  availability_zone = "eu-central-1a", type = "public", nat_gateway = true },
        { name = "private-a", cidr = "10.0.10.0/24", availability_zone = "eu-central-1a", type = "private" },
        { name = "isolated-a", cidr = "10.0.20.0/24", availability_zone = "eu-central-1a", type = "isolated" },
        { name = "tgw-a", cidr = "10.0.30.0/28", availability_zone = "eu-central-1a", type = "isolated" },
      ]
      tgw_attachment = { route_table_name = "shared" } # attaches through tgw-a
      flow_logs      = { destination = "s3" }
    },
  ]

  transit_gateway = {
    enabled      = true
    route_tables = ["shared", "segregated"]
  }

  central_log_bucket_name = "my-central-logs-bucket"
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
