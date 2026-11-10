# Networking module variables

variable "vpcs" {
  description = "List of VPC definitions with subnets, TGW attachment, and flow logs"
  type = list(object({
    name                = string
    cidr                = optional(string, "")   # Optional for IPAM-based VPCs
    ipam_pool_name      = optional(string, null) # G1: IPAM pool name reference
    ipam_netmask_length = optional(number, null) # G1: Netmask length for IPAM allocation
    account_name        = string
    region              = optional(string)
    secondary_cidrs     = optional(list(string), []) # Additional CIDR blocks
    enable_ipv6         = optional(bool, false)      # Amazon-provided IPv6 CIDR
    tags                = optional(map(string), {})  # Free-form tags for the VPC
    # Instance tenancy of the VPC: "default" places instances on shared
    # hardware, "dedicated" on hardware dedicated to this account. null writes
    # nothing and leaves the AWS default ("default") in place.
    instance_tenancy = optional(string, null)
    # DNS behaviour of the VPC. Both default to true. enable_dns_support turns the Amazon resolver at the
    # VPC's second address on or off; enable_dns_hostnames decides whether
    # instances receive a public DNS name. Turning support off also switches
    # off private hosted zones, interface endpoint private DNS and the
    # resolver endpoints of this module, so it belongs to isolated networks
    # that carry their own resolver.
    enable_dns_support   = optional(bool, true)
    enable_dns_hostnames = optional(bool, true)
    # Consume the central interface endpoints of this module: the VPC is
    # associated with the private hosted zone of every endpoint declared with
    # central = true, so the service resolves to that endpoint here as well.
    # The endpoint's own VPC already carries the zone and is skipped.
    use_central_endpoints = optional(bool, false)
    # Egress-only internet gateway, the IPv6 counterpart of a NAT gateway.
    # null keeps the module's derivation — the gateway exists when a private or
    # isolated subnet of an IPv6-enabled VPC carries an ipv6_cidr_suffix. true
    # creates it regardless of the subnets, false suppresses the derivation.
    egress_only_igw = optional(bool, null)
    # IPv6 ranges of the VPC beyond the Amazon-provided /56 that enable_ipv6
    # requests. Each entry names exactly one source: the Amazon pool
    # (amazon_provided), a BYOIP pool (byoip_pool_id, optionally with the
    # range to take from it), or an IPv6 pool of var.ipam.pools
    # (ipam_pool_name with netmask_length or cidr_block). The first source of
    # a VPC — enable_ipv6, else the first list entry — carries the range the
    # subnets derive their /64 from.
    ipv6_cidrs = optional(list(object({
      amazon_provided = optional(bool, false)
      byoip_pool_id   = optional(string, null)
      cidr_block      = optional(string, null)
      ipam_pool_name  = optional(string, null)
      netmask_length  = optional(number, null)
    })), [])
    # Virtual private gateway of the VPC. Declared here the gateway exists on
    # its own, without a VPN connection terminating on it, and asn sets the
    # ASN of the Amazon side; null leaves the AWS default (64512). A
    # customer_gateways entry with vpc_name attaches its connection to this
    # gateway, and routes of target_type "vgw", gateway route tables of
    # gateway_type "virtual_private_gateway" and enable_route_propagation
    # reach it.
    virtual_private_gateway = optional(object({
      asn = optional(number, null)
    }), null)
    subnets = list(object({
      name                = string
      cidr                = optional(string, "")   # Optional for IPAM-based subnets
      ipam_pool_name      = optional(string, null) # G2: IPAM pool name reference
      ipam_netmask_length = optional(number, null) # G2: Netmask length for IPAM allocation
      # Placement: exactly one of the two. availability_zone is a regional zone
      # name; local_zone places the subnet in a Local Zone by its zone name.
      availability_zone = optional(string, null)
      local_zone        = optional(string, null)
      type              = string                 # "public", "private", "isolated"
      ipv6_cidr_suffix  = optional(string, null) # IPv6 subnet suffix (e.g. "00" for ::00/64)
      nat_gateway       = optional(bool, false)
      # NAT gateway details, read only when nat_gateway = true.
      # nat_gateway_name replaces the derived Name tag of the gateway and its
      # address. nat_gateway_private turns it into a private NAT gateway: it
      # translates between private ranges, carries no public address and
      # therefore belongs in a private subnet. The public address of a public
      # NAT gateway comes from the module unless one of the two references
      # names an existing one — a raw allocation ID
      # (nat_gateway_allocation_id) or an entry of var.elastic_ips
      # (nat_gateway_eip_name).
      nat_gateway_name          = optional(string, null)
      nat_gateway_private       = optional(bool, false)
      nat_gateway_allocation_id = optional(string, null)
      nat_gateway_eip_name      = optional(string, null)
      # Outpost placement: a raw Outpost ARN, or the name of an entry in the
      # VPC's outposts list (the module resolves the name to that entry's ARN).
      outpost_arn  = optional(string, null)
      outpost_name = optional(string, null)
      # Explicit switch for automatic public IP assignment. null keeps the
      # module's derivation: on for type "public", off otherwise.
      map_public_ip_on_launch = optional(bool, null)
      # Explicit switch for IPv6 address assignment on interface creation.
      # null keeps the module's derivation: on when the subnet carries an
      # ipv6_cidr_suffix in an IPv6-enabled VPC, off otherwise.
      assign_ipv6_on_creation = optional(bool, null)
      # DNS64: the Amazon resolver answers IPv4-only destinations with
      # synthetic IPv6 addresses. null leaves the AWS default (off) in place.
      enable_dns64 = optional(bool, null)
      # Private DNS naming of instances launched into the subnet. null writes
      # nothing and leaves every AWS default in place.
      private_dns_options = optional(object({
        hostname_type          = optional(string, null) # "ip-name" or "resource-name"
        enable_dns_a_record    = optional(bool, null)
        enable_dns_aaaa_record = optional(bool, null)
      }), null)
      # Free-form tags. The module derives a route table and — with
      # nat_gateway = true — a NAT gateway with its Elastic IP from each subnet,
      # so those resources carry their own tag maps instead of inheriting the
      # subnet's.
      tags             = optional(map(string), {})
      route_table_tags = optional(map(string), {})
      nat_gateway_tags = optional(map(string), {})
      # share_targets: RAM sharing targets — account names from account_ids,
      # raw account IDs, organizational unit ARNs or the organization ARN.
      # Unlike deployment_targets (cross-account deployment scope for Terragrunt per-account stacks),
      # share_targets controls which principals receive RAM resource shares for this subnet.
      share_targets = optional(list(string), [])
      # Propagate the routes of the VPC's virtual private gateway into this
      # subnet's route table. Requires a customer_gateways entry that
      # terminates on this VPC (vpc_name), because that is what attaches the
      # virtual private gateway.
      enable_route_propagation = optional(bool, false)
      # Custom routes for the subnet's route table. Exactly one destination —
      # an IPv4 CIDR, an IPv6 CIDR, or the name of an entry in prefix_lists —
      # and a typed next hop. target_name names the module object for the
      # types that need one; tgw, igw, eigw and vgw resolve within the VPC.
      # For target_type "network_firewall", target_name is the availability
      # zone (e.g. eu-central-1a) whose firewall endpoint the route uses;
      # target_type "tgw" requires transit_gateway.enabled.
      custom_routes = optional(list(object({
        destination_cidr_block       = optional(string, null)
        destination_ipv6_cidr_block  = optional(string, null)
        destination_prefix_list_name = optional(string, null)
        # "tgw", "nat", "vpc_endpoint", "eni", "peering", "network_firewall",
        # "gwlb_endpoint", "igw", "eigw", "vgw", "local_gateway"
        target_type = string
        target_name = optional(string, "")
      })), [])
    }))
    # Gateway route tables (edge routing): each table is associated with the
    # VPC's internet gateway or virtual private gateway instead of a subnet,
    # so traffic entering through that gateway follows the listed routes —
    # for example through a firewall or Gateway Load Balancer endpoint.
    # AWS allows at most one route table per gateway.
    gateway_route_tables = optional(list(object({
      name         = string
      gateway_type = string # "internet_gateway" or "virtual_private_gateway"
      tags         = optional(map(string), {})
      routes = optional(list(object({
        destination_cidr_block       = optional(string, null)
        destination_ipv6_cidr_block  = optional(string, null)
        destination_prefix_list_name = optional(string, null)
        target_type                  = string
        target_name                  = optional(string, "")
      })), [])
    })), [])
    # Outposts the VPC reaches. Each entry names an existing Outpost so that
    # subnets can reference it (subnets[].outpost_name), and optionally its
    # local gateway: every route table listed there is associated with the
    # VPC, which is what lets Outpost subnets route to the on-premises network.
    outposts = optional(list(object({
      name = string
      arn  = string
      local_gateway = optional(object({
        name = string
        id   = string
        route_tables = optional(list(object({
          name = string
          id   = string
        })), [])
      }), null)
    })), [])
    tgw_attachment = optional(object({
      route_table_name       = string
      appliance_mode_support = optional(string, null) # "enable" or "disable", null = AWS default
      # Attachment options, each "enable" or "disable"; null leaves the AWS
      # default in place (dns_support enabled, the other two disabled).
      dns_support                        = optional(string, null)
      ipv6_support                       = optional(string, null)
      security_group_referencing_support = optional(string, null)
      # Explicit subnet choice for the attachment. Empty keeps the module's
      # derivation: one subnet per AZ whose name contains "tgw".
      subnet_names = optional(list(string), [])
      tags         = optional(map(string), {})
    }))
    # Same four attributes as var.vpc_flow_logs_default, with the same defaults,
    # so that a per-VPC block and the global default behave identically.
    flow_logs = optional(object({
      # "s3", "cloudwatch", or "both" for simultaneous delivery to both
      destination              = optional(string, "s3")
      traffic_type             = optional(string, "ALL") # ALL, ACCEPT, REJECT
      max_aggregation_interval = optional(number, 600)   # 60 or 600
      log_format               = optional(string, null)  # Custom flow log format
      # Retention of the CloudWatch log group this flow log writes to, in days.
      cloudwatch_retention_days = optional(number, 365)
      # Key prefix inside central_log_bucket_name, without leading or trailing
      # slash. null keeps the derivation "vpc-flow-logs/<vpc name>".
      s3_log_path = optional(string, null)
    }))
    # VPC Endpoints
    gateway_endpoints = optional(list(string), []) # ["s3", "dynamodb"]
    # Per-service options for the gateway endpoints, keyed by an entry of
    # gateway_endpoints. A plain service name keeps working unchanged; an
    # options entry attaches an endpoint policy (named or inline; both empty
    # keeps the endpoint without one, which is the same as applying none) and
    # a full service name that replaces the regional derivation for special
    # cases such as partner services.
    gateway_endpoint_options = optional(map(object({
      policy       = optional(string, "")   # inline JSON policy document
      policy_name  = optional(string, "")   # named policy from endpoint_policies
      service_name = optional(string, null) # full service name override
    })), {})
    interface_endpoints = optional(list(object({
      service      = string
      subnet_names = optional(list(string), [])
      policy       = optional(string, "")
      policy_name  = optional(string, "") # Named policy reference
      # Full service name override for special cases such as partner
      # services; null keeps the regional derivation from the service label.
      service_name = optional(string, null)
      # Security group of the same VPC (security_groups[].name) that replaces
      # the module's default endpoint security group for this endpoint.
      security_group = optional(string, "")
      # Centralized endpoint: the endpoint stops claiming the service's
      # private DNS name, and a private hosted zone with an alias record
      # takes over — consumer VPCs resolve the service to this endpoint once
      # they are associated with the zone.
      central          = optional(bool, false)
      hosted_zone_name = optional(string, null) # zone name override, needs central
      tags             = optional(map(string), {})
    })), [])
    # NACLs. Each rule names its traffic through exactly one of three forms:
    # an IPv4 CIDR (cidr_block), an IPv6 CIDR (ipv6_cidr_block) or a subnet
    # selector (source on inbound rules, destination on outbound rules) that
    # resolves a subnet of this variable — the same or another VPC entry — to
    # its CIDR at plan time. Ports are optional so that all-protocol ("-1")
    # and ICMP rules can leave them unset; the icmp pair carries type and
    # code for protocol "1"/"icmp" and "58"/"icmpv6" (-1 = all).
    nacls = optional(list(object({
      name         = string
      subnet_names = list(string)
      tags         = optional(map(string), {})
      inbound = optional(list(object({
        rule_number     = number
        protocol        = string
        action          = string
        cidr_block      = optional(string, null)
        ipv6_cidr_block = optional(string, null)
        source = optional(object({
          vpc     = string
          subnet  = string
          account = optional(string, null) # must match the VPC entry's account_name
          region  = optional(string, null) # must match the VPC entry's region
          ipv6    = optional(bool, false)  # resolve the subnet's IPv6 CIDR
        }), null)
        from_port = optional(number, null)
        to_port   = optional(number, null)
        icmp = optional(object({
          type = number
          code = optional(number, -1)
        }), null)
      })), [])
      outbound = optional(list(object({
        rule_number     = number
        protocol        = string
        action          = string
        cidr_block      = optional(string, null)
        ipv6_cidr_block = optional(string, null)
        destination = optional(object({
          vpc     = string
          subnet  = string
          account = optional(string, null)
          region  = optional(string, null)
          ipv6    = optional(bool, false)
        }), null)
        from_port = optional(number, null)
        to_port   = optional(number, null)
        icmp = optional(object({
          type = number
          code = optional(number, -1)
        }), null)
      })), [])
    })), [])
    # Security Groups. A rule declares its port/protocol either explicitly
    # (protocol + from_port/to_port) or through `types`: named shortcuts
    # (RDP, SSH, HTTP, HTTPS, MSSQL, MYSQL/AURORA, REDSHIFT, POSTGRESQL,
    # ORACLE-RDS expand to their fixed TCP port; TCP, UDP and ICMP use the
    # rule's own port pair; ALL means all protocols), one rule per entry.
    # Sources combine freely per rule: IPv4 CIDRs, IPv6 CIDRs, subnet
    # selectors (source_subnets, resolved against this variable at plan
    # time), a security group of the same VPC and a prefix list. An egress
    # rule keeps its open IPv4 default — set cidr_blocks = [] to scope an
    # egress rule to the other sources.
    security_groups = optional(list(object({
      name        = string
      description = optional(string, null) # null keeps the derived description
      tags        = optional(map(string), {})
      ingress = optional(list(object({
        protocol         = optional(string, null)
        from_port        = optional(number, null)
        to_port          = optional(number, null)
        types            = optional(list(string), [])
        cidr_blocks      = optional(list(string), [])
        ipv6_cidr_blocks = optional(list(string), [])
        source_subnets = optional(list(object({
          vpc     = string
          subnets = list(string)
          account = optional(string, null) # must match the VPC entry's account_name
          ipv6    = optional(bool, false)  # resolve the subnets' IPv6 CIDRs
        })), [])
        source_security_group = optional(string, "")
        prefix_list_id        = optional(string, "") # Prefix list reference
        description           = optional(string, "")
        # An ingress rule opening every port (ALL protocols, or TCP/UDP
        # 0-65535) to 0.0.0.0/0, ::/0 or a /1 half of the address space is
        # refused unless this is true (see the validation on var.vpcs).
        acknowledge_world_open_all_protocols = optional(bool, false)
      })), [])
      egress = optional(list(object({
        protocol         = optional(string, null)
        from_port        = optional(number, null)
        to_port          = optional(number, null)
        types            = optional(list(string), [])
        cidr_blocks      = optional(list(string), ["0.0.0.0/0"])
        ipv6_cidr_blocks = optional(list(string), [])
        source_subnets = optional(list(object({
          vpc     = string
          subnets = list(string)
          account = optional(string, null)
          ipv6    = optional(bool, false)
        })), [])
        source_security_group = optional(string, "")
        prefix_list_id        = optional(string, "") # Prefix list reference
        description           = optional(string, "")
      })), [])
    })), [])
  }))
  default = []

  # The module joins these names with "." into flat map keys ("<vpc>.<subnet>",
  # "<vpc>.<security group>", ...). A dot inside a name would let two different
  # configurations produce the same key, and merge() would silently overwrite
  # one of the resources. The character set therefore excludes the separator.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : concat(
        [can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", vpc.name))],
        [for s in vpc.subnets : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", s.name))],
        [for sg in vpc.security_groups : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", sg.name))],
        [for n in vpc.nacls : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", n.name))],
        [for g in vpc.gateway_route_tables : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", g.name))]
      )
    ]))
    error_message = "VPC, subnet, security group, NACL and gateway route table names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<vpc>.<name>\" map keys from these names, and a dot inside a name could collide two keys and silently drop a resource."
  }

  # G1: Either cidr or ipam_pool_name must be set for each VPC
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.cidr != "" || vpc.ipam_pool_name != null
    ])
    error_message = "Each VPC must have either 'cidr' or 'ipam_pool_name' set."
  }

  # G1: ipam_netmask_length required when ipam_pool_name is set (VPC)
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.ipam_pool_name == null || vpc.ipam_netmask_length != null
    ])
    error_message = "ipam_netmask_length is required when ipam_pool_name is set for a VPC."
  }

  # Validate VPC CIDR format (only for static-CIDR VPCs, skip IPAM-based)
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.cidr == "" || can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", vpc.cidr))
    ])
    error_message = "Each VPC CIDR must have a valid CIDR format (e.g. 10.0.0.0/16)."
  }

  # Validate secondary CIDRs format
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for cidr in vpc.secondary_cidrs :
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", cidr))
      ]
    ]))
    error_message = "Each secondary CIDR must have a valid CIDR format (e.g. 10.1.0.0/16)."
  }

  # G2: Either cidr or ipam_pool_name must be set for each subnet
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.cidr != "" || s.ipam_pool_name != null
      ]
    ]))
    error_message = "Each subnet must have either 'cidr' or 'ipam_pool_name' set."
  }

  # G2: ipam_netmask_length required when ipam_pool_name is set (subnet)
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.ipam_pool_name == null || s.ipam_netmask_length != null
      ]
    ]))
    error_message = "ipam_netmask_length is required when ipam_pool_name is set for a subnet."
  }

  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        contains(["public", "private", "isolated"], s.type)
      ]
    ]))
    error_message = "Subnet type must be 'public', 'private', or 'isolated'."
  }

  # Placement is exactly one zone: a subnet with both entries would silently
  # ignore one of them, a subnet with neither has no place to exist.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        (s.availability_zone != null) != (s.local_zone != null)
      ]
    ]))
    error_message = "Each subnet must set exactly one of availability_zone or local_zone."
  }

  # IPv6 assignment needs an IPv6 CIDR on the subnet. AWS accepts the flag at
  # plan time and rejects the subnet at apply — after the VPC already exists.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.assign_ipv6_on_creation != true || ((vpc.enable_ipv6 || length(vpc.ipv6_cidrs) > 0) && s.ipv6_cidr_suffix != null)
      ]
    ]))
    error_message = "assign_ipv6_on_creation = true requires an IPv6 range on the VPC (enable_ipv6 = true or an ipv6_cidrs entry) and an ipv6_cidr_suffix on the subnet."
  }

  # DNS64 answers IPv4-only destinations with synthetic IPv6 addresses; on a
  # subnet without IPv6 the option changes nothing and hides a broken intent.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.enable_dns64 != true || ((vpc.enable_ipv6 || length(vpc.ipv6_cidrs) > 0) && s.ipv6_cidr_suffix != null)
      ]
    ]))
    error_message = "enable_dns64 = true requires an IPv6 range on the VPC (enable_ipv6 = true or an ipv6_cidrs entry) and an ipv6_cidr_suffix on the subnet."
  }

  # EC2 knows exactly these two hostname schemes; an unknown value fails only
  # when the subnet is applied.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.private_dns_options == null ? true :
        s.private_dns_options.hostname_type == null ||
        contains(["ip-name", "resource-name"], s.private_dns_options.hostname_type)
      ]
    ]))
    error_message = "private_dns_options hostname_type must be null, \"ip-name\", or \"resource-name\"."
  }

  # The module resolves subnets[].outpost_name against this list, so the names
  # must be unique within their VPC.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      length(distinct([for o in vpc.outposts : o.name])) == length(vpc.outposts)
    ])
    error_message = "Each outposts name must be unique within its VPC — subnets reference outposts by name."
  }

  # The ARN is handed to aws_subnet unchanged; a malformed one fails at apply,
  # after the VPC already exists. The partition stays a free segment.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for o in vpc.outposts :
        can(regex("^arn:[^:]+:outposts:[a-z0-9-]+:[0-9]{12}:outpost/op-[0-9a-f]{17}$", o.arn))
      ]
    ]))
    error_message = "Each outposts arn must be an Outpost ARN (arn:<partition>:outposts:<region>:<account>:outpost/op-...)."
  }

  # A subnet names its Outpost either directly (ARN) or through the outposts
  # list — both at once would leave the winner implicit.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.outpost_arn == null || s.outpost_name == null
      ]
    ]))
    error_message = "Each subnet may set outpost_arn or outpost_name, not both."
  }

  # An unknown outpost_name would resolve to nothing and the subnet would
  # silently land in the region instead of on the Outpost.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.outpost_name == null || contains([for o in vpc.outposts : o.name], s.outpost_name)
      ]
    ]))
    error_message = "Each subnet outpost_name must name an entry of the same VPC's outposts list."
  }

  # The local gateway id is the route target of target_type "local_gateway";
  # EC2 rejects a malformed id only when the route is applied.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for o in vpc.outposts :
        o.local_gateway == null ? true :
        can(regex("^lgw-[0-9a-f]{8,17}$", o.local_gateway.id))
      ]
    ]))
    error_message = "Each outposts local_gateway id must be a local gateway id (lgw-...)."
  }

  # Every listed route table id is associated with the VPC; a malformed id
  # fails at apply, after VPC and subnets already exist.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for o in vpc.outposts : o.local_gateway == null ? [true] : [
          for rt in o.local_gateway.route_tables :
          can(regex("^lgw-rtb-[0-9a-f]{8,17}$", rt.id))
        ]
      ]
    ]))
    error_message = "Each outposts local_gateway route_tables id must be a local gateway route table id (lgw-rtb-...)."
  }

  # A local gateway without route tables associates nothing and does nothing —
  # a declaration without effect that no plan would report.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for o in vpc.outposts :
        o.local_gateway == null ? true :
        length(o.local_gateway.route_tables) > 0
      ]
    ]))
    error_message = "Each outposts local_gateway must list at least one route_tables entry — the association is its purpose."
  }

  # The association map is keyed by route table name; a duplicate would
  # silently collapse two associations into one.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for o in vpc.outposts :
        o.local_gateway == null ? true :
        length(distinct([for rt in o.local_gateway.route_tables : rt.name])) == length(o.local_gateway.route_tables)
      ]
    ]))
    error_message = "Each outposts local_gateway route_tables name must be unique within its local gateway."
  }

  # The route checks below cover both route lists — the subnets' custom_routes
  # and the routes of the gateway route tables — because both feed aws_route
  # with the same shape.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        contains(["tgw", "nat", "vpc_endpoint", "eni", "peering", "network_firewall", "gwlb_endpoint", "igw", "eigw", "vgw", "local_gateway"], route.target_type)
      ]
    ]))
    error_message = "Route target_type must be one of: tgw, nat, vpc_endpoint, eni, peering, network_firewall, gwlb_endpoint, igw, eigw, vgw, local_gateway."
  }

  # A route needs exactly one destination. Two destinations would write two
  # route entries under one intent, none would write nothing — both silently.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        length([for d in [route.destination_cidr_block, route.destination_ipv6_cidr_block, route.destination_prefix_list_name] : d if d != null]) == 1
      ]
    ]))
    error_message = "Each route must set exactly one of destination_cidr_block, destination_ipv6_cidr_block, or destination_prefix_list_name."
  }

  # AWS rejects a malformed destination only when the route is applied — after
  # VPC, subnets and route tables already exist.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        route.destination_cidr_block == null ? true :
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", route.destination_cidr_block))
      ]
    ]))
    error_message = "Each route destination_cidr_block must be a valid IPv4 CIDR block (e.g. 10.0.0.0/16)."
  }

  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        route.destination_ipv6_cidr_block == null ? true :
        can(cidrhost(route.destination_ipv6_cidr_block, 0)) && strcontains(route.destination_ipv6_cidr_block, ":")
      ]
    ]))
    error_message = "Each route destination_ipv6_cidr_block must be a valid IPv6 CIDR block (e.g. ::/0)."
  }

  # An unknown prefix list name would resolve to nothing and the route would
  # silently be missing.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        route.destination_prefix_list_name == null ? true :
        contains([for pl in var.prefix_lists : pl.name], route.destination_prefix_list_name)
      ]
    ]))
    error_message = "Each route destination_prefix_list_name must name an entry of prefix_lists."
  }

  # These next-hop types are resolved by name; without one the route has no
  # target to point at.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        !contains(["nat", "vpc_endpoint", "eni", "peering", "network_firewall", "gwlb_endpoint", "local_gateway"], route.target_type) || route.target_name != ""
      ]
    ]))
    error_message = "Routes of target_type nat, vpc_endpoint, eni, peering, network_firewall, gwlb_endpoint, and local_gateway must set target_name."
  }

  # The internet gateway exists only for VPCs with at least one public subnet
  # — a route at a VPC without one would reference a resource that is never
  # created.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      !contains([
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) : route.target_type
      ], "igw") || length([for s in vpc.subnets : s if s.type == "public"]) > 0
    ])
    error_message = "Routes of target_type igw require at least one public subnet in the same VPC — that is what creates the internet gateway."
  }

  # The egress-only internet gateway exists only for IPv6-enabled VPCs with at
  # least one private or isolated IPv6 subnet (the module's derivation).
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      !contains([
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) : route.target_type
      ], "eigw") || vpc.egress_only_igw == true || (vpc.egress_only_igw != false && (vpc.enable_ipv6 || length(vpc.ipv6_cidrs) > 0) && length([for s in vpc.subnets : s if contains(["private", "isolated"], s.type) && s.ipv6_cidr_suffix != null]) > 0)
    ])
    error_message = "Routes of target_type eigw require egress_only_igw = true, or an IPv6 range on the VPC together with at least one private or isolated subnet carrying an ipv6_cidr_suffix — that is what creates the egress-only internet gateway."
  }

  # A local gateway target must name a declared local gateway of the same VPC;
  # an unknown name would resolve to nothing.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        route.target_type != "local_gateway" || contains([for o in vpc.outposts : o.local_gateway.name if o.local_gateway != null], route.target_name)
      ]
    ]))
    error_message = "Routes of target_type local_gateway must name the local_gateway of one of the same VPC's outposts entries."
  }

  # The network_firewall route target is the availability zone
  # whose firewall endpoint the route should use (the module's endpoint map is
  # keyed by AZ). Anything else would reach AWS as an invalid endpoint ID.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        route.target_type != "network_firewall" || can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+[a-z]$", route.target_name))
      ]
    ]))
    error_message = "Routes of target_type network_firewall must name an availability zone (e.g. eu-central-1a) as target_name — the firewall endpoint of that zone becomes the route target."
  }

  # AWS knows exactly these two gateway associations for a route table.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for g in vpc.gateway_route_tables :
        contains(["internet_gateway", "virtual_private_gateway"], g.gateway_type)
      ]
    ]))
    error_message = "Each gateway_route_tables gateway_type must be \"internet_gateway\" or \"virtual_private_gateway\"."
  }

  # The module keys the tables by name; a duplicate would silently collapse
  # two tables into one.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      length(distinct([for g in vpc.gateway_route_tables : g.name])) == length(vpc.gateway_route_tables)
    ])
    error_message = "Each gateway_route_tables name must be unique within its VPC."
  }

  # AWS associates at most one route table with a gateway; the second
  # association fails at apply — after the first one already exists.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      length(distinct([for g in vpc.gateway_route_tables : g.gateway_type])) == length(vpc.gateway_route_tables)
    ])
    error_message = "Each VPC may carry at most one gateway_route_tables entry per gateway_type — AWS accepts only one route table per gateway."
  }

  # An edge table on the internet gateway needs that gateway to exist, and it
  # exists only for VPCs with at least one public subnet.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      !contains([for g in vpc.gateway_route_tables : g.gateway_type], "internet_gateway") || length([for s in vpc.subnets : s if s.type == "public"]) > 0
    ])
    error_message = "gateway_route_tables of gateway_type internet_gateway require at least one public subnet in the same VPC — that is what creates the internet gateway."
  }

  # Validate appliance_mode_support values
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.tgw_attachment == null ? true :
      vpc.tgw_attachment.appliance_mode_support == null ||
      contains(["enable", "disable"], vpc.tgw_attachment.appliance_mode_support)
    ])
    error_message = "appliance_mode_support must be null, \"enable\", or \"disable\"."
  }

  # The attachment options take the same two values as appliance_mode_support.
  # An unknown value would be rejected by AWS only when the attachment is
  # applied — after the VPC and its subnets have already been created.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs :
      vpc.tgw_attachment == null ? [true] : [
        for option in [
          vpc.tgw_attachment.dns_support,
          vpc.tgw_attachment.ipv6_support,
          vpc.tgw_attachment.security_group_referencing_support,
        ] : option == null || contains(["enable", "disable"], option)
      ]
    ]))
    error_message = "tgw_attachment dns_support, ipv6_support, and security_group_referencing_support must each be null, \"enable\", or \"disable\"."
  }

  # IPv6 support on the attachment needs an IPv6 CIDR on the VPC. AWS accepts
  # the mismatch at plan time and fails the attachment at apply.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.tgw_attachment == null ? true :
      vpc.tgw_attachment.ipv6_support != "enable" || vpc.enable_ipv6
    ])
    error_message = "tgw_attachment ipv6_support can only be \"enable\" when the VPC sets enable_ipv6 = true."
  }

  # Every explicitly chosen attachment subnet must exist in the same VPC;
  # an unknown name would resolve to nothing and the attachment would silently
  # miss an availability zone.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs :
      vpc.tgw_attachment == null ? [true] : [
        for name in vpc.tgw_attachment.subnet_names :
        contains([for s in vpc.subnets : s.name], name)
      ]
    ]))
    error_message = "Each tgw_attachment subnet_names entry must name a subnet of the same VPC."
  }

  # Endpoint options attach to a gateway endpoint by its service name; an
  # entry whose key is not listed in gateway_endpoints would silently
  # configure nothing.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for svc, o in vpc.gateway_endpoint_options :
        contains(vpc.gateway_endpoints, svc)
      ]
    ]))
    error_message = "Each gateway_endpoint_options key must name an entry of gateway_endpoints in the same VPC."
  }

  # A named gateway endpoint policy must exist: an unknown name would
  # otherwise leave the endpoint without any policy — an open endpoint
  # instead of the intended restriction.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for svc, o in vpc.gateway_endpoint_options :
        o.policy_name == "" || contains([for p in var.endpoint_policies : p.name], o.policy_name)
      ]
    ]))
    error_message = "Each gateway_endpoint_options policy_name must reference the name of an entry in endpoint_policies."
  }

  # The per-endpoint security group replaces the module's default endpoint
  # security group; an unknown name would fail only when the plan resolves
  # the group's resource address.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for ep in vpc.interface_endpoints :
        ep.security_group == "" || contains([for g in vpc.security_groups : g.name], ep.security_group)
      ]
    ]))
    error_message = "Each interface_endpoints security_group must name an entry of security_groups in the same VPC."
  }

  # A full service name replaces the regional derivation; an empty string
  # would reach the provider and fail only at apply time.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : concat(
        [
          for ep in vpc.interface_endpoints :
          ep.service_name == null || ep.service_name != ""
        ],
        [
          for svc, o in vpc.gateway_endpoint_options :
          o.service_name == null || o.service_name != ""
        ]
      )
    ]))
    error_message = "A service_name on interface_endpoints or gateway_endpoint_options must not be empty — leave it null to keep the regional service name."
  }

  # The zone name override belongs to the central-endpoint pattern: without
  # central = true no hosted zone is created and the name would configure
  # nothing.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for ep in vpc.interface_endpoints :
        ep.hosted_zone_name == null || (ep.central && ep.hosted_zone_name != "")
      ]
    ]))
    error_message = "An interface_endpoints hosted_zone_name needs central = true and must not be empty."
  }

  # A named endpoint policy must exist: an unknown name would otherwise leave the
  # interface endpoint without any policy — an open endpoint instead of the
  # intended restriction.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for ep in vpc.interface_endpoints :
        ep.policy_name == "" || contains([for p in var.endpoint_policies : p.name], ep.policy_name)
      ]
    ]))
    error_message = "Each interface_endpoints policy_name must reference the name of an entry in endpoint_policies."
  }
  # Each NACL rule names its traffic through exactly one source form. Two
  # forms at once would be ambiguous, none at all would send AWS a rule
  # without a target — both rejected only at apply time.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for nacl in vpc.nacls : concat(
          [
            for rule in nacl.inbound :
            (rule.cidr_block != null ? 1 : 0) + (rule.ipv6_cidr_block != null ? 1 : 0) + (rule.source != null ? 1 : 0) == 1
          ],
          [
            for rule in nacl.outbound :
            (rule.cidr_block != null ? 1 : 0) + (rule.ipv6_cidr_block != null ? 1 : 0) + (rule.destination != null ? 1 : 0) == 1
          ]
        )
      ]
    ]))
    error_message = "Each NACL rule must set exactly one of cidr_block, ipv6_cidr_block or the subnet selector (source on inbound rules, destination on outbound rules)."
  }
  # A subnet selector resolves against this variable at plan time: the named
  # VPC entry and its subnet must exist — an unknown name would fail only
  # when the plan resolves the subnet's resource address.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for nacl in vpc.nacls : [
          for sel in concat(
            [for rule in nacl.inbound : rule.source],
            [for rule in nacl.outbound : rule.destination]
          ) :
          sel == null ? true : anytrue([
            for other in var.vpcs :
            other.name == sel.vpc && contains([for s in other.subnets : s.name], sel.subnet)
          ])
        ]
      ]
    ]))
    error_message = "Each NACL rule subnet selector must name a VPC entry of vpcs and a subnet of that VPC."
  }
  # The selector's account and region document where the referenced subnet
  # lives; a claim that contradicts the referenced VPC entry would resolve a
  # different subnet than the rule announces.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for nacl in vpc.nacls : [
          for sel in concat(
            [for rule in nacl.inbound : rule.source],
            [for rule in nacl.outbound : rule.destination]
          ) :
          sel == null ? true : alltrue([
            for other in var.vpcs :
            other.name == sel.vpc ? (sel.account == null || sel.account == other.account_name) && (sel.region == null || sel.region == other.region) : true
          ])
        ]
      ]
    ]))
    error_message = "A NACL subnet selector's account and region must match the referenced VPC entry's account_name and region."
  }
  # An IPv6 selector needs an IPv6 CIDR to resolve: the referenced subnet
  # must carry an ipv6_cidr_suffix in an IPv6-enabled VPC. AWS accepts the
  # mismatch at plan time and fails the rule at apply.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for nacl in vpc.nacls : [
          for sel in concat(
            [for rule in nacl.inbound : rule.source],
            [for rule in nacl.outbound : rule.destination]
          ) :
          sel == null ? true : (sel.ipv6 == false || anytrue([
            for other in var.vpcs :
            other.name == sel.vpc && (other.enable_ipv6 || length(other.ipv6_cidrs) > 0) && anytrue([for s in other.subnets : s.name == sel.subnet && s.ipv6_cidr_suffix != null])
          ]))
        ]
      ]
    ]))
    error_message = "A NACL subnet selector with ipv6 = true must reference a subnet that carries an ipv6_cidr_suffix in a VPC with an IPv6 range (enable_ipv6 = true or an ipv6_cidrs entry)."
  }
  # ICMP type and code belong to the ICMP protocols and the ICMP protocols
  # need them: a mismatch either configures nothing or fails at apply time.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for nacl in vpc.nacls : [
          for pair in concat(
            [for rule in nacl.inbound : { protocol = rule.protocol, icmp = rule.icmp }],
            [for rule in nacl.outbound : { protocol = rule.protocol, icmp = rule.icmp }]
          ) :
          contains(["1", "icmp", "58", "icmpv6"], lower(pair.protocol)) ? pair.icmp != null : pair.icmp == null
        ]
      ]
    ]))
    error_message = "A NACL rule icmp block requires protocol \"1\"/\"icmp\" or \"58\"/\"icmpv6\", and those protocols require the icmp block."
  }
  # ICMP types and codes live in -1..255 (-1 = all). AWS rejects values
  # outside that range at apply time — after the NACL has been created.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for nacl in vpc.nacls : [
          for icmp in concat(
            [for rule in nacl.inbound : rule.icmp],
            [for rule in nacl.outbound : rule.icmp]
          ) :
          icmp == null ? true : (icmp.type >= -1 && icmp.type <= 255 && icmp.code >= -1 && icmp.code <= 255)
        ]
      ]
    ]))
    error_message = "A NACL rule icmp type and code must lie between -1 and 255."
  }
  # TCP and UDP rules filter by port, so the range must be present; other
  # protocols may leave it unset.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for nacl in vpc.nacls : [
          for pair in concat(
            [for rule in nacl.inbound : { protocol = rule.protocol, from_port = rule.from_port, to_port = rule.to_port }],
            [for rule in nacl.outbound : { protocol = rule.protocol, from_port = rule.from_port, to_port = rule.to_port }]
          ) :
          contains(["6", "tcp", "17", "udp"], lower(pair.protocol)) ? pair.from_port != null && pair.to_port != null : true
        ]
      ]
    ]))
    error_message = "A NACL rule with protocol tcp/6 or udp/17 must set from_port and to_port."
  }
  # A security group description is immutable in AWS (a change replaces the
  # group) and limited to 255 characters; an empty string is rejected by the
  # API. null keeps the module's derived description.
  validation {
    condition = alltrue([
      for vpc in var.vpcs : alltrue([
        for sg in vpc.security_groups :
        sg.description == null ? true : (length(sg.description) > 0 && length(sg.description) <= 255)
      ])
    ])
    error_message = "A security group description must be 1-255 characters long — leave it null to keep the derived description."
  }
  # A rule declares its port/protocol exactly once: either the explicit
  # triple or named types. Without types the explicit form must be complete;
  # AWS rejects a portless tcp rule only at apply time.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in concat(sg.ingress, sg.egress) :
          length(rule.types) == 0 ? rule.protocol != null && rule.from_port != null && rule.to_port != null : true
        ]
      ]
    ]))
    error_message = "A security group rule without types must set protocol, from_port and to_port."
  }
  # The named types are a fixed set; an unknown name would silently expand
  # to nothing.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in concat(sg.ingress, sg.egress) : [
            for t in rule.types :
            contains(["RDP", "SSH", "HTTP", "HTTPS", "MSSQL", "MYSQL/AURORA", "REDSHIFT", "POSTGRESQL", "ORACLE-RDS", "TCP", "UDP", "ICMP", "ALL"], t)
          ]
        ]
      ]
    ]))
    error_message = "Each security group rule type must be one of RDP, SSH, HTTP, HTTPS, MSSQL, MYSQL/AURORA, REDSHIFT, POSTGRESQL, ORACLE-RDS, TCP, UDP, ICMP, ALL."
  }
  # Typed rules carry their protocol in the type: TCP, UDP and ICMP take the
  # rule's port pair, all other types bring their ports themselves; TCP/UDP
  # and ICMP describe incompatible port semantics in one rule.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in concat(sg.ingress, sg.egress) :
          length(rule.types) == 0 ? true : (
            rule.protocol == null
            && (length(setintersection(toset(rule.types), toset(["TCP", "UDP", "ICMP"]))) > 0 ? rule.from_port != null && rule.to_port != null : rule.from_port == null && rule.to_port == null)
            && (contains(rule.types, "ICMP") ? length(setintersection(toset(rule.types), toset(["TCP", "UDP"]))) == 0 : true)
          )
        ]
      ]
    ]))
    error_message = "A security group rule with types must leave protocol null, must set from_port/to_port exactly when a TCP, UDP or ICMP type is listed, and must not mix ICMP with TCP/UDP types."
  }
  # TCP and UDP ports live in 0..65535 with an ordered range. AWS rejects
  # the violation at apply time — after the group has been created.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in concat(sg.ingress, sg.egress) :
          (contains(["tcp", "6", "udp", "17"], lower(coalesce(rule.protocol, "none"))) || length(setintersection(toset(rule.types), toset(["TCP", "UDP"]))) > 0) == false ? true : (
            (rule.from_port == null || rule.to_port == null) ? true : (rule.from_port >= 0 && rule.from_port <= 65535 && rule.to_port >= 0 && rule.to_port <= 65535 && rule.from_port <= rule.to_port)
          )
        ]
      ]
    ]))
    error_message = "A security group rule filtering TCP or UDP must keep from_port and to_port between 0 and 65535 with from_port <= to_port."
  }
  # An ingress rule that opens every port to the whole internet — the
  # "security group open to the world on all ports" state of the security
  # preflight. Every port: ALL protocols, or TCP/UDP with the port range
  # 0-65535 (or 1-65535). The whole internet: any source CIDR with a prefix
  # length of 0 or 1 — 0.0.0.0/0, ::/0, and each half of the address space
  # (0.0.0.0/1, 128.0.0.0/1), since the two halves together are the world.
  # This is an operator-error gate, not an adversary boundary. It is not a
  # ban: it needs a second word on the rule itself; a world-open rule for one
  # protocol/port (a public HTTPS endpoint) stays allowed without one.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in sg.ingress :
          rule.acknowledge_world_open_all_protocols || !(
            (
              contains(rule.types, "ALL") || contains(["-1", "all"], lower(coalesce(rule.protocol, "none")))
              || (
                (length(setintersection(toset(rule.types), toset(["TCP", "UDP"]))) > 0 || contains(["tcp", "6", "udp", "17"], lower(coalesce(rule.protocol, "none"))))
                && contains([0, 1], coalesce(rule.from_port, -1)) && coalesce(rule.to_port, -1) == 65535
              )
            )
            && anytrue([for cidr in concat(rule.cidr_blocks, rule.ipv6_cidr_blocks) : try(tonumber(split("/", cidr)[1]) <= 1, false)])
          )
        ]
      ]
    ]))
    error_message = format(
      "vpcs: %s. An ingress rule for all protocols, or for TCP/UDP ports 0-65535, from 0.0.0.0/0, ::/0 or a half of the address space (prefix /1) opens every port of the group to the internet: narrow the rule to the protocol and ports it needs or to narrower sources, or set acknowledge_world_open_all_protocols = true on the rule.",
      join("; ", flatten([
        for vpc in var.vpcs : [
          for sg in vpc.security_groups : [
            for idx, rule in sg.ingress :
            format("vpc %q security group %q ingress rule %d opens every port to the world", vpc.name, sg.name, idx)
            if !rule.acknowledge_world_open_all_protocols && (
              contains(rule.types, "ALL") || contains(["-1", "all"], lower(coalesce(rule.protocol, "none")))
              || (
                (length(setintersection(toset(rule.types), toset(["TCP", "UDP"]))) > 0 || contains(["tcp", "6", "udp", "17"], lower(coalesce(rule.protocol, "none"))))
                && contains([0, 1], coalesce(rule.from_port, -1)) && coalesce(rule.to_port, -1) == 65535
              )
            ) && anytrue([for cidr in concat(rule.cidr_blocks, rule.ipv6_cidr_blocks) : try(tonumber(split("/", cidr)[1]) <= 1, false)])
          ]
        ]
      ]))
    )
  }
  # A rule without any source configures nothing — no resource would be
  # created and the rule would silently not exist.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in concat(sg.ingress, sg.egress) :
          length(rule.cidr_blocks) > 0 || length(rule.ipv6_cidr_blocks) > 0 || length(rule.source_subnets) > 0 || rule.source_security_group != "" || rule.prefix_list_id != ""
        ]
      ]
    ]))
    error_message = "Each security group rule must carry at least one source: cidr_blocks, ipv6_cidr_blocks, source_subnets, source_security_group or prefix_list_id."
  }
  # A rule that combines source_security_group with prefix_list_id and carries
  # no CIDR or subnet source creates only the security-group half: the
  # CIDR-based resource skips it (no CIDR source) and the prefix-list-only
  # resource excludes rules with a security group reference, so the prefix
  # list half would silently not exist — the same failure class the "at least
  # one source" validation above rejects. With a CIDR or subnet source present
  # the prefix list rides along on the CIDR-based rule, so that combination
  # stays valid.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in concat(sg.ingress, sg.egress) :
          !(rule.source_security_group != "" && rule.prefix_list_id != "" && length(rule.cidr_blocks) == 0 && length(rule.ipv6_cidr_blocks) == 0 && length(rule.source_subnets) == 0)
        ]
      ]
    ]))
    error_message = "A security group rule must not combine source_security_group and prefix_list_id as its only sources — the prefix list half would silently not exist. Configure two separate rules: one with source_security_group and one with prefix_list_id."
  }
  # A subnet selector resolves against this variable at plan time: the named
  # VPC entry and each of its subnets must exist, and an empty subnet list
  # would configure nothing.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for sel in flatten([for rule in concat(sg.ingress, sg.egress) : rule.source_subnets]) :
          length(sel.subnets) > 0 && alltrue([
            for sn in sel.subnets :
            anytrue([for other in var.vpcs : other.name == sel.vpc && contains([for s in other.subnets : s.name], sn)])
          ])
        ]
      ]
    ]))
    error_message = "Each security group source_subnets entry must name a VPC entry of vpcs and at least one subnet of that VPC."
  }
  # The selector's account documents where the referenced subnets live; a
  # claim that contradicts the referenced VPC entry would resolve different
  # subnets than the rule announces.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for sel in flatten([for rule in concat(sg.ingress, sg.egress) : rule.source_subnets]) :
          alltrue([
            for other in var.vpcs :
            other.name == sel.vpc ? (sel.account == null || sel.account == other.account_name) : true
          ])
        ]
      ]
    ]))
    error_message = "A security group source_subnets account must match the referenced VPC entry's account_name."
  }
  # An IPv6 selector needs IPv6 CIDRs to resolve: every referenced subnet
  # must carry an ipv6_cidr_suffix in an IPv6-enabled VPC. AWS accepts the
  # mismatch at plan time and fails the rule at apply.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for sel in flatten([for rule in concat(sg.ingress, sg.egress) : rule.source_subnets]) :
          sel.ipv6 == false || anytrue([
            for other in var.vpcs :
            other.name == sel.vpc && (other.enable_ipv6 || length(other.ipv6_cidrs) > 0) && alltrue([for sn in sel.subnets : anytrue([for s in other.subnets : s.name == sn && s.ipv6_cidr_suffix != null])])
          ])
        ]
      ]
    ]))
    error_message = "A security group source_subnets entry with ipv6 = true must reference subnets that carry an ipv6_cidr_suffix in a VPC with an IPv6 range (enable_ipv6 = true or an ipv6_cidrs entry)."
  }
  # A security group reference resolves within the same VPC; an unknown name
  # would fail only when the plan resolves the group's resource address.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for sg in vpc.security_groups : [
          for rule in concat(sg.ingress, sg.egress) :
          rule.source_security_group == "" || contains([for g in vpc.security_groups : g.name], rule.source_security_group)
        ]
      ]
    ]))
    error_message = "Each security group rule source_security_group must name an entry of security_groups in the same VPC."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone. AWS rejects a tag
  # that breaks one of these rules at apply time — after the resource has
  # already been created.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for tag_map in concat(
          [vpc.tags],
          [for s in vpc.subnets : s.tags],
          [for s in vpc.subnets : s.route_table_tags],
          [for s in vpc.subnets : s.nat_gateway_tags],
          [for n in vpc.nacls : n.tags],
          [for g in vpc.security_groups : g.tags],
          [for ep in vpc.interface_endpoints : ep.tags],
          [for g in vpc.gateway_route_tables : g.tags],
          [vpc.tgw_attachment == null ? {} : vpc.tgw_attachment.tags]
          ) : [
          for key, value in tag_map :
          length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
        ]
      ]
    ]))
    error_message = "Each tags key in vpcs must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  # Each share target must resolve to a RAM principal at plan time: an account
  # name from account_ids, a 12-digit account ID, an organizational unit ARN or
  # the organization ARN. Anything else would only fail when RAM processes the
  # principal association — after the share already exists.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets : [
          for target in s.share_targets :
          contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
        ]
      ]
    ]))
    error_message = "Each vpcs subnet share_targets entry must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }

  # EC2 knows exactly these two tenancy modes for a VPC; an unknown value
  # fails only when the VPC is applied.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.instance_tenancy == null || contains(["default", "dedicated"], vpc.instance_tenancy)
    ])
    error_message = "Each vpcs instance_tenancy must be null, \"default\", or \"dedicated\"."
  }

  # An egress-only internet gateway routes IPv6 only. On a VPC without an IPv6
  # range it would be created, cost nothing and carry no traffic — and the
  # configuration would read as if IPv6 egress were in place.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.egress_only_igw != true || vpc.enable_ipv6 || length(vpc.ipv6_cidrs) > 0
    ])
    error_message = "egress_only_igw = true requires an IPv6 range on the VPC: enable_ipv6 = true or an ipv6_cidrs entry."
  }

  # The module routes ::/0 of every private and isolated IPv6 subnet to the
  # egress-only internet gateway. Suppressing the gateway while such a subnet
  # exists would leave that route pointing at a resource that is never created,
  # and the plan would fail on the resource address instead of on the switch.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.egress_only_igw != false || length([
        for s in vpc.subnets : s
        if contains(["private", "isolated"], s.type) && s.ipv6_cidr_suffix != null
      ]) == 0
    ])
    error_message = "egress_only_igw = false must not be combined with a private or isolated subnet that carries an ipv6_cidr_suffix — the module routes ::/0 of those subnets to the egress-only internet gateway."
  }

  # Each IPv6 range comes from exactly one source. Two sources in one entry
  # would leave the winner to the provider, none would associate nothing —
  # a range on its own (cidr_block) does not say where it comes from.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for source in vpc.ipv6_cidrs :
        length([
          for present in [
            source.amazon_provided == true,
            source.byoip_pool_id != null,
            source.ipam_pool_name != null,
          ] : present if present
        ]) == 1
      ]
    ]))
    error_message = "Each vpcs ipv6_cidrs entry must name exactly one source: amazon_provided = true, byoip_pool_id, or ipam_pool_name."
  }

  # The Amazon pool hands out a /56 of its own choosing — a range or a prefix
  # length next to it would be silently dropped.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for source in vpc.ipv6_cidrs :
        source.amazon_provided != true || (source.cidr_block == null && source.netmask_length == null)
      ]
    ]))
    error_message = "A vpcs ipv6_cidrs entry with amazon_provided = true must not set cidr_block or netmask_length — Amazon assigns a /56 of its own choosing."
  }

  # A prefix length is a request against a pool; only IPAM answers it. A BYOIP
  # range is named through cidr_block.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for source in vpc.ipv6_cidrs :
        source.netmask_length == null || source.ipam_pool_name != null
      ]
    ]))
    error_message = "A vpcs ipv6_cidrs netmask_length requires ipam_pool_name — a BYOIP range is named through cidr_block."
  }

  # AWS associates IPv6 ranges between /44 and /60 in steps of four with a VPC
  # and rejects everything else at apply time.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for source in vpc.ipv6_cidrs :
        source.netmask_length == null || (
          source.netmask_length >= 44 && source.netmask_length <= 60 && source.netmask_length % 4 == 0
        )
      ]
    ]))
    error_message = "Each vpcs ipv6_cidrs netmask_length must be between 44 and 60 in steps of four (44, 48, 52, 56, 60)."
  }

  # An unknown pool name would resolve to nothing and the association would
  # fail on the lookup instead of on the name.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for source in vpc.ipv6_cidrs :
        source.ipam_pool_name == null || contains([for pool in var.ipam.pools : pool.name], source.ipam_pool_name)
      ]
    ]))
    error_message = "Each vpcs ipv6_cidrs ipam_pool_name must name an entry of ipam.pools."
  }

  # An IPv6 range comes from an IPv6 pool. IPAM rejects the allocation from an
  # IPv4 pool, and it does so only when the association is applied.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for source in vpc.ipv6_cidrs :
        source.ipam_pool_name == null || anytrue([
          for pool in var.ipam.pools :
          pool.address_family == "ipv6" if pool.name == source.ipam_pool_name
        ])
      ]
    ]))
    error_message = "Each vpcs ipv6_cidrs ipam_pool_name must name an ipam.pools entry with address_family = \"ipv6\"."
  }

  # An IPv6 range of a VPC carries a prefix between /44 and /60; the module
  # derives each subnet's /64 from it.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for source in vpc.ipv6_cidrs :
        source.cidr_block == null || can(regex("^[0-9A-Fa-f:]+/(44|48|52|56|60)$", source.cidr_block))
      ]
    ]))
    error_message = "Each vpcs ipv6_cidrs cidr_block must be an IPv6 CIDR with a prefix of 44, 48, 52, 56, or 60 (for example 2001:db8::/56)."
  }

  # A VPC takes exactly one Amazon-provided /56, and enable_ipv6 already
  # requests it. Both forms at once would plan two associations for the one
  # range AWS grants.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      length([for source in vpc.ipv6_cidrs : source if source.amazon_provided == true]) + (vpc.enable_ipv6 ? 1 : 0) <= 1
    ])
    error_message = "A VPC requests the Amazon-provided IPv6 range once: either enable_ipv6 = true or a single ipv6_cidrs entry with amazon_provided = true."
  }

  # The Amazon side of a virtual private gateway takes a private ASN: the
  # 16-bit range 64512-65534 or the 32-bit range 4200000000-4294967294. AWS
  # rejects anything else when the gateway is created.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.virtual_private_gateway == null || vpc.virtual_private_gateway.asn == null || (
        (vpc.virtual_private_gateway.asn >= 64512 && vpc.virtual_private_gateway.asn <= 65534)
        || (vpc.virtual_private_gateway.asn >= 4200000000 && vpc.virtual_private_gateway.asn <= 4294967294)
      )
    ])
    error_message = "Each vpcs virtual_private_gateway asn must be in a private ASN range: 64512-65534 or 4200000000-4294967294."
  }

  # A private NAT gateway carries no public address, so an address reference
  # next to it would be dropped without a trace.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.nat_gateway_private != true || (s.nat_gateway_allocation_id == null && s.nat_gateway_eip_name == null)
      ]
    ]))
    error_message = "A subnet with nat_gateway_private = true must not set nat_gateway_allocation_id or nat_gateway_eip_name — a private NAT gateway has no public address."
  }

  # One address per NAT gateway: a raw allocation ID or an entry of
  # elastic_ips. Both at once would leave the winner implicit.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.nat_gateway_allocation_id == null || s.nat_gateway_eip_name == null
      ]
    ]))
    error_message = "Each subnet may set nat_gateway_allocation_id or nat_gateway_eip_name, not both."
  }

  # The allocation ID reaches the NAT gateway unchanged; a malformed one fails
  # at apply, after the subnet already exists.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.nat_gateway_allocation_id == null || can(regex("^eipalloc-[0-9a-f]{8,17}$", s.nat_gateway_allocation_id))
      ]
    ]))
    error_message = "Each subnet nat_gateway_allocation_id must be an Elastic IP allocation ID (eipalloc-...)."
  }

  # An unknown elastic_ips name would resolve to nothing and the NAT gateway
  # would fail on the lookup instead of on the name.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.nat_gateway_eip_name == null || contains([for eip in var.elastic_ips : eip.name], s.nat_gateway_eip_name)
      ]
    ]))
    error_message = "Each subnet nat_gateway_eip_name must name an entry of var.elastic_ips."
  }

  # A NAT gateway detail without nat_gateway = true reads as if it were in
  # effect while the module creates no gateway at all for that subnet.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.nat_gateway || (
          s.nat_gateway_name == null
          && (s.nat_gateway_private != true)
          && s.nat_gateway_allocation_id == null
          && s.nat_gateway_eip_name == null
        )
      ]
    ]))
    error_message = "nat_gateway_name, nat_gateway_private, nat_gateway_allocation_id and nat_gateway_eip_name require nat_gateway = true on the same subnet."
  }

  # A public NAT gateway needs a public subnet to reach the internet gateway
  # from, a private one belongs in a private subnet. Without this check the
  # module would drop the gateway of an isolated or private subnet silently.
  validation {
    condition = alltrue(flatten([
      for vpc in var.vpcs : [
        for s in vpc.subnets :
        s.nat_gateway == false || (s.nat_gateway_private ? s.type == "private" : s.type == "public")
      ]
    ]))
    error_message = "A subnet with nat_gateway = true must be of type \"public\", or of type \"private\" together with nat_gateway_private = true."
  }

  # The module keys the gateway by its subnet but tags it by name; a duplicate
  # name would produce two gateways that cannot be told apart.
  validation {
    condition = length([
      for name in flatten([
        for vpc in var.vpcs : [for s in vpc.subnets : s.nat_gateway_name if s.nat_gateway_name != null]
      ]) : name
      ]) == length(distinct(flatten([
        for vpc in var.vpcs : [for s in vpc.subnets : s.nat_gateway_name if s.nat_gateway_name != null]
    ])))
    error_message = "Each nat_gateway_name must be unique across var.vpcs — the name is what tells two NAT gateways apart."
  }

  # --- DNS behaviour and central endpoint consumption ---
  # Hostnames need resolution: AWS rejects enable_dns_hostnames = true on a VPC
  # with enable_dns_support = false, and the plan would carry the combination
  # until the apply.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.enable_dns_support || vpc.enable_dns_hostnames == false
    ])
    error_message = "A vpcs entry with enable_dns_hostnames = true needs enable_dns_support = true — AWS rejects hostnames without resolution."
  }

  # The private hosted zone of a central endpoint only resolves in a VPC whose
  # resolver is on. Without support the association would exist and change
  # nothing.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.use_central_endpoints == false || vpc.enable_dns_support
    ])
    error_message = "A vpcs entry with use_central_endpoints = true needs enable_dns_support = true — without the resolver the private hosted zone of a central endpoint answers nothing."
  }

  # Without a central endpoint there is no zone to associate, so the switch
  # would be set and do nothing.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.use_central_endpoints == false || anytrue(flatten([
        for other in var.vpcs : [
          for ep in other.interface_endpoints : ep.central
        ]
      ]))
    ])
    error_message = "use_central_endpoints requires at least one interface_endpoints entry with central = true somewhere in var.vpcs — that entry is what creates the private hosted zone the VPC is associated with."
  }

  # A VPC that only declares central endpoints itself already carries their
  # zones through the endpoint; the switch would produce no association.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.use_central_endpoints == false || anytrue(flatten([
        for other in var.vpcs : [
          for ep in other.interface_endpoints : ep.central if other.name != vpc.name
        ]
      ]))
    ])
    error_message = "A vpcs entry with use_central_endpoints = true needs a central interface endpoint in another VPC — the endpoint's own VPC is already associated with its zone."
  }

  # --- Flow log details per VPC ---
  # The same checks var.vpc_flow_logs_default carries for the three destination
  # details, so that a per-VPC block and the global default are held to one
  # standard.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.flow_logs == null || contains(["s3", "cloudwatch", "both"], vpc.flow_logs.destination)
    ])
    error_message = "Each vpcs flow_logs destination must be s3, cloudwatch or both."
  }

  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.flow_logs == null || contains([
        1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096,
        1827, 2192, 2557, 2922, 3288, 3653,
      ], vpc.flow_logs.cloudwatch_retention_days)
    ])
    error_message = "Each vpcs flow_logs cloudwatch_retention_days must be one of the retention values CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, or 3653)."
  }

  # A leading or trailing slash would produce an empty path segment in the
  # bucket, and the flow log would be filed under a key nobody looks at.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.flow_logs == null || vpc.flow_logs.s3_log_path == null || (can(regex("^[0-9A-Za-z!_.*'()/-]+$", vpc.flow_logs.s3_log_path)) && !startswith(vpc.flow_logs.s3_log_path, "/") && !endswith(vpc.flow_logs.s3_log_path, "/"))
    ])
    error_message = "Each vpcs flow_logs s3_log_path must be a non-empty S3 key prefix without leading or trailing slash."
  }

  # The path only reaches a flow log that writes to S3.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.flow_logs == null || vpc.flow_logs.s3_log_path == null || contains(["s3", "both"], vpc.flow_logs.destination)
    ])
    error_message = "Each vpcs flow_logs s3_log_path requires destination s3 or both — a CloudWatch-only flow log writes no S3 objects."
  }

  # Two VPCs writing to the same prefix interleave their objects, and the
  # partition of a flow log query would then span both networks.
  validation {
    condition = length(distinct([
      for vpc in var.vpcs : vpc.flow_logs.s3_log_path
      if vpc.flow_logs != null && vpc.flow_logs.s3_log_path != null
      ])) == length([
      for vpc in var.vpcs : vpc.flow_logs.s3_log_path
      if vpc.flow_logs != null && vpc.flow_logs.s3_log_path != null
    ])
    error_message = "Each vpcs flow_logs s3_log_path must be unique across var.vpcs — two VPCs sharing a prefix interleave their flow log objects."
  }
}

variable "transit_gateway" {
  description = "Transit Gateway configuration with route tables and peering"
  type = object({
    enabled      = optional(bool, false)
    amazon_asn   = optional(number, 64512)
    route_tables = optional(list(string), [])
    # Gateway options, each "enable" or "disable". dns_support defaults to
    # "enable" and the two default route table switches to "disable"; the
    # remaining three default to null, which leaves the AWS
    # default in place (ECMP enabled, multicast and security group referencing
    # disabled).
    dns_support                        = optional(string, "enable")
    vpn_ecmp_support                   = optional(string, null)
    multicast_support                  = optional(string, null)
    security_group_referencing_support = optional(string, null)
    default_route_table_association    = optional(string, "disable")
    default_route_table_propagation    = optional(string, "disable")
    # IPv4 and IPv6 CIDR blocks assigned to the Transit Gateway (for Connect
    # peers and private VPN outer addresses). Empty writes nothing.
    cidr_blocks = optional(list(string), [])
    # Free-form tags for the Transit Gateway itself.
    tags = optional(map(string), {})
    # Free-form tags per route table, keyed by the route table name from
    # route_tables. route_tables stays a list of names, so the tags of a route
    # table are addressed by that name instead of turning the list into objects.
    route_table_tags = optional(map(map(string)), {})
    # Whether attachments from RAM-shared accounts are accepted automatically.
    # "enable" (default) keeps automated spoke onboarding working; the tradeoff
    # is that every organization account can attach a VPC to the hub without a
    # manual acceptance step. "disable" adds that control step, but attachment
    # resources of other accounts then wait in pendingAcceptance until someone
    # accepts them.
    auto_accept_shared_attachments = optional(string, "enable")
    peering = optional(list(object({
      peer_region             = string
      peer_transit_gateway_id = string
      # Route table of this gateway the peering attachment is associated with:
      # the requester side of the peering. An attachment carries one
      # association per gateway it spans, so this one is the association of
      # the gateway the module owns.
      route_table_name = string
      auto_accept      = optional(bool, false) # auto-accept peering attachment
      tags             = optional(map(string), {})
      # Accepter side of the peering. account names the account that owns the
      # peer gateway — an account name from account_ids or a raw account ID;
      # null leaves the requester account in place, which is what AWS assumes
      # for a peering inside one account. apply_tags_from_requester copies the
      # tags of this entry onto the accepter attachment, tags adds
      # accepter-only tags on top of them. Both need auto_accept = true,
      # because without it this module creates no accepter attachment to tag.
      accepter = optional(object({
        account                   = optional(string, null)
        apply_tags_from_requester = optional(bool, false)
        tags                      = optional(map(string), {})
      }), null)
    })), [])
    # Peering attachments this gateway accepts, the counterpart of peering:
    # there the module requests the peering, here it accepts one that another
    # account or region requested. transit_gateway_attachment_id is the
    # attachment of that request — the tgw_peering_attachment_ids output of the
    # requesting module instance carries it. route_table_name associates the
    # accepted attachment with a route table of this gateway; null leaves the
    # attachment unassociated, which is the state right after acceptance.
    peering_accepters = optional(list(object({
      name                          = string
      transit_gateway_attachment_id = string
      route_table_name              = optional(string, null)
      tags                          = optional(map(string), {})
    })), [])
    # Static routes for TGW route tables. The destination is a CIDR block or
    # a named managed prefix list (exactly one of the two); the next hop is a
    # named attachment of the given type, or a blackhole.
    static_routes = optional(list(object({
      route_table_name             = string
      destination_cidr_block       = optional(string, null)
      destination_prefix_list_name = optional(string, null)
      attachment_name              = optional(string, "")
      # "vpc" (default), "vpn" (customer gateway name), "dx-gateway"
      # (DX gateway name), or "peering" (peering key
      # "<peer_region>-<peer_transit_gateway_id>").
      attachment_type = optional(string, "vpc")
      blackhole       = optional(bool, false)
    })), [])
    # share_targets: RAM sharing targets — account names from account_ids,
    # raw account IDs, organizational unit ARNs or the organization ARN.
    # Unlike deployment_targets (cross-account deployment scope for Terragrunt per-account stacks),
    # share_targets controls which principals receive RAM resource shares for the Transit Gateway.
    share_targets = optional(list(string), [])
    # TGW route table propagations
    route_table_propagations = optional(list(object({
      route_table_name = string
      attachment_name  = string
      attachment_type  = optional(string, "vpc") # "vpc" or "peering"
    })), [])
  })
  default = {}

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway.auto_accept_shared_attachments)
    error_message = "transit_gateway.auto_accept_shared_attachments must be \"enable\" or \"disable\"."
  }

  # 64512-65534 is the private ASN range for a TGW; a public ASN here is a
  # routing mistake that AWS accepts and the network then pays for.
  validation {
    condition = (
      try(var.transit_gateway.amazon_asn, 64512) >= 64512
      && try(var.transit_gateway.amazon_asn, 64512) <= 65534
    )
    error_message = "transit_gateway.amazon_asn must be in the private ASN range 64512-65534."
  }

  validation {
    condition     = length(distinct(try(var.transit_gateway.route_tables, []))) == length(try(var.transit_gateway.route_tables, []))
    error_message = "transit_gateway.route_tables must not contain duplicate names — the module keys its route tables by name."
  }

  # Every name-based reference must point at a declared route table, otherwise
  # the reference resolves to nothing and the route is silently missing.
  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      contains(try(var.transit_gateway.route_tables, []), route.route_table_name)
    ])
    error_message = "Each transit_gateway.static_routes route_table_name must name one of transit_gateway.route_tables."
  }

  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      route.destination_cidr_block == null || can(cidrhost(route.destination_cidr_block, 0))
    ])
    error_message = "Each transit_gateway.static_routes destination_cidr_block must be a valid CIDR block."
  }

  # A route needs exactly one destination. Both set would be two routes in one
  # entry; neither set routes nothing.
  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      (route.destination_cidr_block == null) != (route.destination_prefix_list_name == null)
    ])
    error_message = "Each transit_gateway.static_routes entry must set exactly one of destination_cidr_block or destination_prefix_list_name."
  }

  # A named prefix list destination must exist in var.prefix_lists.
  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      route.destination_prefix_list_name == null || contains([for pl in var.prefix_lists : pl.name], route.destination_prefix_list_name)
    ])
    error_message = "Each transit_gateway.static_routes destination_prefix_list_name must name an entry of var.prefix_lists."
  }

  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      contains(["vpc", "vpn", "dx-gateway", "peering"], route.attachment_type)
    ])
    error_message = "Each transit_gateway.static_routes attachment_type must be vpc, vpn, dx-gateway, or peering."
  }

  # A route that is no blackhole needs a next hop.
  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      route.blackhole || route.attachment_name != ""
    ])
    error_message = "Each transit_gateway.static_routes entry must name an attachment_name unless blackhole = true."
  }

  # Every typed attachment reference must resolve against the collection it
  # names: a VPC with tgw_attachment, a customer gateway, a DX gateway, or a
  # peering key. An unknown name would fail only when the route is planned
  # against the missing resource.
  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      route.blackhole || route.attachment_type != "vpn" || contains([for cgw in var.customer_gateways : cgw.name], route.attachment_name)
    ])
    error_message = "Each transit_gateway.static_routes entry with attachment_type vpn must name an entry of var.customer_gateways."
  }

  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      route.blackhole || route.attachment_type != "dx-gateway" || contains([for dxg in var.dx_gateways : dxg.name], route.attachment_name)
    ])
    error_message = "Each transit_gateway.static_routes entry with attachment_type dx-gateway must name an entry of var.dx_gateways."
  }

  validation {
    condition = alltrue([
      for route in try(var.transit_gateway.static_routes, []) :
      route.blackhole || route.attachment_type != "peering" || contains([
        for p in try(var.transit_gateway.peering, []) : "${p.peer_region}-${p.peer_transit_gateway_id}"
      ], route.attachment_name)
    ])
    error_message = "Each transit_gateway.static_routes entry with attachment_type peering must name a peering key \"<peer_region>-<peer_transit_gateway_id>\" of transit_gateway.peering."
  }

  # The gateway options take the same two values throughout; an unknown value
  # is rejected by AWS only when the gateway is modified.
  validation {
    condition = alltrue([
      for option in [
        var.transit_gateway.dns_support,
        var.transit_gateway.vpn_ecmp_support,
        var.transit_gateway.multicast_support,
        var.transit_gateway.security_group_referencing_support,
        var.transit_gateway.default_route_table_association,
        var.transit_gateway.default_route_table_propagation,
      ] : option == null || contains(["enable", "disable"], option)
    ])
    error_message = "transit_gateway dns_support, vpn_ecmp_support, multicast_support, security_group_referencing_support, default_route_table_association, and default_route_table_propagation must each be null, \"enable\", or \"disable\"."
  }

  validation {
    condition = alltrue([
      for cidr in try(var.transit_gateway.cidr_blocks, []) :
      can(cidrhost(cidr, 0))
    ])
    error_message = "Each transit_gateway.cidr_blocks entry must be a valid IPv4 or IPv6 CIDR block."
  }

  # Every route table named by the Direct Connect gateway wiring must exist on
  # the module's Transit Gateway; an unknown name would resolve to nothing and
  # the wiring would be silently missing. The check lives on this variable
  # because it already reads var.dx_gateways — the reverse direction would be
  # a reference cycle between the two validations.
  validation {
    condition = alltrue(flatten([
      for dxg in var.dx_gateways : [
        for name in concat(dxg.route_table_associations, dxg.route_table_propagations) :
        contains(try(var.transit_gateway.route_tables, []), name)
      ]
    ]))
    error_message = "Each dx_gateways route_table_associations and route_table_propagations entry must name one of transit_gateway.route_tables."
  }

  # Four collections reference aws_ec2_transit_gateway.this[0] — Direct
  # Connect gateway associations, TGW-terminated VPN connections, Connect
  # attachments and routes of target_type "tgw". Configuring any of them with
  # the Transit Gateway off would abort the plan with "Invalid index" and no
  # hint at the switch, so these checks name the switch instead. The four checks live on this variable
  # for the same cycle reason as the wiring check above.
  validation {
    condition     = var.transit_gateway.enabled || length(var.dx_gateways) == 0
    error_message = "dx_gateways requires transit_gateway.enabled = true — each Direct Connect gateway is associated with the Transit Gateway, which is not created otherwise."
  }

  validation {
    condition = var.transit_gateway.enabled || alltrue([
      for cgw in var.customer_gateways : cgw.vpc_name != null
    ])
    error_message = "customer_gateways entries without vpc_name terminate on the Transit Gateway and require transit_gateway.enabled = true — connections with vpc_name stay available while it is off."
  }

  validation {
    condition     = var.transit_gateway.enabled || length(var.tgw_connect_attachments) == 0
    error_message = "tgw_connect_attachments requires transit_gateway.enabled = true — the Transit Gateway they attach to is not created otherwise."
  }

  validation {
    condition = var.transit_gateway.enabled || alltrue(flatten([
      for vpc in var.vpcs : [
        for route in concat(
          flatten([for s in vpc.subnets : s.custom_routes]),
          flatten([for g in vpc.gateway_route_tables : g.routes])
        ) :
        route.target_type != "tgw"
      ]
    ]))
    error_message = "Routes of target_type tgw require transit_gateway.enabled = true — the Transit Gateway they target is not created otherwise."
  }

  validation {
    condition = alltrue([
      for prop in try(var.transit_gateway.route_table_propagations, []) :
      contains(["vpc", "peering"], try(prop.attachment_type, "vpc"))
    ])
    error_message = "Each transit_gateway.route_table_propagations attachment_type must be vpc or peering."
  }

  validation {
    condition = alltrue([
      for prop in try(var.transit_gateway.route_table_propagations, []) :
      contains(try(var.transit_gateway.route_tables, []), prop.route_table_name)
    ])
    error_message = "Each transit_gateway.route_table_propagations route_table_name must name one of transit_gateway.route_tables."
  }

  validation {
    condition = alltrue([
      for peer in try(var.transit_gateway.peering, []) :
      can(regex("^tgw-[0-9a-f]+$", peer.peer_transit_gateway_id))
    ])
    error_message = "Each transit_gateway.peering peer_transit_gateway_id must be a Transit Gateway ID (tgw-…)."
  }

  # The route table of a peering entry carries the requester-side association
  # of that attachment. An unknown name would resolve to nothing and the
  # association would be silently missing.
  validation {
    condition = alltrue([
      for peer in try(var.transit_gateway.peering, []) :
      contains(try(var.transit_gateway.route_tables, []), peer.route_table_name)
    ])
    error_message = "Each transit_gateway.peering route_table_name must name one of transit_gateway.route_tables."
  }

  # The accepter account becomes peer_account_id of the peering attachment, so
  # it must resolve to an account ID at plan time: an account name from
  # account_ids or a 12-digit account ID.
  validation {
    condition = alltrue([
      for peer in try(var.transit_gateway.peering, []) :
      try(peer.accepter, null) == null || try(peer.accepter.account, null) == null || contains(keys(var.account_ids), peer.accepter.account) || can(regex("^[0-9]{12}$", peer.accepter.account))
    ])
    error_message = "Each transit_gateway.peering accepter.account must be an account name from account_ids or a 12-digit account ID."
  }

  # apply_tags_from_requester and the accepter tags act on the accepter
  # attachment, and this module creates one only for auto_accept = true.
  # Without it both settings would be accepted and change nothing.
  validation {
    condition = alltrue([
      for peer in try(var.transit_gateway.peering, []) :
      peer.auto_accept || try(peer.accepter, null) == null || (try(peer.accepter.apply_tags_from_requester, false) != true && length(try(peer.accepter.tags, {})) == 0)
    ])
    error_message = "transit_gateway.peering accepter.apply_tags_from_requester and accepter.tags require auto_accept = true on the same entry — without it the module creates no accepter attachment to tag."
  }

  validation {
    condition = alltrue([
      for accepter in try(var.transit_gateway.peering_accepters, []) :
      trimspace(accepter.name) != ""
    ])
    error_message = "Each transit_gateway.peering_accepters entry needs a non-empty name — the module keys its accepted attachments by name."
  }

  validation {
    condition     = length(distinct([for accepter in try(var.transit_gateway.peering_accepters, []) : accepter.name])) == length(try(var.transit_gateway.peering_accepters, []))
    error_message = "transit_gateway.peering_accepters names must be unique."
  }

  validation {
    condition = alltrue([
      for accepter in try(var.transit_gateway.peering_accepters, []) :
      can(regex("^tgw-attach-[0-9a-f]+$", accepter.transit_gateway_attachment_id))
    ])
    error_message = "Each transit_gateway.peering_accepters transit_gateway_attachment_id must be a Transit Gateway attachment ID (tgw-attach-…)."
  }

  validation {
    condition = alltrue([
      for accepter in try(var.transit_gateway.peering_accepters, []) :
      try(accepter.route_table_name, null) == null || contains(try(var.transit_gateway.route_tables, []), accepter.route_table_name)
    ])
    error_message = "Each transit_gateway.peering_accepters route_table_name must name one of transit_gateway.route_tables."
  }

  # A route_table_tags key that names no route table would tag nothing; the
  # misplaced tags would be silently missing.
  validation {
    condition = alltrue([
      for name in keys(try(var.transit_gateway.route_table_tags, {})) :
      contains(try(var.transit_gateway.route_tables, []), name)
    ])
    error_message = "Each transit_gateway.route_table_tags key must name one of transit_gateway.route_tables."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for tag_map in concat(
        [try(var.transit_gateway.tags, {})],
        values(try(var.transit_gateway.route_table_tags, {})),
        [for peer in try(var.transit_gateway.peering, []) : peer.tags],
        [for peer in try(var.transit_gateway.peering, []) : try(peer.accepter.tags, {})],
        [for accepter in try(var.transit_gateway.peering_accepters, []) : accepter.tags]
        ) : [
        for key, value in tag_map :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in transit_gateway must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  # Each share target must resolve to a RAM principal at plan time: an account
  # name from account_ids, a 12-digit account ID, an organizational unit ARN or
  # the organization ARN. Anything else would only fail when RAM processes the
  # principal association — after the share already exists.
  validation {
    condition = alltrue([
      for target in var.transit_gateway.share_targets :
      contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
    ])
    error_message = "Each transit_gateway.share_targets entry must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }
}

variable "route53_zones" {
  description = "Private Hosted Zones and Resolver Rules for centralized DNS"
  type = list(object({
    name    = string
    vpc_ids = optional(list(string), [])
    resolver_rules = optional(list(object({
      domain_name = string
      target_ips  = list(string)
      # Name of the OUTBOUND entry in resolver_endpoints that forwards this rule
      resolver_endpoint_name = optional(string, null)
    })), [])
    # cross_account_associations: an authorization plus an association, both
    # made with the module's one provider in the zone owner's account. Route 53
    # accepts the association for another account's VPC only from that
    # account, so account_id must be the account the stack runs in; any other
    # account is refused at plan (precondition in route53.tf).
    cross_account_associations = optional(list(object({
      vpc_id     = string
      account_id = string
      region     = optional(string, null) # Defaults to current region
    })), [])
  }))
  default = []

  # Route 53 rejects a FORWARD rule without an outbound Resolver Endpoint, so a
  # zone-scoped rule must name one of the configured outbound endpoints.
  validation {
    condition = alltrue(flatten([
      for zone in var.route53_zones : [
        for rule in zone.resolver_rules :
        rule.resolver_endpoint_name == null ? false : contains(
          [for ep in var.resolver_endpoints : ep.name if ep.direction == "OUTBOUND"],
          rule.resolver_endpoint_name
        )
      ]
    ]))
    error_message = "Each route53_zones resolver_rules entry must set resolver_endpoint_name to the name of an OUTBOUND entry in resolver_endpoints."
  }
}

variable "network_firewall" {
  description = "AWS Network Firewall configuration with firewall policy, rule groups, and logging"
  type = object({
    enabled      = optional(bool, false)
    vpc_name     = optional(string, "")
    subnet_ids   = optional(list(string), []) # Deprecated: use subnet_names instead
    subnet_names = optional(list(string), [])
    description  = optional(string, null)
    # Free-form tags for the firewall itself; the policy and each rule group
    # carry their own tag map below.
    tags = optional(map(string), {})
    # Change protection on the module's own firewall (see README, section
    # "Deletion protection"); firewall_policy_change_protection keeps the
    # service default false.
    delete_protection                 = optional(bool, true)
    subnet_change_protection          = optional(bool, true)
    firewall_policy_change_protection = optional(bool, false)
    rule_groups = optional(list(object({
      name        = string
      capacity    = number
      type        = string           # STATELESS or STATEFUL
      rules       = optional(string) # Suricata rules or a JSON rule definition
      description = optional(string, null)
      tags        = optional(map(string), {})
      # share_targets: RAM sharing targets — account names from account_ids,
      # raw account IDs, organizational unit ARNs or the organization ARN.
      # Each target receives this rule group through RAM (requires
      # enable_ram_sharing) for use in its own firewall policies.
      share_targets = optional(list(string), [])
      # rule_group: the structured alternative to the `rules` string. Exactly
      # one of the two describes a rule group — see README, section "Network
      # Firewall rule sources".
      rule_group = optional(object({
        rule_variables = optional(object({
          ip_sets   = optional(list(object({ name = string, definition = list(string) })), [])
          port_sets = optional(list(object({ name = string, definition = list(string) })), [])
        }), null)
        stateful_rule_options = optional(string, null) # DEFAULT_ACTION_ORDER or STRICT_ORDER
        rules_source = object({
          # rules_string carries a Suricata-compatible rule set. A rules file
          # is read at the call site with Terraform's file() function and
          # passed in here; the module itself reads no files.
          rules_string = optional(string, null)
          rules_source_list = optional(object({
            generated_rules_type = string       # ALLOWLIST or DENYLIST
            target_types         = list(string) # TLS_SNI and/or HTTP_HOST
            targets              = list(string) # domain names
          }), null)
          stateful_rules = optional(list(object({
            action = string # ALERT, DROP or PASS
            header = object({
              source           = string
              source_port      = string
              destination      = string
              destination_port = string
              direction        = string # ANY or FORWARD
              protocol         = string
            })
            rule_options = optional(list(object({
              keyword  = string
              settings = optional(list(string), [])
            })), [])
          })), [])
          stateless_rules_and_custom_actions = optional(object({
            custom_actions = optional(list(object({
              action_name               = string
              publish_metric_dimensions = list(string)
            })), [])
            stateless_rules = list(object({
              priority = number
              rule_definition = object({
                actions = list(string)
                match_attributes = object({
                  sources           = optional(list(string), [])
                  destinations      = optional(list(string), [])
                  source_ports      = optional(list(object({ from_port = number, to_port = optional(number, null) })), [])
                  destination_ports = optional(list(object({ from_port = number, to_port = optional(number, null) })), [])
                  protocols         = optional(list(number), [])
                  tcp_flags = optional(list(object({
                    flags = list(string)
                    masks = optional(list(string), [])
                  })), [])
                })
              })
            }))
          }), null)
        })
      }), null)
    })), [])
    firewall_policy = optional(object({
      description                        = optional(string, null)
      stateless_default_actions          = optional(list(string), ["aws:forward_to_sfe"])
      stateless_fragment_default_actions = optional(list(string), ["aws:forward_to_sfe"])
      stateful_rule_group_references     = optional(list(string), [])
      stateful_default_actions           = optional(list(string), [])
      stateful_engine_options = optional(object({
        rule_order               = optional(string, null) # DEFAULT_ACTION_ORDER or STRICT_ORDER
        stream_exception_policy  = optional(string, null) # DROP, CONTINUE or REJECT
        tcp_idle_timeout_seconds = optional(number, null)
      }), null)
      # stateful_rule_groups: a reference per entry, with the priority strict
      # ordering needs. Each entry names exactly one source: a rule_groups
      # entry of this module (name), an AWS managed rule group
      # (managed_rule_group_name) or a rule group outside this module (arn).
      stateful_rule_groups = optional(list(object({
        name                    = optional(string, null)
        managed_rule_group_name = optional(string, null)
        arn                     = optional(string, null)
        priority                = optional(number, null)
      })), [])
      # stateless_rule_groups: an explicit priority per STATELESS rule group of
      # this module. Left empty, the module assigns (index + 1) * 10, where
      # index is the group's position among the STATELESS group names sorted
      # lexically (keys() of a map), not its position in rule_groups.
      stateless_rule_groups = optional(list(object({
        name     = string
        priority = number
      })), [])
      stateless_custom_actions = optional(list(object({
        action_name               = string
        publish_metric_dimensions = list(string)
      })), [])
      tags = optional(map(string), {})
      # share_targets: RAM sharing targets — account names from account_ids,
      # raw account IDs, organizational unit ARNs or the organization ARN.
      # Each target receives the firewall policy through RAM (requires
      # enable_ram_sharing) for use with its own firewalls.
      share_targets = optional(list(string), [])
    }), {})
    logging_configuration = optional(object({
      flow_log_destination_type  = optional(string, "S3")
      flow_log_destination       = optional(string, "")
      alert_log_destination_type = optional(string, "S3")
      alert_log_destination      = optional(string, "")
    }), null)
    # policies: further firewall policies beside the module's own one. Each
    # carries the same firewall_policy shape and is referenced by name from a
    # firewalls entry.
    policies = optional(list(object({
      name        = string
      description = optional(string, null)
      tags        = optional(map(string), {})
      firewall_policy = object({
        stateless_default_actions          = optional(list(string), ["aws:forward_to_sfe"])
        stateless_fragment_default_actions = optional(list(string), ["aws:forward_to_sfe"])
        stateful_rule_group_references     = optional(list(string), [])
        stateful_default_actions           = optional(list(string), [])
        stateful_engine_options = optional(object({
          rule_order               = optional(string, null)
          stream_exception_policy  = optional(string, null)
          tcp_idle_timeout_seconds = optional(number, null)
        }), null)
        stateful_rule_groups = optional(list(object({
          name                    = optional(string, null)
          managed_rule_group_name = optional(string, null)
          arn                     = optional(string, null)
          priority                = optional(number, null)
        })), [])
        stateless_rule_groups = optional(list(object({
          name     = string
          priority = number
        })), [])
        stateless_custom_actions = optional(list(object({
          action_name               = string
          publish_metric_dimensions = list(string)
        })), [])
      })
      share_targets = optional(list(string), [])
    })), [])
    # firewalls: further firewalls beside the module's own one. Each names the
    # VPC and subnets it runs in and, optionally, one of the policies above;
    # without policy_name it uses the module's own policy.
    firewalls = optional(list(object({
      name                              = string
      vpc_name                          = string
      subnet_names                      = optional(list(string), [])
      subnet_ids                        = optional(list(string), [])
      description                       = optional(string, null)
      policy_name                       = optional(string, null)
      delete_protection                 = optional(bool, true)
      subnet_change_protection          = optional(bool, true)
      firewall_policy_change_protection = optional(bool, false)
      tags                              = optional(map(string), {})
      logging_configuration = optional(object({
        flow_log_destination_type  = optional(string, "S3")
        flow_log_destination       = optional(string, "")
        alert_log_destination_type = optional(string, "S3")
        alert_log_destination      = optional(string, "")
      }), null)
    })), [])
  })
  default = {}

  # The module joins rule group / policy names with "." into flat share keys
  # ("<name>.<share target>"). A dot inside a name would let two different
  # configurations produce the same key, and merge() would silently overwrite
  # one of the share associations. Same contract as var.vpcs names.
  validation {
    condition = alltrue(concat(
      [for rg in var.network_firewall.rule_groups : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", rg.name))],
      [for p in var.network_firewall.policies : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", p.name))]
    ))
    error_message = "network_firewall rule group and policy names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<name>.<share target>\" keys from these names, and a dot inside a name could collide two keys and silently drop a share association."
  }

  # A firewall with no subnet has no place to run. Both fields are optional in
  # the type so the empty default stays valid; the check only bites once the
  # firewall is switched on.
  # The parentheses around the negation are required: the HCL parser used by the
  # `scan` target rejects a line that opens with `||` when the line before it
  # ends in a negated operand, and then skips this whole file.
  validation {
    condition = (
      (!try(var.network_firewall.enabled, false))
      || (
        try(var.network_firewall.vpc_name, "") != ""
        && length(concat(try(var.network_firewall.subnet_names, []), try(var.network_firewall.subnet_ids, []))) > 0
      )
    )
    error_message = "network_firewall requires vpc_name and at least one subnet_names (or the deprecated subnet_ids) entry once enabled is true."
  }

  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      contains(["STATELESS", "STATEFUL"], group.type)
    ])
    error_message = "Each network_firewall.rule_groups type must be STATELESS or STATEFUL."
  }

  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      group.capacity >= 1 && group.capacity <= 30000
    ])
    error_message = "Each network_firewall.rule_groups capacity must be between 1 and 30000 — the AWS Network Firewall limit."
  }

  validation {
    condition = alltrue([
      for kind in [
        try(var.network_firewall.logging_configuration.flow_log_destination_type, "S3"),
        try(var.network_firewall.logging_configuration.alert_log_destination_type, "S3"),
      ] : contains(["S3", "CloudWatchLogs", "KinesisDataFirehose"], kind)
    ])
    error_message = "network_firewall.logging_configuration destination types must be S3, CloudWatchLogs or KinesisDataFirehose."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for tag_map in concat(
        [try(var.network_firewall.tags, {})],
        [try(var.network_firewall.firewall_policy.tags, {})],
        [for group in try(var.network_firewall.rule_groups, []) : group.tags],
        [for entry in try(var.network_firewall.policies, []) : entry.tags],
        [for entry in try(var.network_firewall.firewalls, []) : entry.tags]
        ) : [
        for key, value in tag_map :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in network_firewall must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  # Each share target must resolve to a RAM principal at plan time: an account
  # name from account_ids, a 12-digit account ID, an organizational unit ARN or
  # the organization ARN. Anything else would only fail when RAM processes the
  # principal association — after the share already exists.
  validation {
    condition = alltrue([
      for target in concat(
        flatten([for group in try(var.network_firewall.rule_groups, []) : group.share_targets]),
        try(var.network_firewall.firewall_policy.share_targets, []),
        flatten([for entry in try(var.network_firewall.policies, []) : entry.share_targets])
      ) :
      contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
    ])
    error_message = "Each network_firewall share_targets entry (rule_groups, firewall_policy and policies) must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }

  # --- Rule group source: exactly one of the two forms ---
  # A rule group is described by the `rules` string or by the structured
  # `rule_group` block. Both at once would leave the module choosing silently,
  # neither leaves a rule group without rules — AWS rejects that at apply time.
  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      (try(group.rules, null) == null) != (try(group.rule_group, null) == null)
    ])
    error_message = "Each network_firewall.rule_groups entry must set exactly one of rules (a Suricata or JSON rule string) and rule_group (the structured form)."
  }

  # A structured rules_source names exactly one source. The four forms are
  # alternatives in the service API, and an entry with none would plan an empty
  # rule group.
  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      length([
        for present in [
          try(group.rule_group.rules_source.rules_string, null) != null,
          try(group.rule_group.rules_source.rules_source_list, null) != null,
          length(try(group.rule_group.rules_source.stateful_rules, [])) > 0,
          try(group.rule_group.rules_source.stateless_rules_and_custom_actions, null) != null,
        ] : present if present
      ]) == 1 if try(group.rule_group, null) != null
    ])
    error_message = "Each network_firewall.rule_groups rule_group.rules_source must name exactly one source: rules_string, rules_source_list, stateful_rules or stateless_rules_and_custom_actions."
  }

  # The source form has to match the rule group type: stateless rules belong to
  # a STATELESS group, every other form to a STATEFUL one. AWS rejects the
  # mismatch, and the message points at the field instead of the API error.
  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      (
        group.type == "STATELESS"
        ) == (
        try(group.rule_group.rules_source.stateless_rules_and_custom_actions, null) != null
      ) if try(group.rule_group, null) != null
    ])
    error_message = "A network_firewall.rule_groups entry of type STATELESS must use rule_group.rules_source.stateless_rules_and_custom_actions, an entry of type STATEFUL one of rules_string, rules_source_list or stateful_rules."
  }

  # --- Structured stateful rules ---
  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateful_rules, []) :
        contains(["ALERT", "DROP", "PASS"], rule.action)
      ]
    ]))
    error_message = "Each network_firewall stateful_rules action must be ALERT, DROP or PASS."
  }

  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateful_rules, []) :
        contains(["ANY", "FORWARD"], rule.header.direction)
      ]
    ]))
    error_message = "Each network_firewall stateful_rules header direction must be ANY or FORWARD."
  }

  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateful_rules, []) :
        contains([
          "DCERPC", "DHCP", "DNS", "FTP", "HTTP", "ICMP", "IKEV2", "IMAP", "IP",
          "KRB5", "MSN", "NTP", "SMB", "SMTP", "SSH", "TCP", "TFTP", "TLS", "UDP",
        ], rule.header.protocol)
      ]
    ]))
    error_message = "Each network_firewall stateful_rules header protocol must be one of DCERPC, DHCP, DNS, FTP, HTTP, ICMP, IKEV2, IMAP, IP, KRB5, MSN, NTP, SMB, SMTP, SSH, TCP, TFTP, TLS, UDP."
  }

  # A stateful rule option carries a Suricata keyword; an empty keyword would
  # produce a rule the engine cannot compile.
  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateful_rules, []) : [
          for option in rule.rule_options : length(option.keyword) > 0
        ]
      ]
    ]))
    error_message = "Each network_firewall stateful_rules rule_options keyword must be a non-empty Suricata keyword."
  }

  # --- Domain lists ---
  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      contains(["ALLOWLIST", "DENYLIST"], group.rule_group.rules_source.rules_source_list.generated_rules_type)
      if try(group.rule_group.rules_source.rules_source_list, null) != null
    ])
    error_message = "Each network_firewall rules_source_list generated_rules_type must be ALLOWLIST or DENYLIST."
  }

  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for kind in try(group.rule_group.rules_source.rules_source_list.target_types, []) :
        contains(["TLS_SNI", "HTTP_HOST"], kind)
      ]
    ]))
    error_message = "Each network_firewall rules_source_list target_types entry must be TLS_SNI or HTTP_HOST."
  }

  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      length(try(group.rule_group.rules_source.rules_source_list.targets, [])) > 0
      if try(group.rule_group.rules_source.rules_source_list, null) != null
    ])
    error_message = "Each network_firewall rules_source_list must name at least one target domain — an empty list inspects nothing."
  }

  # --- Structured stateless rules ---
  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules, []) :
        rule.priority >= 1 && rule.priority <= 65535
      ]
    ]))
    error_message = "Each network_firewall stateless_rules priority must be between 1 and 65535."
  }

  # Two stateless rules of one group must not share a priority: the priority is
  # the evaluation order, and AWS rejects a duplicate.
  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      length(distinct([
        for rule in group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules : rule.priority
      ])) == length(group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules)
      if try(group.rule_group.rules_source.stateless_rules_and_custom_actions, null) != null
    ])
    error_message = "network_firewall stateless_rules priorities must be unique within their rule group — the priority is the evaluation order."
  }

  # A stateless action is one of the three service actions or the name of a
  # custom action of the same rule group. A name that matches neither would be
  # rejected when the rule group is created.
  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules, []) : [
          for action in rule.rule_definition.actions :
          contains(["aws:pass", "aws:drop", "aws:forward_to_sfe"], action) || contains([
            for custom in try(group.rule_group.rules_source.stateless_rules_and_custom_actions.custom_actions, []) : custom.action_name
          ], action)
        ]
      ]
    ]))
    error_message = "Each network_firewall stateless_rules action must be aws:pass, aws:drop, aws:forward_to_sfe or the action_name of a custom_actions entry of the same rule group."
  }

  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules, []) : [
          for range in concat(
            rule.rule_definition.match_attributes.source_ports,
            rule.rule_definition.match_attributes.destination_ports
          ) :
          range.from_port >= 0 && range.from_port <= 65535
          && (range.to_port == null || (range.to_port >= range.from_port && range.to_port <= 65535))
        ]
      ]
    ]))
    error_message = "Each network_firewall stateless_rules port range must lie between 0 and 65535 with to_port not below from_port."
  }

  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules, []) : [
          for protocol in rule.rule_definition.match_attributes.protocols :
          protocol >= 0 && protocol <= 255
        ]
      ]
    ]))
    error_message = "Each network_firewall stateless_rules match_attributes protocols entry must be an IP protocol number between 0 and 255."
  }

  # TCP flags: every flag and mask is one of the eight header flags, and a flag
  # that is inspected has to be part of the mask — otherwise the rule asks for
  # a bit the service was told to ignore.
  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules, []) : [
          for entry in rule.rule_definition.match_attributes.tcp_flags : [
            for flag in concat(entry.flags, entry.masks) :
            contains(["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"], flag)
          ]
        ]
      ]
    ]))
    error_message = "Each network_firewall stateless_rules tcp_flags flag and mask must be one of FIN, SYN, RST, PSH, ACK, URG, ECE, CWR."
  }

  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for rule in try(group.rule_group.rules_source.stateless_rules_and_custom_actions.stateless_rules, []) : [
          for entry in rule.rule_definition.match_attributes.tcp_flags :
          length(entry.masks) == 0 || length(setsubtract(entry.flags, entry.masks)) == 0
        ]
      ]
    ]))
    error_message = "Each network_firewall stateless_rules tcp_flags flags entry must also appear in masks — a flag outside the mask asks for a bit the inspection ignores."
  }

  # --- Rule variables ---
  validation {
    condition = alltrue(flatten([
      for group in try(var.network_firewall.rule_groups, []) : [
        for entry in concat(
          try(group.rule_group.rule_variables.ip_sets, []),
          try(group.rule_group.rule_variables.port_sets, [])
        ) : length(entry.name) > 0 && length(entry.definition) > 0
      ]
    ]))
    error_message = "Each network_firewall rule_variables entry needs a non-empty name and at least one definition value — the name is what a Suricata rule references."
  }

  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      length(distinct([
        for entry in concat(
          try(group.rule_group.rule_variables.ip_sets, []),
          try(group.rule_group.rule_variables.port_sets, [])
        ) : entry.name
        ])) == length(concat(
        try(group.rule_group.rule_variables.ip_sets, []),
        try(group.rule_group.rule_variables.port_sets, [])
      ))
    ])
    error_message = "network_firewall rule_variables names must be unique within their rule group — a repeated name would leave a Suricata reference ambiguous."
  }

  validation {
    condition = alltrue([
      for group in try(var.network_firewall.rule_groups, []) :
      contains(["DEFAULT_ACTION_ORDER", "STRICT_ORDER"], group.rule_group.stateful_rule_options)
      if try(group.rule_group.stateful_rule_options, null) != null
    ])
    error_message = "Each network_firewall rule_group.stateful_rule_options must be DEFAULT_ACTION_ORDER or STRICT_ORDER."
  }

  # --- Firewall policy depth (the module's own policy and each policies entry) ---
  validation {
    condition = alltrue(flatten([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
        ) : [
        for action in try(policy.stateful_default_actions, []) :
        contains([
          "aws:drop_strict", "aws:drop_established", "aws:drop_established_app_layer",
          "aws:alert_strict", "aws:alert_established", "aws:alert_established_app_layer",
        ], action)
      ]
    ]))
    error_message = "Each network_firewall stateful_default_actions entry must be one of aws:drop_strict, aws:drop_established, aws:drop_established_app_layer, aws:alert_strict, aws:alert_established, aws:alert_established_app_layer."
  }

  validation {
    condition = alltrue([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
      ) :
      contains(["DEFAULT_ACTION_ORDER", "STRICT_ORDER"], policy.stateful_engine_options.rule_order)
      if try(policy.stateful_engine_options.rule_order, null) != null
    ])
    error_message = "Each network_firewall stateful_engine_options rule_order must be DEFAULT_ACTION_ORDER or STRICT_ORDER."
  }

  validation {
    condition = alltrue([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
      ) :
      contains(["DROP", "CONTINUE", "REJECT"], policy.stateful_engine_options.stream_exception_policy)
      if try(policy.stateful_engine_options.stream_exception_policy, null) != null
    ])
    error_message = "Each network_firewall stateful_engine_options stream_exception_policy must be DROP, CONTINUE or REJECT."
  }

  validation {
    condition = alltrue([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
      ) :
      policy.stateful_engine_options.tcp_idle_timeout_seconds >= 60 && policy.stateful_engine_options.tcp_idle_timeout_seconds <= 6000
      if try(policy.stateful_engine_options.tcp_idle_timeout_seconds, null) != null
    ])
    error_message = "Each network_firewall stateful_engine_options tcp_idle_timeout_seconds must be between 60 and 6000 seconds."
  }

  # A stateful rule group reference names exactly one source: a rule group of
  # this module, an AWS managed rule group, or a rule group elsewhere by ARN.
  validation {
    condition = alltrue(flatten([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
        ) : [
        for reference in try(policy.stateful_rule_groups, []) :
        length([
          for present in [
            reference.name != null,
            reference.managed_rule_group_name != null,
            reference.arn != null,
          ] : present if present
        ]) == 1
      ]
    ]))
    error_message = "Each network_firewall stateful_rule_groups entry must name exactly one source: name (a rule_groups entry of this module), managed_rule_group_name or arn."
  }

  validation {
    condition = alltrue(flatten([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
        ) : [
        for reference in try(policy.stateful_rule_groups, []) :
        contains([
          for group in try(var.network_firewall.rule_groups, []) : group.name if group.type == "STATEFUL"
        ], reference.name) if reference.name != null
      ]
    ]))
    error_message = "Each network_firewall stateful_rule_groups name must name a network_firewall.rule_groups entry of type STATEFUL."
  }

  # A priority on a stateful reference is only read in strict order; in default
  # action order the service ignores it, and the entry would read as if the
  # order had been set.
  validation {
    condition = alltrue([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
      ) :
      try(policy.stateful_engine_options.rule_order, null) == "STRICT_ORDER"
      if length([for reference in try(policy.stateful_rule_groups, []) : reference if reference.priority != null]) > 0
    ])
    error_message = "A network_firewall stateful_rule_groups priority requires stateful_engine_options rule_order = \"STRICT_ORDER\" — the service reads the priority in strict order only."
  }

  validation {
    condition = alltrue(flatten([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
        ) : [
        for reference in concat(
          [for entry in try(policy.stateful_rule_groups, []) : entry if entry.priority != null],
          try(policy.stateless_rule_groups, [])
        ) : reference.priority >= 1 && reference.priority <= 65535
      ]
    ]))
    error_message = "Each network_firewall rule group reference priority must be between 1 and 65535."
  }

  validation {
    condition = alltrue([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
      ) :
      length(distinct([
        for reference in try(policy.stateless_rule_groups, []) : reference.priority
      ])) == length(try(policy.stateless_rule_groups, []))
    ])
    error_message = "network_firewall stateless_rule_groups priorities must be unique within their policy — the priority is the evaluation order."
  }

  validation {
    condition = alltrue(flatten([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
        ) : [
        for reference in try(policy.stateless_rule_groups, []) :
        contains([
          for group in try(var.network_firewall.rule_groups, []) : group.name if group.type == "STATELESS"
        ], reference.name)
      ]
    ]))
    error_message = "Each network_firewall stateless_rule_groups name must name a network_firewall.rule_groups entry of type STATELESS."
  }

  validation {
    condition = alltrue(flatten([
      for policy in concat(
        [try(var.network_firewall.firewall_policy, {})],
        [for entry in try(var.network_firewall.policies, []) : entry.firewall_policy]
        ) : [
        for action in try(policy.stateless_custom_actions, []) :
        length(action.action_name) > 0 && length(action.publish_metric_dimensions) > 0
      ]
    ]))
    error_message = "Each network_firewall stateless_custom_actions entry needs a non-empty action_name and at least one publish_metric_dimensions value."
  }

  # --- Further policies and firewalls ---
  validation {
    condition = alltrue([
      for entry in try(var.network_firewall.policies, []) : length(entry.name) > 0
      ]) && length(distinct([
        for entry in try(var.network_firewall.policies, []) : entry.name
    ])) == length(try(var.network_firewall.policies, []))
    error_message = "Each network_firewall.policies name must be non-empty and unique — the module keys its policies by name."
  }

  validation {
    condition = alltrue([
      for entry in try(var.network_firewall.firewalls, []) : length(entry.name) > 0
      ]) && length(distinct([
        for entry in try(var.network_firewall.firewalls, []) : entry.name
    ])) == length(try(var.network_firewall.firewalls, []))
    error_message = "Each network_firewall.firewalls name must be non-empty and unique — the module keys its firewalls by name."
  }

  # The module's own firewall carries the fixed name tlz-network-firewall; an
  # entry of the same name would collide with it in AWS.
  validation {
    condition = alltrue([
      for entry in try(var.network_firewall.firewalls, []) : entry.name != "tlz-network-firewall"
    ])
    error_message = "A network_firewall.firewalls name must differ from tlz-network-firewall — that is the name of the module's own firewall."
  }

  validation {
    condition = alltrue([
      for entry in try(var.network_firewall.firewalls, []) :
      entry.vpc_name != "" && length(concat(entry.subnet_names, entry.subnet_ids)) > 0
    ])
    error_message = "Each network_firewall.firewalls entry needs a vpc_name and at least one subnet_names (or subnet_ids) entry — a firewall without a subnet has no place to run."
  }

  # The VPC and every named subnet have to exist in this module's var.vpcs, or
  # the subnet lookup fails with a map key error instead of naming the field.
  validation {
    condition = alltrue([
      for entry in try(var.network_firewall.firewalls, []) :
      contains([for vpc in var.vpcs : vpc.name], entry.vpc_name)
    ])
    error_message = "Each network_firewall.firewalls vpc_name must name an entry of var.vpcs."
  }

  validation {
    condition = alltrue(flatten([
      for entry in try(var.network_firewall.firewalls, []) : [
        for name in entry.subnet_names : contains(flatten([
          for vpc in var.vpcs : [for subnet in vpc.subnets : subnet.name] if vpc.name == entry.vpc_name
        ]), name)
      ]
    ]))
    error_message = "Each network_firewall.firewalls subnet_names entry must name a subnet of the same VPC."
  }

  validation {
    condition = alltrue([
      for entry in try(var.network_firewall.firewalls, []) :
      entry.firewall_policy_change_protection == false || entry.delete_protection
    ])
    error_message = "A network_firewall.firewalls entry with firewall_policy_change_protection = true must keep delete_protection = true — protecting the policy of a firewall that any plan may destroy protects nothing."
  }

  validation {
    condition = alltrue([
      for entry in try(var.network_firewall.firewalls, []) :
      contains([for policy in try(var.network_firewall.policies, []) : policy.name], entry.policy_name)
      if entry.policy_name != null
    ])
    error_message = "Each network_firewall.firewalls policy_name must name an entry of network_firewall.policies — without policy_name the firewall uses the module's own policy."
  }

  validation {
    condition = alltrue([
      for kind in flatten([
        for entry in try(var.network_firewall.firewalls, []) : [
          try(entry.logging_configuration.flow_log_destination_type, "S3"),
          try(entry.logging_configuration.alert_log_destination_type, "S3"),
        ]
      ]) : contains(["S3", "CloudWatchLogs", "KinesisDataFirehose"], kind)
    ])
    error_message = "Each network_firewall.firewalls logging_configuration destination type must be S3, CloudWatchLogs or KinesisDataFirehose."
  }
}

variable "ipam" {
  description = "VPC IPAM configuration for centralized IP address management"
  type = object({
    enabled                    = optional(bool, false)
    description                = optional(string, "Landing Zone IPAM")
    regions                    = optional(list(string), [])
    delegated_admin_account_id = optional(string, "")
    # Free-form tags for the IPAM itself; each pool carries its own tag map.
    tags = optional(map(string), {})
    # Scopes of the IPAM beyond the two it brings itself. A pool names the
    # scope it lives in through pools[].scope; the two reserved names
    # "private-default" and "public-default" address the IPAM's own scopes, so
    # a scope declared here must not use them.
    scopes = optional(list(object({
      name        = string
      description = optional(string, null)
      tags        = optional(map(string), {})
    })), [])
    pools = optional(list(object({
      name = string
      cidr = string
      # Further ranges of the same pool. The first range stays `cidr` so that
      # a pool keeps the resource it already has.
      additional_cidrs = optional(list(string), [])
      description      = optional(string, null)
      # Address family of the pool, "ipv4" by default; "ipv6" pools hand out
      # IPv6 ranges, for example to a vpcs entry's ipv6_cidrs.
      address_family = optional(string, "ipv4")
      locale         = optional(string, null)
      # Scope the pool lives in: an entry of scopes, "private-default" (the
      # default) or "public-default" for

      # publicly advertisable ranges.
      scope            = optional(string, null)
      parent_pool_name = optional(string, null)
      # Continuously import resources that already use a range of this pool as
      # allocations. null leaves the AWS default (off) in place.
      auto_import = optional(bool, null)
      # Public ranges: publicly_advertisable decides whether the IPv6 space is
      # advertised to the internet, public_ip_source where a public range
      # comes from. Both belong to a pool in the public scope.
      publicly_advertisable = optional(bool, null)
      public_ip_source      = optional(string, null)
      # Netmask lengths of the allocations made from this pool: the length a
      # request gets without asking, and the two ends of the permitted range.
      allocation_default_netmask_length = optional(number, null)
      allocation_min_netmask_length     = optional(number, null)
      allocation_max_netmask_length     = optional(number, null)
      # Tags a resource must carry to receive an allocation from this pool.
      allocation_resource_tags = optional(map(string), {})
      tags                     = optional(map(string), {})
      # share_targets: RAM sharing targets — account names from account_ids,
      # raw account IDs, organizational unit ARNs or the organization ARN.
      # Each target receives this pool through RAM (requires enable_ram_sharing)
      # so its account(s) can allocate CIDRs from the pool.
      share_targets = optional(list(string), [])
    })), [])
  })
  default = {}

  # The module joins pool names with "." into flat map keys
  # ("<pool>.<cidr>", "<pool>.<share target>"). A dot inside a pool name
  # would let two different configurations produce the same key, and merge()
  # would silently overwrite one of the resources. Same contract as var.vpcs
  # names.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", pool.name))
    ])
    error_message = "ipam pool names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<pool>.<suffix>\" map keys from these names, and a dot inside a name could collide two keys and silently drop a resource."
  }

  validation {
    condition     = var.ipam.delegated_admin_account_id == "" || can(regex("^[0-9]{12}$", var.ipam.delegated_admin_account_id))
    error_message = "ipam.delegated_admin_account_id must be empty or a 12-digit AWS account ID."
  }

  # Every range of a pool — the first one and the further ones — carries the
  # form of the pool's address family. A range of the other family is rejected
  # when IPAM provisions it, after the pool already exists.
  validation {
    condition = alltrue(flatten([
      for pool in var.ipam.pools : [
        for cidr in concat([pool.cidr], pool.additional_cidrs) :
        pool.address_family == "ipv6" ? can(regex("^[0-9A-Fa-f:]+/[0-9]{1,3}$", cidr)) : can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", cidr))
      ]
    ]))
    error_message = "Each IPAM pool cidr and additional_cidrs entry must match the pool's address_family (e.g., 10.0.0.0/8 for ipv4, 2001:db8::/48 for ipv6)."
  }

  # A parent pool must exist in the same pool list, otherwise the pool hierarchy
  # cannot be resolved.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      pool.parent_pool_name == null || contains([for p in var.ipam.pools : p.name], pool.parent_pool_name)
    ])
    error_message = "Each ipam.pools parent_pool_name must reference the name of another pool in ipam.pools."
  }

  # The pool hierarchy is resolved in three levels (root, child, grandchild).
  # This also rejects a pool that is its own parent and parent cycles.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      pool.parent_pool_name == null || alltrue([
        for parent in var.ipam.pools : (
          parent.parent_pool_name == null || alltrue([
            for grandparent in var.ipam.pools : grandparent.parent_pool_name == null
            if grandparent.name == parent.parent_pool_name
          ])
        ) if parent.name == pool.parent_pool_name
      ])
    ])
    error_message = "ipam.pools supports at most three nesting levels (root pool, child pool, grandchild pool) and no parent cycles."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for tag_map in concat(
        [try(var.ipam.tags, {})],
        [for pool in try(var.ipam.pools, []) : pool.tags]
        ) : [
        for key, value in tag_map :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in ipam must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  # Each share target must resolve to a RAM principal at plan time: an account
  # name from account_ids, a 12-digit account ID, an organizational unit ARN or
  # the organization ARN. Anything else would only fail when RAM processes the
  # principal association — after the share already exists.
  validation {
    condition = alltrue(flatten([
      for pool in var.ipam.pools : [
        for target in pool.share_targets :
        contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
      ]
    ]))
    error_message = "Each ipam.pools share_targets entry must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }

  # IPAM knows exactly these two address families; an unknown value fails only
  # when the pool is created.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      contains(["ipv4", "ipv6"], pool.address_family)
    ])
    error_message = "Each ipam.pools address_family must be \"ipv4\" or \"ipv6\"."
  }

  # A child pool hands out ranges of its parent, so both live in the same
  # address family. IPAM rejects the mismatch when the pool is created.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      pool.parent_pool_name == null || anytrue([
        for parent in var.ipam.pools :
        parent.address_family == pool.address_family if parent.name == pool.parent_pool_name
      ])
    ])
    error_message = "Each ipam.pools entry with a parent_pool_name must share the parent's address_family."
  }

  # The module keys the scopes by name, and the two reserved names address the
  # IPAM's own scopes. A collision would make one of them unreachable.
  validation {
    condition = alltrue([
      for scope in var.ipam.scopes :
      (!contains(["private-default", "public-default"], scope.name))
    ])
    error_message = "An ipam.scopes name must not be \"private-default\" or \"public-default\" — those two names address the scopes the IPAM brings itself."
  }

  validation {
    condition     = length(distinct([for scope in var.ipam.scopes : scope.name])) == length(var.ipam.scopes)
    error_message = "Each ipam.scopes name must be unique — pools reference a scope by name."
  }

  # An unknown scope name would resolve to nothing and the pool would fail on
  # the lookup instead of on the name.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      pool.scope == null || contains(concat(["private-default", "public-default"], [for scope in var.ipam.scopes : scope.name]), pool.scope)
    ])
    error_message = "Each ipam.pools scope must be \"private-default\", \"public-default\", or the name of an ipam.scopes entry."
  }

  # A child pool takes its ranges from its parent, so both live in the same
  # scope. IPAM rejects a cross-scope hierarchy when the pool is created.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      pool.parent_pool_name == null || anytrue([
        for parent in var.ipam.pools :
        (parent.scope == null ? "private-default" : parent.scope) == (pool.scope == null ? "private-default" : pool.scope)
        if parent.name == pool.parent_pool_name
      ])
    ])
    error_message = "Each ipam.pools entry with a parent_pool_name must live in the parent's scope."
  }

  # AWS states the rule as one sentence: a pool may carry
  # publicly_advertisable only when its address family is IPv6 and its public
  # ranges come from BYOIP. Without the check the pool creation fails.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      pool.publicly_advertisable == null || (
        pool.address_family == "ipv6"
        && (pool.public_ip_source == null || pool.public_ip_source == "byoip")
      )
    ])
    error_message = "ipam.pools publicly_advertisable requires address_family = \"ipv6\" and public_ip_source = \"byoip\" (or unset, which is that default)."
  }

  # Both attributes describe public address space; in a private scope they
  # change nothing and the pool would read as if it advertised its ranges.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      (pool.publicly_advertisable == null && pool.public_ip_source == null) || pool.scope == "public-default"
    ])
    error_message = "ipam.pools publicly_advertisable and public_ip_source require scope = \"public-default\" — they describe public address space."
  }

  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      pool.public_ip_source == null || contains(["byoip", "amazon"], pool.public_ip_source)
    ])
    error_message = "Each ipam.pools public_ip_source must be \"byoip\" or \"amazon\"."
  }

  # Netmask lengths lie inside the address family's range: 0-32 for IPv4,
  # 0-128 for IPv6. IPAM rejects anything else when the pool is created.
  validation {
    condition = alltrue(flatten([
      for pool in var.ipam.pools : [
        for length_value in [
          pool.allocation_default_netmask_length,
          pool.allocation_min_netmask_length,
          pool.allocation_max_netmask_length,
        ] :
        length_value == null || (
          length_value >= 0 && length_value <= (pool.address_family == "ipv6" ? 128 : 32)
        )
      ]
    ]))
    error_message = "Each ipam.pools allocation netmask length must be between 0 and 32 for an ipv4 pool, between 0 and 128 for an ipv6 pool."
  }

  # The three lengths describe one range, so they have to agree: minimum at
  # most maximum, and the default inside both ends. A contradiction leaves the
  # pool unable to answer any request.
  validation {
    condition = alltrue([
      for pool in var.ipam.pools :
      (pool.allocation_min_netmask_length == null || pool.allocation_max_netmask_length == null || pool.allocation_min_netmask_length <= pool.allocation_max_netmask_length)
      && (pool.allocation_default_netmask_length == null || pool.allocation_min_netmask_length == null || pool.allocation_default_netmask_length >= pool.allocation_min_netmask_length)
      && (pool.allocation_default_netmask_length == null || pool.allocation_max_netmask_length == null || pool.allocation_default_netmask_length <= pool.allocation_max_netmask_length)
    ])
    error_message = "Each ipam.pools allocation netmask lengths must agree: allocation_min_netmask_length <= allocation_default_netmask_length <= allocation_max_netmask_length."
  }

  # The allocation tags and the scope tags follow the same AWS limits as every
  # other tag map of the module (key 1-128, value 0-256 characters, no
  # reserved prefix).
  validation {
    condition = alltrue(flatten([
      for tag_map in concat(
        [for pool in var.ipam.pools : pool.allocation_resource_tags],
        [for scope in var.ipam.scopes : scope.tags]
        ) : [
        for key, value in tag_map :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each ipam.pools allocation_resource_tags and ipam.scopes tags key must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

variable "prefix_lists" {
  description = "Managed Prefix Lists for reusable CIDR references"
  type = list(object({
    name           = string
    address_family = optional(string, "IPv4")
    max_entries    = number
    tags           = optional(map(string), {})
    entries = list(object({
      cidr        = string
      description = optional(string, "")
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for list in var.prefix_lists :
      contains(["IPv4", "IPv6"], try(list.address_family, "IPv4"))
    ])
    error_message = "Each prefix_lists address_family must be IPv4 or IPv6."
  }

  validation {
    condition = alltrue([
      for list in var.prefix_lists :
      list.max_entries >= length(list.entries)
    ])
    error_message = "Each prefix_lists max_entries must be at least the number of entries — AWS rejects a prefix list that is already full on creation, and the list can then never grow."
  }

  validation {
    condition = alltrue(flatten([
      for list in var.prefix_lists : [
        for entry in list.entries : can(cidrhost(entry.cidr, 0))
      ]
    ]))
    error_message = "Each prefix_lists entry cidr must be a valid CIDR block."
  }

  validation {
    condition     = length(distinct([for list in var.prefix_lists : list.name])) == length(var.prefix_lists)
    error_message = "prefix_lists names must be unique — the module keys its prefix lists by name."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for list in var.prefix_lists : [
        for key, value in list.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in prefix_lists must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

variable "vpc_peering" {
  description = "List of VPC peering connection definitions. Each entry creates a peering connection between two VPCs and routes for their CIDRs."
  type = list(object({
    name               = string
    requester_vpc_name = string
    accepter_vpc_name  = string
    auto_accept        = optional(bool, true)
    tags               = optional(map(string), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for p in var.vpc_peering :
      p.requester_vpc_name != p.accepter_vpc_name
    ])
    error_message = "requester_vpc_name and accepter_vpc_name must be different VPCs."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for p in var.vpc_peering : [
        for key, value in p.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in vpc_peering must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

# The OIDC issuers an authenticated_edge may name. The module checks only the
# shape of an edge's URLs, so without this list any HTTPS provider could
# authenticate a public entry point. The operator names the issuers they
# trust — the issuer URL exactly as the identity provider publishes it; the
# module hard-codes none. An edge whose issuer
# is not in the list is refused on every load balancer, and an internet-facing
# load balancer is refused while the list is empty.
variable "authenticated_edge_allowed_issuers" {
  description = "OIDC issuer URLs an authenticated_edge may name, each a full https:// URL compared as an exact string. An edge whose issuer is not in the list is refused; an internet-facing load balancer is refused while the list is empty. Default empty: no issuer is trusted until the operator names one."
  type        = list(string)
  default     = []

  validation {
    # Each entry is https:// followed by a host of one or more DNS labels
    # separated by single dots -- every label 1 to 63 letters, digits and
    # hyphens, starting and ending alphanumeric, no trailing dot -- then an
    # optional :port of 1 to 5 digits whose number is 1..65535, then an
    # optional path starting with / that carries neither ? nor #. Nothing
    # else: "https://?" and "https:///x" name no issuer, "https://a..b" and
    # "https://a-.b" are no DNS name, ":99999" is no port, and a query or a
    # fragment is no part of an issuer -- all refused here, at plan time,
    # instead of by the provider. The port is checked as a number because a
    # regex alone cannot bound it to 1..65535; an entry without a port passes
    # that check as 1 (the port regex is anchored at the host, so a ":" inside
    # the path is not read as a port).
    condition = alltrue([
      for issuer in var.authenticated_edge_allowed_issuers :
      can(regex("^https://[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:[0-9]{1,5})?(/[^?#]*)?$", issuer))
      && try(tonumber(regex("^https://[A-Za-z0-9.-]+:([0-9]{1,5})", issuer)[0]), 1) >= 1
      && try(tonumber(regex("^https://[A-Za-z0-9.-]+:([0-9]{1,5})", issuer)[0]), 1) <= 65535
    ])
    error_message = "Each authenticated_edge_allowed_issuers entry must be https://<host>[:port][/path] exactly as the provider publishes its issuer: a DNS name as host, a port in 1..65535, and a path without a query or fragment (? and # are refused)."
  }
}

variable "load_balancers" {
  description = "List of ALB/NLB definitions. Each entry creates a load balancer in the specified VPC. The optional attributes cover the HTTP behaviour of an application load balancer (idle timeout, HTTP/2, desync mitigation, client-port and forwarded-header handling, TLS header exposure, behaviour when the web application firewall is unreachable), cross-zone distribution for a network load balancer, the listener action (forward to one or several target groups, return a fixed response, or redirect) and the authenticated edge of a listener (authenticate-oidc ahead of its action). An internet-facing entry is refused unless it is an application load balancer whose every listener is HTTPS and declares an authenticated_edge; a network load balancer can only be internal."
  type = list(object({
    name            = string
    type            = string # "application" or "network"
    vpc_name        = string
    subnet_names    = list(string)
    scheme          = optional(string, "internal") # "internal" or "internet-facing"
    security_groups = optional(list(string), [])   # SG names (VPC-scoped); only for ALB
    access_logs = optional(object({
      bucket  = string
      prefix  = optional(string, "")
      enabled = optional(bool, true)
    }), null)

    # Application load balancer behaviour. Every attribute is null by default,
    # so the load balancing service keeps applying its own default and an entry
    # that names none of them stays unchanged. Setting any of them on a network
    # load balancer is rejected in the plan (see the validation below), because
    # the API only knows them for application load balancers.
    #
    # idle_timeout                  seconds a connection may sit idle (1-4000)
    # enable_http2                  answer HTTP/2 requests
    # desync_mitigation_mode        how ambiguous requests are handled:
    #                               "defensive", "strictest" or "monitor"
    # enable_xff_client_port        record the client port in X-Forwarded-For
    # xff_header_processing_mode    what happens to an inbound X-Forwarded-For:
    #                               "append", "preserve" or "remove"
    # enable_tls_headers            pass the negotiated TLS version and cipher
    #                               to the target as x-amzn-tls-* headers
    # enable_waf_fail_open          forward a request when the web application
    #                               firewall cannot be reached instead of
    #                               rejecting it
    idle_timeout               = optional(number, null)
    enable_http2               = optional(bool, null)
    desync_mitigation_mode     = optional(string, null)
    enable_xff_client_port     = optional(bool, null)
    xff_header_processing_mode = optional(string, null)
    enable_tls_headers         = optional(bool, null)
    enable_waf_fail_open       = optional(bool, null)

    # Spread traffic over targets in every availability zone the load balancer
    # reaches, not only the zone the request arrived in. Application load
    # balancers always do this; for a network load balancer it is a decision
    # between the resilience of an unbalanced zone and the cost of cross-zone
    # traffic. null keeps the service default (off for a network load
    # balancer).
    enable_cross_zone_load_balancing = optional(bool, null)

    # LB Listeners — forward traffic to target groups, return a fixed response
    # or redirect
    listeners = optional(list(object({
      port     = number
      protocol = string # "HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"
      # Reference to target_groups by name. Needed for a forwarding listener
      # unless action.target_groups names the targets instead; a
      # fixed-response or redirect listener needs no target group.
      target_group_name = optional(string, null)
      ssl_policy        = optional(string, null) # Required for HTTPS/TLS listeners
      certificate_arn   = optional(string, null) # Required for HTTPS/TLS listeners
      # Protocol negotiated over TLS for a network load balancer:
      # "HTTP1Only", "HTTP2Only", "HTTP2Optional", "HTTP2Preferred" or "None".
      alpn_policy = optional(string, null)

      # What the listener does with a request that matches no other rule. null
      # forwards to target_group_name.
      action = optional(object({
        # "forward", "fixed-response" or "redirect"
        type = optional(string, "forward")
        # Position of the action within the listener; null lets AWS order it.
        order = optional(number, null)

        # Weighted forwarding over several target groups. Empty forwards to
        # target_group_name alone.
        target_groups = optional(list(object({
          target_group_name = string
          weight            = optional(number, null)
        })), [])
        # Keep a client on the target group it first reached, for the given
        # number of seconds.
        stickiness = optional(object({
          duration = number
          enabled  = optional(bool, true)
        }), null)

        # Answer directly, without a target: a maintenance page, a health
        # endpoint, a deliberate rejection. The API always needs a content type
        # for the body, so it carries a default rather than being null.
        fixed_response = optional(object({
          status_code  = string
          content_type = optional(string, "text/plain")
          message_body = optional(string, null)
        }), null)

        # Send the client elsewhere. Every part not set is taken from the
        # original request.
        redirect = optional(object({
          status_code = optional(string, "HTTP_302")
          host        = optional(string, null)
          path        = optional(string, null)
          port        = optional(string, null)
          protocol    = optional(string, null)
          query       = optional(string, null)
        }), null)
      }), null)

      # The authenticated edge: the listener authenticates every caller against
      # an OpenID Connect provider before its own
      # action runs. Rendered as an authenticate-oidc action in position 1 of
      # the listener's default action chain, ahead of the forward, redirect or
      # fixed response above. It sits on the listener, not on the load
      # balancer, because that is where the load balancing API keeps it: each
      # listener has its own action chain, its own client registration at the
      # provider and its own redirect URL.
      #
      # Mandatory on every listener of an internet-facing load balancer (see
      # the validations below), optional on an internal one. The provider only
      # offers it on HTTPS listeners, so a listener that declares it must be
      # HTTPS. The client secret comes from exactly one of two places:
      # client_secret_arn names a Secrets Manager secret the module reads, so
      # the value never appears in configuration; client_secret hands the
      # value in directly, for a secret that already arrives as a sensitive
      # variable value — never as a literal in a file.
      #
      # issuer, authorization_endpoint, token_endpoint, user_info_endpoint
      #                      the provider's OIDC endpoints, full https:// URLs
      # client_id            the client registered at the provider
      # scope                OAuth scopes requested; null keeps the service
      #                      default "openid"
      # session_timeout      seconds a session cookie stays valid (1-604800);
      #                      null keeps the service default of 7 days
      authenticated_edge = optional(object({
        type                   = optional(string, "oidc")
        issuer                 = string
        authorization_endpoint = string
        token_endpoint         = string
        user_info_endpoint     = string
        client_id              = string
        client_secret_arn      = optional(string, null)
        client_secret          = optional(string, null)
        scope                  = optional(string, null)
        session_timeout        = optional(number, null)
      }), null)
    })), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      contains(["application", "network"], lb.type)
    ])
    error_message = "Each load_balancers type must be 'application' or 'network'."
  }

  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      contains(["internal", "internet-facing"], lb.scheme)
    ])
    error_message = "Each load_balancers scheme must be 'internal' or 'internet-facing'."
  }

  # An internet-facing load balancer answers anyone on the internet the moment
  # it exists. This module's rule is that nothing public is anonymous, so the
  # scheme is refused unless every caller is authenticated
  # at the edge. A network load balancer passes TCP, TLS and UDP flows through
  # and has no listener authentication at all — for it the scheme is refused
  # outright. The messages name the entry, its scheme and what to declare.
  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      lb.scheme != "internet-facing" || lb.type == "application"
    ])
    error_message = format(
      "load_balancers: %s. A network load balancer has no listener authentication, so it can only be scheme = \"internal\"; an internet-facing entry must be type = \"application\" with an authenticated_edge on every listener.",
      join("; ", [
        for lb in var.load_balancers :
        format("entry %q has scheme = %q with type = %q", lb.name, lb.scheme, lb.type)
        if lb.scheme == "internet-facing" && lb.type != "application"
      ])
    )
  }

  # The edge is declared per listener, and an internet-facing application load
  # balancer needs it on every one of them: a single listener without it is a
  # workload reachable by anyone, and an entry without any listener is a
  # public entry point whose listeners would be added past this rule.
  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      lb.scheme != "internet-facing" || lb.type != "application" || (
        length(lb.listeners) > 0 &&
        alltrue([for listener in lb.listeners : listener.authenticated_edge != null])
      )
    ])
    error_message = format(
      "load_balancers: %s. An internet-facing load balancer must authenticate every caller: declare authenticated_edge = { issuer, authorization_endpoint, token_endpoint, user_info_endpoint, client_id, client_secret_arn } on each of its listeners, or make it scheme = \"internal\".",
      join("; ", flatten([
        for lb in var.load_balancers :
        length(lb.listeners) == 0 ? [format("entry %q (scheme = %q) declares no listener", lb.name, lb.scheme)] : [
          for listener in lb.listeners :
          format("entry %q (scheme = %q) listener port %d has no authenticated_edge", lb.name, lb.scheme, listener.port)
          if listener.authenticated_edge == null
        ]
        if lb.scheme == "internet-facing" && lb.type == "application"
      ]))
    )
  }

  # The load balancing service offers authenticate-oidc on HTTPS listeners of an
  # application load balancer only. A plaintext listener cannot carry the edge —
  # not even the customary redirect to HTTPS — which is why an internet-facing
  # load balancer has HTTPS listeners alone.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.authenticated_edge == null || (lb.type == "application" && listener.protocol == "HTTPS")
      ]
    ]))
    error_message = format(
      "load_balancers: %s. authenticate-oidc exists on HTTPS listeners of an application load balancer only: a listener with an authenticated_edge must be protocol = \"HTTPS\" with a certificate_arn on type = \"application\"; a plaintext listener cannot carry the edge, not even a redirect to HTTPS.",
      join("; ", flatten([
        for lb in var.load_balancers : [
          for listener in lb.listeners :
          format("entry %q listener port %d declares an authenticated_edge but is protocol = %q on type = %q", lb.name, listener.port, listener.protocol, lb.type)
          if listener.authenticated_edge != null && !(lb.type == "application" && listener.protocol == "HTTPS")
        ]
      ]))
    )
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.authenticated_edge == null || listener.authenticated_edge.type == "oidc"
      ]
    ]))
    error_message = "Each listener authenticated_edge type must be \"oidc\" — the edge the module renders is an authenticate-oidc action."
  }

  # The client secret comes from exactly one place. Neither would fail at apply
  # with the listener half-created; both would leave it unclear which one the
  # edge uses.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.authenticated_edge == null || (
          (listener.authenticated_edge.client_secret_arn != null && listener.authenticated_edge.client_secret_arn != "") !=
          (listener.authenticated_edge.client_secret != null && listener.authenticated_edge.client_secret != "")
        )
      ]
    ]))
    error_message = format(
      "load_balancers: %s. An authenticated_edge takes its client secret from exactly one of client_secret_arn (a Secrets Manager secret the module reads at plan time) and client_secret (a value handed in from a sensitive variable — never a literal in a file).",
      join("; ", flatten([
        for lb in var.load_balancers : [
          for listener in lb.listeners :
          format("entry %q listener port %d names %s", lb.name, listener.port,
            (listener.authenticated_edge.client_secret_arn != null && listener.authenticated_edge.client_secret_arn != "") ? "both client_secret_arn and client_secret" : "neither client_secret_arn nor client_secret"
          )
          if listener.authenticated_edge != null && (
            (listener.authenticated_edge.client_secret_arn != null && listener.authenticated_edge.client_secret_arn != "") ==
            (listener.authenticated_edge.client_secret != null && listener.authenticated_edge.client_secret != "")
          )
        ]
      ]))
    )
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.authenticated_edge == null || listener.authenticated_edge.client_secret_arn == null || listener.authenticated_edge.client_secret_arn == "" ||
        can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:.+$", listener.authenticated_edge.client_secret_arn))
      ]
    ]))
    error_message = "Each listener authenticated_edge client_secret_arn must be a Secrets Manager secret ARN (arn:<partition>:secretsmanager:<region>:<account-id>:secret:<name>) whose secret string is the client secret."
  }

  # The API requires every endpoint as a full URL over HTTPS; a plain http://
  # endpoint would be refused at apply, with the listener half-created.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.authenticated_edge == null || alltrue([
          for url in [
            listener.authenticated_edge.issuer,
            listener.authenticated_edge.authorization_endpoint,
            listener.authenticated_edge.token_endpoint,
            listener.authenticated_edge.user_info_endpoint,
          ] : startswith(url, "https://") && length(url) > length("https://")
        ]) && length(listener.authenticated_edge.client_id) > 0
      ]
    ]))
    error_message = "Each listener authenticated_edge needs issuer, authorization_endpoint, token_endpoint and user_info_endpoint as full https:// URLs and a non-empty client_id."
  }

  # The shape of an issuer says nothing about who runs it: the edge is only as
  # trustworthy as its provider. An edge's issuer must be
  # one the operator named in authenticated_edge_allowed_issuers, compared as an
  # exact string, on internal load balancers as well — an edge that names an
  # untrusted issuer is wrong anywhere.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.authenticated_edge == null || contains(var.authenticated_edge_allowed_issuers, listener.authenticated_edge.issuer)
      ]
    ]))
    error_message = format(
      "load_balancers: %s. An authenticated_edge may name only an issuer listed in authenticated_edge_allowed_issuers (exact string); name the issuers you trust in authenticated_edge_allowed_issuers (env/common.hcl) or correct the edge's issuer.",
      join("; ", flatten([
        for lb in var.load_balancers : [
          for listener in lb.listeners :
          format("entry %q listener port %d names issuer %q", lb.name, listener.port, listener.authenticated_edge.issuer)
          if listener.authenticated_edge != null && !contains(var.authenticated_edge_allowed_issuers, listener.authenticated_edge.issuer)
        ]
      ]))
    )
  }

  # An internet-facing load balancer is authenticated by a trusted issuer or not
  # at all, so it is refused while no issuer is trusted. An internal entry
  # without an edge is unaffected.
  validation {
    condition = length(var.authenticated_edge_allowed_issuers) > 0 || alltrue([
      for lb in var.load_balancers : lb.scheme != "internet-facing"
    ])
    error_message = format(
      "load_balancers: %s. An internet-facing load balancer needs a trusted issuer, and authenticated_edge_allowed_issuers is empty: name the issuers you trust in authenticated_edge_allowed_issuers (env/common.hcl), or make the entry scheme = \"internal\".",
      join("; ", [
        for lb in var.load_balancers :
        format("entry %q has scheme = %q", lb.name, lb.scheme)
        if lb.scheme == "internet-facing"
      ])
    )
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners : [
          listener.authenticated_edge == null || listener.authenticated_edge.scope == null || length(listener.authenticated_edge.scope) > 0,
          listener.authenticated_edge == null || listener.authenticated_edge.session_timeout == null ||
          (listener.authenticated_edge.session_timeout >= 1 && listener.authenticated_edge.session_timeout <= 604800),
        ]
      ]
    ]))
    error_message = "Each listener authenticated_edge scope must be null or non-empty, and session_timeout null or between 1 and 604800 seconds (7 days)."
  }

  # The edge holds position 1 of the action chain, so the listener's own action
  # follows it: order null (the module writes 2) or an explicit 2 or more.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.authenticated_edge == null || listener.action == null || listener.action.order == null || listener.action.order >= 2
      ]
    ]))
    error_message = "Each listener with an authenticated_edge must leave action.order null or set it to 2 or more — the authenticate-oidc action holds position 1."
  }

  # Validate certificate_arn format on listeners (ACM ARN or null)
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.certificate_arn == null || listener.certificate_arn == "" ||
        can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-zA-Z0-9-]+$", listener.certificate_arn))
      ]
    ]))
    error_message = "Each listener certificate_arn must be a valid ACM certificate ARN (arn:<partition>:acm:<region>:<account-id>:certificate/<id>) or null. Received a value that does not match the expected ARN pattern."
  }

  # Case-exact, like target_groups.protocol: the provider accepts "https", but
  # the default TLS policy (endpoints.tf, default_ssl_policy) is only applied to
  # "HTTPS" and "TLS", so a lowercase spelling would keep the service's older
  # policy without saying so.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        contains(["HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"], listener.protocol)
      ]
    ]))
    error_message = "Each listener protocol must be one of HTTP, HTTPS, TCP, TLS, UDP, TCP_UDP (upper case)."
  }

  # The remaining checks reject a value the load balancing API would reject when
  # the load balancer or listener is created. A load balancer that is created
  # but has no usable listener is an entry point that answers nothing, and the
  # failure would only surface during the apply.

  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      lb.desync_mitigation_mode == null ||
      contains(["defensive", "strictest", "monitor"], lb.desync_mitigation_mode)
    ])
    error_message = "Each load_balancers desync_mitigation_mode must be defensive, strictest, monitor or null."
  }

  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      lb.xff_header_processing_mode == null ||
      contains(["append", "preserve", "remove"], lb.xff_header_processing_mode)
    ])
    error_message = "Each load_balancers xff_header_processing_mode must be append, preserve, remove or null."
  }

  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      lb.idle_timeout == null || (lb.idle_timeout >= 1 && lb.idle_timeout <= 4000)
    ])
    error_message = "Each load_balancers idle_timeout must be between 1 and 4000 seconds or null."
  }

  # The HTTP attributes exist only for application load balancers. Set on a
  # network load balancer the API rejects them, and the entry would read as if
  # the setting had taken effect.
  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      lb.type == "application" || alltrue([
        lb.idle_timeout == null,
        lb.enable_http2 == null,
        lb.desync_mitigation_mode == null,
        lb.enable_xff_client_port == null,
        lb.xff_header_processing_mode == null,
        lb.enable_tls_headers == null,
        lb.enable_waf_fail_open == null,
      ])
    ])
    error_message = "The load_balancers attributes idle_timeout, enable_http2, desync_mitigation_mode, enable_xff_client_port, xff_header_processing_mode, enable_tls_headers and enable_waf_fail_open apply to type 'application' only; leave them null on a network load balancer."
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.alpn_policy == null ||
        contains(["HTTP1Only", "HTTP2Only", "HTTP2Optional", "HTTP2Preferred", "None"], listener.alpn_policy)
      ]
    ]))
    error_message = "Each listener alpn_policy must be HTTP1Only, HTTP2Only, HTTP2Optional, HTTP2Preferred, None or null."
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.action == null ||
        contains(["forward", "fixed-response", "redirect"], listener.action.type)
      ]
    ]))
    error_message = "Each listener action type must be forward, fixed-response or redirect."
  }

  # A forwarding listener needs somewhere to forward to: either the single
  # target_group_name or the weighted list in action.target_groups.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        (listener.action != null && listener.action.type != "forward") ||
        (listener.target_group_name != null && listener.target_group_name != "") ||
        (listener.action != null && length(listener.action.target_groups) > 0)
      ]
    ]))
    error_message = "Each forwarding listener must name its destination — either target_group_name or at least one entry in action.target_groups."
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.action == null || listener.action.fixed_response == null ||
        can(regex("^[2-5][0-9][0-9]$", listener.action.fixed_response.status_code))
      ]
    ]))
    error_message = "Each listener fixed_response status_code must be a three-digit HTTP status between 200 and 599, given as a string."
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.action == null || listener.action.fixed_response == null ||
        contains(
          ["text/plain", "text/css", "text/html", "application/javascript", "application/json"],
          listener.action.fixed_response.content_type
        )
      ]
    ]))
    error_message = "Each listener fixed_response content_type must be one of text/plain, text/css, text/html, application/javascript, application/json."
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.action == null || listener.action.redirect == null ||
        contains(["HTTP_301", "HTTP_302"], listener.action.redirect.status_code)
      ]
    ]))
    error_message = "Each listener redirect status_code must be HTTP_301 (permanent) or HTTP_302 (temporary)."
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners : [
          listener.action == null || listener.action.order == null ||
          (listener.action.order >= 1 && listener.action.order <= 50000),
          listener.action == null || listener.action.stickiness == null ||
          (listener.action.stickiness.duration >= 1 && listener.action.stickiness.duration <= 604800),
        ]
      ]
    ]))
    error_message = "Each listener action order must be between 1 and 50000, and each forward stickiness duration between 1 and 604800 seconds (7 days)."
  }
}

variable "target_groups" {
  description = "List of target group definitions. Each entry creates a target group in the specified VPC. The optional attributes cover deregistration timing, warm-up, the distribution algorithm, session affinity, the network-target-group behaviour (client IP, Proxy Protocol v2, connection termination, failover) and the application protocol version."
  type = list(object({
    name        = string
    port        = number
    protocol    = string # "HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"
    vpc_name    = string
    target_type = optional(string, "instance") # "instance", "ip", "lambda", "alb"

    # How long a deregistering target keeps draining open connections, in
    # seconds (0-3600). null keeps the AWS default of 300.
    deregistration_delay = optional(number, null)

    # Warm-up window for a newly registered target, in seconds. 0 disables the
    # warm-up, 30-900 ramps traffic up over that period. null keeps the AWS
    # default (disabled).
    slow_start = optional(number, null)

    # How requests are spread over the targets: "round_robin",
    # "least_outstanding_requests" or "weighted_random". null keeps the AWS
    # default (round_robin).
    algorithm = optional(string, null)

    # Session affinity. null leaves affinity off, which is the AWS default.
    # `type` picks the mechanism: "lb_cookie" and "app_cookie" for application
    # target groups, "source_ip" for network target groups,
    # "source_ip_dest_ip" and "source_ip_dest_ip_proto" for gateway target
    # groups. "app_cookie" additionally needs cookie_name — the cookie the
    # application itself sets.
    stickiness = optional(object({
      type            = string
      enabled         = optional(bool, true)
      cookie_duration = optional(number, null)
      cookie_name     = optional(string, null)
    }), null)

    # Network and gateway target group behaviour. null keeps the AWS default
    # for the protocol in each case, so leaving these unset changes nothing.
    preserve_client_ip     = optional(bool, null)
    proxy_protocol_v2      = optional(bool, null)
    connection_termination = optional(bool, null)

    # What happens to established flows when a gateway target deregisters or
    # turns unhealthy: "no_rebalance" keeps them on the existing target,
    # "rebalance" moves them. Applies to GENEVE target groups.
    target_failover = optional(string, null)

    # Application protocol the targets speak: "HTTP1", "HTTP2" or "GRPC". null
    # keeps the AWS default (HTTP1 for HTTP/HTTPS target groups).
    protocol_version = optional(string, null)

    health_check = optional(object({
      enabled             = optional(bool, true)
      path                = optional(string, "/")
      port                = optional(string, "traffic-port")
      protocol            = optional(string, "HTTP")
      healthy_threshold   = optional(number, 3)
      unhealthy_threshold = optional(number, 3)
      interval            = optional(number, 30)
      timeout             = optional(number, 5)
      matcher             = optional(string, "200")
    }), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for group in var.target_groups :
      contains(["HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP", "GENEVE"], group.protocol)
    ])
    error_message = "Each target_groups protocol must be one of HTTP, HTTPS, TCP, TLS, UDP, TCP_UDP, GENEVE."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      contains(["instance", "ip", "lambda", "alb"], try(group.target_type, "instance"))
    ])
    error_message = "Each target_groups target_type must be one of instance, ip, lambda, alb."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.port >= 1 && group.port <= 65535
    ])
    error_message = "Each target_groups port must be between 1 and 65535."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]{0,31}$", group.name)) && group.vpc_name != ""
    ])
    error_message = "Each target_groups name must be at most 32 characters of letters, digits and hyphens starting alphanumeric (the AWS limit), and vpc_name must not be empty."
  }

  # The remaining checks reject a value the load balancing API would reject when
  # the target group is created. Catching them in the plan keeps a half-applied
  # run from leaving a target group behind that the listener cannot use.

  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.algorithm == null ||
      contains(["round_robin", "least_outstanding_requests", "weighted_random"], group.algorithm)
    ])
    error_message = "Each target_groups algorithm must be round_robin, least_outstanding_requests, weighted_random or null."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.stickiness == null ||
      contains(
        ["lb_cookie", "app_cookie", "source_ip", "source_ip_dest_ip", "source_ip_dest_ip_proto"],
        group.stickiness.type
      )
    ])
    error_message = "Each target_groups stickiness type must be one of lb_cookie, app_cookie, source_ip, source_ip_dest_ip, source_ip_dest_ip_proto."
  }

  # An app_cookie affinity follows a cookie the application sets; without its
  # name the load balancer has nothing to follow.
  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.stickiness == null || group.stickiness.type != "app_cookie" ||
      (group.stickiness.cookie_name != null && group.stickiness.cookie_name != "")
    ])
    error_message = "Each target_groups stickiness of type app_cookie must name the application cookie in cookie_name."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.stickiness == null || group.stickiness.cookie_duration == null ||
      (group.stickiness.cookie_duration >= 1 && group.stickiness.cookie_duration <= 604800)
    ])
    error_message = "Each target_groups stickiness cookie_duration must be between 1 and 604800 seconds (7 days) or null."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.deregistration_delay == null ||
      (group.deregistration_delay >= 0 && group.deregistration_delay <= 3600)
    ])
    error_message = "Each target_groups deregistration_delay must be between 0 and 3600 seconds or null."
  }

  # AWS accepts 0 (warm-up off) or a window of 30 to 900 seconds; a value in
  # between is rejected.
  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.slow_start == null || group.slow_start == 0 ||
      (group.slow_start >= 30 && group.slow_start <= 900)
    ])
    error_message = "Each target_groups slow_start must be 0 (no warm-up), between 30 and 900 seconds, or null."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.target_failover == null ||
      contains(["no_rebalance", "rebalance"], group.target_failover)
    ])
    error_message = "Each target_groups target_failover must be no_rebalance, rebalance or null."
  }

  validation {
    condition = alltrue([
      for group in var.target_groups :
      group.protocol_version == null ||
      contains(["HTTP1", "HTTP2", "GRPC"], group.protocol_version)
    ])
    error_message = "Each target_groups protocol_version must be HTTP1, HTTP2, GRPC or null."
  }
}

variable "account_ids" {
  description = "Map of account name to account ID for cross-account provider aliases"
  type        = map(string)
  default     = {}
}

variable "delete_default_vpc" {
  description = "Delete the default VPC and associated resources (subnets, internet gateway, security group) in the current account/region"
  type        = bool
  default     = false
}

variable "default_vpc_availability_zones" {
  description = "List of availability zones for default VPC subnet cleanup. Required when delete_default_vpc is true."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for az in var.default_vpc_availability_zones :
      can(regex("^[a-z]{2,4}(-[a-z]+)+-[0-9]+[a-z]$", az))
    ])
    error_message = "Each availability zone must be a valid format (e.g., eu-central-1a)."
  }
}

variable "dx_gateways" {
  description = "List of Direct Connect Gateway definitions. Each entry creates a DX gateway and associates it with the specified Transit Gateway, optionally restricted to allowed_prefixes and wired into named TGW route tables. Supports cross-account association proposals for sharing DX gateways."
  type = list(object({
    name                 = string
    amazon_asn           = number
    transit_gateway_name = string
    # CIDR prefixes advertised over the Transit Gateway association; empty
    # leaves the AWS default (all connected routes) in place.
    allowed_prefixes = optional(list(string), [])
    # Named TGW route tables the gateway attachment is associated with
    # (at most one) and propagates its routes into.
    route_table_associations = optional(list(string), [])
    route_table_propagations = optional(list(string), [])
    # Virtual Interfaces
    virtual_interfaces = optional(list(object({
      name           = string
      type           = string # "private" or "transit"
      vlan           = number
      bgp_asn        = number
      connection_id  = string
      address_family = optional(string, "ipv4")
      # BGP peering details — null keeps the AWS defaults (auto-assigned
      # addresses, generated key, 1500 MTU, no SiteLink).
      amazon_address   = optional(string, null) # e.g. "175.45.176.1/30"
      customer_address = optional(string, null) # e.g. "175.45.176.2/30"
      auth_key         = optional(string, null) # BGP MD5 authentication key
      mtu              = optional(number, null) # 1500 or 9001 (private), 1500 or 8500 (transit)
      sitelink_enabled = optional(bool, null)   # site-to-site traffic over the DX backbone
      tags             = optional(map(string), {})
    })), [])
    # Cross-account DX association proposals
    association_proposals = optional(list(object({
      name                        = string
      associated_gateway_id       = string # TGW or VGW ID in another account
      dx_gateway_owner_account_id = string
      allowed_prefixes            = optional(list(string), [])
    })), [])
  }))
  default = []

  # The module joins gateway and route table names with "." into flat
  # association keys ("<gateway>.<route table>"). A dot inside a gateway name
  # would let two different configurations produce the same key, and merge()
  # would silently overwrite one of the associations. Same contract as
  # var.vpcs names.
  validation {
    condition = alltrue([
      for dxg in var.dx_gateways : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", dxg.name))
    ])
    error_message = "dx_gateways names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<gateway>.<route table>\" association keys from these names, and a dot inside a name could collide two keys and silently drop an association."
  }

  validation {
    condition = alltrue([
      for dxg in var.dx_gateways :
      dxg.amazon_asn >= 1 && dxg.amazon_asn <= 4294967295
    ])
    error_message = "Each dx_gateways entry must have a valid amazon_asn (1-4294967295)."
  }

  # The peer addresses are interface addresses with prefix length; a malformed
  # value is rejected by AWS only when the virtual interface is created.
  validation {
    condition = alltrue(flatten([
      for dxg in var.dx_gateways : [
        for vif in dxg.virtual_interfaces : [
          for address in [vif.amazon_address, vif.customer_address] :
          address == null || can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$", address))
        ]
      ]
    ]))
    error_message = "Each virtual_interfaces amazon_address and customer_address must be an IPv4 interface address with prefix length (e.g. 175.45.176.1/30) or null."
  }

  # BGP MD5 keys are 8-80 characters; AWS rejects other lengths at apply time.
  validation {
    condition = alltrue(flatten([
      for dxg in var.dx_gateways : [
        for vif in dxg.virtual_interfaces :
        vif.auth_key == null || (length(vif.auth_key) >= 8 && length(vif.auth_key) <= 80)
      ]
    ]))
    error_message = "Each virtual_interfaces auth_key must be 8-80 characters long or null."
  }

  # The MTU values AWS accepts depend on the interface type: a private
  # interface takes 1500 or 9001, a transit interface 1500 or 8500.
  validation {
    condition = alltrue(flatten([
      for dxg in var.dx_gateways : [
        for vif in dxg.virtual_interfaces :
        vif.mtu == null || contains(vif.type == "transit" ? [1500, 8500] : [1500, 9001], vif.mtu)
      ]
    ]))
    error_message = "Each virtual_interfaces mtu must be 1500 or 9001 for type 'private', 1500 or 8500 for type 'transit', or null."
  }

  validation {
    condition = alltrue(flatten([
      for dxg in var.dx_gateways : [
        for cidr in dxg.allowed_prefixes : can(cidrhost(cidr, 0))
      ]
    ]))
    error_message = "Each dx_gateways allowed_prefixes entry must be a valid CIDR block."
  }

  # A Transit Gateway attachment associates with at most one route table;
  # AWS rejects the second association only at apply time.
  validation {
    condition = alltrue([
      for dxg in var.dx_gateways :
      length(dxg.route_table_associations) <= 1
    ])
    error_message = "Each dx_gateways entry can carry at most one route_table_associations entry — a Transit Gateway attachment associates with a single route table."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for dxg in var.dx_gateways : [
        for vif in dxg.virtual_interfaces : [
          for key, value in vif.tags :
          length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
        ]
      ]
    ]))
    error_message = "Each virtual_interfaces tags key in dx_gateways must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

}

variable "customer_gateways" {
  description = "List of customer gateway and VPN connection definitions. Each entry creates a customer gateway and a VPN connection terminating on the module's Transit Gateway, or — with vpc_name — on a virtual private gateway the module attaches to that VPC."
  type = list(object({
    name       = string
    bgp_asn    = number
    ip_address = string
    # Where the connection terminates: the module's Transit Gateway (default)
    # or — with vpc_name — a virtual private gateway the module creates and
    # attaches to that VPC. Exactly one of the two must be set.
    transit_gateway_name = optional(string, null)
    vpc_name             = optional(string, null)
    # Free-form tags. `tags` reaches the customer gateway, and
    # `vpn_connection_tags` the VPN connection the module creates for it — the
    # two resources are tagged separately.
    tags                = optional(map(string), {})
    vpn_connection_tags = optional(map(string), {})
    # Connection-level options — all default to null, so the AWS defaults
    # apply to an entry that names none of them.
    static_routes_only       = optional(bool, null)   # true for devices without BGP
    enable_acceleration      = optional(bool, null)   # tunnels over the AWS global network (Transit Gateway only)
    outside_ip_address_type  = optional(string, null) # "PublicIpv4" or "PrivateIpv4"
    tunnel_inside_ip_version = optional(string, null) # "ipv4" or "ipv6"
    # Traffic filters for the tunnel: which CIDR ranges may talk over the
    # connection, per side and address family. The IPv6 pair needs
    # tunnel_inside_ip_version = "ipv6".
    amazon_ipv4_network_cidr   = optional(string, null)
    amazon_ipv6_network_cidr   = optional(string, null)
    customer_ipv4_network_cidr = optional(string, null)
    customer_ipv6_network_cidr = optional(string, null)
    # VPN Tunnel Options (max 2 entries)
    tunnel_options = optional(list(object({
      tunnel_inside_cidr  = optional(string, null)
      pre_shared_key      = optional(string, null)
      dpd_timeout_seconds = optional(number, null)
      # Advanced tunnel options — all default to null for backward compatibility (AWS defaults apply)
      ike_versions                 = optional(list(string), null) # e.g. ["ikev1", "ikev2"]
      phase1_encryption_algorithms = optional(list(string), null) # e.g. ["AES128", "AES256"]
      phase2_encryption_algorithms = optional(list(string), null)
      phase1_integrity_algorithms  = optional(list(string), null) # e.g. ["SHA1", "SHA2-256"]
      phase2_integrity_algorithms  = optional(list(string), null)
      phase1_dh_group_numbers      = optional(list(number), null) # e.g. [2, 14, 15]
      phase2_dh_group_numbers      = optional(list(number), null)
      startup_action               = optional(string, null) # "add" or "start"
      dpd_timeout_action           = optional(string, null) # "clear", "none", "restart"
      rekey_margin_time_seconds    = optional(number, null)
      rekey_fuzz_percentage        = optional(number, null)
      replay_window_size           = optional(number, null)
      # IKE lifetimes in seconds; null keeps the AWS defaults (28800 / 3600).
      phase1_lifetime_seconds = optional(number, null)
      phase2_lifetime_seconds = optional(number, null)
      # Inside IPv6 addressing (/126) — needs tunnel_inside_ip_version "ipv6".
      tunnel_inside_ipv6_cidr = optional(string, null)
      # Control over the schedule of tunnel endpoint replacements.
      enable_tunnel_lifecycle_control = optional(bool, null)
      # Tunnel activity logging to CloudWatch Logs. The module creates the log
      # group; log_group_name overrides its derived name
      # ("/vpn/<gateway>/tunnel<n>"), output_format is "json" (default) or "text".
      logging = optional(object({
        enable         = optional(bool, false)
        log_group_name = optional(string, null)
        output_format  = optional(string, null)
      }), null)
    })), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for cgw in var.customer_gateways :
      can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}$", cgw.ip_address))
    ])
    error_message = "Each customer_gateways entry must have a valid IPv4 ip_address."
  }

  # Validate startup_action allowed values
  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for t in cgw.tunnel_options :
        t.startup_action == null || contains(["add", "start"], t.startup_action)
      ]
    ]))
    error_message = "tunnel_options startup_action must be 'add', 'start', or null."
  }

  # Validate dpd_timeout_action allowed values
  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for t in cgw.tunnel_options :
        t.dpd_timeout_action == null || contains(["clear", "none", "restart"], t.dpd_timeout_action)
      ]
    ]))
    error_message = "tunnel_options dpd_timeout_action must be 'clear', 'none', 'restart', or null."
  }

  # The connection needs exactly one termination point. Both set would leave
  # ambiguous which gateway carries the tunnel; neither set builds nothing.
  validation {
    condition = alltrue([
      for cgw in var.customer_gateways :
      (cgw.vpc_name == null) != (cgw.transit_gateway_name == null)
    ])
    error_message = "Each customer_gateways entry must set exactly one of transit_gateway_name or vpc_name."
  }

  # A vpc_name that names no VPC of the module would leave the virtual private
  # gateway without a VPC to attach to.
  validation {
    condition = alltrue([
      for cgw in var.customer_gateways :
      cgw.vpc_name == null || contains([for vpc in var.vpcs : vpc.name], cgw.vpc_name)
    ])
    error_message = "Each customer_gateways vpc_name must name an entry of var.vpcs."
  }

  # Three features of var.vpcs lean on the virtual private gateway: routes of
  # target_type "vgw", gateway route tables of gateway_type
  # "virtual_private_gateway", and enable_route_propagation on a subnet. The
  # gateway exists for VPCs that declare it themselves
  # (virtual_private_gateway) and for VPCs a customer_gateways entry
  # terminates on (vpc_name) — without either, each of them would reference a
  # resource that is never created. The check lives here because
  # var.customer_gateways already reads var.vpcs; the reverse direction would
  # be a reference cycle.
  # The wired case leads the disjunction and every negation carries its own
  # parentheses: the HCL parser used by the `scan` target rejects a line that
  # opens with `||` when the line before it ends in a negated operand, and
  # then skips this whole file.
  validation {
    condition = alltrue([
      for vpc in var.vpcs :
      vpc.virtual_private_gateway != null || contains([for cgw in var.customer_gateways : cgw.vpc_name], vpc.name) || (
        (!contains([
          for route in concat(
            flatten([for s in vpc.subnets : s.custom_routes]),
            flatten([for g in vpc.gateway_route_tables : g.routes])
          ) : route.target_type
        ], "vgw"))
        && (!contains([for g in vpc.gateway_route_tables : g.gateway_type], "virtual_private_gateway"))
        && (!anytrue([for s in vpc.subnets : s.enable_route_propagation]))
      )
    ])
    error_message = "Routes of target_type vgw, gateway_route_tables of gateway_type virtual_private_gateway, and enable_route_propagation require a virtual private gateway on the same VPC: a virtual_private_gateway block on the vpcs entry, or a customer_gateways entry with vpc_name set to it."
  }

  # VPN acceleration exists only on Transit Gateway connections; AWS rejects
  # it on a virtual private gateway at apply time.
  validation {
    condition = alltrue([
      for cgw in var.customer_gateways :
      cgw.enable_acceleration != true || cgw.vpc_name == null
    ])
    error_message = "customer_gateways enable_acceleration requires a Transit Gateway connection (vpc_name must not be set)."
  }

  validation {
    condition = alltrue([
      for cgw in var.customer_gateways :
      cgw.outside_ip_address_type == null || contains(["PublicIpv4", "PrivateIpv4"], cgw.outside_ip_address_type)
    ])
    error_message = "customer_gateways outside_ip_address_type must be 'PublicIpv4', 'PrivateIpv4', or null."
  }

  validation {
    condition = alltrue([
      for cgw in var.customer_gateways :
      cgw.tunnel_inside_ip_version == null || contains(["ipv4", "ipv6"], cgw.tunnel_inside_ip_version)
    ])
    error_message = "customer_gateways tunnel_inside_ip_version must be 'ipv4', 'ipv6', or null."
  }

  # The traffic filters must be valid CIDR blocks; AWS rejects a malformed
  # range only when the connection is created.
  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for cidr in [
          cgw.amazon_ipv4_network_cidr,
          cgw.amazon_ipv6_network_cidr,
          cgw.customer_ipv4_network_cidr,
          cgw.customer_ipv6_network_cidr,
        ] : cidr == null || can(cidrhost(cidr, 0))
      ]
    ]))
    error_message = "customer_gateways amazon_ipv4_network_cidr, amazon_ipv6_network_cidr, customer_ipv4_network_cidr, and customer_ipv6_network_cidr must each be a valid CIDR block or null."
  }

  # The IPv6 surfaces of the connection exist only when the tunnels carry
  # IPv6 inside addresses.
  validation {
    condition = alltrue([
      for cgw in var.customer_gateways :
      (
        cgw.amazon_ipv6_network_cidr == null
        && cgw.customer_ipv6_network_cidr == null
        && alltrue([for t in cgw.tunnel_options : t.tunnel_inside_ipv6_cidr == null])
      ) || cgw.tunnel_inside_ip_version == "ipv6"
    ])
    error_message = "customer_gateways amazon_ipv6_network_cidr, customer_ipv6_network_cidr, and tunnel_options tunnel_inside_ipv6_cidr require tunnel_inside_ip_version = 'ipv6'."
  }

  # IKE lifetimes within the AWS bounds: phase 1 900-28800 s, phase 2
  # 900-3600 s. An out-of-range value fails only when the tunnel is applied.
  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for t in cgw.tunnel_options :
        t.phase1_lifetime_seconds == null || (t.phase1_lifetime_seconds >= 900 && t.phase1_lifetime_seconds <= 28800)
      ]
    ]))
    error_message = "tunnel_options phase1_lifetime_seconds must be between 900 and 28800 seconds or null."
  }

  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for t in cgw.tunnel_options :
        t.phase2_lifetime_seconds == null || (t.phase2_lifetime_seconds >= 900 && t.phase2_lifetime_seconds <= 3600)
      ]
    ]))
    error_message = "tunnel_options phase2_lifetime_seconds must be between 900 and 3600 seconds or null."
  }

  # The inside IPv6 range of a tunnel is a /126 — two endpoint addresses.
  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for t in cgw.tunnel_options :
        t.tunnel_inside_ipv6_cidr == null || (can(cidrhost(t.tunnel_inside_ipv6_cidr, 0)) && endswith(t.tunnel_inside_ipv6_cidr, "/126"))
      ]
    ]))
    error_message = "tunnel_options tunnel_inside_ipv6_cidr must be a valid /126 CIDR block or null."
  }

  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for t in cgw.tunnel_options :
        t.logging == null || t.logging.output_format == null || contains(["json", "text"], t.logging.output_format)
      ]
    ]))
    error_message = "tunnel_options logging output_format must be 'json', 'text', or null."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for cgw in var.customer_gateways : [
        for tag_map in [cgw.tags, cgw.vpn_connection_tags] : [
          for key, value in tag_map :
          length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
        ]
      ]
    ]))
    error_message = "Each tags key in customer_gateways must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

}

variable "dns_firewall_rule_groups" {
  description = "List of Route53 DNS Firewall rule group definitions. Each entry creates a firewall rule group with domain list rules and associates it with specified VPCs; mutation_protection optionally locks single associations. Supports custom domain lists and RAM sharing for cross-account rule group distribution."
  type = list(object({
    name      = string
    vpc_names = list(string)
    tags      = optional(map(string), {})
    # Custom domain lists defined inline for this rule group
    custom_domain_lists = optional(list(object({
      name    = string
      domains = list(string)
    })), [])
    # share_targets: RAM sharing targets — account names from account_ids,
    # raw account IDs, organizational unit ARNs or the organization ARN.
    # Unlike deployment_targets (cross-account deployment scope for Terragrunt per-account stacks),
    # share_targets controls which principals receive RAM resource shares for this DNS firewall rule group.
    share_targets = optional(list(string), [])
    # Mutation protection per VPC association, keyed by an entry of vpc_names.
    # ENABLED locks that one association against modification and removal
    # until it is switched off again; a VPC name without an entry keeps the
    # service default (DISABLED).
    mutation_protection = optional(map(string), {})
    rules = list(object({
      name                    = string
      priority                = number
      action                  = string                     # "ALLOW", "BLOCK", "ALERT"
      domain_list_id          = optional(string, "")       # managed domain list ID or custom domain list ID
      custom_domain_list_name = optional(string, "")       # reference to custom domain list by name
      block_response          = optional(string, "NODATA") # "NODATA", "NXDOMAIN", "OVERRIDE"
      block_override_domain   = optional(string, "")
      block_override_ttl      = optional(number, 0)
    }))
  }))
  default = []

  # The module joins rule group, domain list and share target names with "."
  # into flat map keys ("<group>.<domain list>", "<group>.<target>"). A dot
  # inside a name would let two different configurations produce the same
  # key, and merge() would silently overwrite one of the resources. Same
  # contract as var.vpcs names.
  validation {
    condition = alltrue(flatten([
      for rg in var.dns_firewall_rule_groups : concat(
        [can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", rg.name))],
        [for dl in rg.custom_domain_lists : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", dl.name))]
      )
    ]))
    error_message = "dns_firewall_rule_groups names and their custom_domain_lists names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<group>.<name>\" map keys from these names, and a dot inside a name could collide two keys and silently drop a resource."
  }

  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for rule in group.rules : contains(["ALLOW", "BLOCK", "ALERT"], rule.action)
      ]
    ]))
    error_message = "Each dns_firewall_rule_groups rule action must be ALLOW, BLOCK or ALERT."
  }

  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for rule in group.rules :
        rule.action != "BLOCK" || contains(["NODATA", "NXDOMAIN", "OVERRIDE"], try(rule.block_response, "NODATA"))
      ]
    ]))
    error_message = "Each blocking dns_firewall_rule_groups rule must use block_response NODATA, NXDOMAIN or OVERRIDE."
  }

  # OVERRIDE needs a replacement domain; without it AWS rejects the rule.
  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for rule in group.rules :
        try(rule.block_response, "NODATA") != "OVERRIDE" || try(rule.block_override_domain, "") != ""
      ]
    ]))
    error_message = "A dns_firewall_rule_groups rule with block_response OVERRIDE must set block_override_domain."
  }

  # A rule takes its domains either from a managed list ID or from a custom
  # list declared in the same group. Neither means the rule matches nothing.
  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for rule in group.rules :
        try(rule.domain_list_id, "") != "" || contains(
          [for list in try(group.custom_domain_lists, []) : list.name],
          try(rule.custom_domain_list_name, "")
        )
      ]
    ]))
    error_message = "Each dns_firewall_rule_groups rule must set domain_list_id or a custom_domain_list_name that names one of the group's custom_domain_lists."
  }

  validation {
    condition = alltrue([
      for group in var.dns_firewall_rule_groups :
      length(group.vpc_names) > 0 && length(distinct([for rule in group.rules : rule.priority])) == length(group.rules)
    ])
    error_message = "Each dns_firewall_rule_groups entry needs at least one vpc_names entry, and its rule priorities must be unique — AWS evaluates by priority and rejects duplicates."
  }

  # Mutation protection guards the association of one rule group with one
  # VPC; a key outside vpc_names would silently protect nothing.
  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for vpc_name, protection in group.mutation_protection :
        contains(group.vpc_names, vpc_name)
      ]
    ]))
    error_message = "Each dns_firewall_rule_groups mutation_protection key must name an entry of the group's vpc_names."
  }

  # AWS accepts exactly the two states; anything else fails at apply time,
  # after the rule group has already been created.
  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for vpc_name, protection in group.mutation_protection :
        contains(["ENABLED", "DISABLED"], protection)
      ]
    ]))
    error_message = "Each dns_firewall_rule_groups mutation_protection value must be ENABLED or DISABLED."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for key, value in group.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in dns_firewall_rule_groups must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  # Each share target must resolve to a RAM principal at plan time: an account
  # name from account_ids, a 12-digit account ID, an organizational unit ARN or
  # the organization ARN. Anything else would only fail when RAM processes the
  # principal association — after the share already exists.
  validation {
    condition = alltrue(flatten([
      for group in var.dns_firewall_rule_groups : [
        for target in group.share_targets :
        contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
      ]
    ]))
    error_message = "Each dns_firewall_rule_groups share_targets entry must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }
}

# The one toggle of the query logging feature.
variable "enable_route53_query_logging" {
  description = "Enable Route53 Resolver query logging. Logs DNS queries to CloudWatch Log Group or S3."
  type        = bool
  default     = false
}

variable "route53_query_logging_destination" {
  description = "Destination type for Route53 query logging: 'cloudwatch' or 's3'. When 's3', uses central_log_bucket_name."
  type        = string
  default     = "cloudwatch"

  validation {
    condition     = contains(["cloudwatch", "s3"], var.route53_query_logging_destination)
    error_message = "route53_query_logging_destination must be 'cloudwatch' or 's3'."
  }
}

variable "route53_query_logging_vpc_names" {
  description = "List of VPC names to associate with Route53 query logging. If empty and query logging is enabled, all VPCs are associated."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for name in var.route53_query_logging_vpc_names : trimspace(name) != ""])
    error_message = "route53_query_logging_vpc_names must not contain empty entries — an empty name resolves to no VPC and the association is silently missing."
  }
}

variable "route53_query_logging_share_targets" {
  description = "RAM sharing targets for the Route53 Resolver query logging configuration: account names from account_ids, raw account IDs, organizational unit ARNs or the organization ARN. Each target can associate its own VPCs with the shared configuration. Requires enable_ram_sharing and an enabled query logging configuration."
  type        = list(string)
  default     = []

  # A share target without an enabled query logging configuration shares
  # nothing: the configuration resource only exists once query logging is on.
  validation {
    condition     = var.enable_route53_query_logging || length(var.route53_query_logging_share_targets) == 0
    error_message = "route53_query_logging_share_targets requires enable_route53_query_logging — without query logging there is no configuration to share."
  }

  # Each share target must resolve to a RAM principal at plan time. Anything
  # else would only fail when RAM processes the principal association — after
  # the share already exists.
  validation {
    condition = alltrue([
      for target in var.route53_query_logging_share_targets :
      contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
    ])
    error_message = "Each route53_query_logging_share_targets entry must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }
}

variable "gateway_load_balancers" {
  description = "List of Gateway Load Balancer definitions. Each entry creates a GWLB, target group, VPC endpoint service, and optional consumer VPC endpoints."
  type = list(object({
    name         = string
    vpc_name     = string
    subnet_names = list(string)
    tags         = optional(map(string), {})
    target_group = object({
      name     = string
      port     = optional(number, 6081)
      protocol = optional(string, "GENEVE")
      health_check = optional(object({
        port     = optional(number, 80)
        protocol = optional(string, "TCP")
      }), {})
    })
    endpoint_consumers = optional(list(object({
      vpc_name     = string
      subnet_names = list(string)
    })), [])
    # Whether endpoint requests to the GWLB endpoint service must be accepted
    # manually. false (default) keeps automated spoke onboarding working; true
    # adds a manual control step — consumer endpoints then wait in
    # pendingAcceptance until the operator accepts them.
    acceptance_required = optional(bool, false)
    # Both default to true (see README, section "Deletion protection"): the
    # central inspection load balancer survives an
    # accidental destroy, and cross-zone load balancing keeps an AZ whose last
    # healthy appliance failed on a working path. Turning either off is a
    # deliberate choice per deployment.
    deletion_protection       = optional(bool, true)
    cross_zone_load_balancing = optional(bool, true)
    # How long a TCP flow may sit idle before the load balancer forgets it.
    # null keeps the service default of 350 seconds.
    tcp_idle_timeout = optional(number, null)
  }))
  default = []

  # The module joins GWLB and consumer VPC names with "." into flat endpoint
  # keys ("<gwlb>.<consumer vpc>"). A dot inside a GWLB name would let two
  # different configurations produce the same key, and merge() would silently
  # overwrite one of the consumer endpoints. Same contract as var.vpcs names.
  validation {
    condition = alltrue([
      for gwlb in var.gateway_load_balancers : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", gwlb.name))
    ])
    error_message = "gateway_load_balancers names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<gwlb>.<consumer vpc>\" endpoint keys from these names, and a dot inside a name could collide two keys and silently drop an endpoint."
  }

  # A GWLB needs at least one subnet; without one the load balancer has no
  # place to attach and AWS rejects it at apply time.
  validation {
    condition = alltrue([
      for lb in var.gateway_load_balancers :
      lb.vpc_name != "" && length(lb.subnet_names) > 0
    ])
    error_message = "Each gateway_load_balancers entry needs a vpc_name and at least one subnet_names entry."
  }

  validation {
    condition = alltrue([
      for lb in var.gateway_load_balancers :
      try(lb.target_group.protocol, "GENEVE") == "GENEVE" && try(lb.target_group.port, 6081) == 6081
    ])
    error_message = "A Gateway Load Balancer target group must use protocol GENEVE on port 6081 — AWS supports no other combination."
  }

  validation {
    condition = alltrue(flatten([
      for lb in var.gateway_load_balancers : [
        for consumer in try(lb.endpoint_consumers, []) :
        consumer.vpc_name != "" && length(consumer.subnet_names) > 0
      ]
    ]))
    error_message = "Each gateway_load_balancers endpoint_consumers entry needs a vpc_name and at least one subnet_names entry."
  }

  validation {
    condition     = length(distinct([for lb in var.gateway_load_balancers : lb.name])) == length(var.gateway_load_balancers)
    error_message = "gateway_load_balancers names must be unique — the module keys its load balancers by name."
  }

  # The TCP idle timeout of a Gateway Load Balancer is a whole number of
  # seconds between 60 and 6000. A value outside that range is rejected when
  # the listener attribute is written, after the load balancer already exists.
  validation {
    condition = alltrue([
      for lb in var.gateway_load_balancers :
      floor(lb.tcp_idle_timeout) == lb.tcp_idle_timeout && lb.tcp_idle_timeout >= 60 && lb.tcp_idle_timeout <= 6000
      if lb.tcp_idle_timeout != null
    ])
    error_message = "Each gateway_load_balancers tcp_idle_timeout must be a whole number of seconds between 60 and 6000 — leave it null for the service default of 350."
  }

  # Cross-zone load balancing is what keeps an AZ whose last healthy appliance
  # failed on a working path. Turning it off on a load balancer that inspects
  # for other VPCs takes that away from every consumer at once, so the entry
  # has to say who consumes it before it may go.
  validation {
    condition = alltrue([
      for lb in var.gateway_load_balancers :
      lb.cross_zone_load_balancing || length(lb.endpoint_consumers) == 0
    ])
    error_message = "A gateway_load_balancers entry with endpoint_consumers must keep cross_zone_load_balancing = true — without it the traffic path of an Availability Zone breaks for every consumer as soon as its last healthy appliance fails."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for lb in var.gateway_load_balancers : [
        for key, value in lb.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in gateway_load_balancers must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

# VPC Templates — Terraform Limitation
# Terraform cannot dynamically create providers in for_each. The vpc_templates
# variable serves as documentation/intent only. Cross-account VPC creation
# requires static provider aliases per account. The intended deployment
# mechanism is Terragrunt per-account stacks under stacks/workload-*/networking/.
# This is a by-design limitation — Terraform cannot dynamically create providers.

variable "vpc_templates" {
  description = "List of VPC template definitions: the VPC layout each account in deployment_targets is meant to receive. Terraform cannot create providers dynamically, so this variable is documentation/intent only and creates no resource; the module only reports the expanded keys (output vpc_template_expanded_keys). A check block warns when a deployment_targets entry is not a key of account_ids."
  type = list(object({
    name               = string
    cidr               = string
    deployment_targets = list(string)
    subnets = list(object({
      name              = string
      cidr              = string
      availability_zone = string
      type              = string
      nat_gateway       = optional(bool, false)
    }))
    tgw_attachment = optional(object({
      route_table_name = string
    }))
    flow_logs = optional(object({
      destination = optional(string, "s3")
    }))
    gateway_endpoints = optional(list(string), [])
    interface_endpoints = optional(list(object({
      service      = string
      subnet_names = optional(list(string), [])
      policy       = optional(string, "")
    })), [])
    security_groups = optional(list(object({
      name = string
      ingress = optional(list(object({
        protocol              = string
        from_port             = number
        to_port               = number
        cidr_blocks           = optional(list(string), [])
        source_security_group = optional(string, "")
        description           = optional(string, "")
        # An ingress rule opening every port (ALL protocols, or TCP/UDP
        # 0-65535) to 0.0.0.0/0 or a /1 half of the address space is refused
        # unless this is true (see the validation on var.vpc_templates).
        acknowledge_world_open_all_protocols = optional(bool, false)
      })), [])
      egress = optional(list(object({
        protocol    = string
        from_port   = number
        to_port     = number
        cidr_blocks = optional(list(string), ["0.0.0.0/0"])
        description = optional(string, "")
      })), [])
    })), [])
    nacls = optional(list(object({
      name         = string
      subnet_names = list(string)
      inbound = optional(list(object({
        rule_number = number
        protocol    = string
        action      = string
        cidr_block  = string
        from_port   = number
        to_port     = number
      })), [])
      outbound = optional(list(object({
        rule_number = number
        protocol    = string
        action      = string
        cidr_block  = string
        from_port   = number
        to_port     = number
      })), [])
    })), [])
  }))
  default = []

  # The module joins template and account names with "." into flat map keys
  # ("<account>.<template>"). A dot inside a template name would let two
  # different configurations produce the same key, and merge() would silently
  # overwrite one of the resources. Same contract as var.vpcs names.
  validation {
    condition = alltrue([
      for tpl in var.vpc_templates : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", tpl.name))
    ])
    error_message = "vpc_templates names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<account>.<template>\" map keys from these names, and a dot inside a name could collide two keys and silently drop a resource."
  }

  validation {
    condition = alltrue([
      for template in var.vpc_templates :
      can(cidrhost(template.cidr, 0)) && length(template.deployment_targets) > 0
    ])
    error_message = "Each vpc_templates entry needs a valid cidr and at least one deployment_targets entry — a template without a target account creates nothing anywhere."
  }

  validation {
    condition = alltrue(flatten([
      for template in var.vpc_templates : [
        for subnet in template.subnets : can(cidrhost(subnet.cidr, 0))
      ]
    ]))
    error_message = "Each vpc_templates subnet cidr must be a valid CIDR block."
  }

  validation {
    condition = alltrue(flatten([
      for template in var.vpc_templates : [
        for subnet in template.subnets : contains(["public", "private", "isolated", "transit"], subnet.type)
      ]
    ]))
    error_message = "Each vpc_templates subnet type must be one of public, private, isolated, transit."
  }

  validation {
    condition = alltrue([
      for template in var.vpc_templates :
      length(distinct([for subnet in template.subnets : subnet.name])) == length(template.subnets)
    ])
    error_message = "Subnet names must be unique within a vpc_templates entry — NACL and endpoint blocks reference subnets by name."
  }

  # Same contract as the security group rules of var.vpcs: an ingress rule
  # for ALL protocols, or for TCP/UDP ports 0-65535 (or 1-65535), from a
  # source with prefix length 0 or 1 (0.0.0.0/0, 0.0.0.0/1, 128.0.0.0/1)
  # opens every port to the internet and needs a second word on the rule; a
  # single-port world-open rule stays allowed without one.
  validation {
    condition = alltrue(flatten([
      for template in var.vpc_templates : [
        for sg in template.security_groups : [
          for rule in sg.ingress :
          rule.acknowledge_world_open_all_protocols || !(
            (
              contains(["-1", "all"], lower(rule.protocol))
              || (contains(["tcp", "6", "udp", "17"], lower(rule.protocol)) && contains([0, 1], rule.from_port) && rule.to_port == 65535)
            )
            && anytrue([for cidr in rule.cidr_blocks : try(tonumber(split("/", cidr)[1]) <= 1, false)])
          )
        ]
      ]
    ]))
    error_message = format(
      "vpc_templates: %s. An ingress rule for all protocols, or for TCP/UDP ports 0-65535, from 0.0.0.0/0 or a half of the address space (prefix /1) opens every port of the group to the internet: narrow the rule to the protocol and ports it needs or to narrower sources, or set acknowledge_world_open_all_protocols = true on the rule.",
      join("; ", flatten([
        for template in var.vpc_templates : [
          for sg in template.security_groups : [
            for idx, rule in sg.ingress :
            format("template %q security group %q ingress rule %d opens every port to the world", template.name, sg.name, idx)
            if !rule.acknowledge_world_open_all_protocols && (
              contains(["-1", "all"], lower(rule.protocol))
              || (contains(["tcp", "6", "udp", "17"], lower(rule.protocol)) && contains([0, 1], rule.from_port) && rule.to_port == 65535)
            ) && anytrue([for cidr in rule.cidr_blocks : try(tonumber(split("/", cidr)[1]) <= 1, false)])
          ]
        ]
      ]))
    )
  }

  validation {
    condition     = length(distinct([for template in var.vpc_templates : template.name])) == length(var.vpc_templates)
    error_message = "vpc_templates names must be unique."
  }
}

# --- Elastic IPs ---

variable "elastic_ips" {
  description = "List of Elastic IP definitions. Each entry creates an EIP in the current region."
  type = list(object({
    name = string
    tags = optional(map(string), {})
  }))
  default = []

  validation {
    condition     = alltrue([for eip in var.elastic_ips : trimspace(eip.name) != ""])
    error_message = "Each elastic_ips entry needs a non-empty name — the module keys its addresses by name."
  }

  validation {
    condition     = length(distinct([for eip in var.elastic_ips : eip.name])) == length(var.elastic_ips)
    error_message = "elastic_ips names must be unique — a duplicate would silently drop one address."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for eip in var.elastic_ips : [
        for key, value in eip.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in elastic_ips must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

# --- Endpoint Policies ---

variable "endpoint_policies" {
  description = "List of named VPC endpoint policies. Referenced by policy_name in interface_endpoints."
  type = list(object({
    name   = string
    policy = string # JSON policy document
  }))
  default = []

  validation {
    condition     = alltrue([for policy in var.endpoint_policies : can(jsondecode(policy.policy))])
    error_message = "Each endpoint_policies policy must be a valid JSON document — an unparsable policy is only rejected at apply time, after the endpoint has been created."
  }

  validation {
    condition     = length(distinct([for policy in var.endpoint_policies : policy.name])) == length(var.endpoint_policies)
    error_message = "endpoint_policies names must be unique — interface_endpoints reference them by policy_name."
  }
}

# --- Standalone Resolver Rules ---

variable "resolver_rules" {
  description = "List of standalone Route53 Resolver Rule definitions, independent from route53_zones. Each entry creates a resolver rule and optional VPC associations."
  type = list(object({
    name        = string
    domain_name = string
    rule_type   = optional(string, "FORWARD")
    target_ips = optional(list(object({
      ip   = string
      port = optional(number, 53)
    })), [])
    vpc_names = optional(list(string), [])
    # share_targets: RAM sharing targets — account names from account_ids,
    # raw account IDs, organizational unit ARNs or the organization ARN.
    # Unlike deployment_targets (cross-account deployment scope for Terragrunt per-account stacks),
    # share_targets controls which principals receive RAM resource shares for this resolver rule.
    share_targets = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.resolver_rules :
      contains(["FORWARD", "SYSTEM", "RECURSIVE"], rule.rule_type)
    ])
    error_message = "Each resolver_rules rule_type must be FORWARD, SYSTEM, or RECURSIVE."
  }

  # Each share target must resolve to a RAM principal at plan time: an account
  # name from account_ids, a 12-digit account ID, an organizational unit ARN or
  # the organization ARN. Anything else would only fail when RAM processes the
  # principal association — after the share already exists.
  validation {
    condition = alltrue(flatten([
      for rule in var.resolver_rules : [
        for target in rule.share_targets :
        contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
      ]
    ]))
    error_message = "Each resolver_rules share_targets entry must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }
}

variable "cloudwatch_logs_kms_key_arn" {
  description = "Optional KMS key ARN for encrypting the module's CloudWatch log groups (flow logs, TGW flow logs, Route 53 query logs). Empty string keeps the CloudWatch service default encryption; no key is created by this module."
  type        = string
  default     = ""

  validation {
    condition     = var.cloudwatch_logs_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.cloudwatch_logs_kms_key_arn))
    error_message = "cloudwatch_logs_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}

variable "central_log_bucket_name" {
  description = "Name of the central S3 log bucket for VPC Flow Logs"
  type        = string
  default     = ""

  validation {
    condition     = var.central_log_bucket_name == "" || can(regex("^[a-z0-9][a-z0-9.\\-]{1,61}[a-z0-9]$", var.central_log_bucket_name))
    error_message = "central_log_bucket_name must be a valid S3 bucket name (3-63 characters, lowercase letters, numbers, dots, and hyphens)."
  }
}

# --- VPC Flow Logs Default ---

variable "vpc_flow_logs_default" {
  description = "Global default flow log configuration applied to VPCs without an explicit flow_logs block. Set to null to disable (current behavior)."
  type = object({
    destination              = string                  # "s3", "cloudwatch", or "both"
    traffic_type             = optional(string, "ALL") # ALL, ACCEPT, REJECT
    max_aggregation_interval = optional(number, 600)   # 60 or 600
    log_format               = optional(string, null)  # Custom log format string
    # Same two destination details as the per-VPC flow_logs block, with the
    # same defaults, so that both forms reach the flow log identically.
    cloudwatch_retention_days = optional(number, 365)
    s3_log_path               = optional(string, null)
  })
  default = null

  validation {
    condition     = var.vpc_flow_logs_default == null || contains(["s3", "cloudwatch", "both"], var.vpc_flow_logs_default.destination)
    error_message = "vpc_flow_logs_default.destination must be s3, cloudwatch or both."
  }

  validation {
    condition     = var.vpc_flow_logs_default == null || contains(["ALL", "ACCEPT", "REJECT"], try(var.vpc_flow_logs_default.traffic_type, "ALL"))
    error_message = "vpc_flow_logs_default.traffic_type must be ALL, ACCEPT or REJECT."
  }

  # AWS accepts exactly these two aggregation intervals.
  validation {
    condition     = var.vpc_flow_logs_default == null || contains([60, 600], try(var.vpc_flow_logs_default.max_aggregation_interval, 600))
    error_message = "vpc_flow_logs_default.max_aggregation_interval must be 60 or 600 seconds."
  }

  validation {
    condition = var.vpc_flow_logs_default == null || contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096,
      1827, 2192, 2557, 2922, 3288, 3653,
    ], try(var.vpc_flow_logs_default.cloudwatch_retention_days, 365))
    error_message = "vpc_flow_logs_default.cloudwatch_retention_days must be one of the retention values CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, or 3653)."
  }

  # A leading or trailing slash would produce an empty path segment in the
  # bucket, and the flow log would be filed under a key nobody looks at.
  validation {
    condition     = var.vpc_flow_logs_default == null || try(var.vpc_flow_logs_default.s3_log_path, null) == null || (can(regex("^[0-9A-Za-z!_.*'()/-]+$", var.vpc_flow_logs_default.s3_log_path)) && !startswith(var.vpc_flow_logs_default.s3_log_path, "/") && !endswith(var.vpc_flow_logs_default.s3_log_path, "/"))
    error_message = "vpc_flow_logs_default.s3_log_path must be a non-empty S3 key prefix without leading or trailing slash."
  }

  # The path only reaches a flow log that writes to S3.
  validation {
    condition     = var.vpc_flow_logs_default == null || try(var.vpc_flow_logs_default.s3_log_path, null) == null || contains(["s3", "both"], var.vpc_flow_logs_default.destination)
    error_message = "vpc_flow_logs_default.s3_log_path requires destination s3 or both — a CloudWatch-only flow log writes no S3 objects."
  }
}

variable "private_subnet_only" {
  description = "Advisory intent flag from the compliance layer (networking_defaults.private_subnet_only): when true, a check warns about every VPC that declares public subnets. The warning does not block the plan — public subnets stay deployable, the flag documents the framework's intent."
  type        = bool
  default     = false
}

# --- Resolver Endpoints ---

variable "resolver_endpoints" {
  description = "List of Route53 Resolver Endpoint definitions. Each entry creates a resolver endpoint with a security group and IP addresses per subnet."
  type = list(object({
    name               = string
    direction          = string # INBOUND or OUTBOUND
    vpc_name           = string
    subnet_names       = list(string)
    security_group_ids = optional(list(string), []) # Optional user-provided SG IDs; if empty, a default DNS SG is created
    allowed_cidrs      = optional(list(string), []) # Optional CIDRs for auto-created SG; if empty, VPC CIDR is used
    protocols          = optional(list(string), []) # Optional resolver protocols: "Do53", "DoH", "DoH-FIPS"
    tags               = optional(map(string), {})  # Free-form tags for the endpoint
    resolver_rules = optional(list(object({
      domain_name = string
      target_ips  = list(object({ ip = string, port = optional(number, 53) }))
      vpc_names   = optional(list(string), []) # VPCs to associate the rule with
      tags        = optional(map(string), {})
      # share_targets: RAM sharing targets — account names from account_ids,
      # raw account IDs, organizational unit ARNs or the organization ARN.
      # Unlike deployment_targets (cross-account deployment scope for Terragrunt per-account stacks),
      # share_targets controls which principals receive RAM resource shares for this resolver rule.
      share_targets = optional(list(string), [])
    })), [])
  }))
  default = []

  # The module joins endpoint names with "." into flat rule keys
  # ("<endpoint>.<domain>", "<endpoint>.<domain>.<vpc>"). Domain names carry
  # dots by design, so endpoint-name cleanliness is the only thing keeping
  # two keys distinct — a dot inside an endpoint name could collide two keys
  # and merge() would silently drop a rule. Same contract as var.vpcs names.
  validation {
    condition = alltrue([
      for ep in var.resolver_endpoints : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", ep.name))
    ])
    error_message = "resolver_endpoints names must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<endpoint>.<domain>\" rule keys from these names, and a dot inside an endpoint name could collide two keys and silently drop a rule."
  }

  validation {
    condition = alltrue([
      for ep in var.resolver_endpoints :
      contains(["INBOUND", "OUTBOUND"], ep.direction)
    ])
    error_message = "Each resolver_endpoints direction must be INBOUND or OUTBOUND."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for ep in var.resolver_endpoints : [
        for tag_map in concat(
          [ep.tags],
          [for rule in ep.resolver_rules : rule.tags]
          ) : [
          for key, value in tag_map :
          length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
        ]
      ]
    ]))
    error_message = "Each tags key in resolver_endpoints must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  # Each share target must resolve to a RAM principal at plan time: an account
  # name from account_ids, a 12-digit account ID, an organizational unit ARN or
  # the organization ARN. Anything else would only fail when RAM processes the
  # principal association — after the share already exists.
  validation {
    condition = alltrue(flatten([
      for ep in var.resolver_endpoints : [
        for rule in ep.resolver_rules : [
          for target in rule.share_targets :
          contains(keys(var.account_ids), target) || can(regex("^[0-9]{12}$", target)) || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):organizations::[0-9]{12}:(ou/o-[a-z0-9]+/ou-[a-z0-9-]+|organization/o-[a-z0-9]+)$", target))
        ]
      ]
    ]))
    error_message = "Each resolver_endpoints resolver_rules share_targets entry must be an account name from account_ids, a 12-digit account ID, an organizational unit ARN (arn:<partition>:organizations::<management-account-id>:ou/o-.../ou-...) or an organization ARN (.../organization/o-...)."
  }
}

# --- DHCP Options Sets ---

variable "dhcp_options_sets" {
  description = "List of VPC DHCP Options Set definitions. Each entry creates a DHCP options set and optionally associates it with specified VPCs."
  type = list(object({
    name                 = string
    domain_name          = optional(string, null)
    domain_name_servers  = optional(list(string), null)
    ntp_servers          = optional(list(string), null)
    netbios_name_servers = optional(list(string), null)
    netbios_node_type    = optional(number, null)
    vpc_names            = optional(list(string), [])
    tags                 = optional(map(string), {})
  }))
  default = []

  validation {
    condition     = alltrue([for set in var.dhcp_options_sets : trimspace(set.name) != ""])
    error_message = "Each dhcp_options_sets entry needs a non-empty name — the module keys its option sets by name."
  }

  # AWS accepts only these NetBIOS node types; 2 is the recommended value.
  validation {
    condition = alltrue([
      for set in var.dhcp_options_sets :
      try(set.netbios_node_type, null) == null || contains([1, 2, 4, 8], set.netbios_node_type)
    ])
    error_message = "Each dhcp_options_sets netbios_node_type must be null or one of 1, 2, 4, 8."
  }

  # A DHCP options set with no option at all is created and then changes
  # nothing — AWS falls back to its defaults.
  validation {
    condition = alltrue([
      for set in var.dhcp_options_sets :
      try(set.domain_name, null) != null
      || try(set.domain_name_servers, null) != null
      || try(set.ntp_servers, null) != null
      || try(set.netbios_name_servers, null) != null
    ])
    error_message = "Each dhcp_options_sets entry must set at least one option (domain_name, domain_name_servers, ntp_servers or netbios_name_servers)."
  }

  validation {
    condition     = length(distinct([for set in var.dhcp_options_sets : set.name])) == length(var.dhcp_options_sets)
    error_message = "dhcp_options_sets names must be unique."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for set in var.dhcp_options_sets : [
        for key, value in set.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in dhcp_options_sets must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }
}

# --- TGW Connect Attachments ---

variable "tgw_connect_attachments" {
  description = "List of Transit Gateway Connect attachment definitions for SD-WAN and third-party appliance integration. Each entry creates a TGW Connect attachment over a VPC transport attachment, with optional BGP peers for GRE-based connectivity."
  type = list(object({
    name                 = string
    transit_gateway_name = string
    transport_attachment = string # VPC attachment name (key in aws_ec2_transit_gateway_vpc_attachment.this)
    # Kind of transport the Connect attachment runs over: "vpc" (default)
    # reads transport_attachment as a VPC of var.vpcs with a tgw_attachment,
    # "dx-gateway" as an entry of var.dx_gateways — the module then looks up
    # the Transit Gateway attachment of that gateway, because no resource
    # exports it.
    transport_attachment_type = optional(string, "vpc")
    protocol                  = optional(string, "gre")
    tags                      = optional(map(string), {})
    peers = optional(list(object({
      name                    = string
      peer_address            = string # GRE outer IP of the appliance
      transit_gateway_address = string # GRE outer IP on the TGW side
      bgp_asn                 = number
      inside_cidr_blocks      = list(string) # BGP peering /29 CIDRs
    })), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for attachment in var.tgw_connect_attachments :
      try(attachment.protocol, "gre") == "gre"
    ])
    error_message = "tgw_connect_attachments protocol must be gre — AWS supports no other Transit Gateway Connect protocol."
  }

  validation {
    condition = alltrue([
      for attachment in var.tgw_connect_attachments :
      trimspace(attachment.name) != "" && trimspace(attachment.transport_attachment) != ""
    ])
    error_message = "Each tgw_connect_attachments entry needs a non-empty name and transport_attachment (the VPC attachment it runs over)."
  }

  validation {
    condition = alltrue([
      for attachment in var.tgw_connect_attachments :
      contains(["vpc", "dx-gateway"], attachment.transport_attachment_type)
    ])
    error_message = "Each tgw_connect_attachments transport_attachment_type must be vpc or dx-gateway."
  }

  # The transport must resolve against the collection its type names. An
  # unknown name would fail only when the Connect attachment is planned
  # against a resource that does not exist.
  validation {
    condition = alltrue([
      for attachment in var.tgw_connect_attachments :
      attachment.transport_attachment_type != "vpc" || anytrue([
        for vpc in var.vpcs :
        vpc.name == attachment.transport_attachment && vpc.tgw_attachment != null
      ])
    ])
    error_message = "Each tgw_connect_attachments entry with transport_attachment_type vpc must name a var.vpcs entry that carries a tgw_attachment — that attachment is the transport."
  }

  validation {
    condition = alltrue([
      for attachment in var.tgw_connect_attachments :
      attachment.transport_attachment_type != "dx-gateway" || contains([for dxg in var.dx_gateways : dxg.name], attachment.transport_attachment)
    ])
    error_message = "Each tgw_connect_attachments entry with transport_attachment_type dx-gateway must name an entry of var.dx_gateways."
  }

  # BGP over Connect uses a /29 inside each peering; a wider or narrower prefix
  # is rejected by AWS.
  validation {
    condition = alltrue(flatten([
      for attachment in var.tgw_connect_attachments : [
        for peer in try(attachment.peers, []) : [
          for cidr in peer.inside_cidr_blocks : can(cidrhost(cidr, 0)) && endswith(cidr, "/29")
        ]
      ]
    ]))
    error_message = "Each tgw_connect_attachments peer inside_cidr_blocks entry must be a valid /29 CIDR block."
  }

  validation {
    condition = alltrue(flatten([
      for attachment in var.tgw_connect_attachments : [
        for peer in try(attachment.peers, []) : peer.bgp_asn >= 1 && peer.bgp_asn <= 4294967294
      ]
    ]))
    error_message = "Each tgw_connect_attachments peer bgp_asn must be between 1 and 4294967294."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for attachment in var.tgw_connect_attachments : [
        for key, value in attachment.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in tgw_connect_attachments must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

}

# --- TGW Flow Logs ---

variable "enable_tgw_flow_logs" {
  description = "Enable flow logs on the Transit Gateway"
  type        = bool
  default     = false
}

variable "tgw_flow_logs_destination" {
  description = "Destination for TGW flow logs: 's3', 'cloudwatch', or 'both' for simultaneous delivery to both destinations"
  type        = string
  default     = "s3"

  validation {
    condition     = contains(["s3", "cloudwatch", "both"], var.tgw_flow_logs_destination)
    error_message = "tgw_flow_logs_destination must be 's3', 'cloudwatch', or 'both'."
  }
}

variable "tgw_flow_logs_retention_days" {
  description = "Retention in days for the CloudWatch log group of the TGW flow logs. Only the values CloudWatch Logs accepts are valid."
  type        = number
  default     = 365

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096,
      1827, 2192, 2557, 2922, 3288, 3653,
    ], var.tgw_flow_logs_retention_days)
    error_message = "tgw_flow_logs_retention_days must be one of the retention values CloudWatch Logs accepts (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, or 3653)."
  }
}

variable "tgw_flow_logs_s3_path" {
  description = "Key prefix inside the central log bucket for the TGW flow logs (without leading or trailing slash)"
  type        = string
  default     = "tgw-flow-logs"

  validation {
    condition     = can(regex("^[0-9A-Za-z!_.*'()/-]+$", var.tgw_flow_logs_s3_path)) && !startswith(var.tgw_flow_logs_s3_path, "/") && !endswith(var.tgw_flow_logs_s3_path, "/")
    error_message = "tgw_flow_logs_s3_path must be a non-empty S3 key prefix without leading or trailing slash."
  }
}

# --- TGW Multicast Domains (Deferred) ---

variable "tgw_multicast_domains" {
  description = "List of Transit Gateway multicast domain definitions. DEFERRED: TGW multicast support is not yet implemented. This variable is a placeholder for future work. A check block warns if non-empty."
  type = list(object({
    name                   = string
    transit_gateway_name   = string
    auto_accept_shared     = optional(bool, false)
    igmpv2_support         = optional(string, "disable")
    static_sources_support = optional(string, "disable")
  }))
  default = []

  validation {
    condition = alltrue([
      for domain in var.tgw_multicast_domains :
      trimspace(domain.name) != "" && trimspace(domain.transit_gateway_name) != ""
    ])
    error_message = "Each tgw_multicast_domains entry needs a non-empty name and transit_gateway_name."
  }

  validation {
    condition = alltrue(flatten([
      for domain in var.tgw_multicast_domains : [
        contains(["enable", "disable"], try(domain.igmpv2_support, "disable")),
        contains(["enable", "disable"], try(domain.static_sources_support, "disable")),
      ]
    ]))
    error_message = "tgw_multicast_domains igmpv2_support and static_sources_support must be enable or disable."
  }
}

# --- ACM Certificates ---

variable "enable_ram_sharing" {
  description = "Enable RAM resource sharing for subnets, the Transit Gateway, DNS firewall rule groups, resolver rules, IPAM pools, Network Firewall rule groups and policy, and the query logging configuration. When false, no aws_ram_resource_share resources are created."
  type        = bool
  default     = false
}

variable "acm_certificates" {
  description = "List of ACM certificate definitions. type 'request' asks ACM for a new certificate (DNS or EMAIL validation); type 'import' uploads existing material referenced by domain_name in acm_certificate_material. With validation_zone_name, the DNS validation records are written into that route53_zones entry and issuance is awaited; without it the records must be created wherever the domain is hosted. Email validation always requires manual action."
  type = list(object({
    domain_name               = string
    subject_alternative_names = optional(list(string), [])
    validation_method         = optional(string, "DNS")
    # "request" asks ACM for a new certificate; "import" uploads the material
    # referenced by domain_name in var.acm_certificate_material. An import
    # ignores validation_method — imported certificates are usable as-is.
    type = optional(string, "request")
    # Key algorithm for a requested certificate: RSA_2048, EC_prime256v1 or
    # EC_secp384r1. null keeps the ACM default (RSA_2048); imported material
    # carries its own algorithm.
    key_algorithm = optional(string, null)
    # Name of the route53_zones entry that hosts this certificate's DNS
    # validation records. Set, the module writes the records itself and waits
    # for issuance. null leaves record creation to the operator — required
    # whenever the domain's zone lives outside this module, and whenever the
    # named zone carries a VPC: ACM reads public DNS only, so a record in a
    # private hosted zone never completes the issuance. A check block names
    # every certificate in that situation in the plan.
    validation_zone_name = optional(string, null)
    tags                 = optional(map(string), {})
  }))
  default = []

  validation {
    condition = alltrue([
      for cert in var.acm_certificates :
      contains(["DNS", "EMAIL"], cert.validation_method)
    ])
    error_message = "Each acm_certificates validation_method must be DNS or EMAIL."
  }

  # Tag keys and values stay inside the AWS limits (key 1-128, value 0-256
  # characters) and leave the reserved prefix "aws:" alone.
  validation {
    condition = alltrue(flatten([
      for cert in var.acm_certificates : [
        for key, value in cert.tags :
        length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
      ]
    ]))
    error_message = "Each tags key in acm_certificates must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  validation {
    condition = alltrue([
      for cert in var.acm_certificates :
      contains(["request", "import"], cert.type)
    ])
    error_message = "Each acm_certificates type must be request or import."
  }

  # An import without material cannot create anything; the reference is the
  # map key in acm_certificate_material.
  validation {
    condition = alltrue([
      for cert in var.acm_certificates :
      cert.type == "request" || contains(keys(var.acm_certificate_material), cert.domain_name)
    ])
    error_message = "Each acm_certificates entry with type import needs an acm_certificate_material entry under its domain_name."
  }

  # The request-only attributes are ignored by an import — ACM reads domains
  # and algorithm from the certificate itself. Set on an import, the entry
  # would read as if they had an effect.
  validation {
    condition = alltrue([
      for cert in var.acm_certificates :
      cert.type == "request" || (length(cert.subject_alternative_names) == 0 && cert.key_algorithm == null && cert.validation_zone_name == null)
    ])
    error_message = "The acm_certificates attributes subject_alternative_names, key_algorithm and validation_zone_name apply to type request only; leave them unset on an import."
  }

  validation {
    condition = alltrue([
      for cert in var.acm_certificates :
      cert.key_algorithm == null || contains(["RSA_2048", "EC_prime256v1", "EC_secp384r1"], cert.key_algorithm)
    ])
    error_message = "Each acm_certificates key_algorithm must be RSA_2048, EC_prime256v1, EC_secp384r1 or null — the algorithms ACM issues new certificates with."
  }

  # Validation records can only land in a zone this module manages, and only
  # DNS validation has records to write.
  validation {
    condition = alltrue([
      for cert in var.acm_certificates :
      cert.validation_zone_name == null || (cert.validation_method == "DNS" && contains([for zone in var.route53_zones : zone.name], cert.validation_zone_name))
    ])
    error_message = "Each acm_certificates validation_zone_name must name a route53_zones entry and belongs to a DNS-validated certificate — for zones hosted elsewhere, leave it null and create the records there."
  }

  # Every domain of the certificate must sit inside the named zone, otherwise
  # the record would be written where no resolver looks for it.
  validation {
    condition = alltrue(flatten([
      for cert in var.acm_certificates : [
        for domain in concat([cert.domain_name], cert.subject_alternative_names) :
        trimprefix(domain, "*.") == cert.validation_zone_name || endswith(trimprefix(domain, "*."), ".${cert.validation_zone_name}")
      ] if cert.validation_zone_name != null
    ]))
    error_message = "Each domain of an acm_certificates entry with validation_zone_name must lie inside that zone: the domain (without a *. prefix) equals the zone name or ends with .<zone name>."
  }
}

variable "acm_certificate_material" {
  description = "Certificate material for acm_certificates entries with type 'import', keyed by their domain_name. Values are PEM strings handed in as variable values (for example from an encrypted tfvars source) — never files in the repository. Terraform state stores what ACM receives, so the state backend's encryption is the protection boundary."
  type = map(object({
    private_key       = string
    certificate_body  = string
    certificate_chain = optional(string, null)
  }))
  default   = {}
  sensitive = true

  validation {
    condition = alltrue([
      for name, material in var.acm_certificate_material :
      can(regex("-----BEGIN [A-Z ]*PRIVATE KEY-----", material.private_key)) && can(regex("-----BEGIN CERTIFICATE-----", material.certificate_body))
    ])
    error_message = "Each acm_certificate_material entry needs PEM-encoded material: private_key with a BEGIN ... PRIVATE KEY block and certificate_body with a BEGIN CERTIFICATE block."
  }

  validation {
    condition = alltrue([
      for name, material in var.acm_certificate_material :
      material.certificate_chain == null || can(regex("-----BEGIN CERTIFICATE-----", material.certificate_chain))
    ])
    error_message = "Each acm_certificate_material certificate_chain must be PEM-encoded (BEGIN CERTIFICATE) or null."
  }
}

# --- Shared Subnet Tags in Recipient Accounts ---

variable "enable_shared_subnet_tagging" {
  description = "Materialise the shared_subnet_tags entries as aws_ec2_tag resources on RAM-shared subnets (and optionally their VPC) this account RECEIVED. EC2 tags are account-local views, so a shared subnet arrives untagged; this switch is the receiving side's answer and is independent of enable_ram_sharing (which shares subnets out of this account)."
  type        = bool
  default     = false
}

variable "shared_subnet_tags" {
  description = "Tags to materialise on received shared subnets (required non-empty when enable_shared_subnet_tagging is true). Each entry names one received subnet_id with the tags to hold there; vpc_id/vpc_tags optionally tag the owning VPC the share made visible."
  type = list(object({
    subnet_id = string
    tags      = optional(map(string), {})
    vpc_id    = optional(string, null)
    vpc_tags  = optional(map(string), {})
  }))
  default = []

  validation {
    condition     = !var.enable_shared_subnet_tagging || length(var.shared_subnet_tags) > 0
    error_message = "enable_shared_subnet_tagging requires at least one shared_subnet_tags entry — an active switch over an empty list would silently tag nothing."
  }

  validation {
    condition     = length(var.shared_subnet_tags) == 0 || var.enable_shared_subnet_tagging
    error_message = "shared_subnet_tags entries require enable_shared_subnet_tagging — declared tags that never materialise would misstate the deployed state."
  }

  validation {
    condition = alltrue([
      for entry in var.shared_subnet_tags :
      can(regex("^subnet-[0-9a-f]+$", entry.subnet_id))
    ])
    error_message = "Each shared_subnet_tags subnet_id must be a subnet ID (subnet-<hex>) — the received subnet is addressed by ID, names do not travel across the share."
  }

  validation {
    condition     = length(distinct([for entry in var.shared_subnet_tags : entry.subnet_id])) == length(var.shared_subnet_tags)
    error_message = "shared_subnet_tags subnet_ids must be unique — two entries for one subnet would collide on the same tag resources."
  }

  validation {
    condition = alltrue([
      for entry in var.shared_subnet_tags :
      length(entry.tags) > 0
    ])
    error_message = "Each shared_subnet_tags entry must declare at least one tag — an entry without tags materialises nothing."
  }

  validation {
    condition = alltrue(flatten([
      for entry in var.shared_subnet_tags : [
        for tag_map in [entry.tags, entry.vpc_tags] : [
          for key, value in tag_map :
          length(key) > 0 && length(key) <= 128 && length(value) <= 256 && !startswith(lower(key), "aws:")
        ]
      ]
    ]))
    error_message = "Each shared_subnet_tags key must be 1-128 characters long and must not start with the reserved prefix \"aws:\", each value at most 256 characters."
  }

  validation {
    condition = alltrue([
      for entry in var.shared_subnet_tags :
      (entry.vpc_id == null) == (length(entry.vpc_tags) == 0)
    ])
    error_message = "shared_subnet_tags vpc_id and vpc_tags come as a pair: a vpc_id without vpc_tags materialises nothing, vpc_tags without a vpc_id have no address."
  }

  validation {
    condition = alltrue([
      for entry in var.shared_subnet_tags :
      entry.vpc_id == null || can(regex("^vpc-[0-9a-f]+$", entry.vpc_id))
    ])
    error_message = "Each shared_subnet_tags vpc_id must be a VPC ID (vpc-<hex>)."
  }

  validation {
    condition = alltrue(flatten([
      for a in var.shared_subnet_tags : [
        for b in var.shared_subnet_tags :
        a.vpc_id == null || b.vpc_id == null || a.vpc_id != b.vpc_id || a.vpc_tags == b.vpc_tags
      ]
    ]))
    error_message = "shared_subnet_tags entries naming the same vpc_id must declare identical vpc_tags — diverging maps would race on the same VPC tag."
  }
}
