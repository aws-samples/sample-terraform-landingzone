# Workload networking — variables
#
# The module runs in a WORKLOAD account that participates in VPCs the
# management account owns and shares (RAM). It creates what AWS requires to be
# owned by the account that runs the workload: security groups, target groups
# and the internal load balancer in front of an auto-scaling group. Subnets
# stay management-owned; the module only receives their IDs.
#
# Conventions:
#   * enable defaults to false; off or empty collections mean zero resources.
#   * Names, not IDs: vpc_name resolves through vpc_ids, subnet names through
#     subnet_ids (keys vpc_name.subnet_name), both supplied by the stack from
#     the management networking outputs. An unknown name fails the plan with
#     a message naming the entry (resource preconditions, no silent fallback).
#   * The entry schemas follow modules/networking: a target_groups entry moves
#     by cut and paste; a security group entry carries its vpc_name itself and
#     has no source_subnets selector (the subnets of another account cannot be
#     resolved here); a load_balancers entry is the internal subset.

variable "enable" {
  description = "Global gate of the module. false means zero resources, regardless of the collections."
  type        = bool
  default     = false
}

variable "vpc_ids" {
  description = "Resolution map VPC name to VPC ID, supplied by the stack from the management networking output vpc_ids. Every vpc_name of the collections must be a key."
  type        = map(string)
  default     = {}
}

variable "subnet_ids" {
  description = "Resolution map vpc_name.subnet_name to subnet ID, supplied by the stack from the management networking output subnet_ids (the subnets shared with this account). A load balancer's subnet_names resolve as vpc_name.subnet_name against it."
  type        = map(string)
  default     = {}
}

variable "security_groups" {
  description = "Security groups of the workload account, one entry per group with the VPC it belongs to (vpc_name). The rule schema is the one of modules/networking without source_subnets: a rule declares its port/protocol explicitly (protocol + from_port/to_port) or through types (RDP, SSH, HTTP, HTTPS, MSSQL, MYSQL/AURORA, REDSHIFT, POSTGRESQL, ORACLE-RDS expand to their fixed TCP port; TCP, UDP and ICMP use the rule's own port pair; ALL means all protocols), and combines IPv4 CIDRs, IPv6 CIDRs, a security group of this module in the same VPC (source_security_group) and a prefix list as sources. An egress rule keeps its open IPv4 default; set cidr_blocks = [] to scope it to the other sources. The module publishes the groups as vpc_name.sg_name in security_group_ids."
  type = list(object({
    vpc_name    = string
    name        = string
    description = optional(string, null) # null keeps the derived description
    tags        = optional(map(string), {})
    ingress = optional(list(object({
      # Optional stable name: keys the rule by name instead of its list
      # position, so removing or reordering other rules leaves it alone.
      name                  = optional(string, null)
      protocol              = optional(string, null)
      from_port             = optional(number, null)
      to_port               = optional(number, null)
      types                 = optional(list(string), [])
      cidr_blocks           = optional(list(string), [])
      ipv6_cidr_blocks      = optional(list(string), [])
      source_security_group = optional(string, "")
      prefix_list_id        = optional(string, "") # Prefix list reference
      description           = optional(string, "")
      # An ingress rule opening every port (ALL protocols, or TCP/UDP
      # 0-65535) to 0.0.0.0/0, ::/0 or a /1 half of the address space is
      # refused unless this is true (see the validation below).
      acknowledge_world_open_all_protocols = optional(bool, false)
    })), [])
    egress = optional(list(object({
      name                  = optional(string, null) # stable key, as on ingress
      protocol              = optional(string, null)
      from_port             = optional(number, null)
      to_port               = optional(number, null)
      types                 = optional(list(string), [])
      cidr_blocks           = optional(list(string), ["0.0.0.0/0"])
      ipv6_cidr_blocks      = optional(list(string), [])
      source_security_group = optional(string, "")
      prefix_list_id        = optional(string, "") # Prefix list reference
      description           = optional(string, "")
    })), [])
  }))
  default = []

  # The module joins vpc_name and name with "." into flat map keys. A dot
  # inside a name would let two different entries produce the same key, and
  # merge() would silently overwrite one of the groups.
  validation {
    condition = alltrue([
      for sg in var.security_groups :
      can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", sg.vpc_name)) && can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", sg.name))
    ])
    error_message = "Security group vpc_name and name must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<vpc>.<name>\" map keys from them, and a dot inside a name could collide two keys and silently drop a group."
  }
  # A security group description is immutable in AWS (a change replaces the
  # group) and limited to 255 characters; an empty string is rejected by the
  # API. null keeps the module's derived description.
  validation {
    condition = alltrue([
      for sg in var.security_groups :
      sg.description == null ? true : (length(sg.description) > 0 && length(sg.description) <= 255)
    ])
    error_message = "A security group description must be 1-255 characters long — leave it null to keep the derived description."
  }
  # A rule declares its port/protocol exactly once: either the explicit
  # triple or named types. Without types the explicit form must be complete;
  # AWS rejects a portless tcp rule only at apply time.
  validation {
    condition = alltrue(flatten([
      for sg in var.security_groups : [
        for rule in concat(sg.ingress, sg.egress) :
        length(rule.types) == 0 ? rule.protocol != null && rule.from_port != null && rule.to_port != null : true
      ]
    ]))
    error_message = "A security group rule without types must set protocol, from_port and to_port."
  }
  # The named types are a fixed set; an unknown name would silently expand
  # to nothing.
  validation {
    condition = alltrue(flatten([
      for sg in var.security_groups : [
        for rule in concat(sg.ingress, sg.egress) : [
          for t in rule.types :
          contains(["RDP", "SSH", "HTTP", "HTTPS", "MSSQL", "MYSQL/AURORA", "REDSHIFT", "POSTGRESQL", "ORACLE-RDS", "TCP", "UDP", "ICMP", "ALL"], t)
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
      for sg in var.security_groups : [
        for rule in concat(sg.ingress, sg.egress) :
        length(rule.types) == 0 ? true : (
          rule.protocol == null
          && (length(setintersection(toset(rule.types), toset(["TCP", "UDP", "ICMP"]))) > 0 ? rule.from_port != null && rule.to_port != null : rule.from_port == null && rule.to_port == null)
          && (contains(rule.types, "ICMP") ? length(setintersection(toset(rule.types), toset(["TCP", "UDP"]))) == 0 : true)
        )
      ]
    ]))
    error_message = "A security group rule with types must leave protocol null, must set from_port/to_port exactly when a TCP, UDP or ICMP type is listed, and must not mix ICMP with TCP/UDP types."
  }
  # TCP and UDP ports live in 0..65535 with an ordered range. AWS rejects
  # the violation at apply time — after the group has been created.
  validation {
    condition = alltrue(flatten([
      for sg in var.security_groups : [
        for rule in concat(sg.ingress, sg.egress) :
        (contains(["tcp", "6", "udp", "17"], lower(coalesce(rule.protocol, "none"))) || length(setintersection(toset(rule.types), toset(["TCP", "UDP"]))) > 0) == false ? true : (
          (rule.from_port == null || rule.to_port == null) ? true : (rule.from_port >= 0 && rule.from_port <= 65535 && rule.to_port >= 0 && rule.to_port <= 65535 && rule.from_port <= rule.to_port)
        )
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
      for sg in var.security_groups : [
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
    ]))
    error_message = format(
      "security_groups: %s. An ingress rule for all protocols, or for TCP/UDP ports 0-65535, from 0.0.0.0/0, ::/0 or a half of the address space (prefix /1) opens every port of the group to the internet: narrow the rule to the protocol and ports it needs or to narrower sources, or set acknowledge_world_open_all_protocols = true on the rule.",
      join("; ", flatten([
        for sg in var.security_groups : [
          for idx, rule in sg.ingress :
          format("vpc %q security group %q ingress rule %d opens every port to the world", sg.vpc_name, sg.name, idx)
          if !rule.acknowledge_world_open_all_protocols && (
            contains(rule.types, "ALL") || contains(["-1", "all"], lower(coalesce(rule.protocol, "none")))
            || (
              (length(setintersection(toset(rule.types), toset(["TCP", "UDP"]))) > 0 || contains(["tcp", "6", "udp", "17"], lower(coalesce(rule.protocol, "none"))))
              && contains([0, 1], coalesce(rule.from_port, -1)) && coalesce(rule.to_port, -1) == 65535
            )
          ) && anytrue([for cidr in concat(rule.cidr_blocks, rule.ipv6_cidr_blocks) : try(tonumber(split("/", cidr)[1]) <= 1, false)])
        ]
      ]))
    )
  }
  # A rule without any source configures nothing — no resource would be
  # created and the rule would silently not exist.
  validation {
    condition = alltrue(flatten([
      for sg in var.security_groups : [
        for rule in concat(sg.ingress, sg.egress) :
        length(rule.cidr_blocks) > 0 || length(rule.ipv6_cidr_blocks) > 0 || rule.source_security_group != "" || rule.prefix_list_id != ""
      ]
    ]))
    error_message = "Each security group rule must carry at least one source: cidr_blocks, ipv6_cidr_blocks, source_security_group or prefix_list_id."
  }
  # A rule that combines source_security_group with prefix_list_id and carries
  # no CIDR source creates only the security-group half: the CIDR-based
  # resource skips it (no CIDR source) and the prefix-list-only resource
  # excludes rules with a security group reference, so the prefix list half
  # would silently not exist. With a CIDR source present the prefix list
  # rides along on the CIDR-based rule, so that combination stays valid.
  validation {
    condition = alltrue(flatten([
      for sg in var.security_groups : [
        for rule in concat(sg.ingress, sg.egress) :
        !(rule.source_security_group != "" && rule.prefix_list_id != "" && length(rule.cidr_blocks) == 0 && length(rule.ipv6_cidr_blocks) == 0)
      ]
    ]))
    error_message = "A security group rule must not combine source_security_group and prefix_list_id as its only sources — the prefix list half would silently not exist. Configure two separate rules: one with source_security_group and one with prefix_list_id."
  }
  # A security group reference resolves within the same VPC and within this
  # module: a management-owned group is not resolvable in the workload
  # account. An unknown name would fail only when the plan resolves the
  # group's resource address.
  validation {
    condition = alltrue(flatten([
      for sg in var.security_groups : [
        for rule in concat(sg.ingress, sg.egress) :
        rule.source_security_group == "" || contains([for g in var.security_groups : g.name if g.vpc_name == sg.vpc_name], rule.source_security_group)
      ]
    ]))
    error_message = "Each security group rule source_security_group must name an entry of security_groups with the same vpc_name — a group of the management account cannot be referenced here."
  }
  # Rule names key the rule resources; a malformed or repeated name would
  # produce an invalid or colliding key.
  validation {
    condition = alltrue(flatten([
      for sg in var.security_groups : [
        for names in [[for r in sg.ingress : r.name], [for r in sg.egress : r.name]] : [
          alltrue([for n in names : n == null || can(regex("^[A-Za-z][A-Za-z0-9_-]*$", n))]),
          length(distinct(compact(names))) == length(compact(names)),
        ]
      ]
    ]))
    error_message = "Each security group rule name must start with a letter, contain only letters, digits, hyphens and underscores, and be unique within its list."
  }
}

variable "target_groups" {
  description = "List of target group definitions, the schema of modules/networking target_groups: an entry moves between the two by cut and paste. Each entry creates a target group in the named VPC of this account; target_type must be instance, the only type an auto-scaling group can be attached to. The optional attributes cover deregistration timing, warm-up, the distribution algorithm, session affinity, the network-target-group behaviour (client IP, Proxy Protocol v2, connection termination, failover) and the application protocol version."
  type = list(object({
    name        = string
    port        = number
    protocol    = string # "HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"
    vpc_name    = string
    target_type = optional(string, "instance") # "instance" is the only accepted value, see the validation

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
    # target groups, "source_ip" for network target groups. "app_cookie"
    # additionally needs cookie_name — the cookie the application itself sets.
    stickiness = optional(object({
      type            = string
      enabled         = optional(bool, true)
      cookie_duration = optional(number, null)
      cookie_name     = optional(string, null)
    }), null)

    # Network target group behaviour. null keeps the AWS default for the
    # protocol in each case, so leaving these unset changes nothing.
    preserve_client_ip     = optional(bool, null)
    proxy_protocol_v2      = optional(bool, null)
    connection_termination = optional(bool, null)

    # What happens to established flows when a target deregisters or turns
    # unhealthy: "no_rebalance" keeps them on the existing target, "rebalance"
    # moves them.
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
      contains(["HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"], group.protocol)
    ])
    error_message = "Each target_groups protocol must be one of HTTP, HTTPS, TCP, TLS, UDP, TCP_UDP."
  }

  # An auto-scaling group registers its instances by instance ID; AWS refuses
  # the attachment to a target group of any other type.
  validation {
    condition = alltrue([
      for group in var.target_groups : group.target_type == "instance"
    ])
    error_message = format(
      "target_groups: %s. An auto-scaling group can only be attached to a target group with target_type = \"instance\"; a target group of another type belongs in the management networking stack (target_groups in env/common.hcl).",
      join("; ", [
        for group in var.target_groups :
        format("entry %q has target_type = %q", group.name, group.target_type)
        if group.target_type != "instance"
      ])
    )
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
      contains(["lb_cookie", "app_cookie", "source_ip"], group.stickiness.type)
    ])
    error_message = "Each target_groups stickiness type must be one of lb_cookie, app_cookie, source_ip."
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

variable "load_balancers" {
  description = "List of internal application or network load balancers of this account, the internal subset of modules/networking load_balancers: name, type, vpc_name, subnet_names (names of shared subnets in that VPC), security_groups (names of this module's groups in the same VPC, application load balancers only), access_logs, the application load balancer attributes (idle_timeout, enable_http2, desync_mitigation_mode, enable_xff_client_port, xff_header_processing_mode, enable_tls_headers, enable_waf_fail_open), enable_cross_zone_load_balancing and listeners that each forward to one target_group of this module. scheme is internal only: a public entry point with its authenticated edge stays in the management networking stack. A listener whose protocol is HTTPS or TLS and names no ssl_policy gets the TLS-1.2-minimum policy ELBSecurityPolicy-TLS13-1-2-2021-06; its certificate_arn must belong to this account."
  type = list(object({
    name            = string
    type            = string # "application" or "network"
    vpc_name        = string
    subnet_names    = list(string)
    scheme          = optional(string, "internal") # "internal" is the only accepted value, see the validation
    security_groups = optional(list(string), [])   # names of this module's groups in vpc_name; only for ALB
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
    idle_timeout               = optional(number, null)
    enable_http2               = optional(bool, null)
    desync_mitigation_mode     = optional(string, null)
    enable_xff_client_port     = optional(bool, null)
    xff_header_processing_mode = optional(string, null)
    enable_tls_headers         = optional(bool, null)
    enable_waf_fail_open       = optional(bool, null)

    # Spread traffic over targets in every availability zone the load balancer
    # reaches. Application load balancers always do this; for a network load
    # balancer null keeps the service default (off).
    enable_cross_zone_load_balancing = optional(bool, null)

    # Listeners — each forwards every request to one target group of this
    # module (target_group names an entry of target_groups).
    listeners = optional(list(object({
      port            = number
      protocol        = string # "HTTP", "HTTPS", "TCP", "TLS", "UDP", "TCP_UDP"
      target_group    = string
      ssl_policy      = optional(string, null) # HTTPS/TLS listeners; null takes the module default
      certificate_arn = optional(string, null) # Required for HTTPS/TLS listeners; an ACM certificate of this account
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

  # The workload account's load balancers are reached from inside the shared
  # VPC. A public entry point needs the authenticated edge the management
  # networking module enforces on every internet-facing load balancer, and that
  # module is where it stays.
  validation {
    condition = alltrue([
      for lb in var.load_balancers : lb.scheme == "internal"
    ])
    error_message = format(
      "load_balancers: %s. This module creates internal load balancers only (scheme = \"internal\"); an internet-facing entry point belongs in the management networking stack (load_balancers in env/common.hcl), which requires an authenticated_edge on each of its listeners.",
      join("; ", [
        for lb in var.load_balancers :
        format("entry %q has scheme = %q", lb.name, lb.scheme)
        if lb.scheme != "internal"
      ])
    )
  }

  # An application load balancer created without a security group gets the
  # VPC's default group, which the management networking module strips of
  # every rule: the load balancer would pass no traffic.
  validation {
    condition = alltrue([
      for lb in var.load_balancers :
      lb.type != "application" || length(lb.security_groups) > 0
    ])
    error_message = "Each load_balancers entry of type 'application' must name at least one security group in security_groups. Without one AWS attaches the VPC's default security group, which the networking module strips of every rule, so the load balancer would pass no traffic."
  }

  # The groups resolve within this module and the same VPC; a management
  # group is not resolvable in the workload account.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for sg_name in lb.security_groups :
        contains([for g in var.security_groups : g.name if g.vpc_name == lb.vpc_name], sg_name)
      ]
    ]))
    error_message = "Each load_balancers security_groups entry must name an entry of security_groups with the same vpc_name as the load balancer."
  }

  # Validate certificate_arn format on listeners (ACM ARN or null); the
  # account check of the listener precondition reads the ARN's fifth field.
  validation {
    condition = alltrue(flatten([
      for lb in var.load_balancers : [
        for listener in lb.listeners :
        listener.certificate_arn == null || listener.certificate_arn == "" ||
        can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-zA-Z0-9-]+$", listener.certificate_arn))
      ]
    ]))
    error_message = "Each listener certificate_arn must be a valid ACM certificate ARN (arn:<partition>:acm:<region>:<account-id>:certificate/<id>) or null."
  }

  # Case-exact, like target_groups.protocol: the provider accepts "https", but
  # the default TLS policy (load-balancing.tf, default_ssl_policy) is only
  # applied to "HTTPS" and "TLS", so a lowercase spelling would keep the
  # service's older policy without saying so.
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
  # the load balancer is created.

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
}

variable "default_tags" {
  description = "Tags merged into every resource of the module."
  type        = map(string)
  default     = {}
}
