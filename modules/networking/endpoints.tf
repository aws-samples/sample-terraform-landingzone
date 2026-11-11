# =============================================================================
# Managed Prefix Lists
# =============================================================================

resource "aws_ec2_managed_prefix_list" "this" {
  for_each = {
    for pl in var.prefix_lists : pl.name => pl
  }

  name           = each.value.name
  address_family = each.value.address_family
  max_entries    = each.value.max_entries

  dynamic "entry" {
    for_each = each.value.entries
    content {
      cidr        = entry.value.cidr
      description = entry.value.description
    }
  }

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# =============================================================================
# VPC Endpoints — Gateway (S3, DynamoDB) + Interface
# =============================================================================

locals {
  # Flattened gateway endpoints: "vpc_name.service" → { vpc_name, service }
  # Per-service options attach by name (gateway_endpoint_options[service]);
  # a plain service entry without options gets a plain endpoint.
  gateway_endpoint_map = merge([
    for vpc in var.vpcs : {
      for svc in vpc.gateway_endpoints : "${vpc.name}.${svc}" => {
        vpc_name = vpc.name
        service  = svc
        service_name = (
          contains(keys(vpc.gateway_endpoint_options), svc)
          ? vpc.gateway_endpoint_options[svc].service_name
          : null
        )
        # Resolve policy — prefer the named policy, then the inline policy.
        # A named policy is looked up without a substitute value: an unknown name
        # must fail instead of silently producing an unrestricted endpoint.
        # variables.tf validates every policy_name against var.endpoint_policies.
        resolved_policy = (
          contains(keys(vpc.gateway_endpoint_options), svc) ? (
            vpc.gateway_endpoint_options[svc].policy_name != "" ? local.endpoint_policy_map[vpc.gateway_endpoint_options[svc].policy_name] :
            vpc.gateway_endpoint_options[svc].policy
          ) : ""
        )
      }
    }
  ]...)

  # Flattened interface endpoints: "vpc_name.service" → { vpc_name, service, subnet_names, policy }
  interface_endpoint_map = merge([
    for vpc in var.vpcs : {
      for ep in vpc.interface_endpoints : "${vpc.name}.${ep.service}" => {
        vpc_name     = vpc.name
        vpc_cidr     = vpc.cidr
        service      = ep.service
        subnet_names = ep.subnet_names
        tags         = ep.tags
        # Endpoint options: full service name, per-endpoint security group,
        # and the central-endpoint pattern (hosted zone + alias record).
        service_name     = ep.service_name
        security_group   = ep.security_group
        central          = ep.central
        hosted_zone_name = ep.hosted_zone_name
        # Resolve policy — prefer the named policy, then the inline policy.
        # A named policy is looked up without a substitute value: an unknown name
        # must fail instead of silently producing an unrestricted endpoint.
        # variables.tf validates every policy_name against var.endpoint_policies.
        resolved_policy = (
          ep.policy_name != "" ? local.endpoint_policy_map[ep.policy_name] :
          ep.policy != "" ? ep.policy : ""
        )
      }
    }
  ]...)

  # Named endpoint policy map for lookup
  endpoint_policy_map = {
    for ep in var.endpoint_policies : ep.name => ep.policy
  }

  # Private subnet keys per VPC (fallback when no subnet_names specified)
  private_subnet_keys_per_vpc = {
    for vpc in var.vpcs : vpc.name => [
      for s in vpc.subnets : "${vpc.name}.${s.name}"
      if s.type == "private"
    ]
  }

  # All route table IDs per VPC (for gateway endpoint associations)
  route_table_ids_per_vpc = {
    for vpc in var.vpcs : vpc.name => [
      for s in vpc.subnets : "${vpc.name}.${s.name}"
    ]
  }
}

# Gateway endpoints (S3, DynamoDB) — attach to route tables
resource "aws_vpc_endpoint" "gateway" {
  for_each = local.gateway_endpoint_map

  vpc_id = aws_vpc.this[each.value.vpc_name].id

  # The full service name from the options wins over the regional derivation —
  # special cases such as partner services carry names outside the
  # partition-derived pattern.
  service_name      = each.value.service_name != null ? each.value.service_name : "${local.endpoint_prefix}.${local.region}.${each.value.service}"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    for rt_key in local.route_table_ids_per_vpc[each.value.vpc_name] :
    aws_route_table.this[rt_key].id
  ]

  # Custom endpoint policy (if provided — supports inline or named policy)
  policy = each.value.resolved_policy != "" ? each.value.resolved_policy : null

  tags = {
    Name = "${each.value.vpc_name}-${each.value.service}-gw-endpoint"
  }
}

# Default security group for interface endpoints (HTTPS from VPC CIDR)
resource "aws_security_group" "interface_endpoint" {
  for_each = {
    for vpc in var.vpcs : vpc.name => vpc
    if length(vpc.interface_endpoints) > 0
  }

  name        = "${each.key}-interface-endpoints-sg"
  description = "Default SG for interface endpoints - allows HTTPS from VPC CIDR"
  vpc_id      = aws_vpc.this[each.key].id

  tags = {
    Name = "${each.key}-interface-endpoints-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "interface_endpoint_https" {
  for_each = {
    for vpc in var.vpcs : vpc.name => vpc
    if length(vpc.interface_endpoints) > 0
  }

  # cidr_ipv4 is the VPC's own CIDR: the configured one, or the range an IPAM
  # pool allocated (cidr is empty for an IPAM-fed VPC).
  security_group_id = aws_security_group.interface_endpoint[each.key].id
  cidr_ipv4         = aws_vpc.this[each.key].cidr_block
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from VPC CIDR"
}

# Interface endpoints — attach to subnets with security group
resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_map

  vpc_id = aws_vpc.this[each.value.vpc_name].id

  # The full service name from the entry wins over the regional derivation —
  # special cases such as partner services carry names outside the
  # partition-derived pattern.
  service_name      = each.value.service_name != null ? each.value.service_name : "${local.endpoint_prefix}.${local.region}.${each.value.service}"
  vpc_endpoint_type = "Interface"

  # A central endpoint leaves the service's private DNS name to its hosted
  # zone (see aws_route53_zone.central_endpoint below); every other endpoint
  # claims the name itself.
  private_dns_enabled = each.value.central ? false : true

  # Use specified subnets, or fall back to all private subnets
  subnet_ids = [
    for sk in(
      length(each.value.subnet_names) > 0
      ? [for sn in each.value.subnet_names : "${each.value.vpc_name}.${sn}"]
      : local.private_subnet_keys_per_vpc[each.value.vpc_name]
    ) : aws_subnet.this[sk].id
  ]

  # The per-endpoint security group replaces the module's default endpoint
  # security group; variables.tf checks the name against the VPC's
  # security_groups.
  security_group_ids = [
    each.value.security_group != ""
    ? aws_security_group.this["${each.value.vpc_name}.${each.value.security_group}"].id
    : aws_security_group.interface_endpoint[each.value.vpc_name].id
  ]

  # Custom endpoint policy (if provided — supports inline or named policy)
  policy = each.value.resolved_policy != "" ? each.value.resolved_policy : null

  tags = merge(each.value.tags, {
    Name = "${each.value.vpc_name}-${each.value.service}-if-endpoint"
  })
}

# =============================================================================
# Central Interface Endpoints — hosted zone and alias per endpoint
# =============================================================================

locals {
  # Central interface endpoints: "vpc_name.service" → endpoint definition
  central_endpoint_map = {
    for key, ep in local.interface_endpoint_map : key => ep
    if ep.central
  }

  # Consumers of the central endpoints: "endpoint_key.vpc_name" → the VPC that
  # is associated with that endpoint's private hosted zone. The endpoint's own
  # VPC is skipped — aws_route53_zone.central_endpoint already carries it in
  # its vpc block, and a second association of the same VPC would collide.
  central_endpoint_consumer_map = merge([
    for key, ep in local.central_endpoint_map : {
      for vpc in var.vpcs : "${key}.${vpc.name}" => {
        endpoint_key = key
        vpc_name     = vpc.name
      }
      if vpc.use_central_endpoints && vpc.name != ep.vpc_name
    }
  ]...)
}

# The zone carries the service's private DNS name (or the explicit
# hosted_zone_name) in the endpoint's VPC. Consumer VPCs resolve the service
# to the central endpoint once they are associated with the zone — in the same
# account through additional zone associations, across accounts through the
# association authorization pattern of route53_zones.
resource "aws_route53_zone" "central_endpoint" {
  for_each = local.central_endpoint_map

  name = each.value.hosted_zone_name != null ? each.value.hosted_zone_name : "${each.value.service}.${local.region}.${local.dns_suffix}"

  vpc {
    vpc_id = aws_vpc.this[each.value.vpc_name].id
  }

  tags = {
    Name = "${each.value.vpc_name}-${each.value.service}-central-endpoint"
  }
}

# The apex alias points the zone at the endpoint's regional DNS name; target
# health evaluation keeps resolution honest when the endpoint loses subnets.
resource "aws_route53_record" "central_endpoint" {
  for_each = local.central_endpoint_map

  zone_id = aws_route53_zone.central_endpoint[each.key].zone_id
  name    = aws_route53_zone.central_endpoint[each.key].name
  type    = "A"

  alias {
    name                   = aws_vpc_endpoint.interface[each.key].dns_entry[0].dns_name
    zone_id                = aws_vpc_endpoint.interface[each.key].dns_entry[0].hosted_zone_id
    evaluate_target_health = true
  }
}

# A VPC with use_central_endpoints resolves every central endpoint through its
# zone. Consumers in other accounts go through the authorization pattern of
# route53_zones instead — an association across accounts needs a provider in
# the consuming account.
resource "aws_route53_zone_association" "central_endpoint" {
  for_each = local.central_endpoint_consumer_map

  zone_id = aws_route53_zone.central_endpoint[each.value.endpoint_key].zone_id
  vpc_id  = aws_vpc.this[each.value.vpc_name].id
}

# =============================================================================
# Gateway Load Balancers
# =============================================================================

locals {
  # Map: gwlb_name → gwlb definition
  gwlb_map = {
    for gwlb in var.gateway_load_balancers : gwlb.name => gwlb
  }

  # Flattened consumer endpoints: "gwlb_name.consumer_vpc_name" → { gwlb_name, vpc_name, subnet_names }
  gwlb_consumer_endpoint_map = merge([
    for gwlb in var.gateway_load_balancers : {
      for consumer in gwlb.endpoint_consumers : "${gwlb.name}.${consumer.vpc_name}" => {
        gwlb_name    = gwlb.name
        vpc_name     = consumer.vpc_name
        subnet_names = consumer.subnet_names
      }
    }
  ]...)

  # VPC template expansion: "account_name.vpc_template_name" → resolved template
  vpc_template_expanded = merge([
    for tpl in var.vpc_templates : {
      for account_name in tpl.deployment_targets : "${account_name}.${tpl.name}" => {
        template_name = tpl.name
        account_name  = account_name
        account_id    = lookup(var.account_ids, account_name, "")
        cidr          = tpl.cidr
        subnets       = tpl.subnets
      }
    }
  ]...)
}

resource "aws_lb" "gwlb" {
  for_each = local.gwlb_map

  name               = each.value.name
  load_balancer_type = "gateway"
  internal           = false

  # A central inspection LB must not disappear through an accidental destroy;
  # deleting it requires disabling the protection first (see README, section
  # "Deletion protection"). The default of the attribute is true.
  enable_deletion_protection = each.value.deletion_protection

  # Without cross-zone, the failure of the last healthy appliance in one AZ
  # breaks that AZ's traffic path even while other AZs have healthy targets.
  # The resilience of central inspection outweighs the cross-AZ data cost, so
  # the default is true and a validation refuses false wherever another VPC
  # consumes this load balancer.
  enable_cross_zone_load_balancing = each.value.cross_zone_load_balancing

  subnets = [
    for sn in each.value.subnet_names :
    aws_subnet.this["${each.value.vpc_name}.${sn}"].id
  ]

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

resource "aws_lb_target_group" "gwlb" {
  for_each = local.gwlb_map

  name     = each.value.target_group.name
  port     = each.value.target_group.port
  protocol = each.value.target_group.protocol
  vpc_id   = aws_vpc.this[each.value.vpc_name].id

  health_check {
    port     = each.value.target_group.health_check.port
    protocol = each.value.target_group.health_check.protocol
  }

  tags = {
    Name = each.value.target_group.name
  }
}

resource "aws_lb_listener" "gwlb" {
  for_each = local.gwlb_map

  load_balancer_arn = aws_lb.gwlb[each.key].arn

  # The TCP idle timeout of a Gateway Load Balancer is an attribute of its
  # listener, not of the load balancer. null leaves it unset and the service
  # keeps its own default of 350 seconds.
  tcp_idle_timeout_seconds = each.value.tcp_idle_timeout

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gwlb[each.key].arn
  }

  tags = {
    Name = "${each.key}-listener"
  }
}

resource "aws_vpc_endpoint_service" "gwlb" {
  for_each = local.gwlb_map

  # Whether endpoint requests must be accepted manually is a per-deployment
  # control decision; the default false keeps automated spoke onboarding
  # working (see variables.tf, gateway_load_balancers.acceptance_required).
  acceptance_required        = each.value.acceptance_required
  gateway_load_balancer_arns = [aws_lb.gwlb[each.key].arn]

  tags = {
    Name = "${each.key}-endpoint-service"
  }
}

resource "aws_vpc_endpoint" "gwlb_consumer" {
  for_each = local.gwlb_consumer_endpoint_map

  vpc_id            = aws_vpc.this[each.value.vpc_name].id
  service_name      = aws_vpc_endpoint_service.gwlb[each.value.gwlb_name].service_name
  vpc_endpoint_type = "GatewayLoadBalancer"

  subnet_ids = [
    for sn in each.value.subnet_names :
    aws_subnet.this["${each.value.vpc_name}.${sn}"].id
  ]

  tags = {
    Name = "${each.key}-gwlb-endpoint"
  }
}

# =============================================================================
# VPC Templates Cross-Account Check
# =============================================================================

check "vpc_templates_cross_account" {
  assert {
    condition = alltrue([
      for tpl in var.vpc_templates : alltrue([
        for account_name in tpl.deployment_targets :
        contains(keys(var.account_ids), account_name)
      ])
    ])
    error_message = "VPC Templates reference accounts not found in account_ids. Cross-account VPC deployment requires static provider aliases for each target account. Ensure all deployment_targets are present in account_ids or configure providers manually."
  }
}

# =============================================================================
# ALB/NLB Load Balancers
# =============================================================================

locals {
  load_balancer_map = {
    for lb in var.load_balancers : lb.name => lb
  }
}

resource "aws_lb" "this" {
  for_each = local.load_balancer_map

  name               = each.value.name
  load_balancer_type = each.value.type
  internal           = each.value.scheme == "internal"

  # Workload entry points must not disappear through an accidental destroy;
  # deleting one requires disabling the protection first (see README, section
  # "Deletion protection").
  enable_deletion_protection = true

  # Dropping malformed HTTP headers is the recommended hardening against
  # request-smuggling/desync attacks. The attribute only acts on application
  # load balancers; network load balancers ignore it.
  drop_invalid_header_fields = true

  # Every attribute below is null unless the entry sets it, so the load
  # balancing service keeps applying its own default. The HTTP attributes
  # are rejected in the plan on a network load balancer (see variables.tf,
  # load_balancers), which is why they can be passed unconditionally here.
  idle_timeout                                = each.value.idle_timeout
  enable_http2                                = each.value.enable_http2
  desync_mitigation_mode                      = each.value.desync_mitigation_mode
  enable_xff_client_port                      = each.value.enable_xff_client_port
  xff_header_processing_mode                  = each.value.xff_header_processing_mode
  enable_tls_version_and_cipher_suite_headers = each.value.enable_tls_headers
  enable_waf_fail_open                        = each.value.enable_waf_fail_open
  enable_cross_zone_load_balancing            = each.value.enable_cross_zone_load_balancing

  subnets = [
    for sn in each.value.subnet_names :
    aws_subnet.this["${each.value.vpc_name}.${sn}"].id
  ]

  security_groups = each.value.type == "application" && length(each.value.security_groups) > 0 ? [
    for sg_name in each.value.security_groups :
    aws_security_group.this["${each.value.vpc_name}.${sg_name}"].id
  ] : null

  dynamic "access_logs" {
    for_each = each.value.access_logs != null ? [each.value.access_logs] : []
    content {
      bucket  = access_logs.value.bucket
      prefix  = access_logs.value.prefix
      enabled = access_logs.value.enabled
    }
  }

  tags = {
    Name = each.key
  }
}

# =============================================================================
# Target Groups
# =============================================================================

locals {
  target_group_map = {
    for tg in var.target_groups : tg.name => tg
  }
}

resource "aws_lb_target_group" "this" {
  for_each = local.target_group_map

  name        = each.value.name
  port        = each.value.port
  protocol    = each.value.protocol
  vpc_id      = aws_vpc.this[each.value.vpc_name].id
  target_type = each.value.target_type

  # Every attribute below is null unless the entry sets it, so the load
  # balancing service keeps applying its own default.
  deregistration_delay          = each.value.deregistration_delay
  slow_start                    = each.value.slow_start
  load_balancing_algorithm_type = each.value.algorithm
  protocol_version              = each.value.protocol_version
  proxy_protocol_v2             = each.value.proxy_protocol_v2
  connection_termination        = each.value.connection_termination

  # The API models client IP preservation as a string because its default
  # depends on the protocol; the entry states it as a boolean.
  preserve_client_ip = each.value.preserve_client_ip == null ? null : tostring(each.value.preserve_client_ip)

  dynamic "stickiness" {
    for_each = each.value.stickiness != null ? [each.value.stickiness] : []
    content {
      type            = stickiness.value.type
      enabled         = stickiness.value.enabled
      cookie_duration = stickiness.value.cookie_duration
      cookie_name     = stickiness.value.cookie_name
    }
  }

  # AWS requires the same decision for both transitions, so one entry value
  # covers deregistration and unhealthy targets alike.
  dynamic "target_failover" {
    for_each = each.value.target_failover != null ? [each.value.target_failover] : []
    content {
      on_deregistration = target_failover.value
      on_unhealthy      = target_failover.value
    }
  }

  health_check {
    enabled             = each.value.health_check.enabled
    path                = each.value.health_check.path
    port                = each.value.health_check.port
    protocol            = each.value.health_check.protocol
    healthy_threshold   = each.value.health_check.healthy_threshold
    unhealthy_threshold = each.value.health_check.unhealthy_threshold
    interval            = each.value.health_check.interval
    timeout             = each.value.health_check.timeout
    matcher             = each.value.health_check.matcher
  }

  tags = {
    Name = each.key
  }
}

# =============================================================================
# LB Listeners
# =============================================================================

locals {
  # A TLS listener that names no policy would otherwise get the ELB default
  # ELBSecurityPolicy-2016-08, which still negotiates TLS 1.0 and 1.1. The
  # module names a TLS-1.2-minimum policy instead; both ALB and NLB accept it.
  # An entry that names its own ssl_policy keeps it, unchanged.
  default_ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  lb_listener_map = merge([
    for lb in var.load_balancers : {
      for idx, listener in lb.listeners : "${lb.name}.${listener.port}" => {
        lb_name           = lb.name
        port              = listener.port
        protocol          = listener.protocol
        target_group_name = listener.target_group_name
        # null stays null on every non-TLS protocol, where the attribute is
        # not valid at all.
        ssl_policy = (
          listener.ssl_policy != null ? listener.ssl_policy :
          contains(["HTTPS", "TLS"], listener.protocol) ? local.default_ssl_policy : null
        )
        certificate_arn = listener.certificate_arn
        alpn_policy     = listener.alpn_policy

        # The listener action, flattened so the resource reads the same whether
        # the entry names an action or not. A listener without an action block
        # forwards to target_group_name.
        action_type           = listener.action == null ? "forward" : listener.action.type
        action_order          = listener.action == null ? null : listener.action.order
        action_target_groups  = listener.action == null ? [] : listener.action.target_groups
        action_stickiness     = listener.action == null ? null : listener.action.stickiness
        action_fixed_response = listener.action == null ? null : listener.action.fixed_response
        action_redirect       = listener.action == null ? null : listener.action.redirect

        # The authenticated edge, null on a listener that declares none. With an
        # edge the listener's own action moves to position 2: an explicit
        # action.order is kept (the validation holds it at 2 or more), null
        # becomes 2 so the chain is stated rather than left to the provider's
        # positional default.
        edge = listener.authenticated_edge
        edge_action_order = (
          listener.authenticated_edge == null ? (listener.action == null ? null : listener.action.order) :
          listener.action == null || listener.action.order == null ? 2 : listener.action.order
        )
      }
    }
  ]...)

  # Listeners whose edge names its client secret by ARN: the module reads the
  # secret so the value never appears in configuration. A listener that hands
  # the value in through client_secret causes no read.
  lb_edge_client_secret_arns = {
    for key, listener in local.lb_listener_map : key => listener.edge.client_secret_arn
    if listener.edge != null && listener.edge.client_secret_arn != null && listener.edge.client_secret_arn != ""
  }
}

# The current version of each named secret; its secret string is the OIDC
# client secret. Read at plan time, so the planning identity needs
# secretsmanager:GetSecretValue on these ARNs. The value is sensitive on the
# listener as well; Terraform state stores what the load balancing API
# receives, so the state backend's encryption is the protection boundary —
# the same statement the module makes for acm_certificate_material.
data "aws_secretsmanager_secret_version" "lb_edge_client_secret" {
  for_each = local.lb_edge_client_secret_arns

  secret_id = each.value
}

resource "aws_lb_listener" "this" {
  for_each = local.lb_listener_map

  load_balancer_arn = aws_lb.this[each.value.lb_name].arn
  port              = each.value.port
  protocol          = each.value.protocol
  ssl_policy        = each.value.ssl_policy
  certificate_arn   = each.value.certificate_arn
  alpn_policy       = each.value.alpn_policy

  # The authenticated edge first, when the listener declares one: position 1 of
  # the chain, so every caller is authenticated against the OpenID Connect
  # provider before the listener's own action below runs. Which client secret
  # is used follows from the entry: the string handed in, or the secret string
  # read from Secrets Manager for this listener. A request without a session
  # is redirected to the provider — the module writes "authenticate" and never
  # "allow" here, an edge that lets anonymous callers through is no edge.
  dynamic "default_action" {
    for_each = each.value.edge != null ? [each.value.edge] : []
    content {
      type  = "authenticate-oidc"
      order = 1
      authenticate_oidc {
        issuer                 = default_action.value.issuer
        authorization_endpoint = default_action.value.authorization_endpoint
        token_endpoint         = default_action.value.token_endpoint
        user_info_endpoint     = default_action.value.user_info_endpoint
        client_id              = default_action.value.client_id
        client_secret = (
          default_action.value.client_secret != null && default_action.value.client_secret != "" ?
          default_action.value.client_secret :
          data.aws_secretsmanager_secret_version.lb_edge_client_secret[each.key].secret_string
        )
        scope           = default_action.value.scope
        session_timeout = default_action.value.session_timeout
        # The promise is written, not inherited: a request without a session
        # is always sent to the provider to log in, whatever the default says.
        on_unauthenticated_request = "authenticate"
      }
    }
  }

  # Exactly one of the four blocks below produces an element, chosen by
  # action_type and — for forwarding — by whether the entry names a weighted
  # target group list. Behind an edge it is position 2 (edge_action_order);
  # without one its order is the entry's own, null included.

  # Single destination: target_group_arn rather than a forward block, so a
  # listener without an action block plans a plain forward.
  dynamic "default_action" {
    for_each = each.value.action_type == "forward" && length(each.value.action_target_groups) == 0 ? [1] : []
    content {
      type             = "forward"
      order            = each.value.edge_action_order
      target_group_arn = aws_lb_target_group.this[each.value.target_group_name].arn
    }
  }

  dynamic "default_action" {
    for_each = each.value.action_type == "forward" && length(each.value.action_target_groups) > 0 ? [1] : []
    content {
      type  = "forward"
      order = each.value.edge_action_order
      forward {
        dynamic "target_group" {
          for_each = each.value.action_target_groups
          content {
            arn    = aws_lb_target_group.this[target_group.value.target_group_name].arn
            weight = target_group.value.weight
          }
        }
        dynamic "stickiness" {
          for_each = each.value.action_stickiness != null ? [each.value.action_stickiness] : []
          content {
            enabled  = stickiness.value.enabled
            duration = stickiness.value.duration
          }
        }
      }
    }
  }

  dynamic "default_action" {
    for_each = each.value.action_type == "fixed-response" && each.value.action_fixed_response != null ? [each.value.action_fixed_response] : []
    content {
      type  = "fixed-response"
      order = each.value.edge_action_order
      fixed_response {
        status_code  = default_action.value.status_code
        content_type = default_action.value.content_type
        message_body = default_action.value.message_body
      }
    }
  }

  dynamic "default_action" {
    for_each = each.value.action_type == "redirect" && each.value.action_redirect != null ? [each.value.action_redirect] : []
    content {
      type  = "redirect"
      order = each.value.edge_action_order
      redirect {
        status_code = default_action.value.status_code
        host        = default_action.value.host
        path        = default_action.value.path
        port        = default_action.value.port
        protocol    = default_action.value.protocol
        query       = default_action.value.query
      }
    }
  }

  tags = {
    Name = each.key
  }
}
