# =============================================================================
# Target groups, internal load balancers and listeners of the workload account
# =============================================================================

locals {
  target_group_map = {
    for tg in local.target_groups : tg.name => tg
  }

  load_balancer_map = {
    for lb in local.load_balancers : lb.name => lb
  }

  # A TLS listener that names no policy would otherwise get the ELB default
  # ELBSecurityPolicy-2016-08, which still negotiates TLS 1.0 and 1.1. The
  # module names a TLS-1.2-minimum policy instead, the same default as
  # modules/networking; both ALB and NLB accept it. An entry that names its
  # own ssl_policy keeps it, unchanged.
  default_ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  lb_listener_map = merge([
    for lb in local.load_balancers : {
      for listener in lb.listeners : "${lb.name}.${listener.port}" => {
        lb_name      = lb.name
        port         = listener.port
        protocol     = listener.protocol
        target_group = listener.target_group
        # null stays null on every non-TLS protocol, where the attribute is
        # not valid at all.
        ssl_policy = (
          listener.ssl_policy != null ? listener.ssl_policy :
          contains(["HTTPS", "TLS"], listener.protocol) ? local.default_ssl_policy : null
        )
        certificate_arn = listener.certificate_arn
      }
    }
  ]...)
}

# -----------------------------------------------------------------------------
# Target groups — target_type instance, the type an auto-scaling group attaches to
# -----------------------------------------------------------------------------

resource "aws_lb_target_group" "this" {
  for_each = local.target_group_map

  name        = each.value.name
  port        = each.value.port
  protocol    = each.value.protocol
  vpc_id      = lookup(var.vpc_ids, each.value.vpc_name, "")
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

  tags = merge(var.default_tags, {
    Name = each.key
  })

  lifecycle {
    precondition {
      condition     = contains(keys(var.vpc_ids), each.value.vpc_name)
      error_message = "Target group ${each.key}: vpc_name ${each.value.vpc_name} is not a key of vpc_ids — the management networking stack supplies that map (vpc name to VPC ID)."
    }
  }
}

# -----------------------------------------------------------------------------
# Load balancers — internal, in the shared subnets
# -----------------------------------------------------------------------------

resource "aws_lb" "this" {
  for_each = local.load_balancer_map

  name               = each.value.name
  load_balancer_type = each.value.type
  # scheme is validated to "internal" (variables.tf): the public entry point
  # with its authenticated edge stays in the management networking module.
  internal = true

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

  # The shared subnets, resolved as vpc_name.subnet_name against the
  # management networking output.
  subnets = [
    for sn in each.value.subnet_names :
    lookup(var.subnet_ids, "${each.value.vpc_name}.${sn}", "")
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

  tags = merge(var.default_tags, {
    Name = each.key
  })

  lifecycle {
    precondition {
      condition     = contains(keys(var.vpc_ids), each.value.vpc_name)
      error_message = "Load balancer ${each.key}: vpc_name ${each.value.vpc_name} is not a key of vpc_ids — the management networking stack supplies that map (vpc name to VPC ID)."
    }
    precondition {
      condition = alltrue([
        for sn in each.value.subnet_names : contains(keys(var.subnet_ids), "${each.value.vpc_name}.${sn}")
      ])
      error_message = "Load balancer ${each.key}: a subnet_names entry is not a key of subnet_ids as ${each.value.vpc_name}.<subnet> — the management networking stack supplies that map (vpc_name.subnet_name); only a subnet shared with this account resolves."
    }
  }
}

# -----------------------------------------------------------------------------
# Listeners — each forwards to one target group of this module
# -----------------------------------------------------------------------------

resource "aws_lb_listener" "this" {
  for_each = local.lb_listener_map

  load_balancer_arn = aws_lb.this[each.value.lb_name].arn
  port              = each.value.port
  protocol          = each.value.protocol
  ssl_policy        = each.value.ssl_policy
  certificate_arn   = each.value.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[each.value.target_group].arn
  }

  tags = var.default_tags

  lifecycle {
    precondition {
      condition     = contains(keys(local.target_group_map), each.value.target_group)
      error_message = "Listener ${each.key}: target_group ${each.value.target_group} is not an entry of target_groups — a listener of this module forwards to a target group of this module only."
    }
    # A certificate of another account cannot be attached: ACM certificates are
    # account-bound, and the load balancing API refuses the listener at apply.
    precondition {
      condition = (
        each.value.certificate_arn == null || each.value.certificate_arn == ""
        || try(split(":", each.value.certificate_arn)[4], "") == data.aws_caller_identity.current.account_id
      )
      error_message = "Listener ${each.key}: certificate_arn belongs to account ${try(split(":", each.value.certificate_arn)[4], "?")}, not to this account (${data.aws_caller_identity.current.account_id}) — request or import the certificate in the workload account and name that ARN."
    }
  }
}
