# =============================================================================
# Route 53 Private Hosted Zones
# =============================================================================

resource "aws_route53_zone" "private" {
  for_each = {
    for zone in var.route53_zones : zone.name => zone
  }

  name = each.key

  # Associate with all VPCs (dynamic)
  dynamic "vpc" {
    for_each = length(each.value.vpc_ids) > 0 ? each.value.vpc_ids : [
      for vpc_name, vpc_res in aws_vpc.this : vpc_res.id
    ]
    content {
      vpc_id = vpc.value
    }
  }

  tags = {
    Name = each.key
  }
}

# Zone-scoped Route 53 Resolver Rules — forwarded through an outbound endpoint
resource "aws_route53_resolver_rule" "this" {
  for_each = merge([
    for zone in var.route53_zones : {
      for rule in zone.resolver_rules : "${zone.name}-${rule.domain_name}" => {
        domain_name            = rule.domain_name
        target_ips             = rule.target_ips
        resolver_endpoint_name = rule.resolver_endpoint_name
      }
    }
  ]...)

  domain_name = each.value.domain_name
  rule_type   = "FORWARD"
  name        = replace(each.key, ".", "-")

  # A FORWARD rule is only accepted with an outbound endpoint; the endpoint name
  # is validated against resolver_endpoints in variables.tf
  resolver_endpoint_id = aws_route53_resolver_endpoint.this[each.value.resolver_endpoint_name].id

  dynamic "target_ip" {
    for_each = each.value.target_ips
    content {
      ip = target_ip.value
    }
  }

  tags = {
    Name = each.key
  }
}

# =============================================================================
# Route53 DNS Firewall
# =============================================================================

locals {
  # Map: rule_group_name → rule group definition
  dns_firewall_rule_group_map = {
    for rg in var.dns_firewall_rule_groups : rg.name => rg
  }

  # Flattened rules: "group_name.rule_name" → rule definition + group_name
  dns_firewall_rule_map = merge([
    for rg in var.dns_firewall_rule_groups : {
      for rule in rg.rules : "${rg.name}.${rule.name}" => {
        group_name              = rg.name
        name                    = rule.name
        priority                = rule.priority
        action                  = rule.action
        domain_list_id          = rule.domain_list_id
        custom_domain_list_name = rule.custom_domain_list_name
        block_response          = rule.block_response
        block_override_domain   = rule.block_override_domain
        block_override_ttl      = rule.block_override_ttl
      }
    }
  ]...)

  # Flattened associations: "group_name.vpc_name" → { group_name, vpc_name }
  dns_firewall_association_map = merge([
    for rg in var.dns_firewall_rule_groups : {
      for vpc_name in rg.vpc_names : "${rg.name}.${vpc_name}" => {
        group_name = rg.name
        vpc_name   = vpc_name
        # Mutation protection is a property of this one association; a VPC
        # without an entry keeps the service default (DISABLED).
        mutation_protection = lookup(rg.mutation_protection, vpc_name, null)
      }
    }
  ]...)

  # Flattened custom domain lists: "group_name.domain_list_name" → { group_name, name, domains }
  dns_firewall_domain_list_map = merge([
    for rg in var.dns_firewall_rule_groups : {
      for dl in rg.custom_domain_lists : "${rg.name}.${dl.name}" => {
        group_name = rg.name
        name       = dl.name
        domains    = dl.domains
      }
    }
  ]...)

  # Rule groups that have share_targets: group_name → rule group definition
  dns_firewall_share_map = var.enable_ram_sharing ? {
    for rg in var.dns_firewall_rule_groups : rg.name => rg
    if length(rg.share_targets) > 0
  } : {}

  # Flattened principal associations for DNS firewall RAM shares: "group_name.target" → { group_name, account_id }
  dns_firewall_share_principal_map = var.enable_ram_sharing ? merge([
    for rg in var.dns_firewall_rule_groups : {
      for target in rg.share_targets : "${rg.name}.${target}" => {
        group_name = rg.name
        account_id = lookup(var.account_ids, target, target)
      }
    } if length(rg.share_targets) > 0
  ]...) : {}
}

resource "aws_route53_resolver_firewall_rule_group" "this" {
  for_each = local.dns_firewall_rule_group_map

  name = each.key

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

resource "aws_route53_resolver_firewall_rule" "this" {
  for_each = local.dns_firewall_rule_map

  name   = each.value.name
  action = each.value.action

  # Resolve domain list ID: prefer custom domain list by name, fall back to explicit domain_list_id
  firewall_domain_list_id = (
    each.value.custom_domain_list_name != ""
    ? aws_route53_resolver_firewall_domain_list.this["${each.value.group_name}.${each.value.custom_domain_list_name}"].id
    : each.value.domain_list_id
  )

  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.this[each.value.group_name].id
  priority               = each.value.priority

  block_response = each.value.action == "BLOCK" ? each.value.block_response : null

  block_override_domain   = each.value.action == "BLOCK" && each.value.block_response == "OVERRIDE" ? each.value.block_override_domain : null
  block_override_dns_type = each.value.action == "BLOCK" && each.value.block_response == "OVERRIDE" ? "CNAME" : null
  block_override_ttl      = each.value.action == "BLOCK" && each.value.block_response == "OVERRIDE" ? each.value.block_override_ttl : null
}

resource "aws_route53_resolver_firewall_rule_group_association" "this" {
  for_each = local.dns_firewall_association_map

  name                   = "${each.value.group_name}-${each.value.vpc_name}"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.this[each.value.group_name].id
  vpc_id                 = aws_vpc.this[each.value.vpc_name].id
  priority               = 100 + index(var.dns_firewall_rule_groups[index(var.dns_firewall_rule_groups.*.name, each.value.group_name)].vpc_names, each.value.vpc_name)

  # ENABLED locks this one association against modification and removal until
  # it is switched off again; null leaves the service default (DISABLED)
  # untouched.
  mutation_protection = each.value.mutation_protection

  tags = {
    Name = each.key
  }
}

# --- DNS Firewall Custom Domain Lists ---
resource "aws_route53_resolver_firewall_domain_list" "this" {
  for_each = local.dns_firewall_domain_list_map

  name    = each.value.name
  domains = each.value.domains

  tags = {
    Name = each.value.name
  }
}

# --- RAM Sharing for DNS Firewall Rule Groups ---
resource "aws_ram_resource_share" "dns_firewall" {
  for_each = local.dns_firewall_share_map

  name                      = "${each.key}-dns-firewall-share"
  allow_external_principals = false

  tags = {
    Name = "${each.key}-dns-firewall-share"
  }
}

resource "aws_ram_resource_association" "dns_firewall" {
  for_each = local.dns_firewall_share_map

  resource_arn       = aws_route53_resolver_firewall_rule_group.this[each.key].arn
  resource_share_arn = aws_ram_resource_share.dns_firewall[each.key].arn
}

resource "aws_ram_principal_association" "dns_firewall" {
  for_each = local.dns_firewall_share_principal_map

  principal          = each.value.account_id
  resource_share_arn = aws_ram_resource_share.dns_firewall[each.value.group_name].arn
}

# =============================================================================
# Route53 Query Logging
# =============================================================================

locals {
  # Exactly one toggle switches query logging.
  dns_query_logging_enabled = var.enable_route53_query_logging

  # VPCs to associate with query logging
  query_logging_vpc_names = local.dns_query_logging_enabled ? (
    length(var.route53_query_logging_vpc_names) > 0
    ? var.route53_query_logging_vpc_names
    : [for vpc in var.vpcs : vpc.name]
  ) : []

  query_logging_vpc_map = {
    for vpc_name in local.query_logging_vpc_names : vpc_name => vpc_name
  }

  # Destination ARN: CloudWatch Log Group or S3 bucket
  query_logging_destination_arn = local.dns_query_logging_enabled ? (
    var.route53_query_logging_destination == "s3"
    ? "arn:${local.partition}:s3:::${var.central_log_bucket_name}"
    : aws_cloudwatch_log_group.query_logging[0].arn
  ) : ""
}

# CloudWatch Log Group — only when destination is cloudwatch
resource "aws_cloudwatch_log_group" "query_logging" {
  count = local.dns_query_logging_enabled && var.route53_query_logging_destination == "cloudwatch" ? 1 : 0

  name = "/aws/route53/${data.aws_caller_identity.current.account_id}/query-logs"
  # 365 days matches the retention baseline the project applies to its other
  # log groups (configurations/base/base.tfvars); long-term storage beyond
  # that lives in the central S3 log bucket.
  retention_in_days = 365
  kms_key_id        = var.cloudwatch_logs_kms_key_arn != "" ? var.cloudwatch_logs_kms_key_arn : null

  tags = {
    Name = "route53-query-logs"
  }
}

resource "aws_route53_resolver_query_log_config" "this" {
  count = local.dns_query_logging_enabled ? 1 : 0

  name            = "tlz-route53-query-logging"
  destination_arn = local.query_logging_destination_arn

  tags = {
    Name = "tlz-route53-query-logging"
  }
}

resource "aws_route53_resolver_query_log_config_association" "this" {
  for_each = local.query_logging_vpc_map

  resolver_query_log_config_id = aws_route53_resolver_query_log_config.this[0].id
  resource_id                  = aws_vpc.this[each.value].id
}

# --- RAM Sharing for the query logging configuration ---

locals {
  query_logging_share_targets = var.enable_ram_sharing && local.dns_query_logging_enabled ? var.route53_query_logging_share_targets : []

  query_logging_share_principal_map = {
    for target in local.query_logging_share_targets : target => lookup(var.account_ids, target, target)
  }
}

resource "aws_ram_resource_share" "query_logs" {
  count = length(local.query_logging_share_targets) > 0 ? 1 : 0

  name                      = "tlz-route53-query-logging-share"
  allow_external_principals = false

  tags = {
    Name = "tlz-route53-query-logging-share"
  }
}

resource "aws_ram_resource_association" "query_logs" {
  count = length(local.query_logging_share_targets) > 0 ? 1 : 0

  resource_arn       = aws_route53_resolver_query_log_config.this[0].arn
  resource_share_arn = aws_ram_resource_share.query_logs[0].arn
}

resource "aws_ram_principal_association" "query_logs" {
  for_each = local.query_logging_share_principal_map

  principal          = each.value
  resource_share_arn = aws_ram_resource_share.query_logs[0].arn
}

# =============================================================================
# Route53 Resolver Endpoints
# =============================================================================

locals {
  # Map: endpoint_name → endpoint definition
  resolver_endpoint_map = {
    for ep in var.resolver_endpoints : ep.name => ep
  }

  # Endpoints that need an auto-created security group (no user-provided SG IDs)
  resolver_endpoint_auto_sg_map = {
    for ep in var.resolver_endpoints : ep.name => ep
    if length(ep.security_group_ids) == 0
  }

  # Flattened allowed CIDRs for auto-created SGs: "endpoint_name.idx" → { endpoint_name, cidr }
  # When allowed_cidrs is empty, use VPC CIDR as default
  resolver_endpoint_ingress_cidrs = merge([
    for ep_name, ep in local.resolver_endpoint_auto_sg_map : {
      for idx, cidr in(length(ep.allowed_cidrs) > 0 ? ep.allowed_cidrs : [aws_vpc.this[ep.vpc_name].cidr_block]) :
      "${ep_name}.${idx}" => {
        endpoint_name = ep_name
        cidr          = cidr
      }
    }
  ]...)

  # Flattened resolver rules for OUTBOUND endpoints: "endpoint_name.domain_name" → rule
  resolver_endpoint_rule_map = merge([
    for ep in var.resolver_endpoints : {
      for rule in ep.resolver_rules : "${ep.name}.${rule.domain_name}" => {
        endpoint_name = ep.name
        domain_name   = rule.domain_name
        target_ips    = rule.target_ips
        tags          = rule.tags
      }
    } if ep.direction == "OUTBOUND"
  ]...)

  # Flattened VPC associations for endpoint resolver rules: "endpoint_name.domain_name.vpc_name" → { rule_key, vpc_name }
  resolver_endpoint_rule_vpc_map = merge([
    for ep in var.resolver_endpoints : merge([
      for rule in ep.resolver_rules : {
        for vpc_name in rule.vpc_names : "${ep.name}.${rule.domain_name}.${vpc_name}" => {
          rule_key = "${ep.name}.${rule.domain_name}"
          vpc_name = vpc_name
        }
      }
    ]...)
    if ep.direction == "OUTBOUND"
  ]...)

  # Endpoint resolver rules that have share_targets: "endpoint_name.domain_name" → rule
  resolver_endpoint_rule_share_map = var.enable_ram_sharing ? merge([
    for ep in var.resolver_endpoints : {
      for rule in ep.resolver_rules : "${ep.name}.${rule.domain_name}" => {
        endpoint_name = ep.name
        domain_name   = rule.domain_name
        share_targets = rule.share_targets
      }
      if length(rule.share_targets) > 0
    } if ep.direction == "OUTBOUND"
  ]...) : {}

  # Flattened principal associations for endpoint resolver rule shares: "endpoint_name.domain_name.target" → { rule_key, account_id }
  resolver_endpoint_rule_share_principal_map = var.enable_ram_sharing ? merge([
    for rule_key, rule in local.resolver_endpoint_rule_share_map : {
      for target in rule.share_targets : "${rule_key}.${target}" => {
        rule_key   = rule_key
        account_id = lookup(var.account_ids, target, target)
      }
    }
  ]...) : {}
}

# --- Security Group per Resolver Endpoint (DNS port 53 TCP/UDP) ---
# Only created when no user-provided security_group_ids are specified
resource "aws_security_group" "resolver_endpoint" {
  for_each = local.resolver_endpoint_auto_sg_map

  name        = "${each.key}-resolver-sg"
  description = "Security group for Route53 Resolver Endpoint ${each.key}"
  vpc_id      = aws_vpc.this[each.value.vpc_name].id

  tags = {
    Name = "${each.key}-resolver-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "resolver_dns_udp" {
  for_each = local.resolver_endpoint_ingress_cidrs

  security_group_id = aws_security_group.resolver_endpoint[each.value.endpoint_name].id
  cidr_ipv4         = each.value.cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "DNS UDP from ${each.value.cidr}"
}

resource "aws_vpc_security_group_ingress_rule" "resolver_dns_tcp" {
  for_each = local.resolver_endpoint_ingress_cidrs

  security_group_id = aws_security_group.resolver_endpoint[each.value.endpoint_name].id
  cidr_ipv4         = each.value.cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  description       = "DNS TCP from ${each.value.cidr}"
}

resource "aws_vpc_security_group_egress_rule" "resolver_all" {
  for_each = local.resolver_endpoint_auto_sg_map

  security_group_id = aws_security_group.resolver_endpoint[each.key].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Allow all outbound"
}

# --- Resolver Endpoints ---
resource "aws_route53_resolver_endpoint" "this" {
  for_each = local.resolver_endpoint_map

  name      = each.key
  direction = each.value.direction

  # Use user-provided SG IDs if specified, otherwise use the auto-created SG
  security_group_ids = length(each.value.security_group_ids) > 0 ? each.value.security_group_ids : [
    aws_security_group.resolver_endpoint[each.key].id
  ]

  # Optional resolver protocols (DoH, DoH-FIPS, Do53)
  protocols = length(each.value.protocols) > 0 ? each.value.protocols : null

  dynamic "ip_address" {
    for_each = each.value.subnet_names
    content {
      subnet_id = aws_subnet.this["${each.value.vpc_name}.${ip_address.value}"].id
    }
  }

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- Resolver Rules for OUTBOUND endpoints ---
resource "aws_route53_resolver_rule" "endpoint" {
  for_each = local.resolver_endpoint_rule_map

  domain_name          = each.value.domain_name
  rule_type            = "FORWARD"
  name                 = replace(each.key, ".", "-")
  resolver_endpoint_id = aws_route53_resolver_endpoint.this[each.value.endpoint_name].id

  dynamic "target_ip" {
    for_each = each.value.target_ips
    content {
      ip   = target_ip.value.ip
      port = target_ip.value.port
    }
  }

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- VPC Associations for endpoint resolver rules ---
resource "aws_route53_resolver_rule_association" "endpoint" {
  for_each = local.resolver_endpoint_rule_vpc_map

  resolver_rule_id = aws_route53_resolver_rule.endpoint[each.value.rule_key].id
  vpc_id           = aws_vpc.this[each.value.vpc_name].id

  # Association names accept letters, digits, hyphens and underscores — the map
  # key carries dots as separators
  name = replace(each.key, ".", "-")
}

# --- RAM Sharing for endpoint resolver rules ---
resource "aws_ram_resource_share" "resolver_endpoint_rule" {
  for_each = local.resolver_endpoint_rule_share_map

  name                      = "${replace(each.key, ".", "-")}-resolver-share"
  allow_external_principals = false

  tags = {
    Name = "${replace(each.key, ".", "-")}-resolver-share"
  }
}

resource "aws_ram_resource_association" "resolver_endpoint_rule" {
  for_each = local.resolver_endpoint_rule_share_map

  resource_arn       = aws_route53_resolver_rule.endpoint[each.key].arn
  resource_share_arn = aws_ram_resource_share.resolver_endpoint_rule[each.key].arn
}

resource "aws_ram_principal_association" "resolver_endpoint_rule" {
  for_each = local.resolver_endpoint_rule_share_principal_map

  principal          = each.value.account_id
  resource_share_arn = aws_ram_resource_share.resolver_endpoint_rule[each.value.rule_key].arn
}

# =============================================================================
# Standalone Resolver Rules
# =============================================================================

locals {
  # Map: rule_name → rule definition
  standalone_resolver_rule_map = {
    for rule in var.resolver_rules : rule.name => rule
  }

  # Flattened VPC associations: "rule_name.vpc_name" → { rule_name, vpc_name }
  standalone_resolver_rule_vpc_map = merge([
    for rule in var.resolver_rules : {
      for vpc_name in rule.vpc_names : "${rule.name}.${vpc_name}" => {
        rule_name = rule.name
        vpc_name  = vpc_name
      }
    }
  ]...)

  # Standalone resolver rules that have share_targets: "rule_name" → rule
  standalone_resolver_rule_share_map = var.enable_ram_sharing ? {
    for rule in var.resolver_rules : rule.name => rule
    if length(rule.share_targets) > 0
  } : {}

  # Flattened principal associations for standalone resolver rule shares: "rule_name.target" → { rule_name, account_id }
  standalone_resolver_rule_share_principal_map = var.enable_ram_sharing ? merge([
    for rule in var.resolver_rules : {
      for target in rule.share_targets : "${rule.name}.${target}" => {
        rule_name  = rule.name
        account_id = lookup(var.account_ids, target, target)
      }
    } if length(rule.share_targets) > 0
  ]...) : {}
}

resource "aws_route53_resolver_rule" "standalone" {
  for_each = local.standalone_resolver_rule_map

  domain_name = each.value.domain_name
  rule_type   = each.value.rule_type
  name        = each.key

  dynamic "target_ip" {
    for_each = each.value.target_ips
    content {
      ip   = target_ip.value.ip
      port = target_ip.value.port
    }
  }

  tags = {
    Name = each.key
  }
}

resource "aws_route53_resolver_rule_association" "standalone" {
  for_each = local.standalone_resolver_rule_vpc_map

  resolver_rule_id = aws_route53_resolver_rule.standalone[each.value.rule_name].id
  vpc_id           = aws_vpc.this[each.value.vpc_name].id

  # Association names accept letters, digits, hyphens and underscores — the map
  # key carries a dot as separator
  name = replace(each.key, ".", "-")
}

# --- RAM Sharing for standalone resolver rules ---
resource "aws_ram_resource_share" "resolver_standalone_rule" {
  for_each = local.standalone_resolver_rule_share_map

  name                      = "${each.key}-resolver-share"
  allow_external_principals = false

  tags = {
    Name = "${each.key}-resolver-share"
  }
}

resource "aws_ram_resource_association" "resolver_standalone_rule" {
  for_each = local.standalone_resolver_rule_share_map

  resource_arn       = aws_route53_resolver_rule.standalone[each.key].arn
  resource_share_arn = aws_ram_resource_share.resolver_standalone_rule[each.key].arn
}

resource "aws_ram_principal_association" "resolver_standalone_rule" {
  for_each = local.standalone_resolver_rule_share_principal_map

  principal          = each.value.account_id
  resource_share_arn = aws_ram_resource_share.resolver_standalone_rule[each.value.rule_name].arn
}

# =============================================================================
# Route53 Hosted Zone Cross-Account Associations
# =============================================================================

locals {
  # Flattened cross-account associations: "zone_name.vpc_id" → { zone_name, vpc_id, account_id, region }
  route53_cross_account_map = merge([
    for zone in var.route53_zones : {
      for assoc in zone.cross_account_associations : "${zone.name}.${assoc.vpc_id}" => {
        zone_name  = zone.name
        vpc_id     = assoc.vpc_id
        account_id = assoc.account_id
        region     = assoc.region != null ? assoc.region : local.region
      }
    }
  ]...)
}

# Authorization from the zone owner account
resource "aws_route53_vpc_association_authorization" "this" {
  for_each = local.route53_cross_account_map

  zone_id = aws_route53_zone.private[each.value.zone_name].zone_id
  vpc_id  = each.value.vpc_id

  vpc_region = each.value.region
}

# The association. The module has ONE unaliased provider, so this call runs
# with the zone owner's credentials, in the account the stack runs in; it does
# not run in account_id. Route 53 accepts AssociateVPCWithHostedZone for a VPC
# of another account only from the account that owns the VPC (AWS
# documentation), so an entry whose account_id is not the
# stack's own account cannot succeed. The precondition refuses such an entry
# at plan instead of letting the apply fail after the authorization exists.
resource "aws_route53_zone_association" "cross_account" {
  for_each = local.route53_cross_account_map

  zone_id = aws_route53_zone.private[each.value.zone_name].zone_id
  vpc_id  = each.value.vpc_id

  vpc_region = each.value.region

  depends_on = [aws_route53_vpc_association_authorization.this]

  lifecycle {
    precondition {
      condition     = each.value.account_id == data.aws_caller_identity.current.account_id
      error_message = "route53_zones \"${each.value.zone_name}\" cross_account_associations: VPC ${each.value.vpc_id} is declared in account ${each.value.account_id}, but this module runs with one provider in account ${data.aws_caller_identity.current.account_id}, the zone owner's. Route 53 associates a VPC of another account only when that account makes the call, and this module makes the authorization and the association together from its own account. Remove the entry; the association has to be made from account ${each.value.account_id}."
    }
  }
}
