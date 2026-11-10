# =============================================================================
# Security Groups
# =============================================================================

locals {
  # Flattened security group map: "vpc_name.sg_name" → { vpc_name, sg definition }
  security_group_map = merge([
    for vpc in var.vpcs : {
      for sg in vpc.security_groups : "${vpc.name}.${sg.name}" => {
        vpc_name    = vpc.name
        name        = sg.name
        description = sg.description != null ? sg.description : "Security group ${sg.name} in VPC ${vpc.name}"
        tags        = sg.tags
        ingress     = sg.ingress
        egress      = sg.egress
      }
    }
  ]...)

  # Fixed TCP port per named rule type; TCP, UDP, ICMP and ALL are handled
  # in the expansion below.
  sg_type_ports = {
    "RDP"          = 3389
    "SSH"          = 22
    "HTTP"         = 80
    "HTTPS"        = 443
    "MSSQL"        = 1433
    "MYSQL/AURORA" = 3306
    "REDSHIFT"     = 5439
    "POSTGRESQL"   = 5432
    "ORACLE-RDS"   = 1521
  }

  # Flattened rules before type expansion: "vpc_name.sg_name.direction.idx"
  # → { sg_key, vpc_name, direction, rule }.
  sg_rules_raw = merge([
    for sg_key, sg in local.security_group_map : merge(
      {
        for idx, rule in sg.ingress : "${sg_key}.ingress.${idx}" => {
          sg_key    = sg_key
          vpc_name  = sg.vpc_name
          direction = "ingress"
          rule      = rule
        }
      },
      {
        for idx, rule in sg.egress : "${sg_key}.egress.${idx}" => {
          sg_key    = sg_key
          vpc_name  = sg.vpc_name
          direction = "egress"
          rule      = rule
        }
      }
    )
  ]...)

  # Concrete protocol/port forms per rule. A rule without types keeps its
  # explicit protocol/port triple under the empty suffix; a rule with types
  # yields one form per type (".<type>"): the named application types expand
  # to their fixed TCP port, TCP/UDP/ICMP use the rule's own port pair, ALL
  # means all protocols.
  sg_rule_forms = {
    for base_key, entry in local.sg_rules_raw : base_key => (
      length(entry.rule.types) == 0 ? { "" = { protocol = entry.rule.protocol, from_port = entry.rule.from_port, to_port = entry.rule.to_port } } : {
        for t in entry.rule.types : ".${t}" => (
          t == "ALL" ? { protocol = "-1", from_port = 0, to_port = 0 } : (
            contains(["TCP", "UDP", "ICMP"], t) ? { protocol = lower(t), from_port = entry.rule.from_port, to_port = entry.rule.to_port } : { protocol = "tcp", from_port = local.sg_type_ports[t], to_port = local.sg_type_ports[t] }
          )
        )
      }
    )
  }

  # Type expansion and source resolution: one entry per rule and form.
  # Subnet selectors resolve to the referenced subnets' CIDRs through the
  # subnet resource, so IPAM-assigned CIDRs resolve as well.
  sg_rules = merge([
    for base_key, entry in local.sg_rules_raw : {
      for suffix, form in local.sg_rule_forms[base_key] : "${base_key}${suffix}" => {
        sg_key           = entry.sg_key
        vpc_name         = entry.vpc_name
        direction        = entry.direction
        protocol         = form.protocol
        from_port        = form.from_port
        to_port          = form.to_port
        cidr_blocks      = entry.rule.cidr_blocks
        ipv6_cidr_blocks = entry.rule.ipv6_cidr_blocks
        subnet_cidrs_v4 = flatten([
          for sel in entry.rule.source_subnets : [for sn in sel.subnets : aws_subnet.this["${sel.vpc}.${sn}"].cidr_block] if sel.ipv6 == false
        ])
        subnet_cidrs_v6 = flatten([
          for sel in entry.rule.source_subnets : [for sn in sel.subnets : aws_subnet.this["${sel.vpc}.${sn}"].ipv6_cidr_block] if sel.ipv6
        ])
        source_security_group = entry.rule.source_security_group
        prefix_list_id        = entry.rule.prefix_list_id
        description           = entry.rule.description
      }
    }
  ]...)

  # Flattened ingress rules: "vpc_name.sg_name.ingress.idx[.type]" → rule
  sg_ingress_rules = { for key, rule in local.sg_rules : key => rule if rule.direction == "ingress" }

  # Flattened egress rules: "vpc_name.sg_name.egress.idx[.type]" → rule
  sg_egress_rules = { for key, rule in local.sg_rules : key => rule if rule.direction == "egress" }
}

resource "aws_security_group" "this" {
  for_each = local.security_group_map

  name        = each.value.name
  description = each.value.description
  vpc_id      = aws_vpc.this[each.value.vpc_name].id

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# Ingress rules — CIDR-based (literal IPv4/IPv6 CIDRs and resolved subnet
# selectors land on one rule; a prefix list on the same rule rides along)
resource "aws_security_group_rule" "ingress_cidr" {
  for_each = {
    for key, rule in local.sg_ingress_rules : key => rule
    if length(rule.cidr_blocks) > 0 || length(rule.ipv6_cidr_blocks) > 0 || length(rule.subnet_cidrs_v4) > 0 || length(rule.subnet_cidrs_v6) > 0
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "ingress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_blocks       = length(concat(each.value.cidr_blocks, each.value.subnet_cidrs_v4)) > 0 ? concat(each.value.cidr_blocks, each.value.subnet_cidrs_v4) : null
  ipv6_cidr_blocks  = length(concat(each.value.ipv6_cidr_blocks, each.value.subnet_cidrs_v6)) > 0 ? concat(each.value.ipv6_cidr_blocks, each.value.subnet_cidrs_v6) : null
  prefix_list_ids   = each.value.prefix_list_id != "" ? [each.value.prefix_list_id] : []
  description       = each.value.description
}

# Ingress rules — source security group reference
resource "aws_security_group_rule" "ingress_sg" {
  for_each = {
    for key, rule in local.sg_ingress_rules : key => rule
    if rule.source_security_group != ""
  }

  security_group_id        = aws_security_group.this[each.value.sg_key].id
  type                     = "ingress"
  protocol                 = each.value.protocol
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  source_security_group_id = aws_security_group.this["${each.value.vpc_name}.${each.value.source_security_group}"].id
  description              = each.value.description
}

# Ingress rules — prefix list only
resource "aws_security_group_rule" "ingress_prefix_list" {
  for_each = {
    for key, rule in local.sg_ingress_rules : key => rule
    if rule.prefix_list_id != "" && length(rule.cidr_blocks) == 0 && length(rule.ipv6_cidr_blocks) == 0 && length(rule.subnet_cidrs_v4) == 0 && length(rule.subnet_cidrs_v6) == 0 && rule.source_security_group == ""
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "ingress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  prefix_list_ids   = [each.value.prefix_list_id]
  description       = each.value.description
}

# Egress rules — CIDR-based (literal IPv4/IPv6 CIDRs and resolved subnet
# selectors land on one rule; a prefix list on the same rule rides along)
resource "aws_security_group_rule" "egress_cidr" {
  for_each = {
    for key, rule in local.sg_egress_rules : key => rule
    if length(rule.cidr_blocks) > 0 || length(rule.ipv6_cidr_blocks) > 0 || length(rule.subnet_cidrs_v4) > 0 || length(rule.subnet_cidrs_v6) > 0
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "egress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_blocks       = length(concat(each.value.cidr_blocks, each.value.subnet_cidrs_v4)) > 0 ? concat(each.value.cidr_blocks, each.value.subnet_cidrs_v4) : null
  ipv6_cidr_blocks  = length(concat(each.value.ipv6_cidr_blocks, each.value.subnet_cidrs_v6)) > 0 ? concat(each.value.ipv6_cidr_blocks, each.value.subnet_cidrs_v6) : null
  prefix_list_ids   = each.value.prefix_list_id != "" ? [each.value.prefix_list_id] : []
  description       = each.value.description
}

# Egress rules — destination security group reference
resource "aws_security_group_rule" "egress_sg" {
  for_each = {
    for key, rule in local.sg_egress_rules : key => rule
    if rule.source_security_group != ""
  }

  security_group_id        = aws_security_group.this[each.value.sg_key].id
  type                     = "egress"
  protocol                 = each.value.protocol
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  source_security_group_id = aws_security_group.this["${each.value.vpc_name}.${each.value.source_security_group}"].id
  description              = each.value.description
}

# Egress rules — prefix list only
resource "aws_security_group_rule" "egress_prefix_list" {
  for_each = {
    for key, rule in local.sg_egress_rules : key => rule
    if rule.prefix_list_id != "" && length(rule.cidr_blocks) == 0 && length(rule.ipv6_cidr_blocks) == 0 && length(rule.subnet_cidrs_v4) == 0 && length(rule.subnet_cidrs_v6) == 0 && rule.source_security_group == ""
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "egress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  prefix_list_ids   = [each.value.prefix_list_id]
  description       = each.value.description
}

# =============================================================================
# Default Security Group Restriction — zero ingress/egress per VPC
# =============================================================================

resource "aws_default_security_group" "vpc" {
  for_each = local.vpc_map

  vpc_id = aws_vpc.this[each.key].id

  # No ingress or egress blocks — all default rules are removed

  tags = {
    Name      = "${each.key}-default-sg-restricted"
    ManagedBy = "TLZ"
  }
}
