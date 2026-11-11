# =============================================================================
# Security Groups — owned by the workload account, placed in a shared VPC
# =============================================================================
# shortcut: the rule expansion below duplicates the one of
# modules/networking/security-groups.tf (minus the subnet selectors, which
# resolve against VPC entries this account does not own). Upgrade to a shared
# child module only together with moved blocks for every management-owned
# group — that is a state migration of its own.

locals {
  # Flattened security group map: "vpc_name.sg_name" → { vpc_name, sg definition }
  security_group_map = {
    for sg in local.security_groups : "${sg.vpc_name}.${sg.name}" => {
      vpc_name    = sg.vpc_name
      name        = sg.name
      description = sg.description != null ? sg.description : "Security group ${sg.name} in VPC ${sg.vpc_name}"
      tags        = sg.tags
      ingress     = sg.ingress
      egress      = sg.egress
    }
  }

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

  # Flattened rules before type expansion: "vpc_name.sg_name.direction.<name
  # or idx>" → { sg_key, vpc_name, direction, rule }. A rule's optional name
  # replaces its list index in the key, so removing or reordering other rules
  # leaves a named rule in place; an unnamed rule keeps the index key.
  sg_rules_raw = merge([
    for sg_key, sg in local.security_group_map : merge(
      {
        for idx, rule in sg.ingress : "${sg_key}.ingress.${rule.name != null ? rule.name : idx}" => {
          sg_key    = sg_key
          vpc_name  = sg.vpc_name
          direction = "ingress"
          rule      = rule
        }
      },
      {
        for idx, rule in sg.egress : "${sg_key}.egress.${rule.name != null ? rule.name : idx}" => {
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

  # Type expansion: one entry per rule and form.
  sg_rules = merge([
    for base_key, entry in local.sg_rules_raw : {
      for suffix, form in local.sg_rule_forms[base_key] : "${base_key}${suffix}" => {
        sg_key                = entry.sg_key
        vpc_name              = entry.vpc_name
        direction             = entry.direction
        protocol              = form.protocol
        from_port             = form.from_port
        to_port               = form.to_port
        cidr_blocks           = entry.rule.cidr_blocks
        ipv6_cidr_blocks      = entry.rule.ipv6_cidr_blocks
        source_security_group = entry.rule.source_security_group
        prefix_list_id        = entry.rule.prefix_list_id
        description           = entry.rule.description
      }
    }
  ]...)

  # Flattened ingress rules: "vpc_name.sg_name.ingress.<name or idx>[.type]" → rule
  sg_ingress_rules = { for key, rule in local.sg_rules : key => rule if rule.direction == "ingress" }

  # Flattened egress rules: "vpc_name.sg_name.egress.<name or idx>[.type]" → rule
  sg_egress_rules = { for key, rule in local.sg_rules : key => rule if rule.direction == "egress" }
}

resource "aws_security_group" "this" {
  for_each = local.security_group_map

  name        = each.value.name
  description = each.value.description
  vpc_id      = lookup(var.vpc_ids, each.value.vpc_name, "")

  tags = merge(var.default_tags, each.value.tags, {
    Name = each.key
  })

  lifecycle {
    precondition {
      condition     = contains(keys(var.vpc_ids), each.value.vpc_name)
      error_message = "Security group ${each.key}: vpc_name ${each.value.vpc_name} is not a key of vpc_ids — the management networking stack supplies that map (vpc name to VPC ID)."
    }
  }
}

# Ingress rules — CIDR-based (a prefix list on the same rule rides along)
resource "aws_security_group_rule" "ingress_cidr" {
  for_each = {
    for key, rule in local.sg_ingress_rules : key => rule
    if length(rule.cidr_blocks) > 0 || length(rule.ipv6_cidr_blocks) > 0
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "ingress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_blocks       = length(each.value.cidr_blocks) > 0 ? each.value.cidr_blocks : null
  ipv6_cidr_blocks  = length(each.value.ipv6_cidr_blocks) > 0 ? each.value.ipv6_cidr_blocks : null
  prefix_list_ids   = each.value.prefix_list_id != "" ? [each.value.prefix_list_id] : []
  description       = each.value.description
}

# Ingress rules — source security group reference (a group of this module in
# the same VPC)
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
    if rule.prefix_list_id != "" && length(rule.cidr_blocks) == 0 && length(rule.ipv6_cidr_blocks) == 0 && rule.source_security_group == ""
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "ingress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  prefix_list_ids   = [each.value.prefix_list_id]
  description       = each.value.description
}

# Egress rules — CIDR-based (a prefix list on the same rule rides along)
resource "aws_security_group_rule" "egress_cidr" {
  for_each = {
    for key, rule in local.sg_egress_rules : key => rule
    if length(rule.cidr_blocks) > 0 || length(rule.ipv6_cidr_blocks) > 0
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "egress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_blocks       = length(each.value.cidr_blocks) > 0 ? each.value.cidr_blocks : null
  ipv6_cidr_blocks  = length(each.value.ipv6_cidr_blocks) > 0 ? each.value.ipv6_cidr_blocks : null
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
    if rule.prefix_list_id != "" && length(rule.cidr_blocks) == 0 && length(rule.ipv6_cidr_blocks) == 0 && rule.source_security_group == ""
  }

  security_group_id = aws_security_group.this[each.value.sg_key].id
  type              = "egress"
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  prefix_list_ids   = [each.value.prefix_list_id]
  description       = each.value.description
}
