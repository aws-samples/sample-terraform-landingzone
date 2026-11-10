# =============================================================================
# AWS Network Firewall (conditional)
# =============================================================================

locals {
  # Resolve subnet_names to subnet IDs; fall back to deprecated subnet_ids for backward compat
  nfw_subnet_ids = (
    length(var.network_firewall.subnet_names) > 0
    ? [
      for sn in var.network_firewall.subnet_names :
      aws_subnet.this["${var.network_firewall.vpc_name}.${sn}"].id
    ]
    : var.network_firewall.subnet_ids
  )

  # Rule group map keyed by name
  nfw_rule_group_map = var.network_firewall.enabled ? {
    for rg in var.network_firewall.rule_groups : rg.name => rg
  } : {}

  # The rules string of a rule group: the `rules` entry for a group described
  # by a string, the structured rules_string for a group described by a
  # rule_group block, and null when the structured block names another source.
  # The variable validation ties each group to exactly one of the two forms.
  nfw_rule_group_rules = {
    for name, rg in local.nfw_rule_group_map : name => (
      rg.rule_group == null
      ? rg.rules
      : rg.rule_group.rules_source.rules_string
    )
  }

  # Stateless rule groups need unique priorities — assigned from the index of
  # the name in keys() of this map, which is lexical order, not rule_groups order
  nfw_stateless_rule_groups = {
    for name, rg in aws_networkfirewall_rule_group.this : name => rg
    if local.nfw_rule_group_map[name].type == "STATELESS"
  }

  nfw_stateful_rule_groups = {
    for name, rg in aws_networkfirewall_rule_group.this : name => rg
    if local.nfw_rule_group_map[name].type == "STATEFUL"
  }

  # Merge locally-created stateful rule group ARNs with external references.
  # A group that a stateful_rule_groups entry references by name is left out
  # here: that entry carries its own priority and becomes its own reference
  # block, and the same ARN twice in one policy is rejected.
  nfw_policy_named_stateful = [
    for reference in var.network_firewall.firewall_policy.stateful_rule_groups :
    reference.name if reference.name != null
  ]

  nfw_stateful_arns = concat(
    [
      for name, rg in local.nfw_stateful_rule_groups : rg.arn
      if !contains(local.nfw_policy_named_stateful, name)
    ],
    var.network_firewall.firewall_policy.stateful_rule_group_references
  )

  # ARN of an AWS managed stateful rule group. The account part is the fixed
  # owner aws-managed; partition and region come from the caller's context, so
  # the same configuration resolves in every partition.
  nfw_managed_rule_group_arn_prefix = "${local.arn_prefix}:network-firewall:${local.region}:aws-managed:stateful-rulegroup"

  # NFW endpoint ID map for route target resolution (AZ → endpoint ID)
  nfw_endpoint_id_map = var.network_firewall.enabled ? {
    for state in try(aws_networkfirewall_firewall.this[0].firewall_status[0].sync_states, []) :
    state.availability_zone => try(state.attachment[0].endpoint_id, "")
  } : {}
}

# --- Rule Groups (for_each over rule_groups list) ---
resource "aws_networkfirewall_rule_group" "this" {
  for_each = local.nfw_rule_group_map

  capacity    = each.value.capacity
  name        = each.value.name
  type        = each.value.type
  description = each.value.description

  rule_group {
    # Rule variables let a Suricata rule name an address or port set instead of
    # repeating the literal in every rule.
    dynamic "rule_variables" {
      for_each = try(each.value.rule_group.rule_variables, null) == null ? [] : [each.value.rule_group.rule_variables]
      content {
        dynamic "ip_sets" {
          for_each = { for entry in rule_variables.value.ip_sets : entry.name => entry }
          content {
            key = ip_sets.key
            ip_set {
              definition = ip_sets.value.definition
            }
          }
        }
        dynamic "port_sets" {
          for_each = { for entry in rule_variables.value.port_sets : entry.name => entry }
          content {
            key = port_sets.key
            port_set {
              definition = port_sets.value.definition
            }
          }
        }
      }
    }

    rules_source {
      # A rule group described by the `rules` string keeps writing exactly that
      # string; the structured forms below are alternatives to it.
      rules_string = local.nfw_rule_group_rules[each.key]

      # A domain list: the service generates the Suricata rules from the target
      # domains and the protocols to inspect.
      dynamic "rules_source_list" {
        for_each = try(each.value.rule_group.rules_source.rules_source_list, null) == null ? [] : [each.value.rule_group.rules_source.rules_source_list]
        content {
          generated_rules_type = rules_source_list.value.generated_rules_type
          target_types         = rules_source_list.value.target_types
          targets              = rules_source_list.value.targets
        }
      }

      # Stateful rules in 5-tuple form: the header names the flow, the action
      # what happens to it, and the rule options carry Suricata keywords.
      dynamic "stateful_rule" {
        for_each = try(each.value.rule_group.rules_source.stateful_rules, [])
        content {
          action = stateful_rule.value.action
          header {
            source           = stateful_rule.value.header.source
            source_port      = stateful_rule.value.header.source_port
            destination      = stateful_rule.value.header.destination
            destination_port = stateful_rule.value.header.destination_port
            direction        = stateful_rule.value.header.direction
            protocol         = stateful_rule.value.header.protocol
          }
          dynamic "rule_option" {
            for_each = stateful_rule.value.rule_options
            content {
              keyword  = rule_option.value.keyword
              settings = length(rule_option.value.settings) > 0 ? rule_option.value.settings : null
            }
          }
        }
      }

      # Stateless rules: a priority, the match attributes of the packet and the
      # actions to take, plus the custom actions those actions may name.
      dynamic "stateless_rules_and_custom_actions" {
        for_each = try(each.value.rule_group.rules_source.stateless_rules_and_custom_actions, null) == null ? [] : [each.value.rule_group.rules_source.stateless_rules_and_custom_actions]
        content {
          dynamic "custom_action" {
            for_each = { for entry in stateless_rules_and_custom_actions.value.custom_actions : entry.action_name => entry }
            content {
              action_name = custom_action.key
              action_definition {
                publish_metric_action {
                  dynamic "dimension" {
                    for_each = toset(custom_action.value.publish_metric_dimensions)
                    content {
                      value = dimension.value
                    }
                  }
                }
              }
            }
          }
          dynamic "stateless_rule" {
            for_each = { for entry in stateless_rules_and_custom_actions.value.stateless_rules : tostring(entry.priority) => entry }
            content {
              priority = stateless_rule.value.priority
              rule_definition {
                actions = stateless_rule.value.rule_definition.actions
                match_attributes {
                  protocols = length(stateless_rule.value.rule_definition.match_attributes.protocols) > 0 ? stateless_rule.value.rule_definition.match_attributes.protocols : null
                  dynamic "source" {
                    for_each = toset(stateless_rule.value.rule_definition.match_attributes.sources)
                    content {
                      address_definition = source.value
                    }
                  }
                  dynamic "destination" {
                    for_each = toset(stateless_rule.value.rule_definition.match_attributes.destinations)
                    content {
                      address_definition = destination.value
                    }
                  }
                  dynamic "source_port" {
                    for_each = stateless_rule.value.rule_definition.match_attributes.source_ports
                    content {
                      from_port = source_port.value.from_port
                      to_port   = source_port.value.to_port
                    }
                  }
                  dynamic "destination_port" {
                    for_each = stateless_rule.value.rule_definition.match_attributes.destination_ports
                    content {
                      from_port = destination_port.value.from_port
                      to_port   = destination_port.value.to_port
                    }
                  }
                  dynamic "tcp_flag" {
                    for_each = stateless_rule.value.rule_definition.match_attributes.tcp_flags
                    content {
                      flags = tcp_flag.value.flags
                      masks = length(tcp_flag.value.masks) > 0 ? tcp_flag.value.masks : null
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    # Strict order evaluates the rules of the group by priority instead of by
    # action; it is a property of the group, not of the policy that uses it.
    dynamic "stateful_rule_options" {
      for_each = try(each.value.rule_group.stateful_rule_options, null) == null ? [] : [each.value.rule_group.stateful_rule_options]
      content {
        rule_order = stateful_rule_options.value
      }
    }
  }

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- Firewall Policy ---
resource "aws_networkfirewall_firewall_policy" "this" {
  count = var.network_firewall.enabled ? 1 : 0

  name        = "tlz-firewall-policy"
  description = var.network_firewall.firewall_policy.description

  firewall_policy {
    stateless_default_actions          = var.network_firewall.firewall_policy.stateless_default_actions
    stateless_fragment_default_actions = var.network_firewall.firewall_policy.stateless_fragment_default_actions
    # The stateful default action decides what happens to a packet the stateful
    # rules did not match. Left empty the service keeps its own default.
    stateful_default_actions = length(var.network_firewall.firewall_policy.stateful_default_actions) > 0 ? var.network_firewall.firewall_policy.stateful_default_actions : null

    # Engine options: the order the stateful rules are evaluated in, what
    # happens to a flow the engine loses track of, and how long an idle TCP
    # flow is kept.
    dynamic "stateful_engine_options" {
      for_each = var.network_firewall.firewall_policy.stateful_engine_options == null ? [] : [var.network_firewall.firewall_policy.stateful_engine_options]
      content {
        rule_order              = stateful_engine_options.value.rule_order
        stream_exception_policy = stateful_engine_options.value.stream_exception_policy
        dynamic "flow_timeouts" {
          for_each = stateful_engine_options.value.tcp_idle_timeout_seconds == null ? [] : [stateful_engine_options.value.tcp_idle_timeout_seconds]
          content {
            tcp_idle_timeout_seconds = flow_timeouts.value
          }
        }
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = toset(local.nfw_stateful_arns)
      content {
        resource_arn = stateful_rule_group_reference.value
      }
    }

    # A stateful_rule_groups entry carries its own priority, which strict order
    # evaluates the groups by. The ARN comes from a rule group of this module,
    # from the managed rule group namespace, or straight from the entry.
    dynamic "stateful_rule_group_reference" {
      for_each = { for reference in var.network_firewall.firewall_policy.stateful_rule_groups : coalesce(reference.name, reference.managed_rule_group_name, reference.arn) => reference }
      content {
        resource_arn = (
          stateful_rule_group_reference.value.name != null
          ? aws_networkfirewall_rule_group.this[stateful_rule_group_reference.value.name].arn
          : (
            stateful_rule_group_reference.value.managed_rule_group_name != null
            ? "${local.nfw_managed_rule_group_arn_prefix}/${stateful_rule_group_reference.value.managed_rule_group_name}"
            : stateful_rule_group_reference.value.arn
          )
        )
        priority = stateful_rule_group_reference.value.priority
      }
    }

    # Without an explicit stateless_rule_groups list the module derives the
    # priority from the lexical order of the STATELESS group names (keys() of
    # a map sorts them), not from the order of rule_groups; with it, each
    # named group carries the priority the configuration gives it.
    dynamic "stateless_rule_group_reference" {
      for_each = length(var.network_firewall.firewall_policy.stateless_rule_groups) > 0 ? {} : local.nfw_stateless_rule_groups
      content {
        resource_arn = stateless_rule_group_reference.value.arn
        priority     = (index(keys(local.nfw_stateless_rule_groups), stateless_rule_group_reference.key) + 1) * 10
      }
    }

    dynamic "stateless_rule_group_reference" {
      for_each = { for reference in var.network_firewall.firewall_policy.stateless_rule_groups : reference.name => reference }
      content {
        resource_arn = aws_networkfirewall_rule_group.this[stateless_rule_group_reference.key].arn
        priority     = stateless_rule_group_reference.value.priority
      }
    }

    # A custom action publishes its own CloudWatch metric dimension; a stateless
    # rule names it in place of one of the three service actions.
    dynamic "stateless_custom_action" {
      for_each = { for action in var.network_firewall.firewall_policy.stateless_custom_actions : action.action_name => action }
      content {
        action_name = stateless_custom_action.key
        action_definition {
          publish_metric_action {
            dynamic "dimension" {
              for_each = toset(stateless_custom_action.value.publish_metric_dimensions)
              content {
                value = dimension.value
              }
            }
          }
        }
      }
    }
  }

  tags = merge(var.network_firewall.firewall_policy.tags, {
    Name = "tlz-firewall-policy"
  })
}

# --- Further Firewall Policies (for_each over policies list) ---
locals {
  nfw_policy_map = var.network_firewall.enabled ? {
    for policy in var.network_firewall.policies : policy.name => policy
  } : {}

  # Rule groups a policy references by name do not repeat as a bare ARN; the
  # same ARN twice in one policy is rejected.
  nfw_named_policy_stateful_arns = {
    for name, policy in local.nfw_policy_map : name => concat(
      [
        for group_name, rg in local.nfw_stateful_rule_groups : rg.arn
        if !contains([
          for reference in policy.firewall_policy.stateful_rule_groups : reference.name
          if reference.name != null
        ], group_name)
      ],
      policy.firewall_policy.stateful_rule_group_references
    )
  }
}

resource "aws_networkfirewall_firewall_policy" "named" {
  for_each = local.nfw_policy_map

  name        = each.key
  description = each.value.description

  firewall_policy {
    stateless_default_actions          = each.value.firewall_policy.stateless_default_actions
    stateless_fragment_default_actions = each.value.firewall_policy.stateless_fragment_default_actions
    stateful_default_actions           = length(each.value.firewall_policy.stateful_default_actions) > 0 ? each.value.firewall_policy.stateful_default_actions : null

    dynamic "stateful_engine_options" {
      for_each = each.value.firewall_policy.stateful_engine_options == null ? [] : [each.value.firewall_policy.stateful_engine_options]
      content {
        rule_order              = stateful_engine_options.value.rule_order
        stream_exception_policy = stateful_engine_options.value.stream_exception_policy
        dynamic "flow_timeouts" {
          for_each = stateful_engine_options.value.tcp_idle_timeout_seconds == null ? [] : [stateful_engine_options.value.tcp_idle_timeout_seconds]
          content {
            tcp_idle_timeout_seconds = flow_timeouts.value
          }
        }
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = toset(local.nfw_named_policy_stateful_arns[each.key])
      content {
        resource_arn = stateful_rule_group_reference.value
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = { for reference in each.value.firewall_policy.stateful_rule_groups : coalesce(reference.name, reference.managed_rule_group_name, reference.arn) => reference }
      content {
        resource_arn = (
          stateful_rule_group_reference.value.name != null
          ? aws_networkfirewall_rule_group.this[stateful_rule_group_reference.value.name].arn
          : (
            stateful_rule_group_reference.value.managed_rule_group_name != null
            ? "${local.nfw_managed_rule_group_arn_prefix}/${stateful_rule_group_reference.value.managed_rule_group_name}"
            : stateful_rule_group_reference.value.arn
          )
        )
        priority = stateful_rule_group_reference.value.priority
      }
    }

    dynamic "stateless_rule_group_reference" {
      for_each = length(each.value.firewall_policy.stateless_rule_groups) > 0 ? {} : local.nfw_stateless_rule_groups
      content {
        resource_arn = stateless_rule_group_reference.value.arn
        priority     = (index(keys(local.nfw_stateless_rule_groups), stateless_rule_group_reference.key) + 1) * 10
      }
    }

    dynamic "stateless_rule_group_reference" {
      for_each = { for reference in each.value.firewall_policy.stateless_rule_groups : reference.name => reference }
      content {
        resource_arn = aws_networkfirewall_rule_group.this[stateless_rule_group_reference.key].arn
        priority     = stateless_rule_group_reference.value.priority
      }
    }

    dynamic "stateless_custom_action" {
      for_each = { for action in each.value.firewall_policy.stateless_custom_actions : action.action_name => action }
      content {
        action_name = stateless_custom_action.key
        action_definition {
          publish_metric_action {
            dynamic "dimension" {
              for_each = toset(stateless_custom_action.value.publish_metric_dimensions)
              content {
                value = dimension.value
              }
            }
          }
        }
      }
    }
  }

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- Firewall ---
resource "aws_networkfirewall_firewall" "this" {
  count = var.network_firewall.enabled ? 1 : 0

  name                = "tlz-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.this[0].arn
  vpc_id              = var.network_firewall.vpc_name != "" ? aws_vpc.this[var.network_firewall.vpc_name].id : null

  description = var.network_firewall.description

  # The central inspection firewall must not disappear through an accidental
  # destroy, and its subnet associations must not change unnoticed. Deleting
  # or re-homing it requires disabling the protection first (see README,
  # section "Deletion protection"). Both default to true;
  # firewall_policy_change_protection keeps the service default.
  delete_protection                 = var.network_firewall.delete_protection
  subnet_change_protection          = var.network_firewall.subnet_change_protection
  firewall_policy_change_protection = var.network_firewall.firewall_policy_change_protection

  dynamic "subnet_mapping" {
    for_each = local.nfw_subnet_ids
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = merge(var.network_firewall.tags, {
    Name = "tlz-network-firewall"
  })
}

# --- Further Firewalls (for_each over firewalls list) ---
locals {
  nfw_firewall_map = var.network_firewall.enabled ? {
    for firewall in var.network_firewall.firewalls : firewall.name => firewall
  } : {}

  # Subnet IDs per further firewall, resolved the same way as for the module's
  # own one: named subnets of the firewall's VPC, or raw IDs.
  nfw_firewall_subnet_ids = {
    for name, firewall in local.nfw_firewall_map : name => (
      length(firewall.subnet_names) > 0
      ? [for sn in firewall.subnet_names : aws_subnet.this["${firewall.vpc_name}.${sn}"].id]
      : firewall.subnet_ids
    )
  }

  # Firewalls that carry their own logging configuration.
  nfw_firewall_logging_map = {
    for name, firewall in local.nfw_firewall_map : name => firewall
    if firewall.logging_configuration != null
  }
}

resource "aws_networkfirewall_firewall" "additional" {
  for_each = local.nfw_firewall_map

  name        = each.key
  description = each.value.description
  vpc_id      = aws_vpc.this[each.value.vpc_name].id

  # Without policy_name the firewall runs the module's own policy.
  firewall_policy_arn = (
    each.value.policy_name == null
    ? aws_networkfirewall_firewall_policy.this[0].arn
    : aws_networkfirewall_firewall_policy.named[each.value.policy_name].arn
  )

  delete_protection                 = each.value.delete_protection
  subnet_change_protection          = each.value.subnet_change_protection
  firewall_policy_change_protection = each.value.firewall_policy_change_protection

  dynamic "subnet_mapping" {
    for_each = local.nfw_firewall_subnet_ids[each.key]
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# --- Logging Configuration (conditional on logging_configuration != null) ---
resource "aws_networkfirewall_logging_configuration" "this" {
  count = var.network_firewall.enabled && var.network_firewall.logging_configuration != null ? 1 : 0

  firewall_arn = aws_networkfirewall_firewall.this[0].arn

  logging_configuration {
    # Flow log destination
    dynamic "log_destination_config" {
      for_each = var.network_firewall.logging_configuration.flow_log_destination != "" ? [1] : []
      content {
        log_destination = (
          var.network_firewall.logging_configuration.flow_log_destination_type == "S3"
          ? { bucketName = var.network_firewall.logging_configuration.flow_log_destination }
          : { logGroup = var.network_firewall.logging_configuration.flow_log_destination }
        )
        log_destination_type = var.network_firewall.logging_configuration.flow_log_destination_type
        log_type             = "FLOW"
      }
    }

    # Alert log destination
    dynamic "log_destination_config" {
      for_each = var.network_firewall.logging_configuration.alert_log_destination != "" ? [1] : []
      content {
        log_destination = (
          var.network_firewall.logging_configuration.alert_log_destination_type == "S3"
          ? { bucketName = var.network_firewall.logging_configuration.alert_log_destination }
          : { logGroup = var.network_firewall.logging_configuration.alert_log_destination }
        )
        log_destination_type = var.network_firewall.logging_configuration.alert_log_destination_type
        log_type             = "ALERT"
      }
    }
  }
}

# --- Logging Configuration per further firewall ---
resource "aws_networkfirewall_logging_configuration" "additional" {
  for_each = local.nfw_firewall_logging_map

  firewall_arn = aws_networkfirewall_firewall.additional[each.key].arn

  logging_configuration {
    dynamic "log_destination_config" {
      for_each = each.value.logging_configuration.flow_log_destination != "" ? [1] : []
      content {
        log_destination = (
          each.value.logging_configuration.flow_log_destination_type == "S3"
          ? { bucketName = each.value.logging_configuration.flow_log_destination }
          : { logGroup = each.value.logging_configuration.flow_log_destination }
        )
        log_destination_type = each.value.logging_configuration.flow_log_destination_type
        log_type             = "FLOW"
      }
    }

    dynamic "log_destination_config" {
      for_each = each.value.logging_configuration.alert_log_destination != "" ? [1] : []
      content {
        log_destination = (
          each.value.logging_configuration.alert_log_destination_type == "S3"
          ? { bucketName = each.value.logging_configuration.alert_log_destination }
          : { logGroup = each.value.logging_configuration.alert_log_destination }
        )
        log_destination_type = each.value.logging_configuration.alert_log_destination_type
        log_type             = "ALERT"
      }
    }
  }
}

# =============================================================================
# Network Firewall RAM Sharing
# =============================================================================

locals {
  # Rule groups that have share_targets: group_name → rule group definition.
  # nfw_rule_group_map is already gated on network_firewall.enabled.
  nfw_rule_group_share_map = var.enable_ram_sharing ? {
    for name, rg in local.nfw_rule_group_map : name => rg
    if length(rg.share_targets) > 0
  } : {}

  # Flattened principal associations: "group_name.target" → { group_name, principal }
  nfw_rule_group_share_principal_map = var.enable_ram_sharing ? merge([
    for name, rg in local.nfw_rule_group_map : {
      for target in rg.share_targets : "${name}.${target}" => {
        group_name = name
        principal  = lookup(var.account_ids, target, target)
      }
    } if length(rg.share_targets) > 0
  ]...) : {}

  # The module's one firewall policy, shared when it names targets
  nfw_policy_share_targets = var.enable_ram_sharing && var.network_firewall.enabled ? var.network_firewall.firewall_policy.share_targets : []

  nfw_policy_share_principal_map = {
    for target in local.nfw_policy_share_targets : target => lookup(var.account_ids, target, target)
  }

  # Further policies that name share targets. nfw_policy_map is already gated
  # on network_firewall.enabled.
  nfw_named_policy_share_map = var.enable_ram_sharing ? {
    for name, policy in local.nfw_policy_map : name => policy
    if length(policy.share_targets) > 0
  } : {}

  # Flattened principal associations: "policy_name.target" → { policy_name, principal }
  nfw_named_policy_share_principal_map = var.enable_ram_sharing ? merge([
    for name, policy in local.nfw_policy_map : {
      for target in policy.share_targets : "${name}.${target}" => {
        policy_name = name
        principal   = lookup(var.account_ids, target, target)
      }
    } if length(policy.share_targets) > 0
  ]...) : {}
}

resource "aws_ram_resource_share" "nfw_rule_group" {
  for_each = local.nfw_rule_group_share_map

  name                      = "${each.key}-nfw-rule-group-share"
  allow_external_principals = false

  tags = {
    Name = "${each.key}-nfw-rule-group-share"
  }
}

resource "aws_ram_resource_association" "nfw_rule_group" {
  for_each = local.nfw_rule_group_share_map

  resource_arn       = aws_networkfirewall_rule_group.this[each.key].arn
  resource_share_arn = aws_ram_resource_share.nfw_rule_group[each.key].arn
}

resource "aws_ram_principal_association" "nfw_rule_group" {
  for_each = local.nfw_rule_group_share_principal_map

  principal          = each.value.principal
  resource_share_arn = aws_ram_resource_share.nfw_rule_group[each.value.group_name].arn
}

resource "aws_ram_resource_share" "nfw_policy" {
  count = length(local.nfw_policy_share_targets) > 0 ? 1 : 0

  name                      = "tlz-firewall-policy-share"
  allow_external_principals = false

  tags = {
    Name = "tlz-firewall-policy-share"
  }
}

resource "aws_ram_resource_association" "nfw_policy" {
  count = length(local.nfw_policy_share_targets) > 0 ? 1 : 0

  resource_arn       = aws_networkfirewall_firewall_policy.this[0].arn
  resource_share_arn = aws_ram_resource_share.nfw_policy[0].arn
}

resource "aws_ram_principal_association" "nfw_policy" {
  for_each = local.nfw_policy_share_principal_map

  principal          = each.value
  resource_share_arn = aws_ram_resource_share.nfw_policy[0].arn
}

resource "aws_ram_resource_share" "nfw_named_policy" {
  for_each = local.nfw_named_policy_share_map

  name                      = "${each.key}-nfw-policy-share"
  allow_external_principals = false

  tags = {
    Name = "${each.key}-nfw-policy-share"
  }
}

resource "aws_ram_resource_association" "nfw_named_policy" {
  for_each = local.nfw_named_policy_share_map

  resource_arn       = aws_networkfirewall_firewall_policy.named[each.key].arn
  resource_share_arn = aws_ram_resource_share.nfw_named_policy[each.key].arn
}

resource "aws_ram_principal_association" "nfw_named_policy" {
  for_each = local.nfw_named_policy_share_principal_map

  principal          = each.value.principal
  resource_share_arn = aws_ram_resource_share.nfw_named_policy[each.value.policy_name].arn
}
