# EC2 Compute — launch templates, auto-scaling groups, single instances and
# SSM building blocks (documents, associations)
#
# Resources created here (all gated by enable_ec2_compute):
#   * aws_launch_template.this                          — one per launch_templates entry
#   * aws_autoscaling_group.this                        — one per autoscaling_groups entry
#   * aws_autoscaling_traffic_source_attachment.this    — one per ASG x target group pair
#   * aws_instance.this                                 — one per instances entry
#   * aws_ssm_document.this                             — one per ssm_documents entry
#   * aws_ssm_association.this                          — one per ssm_associations entry
#
# The module reads no files and runs no scripts: user data is rendered with
# templatestring() from configuration strings, SSM document content arrives as
# a configuration string, and there is no local-exec, no remote-exec and no
# external data source.

data "aws_partition" "current" {}

# The account the module runs in: an auto-scaling group can only be attached to
# a target group of that same account (see the traffic source attachment).
data "aws_caller_identity" "current" {}

locals {
  partition = data.aws_partition.current.partition

  # Global gate: off means every collection is empty and zero resources plan.
  launch_templates   = var.enable_ec2_compute ? var.launch_templates : {}
  autoscaling_groups = var.enable_ec2_compute ? var.autoscaling_groups : {}
  instances          = var.enable_ec2_compute ? var.instances : {}
  ssm_documents      = var.enable_ec2_compute ? var.ssm_documents : {}
  ssm_associations   = var.enable_ec2_compute ? var.ssm_associations : {}

  # Built-in placeholders for every user-data template. The bucket ARN is
  # built from the partition (aws and aws-eusc), never written as a literal.
  builtin_user_data_values = {
    config_bucket     = var.config_bucket_name
    config_bucket_arn = var.config_bucket_name != "" ? "arn:${local.partition}:s3:::${var.config_bucket_name}" : ""
  }

  # templatestring() takes a *reference* to a string as its first argument,
  # so the templates are lifted into a local map and referenced by key.
  user_data_templates = {
    for name, lt in local.launch_templates : name => lt.user_data_template
  }

  # ASG x target group pairs for the traffic source attachments.
  asg_target_group_pairs = merge([
    for asg_key, asg in local.autoscaling_groups : {
      for tg in asg.target_groups :
      "${asg_key}.${tg}" => { asg_key = asg_key, target_group = tg }
    }
  ]...)
}

# -----------------------------------------------------------------------------
# Launch templates
# -----------------------------------------------------------------------------

resource "aws_launch_template" "this" {
  for_each = local.launch_templates

  name          = each.key
  image_id      = each.value.ami_id
  instance_type = each.value.instance_type
  key_name      = each.value.key_pair != "" ? each.value.key_pair : null
  ebs_optimized = each.value.ebs_optimized

  # Security groups at template level are only valid without network
  # interfaces — with interfaces the groups belong to the interface.
  vpc_security_group_ids = (
    length(each.value.network_interfaces) == 0
    && (length(each.value.security_group_names) > 0 || length(each.value.security_group_ids) > 0)
    ) ? concat(
    [for sg in each.value.security_group_names : lookup(var.security_group_ids, sg, "")],
    each.value.security_group_ids,
  ) : null

  dynamic "iam_instance_profile" {
    for_each = each.value.iam_instance_profile != "" ? [each.value.iam_instance_profile] : []
    content {
      name = iam_instance_profile.value
    }
  }

  monitoring {
    enabled = each.value.detailed_monitoring
  }

  # IMDSv2 by default; per entry deselectable through http_tokens.
  metadata_options {
    http_tokens = each.value.http_tokens
  }

  # Configuration replacement: the template string from the configuration is
  # rendered against the placeholder map — no file access, no script run.
  user_data = each.value.user_data_template != "" ? base64encode(templatestring(
    local.user_data_templates[each.key],
    merge(local.builtin_user_data_values, each.value.user_data_values),
  )) : null

  dynamic "block_device_mappings" {
    for_each = each.value.block_device_mappings
    content {
      device_name = block_device_mappings.value.device_name
      dynamic "ebs" {
        for_each = block_device_mappings.value.ebs != null ? [block_device_mappings.value.ebs] : []
        content {
          delete_on_termination = ebs.value.delete_on_termination
          encrypted             = ebs.value.encrypted
          iops                  = ebs.value.iops
          kms_key_id            = ebs.value.kms_key_id != "" ? ebs.value.kms_key_id : null
          snapshot_id           = ebs.value.snapshot_id != "" ? ebs.value.snapshot_id : null
          throughput            = ebs.value.throughput
          volume_size           = ebs.value.volume_size
          volume_type           = ebs.value.volume_type != "" ? ebs.value.volume_type : null
        }
      }
    }
  }

  dynamic "network_interfaces" {
    for_each = each.value.network_interfaces
    content {
      device_index                 = network_interfaces.value.device_index
      description                  = network_interfaces.value.description != "" ? network_interfaces.value.description : null
      subnet_id                    = network_interfaces.value.subnet_name != "" ? lookup(var.subnet_ids, network_interfaces.value.subnet_name, "") : (network_interfaces.value.subnet_id != "" ? network_interfaces.value.subnet_id : null)
      security_groups              = length(network_interfaces.value.security_group_names) > 0 || length(network_interfaces.value.security_group_ids) > 0 ? concat([for sg in network_interfaces.value.security_group_names : lookup(var.security_group_ids, sg, "")], network_interfaces.value.security_group_ids) : null
      associate_public_ip_address  = network_interfaces.value.associate_public_ip_address
      associate_carrier_ip_address = network_interfaces.value.associate_carrier_ip_address
      delete_on_termination        = network_interfaces.value.delete_on_termination
      interface_type               = network_interfaces.value.interface_type != "" ? network_interfaces.value.interface_type : null
      network_card_index           = network_interfaces.value.network_card_index
      network_interface_id         = network_interfaces.value.network_interface_id != "" ? network_interfaces.value.network_interface_id : null
      private_ip_address           = network_interfaces.value.private_ip_address != "" ? network_interfaces.value.private_ip_address : null
      ipv4_addresses               = length(network_interfaces.value.ipv4_addresses) > 0 ? network_interfaces.value.ipv4_addresses : null
      ipv4_address_count           = network_interfaces.value.ipv4_address_count
    }
  }

  dynamic "tag_specifications" {
    for_each = length(merge(var.default_tags, each.value.tags)) > 0 ? ["instance"] : []
    content {
      resource_type = tag_specifications.value
      tags          = merge(var.default_tags, each.value.tags, { Name = each.key })
    }
  }

  tags = merge(var.default_tags, each.value.tags, { Name = each.key })

  lifecycle {
    precondition {
      condition = alltrue([
        for sg in each.value.security_group_names : contains(keys(var.security_group_ids), sg)
      ])
      error_message = "Launch template ${each.key}: a security_group_names entry is not a key of security_group_ids — the networking stack supplies that map (vpc_name.sg_name)."
    }
    precondition {
      condition = alltrue([
        for nic in each.value.network_interfaces :
        nic.subnet_name == "" || contains(keys(var.subnet_ids), nic.subnet_name)
      ])
      error_message = "Launch template ${each.key}: a network interface names a subnet that is not a key of subnet_ids — the networking stack supplies that map (vpc_name.subnet_name)."
    }
    precondition {
      condition = alltrue([
        for nic in each.value.network_interfaces : alltrue([
          for sg in nic.security_group_names : contains(keys(var.security_group_ids), sg)
        ])
      ])
      error_message = "Launch template ${each.key}: a network interface names a security group that is not a key of security_group_ids."
    }
  }
}

# -----------------------------------------------------------------------------
# IMDSv1 warning — advisory, from the compliance layer
# -----------------------------------------------------------------------------
# http_tokens defaults to "required" (IMDSv2) and the module never writes
# "optional" itself, so the shipped default is safe. The knob stays because an
# image or agent that cannot sign a token request needs it, and removing a
# value the interface already accepts is a decision about the interface, not a
# fix. What the knob may not be is silent: an instance reachable over IMDSv1 is
# a state the account's own auditor raises, and that ticket goes to the account
# owner rather than to whoever set the value. So a template that selects
# "optional" says so on every plan and every apply, naming the templates.
#
# A check block, deliberately, not a variable validation: validation would
# refuse the value outright, and refusing it is the module owner's call.
#
# imdsv1_acknowledged_launch_templates lets that call be made per template,
# visibly, in the configuration: a name on the list silences this check for
# that one template only, everything else that selects "optional" still fails.
# A stale acknowledgement (a name that is not a launch_templates key, or that
# names a template whose http_tokens is not "optional") is not this check's
# business — the variable's own validation (variables.tf) refuses the plan
# outright before the check ever evaluates, which is stronger than a warning.
locals {
  imdsv1_launch_templates = sort([
    for name, lt in local.launch_templates :
    name if lt.http_tokens == "optional" && !contains(var.imdsv1_acknowledged_launch_templates, name)
  ])
}

check "launch_templates_imdsv1_optional" {
  assert {
    condition     = length(local.imdsv1_launch_templates) == 0
    error_message = "Launch templates set http_tokens = \"optional\", leaving IMDSv1 reachable on every instance started from them [${join(", ", local.imdsv1_launch_templates)}]. Over IMDSv1 any process that reaches the link-local metadata address reads the instance role's credentials without a signed token. Set http_tokens = \"required\" (the module default), or, if an image on it cannot sign a token request, acknowledge the template's name in env/common.hcl on its stack's list: firewall_imdsv1_acknowledged_launch_templates (firewall appliances), workload_imdsv1_acknowledged_launch_templates (workload compute) or directory_config_imdsv1_acknowledged_launch_templates (directory config); a direct module call sets imdsv1_acknowledged_launch_templates. See docs/ec2-compute.md."
  }
}

# -----------------------------------------------------------------------------
# Auto-scaling groups and target group attachments
# -----------------------------------------------------------------------------

resource "aws_autoscaling_group" "this" {
  for_each = local.autoscaling_groups

  name                      = each.key
  min_size                  = each.value.min_size
  max_size                  = each.value.max_size
  desired_capacity          = each.value.desired_capacity
  health_check_type         = each.value.health_check_type
  health_check_grace_period = each.value.health_check_grace_period
  max_instance_lifetime     = each.value.max_instance_lifetime

  vpc_zone_identifier = concat(
    [for sn in each.value.subnet_names : lookup(var.subnet_ids, sn, "")],
    each.value.subnet_ids,
  )

  launch_template {
    id      = aws_launch_template.this[each.value.launch_template].id
    version = "$Latest"
  }

  dynamic "tag" {
    for_each = merge(var.default_tags, each.value.tags)
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.launch_templates), each.value.launch_template)
      error_message = "Auto-scaling group ${each.key}: launch_template ${each.value.launch_template} is not a key of the launch_templates collection."
    }
    precondition {
      condition = alltrue([
        for sn in each.value.subnet_names : contains(keys(var.subnet_ids), sn)
      ])
      error_message = "Auto-scaling group ${each.key}: a subnet_names entry is not a key of subnet_ids — the networking stack supplies that map (vpc_name.subnet_name)."
    }
  }
}

# Target group attachment through the traffic source attachment the pinned
# provider (~> 6.0) supports.
resource "aws_autoscaling_traffic_source_attachment" "this" {
  for_each = local.asg_target_group_pairs

  autoscaling_group_name = aws_autoscaling_group.this[each.value.asg_key].name

  traffic_source {
    identifier = lookup(var.target_group_arns, each.value.target_group, "")
    type       = "elbv2"
  }

  lifecycle {
    precondition {
      condition     = contains(keys(var.target_group_arns), each.value.target_group)
      error_message = "Auto-scaling group ${each.value.asg_key}: target group ${each.value.target_group} is not a key of target_group_arns — the networking stack supplies that map."
    }
    # AWS attaches an auto-scaling group only to a target group of the same
    # account; a management-owned target group fails at apply. The ARN's fifth
    # field is the owning account, compared against the caller.
    precondition {
      condition     = try(split(":", lookup(var.target_group_arns, each.value.target_group, "::::"))[4], "") == data.aws_caller_identity.current.account_id
      error_message = "Auto-scaling group ${each.value.asg_key}: target group ${each.value.target_group} belongs to account ${try(split(":", lookup(var.target_group_arns, each.value.target_group, "::::"))[4], "?")}, not to this account (${data.aws_caller_identity.current.account_id}). An auto-scaling group can only be attached to a target group of its own account: declare the target group in this account (workload compute: workload_target_groups, stacks/workload-dev/networking) and name it there."
    }
  }
}

# -----------------------------------------------------------------------------
# Single instances (firewall single instances, manager nodes, the directory
# configuration instance) — the network interfaces come from the referenced
# launch template.
# -----------------------------------------------------------------------------

resource "aws_instance" "this" {
  for_each = local.instances

  launch_template {
    id      = aws_launch_template.this[each.value.launch_template].id
    version = "$Latest"
  }

  monitoring              = each.value.detailed_monitoring
  disable_api_termination = each.value.termination_protection
  # Firewall appliances forward traffic and need the source/destination check
  # of the primary interface off; null keeps the service default (on).
  source_dest_check = each.value.source_dest_check

  tags = merge(var.default_tags, each.value.tags, { Name = each.key })

  lifecycle {
    precondition {
      condition     = contains(keys(var.launch_templates), each.value.launch_template)
      error_message = "Instance ${each.key}: launch_template ${each.value.launch_template} is not a key of the launch_templates collection."
    }
  }
}

# -----------------------------------------------------------------------------
# SSM building blocks: documents and associations. Content is a configuration
# string; the association targets instances of this module (by key) or a tag
# selector. This is the declarative path the directory configuration instance
# uses (stacks/management/directory-config).
# -----------------------------------------------------------------------------

resource "aws_ssm_document" "this" {
  for_each = local.ssm_documents

  name            = each.key
  document_type   = each.value.document_type
  document_format = each.value.document_format
  content         = each.value.content

  tags = merge(var.default_tags, each.value.tags)
}

resource "aws_ssm_association" "this" {
  for_each = local.ssm_associations

  name = each.value.document_key != "" ? aws_ssm_document.this[each.value.document_key].name : each.value.document_name

  parameters          = each.value.parameters
  schedule_expression = each.value.schedule_expression != "" ? each.value.schedule_expression : null

  dynamic "targets" {
    for_each = length(each.value.instance_keys) > 0 ? [each.value.instance_keys] : []
    content {
      key    = "InstanceIds"
      values = [for k in targets.value : aws_instance.this[k].id]
    }
  }

  dynamic "targets" {
    for_each = each.value.target_tag_key != "" ? [each.value.target_tag_key] : []
    content {
      key    = "tag:${targets.value}"
      values = each.value.target_tag_values
    }
  }

  lifecycle {
    precondition {
      condition     = each.value.document_key == "" || contains(keys(var.ssm_documents), each.value.document_key)
      error_message = "SSM association ${each.key}: document_key ${each.value.document_key} is not a key of the ssm_documents collection."
    }
    precondition {
      condition = alltrue([
        for k in each.value.instance_keys : contains(keys(var.instances), k)
      ])
      error_message = "SSM association ${each.key}: an instance_keys entry is not a key of the instances collection."
    }
  }
}
