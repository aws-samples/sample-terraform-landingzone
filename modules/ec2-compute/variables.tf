# EC2 Compute — variables
#
# One module for two use cases: firewall appliances of third-party vendors
# (single instances, manager nodes, auto-scaling groups behind the gateway
# load balancer) and workload compute (launch templates plus auto-scaling
# groups behind application or network load balancers). Both build from the
# same blocks, so both live here.
#
# Conventions:
#   * enable_ec2_compute defaults to false; off or empty collections mean
#     zero resources.
#   * Every AMI is a per-entry input with a format validation — no AMI is
#     written into the module.
#   * User data is rendered with templatestring() from a template string and
#     a placeholder map; the module reads no files and runs no scripts.
#   * Name references (subnets, security groups, target groups, launch
#     templates) resolve against the maps the stacks supply from their
#     dependency outputs; an unknown name fails the plan with a message that
#     names the entry (resource preconditions, no silent fallback).

variable "enable_ec2_compute" {
  description = "Global gate of the module. false means zero resources, regardless of the collections."
  type        = bool
  default     = false
}

variable "launch_templates" {
  description = "Launch templates by name. ami_id is mandatory per entry (format ami-<hex>); http_tokens defaults to required (IMDSv2); user_data_template is a template string rendered with templatestring() against user_data_values plus the built-in placeholders config_bucket and config_bucket_arn."
  type = map(object({
    ami_id               = string
    instance_type        = string
    key_pair             = optional(string, "")
    iam_instance_profile = optional(string, "")
    detailed_monitoring  = optional(bool, false)
    ebs_optimized        = optional(bool)
    http_tokens          = optional(string, "required")
    user_data_template   = optional(string, "")
    user_data_values     = optional(map(string), {})
    security_group_names = optional(list(string), [])
    security_group_ids   = optional(list(string), [])
    block_device_mappings = optional(list(object({
      device_name = string
      ebs = optional(object({
        delete_on_termination = optional(bool, true)
        encrypted             = optional(bool, true)
        iops                  = optional(number)
        kms_key_id            = optional(string, "")
        snapshot_id           = optional(string, "")
        throughput            = optional(number)
        volume_size           = optional(number)
        volume_type           = optional(string, "")
      }))
    })), [])
    network_interfaces = optional(list(object({
      device_index                 = optional(number, 0)
      description                  = optional(string, "")
      subnet_name                  = optional(string, "")
      subnet_id                    = optional(string, "")
      security_group_names         = optional(list(string), [])
      security_group_ids           = optional(list(string), [])
      associate_public_ip_address  = optional(bool)
      associate_carrier_ip_address = optional(bool)
      delete_on_termination        = optional(bool)
      interface_type               = optional(string, "")
      network_card_index           = optional(number)
      network_interface_id         = optional(string, "")
      private_ip_address           = optional(string, "")
      ipv4_addresses               = optional(list(string), [])
      ipv4_address_count           = optional(number)
    })), [])
    tags = optional(map(string), {})
  }))
  default = {}

  validation {
    condition = alltrue([
      for lt in var.launch_templates : can(regex("^ami-[0-9a-f]+$", lt.ami_id))
    ])
    error_message = "Every launch template entry must set ami_id in the form ami-<hexadecimal characters> — no AMI is written into the module."
  }

  validation {
    condition = alltrue([
      for lt in var.launch_templates : contains(["required", "optional"], lt.http_tokens)
    ])
    error_message = "http_tokens must be \"required\" (IMDSv2, the default) or \"optional\"."
  }
}

variable "imdsv1_acknowledged_launch_templates" {
  description = "Launch template names whose http_tokens = \"optional\" is a deliberate, acknowledged choice — not a blanket switch: each name silences the launch_templates_imdsv1_optional check for that one template only, every other \"optional\" template still fails terraform test and still warns on every plan and apply. What acknowledging costs: on that template, any process that reaches the instance's link-local metadata address reads its role's credentials without a signed token — IMDSv1 stays reachable there for as long as the name stays on this list. A name that is not a key of launch_templates, or that names a template whose http_tokens is not \"optional\", is a stale acknowledgement and fails validation rather than passing unnoticed."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.imdsv1_acknowledged_launch_templates) == length(toset(var.imdsv1_acknowledged_launch_templates))
    error_message = "imdsv1_acknowledged_launch_templates must not repeat a name."
  }

  validation {
    condition = alltrue([
      for name in var.imdsv1_acknowledged_launch_templates : contains(keys(var.launch_templates), name)
    ])
    error_message = "Every name in imdsv1_acknowledged_launch_templates must be a key of launch_templates — a stale acknowledgement (a name that no longer exists) must not pass silently."
  }

  validation {
    condition = alltrue([
      for name in var.imdsv1_acknowledged_launch_templates :
      !contains(keys(var.launch_templates), name) || var.launch_templates[name].http_tokens == "optional"
    ])
    error_message = "Every name in imdsv1_acknowledged_launch_templates must name a launch_templates entry whose http_tokens is \"optional\" — acknowledging a template that already uses \"required\" (IMDSv2) is a stale acknowledgement and must not pass silently."
  }
}

variable "autoscaling_groups" {
  description = "Auto-scaling groups by name. launch_template names an entry of launch_templates; target_groups names entries of target_group_arns; subnet_names resolve through subnet_ids."
  type = map(object({
    launch_template           = string
    min_size                  = number
    max_size                  = number
    desired_capacity          = optional(number)
    health_check_type         = optional(string, "EC2")
    health_check_grace_period = optional(number, 300)
    max_instance_lifetime     = optional(number)
    subnet_names              = optional(list(string), [])
    subnet_ids                = optional(list(string), [])
    target_groups             = optional(list(string), [])
    tags                      = optional(map(string), {})
  }))
  default = {}

  validation {
    condition = alltrue([
      for asg in var.autoscaling_groups : contains(["EC2", "ELB"], asg.health_check_type)
    ])
    error_message = "health_check_type must be \"EC2\" (the default) or \"ELB\"."
  }

  # The module joins the map key and each target group name with "." into the
  # traffic source attachment keys ("<asg>.<target group>"). A dot inside
  # either part would let two different configurations produce the same key,
  # and merge() would silently overwrite one attachment. The character set
  # therefore excludes the separator.
  validation {
    condition = alltrue(flatten([
      for name, asg in var.autoscaling_groups : concat(
        [can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", name))],
        [for tg in asg.target_groups : can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", tg))]
      )
    ]))
    error_message = "Autoscaling group keys and their target_groups entries must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — the module builds \"<asg>.<target group>\" attachment keys from them, and a dot inside a name could collide two keys and silently drop an attachment."
  }
}

variable "instances" {
  description = "Single instances by name (firewall single instances, manager nodes, the directory configuration instance). launch_template names an entry of launch_templates; the network interfaces come from that launch template."
  type = map(object({
    launch_template        = string
    detailed_monitoring    = optional(bool)
    termination_protection = optional(bool, false)
    source_dest_check      = optional(bool)
    tags                   = optional(map(string), {})
  }))
  default = {}
}

variable "ssm_documents" {
  description = "SSM documents by name. The content is a string from the configuration — the module reads no files."
  type = map(object({
    content         = string
    document_type   = optional(string, "Command")
    document_format = optional(string, "JSON")
    tags            = optional(map(string), {})
  }))
  default = {}

  validation {
    condition = alltrue([
      for doc in var.ssm_documents : contains(["JSON", "YAML"], doc.document_format)
    ])
    error_message = "document_format must be \"JSON\" (the default) or \"YAML\"."
  }
}

variable "ssm_associations" {
  description = "SSM associations by name. Exactly one of document_key (an entry of ssm_documents) or document_name (an existing document, e.g. AWS-JoinDirectoryServiceDomain) names the document; the target is a list of instance keys or a tag selector."
  type = map(object({
    document_key        = optional(string, "")
    document_name       = optional(string, "")
    parameters          = optional(map(string), {})
    instance_keys       = optional(list(string), [])
    target_tag_key      = optional(string, "")
    target_tag_values   = optional(list(string), [])
    schedule_expression = optional(string, "")
  }))
  default = {}

  validation {
    condition = alltrue([
      for assoc in var.ssm_associations :
      (assoc.document_key != "" && assoc.document_name == "") || (assoc.document_key == "" && assoc.document_name != "")
    ])
    error_message = "Every SSM association must name its document through exactly one of document_key (module document) or document_name (existing document)."
  }

  validation {
    condition = alltrue([
      for assoc in var.ssm_associations :
      length(assoc.instance_keys) > 0 || assoc.target_tag_key != ""
    ])
    error_message = "Every SSM association must carry a target: instance_keys (keys of the instances collection) or target_tag_key with target_tag_values."
  }
}

variable "subnet_ids" {
  description = "Resolution map subnet name to subnet ID, supplied by the stack from the networking outputs (subnet_ids, keys vpc_name.subnet_name). Entries reference subnets by these names."
  type        = map(string)
  default     = {}
}

variable "security_group_ids" {
  description = "Resolution map security group name to security group ID, supplied by the stack from the networking outputs (security_group_ids, keys vpc_name.sg_name)."
  type        = map(string)
  default     = {}
}

variable "target_group_arns" {
  description = "Resolution map target group name to target group ARN, supplied by the stack from the networking outputs (target_group_arns and gwlb_target_group_arns)."
  type        = map(string)
  default     = {}
}

variable "config_bucket_name" {
  description = "Name of the configuration bucket (modules/security, firewall_config_bucket_name output). Available to every user-data template as the built-in placeholders config_bucket and config_bucket_arn; empty leaves both placeholders empty."
  type        = string
  default     = ""
}

variable "default_tags" {
  description = "Tags merged into every resource of the module."
  type        = map(string)
  default     = {}
}
