# EC2 Compute Module

Creates EC2 compute building blocks — launch templates, auto-scaling groups with target group attachment, single instances and SSM documents/associations — for two use cases: third-party firewall appliances (single instances, manager nodes, fleets behind the gateway load balancer) and workload compute (fleets behind application or network load balancers). The directory configuration instance of the Managed Microsoft AD setup builds on the same blocks (`stacks/management/directory-config`).

The module reads no files and runs no scripts: user data is rendered with `templatestring()` from a template string and a placeholder map, SSM document content arrives as a configuration string, and there is no `local-exec`, no `remote-exec` and no `external` data source. Every AMI is a per-entry input with a format validation — no AMI is written into the module. `metadata_options.http_tokens` defaults to `"required"` (IMDSv2), deselectable per entry; deselecting it warns on every plan and apply, naming the templates, and fails `terraform test` — unless the template's name is on `imdsv1_acknowledged_launch_templates`, a deliberate, visible, per-template acknowledgement, never a blanket switch.

Name references resolve against maps the stacks supply from their dependency outputs: subnets and security groups against the networking outputs (`subnet_ids`, `security_group_ids`), target groups against `target_group_arns`/`gwlb_target_group_arns`. An unknown name fails the plan with a message naming the entry — no silent fallback.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `enable_ec2_compute` | Global gate of the module. `false` means zero resources, regardless of the collections | `bool` | `false` | no |
| `launch_templates` | Launch templates by name. `ami_id` is mandatory per entry (format `ami-<hex>`); `http_tokens` defaults to `required` (IMDSv2) — an entry that sets `optional` warns on every plan and apply, naming the templates, and fails `terraform test` unless the template's name is on `imdsv1_acknowledged_launch_templates`; `user_data_template` is a template string rendered with `templatestring()` against `user_data_values` plus the built-in placeholders `config_bucket` and `config_bucket_arn`. Optional per entry: `key_pair`, `iam_instance_profile`, `detailed_monitoring`, `ebs_optimized`, `security_group_names`/`security_group_ids`, `block_device_mappings` (with an `ebs` block: `delete_on_termination`, `encrypted` default `true`, `iops`, `kms_key_id`, `snapshot_id`, `throughput`, `volume_size`, `volume_type`), `network_interfaces` (`device_index`, `description`, `subnet_name`/`subnet_id`, `security_group_names`/`security_group_ids`, `associate_public_ip_address`, `associate_carrier_ip_address`, `delete_on_termination`, `interface_type`, `network_card_index`, `network_interface_id`, `private_ip_address`, `ipv4_addresses`, `ipv4_address_count`) and `tags` | `map(object)` | `{}` | no |
| `imdsv1_acknowledged_launch_templates` | Launch template names whose `http_tokens = "optional"` is a deliberate, acknowledged choice — not a blanket switch: each name silences the IMDSv1 check for that one template only, every other `optional` template still fails `terraform test`. What acknowledging costs: on that template, any process reaching the instance's link-local metadata address reads its role's credentials without a signed token. A name that is not a key of `launch_templates`, or that names a template whose `http_tokens` is not `optional`, is a stale acknowledgement and fails validation rather than passing unnoticed | `list(string)` | `[]` | no |
| `autoscaling_groups` | Auto-scaling groups by name. `launch_template` names an entry of `launch_templates`; `target_groups` names entries of `target_group_arns`; `subnet_names` resolve through `subnet_ids`. Optional per entry: `desired_capacity`, `health_check_type` (default `EC2`), `health_check_grace_period` (default `300`), `max_instance_lifetime`, `subnet_ids` (literal IDs) and `tags` (propagated at launch) | `map(object)` | `{}` | no |
| `instances` | Single instances by name (firewall single instances, manager nodes, the directory configuration instance). `launch_template` names an entry of `launch_templates`; the network interfaces come from that launch template. Optional per entry: `detailed_monitoring`, `termination_protection` (default `false`), `source_dest_check` (null keeps the service default; firewall appliances set `false`) and `tags` | `map(object)` | `{}` | no |
| `ssm_documents` | SSM documents by name. The `content` is a string from the configuration — the module reads no files. Optional per entry: `document_type` (default `Command`), `document_format` (`JSON` default or `YAML`) and `tags` | `map(object)` | `{}` | no |
| `ssm_associations` | SSM associations by name. Exactly one of `document_key` (an entry of `ssm_documents`) or `document_name` (an existing document, e.g. `AWS-JoinDirectoryServiceDomain`) names the document; the target is a list of `instance_keys` or a tag selector (`target_tag_key`, `target_tag_values`). Optional per entry: `parameters` and `schedule_expression` | `map(object)` | `{}` | no |
| `subnet_ids` | Resolution map subnet name → subnet ID, supplied by the stack from the networking outputs (`subnet_ids`, keys `vpc_name.subnet_name`). Entries reference subnets by these names | `map(string)` | `{}` | no |
| `security_group_ids` | Resolution map security group name → security group ID, supplied by the stack from the networking outputs (`security_group_ids`, keys `vpc_name.sg_name`) | `map(string)` | `{}` | no |
| `target_group_arns` | Resolution map target group name → target group ARN, supplied by the stack from the networking outputs (`target_group_arns` and `gwlb_target_group_arns`) | `map(string)` | `{}` | no |
| `config_bucket_name` | Name of the configuration bucket (`modules/security`, `firewall_config_bucket_name` output). Available to every user-data template as the built-in placeholders `config_bucket` and `config_bucket_arn`; empty leaves both placeholders empty | `string` | `""` | no |
| `default_tags` | Tags merged into every resource of the module | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| `launch_template_ids` | Map of launch template name to launch template ID |
| `autoscaling_group_names` | Map of auto-scaling group key to the created group name |
| `instance_ids` | Map of instance key to instance ID |
| `ssm_document_names` | Map of SSM document key to document name |
| `ssm_association_ids` | Map of SSM association key to association ID |
| `imdsv1_acknowledged_launch_templates` | Launch template names whose `http_tokens = "optional"` was acknowledged for this call (`[]` when none) — the trace in plan and state of an acknowledgement made in the untracked `env/common.hcl` |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_ec2_compute` toggle and the collections that are filled.

- `aws_launch_template`
- `aws_autoscaling_group`
- `aws_autoscaling_traffic_source_attachment`
- `aws_instance`
- `aws_ssm_document`
- `aws_ssm_association`

## Usage Example

### Firewall appliances (stacks/management/firewall-appliances)

An appliance fleet behind the gateway load balancer, plus a manager node as a single instance. The user-data template renders the configuration replacement values; `config_bucket` is a built-in placeholder carrying the firewall configuration bucket of the security stack.

```hcl
module "firewall_appliances" {
  source = "./modules/ec2-compute"

  enable_ec2_compute = true

  launch_templates = {
    appliance = {
      ami_id             = var.appliance_ami_id # vendor AMI of this partition
      instance_type      = "c5.xlarge"
      user_data_template = "config-bucket=$${config_bucket}; license=$${license_key}"
      user_data_values   = { license_key = var.license_key }
      network_interfaces = [{
        device_index         = 0
        subnet_name          = "inspection.firewall-a"
        security_group_names = ["inspection.appliance-mgmt"]
      }]
    }
  }

  autoscaling_groups = {
    appliance-fleet = {
      launch_template = "appliance"
      min_size        = 1
      max_size        = 3
      subnet_names    = ["inspection.firewall-a"]
      target_groups   = ["central-inspection"] # GWLB target group
    }
  }

  instances = {
    manager = { launch_template = "appliance" }
  }

  subnet_ids         = module.networking.subnet_ids
  security_group_ids = module.networking.security_group_ids
  target_group_arns  = module.networking.gwlb_target_group_arns
  config_bucket_name = module.security.firewall_config_bucket_name
}
```

### Workload compute (stacks/workload-dev/workload-compute)

A workload fleet behind an application load balancer target group.

```hcl
module "workload_compute" {
  source = "./modules/ec2-compute"

  enable_ec2_compute = true

  launch_templates = {
    web = {
      ami_id             = var.web_ami_id
      instance_type      = "m5.large"
      user_data_template = "environment=$${environment}"
      user_data_values   = { environment = "dev" }
      security_group_names = ["workload.web"]
      block_device_mappings = [{
        device_name = "/dev/xvda"
        ebs         = { volume_size = 50, volume_type = "gp3" }
      }]
    }
  }

  autoscaling_groups = {
    web-fleet = {
      launch_template = "web"
      min_size        = 2
      max_size        = 6
      subnet_names    = ["workload.private-a", "workload.private-b"]
      target_groups   = ["web-tg"]
    }
  }

  subnet_ids         = module.networking.subnet_ids
  security_group_ids = module.networking.security_group_ids
  target_group_arns  = module.networking.target_group_arns
}
```

## Further Documentation

- [EC2 Compute](../../docs/ec2-compute.md) — Use cases, name resolution and operational notes
- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
