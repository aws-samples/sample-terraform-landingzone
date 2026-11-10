# EC2 Compute

Deploy EC2-based building blocks from the landing zone configuration:
third-party firewall appliances behind the gateway load balancer, and
workload compute (launch templates with auto-scaling groups) behind
application or network load balancers. Both use cases share one module,
`modules/ec2-compute`, because they build from the same blocks — launch
template, auto-scaling group, target group attachment, single instance.
The directory configuration instance of the Managed Microsoft AD setup uses
the same blocks; see [Directory Config](directory-config.md).

## How It Works

1. **Configuration entries** — `env/common.hcl` carries the collections per
   use case: `firewall_launch_templates`, `firewall_autoscaling_groups` and
   `firewall_instances` for the appliance stack, `workload_launch_templates`
   and `workload_autoscaling_groups` for the workload stack. Each stack's
   launch-template collection has a matching IMDSv1 acknowledgement list:
   `firewall_imdsv1_acknowledged_launch_templates` (firewall appliances),
   `workload_imdsv1_acknowledged_launch_templates` (workload compute), and
   `directory_config_imdsv1_acknowledged_launch_templates` (directory
   config, see [Directory Config](directory-config.md)) — each defaults to
   `[]` in `env/common.hcl.example` and feeds the module's
   `imdsv1_acknowledged_launch_templates` input for that collection only.
   The entry schemas, including `http_tokens`, are documented in the module
   README (`modules/ec2-compute/README.md`); `env/common.hcl.example` shows
   the collection keys but not `http_tokens` itself, so the README is the
   schema source.
2. **Loader** — user-data templates travel as strings. An entry carries the
   template inline (`user_data_template`) or names a repository file
   (`user_data_template_file`) that `configurations/loader.hcl` resolves to
   its content. The module itself reads no files and runs no scripts; it
   renders the template with `templatestring()` against the entry's
   `user_data_values` plus two built-in placeholders: `config_bucket` (the
   firewall configuration bucket of the security stack) and
   `config_bucket_arn` (its partition-derived ARN).
3. **Stacks** — `stacks/management/firewall-appliances` binds the module
   with dependencies on the networking stack (subnets, security groups,
   gateway load balancer target groups) and the security stack
   (configuration bucket). `stacks/workload-dev/workload-compute` runs in
   the workload account (cross-account sidecar contract) and depends on the
   management networking stack. `stacks/management/directory-config` binds
   the module with dependencies on the iam stack (directory outputs) and the
   networking stack (see [Directory Config](directory-config.md)). Switches:
   `enable_firewall_appliances`, `enable_workload_compute` and
   `enable_directory_config`, all default `false`.

## Name Resolution

Entries reference network objects by the names the networking module
assigns, not by IDs:

| Reference in an entry | Resolves against | Key form |
|---|---|---|
| `subnet_name` / `subnet_names` | networking output `subnet_ids` | `vpc_name.subnet_name` |
| `security_group_names` | networking output `security_group_ids` | `vpc_name.sg_name` |
| `target_groups` (firewall stack) | networking outputs `gwlb_target_group_arns` + `target_group_arns` | GWLB name / target group name |
| `target_groups` (workload stack) | networking output `target_group_arns` | target group name |

An unknown name fails the plan with a message that names the entry — the
module never falls back silently. Literal IDs stay possible per entry
(`subnet_id`, `subnet_ids`, `security_group_ids`) for objects that live
outside this landing zone.

## AMI Handling

Every launch template entry sets `ami_id` (format `ami-` followed by
hexadecimal characters, validated). No AMI is written into the module or the
repository: appliance images differ per vendor, per region and per
partition, so the concrete ID is a deployment value in `env/common.hcl`.

## Instance Metadata

Launch templates set `metadata_options.http_tokens = "required"` (IMDSv2) by
default. An entry that needs IMDSv1 sets `http_tokens = "optional"`
explicitly — the relaxation is visible in the configuration. Setting it costs
something: a `check` block warns on every `terraform plan` and `terraform
apply`, naming the templates that set it, and it fails `terraform test`.

An operator acknowledges a specific template from `env/common.hcl`, per
stack, without editing the module call: a name on
`firewall_imdsv1_acknowledged_launch_templates` (firewall appliances),
`workload_imdsv1_acknowledged_launch_templates` (workload compute), or
`directory_config_imdsv1_acknowledged_launch_templates` (directory config)
silences the check only for that one template in its own stack's
launch-template collection; every other `"optional"` template still warns
and still fails `terraform test`. An absent or empty list (the default)
leaves every plan exactly as it was.

A name on one of the three lists is checked only when its stack runs: the
module refuses the plan if the name is not a key of that stack's
launch-template collection, or names a template whose `http_tokens` is not
`"optional"`. A stack that is switched off (`enable_firewall_appliances`,
`enable_workload_compute` or `enable_directory_config` false; for workload
compute also an unresolved account id) is excluded from the run and its list
is never evaluated, so a misspelled name there stays silent until the stack
is switched on — the check then warns on the template the typo missed.

The acknowledgement leaves a trace outside the untracked `env/common.hcl`:
the module output `imdsv1_acknowledged_launch_templates` names every
acknowledged template of the stack in its plan and state.

## Operational Notes

- The appliance operating system and its configuration content (vendor
  licenses, rule sets, bootstrap payloads) are deployment values and vendor
  artifacts. The landing zone provisions the compute, the network path and
  the configuration bucket; what the appliance does with its user data is
  vendor-specific and lies with operations.
- Auto-scaling group target group attachments use
  `aws_autoscaling_traffic_source_attachment` (type `elbv2`), the attachment
  resource of the pinned AWS provider.
- Single instances take their network interfaces from the referenced launch
  template; instance-level settings stay limited to monitoring, termination
  protection and tags.

## Further reading

- [Module README](../modules/ec2-compute/README.md) — Inputs, outputs and usage examples
- [Configuration Reference](configuration-reference.md) — All variables, types, defaults, validations
- [Architecture](architecture.md) — Module boundaries and dependencies
