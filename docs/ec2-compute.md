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
   the workload account (cross-account sidecar contract) and depends on two
   stacks: `stacks/workload-dev/networking` in the same account, which owns
   the security groups, target groups and the internal load balancer
   (`modules/workload-networking`, see [Workload networking](#workload-networking)),
   and the management networking stack, which owns the shared subnets.
   `stacks/management/directory-config` binds
   the module with dependencies on the iam stack (directory outputs) and the
   networking stack (see [Directory Config](directory-config.md)). Switches:
   `enable_firewall_appliances`, `enable_workload_compute` (both workload
   units) and `enable_directory_config`, all default `false`.

## Name Resolution

Entries reference network objects by the names the networking modules
assign, not by IDs:

| Reference in an entry | Resolves against | Key form |
|---|---|---|
| `subnet_name` / `subnet_names` | networking output `subnet_ids` | `vpc_name.subnet_name` |
| `security_group_names` (firewall and directory stacks) | networking output `security_group_ids` | `vpc_name.sg_name` |
| `security_group_names` (workload stack) | workload-networking output `security_group_ids` (`workload_security_groups`) | `vpc_name.sg_name` |
| `target_groups` (firewall stack) | networking outputs `gwlb_target_group_arns` + `target_group_arns` | GWLB name / target group name |
| `target_groups` (workload stack) | workload-networking output `target_group_arns` (`workload_target_groups`) | target group name |

An unknown name fails the plan with a message that names the entry — the
module never falls back silently. Literal IDs stay possible per entry
(`subnet_id`, `subnet_ids`, `security_group_ids`) for objects that live
outside this landing zone. A target group must belong to the account the
stack runs in: the module compares the account of the resolved ARN with the
caller and refuses a foreign target group at plan, because AWS attaches an
auto-scaling group only to a target group of its own account.

## Workload networking

The workload fleet runs in the workload account, in a VPC the management
account owns and shares through RAM. AWS fixes what has to be owned where: an
auto-scaling group, its target group and the load balancer in front of it must
be in the same account, the target group must register instances, and a
participant of a shared VPC launches instances only with security groups it
owns. The subnets stay management-owned. `stacks/workload-dev/networking`
therefore creates the workload account's own security groups
(`workload_security_groups`), target groups (`workload_target_groups`,
`target_type = "instance"`) and internal application or network load balancers
(`workload_load_balancers`) in the shared VPC; the entry schemas are the ones of
the management `vpcs[].security_groups`, `target_groups` and `load_balancers`
collections, without subnet selectors and without an internet-facing scheme
(see the [module README](../modules/workload-networking/README.md)). The
compute unit resolves `security_group_names` and `target_groups` against the
names this unit publishes; management-owned groups are not resolvable in the
workload account.

Prerequisites in `env/common.hcl`:

- `enable_workload_compute = true` — one toggle gates both units, so the
  compute unit never depends on an excluded unit;
- `enable_ram_sharing = true` and `ram.<dns suffix>` among the
  `additional_aws_service_access_principals` of the organization (RAM trusted
  access);
- `share_targets = ["Workload-Dev"]` on every `vpcs[].subnets[]` entry the
  workload uses, so the subnet IDs resolve in the workload account;
- the three collections above, and for an `HTTPS`/`TLS` listener an ACM
  certificate requested or imported in the workload account (a certificate of
  another account is refused at plan).

Order on apply, derived by Terragrunt from the dependencies: management
organization (RAM trusted access) → accounts → management networking (VPC,
shared subnets) → workload networking → workload compute. On destroy the
order reverses, and the workload load balancer carries deletion protection as
a fixed value, so its removal is the two-step process described in
[modules/networking/README.md](../modules/networking/README.md#deletion-protection).
What only the apply can show: a subnet that is not shared with the account
(`InvalidSubnetID.NotFound`), and access-log delivery into the central ELB log
bucket, which depends on that bucket's policy admitting the workload account.

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
