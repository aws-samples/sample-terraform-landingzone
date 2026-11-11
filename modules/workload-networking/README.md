# Workload Networking Module

Creates the network objects a workload account has to own itself when its compute runs in a VPC the management account owns and shares: security groups, target groups and internal application or network load balancers. AWS fixes this split — an auto-scaling group, its target group and the load balancer in front of it must be in the same account, the target group must register instances, and a participant of a shared VPC launches instances only with security groups it owns — so `modules/networking` keeps the VPC, the subnets and the share, and this module supplies what `modules/ec2-compute` resolves by name in the workload account (`stacks/workload-dev/networking` → `stacks/workload-dev/workload-compute`).

The module creates no VPC, no subnet and no share. The VPC and subnet IDs arrive as resolution maps from the management networking outputs (`vpc_ids`, `subnet_ids`); an unknown `vpc_name` or subnet name fails the plan with a message naming the entry — no silent fallback. The module reads no files and runs no scripts.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `enable` | Global gate of the module. `false` means zero resources, regardless of the collections | `bool` | `false` | no |
| `vpc_ids` | Resolution map VPC name → VPC ID from the management networking output `vpc_ids`; every `vpc_name` of the collections must be a key | `map(string)` | `{}` | no |
| `subnet_ids` | Resolution map `vpc_name.subnet_name` → subnet ID from the management networking output `subnet_ids` (the subnets shared with this account); a load balancer's `subnet_names` resolve as `vpc_name.subnet_name` against it | `map(string)` | `{}` | no |
| `security_groups` | Security groups of this account, one entry per group with its `vpc_name`, `name`, optional `description` and `tags`, and `ingress`/`egress` rules in the schema of `modules/networking` without `source_subnets`: `types` or `protocol`/`from_port`/`to_port`, sources `cidr_blocks`, `ipv6_cidr_blocks`, `source_security_group` (a group of this module in the same VPC) and `prefix_list_id`, an optional stable `name` per rule, and `acknowledge_world_open_all_protocols` on an ingress rule that opens every port to the internet. Published as `vpc_name.sg_name` in `security_group_ids` | `list(object)` | `[]` | no |
| `target_groups` | Target groups of this account, the schema of `modules/networking` `target_groups` (an entry moves by cut and paste): `name`, `port`, `protocol`, `vpc_name`, `target_type` (must be `instance`, the only type an auto-scaling group attaches to), and the optional `deregistration_delay`, `slow_start`, `algorithm`, `stickiness`, `preserve_client_ip`, `proxy_protocol_v2`, `connection_termination`, `target_failover`, `protocol_version` and `health_check` | `list(object)` | `[]` | no |
| `load_balancers` | Internal load balancers of this account, the internal subset of `modules/networking` `load_balancers`: `name`, `type` (`application` or `network`), `vpc_name`, `subnet_names` (shared subnets of that VPC), `scheme` (`internal` only), `security_groups` (names of this module's groups in the same VPC; an application load balancer names at least one), `access_logs`, the application load balancer attributes (`idle_timeout`, `enable_http2`, `desync_mitigation_mode`, `enable_xff_client_port`, `xff_header_processing_mode`, `enable_tls_headers`, `enable_waf_fail_open`), `enable_cross_zone_load_balancing` and `listeners` (`port`, `protocol`, `target_group` of this module, optional `ssl_policy` and `certificate_arn`). An `HTTPS`/`TLS` listener without `ssl_policy` gets `ELBSecurityPolicy-TLS13-1-2-2021-06`; its certificate must belong to this account | `list(object)` | `[]` | no |
| `default_tags` | Tags merged into every resource of the module | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| `security_group_ids` | Map `vpc_name.sg_name` → security group ID — the `security_group_ids` resolution map of `modules/ec2-compute` in the workload account |
| `target_group_arns` | Map of target group name → target group ARN — the `target_group_arns` resolution map of `modules/ec2-compute` in the workload account |
| `load_balancer_arns` | Map of load balancer name → load balancer ARN |
| `load_balancer_dns_names` | Map of load balancer name → the DNS name clients inside the VPC connect to |

## Resources

The module creates the resource types below. Which of them a run actually creates depends on the inputs — the `enable` toggle and the collections that are filled.

| File | Resource types |
|---|---|
| `security-groups.tf` | `aws_security_group`, `aws_security_group_rule` |
| `load-balancing.tf` | `aws_lb_target_group`, `aws_lb`, `aws_lb_listener` |

## What the plan refuses

- A `vpc_name` that is not a key of `vpc_ids`, a `subnet_names` entry whose `vpc_name.subnet_name` is not a key of `subnet_ids` (the subnet is not shared with this account), a listener `target_group` that is not an entry of `target_groups`.
- `scheme = "internet-facing"`: a public entry point needs the authenticated edge `modules/networking` enforces, and stays there.
- `target_type` other than `instance`: AWS refuses the attachment of an auto-scaling group to any other type.
- A `certificate_arn` of another account: ACM certificates are account-bound; request or import the certificate in the workload account.
- An ingress rule that opens every port to `0.0.0.0/0`, `::/0` or a `/1` half of the address space without `acknowledge_world_open_all_protocols = true` on the rule.
- A `source_security_group` or a load balancer `security_groups` entry that is not a group of this module in the same VPC: a management-owned group is not resolvable in the workload account.

What only the apply can tell: a subnet that is not shared with this account, or an organization without RAM sharing enabled, fails the load balancer creation with `InvalidSubnetID.NotFound` — the plan cannot see the share.

## Deletion protection

`aws_lb.this` is created with `enable_deletion_protection = true` as a fixed value, like the load balancers of `modules/networking`. Destroying one is a two-step process: turn the protection off through console or API, then destroy — see [modules/networking/README.md](../networking/README.md#deletion-protection). The destroy order across stacks is workload compute first, then this module, then management networking.

## Usage Example

A workload fleet behind an internal application load balancer in the shared `workload` VPC. The compute module in the same account resolves the group and the target group by the names this module publishes.

```hcl
module "workload_networking" {
  source = "./modules/workload-networking"

  enable = true

  vpc_ids    = module.networking.vpc_ids    # management networking outputs
  subnet_ids = module.networking.subnet_ids # the shared subnets

  security_groups = [
    {
      vpc_name = "workload"
      name     = "alb"
      ingress  = [{ types = ["HTTPS"], cidr_blocks = ["10.0.0.0/8"] }]
    },
    {
      vpc_name = "workload"
      name     = "web"
      ingress  = [{ types = ["HTTP"], source_security_group = "alb" }]
    },
  ]

  target_groups = [
    { name = "web-tg", port = 80, protocol = "HTTP", vpc_name = "workload" }
  ]

  load_balancers = [
    {
      name            = "web-alb"
      type            = "application"
      vpc_name        = "workload"
      subnet_names    = ["private-a", "private-b"]
      security_groups = ["alb"]
      listeners = [{
        port            = 443
        protocol        = "HTTPS"
        target_group    = "web-tg"
        certificate_arn = var.web_certificate_arn # an ACM certificate of the workload account
      }]
    }
  ]
}

module "workload_compute" {
  source = "./modules/ec2-compute"

  enable_ec2_compute = true
  launch_templates = {
    web = { ami_id = var.web_ami_id, instance_type = "m5.large", security_group_names = ["workload.web"] }
  }
  autoscaling_groups = {
    web-fleet = { launch_template = "web", min_size = 2, max_size = 6, subnet_names = ["workload.private-a", "workload.private-b"], target_groups = ["web-tg"] }
  }

  subnet_ids         = module.networking.subnet_ids
  security_group_ids = module.workload_networking.security_group_ids
  target_group_arns  = module.workload_networking.target_group_arns
}
```

## Further Documentation

- [EC2 Compute](../../docs/ec2-compute.md) — Workload compute: prerequisites, name resolution, order of the stacks
- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Networking module](../networking/README.md) — VPCs, shared subnets and the management-side load balancing
