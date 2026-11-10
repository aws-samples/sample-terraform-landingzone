# Customizations — How-To Guide

## Overview

The landing zone ships with a set of core modules under `modules/`. To add your
own infrastructure — without touching core code — use the **customizations
extension pattern**:

1. Create a Terraform module under `customizations/`
2. Wire it into the Terragrunt DAG via a stack under `stacks/management/customizations/`
3. Toggle it on in `env/common.hcl`

Your code lives in `customizations/`, separate from `modules/`, so landing zone
updates never overwrite your work. Each custom module gets its own Terragrunt
stack with an enable toggle, dependencies, and inputs — just like the built-in
modules.

---

## Step 1: Create a Module

Copy the template:

```bash
cp -r customizations/_template customizations/my-module
```

This gives you four files:

| File | Purpose |
|---|---|
| `main.tf` | Your resources. Replace the example `aws_ssm_parameter` with real resources. |
| `variables.tf` | Inputs. Keep `region`, `default_tags`, `account_ids` — add your own. |
| `outputs.tf` | Outputs consumed by other stacks or used for reference. |
| `versions.tf` | Provider constraints (`>= 1.14`, `~> 6.0`). Adjust if needed. |

Key conventions in `main.tf`:

- Use `data "aws_partition" "current" {}` for partition-aware ARNs (supports
  multi-partition deployments).
- Prefer `for_each` over `count` for resource iteration.
- Always pass `var.default_tags` to every resource that supports tags.

---

## Step 2: Create a Stack

Copy the template stack:

```bash
cp -r stacks/management/customizations/_template stacks/management/customizations/my-module
```

Open `stacks/management/customizations/my-module/terragrunt.hcl` and adjust:

1. **Toggle name** — Change `enable_my_custom_module` to match your module
   (e.g. `enable_my_module`):

   ```hcl
   exclude {
     if      = !try(local.common.locals.enable_my_module, false)
     actions = ["all"]
   }
   ```

2. **Source path** — Point to your module:

   ```hcl
   terraform {
     source = "${get_repo_root()}/customizations/my-module"
   }
   ```

3. **Dependencies** — The template depends on `networking` (ordering-only) and
   `accounts` (for `account_ids` output). Adjust to match what your module
   actually needs:

   ```hcl
   dependency "networking" {
     config_path  = "../../networking"
     skip_outputs = true
   }
   ```

   Use `skip_outputs = true` for pure ordering dependencies. Use `mock_outputs`
   when you consume actual outputs from a dependency.

4. **Inputs** — Map variables from locals and dependency outputs:

   ```hcl
   inputs = {
     region       = local.common.locals.region
     default_tags = local.common.locals.default_tags
     account_ids  = dependency.accounts.outputs.account_ids
     # ← Add your own inputs here
   }
   ```

---

## Step 3: Add a Toggle

Open `env/common.hcl` and add your toggle in the module toggles section:

```hcl
# --- Module Toggles ---
enable_organization   = true
enable_networking     = true
# ...
enable_my_module      = true   # ← your new toggle
```

The `exclude` block in your stack's `terragrunt.hcl` reads this value via
`try(local.common.locals.enable_my_module, false)`. When the toggle is missing
or `false`, Terragrunt skips the stack entirely. When `true`, the stack is
included in the DAG.

---

## Step 4: Customize and Deploy

With the module, stack, and toggle in place:

1. **Add resources** in `customizations/my-module/main.tf`.
2. **Add variables** in `variables.tf` and wire them through `inputs` in the
   stack's `terragrunt.hcl`.
3. **Adjust dependencies** if your module needs outputs from other stacks (e.g.
   VPC IDs from networking).
4. **Deploy**:

   ```bash
   cd stacks/management/customizations/my-module
   terragrunt apply
   ```

   Or deploy everything at once from the root:

   ```bash
   terragrunt run --all -- apply
   ```

---

## Concrete Example: S3 Bucket Module

A complete walkthrough — creating a custom module that provisions S3 buckets.

### 1. Copy the template

```bash
cp -r customizations/_template customizations/s3-buckets
cp -r stacks/management/customizations/_template stacks/management/customizations/s3-buckets
```

### 2. Write the Terraform module

**`customizations/s3-buckets/main.tf`**:

```hcl
data "aws_partition" "current" {}

locals {
  arn_prefix = "arn:${data.aws_partition.current.partition}"
}

resource "aws_s3_bucket" "this" {
  for_each = var.buckets

  bucket = each.value.name
  tags   = merge(var.default_tags, { Name = each.value.name })
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = var.buckets

  bucket = aws_s3_bucket.this[each.key].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = var.buckets

  bucket = aws_s3_bucket.this[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = var.buckets

  bucket                  = aws_s3_bucket.this[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**`customizations/s3-buckets/variables.tf`**:

```hcl
variable "region" {
  description = "AWS region"
  type        = string
}

variable "default_tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default     = {}
}

variable "account_ids" {
  description = "Map of account name to account ID"
  type        = map(string)
  default     = {}
}

variable "buckets" {
  description = "Map of bucket key to bucket configuration"
  type = map(object({
    name = string
  }))
  default = {}
}
```

**`customizations/s3-buckets/outputs.tf`**:

```hcl
output "bucket_arns" {
  description = "Map of bucket key to ARN"
  value       = { for k, v in aws_s3_bucket.this : k => v.arn }
}
```

### 3. Configure the stack

**`stacks/management/customizations/s3-buckets/terragrunt.hcl`**:

```hcl
include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common   = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
}

exclude {
  if      = !try(local.common.locals.enable_s3_buckets, false)
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}/customizations/s3-buckets"
}

dependency "networking" {
  config_path  = "../../networking"
  skip_outputs = true
}

dependency "accounts" {
  config_path = "../../accounts"
  mock_outputs = {
    account_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

inputs = {
  region       = local.common.locals.region
  default_tags = local.common.locals.default_tags
  account_ids  = dependency.accounts.outputs.account_ids

  buckets = {
    data = { name = "my-org-data-bucket" }
    logs = { name = "my-org-log-bucket" }
  }
}
```

### 4. Enable and deploy

Add the toggle to `env/common.hcl`:

```hcl
enable_s3_buckets = true
```

Deploy:

```bash
cd stacks/management/customizations/s3-buckets
terragrunt apply
```

---

## Migration from CloudFormation

The previous `modules/customizations/` module provided CloudFormation-based
resources for EC2 firewalls, ALB/NLB load balancers, and Auto Scaling Groups.
These have been removed in favor of the native Terraform extension pattern. If
you used any of these features, rebuild them as custom modules:

### EC2 Firewall Instances

Create a custom module (e.g. `customizations/firewall/`) that uses:

- `aws_instance` or `aws_launch_template` + `aws_autoscaling_group` for the
  firewall appliances
- `aws_network_interface` for ENI placement in the correct subnets
- Consume VPC and subnet IDs from the networking stack via a dependency

The key difference: you write native Terraform `aws_instance` resources directly
instead of going through CloudFormation templates.

### ALB / NLB Load Balancers

Create a custom module (e.g. `customizations/load-balancers/`) that uses:

- `aws_lb` with `load_balancer_type = "application"` or `"network"`
- `aws_lb_target_group` and `aws_lb_listener` for routing
- Wire subnet IDs and security groups from the networking dependency

This gives you full control over listener rules, health checks, and target group
configuration — all in HCL.

**Authentication boundary:** a custom `aws_lb`, `aws_lb_listener` or listener
rule built here is outside the networking module's refusal — nothing refuses an
internet-facing custom load balancer without an authenticated edge, and a
listener rule you add to a module-managed listener is evaluated before the
listener's default action and so bypasses its `authenticate-oidc`. For an
internal audience every internet-facing endpoint must sit behind your
organization's OpenID Connect (OIDC) identity provider, so a custom listener or rule must carry its own
`authenticate-oidc` action first, or stay internal — see
[the authenticated edge](../modules/networking/README.md#the-authenticated-edge-enforced-on-every-internet-facing-load-balancer).

### ASG (Auto Scaling Groups)

Create a custom module (e.g. `customizations/asg/`) that uses:

- `aws_launch_template` for instance configuration
- `aws_autoscaling_group` with `mixed_instances_policy` if needed
- `aws_autoscaling_policy` for scaling rules

All three patterns follow the same workflow: copy the template, write your
resources, create a stack, add a toggle, and run `terragrunt apply`.

## Further reading

- [Architecture](architecture.md) — Module design, dependency graph and design decisions
- [Configuration Reference](configuration-reference.md) — Full variable reference with types, defaults and validations
- [Operations](operations.md) — Day-2 operations, troubleshooting and state management
