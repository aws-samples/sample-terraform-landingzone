# Customizations

User-created Terraform modules that extend the landing zone. This directory is
separated from `modules/` so your code is never overwritten by landing zone
updates.

## Conventions

| Rule | Detail |
|---|---|
| One subdirectory per module | e.g. `customizations/s3-buckets/` |
| Standard file structure | `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf` |
| Minimum variables | `region`, `default_tags`, `account_ids` (see `_template/variables.tf`) |
| Outputs | One output per resource collection, with a `description` and a map or list keyed like the resource it reports on — e.g. `parameter_arns` in `_template/outputs.tf`. Outputs are the interface another stack reads through a Terragrunt `dependency` block, so name them after what they carry, not after the resource type. |

## `_template/`

The `_template/` folder is a **copy template**, not an active module. Use it as
a starting point:

```bash
cp -r customizations/_template customizations/my-module
```

Then create a matching Terragrunt stack:

```bash
cp -r stacks/management/customizations/_template stacks/management/customizations/my-module
```

## Extension Pattern

The `customizations/` directory is where you add your own Terraform modules
without touching core code. Users create Terraform modules
under `customizations/` and deploy them via Terragrunt stacks.

### Creating a New Customization Module

1. Copy the template:
   ```bash
   cp -r customizations/_template customizations/my-app
   ```

2. Create a matching Terragrunt stack:
   ```bash
   cp -r stacks/management/customizations/_template stacks/management/customizations/my-app
   ```

3. Edit `customizations/my-app/main.tf` with your resources.

4. Deploy:
   ```bash
   cd stacks/management/customizations/my-app
   terragrunt apply
   ```

## Delivered module: `cloudformation/`

`customizations/cloudformation/` is an active module (not a copy template): it
deploys user-defined CloudFormation **stacks** (current account and region)
and **StackSets** from the configuration. Its stack
(`stacks/management/customizations/cloudformation/`) hangs on
`enable_cloudformation_customizations` (default `false`) in `env/common.hcl`
and reads the entries of `cloudformation_stacks` and
`cloudformation_stack_sets`; each entry carries its template inline
(`template_body`) or as a repo-relative file path (`template`), which the
stack reads into a string.

StackSets support both permission models. `SERVICE_MANAGED` (the default)
targets `organizational_units` (names or `ou-`/`r-` IDs) with auto-deployment
to accounts that later join the OU and an optional `excluded_account_ids`
filter — the one deployment shape per-account stacks cannot express.
`SELF_MANAGED` targets explicit `target_account_ids` through the StackSet
administration/execution roles of `modules/iam` (`enable_stackset_roles`).

The module keeps the conventional minimum interface of this directory
(`region`, `default_tags`, `account_ids`): its stack feeds the account map
from the accounts stack, so an extension of the module — customizations are
meant to be extended — can consume account IDs by name without touching the
stack wiring. Its outputs are the deployment's interface: `stack_ids` (stack
name to CloudFormation stack ID), `stack_outputs` (stack name to that
stack's outputs map) and `stack_set_arns` (StackSet name to ARN) — read them
from other stacks via a `dependency` block, or with `terragrunt output`.

```hcl
# env/common.hcl
enable_cloudformation_customizations = true
cloudformation_stack_sets = [
  {
    name                 = "workload-baseline"
    template             = "configurations/cloudformation/workload-baseline.yaml"
    organizational_units = ["Workloads"]
    excluded_account_ids = ["111111111111"]
    capabilities         = ["CAPABILITY_NAMED_IAM"]
  }
]
```

## Example Customization Use Cases

- **AutoScaling** — Launch templates, Auto Scaling Groups, scaling policies.
  AutoScaling is application-specific and varies per workload. Create a
  customization module with your ASG configuration.
- **Application Load Balancers** — ALB rules, target groups, listener rules
- **RDS Databases** — Aurora clusters, parameter groups, subnet groups
- **ECS/EKS Clusters** — Container orchestration infrastructure

## Full Guide

See [docs/customizations.md](../docs/customizations.md) for the complete
step-by-step how-to guide.
