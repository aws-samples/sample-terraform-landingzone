# Member Roles Module

Creates, in one member account, the IAM roles and customer-managed policies whose `deployment_targets` name that account: by the name of its OU, by its account name or by its account ID. It reads the same `roles` and `customer_managed_policies` lists as the iam module, which creates every entry in the management account.

`stacks/management/member-roles` calls it once per active account (toggle `enable_member_roles` in `env/common.hcl`), through a provider that assumes `account_access_role_name` in that account. With the shipped `env/common.hcl.example` this puts `Backup-Role` into the accounts of the Security, Infrastructure and Workloads OUs, where the organization backup policy `primary-backup-plan` runs every backup selection as `arn:<partition>:iam::$account:role/Backup-Role`, and `EC2-Default-SSM-Role` with its instance profile, `SSM-S3-Policy` and the boundary `End-User-Policy` next to it.

A role that already exists in a member account under the same name (created by other means) makes the apply fail with `EntityAlreadyExists`; import it into the unit's state first.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `account_name` | Name of the member account the provider points at | `string` | — | yes |
| `account_id` | 12-digit ID of the member account the provider points at | `string` | — | yes |
| `account_ou_id` | ID of the OU the account sits in; empty when unknown, then only the account name or ID selects it | `string` | `""` | no |
| `ou_name_to_id` | OU name to OU ID map; resolves an OU name in `deployment_targets` | `map(string)` | `{}` | no |
| `partition` | `aws` or `aws-eusc`; expands partition-neutral managed policy names | `string` | `"aws"` | no |
| `roles` | Role definitions as in the iam module, plus `customer_managed_policy_names`. Only entries whose `deployment_targets` name this account are created. A policy named in `customer_managed_policy_names` or as `permissions_boundary` must be deployed to the same account, else the plan fails | `list(object)` | `[]` | no |
| `customer_managed_policies` | Customer-managed policy definitions as in the iam module, selected by the same rule | `list(object)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `role_arns` | Map of role name to ARN for the roles created in this account |
| `policy_arns` | Map of policy name to ARN for the policies created in this account |
| `instance_profile_names` | Names of the instance profiles created in this account |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the collections that are filled and their `deployment_targets`.

- `aws_iam_policy`
- `aws_iam_role`
- `aws_iam_role_policy_attachment`
- `aws_iam_role_policy`
- `aws_iam_instance_profile`

## Usage Example

```hcl
provider "aws" {
  alias = "workload_dev"
  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/AWSControlTowerExecution"
  }
}

module "member_roles" {
  source    = "./modules/member-roles"
  providers = { aws = aws.workload_dev }

  account_name  = "Workload-Dev"
  account_id    = "123456789012"
  account_ou_id = "ou-abcd-workload"
  ou_name_to_id = { Workloads = "ou-abcd-workload" }

  roles = [
    {
      name               = "Backup-Role"
      assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "backup.amazonaws.com" }, Action = "sts:AssumeRole" }] })
      managed_policy_arns = [
        "service-role/AWSBackupServiceRolePolicyForBackup",
        "service-role/AWSBackupServiceRolePolicyForRestores",
      ]
      deployment_targets = ["Workloads"]
    },
  ]
}
```
