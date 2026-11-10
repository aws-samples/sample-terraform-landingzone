# =============================================================================
# Member Roles Module Tests (modules/member-roles)
# =============================================================================
# Coverage:
#   - regression: the backup policy's Backup-Role and the default SSM role
#     reach a member account whose OU the roles target, with their policies
#   - an account none of the entries targets gets nothing
#   - account name and account ID select an account like an OU name
#   - a role naming a policy that is not deployed to the account is refused

mock_provider "aws" {
  override_resource {
    target = aws_iam_policy.this["End-User-Policy"]
    values = { arn = "arn:aws:iam::222222222222:policy/End-User-Policy" }
  }

  override_resource {
    target = aws_iam_policy.this["SSM-S3-Policy"]
    values = { arn = "arn:aws:iam::222222222222:policy/SSM-S3-Policy" }
  }
}

variables {
  account_name  = "Workload-Dev"
  account_id    = "222222222222"
  account_ou_id = "ou-abcd-workload"
  ou_name_to_id = {
    Workloads      = "ou-abcd-workload"
    Infrastructure = "ou-abcd-infra"
    Security       = "ou-abcd-security"
  }
  partition = "aws"

  roles = [
    {
      name               = "Backup-Role"
      assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"backup.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
      managed_policy_arns = [
        "service-role/AWSBackupServiceRolePolicyForBackup",
        "service-role/AWSBackupServiceRolePolicyForRestores",
      ]
      deployment_targets = ["Security", "Infrastructure", "Workloads"]
    },
    {
      name                          = "EC2-Default-SSM-Role"
      assume_role_policy            = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
      managed_policy_arns           = ["AmazonSSMManagedInstanceCore"]
      customer_managed_policy_names = ["SSM-S3-Policy"]
      permissions_boundary          = "End-User-Policy"
      instance_profile              = true
      deployment_targets            = ["Security", "Infrastructure", "Workloads"]
    },
    {
      name               = "management-only"
      assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    },
  ]

  customer_managed_policies = [
    {
      name               = "End-User-Policy"
      policy             = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
      deployment_targets = ["Security", "Infrastructure", "Workloads"]
    },
    {
      name               = "SSM-S3-Policy"
      policy             = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}"
      deployment_targets = ["Security", "Infrastructure", "Workloads"]
    },
  ]
}

run "regression_backup_role_reaches_the_member_account" {
  command = apply

  assert {
    condition     = keys(output.role_arns) == ["Backup-Role", "EC2-Default-SSM-Role"]
    error_message = "The two targeted roles, and only those, must be created in the member account."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.this["Backup-Role:service-role/AWSBackupServiceRolePolicyForBackup"].policy_arn == "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    error_message = "A partition-neutral managed policy name must be expanded with the partition."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.this["EC2-Default-SSM-Role:SSM-S3-Policy"].policy_arn == aws_iam_policy.this["SSM-S3-Policy"].arn
    error_message = "A customer-managed policy named by the role must be attached from this account."
  }

  assert {
    condition     = aws_iam_role.this["EC2-Default-SSM-Role"].permissions_boundary == aws_iam_policy.this["End-User-Policy"].arn
    error_message = "A permissions boundary given by name must be the policy created in this account."
  }

  assert {
    condition     = output.instance_profile_names == ["EC2-Default-SSM-Role"]
    error_message = "The SSM role must get its instance profile."
  }
}

run "untargeted_account_gets_nothing" {
  command = plan

  variables {
    account_name  = "Sandbox-1"
    account_id    = "333333333333"
    account_ou_id = "ou-abcd-sandbox"
  }

  assert {
    condition     = length(aws_iam_role.this) == 0 && length(aws_iam_policy.this) == 0
    error_message = "An account in an OU no entry targets must get no role and no policy."
  }
}

run "account_name_and_id_select_the_account" {
  command = plan

  variables {
    account_ou_id = ""
    roles = [
      {
        name               = "by-name"
        assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        deployment_targets = ["Workload-Dev"]
      },
      {
        name               = "by-id"
        assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        deployment_targets = ["222222222222"]
      },
      {
        name               = "by-ou"
        assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        deployment_targets = ["Workloads"]
      },
    ]
    customer_managed_policies = []
  }

  assert {
    condition     = toset(keys(aws_iam_role.this)) == toset(["by-name", "by-id"])
    error_message = "Account name and ID select the account; an OU name does not when the account's OU is unknown."
  }
}

run "policy_not_deployed_to_the_account_refused" {
  command = plan

  variables {
    customer_managed_policies = [
      {
        name               = "SSM-S3-Policy"
        policy             = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        deployment_targets = ["Workloads"]
      },
    ]
  }

  expect_failures = [
    aws_iam_role.this,
  ]
}
