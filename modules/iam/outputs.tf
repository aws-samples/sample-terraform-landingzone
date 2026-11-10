# IAM module outputs

output "role_arns" {
  description = "Map of role name to role ARN"
  value = {
    for name, role in aws_iam_role.this :
    name => role.arn
  }
}

output "saml_provider_arns" {
  description = "Map of SAML provider name to provider ARN"
  value = {
    for name, sp in aws_iam_saml_provider.this :
    name => sp.arn
  }
}

output "policy_arns" {
  description = "Map of customer-managed policy name to policy ARN"
  value = {
    for name, policy in aws_iam_policy.this :
    name => policy.arn
  }
}

output "user_names" {
  description = "Map of IAM user name to user name (confirms creation)"
  value = {
    for name, user in aws_iam_user.this :
    name => user.name
  }
}

output "group_names" {
  description = "Map of IAM group name to group name (confirms creation)"
  value = {
    for name, group in aws_iam_group.this :
    name => group.name
  }
}

output "managed_ad_ids" {
  description = "Map of directory name to directory ID (both MicrosoftAD and ADConnector)"
  value = merge(
    { for name, dir in aws_directory_service_directory.this : name => dir.id },
    { for name, dir in aws_directory_service_directory.ad_connector : name => dir.id }
  )
}

output "managed_ad_dns_addresses" {
  description = "Map of Managed Microsoft AD directory name to its DNS server addresses (directory-provided resolvers, e.g. for the domain-join association)"
  value = {
    for name, dir in aws_directory_service_directory.this : name => dir.dns_ip_addresses
  }
}

output "managed_ad_domain_names" {
  description = "Map of Managed Microsoft AD directory name to its fully qualified domain name"
  value = {
    for name, dir in aws_directory_service_directory.this : name => dir.name
  }
}

output "managed_ad_resolver_rule_ids" {
  description = "Map of directory name to its Route 53 Resolver rule ID — for aws_route53_resolver_rule_association in VPCs this module does not manage (a rule only changes DNS behaviour in VPCs it is associated with)"
  value = {
    for name, rule in aws_route53_resolver_rule.managed_ad : name => rule.id
  }
}

output "instance_profile_arns" {
  description = "Map of role name to instance profile ARN for roles with instance_profile = true"
  value = {
    for name, profile in aws_iam_instance_profile.this :
    name => profile.arn
  }
}

output "deployment_targets" {
  description = "Map of resource type to deployment targets with management account exclusion applied"
  value = {
    roles = {
      for role in var.roles : role.name => {
        targets                    = role.deployment_targets
        exclude_management_account = role.exclude_management_account
      }
      if length(role.deployment_targets) > 0
    }
    policies = {
      for p in var.customer_managed_policies : p.name => {
        targets                    = p.deployment_targets
        exclude_management_account = p.exclude_management_account
      }
      if length(p.deployment_targets) > 0
    }
    users = {
      for u in var.iam_users : u.name => {
        targets                    = u.deployment_targets
        exclude_management_account = u.exclude_management_account
      }
      if length(u.deployment_targets) > 0
    }
    groups = {
      for g in var.iam_groups : g.name => {
        targets                    = g.deployment_targets
        exclude_management_account = g.exclude_management_account
      }
      if length(g.deployment_targets) > 0
    }
  }
}

output "service_catalog_propagation_role_arn" {
  description = "ARN of the Service Catalog propagation role (empty when disabled)"
  value       = var.enable_service_catalog ? aws_iam_role.service_catalog_propagation[0].arn : ""
}

output "stackset_admin_role_arn" {
  description = "ARN of the CloudFormation StackSet administration role (management account only)."
  value       = try(aws_iam_role.stackset_admin[0].arn, null)
}

output "stackset_execution_role_arn" {
  description = "ARN of the CloudFormation StackSet execution role (member accounts only)."
  value       = try(aws_iam_role.stackset_execution[0].arn, null)
}
