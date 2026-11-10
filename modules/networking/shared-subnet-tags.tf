# =============================================================================
# Shared subnet tags in recipient accounts
# =============================================================================
# AWS RAM shares the subnet resource, not its tags: EC2 tags are account-local
# views, so a shared subnet arrives untagged in every recipient account. This
# capability is the RECEIVING side's answer — the networking-module instance
# of a recipient account materialises the declared tags on the subnets (and
# optionally the owning VPC) it received, as aws_ec2_tag resources: created on
# apply, corrected on drift, removed when the entry goes. That is the same
# place the reference implementation applies them (its per-account stack calls
# CreateTags in the recipient account); only the declaration is per recipient
# stack here, because each stack carries its own configuration.
#
# Deliberately independent of var.enable_ram_sharing: that switch shares
# subnets OUT of this instance's account, while this capability tags subnets
# received INTO it — the typical recipient shares nothing itself. The sharing
# side's reminder lives in the subnet_tag_propagation_limitation check
# (subnets.tf).

locals {
  # One aws_ec2_tag per (resource, key): "subnet-…:Name" → its value. Keyed by
  # ID and key, so changing a value updates in place and removing a key
  # deletes exactly that tag.
  shared_subnet_tag_pairs = var.enable_shared_subnet_tagging ? merge([
    for entry in var.shared_subnet_tags : {
      for key, value in entry.tags :
      "${entry.subnet_id}:${key}" => {
        resource_id = entry.subnet_id
        key         = key
        value       = value
      }
    }
  ]...) : {}

  # The owning VPC becomes visible in the recipient account together with the
  # shared subnet; entries naming the same vpc_id carry identical vpc_tags
  # (validated), so the merge() dedupes them without a value conflict.
  shared_vpc_tag_pairs = var.enable_shared_subnet_tagging ? merge([
    for entry in var.shared_subnet_tags : {
      for key, value in entry.vpc_tags :
      "${entry.vpc_id}:${key}" => {
        resource_id = entry.vpc_id
        key         = key
        value       = value
      }
    } if entry.vpc_id != null
  ]...) : {}
}

resource "aws_ec2_tag" "shared_subnet" {
  for_each = local.shared_subnet_tag_pairs

  resource_id = each.value.resource_id
  key         = each.value.key
  value       = each.value.value
}

resource "aws_ec2_tag" "shared_vpc" {
  for_each = local.shared_vpc_tag_pairs

  resource_id = each.value.resource_id
  key         = each.value.key
  value       = each.value.value
}
