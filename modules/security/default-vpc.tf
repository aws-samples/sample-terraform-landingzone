# =============================================================================
# Default VPC Adoption (prerequisite for removal)
# =============================================================================
# aws_default_vpc does not delete anything on apply: it adopts the existing
# default VPC of the current region into Terraform state. force_destroy only
# takes effect when the resource itself is destroyed — with `terraform destroy`
# or by removing the resource from the configuration. Removing the default VPC
# is therefore a two-step process: adopt it with this toggle enabled, then set
# the toggle back to false (or destroy the stack) so the adopted VPC is
# destroyed together with its default subnets, gateways and route tables.
# The toggle name is kept for interface stability; it enables the adoption step.

resource "aws_default_vpc" "this" {
  count         = var.enable_delete_default_vpc ? 1 : 0
  force_destroy = true
}

check "default_vpc_single_region_limitation" {
  assert {
    condition     = !var.enable_delete_default_vpc
    error_message = "enable_delete_default_vpc is enabled. This apply only adopts the default VPC of the current region into Terraform state — it does not delete it. Disable the toggle again (or destroy the stack) in a second apply to have the adopted VPC destroyed via force_destroy. Cross-account and multi-region removal additionally requires deploying this module via cross-account providers in each target account and region."
  }
}

# =============================================================================
# Default Security Group Rules Removal
# =============================================================================
# Removes all ingress and egress rules from the default security group to
# prevent unintended network traffic via the default SG. The
# aws_default_security_group resource adopts the default SG and removes all
# rules by specifying empty ingress/egress.

resource "aws_default_security_group" "this" {
  count  = var.enable_delete_default_sg_rules ? 1 : 0
  vpc_id = var.default_vpc_id != "" ? var.default_vpc_id : null
  # Empty ingress and egress — removes all rules
}

check "default_sg_per_vpc_limitation" {
  assert {
    condition     = !var.enable_delete_default_sg_rules
    error_message = "enable_delete_default_sg_rules is enabled. Note: the aws_default_security_group resource manages the default security group in the current VPC only. Per-VPC application requires deploying this module with the appropriate VPC ID for each target VPC."
  }
}
