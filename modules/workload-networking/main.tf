# Workload networking — the network objects a workload account must own itself
#
# An auto-scaling group, its target group and the load balancer in front of it
# have to live in the same account, the target group must register instances,
# and a participant of a shared VPC launches instances only with security
# groups it owns. So this module creates, in the WORKLOAD account:
#   * aws_security_group.this and its rules         — one per security_groups entry
#   * aws_lb_target_group.this                      — one per target_groups entry
#   * aws_lb.this and aws_lb_listener.this          — one per load_balancers entry / listener
# in VPCs the management account owns and whose subnets it shares. The VPC and
# subnet IDs arrive as resolution maps from the management networking outputs;
# the module creates no VPC, no subnet and no share.
#
# The module reads no files and runs no scripts.

data "aws_caller_identity" "current" {}

locals {
  # Global gate: off means every collection is empty and zero resources plan.
  security_groups = var.enable ? var.security_groups : []
  target_groups   = var.enable ? var.target_groups : []
  load_balancers  = var.enable ? var.load_balancers : []
}
