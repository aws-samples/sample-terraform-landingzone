# Networking module: VPCs, Subnets, TGW, Route53, Network Firewall, IPAM, Prefix Lists, Flow Logs

# --- Partition Detection ---
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  dns_suffix = data.aws_partition.current.dns_suffix
  arn_prefix = "arn:${local.partition}"
  # VPC endpoint service names carry the DNS suffix in reversed segment
  # order (amazonaws.com → com.amazonaws). Deriving the prefix from the
  # partition's suffix keeps the endpoint names valid in every partition.
  endpoint_prefix = join(".", reverse(split(".", local.dns_suffix)))
  region          = data.aws_region.current.region

  # VPC-Map: vpc_name → vpc-Definition
  vpc_map = {
    for vpc in var.vpcs : vpc.name => vpc
  }

  # Flat subnet map: "vpc_name.subnet_name" → subnet definition + vpc_name
  subnet_map = merge([
    for vpc in var.vpcs : {
      for s in vpc.subnets : "${vpc.name}.${s.name}" => merge(s, {
        vpc_name            = vpc.name
        share_targets       = s.share_targets
        outpost_arn         = s.outpost_arn
        ipam_pool_name      = s.ipam_pool_name
        ipam_netmask_length = s.ipam_netmask_length
      })
    }
  ]...)

  # Subnets that need a NAT Gateway: public subnets with nat_gateway = true,
  # plus the private subnets of a private NAT gateway (nat_gateway_private).
  # The variable validation ties each mode to its subnet type.
  nat_gateway_subnets = {
    for key, s in local.subnet_map : key => s
    if s.nat_gateway && (s.nat_gateway_private || s.type == "public")
  }

  # NAT gateways whose public address the module allocates itself: the public
  # ones that name neither an allocation ID nor an entry of var.elastic_ips.
  nat_gateway_own_address_subnets = {
    for key, s in local.nat_gateway_subnets : key => s
    if s.nat_gateway_private == false && s.nat_gateway_allocation_id == null && s.nat_gateway_eip_name == null
  }

  # Public subnets for Internet Gateway routes
  public_subnets = {
    for key, s in local.subnet_map : key => s
    if s.type == "public"
  }

  # Private subnets for NAT Gateway routes
  private_subnets = {
    for key, s in local.subnet_map : key => s
    if s.type == "private"
  }

  # VPCs with a TGW attachment
  tgw_vpc_attachments = {
    for vpc in var.vpcs : vpc.name => vpc.tgw_attachment
    if vpc.tgw_attachment != null && var.transit_gateway.enabled
  }

  # VPCs with flow logs (apply default to VPCs without explicit flow_logs)
  # Both branches carry the same four attributes so that a per-VPC flow_logs
  # block and var.vpc_flow_logs_default reach the flow log identically.
  flow_log_vpcs = merge(
    # VPCs with explicit flow_logs
    {
      for vpc in var.vpcs : vpc.name => vpc.flow_logs
      if vpc.flow_logs != null
    },
    # VPCs without explicit flow_logs — apply default if set
    var.vpc_flow_logs_default != null ? {
      for vpc in var.vpcs : vpc.name => {
        destination               = var.vpc_flow_logs_default.destination
        traffic_type              = var.vpc_flow_logs_default.traffic_type
        max_aggregation_interval  = var.vpc_flow_logs_default.max_aggregation_interval
        log_format                = var.vpc_flow_logs_default.log_format
        cloudwatch_retention_days = var.vpc_flow_logs_default.cloudwatch_retention_days
        s3_log_path               = var.vpc_flow_logs_default.s3_log_path
      }
      if vpc.flow_logs == null
    } : {}
  )

  # "both" delivers to S3 and CloudWatch at the same time, so a VPC can appear
  # in both sets. The destination decides which of the two flow logs — and
  # which log group, role and prefix — a VPC gets.
  flow_log_vpcs_s3 = {
    for vpc_name, fl in local.flow_log_vpcs : vpc_name => fl
    if contains(["s3", "both"], fl.destination)
  }

  flow_log_vpcs_cloudwatch = {
    for vpc_name, fl in local.flow_log_vpcs : vpc_name => fl
    if contains(["cloudwatch", "both"], fl.destination)
  }

  # NAT gateway per VPC: find the first public subnet with nat_gateway = true
  nat_gw_per_vpc = {
    for vpc_name, vpc in local.vpc_map : vpc_name => [
      for s in vpc.subnets : "${vpc_name}.${s.name}"
      if s.type == "public" && s.nat_gateway
    ][0]
    if length([for s in vpc.subnets : s if s.type == "public" && s.nat_gateway]) > 0
  }
}
