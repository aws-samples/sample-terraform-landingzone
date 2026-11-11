# Workload networking module outputs

output "security_group_ids" {
  description = "Map vpc_name.sg_name to security group ID — the resolution map the workload compute stack hands to modules/ec2-compute as security_group_ids"
  value = {
    for key, sg in aws_security_group.this : key => sg.id
  }
}

output "target_group_arns" {
  description = "Map of target group name to target group ARN — the resolution map the workload compute stack hands to modules/ec2-compute as target_group_arns"
  value = {
    for name, tg in aws_lb_target_group.this : name => tg.arn
  }
}

output "load_balancer_arns" {
  description = "Map of load balancer name to load balancer ARN"
  value = {
    for name, lb in aws_lb.this : name => lb.arn
  }
}

output "load_balancer_dns_names" {
  description = "Map of load balancer name to the DNS name clients inside the VPC connect to"
  value = {
    for name, lb in aws_lb.this : name => lb.dns_name
  }
}
