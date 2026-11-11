# =============================================================================
# Workload Networking Module Tests (modules/workload-networking)
# =============================================================================
# Scenarios:
#   1. Toggle-Off — enable = false with filled collections => zero resources.
#   2. Default configuration — a security group, a target group and an
#      internal application load balancer in a shared VPC: the VPC ID comes
#      from the map, the group is keyed vpc.sg, the listener forwards to the
#      module's own target group, deletion protection is fixed on.
#   3. Refusals — internet-facing scheme, target_type ip, a certificate of
#      another account, an unknown vpc_name, a world-open rule without
#      acknowledgement.
#
# Providers used directly by the module: aws (default only, no aliases). The
# caller identity is pinned so the account check of the listener precondition
# compares against a known value.
mock_provider "aws" {
  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111122223333"
    }
  }
}

variables {
  vpc_ids = {
    workload = "vpc-0aaa1111bbb22222c"
  }
  subnet_ids = {
    "workload.private-a" = "subnet-0aaa1111bbb22222c"
    "workload.private-b" = "subnet-0bbb2222ccc33333d"
  }
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off — enable = false => zero resources
# -----------------------------------------------------------------------------

run "toggle_off_creates_nothing" {
  command = plan

  variables {
    enable = false
    security_groups = [
      {
        vpc_name = "workload"
        name     = "web"
        ingress  = [{ types = ["HTTPS"], cidr_blocks = ["10.0.0.0/8"] }]
      }
    ]
    target_groups = [
      { name = "web-tg", port = 443, protocol = "HTTPS", vpc_name = "workload" }
    ]
    load_balancers = [
      {
        name            = "web-alb"
        type            = "application"
        vpc_name        = "workload"
        subnet_names    = ["private-a", "private-b"]
        security_groups = ["web"]
        listeners       = [{ port = 80, protocol = "HTTP", target_group = "web-tg" }]
      }
    ]
  }

  assert {
    condition     = length(aws_security_group.this) == 0 && length(aws_security_group_rule.ingress_cidr) == 0 && length(aws_security_group_rule.egress_cidr) == 0
    error_message = "Toggle off must create no security group and no rule."
  }
  assert {
    condition     = length(aws_lb_target_group.this) == 0 && length(aws_lb.this) == 0 && length(aws_lb_listener.this) == 0
    error_message = "Toggle off must create no target group, load balancer or listener."
  }
  assert {
    condition     = length(output.security_group_ids) == 0 && length(output.target_group_arns) == 0 && length(output.load_balancer_arns) == 0
    error_message = "Toggle off must yield empty resolution maps."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: a security group, a target group and an internal application load
# balancer in the shared VPC
# -----------------------------------------------------------------------------

run "default_sg_tg_internal_alb" {
  command = plan

  variables {
    enable = true
    security_groups = [
      {
        vpc_name = "workload"
        name     = "alb"
        ingress  = [{ name = "https-in", types = ["HTTPS"], cidr_blocks = ["10.0.0.0/8"] }]
      },
      {
        vpc_name = "workload"
        name     = "web"
        ingress  = [{ types = ["HTTP"], source_security_group = "alb" }]
      }
    ]
    target_groups = [
      { name = "web-tg", port = 80, protocol = "HTTP", vpc_name = "workload" }
    ]
    load_balancers = [
      {
        name            = "web-alb"
        type            = "application"
        vpc_name        = "workload"
        subnet_names    = ["private-a", "private-b"]
        security_groups = ["alb"]
        listeners = [
          {
            port            = 443
            protocol        = "HTTPS"
            target_group    = "web-tg"
            certificate_arn = "arn:aws:acm:eu-central-1:111122223333:certificate/abc-123"
          }
        ]
      }
    ]
    default_tags = { ManagedBy = "terraform" }
  }

  assert {
    condition     = toset(keys(aws_security_group.this)) == toset(["workload.alb", "workload.web"])
    error_message = "Security groups must be keyed vpc_name.sg_name."
  }
  assert {
    condition     = aws_security_group.this["workload.web"].vpc_id == "vpc-0aaa1111bbb22222c"
    error_message = "The security group's VPC must resolve through the vpc_ids map."
  }
  assert {
    condition     = length(aws_security_group_rule.ingress_cidr) == 1 && length(aws_security_group_rule.ingress_sg) == 1 && length(aws_security_group_rule.egress_cidr) == 0
    error_message = "One CIDR ingress rule, one group-referencing ingress rule and no egress rule must plan."
  }
  assert {
    condition     = aws_security_group_rule.ingress_cidr["workload.alb.ingress.https-in.HTTPS"].to_port == 443
    error_message = "The HTTPS type must expand to port 443 under the named rule key."
  }
  assert {
    condition     = aws_lb_target_group.this["web-tg"].vpc_id == "vpc-0aaa1111bbb22222c" && aws_lb_target_group.this["web-tg"].target_type == "instance"
    error_message = "The target group must land in the mapped VPC with target_type instance."
  }
  assert {
    condition     = aws_lb.this["web-alb"].internal == true && aws_lb.this["web-alb"].enable_deletion_protection == true && aws_lb.this["web-alb"].drop_invalid_header_fields == true
    error_message = "The load balancer must be internal with deletion protection and header dropping fixed on."
  }
  assert {
    condition     = aws_lb.this["web-alb"].subnets == toset(["subnet-0aaa1111bbb22222c", "subnet-0bbb2222ccc33333d"])
    error_message = "The subnets must resolve as vpc_name.subnet_name through the subnet_ids map."
  }
  assert {
    condition     = length(aws_lb_listener.this) == 1 && aws_lb_listener.this["web-alb.443"].default_action[0].type == "forward"
    error_message = "The listener must forward."
  }
  assert {
    condition     = aws_lb_listener.this["web-alb.443"].ssl_policy == "ELBSecurityPolicy-TLS13-1-2-2021-06"
    error_message = "An HTTPS listener without ssl_policy must take the TLS-1.2-minimum default."
  }
  assert {
    condition     = toset(keys(output.security_group_ids)) == toset(["workload.alb", "workload.web"])
    error_message = "security_group_ids must publish the groups as vpc_name.sg_name."
  }
  assert {
    condition     = toset(keys(output.target_group_arns)) == toset(["web-tg"]) && toset(keys(output.load_balancer_arns)) == toset(["web-alb"]) && toset(keys(output.load_balancer_dns_names)) == toset(["web-alb"])
    error_message = "The outputs must be keyed by target group and load balancer name."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: refusals
# -----------------------------------------------------------------------------

run "internet_facing_rejected" {
  command = plan

  variables {
    enable = true
    security_groups = [
      { vpc_name = "workload", name = "alb", ingress = [{ types = ["HTTPS"], cidr_blocks = ["10.0.0.0/8"] }] }
    ]
    target_groups = [
      { name = "web-tg", port = 80, protocol = "HTTP", vpc_name = "workload" }
    ]
    load_balancers = [
      {
        name            = "public-alb"
        type            = "application"
        vpc_name        = "workload"
        subnet_names    = ["private-a"]
        scheme          = "internet-facing"
        security_groups = ["alb"]
        listeners       = [{ port = 80, protocol = "HTTP", target_group = "web-tg" }]
      }
    ]
  }

  expect_failures = [var.load_balancers]
}

run "target_type_ip_rejected" {
  command = plan

  variables {
    enable = true
    target_groups = [
      { name = "ip-tg", port = 80, protocol = "HTTP", vpc_name = "workload", target_type = "ip" }
    ]
  }

  expect_failures = [var.target_groups]
}

run "foreign_certificate_rejected" {
  command = plan

  variables {
    enable = true
    security_groups = [
      { vpc_name = "workload", name = "alb", ingress = [{ types = ["HTTPS"], cidr_blocks = ["10.0.0.0/8"] }] }
    ]
    target_groups = [
      { name = "web-tg", port = 80, protocol = "HTTP", vpc_name = "workload" }
    ]
    load_balancers = [
      {
        name            = "web-alb"
        type            = "application"
        vpc_name        = "workload"
        subnet_names    = ["private-a"]
        security_groups = ["alb"]
        listeners = [
          {
            port            = 443
            protocol        = "HTTPS"
            target_group    = "web-tg"
            certificate_arn = "arn:aws:acm:eu-central-1:111111111111:certificate/management-cert"
          }
        ]
      }
    ]
  }

  expect_failures = [aws_lb_listener.this]
}

run "unknown_vpc_name_rejected" {
  command = plan

  variables {
    enable = true
    security_groups = [
      { vpc_name = "hub", name = "web" }
    ]
  }

  expect_failures = [aws_security_group.this]
}

run "world_open_rule_needs_acknowledgement" {
  command = plan

  variables {
    enable = true
    security_groups = [
      {
        vpc_name = "workload"
        name     = "open"
        ingress  = [{ types = ["ALL"], cidr_blocks = ["0.0.0.0/0"] }]
      }
    ]
  }

  expect_failures = [var.security_groups]
}

run "world_open_rule_acknowledged_passes" {
  command = plan

  variables {
    enable = true
    security_groups = [
      {
        vpc_name = "workload"
        name     = "open"
        ingress  = [{ types = ["ALL"], cidr_blocks = ["0.0.0.0/0"], acknowledge_world_open_all_protocols = true }]
      }
    ]
  }

  assert {
    condition     = aws_security_group_rule.ingress_cidr["workload.open.ingress.0.ALL"].protocol == "-1"
    error_message = "An acknowledged world-open rule must plan as all protocols."
  }
}
