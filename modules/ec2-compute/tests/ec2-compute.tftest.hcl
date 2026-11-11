# =============================================================================
# EC2 Compute Module Tests (modules/ec2-compute)
# =============================================================================
# Mandatory scenarios:
#   1. Toggle-Off — enable_ec2_compute = false with filled collections
#      => zero resources.
#   2. Default configuration — no inputs at all (toggle defaults to false,
#      every collection defaults to empty) => zero resources.
#   3. Custom configuration — launch template, auto-scaling group with target
#      group attachment, single instance, SSM document and association.
#   4. Validation failures — invalid AMI format, invalid http_tokens,
#      association with two document references, association without target.
#
# Providers used directly by the module: aws (default only, no aliases). The
# caller identity is pinned: the traffic source attachment compares the account
# of each target group ARN against it.
mock_provider "aws" {
  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111111111111"
    }
  }
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off — enable_ec2_compute = false => zero resources
# -----------------------------------------------------------------------------

run "toggle_off_creates_nothing" {
  command = plan

  variables {
    enable_ec2_compute = false
    launch_templates = {
      appliance = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "c5.xlarge"
      }
    }
    autoscaling_groups = {
      appliance-fleet = {
        launch_template = "appliance"
        min_size        = 1
        max_size        = 2
        subnet_ids      = ["subnet-0aaa1111bbb22222c"]
      }
    }
    instances = {
      manager = {
        launch_template = "appliance"
      }
    }
    ssm_documents = {
      directory-setup = {
        content = "{\"schemaVersion\": \"2.2\"}"
      }
    }
    ssm_associations = {
      directory-setup = {
        document_key  = "directory-setup"
        instance_keys = ["manager"]
      }
    }
  }

  assert {
    condition     = length(aws_launch_template.this) == 0
    error_message = "Toggle off must create no launch template."
  }
  assert {
    condition     = length(aws_autoscaling_group.this) == 0
    error_message = "Toggle off must create no auto-scaling group."
  }
  assert {
    condition     = length(aws_autoscaling_traffic_source_attachment.this) == 0
    error_message = "Toggle off must create no traffic source attachment."
  }
  assert {
    condition     = length(aws_instance.this) == 0
    error_message = "Toggle off must create no instance."
  }
  assert {
    condition     = length(aws_ssm_document.this) == 0
    error_message = "Toggle off must create no SSM document."
  }
  assert {
    condition     = length(aws_ssm_association.this) == 0
    error_message = "Toggle off must create no SSM association."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — no inputs, all variables defaulted
# -----------------------------------------------------------------------------

run "default_configuration" {
  command = plan

  assert {
    condition     = length(aws_launch_template.this) == 0
    error_message = "Module defaults must not create any launch template."
  }
  assert {
    condition     = length(aws_autoscaling_group.this) == 0
    error_message = "Module defaults must not create any auto-scaling group."
  }
  assert {
    condition     = length(aws_instance.this) == 0
    error_message = "Module defaults must not create any instance."
  }
  assert {
    condition     = length(output.launch_template_ids) == 0
    error_message = "Module defaults must yield an empty launch_template_ids map."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — launch template + ASG + attachment +
# instance + SSM document + association, with name resolution maps
# -----------------------------------------------------------------------------

run "custom_configuration" {
  command = plan

  variables {
    enable_ec2_compute = true

    subnet_ids = {
      "inspection.firewall-a" = "subnet-0aaa1111bbb22222c"
    }
    security_group_ids = {
      "inspection.appliance-mgmt" = "sg-0abc1234def567890"
    }
    target_group_arns = {
      "gwlb-inspection" = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/gwlb-inspection/aaaabbbbcccc0001"
    }
    config_bucket_name = "example-firewall-config"

    default_tags = {
      ManagedBy = "terraform"
    }

    launch_templates = {
      appliance = {
        ami_id             = "ami-0abc1234def567890"
        instance_type      = "c5.xlarge"
        user_data_template = "hostname=$${name}; bucket=$${config_bucket}"
        user_data_values   = { name = "fw-1" }
        block_device_mappings = [
          {
            device_name = "/dev/xvda"
            ebs = {
              volume_size = 100
              volume_type = "gp3"
            }
          }
        ]
        network_interfaces = [
          {
            device_index         = 0
            subnet_name          = "inspection.firewall-a"
            security_group_names = ["inspection.appliance-mgmt"]
          }
        ]
        tags = { Role = "appliance" }
      }
      manager = {
        ami_id               = "ami-00000000000000042"
        instance_type        = "m5.large"
        iam_instance_profile = "firewall-manager-profile"
        security_group_names = ["inspection.appliance-mgmt"]
      }
    }

    autoscaling_groups = {
      appliance-fleet = {
        launch_template           = "appliance"
        min_size                  = 1
        max_size                  = 3
        desired_capacity          = 2
        health_check_type         = "ELB"
        health_check_grace_period = 600
        subnet_names              = ["inspection.firewall-a"]
        target_groups             = ["gwlb-inspection"]
      }
    }

    instances = {
      manager = {
        launch_template        = "manager"
        termination_protection = true
      }
    }

    ssm_documents = {
      directory-setup = {
        content = "{\"schemaVersion\": \"2.2\", \"mainSteps\": []}"
      }
    }

    ssm_associations = {
      directory-setup = {
        document_key  = "directory-setup"
        instance_keys = ["manager"]
      }
      domain-join = {
        document_name     = "AWS-JoinDirectoryServiceDomain"
        parameters        = { directoryId = "d-1234567890" }
        target_tag_key    = "Role"
        target_tag_values = ["directory-config"]
      }
    }
  }

  assert {
    condition     = length(aws_launch_template.this) == 2
    error_message = "Both launch templates must be created."
  }
  assert {
    condition     = aws_launch_template.this["appliance"].image_id == "ami-0abc1234def567890"
    error_message = "The AMI must come from the entry — no AMI is written into the module."
  }
  assert {
    condition     = aws_launch_template.this["appliance"].metadata_options[0].http_tokens == "required"
    error_message = "http_tokens must default to required (IMDSv2)."
  }
  assert {
    condition     = aws_launch_template.this["appliance"].user_data == base64encode("hostname=fw-1; bucket=example-firewall-config")
    error_message = "The user data must be the template rendered against the placeholder map, including the built-in config_bucket placeholder."
  }
  assert {
    condition     = aws_launch_template.this["appliance"].network_interfaces[0].subnet_id == "subnet-0aaa1111bbb22222c"
    error_message = "The network interface subnet name must resolve through the subnet_ids map."
  }
  assert {
    condition     = aws_launch_template.this["appliance"].block_device_mappings[0].ebs[0].encrypted == "true"
    error_message = "Block device EBS encryption must default to true."
  }
  assert {
    condition     = length(aws_autoscaling_group.this) == 1
    error_message = "One auto-scaling group must be created."
  }
  assert {
    condition     = aws_autoscaling_group.this["appliance-fleet"].vpc_zone_identifier == toset(["subnet-0aaa1111bbb22222c"])
    error_message = "The ASG subnet names must resolve through the subnet_ids map."
  }
  assert {
    condition     = length(aws_autoscaling_traffic_source_attachment.this) == 1
    error_message = "One traffic source attachment must be created for the ASG x target group pair."
  }
  assert {
    condition     = aws_autoscaling_traffic_source_attachment.this["appliance-fleet.gwlb-inspection"].traffic_source[0].identifier == "arn:aws:elasticloadbalancing:eu-central-1:111111111111:targetgroup/gwlb-inspection/aaaabbbbcccc0001"
    error_message = "The attachment must carry the resolved target group ARN."
  }
  assert {
    condition     = length(aws_instance.this) == 1
    error_message = "One single instance must be created."
  }
  assert {
    condition     = aws_instance.this["manager"].disable_api_termination == true
    error_message = "termination_protection must reach disable_api_termination."
  }
  assert {
    condition     = length(aws_ssm_document.this) == 1
    error_message = "One SSM document must be created."
  }
  assert {
    condition     = aws_ssm_document.this["directory-setup"].content == "{\"schemaVersion\": \"2.2\", \"mainSteps\": []}"
    error_message = "The SSM document content must be the configuration string."
  }
  assert {
    condition     = length(aws_ssm_association.this) == 2
    error_message = "Both SSM associations must be created."
  }
  assert {
    condition     = aws_ssm_association.this["domain-join"].name == "AWS-JoinDirectoryServiceDomain"
    error_message = "An association with document_name must reference the existing document."
  }
  assert {
    condition     = aws_ssm_association.this["domain-join"].targets[0].key == "tag:Role"
    error_message = "A tag-targeted association must carry the tag selector."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b: Custom directory configuration — active toggle creates the
# document and association resources of the directory setup
# (the shape stacks/management/directory-config passes)
# -----------------------------------------------------------------------------

run "directory_configuration" {
  command = plan

  variables {
    enable_ec2_compute = true

    subnet_ids = {
      "management.private-a" = "subnet-0aaa1111bbb22222c"
    }

    launch_templates = {
      directory-config = {
        ami_id        = "ami-0feedfacefeedface0"
        instance_type = "t3.medium"
        network_interfaces = [{
          device_index = 0
          subnet_name  = "management.private-a"
        }]
      }
    }

    instances = {
      directory-config = { launch_template = "directory-config" }
    }

    ssm_documents = {
      directory-setup = {
        document_format = "YAML"
        content         = "schemaVersion: '2.2'\nmainSteps:\n  - action: aws:runPowerShellScript\n    name: setup\n"
      }
    }

    ssm_associations = {
      directory-domain-join = {
        document_name = "AWS-JoinDirectoryServiceDomain"
        parameters = {
          directoryId    = "d-1234567890"
          directoryName  = "corp.example.com"
          dnsIpAddresses = "10.0.0.10,10.0.1.10"
        }
        instance_keys = ["directory-config"]
      }
      directory-setup = {
        document_key  = "directory-setup"
        instance_keys = ["directory-config"]
      }
    }
  }

  assert {
    condition     = length(aws_ssm_document.this) == 1
    error_message = "The active toggle must create the directory setup document."
  }
  assert {
    condition     = aws_ssm_document.this["directory-setup"].document_format == "YAML"
    error_message = "The document format must come from the entry."
  }
  assert {
    condition     = length(aws_ssm_association.this) == 2
    error_message = "The active toggle must create the domain-join and setup associations."
  }
  assert {
    condition     = aws_ssm_association.this["directory-domain-join"].name == "AWS-JoinDirectoryServiceDomain"
    error_message = "The domain join must use the AWS-managed directory join document."
  }
  assert {
    condition     = aws_ssm_association.this["directory-domain-join"].parameters["directoryId"] == "d-1234567890"
    error_message = "The directory ID must reach the association parameters."
  }
  assert {
    condition     = length(aws_instance.this) == 1
    error_message = "The configuration instance must be created."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures — invalid inputs are rejected
# -----------------------------------------------------------------------------

run "invalid_ami_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      broken = {
        ami_id        = "ami-XYZ"
        instance_type = "t3.micro"
      }
    }
  }

  expect_failures = [var.launch_templates]
}

run "invalid_http_tokens_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      broken = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
        http_tokens   = "disabled"
      }
    }
  }

  expect_failures = [var.launch_templates]
}

run "association_with_two_documents_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    ssm_associations = {
      broken = {
        document_key   = "a"
        document_name  = "b"
        target_tag_key = "Role"
      }
    }
  }

  expect_failures = [var.ssm_associations]
}

run "association_without_target_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    ssm_associations = {
      broken = {
        document_name = "AWS-JoinDirectoryServiceDomain"
      }
    }
  }

  expect_failures = [var.ssm_associations]
}

# A dot inside an ASG key or target group name could collide two
# "<asg>.<target group>" attachment keys and merge() would silently drop an
# attachment, so a dotted key is refused.
run "dotted_asg_key_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      fwlt = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
      }
    }
    autoscaling_groups = {
      "fw.edge" = {
        launch_template = "fwlt"
        min_size        = 1
        max_size        = 2
      }
    }
  }

  expect_failures = [var.autoscaling_groups]
}

# -----------------------------------------------------------------------------
# Scenario 5: launch_templates_imdsv1_optional check — an IMDSv1 opt-in is
# always announced, and an acknowledgement silences only its own template.
#
# Both directions of the check itself, plus the acknowledgement variable's
# own validation (a stale acknowledgement fails the plan outright rather than
# passing silently).
# -----------------------------------------------------------------------------

# Direction 1: an unacknowledged "optional" template still fails the test —
# proves the check still fires when nothing acknowledges it.
run "unacknowledged_optional_fails_check" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      unacked = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
        http_tokens   = "optional"
      }
    }
  }

  expect_failures = [check.launch_templates_imdsv1_optional]
}

# Direction 2: the acknowledged template passes, and an unacknowledged
# "optional" template in the SAME plan still fails — proves the
# acknowledgement silences only the template it names, never a blanket
# switch.
run "acknowledged_optional_passes_unacknowledged_still_fails" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      acked = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
        http_tokens   = "optional"
      }
      unacked = {
        ami_id        = "ami-00000000000000042"
        instance_type = "t3.micro"
        http_tokens   = "optional"
      }
    }
    imdsv1_acknowledged_launch_templates = ["acked"]
  }

  expect_failures = [check.launch_templates_imdsv1_optional]
}

# Direction 2b: every "optional" template acknowledged — the check itself
# passes with no unacknowledged names left to report.
run "all_optional_acknowledged_check_passes" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      acked = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
        http_tokens   = "optional"
      }
    }
    imdsv1_acknowledged_launch_templates = ["acked"]
  }
}

# "required" (the default) always passes regardless of acknowledgement.
run "required_passes_with_or_without_acknowledgement" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      safe = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
      }
    }
  }
}

# Stale acknowledgement, case A: the name is not a key of launch_templates at
# all — must not pass silently.
run "stale_acknowledgement_unknown_name_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      real = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
      }
    }
    imdsv1_acknowledged_launch_templates = ["ghost"]
  }

  expect_failures = [var.imdsv1_acknowledged_launch_templates]
}

# Stale acknowledgement, case B: the name exists but its http_tokens is
# "required", not "optional" — acknowledging a template that was never at risk
# must not pass silently either.
run "stale_acknowledgement_not_optional_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      safe = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
      }
    }
    imdsv1_acknowledged_launch_templates = ["safe"]
  }

  expect_failures = [var.imdsv1_acknowledged_launch_templates]
}

# A repeated name in the acknowledgement list is rejected too — the variable
# validation matches its own error_message rather than passing on a duplicate.
run "duplicate_acknowledgement_rejected" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      acked = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
        http_tokens   = "optional"
      }
    }
    imdsv1_acknowledged_launch_templates = ["acked", "acked"]
  }

  expect_failures = [var.imdsv1_acknowledged_launch_templates]
}

# -----------------------------------------------------------------------------
# Scenario 7: an auto-scaling group is attached to a target group of its own
# account only. AWS refuses the attachment of a target group another account
# owns at apply; the module refuses it at plan, naming the target group.
# The caller identity is pinned to 111111111111 in the mock above, the ARNs of
# the custom configuration carry that account.
# -----------------------------------------------------------------------------

run "ec2_compute_refuses_foreign_account_target_group" {
  command = plan

  variables {
    enable_ec2_compute = true
    subnet_ids = {
      "workload.private-a" = "subnet-0aaa1111bbb22222c"
    }
    target_group_arns = {
      "web-tg" = "arn:aws:elasticloadbalancing:eu-central-1:999999999999:targetgroup/web-tg/aaaabbbbcccc0002"
    }
    launch_templates = {
      web = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "m5.large"
      }
    }
    autoscaling_groups = {
      web-fleet = {
        launch_template = "web"
        min_size        = 1
        max_size        = 2
        subnet_names    = ["workload.private-a"]
        target_groups   = ["web-tg"]
      }
    }
  }

  expect_failures = [aws_autoscaling_traffic_source_attachment.this]
}

# -----------------------------------------------------------------------------
# Scenario 6: an IMDSv1 acknowledgement leaves a trace a reviewer can read.
# The acknowledgement lives in the operator's untracked
# env/common.hcl, so the output imdsv1_acknowledged_launch_templates is what
# puts it into plan and state: it must equal the input, and be [] by default.
# -----------------------------------------------------------------------------

run "acknowledgement_output_defaults_to_empty" {
  command = plan

  assert {
    condition     = length(output.imdsv1_acknowledged_launch_templates) == 0
    error_message = "With no acknowledgement the output imdsv1_acknowledged_launch_templates must be []."
  }
}

run "acknowledgement_output_names_every_acknowledged_template" {
  command = plan

  variables {
    enable_ec2_compute = true
    launch_templates = {
      acked-a = {
        ami_id        = "ami-0abc1234def567890"
        instance_type = "t3.micro"
        http_tokens   = "optional"
      }
      acked-b = {
        ami_id        = "ami-00000000000000042"
        instance_type = "t3.micro"
        http_tokens   = "optional"
      }
    }
    imdsv1_acknowledged_launch_templates = ["acked-a", "acked-b"]
  }

  assert {
    condition     = output.imdsv1_acknowledged_launch_templates == tolist(["acked-a", "acked-b"])
    error_message = "The output imdsv1_acknowledged_launch_templates must equal the acknowledged input, so plan and state name every acknowledged template."
  }
}
