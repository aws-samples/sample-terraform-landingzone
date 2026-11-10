# EC2 Compute — outputs

output "launch_template_ids" {
  description = "Map of launch template name to launch template ID"
  value = {
    for name, lt in aws_launch_template.this : name => lt.id
  }
}

output "autoscaling_group_names" {
  description = "Map of auto-scaling group key to the created group name"
  value = {
    for name, asg in aws_autoscaling_group.this : name => asg.name
  }
}

output "instance_ids" {
  description = "Map of instance key to instance ID"
  value = {
    for name, instance in aws_instance.this : name => instance.id
  }
}

output "ssm_document_names" {
  description = "Map of SSM document key to document name"
  value = {
    for name, doc in aws_ssm_document.this : name => doc.name
  }
}

output "ssm_association_ids" {
  description = "Map of SSM association key to association ID"
  value = {
    for name, assoc in aws_ssm_association.this : name => assoc.association_id
  }
}

# The acknowledgement itself lives in the operator's env/common.hcl, which git
# does not track; this output is what writes it into plan and state, so every
# acknowledged template is named where a reviewer can read it.
output "imdsv1_acknowledged_launch_templates" {
  description = "Launch template names whose http_tokens = \"optional\" was acknowledged for this call ([] when none) — the reviewable trace of an acknowledgement made in the untracked env/common.hcl"
  value       = var.imdsv1_acknowledged_launch_templates
}
