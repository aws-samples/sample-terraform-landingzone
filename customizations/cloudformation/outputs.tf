output "stack_ids" {
  description = "Map of stack name to CloudFormation stack ID"
  value       = { for name, stack in aws_cloudformation_stack.this : name => stack.id }
}

output "stack_outputs" {
  description = "Map of stack name to that stack's outputs map"
  value       = { for name, stack in aws_cloudformation_stack.this : name => stack.outputs }
}

output "stack_set_arns" {
  description = "Map of StackSet name to StackSet ARN"
  value       = { for name, set in aws_cloudformation_stack_set.this : name => set.arn }
}
