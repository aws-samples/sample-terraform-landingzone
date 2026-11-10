output "recorder_name" {
  description = "Name of the Config Recorder"
  value       = aws_config_configuration_recorder.this.name
}

output "delivery_channel_name" {
  description = "Name of the Config Delivery Channel"
  value       = aws_config_delivery_channel.this.name
}
