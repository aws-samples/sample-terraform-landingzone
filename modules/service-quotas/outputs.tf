output "quota_request_ids" {
  description = "Map of service/quota code to request ID"
  value = {
    for key, sq in aws_servicequotas_service_quota.this :
    key => sq.id
  }
}
