# =============================================================================
# CloudTrail Lake Event Data Store
# =============================================================================

resource "aws_cloudtrail_event_data_store" "this" {
  count = var.enable_cloudtrail_lake ? 1 : 0

  name                 = "tlz-cloudtrail-lake"
  retention_period     = var.cloudtrail_lake_config.retention_days
  multi_region_enabled = true
  organization_enabled = var.cloudtrail_lake_config.organization_enabled
  kms_key_id           = aws_kms_key.log_bucket.arn

  advanced_event_selector {
    name = "Management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }
}

# AWS closed CloudTrail Lake to NEW customers: as of May 31, 2026 an account
# that has never created an event data store can no longer create one — the
# CreateEventDataStore call is refused at apply time. An account that created a
# store BEFORE the cutoff keeps working, and the resource above must keep
# managing it — which is why this is a warning and not a failing precondition:
# a hard fail would break every pre-cutoff deployment that legitimately keeps
# enable_cloudtrail_lake = true, and plan time cannot distinguish an existing
# store from a new one. This stack also carries the org trail, so a hard fail
# here would take the trail down with it. Same convention as the Audit Manager
# maintenance-mode check: surface the documented service limitation before the
# AWS error does.
check "cloudtrail_lake_new_customer_closure" {
  assert {
    condition     = !var.enable_cloudtrail_lake
    error_message = "enable_cloudtrail_lake is true, but AWS closed CloudTrail Lake to new customers on May 31, 2026: an account that never created an event data store can no longer create one, and the apply fails the management logging stack (which also carries the org trail). An account that created its store before the cutoff keeps working and stays managed — this warning is expected there. If this account never onboarded CloudTrail Lake, set enable_cloudtrail_lake = false."
  }
}
