"""Onboard newly created CloudWatch log groups.

EventBridge invokes this function for every successful CreateLogGroup API
call (recorded by CloudTrail). The function applies the landing zone
defaults to the new group:

- a retention policy (LOG_RETENTION_DAYS),
- optionally a customer-managed KMS key (LOG_KMS_KEY_ARN),
- optionally a subscription filter toward the central log destination
  (LOG_DESTINATION_ARN + LOG_SUBSCRIPTION_ROLE_ARN, LOG_FILTER_PATTERN).

Log groups matching an entry of LOG_EXCLUDED_PATTERNS (exact name, or
prefix with a trailing *) are left untouched. All settings arrive as
environment variables so the function itself stays configuration-free.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logs = boto3.client("logs")


def _excluded(log_group_name, patterns):
    """True when the log group matches an exclusion pattern."""
    for pattern in patterns:
        if pattern.endswith("*"):
            if log_group_name.startswith(pattern[:-1]):
                return True
        elif log_group_name == pattern:
            return True
    return False


def lambda_handler(event, context):
    """Handle a CreateLogGroup event delivered by EventBridge."""
    logger.info("Received event: %s", json.dumps(event))

    log_group_name = (
        event.get("detail", {})
        .get("requestParameters", {})
        .get("logGroupName", "")
    )
    if not log_group_name:
        logger.error("Event carries no logGroupName — nothing to onboard.")
        return {"statusCode": 400, "body": "Missing logGroupName"}

    excluded_patterns = json.loads(os.environ.get("LOG_EXCLUDED_PATTERNS", "[]"))
    if _excluded(log_group_name, excluded_patterns):
        logger.info("Log group %s is excluded — skipping.", log_group_name)
        return {"statusCode": 200, "body": "Excluded"}

    retention_days = int(os.environ["LOG_RETENTION_DAYS"])
    logs.put_retention_policy(
        logGroupName=log_group_name, retentionInDays=retention_days
    )
    logger.info(
        "Set retention of %s to %d days.", log_group_name, retention_days
    )

    kms_key_arn = os.environ.get("LOG_KMS_KEY_ARN", "")
    if kms_key_arn:
        logs.associate_kms_key(
            logGroupName=log_group_name, kmsKeyId=kms_key_arn
        )
        logger.info("Associated KMS key with %s.", log_group_name)

    destination_arn = os.environ.get("LOG_DESTINATION_ARN", "")
    if destination_arn:
        logs.put_subscription_filter(
            logGroupName=log_group_name,
            filterName="tlz-log-group-onboarding",
            filterPattern=os.environ.get("LOG_FILTER_PATTERN", ""),
            destinationArn=destination_arn,
            roleArn=os.environ["LOG_SUBSCRIPTION_ROLE_ARN"],
        )
        logger.info("Attached subscription filter to %s.", log_group_name)

    return {"statusCode": 200, "body": "Onboarded"}
