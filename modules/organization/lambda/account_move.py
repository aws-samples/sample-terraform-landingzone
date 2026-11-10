"""Account Move Lambda — processes Organizations events and logs account movements."""
import json
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

organizations = boto3.client("organizations")


def handler(event, context):
    """Handle CreateAccount and MoveAccount events from EventBridge."""
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name == "CreateAccount":
        request_params = detail.get("requestParameters", {})
        account_name = request_params.get("accountName", "unknown")
        logger.info("New account created: %s", account_name)

    elif event_name == "MoveAccount":
        request_params = detail.get("requestParameters", {})
        account_id = request_params.get("accountId", "unknown")
        source_parent = request_params.get("sourceParentId", "unknown")
        dest_parent = request_params.get("destinationParentId", "unknown")
        logger.info(
            "Account %s moved from %s to %s",
            account_id, source_parent, dest_parent,
        )

    return {"statusCode": 200, "body": json.dumps({"event": event_name})}
