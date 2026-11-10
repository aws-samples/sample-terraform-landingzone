"""Apply the Macie session settings of the landing zone.

Terraform invokes this function synchronously at deployment time
(aws_lambda_invocation, lifecycle_scope CRUD), one invocation per
setting. The event carries a ``setting`` discriminator:

- ``automated-discovery``: applies the requested status (ENABLED or
  DISABLED) to the automated sensitive data discovery configuration;
  on delete it disables the discovery again, so removing the switch
  leaves no sampling behind.
- ``classification-scope``: replaces the S3 bucket exclusion list of
  the account's classification scope with the declared names (the API
  is regional, the module passes only region-local names); on delete
  it replaces the list with an empty one, clearing all exclusions.
- ``publish-policy-findings``: sets the Security Hub publication of
  policy findings while preserving the sensitive-data side of the same
  configuration (read-modify-write); on delete it restores the service
  default (policy findings are published).

Every call is idempotent: applying a state that is already active
succeeds without a change.
"""

import json
import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

macie = boto3.client("macie2")


def _classification_scope_id() -> str:
    """The account has exactly one classification scope; return its ID."""
    scopes = macie.list_classification_scopes().get("classificationScopes", [])
    if not scopes:
        raise RuntimeError("No classification scope found — is Macie enabled?")
    return scopes[0]["id"]


def _apply_automated_discovery(status: str) -> str:
    macie.update_automated_discovery_configuration(status=status)
    return status


def _apply_classification_scope(names: list) -> str:
    macie.update_classification_scope(
        id=_classification_scope_id(),
        s3={"excludes": {"bucketNames": names, "operation": "REPLACE"}},
    )
    return "{0} exclusions".format(len(names))


def _apply_publish_policy_findings(publish: bool) -> str:
    current = macie.get_findings_publication_configuration()
    security_hub = current.get("securityHubConfiguration", {})
    macie.put_findings_publication_configuration(
        securityHubConfiguration={
            "publishClassificationFindings": security_hub.get(
                "publishClassificationFindings", False
            ),
            "publishPolicyFindings": publish,
        }
    )
    return "publishPolicyFindings={0}".format(publish)


def lambda_handler(event, context):
    """Handle a Terraform lifecycle invocation."""
    logger.info("Received event: %s", json.dumps(event))

    setting = event.get("setting", "")
    action = event.get("tf", {}).get("action", "create")

    if setting == "automated-discovery":
        status = "DISABLED" if action == "delete" else event.get("status", "DISABLED")
        result = _apply_automated_discovery(status)
    elif setting == "classification-scope":
        names = [] if action == "delete" else event.get("excluded_bucket_names", [])
        result = _apply_classification_scope(names)
    elif setting == "publish-policy-findings":
        publish = True if action == "delete" else bool(event.get("publish", False))
        result = _apply_publish_policy_findings(publish)
    else:
        logger.error("Unknown setting %r — nothing to configure.", setting)
        return {"statusCode": 400, "body": "Unknown setting"}

    logger.info("Applied %s: %s (action %s).", setting, result, action)
    return {"statusCode": 200, "body": result}
