"""regression: tlz-resource-policy-enforcement accepted ARNs of the wrong shape.

configurations/ssm-documents/resource-policy-enforcement.yaml parses its
ResourceArn in a python3.11 ``aws:executeScript`` step (``parse_arn``) and
then calls either s3:PutBucketPolicy with the bucket name or
kms:PutKeyPolicy with the ARN. A parser that only checks the service field
fails: an S3 ARN carrying a region and an account
(``arn:aws:s3:eu-central-1:<acct>:name``) would hand ``name`` to PutBucketPolicy,
and a KMS ALIAS ARN would reach PutKeyPolicy, which names a key, not an alias.

The automation document itself cannot run offline. What runs here is the
document's own handler: the ``Script`` of the ``parseResourceArn`` step is
read from the YAML the module ships, executed, and ``parse_arn`` is called
with each ARN. No copy of the handler lives in this file, so a change to the
document is what this test measures. What stays unexecuted is the SSM
runtime around it (the branch and the two API steps).
"""

from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
DOCUMENT = REPO / "configurations/ssm-documents/resource-policy-enforcement.yaml"
ACCOUNT = "111111111111"  # documented placeholder
KEY = "00000000-0000-0000-0000-000000000000"


def _handler():
    doc = yaml.safe_load(DOCUMENT.read_text())
    steps = [s for s in doc["mainSteps"] if s["name"] == "parseResourceArn"]
    assert len(steps) == 1, "resource-policy-enforcement.yaml has no single parseResourceArn step"
    inputs = steps[0]["inputs"]
    namespace = {}
    exec(compile(inputs["Script"], str(DOCUMENT), "exec"), namespace)  # nosec B102 - the shipped handler
    return namespace[inputs["Handler"]]


@pytest.mark.parametrize(
    "arn, service, resource",
    [
        ("arn:aws:s3:::tlz-example-bucket", "s3", "tlz-example-bucket"),
        ("arn:aws-eusc:s3:::tlz-example-bucket", "s3", "tlz-example-bucket"),
        ("arn:aws:kms:eu-central-1:%s:key/%s" % (ACCOUNT, KEY), "kms",
         "arn:aws:kms:eu-central-1:%s:key/%s" % (ACCOUNT, KEY)),
        ("arn:aws-us-gov:kms:us-gov-west-1:%s:key/mrk-0123456789abcdef0123456789abcdef" % ACCOUNT, "kms",
         "arn:aws-us-gov:kms:us-gov-west-1:%s:key/mrk-0123456789abcdef0123456789abcdef" % ACCOUNT),
    ],
)
def test_regression_resource_policy_accepts_bucket_and_key_arns(arn, service, resource):
    assert _handler()({"ResourceArn": arn}, None) == {"Service": service, "ResourceName": resource}


@pytest.mark.parametrize(
    "arn",
    [
        # an S3 bucket ARN has no region and no account
        "arn:aws:s3:eu-central-1:%s:tlz-example-bucket" % ACCOUNT,
        "arn:aws:s3:eu-central-1::tlz-example-bucket",
        "arn:aws:s3::%s:tlz-example-bucket" % ACCOUNT,
        # an object ARN is not a bucket, an empty bucket name names nothing
        "arn:aws:s3:::tlz-example-bucket/key",
        "arn:aws:s3:::",
        # a KMS key ARN names a key, not an alias
        "arn:aws:kms:eu-central-1:%s:alias/tlz-example" % ACCOUNT,
        # ... and carries its region, its account and a key id
        "arn:aws:kms::%s:key/%s" % (ACCOUNT, KEY),
        "arn:aws:kms:eu-central-1::key/%s" % KEY,
        "arn:aws:kms:eu-central-1:%s:key/" % ACCOUNT,
        "arn:aws:kms:eu-central-1:%s:%s" % (ACCOUNT, KEY),
    ],
)
def test_regression_resource_policy_refuses_wrong_arn_shape(arn):
    with pytest.raises(ValueError):
        _handler()({"ResourceArn": arn}, None)
