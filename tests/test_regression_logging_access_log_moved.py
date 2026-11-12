"""regression: the central bucket's access logging resource gained a count.

An earlier release addressed aws_s3_bucket_logging.central_logs without an
index. With enable_separate_access_logs_bucket = true and no moved block, the
next plan destroys the old address and creates central_logs[0]: two calls in
no fixed order on the same bucket, which can leave access logging off. The
moved block maps the old address to [0]. With the switch false the
self-logging resource is removed on purpose (count 0).
"""

import re
from pathlib import Path

S3_CENTRAL_TF = Path(__file__).resolve().parents[1] / "modules/logging/s3-central.tf"
MOVED = re.compile(r'moved\s*\{\s*from\s*=\s*(\S+)\s*to\s*=\s*(\S+)\s*\}')


def test_unindexed_access_logging_moves_to_index_zero():
    moved = dict(MOVED.findall(S3_CENTRAL_TF.read_text(encoding="utf-8")))
    assert moved.get("aws_s3_bucket_logging.central_logs") == "aws_s3_bucket_logging.central_logs[0]"
