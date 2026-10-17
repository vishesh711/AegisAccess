"""Create the external audit bucket (object lock + versioning) and its least-privilege bucket policy.

Idempotent; run by `make seed`. Uses the sink's ROOT credentials (DUMMY local defaults), which only this
setup step holds: the shipper may add and read objects, the auditor may only read. Nobody gets delete,
policy, lock-configuration or versioning permissions; COMPLIANCE retention on each object (set by the
shipper) blocks deletion even for root.
"""

from __future__ import annotations

import json
import os
import sys

from botocore.exceptions import ClientError

from aegis.audit_sink import SinkSettings, s3_client

ROOT = SinkSettings(
    endpoint=os.environ.get("AEGIS_AUDIT_SINK_URL", "http://127.0.0.1:7070"),
    access_key=os.environ.get("AUDIT_SINK_ROOT_ACCESS_KEY", "dummy-sink-root"),
    secret_key=os.environ.get("AUDIT_SINK_ROOT_SECRET_KEY", "dummy-sink-root-secret"),
    bucket=os.environ.get("AEGIS_AUDIT_SINK_BUCKET", "aegis-audit"),
)
SHIPPER = os.environ.get("AUDIT_SINK_SHIPPER_ACCESS_KEY", "aegis-shipper")
AUDITOR = os.environ.get("AUDIT_SINK_AUDITOR_ACCESS_KEY", "aegis-auditor")


def policy(bucket: str) -> str:
    resources = [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ShipperAppendOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": [SHIPPER]},
                    "Action": ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject", "s3:ListBucket"],
                    "Resource": resources,
                },
                {
                    "Sid": "AuditorReadOnly",
                    "Effect": "Allow",
                    "Principal": {"AWS": [AUDITOR]},
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:GetObjectRetention",
                        "s3:ListBucket",
                        "s3:ListBucketVersions",
                    ],
                    "Resource": resources,
                },
            ],
        }
    )


def main() -> int:
    s3 = s3_client(ROOT)
    try:
        s3.create_bucket(Bucket=ROOT.bucket, ObjectLockEnabledForBucket=True)
        print(f"created bucket {ROOT.bucket} with object lock")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {
            "BucketAlreadyOwnedByYou",
            "BucketAlreadyExists",
        }:
            raise
    lock = s3.get_object_lock_configuration(Bucket=ROOT.bucket)["ObjectLockConfiguration"]
    versioning = s3.get_bucket_versioning(Bucket=ROOT.bucket).get("Status")
    if lock.get("ObjectLockEnabled") != "Enabled" or versioning != "Enabled":
        print(f"ERROR: bucket {ROOT.bucket} lacks object lock or versioning; recreate the sink volume")
        return 2
    s3.put_bucket_policy(Bucket=ROOT.bucket, Policy=policy(ROOT.bucket))
    print(
        f"audit sink ready: bucket={ROOT.bucket} object_lock=Enabled versioning=Enabled policy=least-privilege"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
