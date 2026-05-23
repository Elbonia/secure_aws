#!/usr/bin/env python3
"""
Delete an S3 bucket and its associated KMS key.

This script is a companion to the SecureAuditedS3Bucket CDK construct. It handles
manual teardown of buckets whose CloudFormation stack has already been destroyed
(or whose removal policy was RETAIN), as well as buckets that failed deletion because
they were not empty.

PREREQUISITES
-------------
1. Install dependencies:
       pip install boto3
   or, from the project root:
       pip install -r requirements.txt

2. Configure AWS credentials. Any of the following work:
   - AWS CLI profile:   export AWS_PROFILE=my-profile
   - Environment vars:  export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=...
   - IAM role:          automatically picked up on EC2/ECS/Lambda

   The caller needs the following IAM permissions:
       s3:HeadBucket, s3:ListBucketVersions, s3:DeleteObjects, s3:DeleteBucket
       kms:ListAliases, kms:DescribeKey, kms:ScheduleKeyDeletion

USAGE
-----
    python scripts/delete_bucket.py <bucket-name> [options]

OPTIONS
-------
    --empty     Delete all objects and versions inside the bucket before
                deleting it. Without this flag the script exits with an error
                if the bucket is not empty, leaving your data intact.

    --audit     Also delete the paired audit bucket (named <bucket>-audit)
                and its KMS key. If you used a custom audit_bucket_name in
                your CDK props, run the script a second time with that name
                instead of using this flag.

    --dry-run   Print every action that would be taken without making any
                changes to AWS. Use this to verify the correct buckets and
                keys will be targeted before committing.

EXAMPLES
--------
    # Delete an empty bucket and its KMS key:
    python scripts/delete_bucket.py my-bucket

    # Preview what would be deleted (no changes made):
    python scripts/delete_bucket.py my-bucket --empty --audit --dry-run

    # Empty the bucket first, then delete it and its KMS key:
    python scripts/delete_bucket.py my-bucket --empty

    # Delete both the data bucket and its paired audit bucket:
    python scripts/delete_bucket.py my-bucket --audit

    # Full teardown — empty and delete both buckets and both KMS keys:
    python scripts/delete_bucket.py my-bucket --empty --audit

KMS DELETION NOTE
-----------------
AWS enforces a mandatory pending-deletion window for KMS keys (minimum 7 days).
The key is disabled immediately but not permanently deleted until the window
expires. During this window you can cancel the deletion via the AWS Console or:
    aws kms cancel-key-deletion --key-id <key-id>
"""

import argparse
import sys
import boto3
from botocore.exceptions import ClientError


KMS_PENDING_WINDOW_DAYS = 7


def get_client(service: str):
    return boto3.client(service)


def bucket_exists(s3, bucket_name: str) -> bool:
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchBucket"):
            return False
        raise


def empty_bucket(s3, bucket_name: str, dry_run: bool) -> None:
    """Delete all objects and all versions from a bucket."""
    paginator = s3.get_paginator("list_object_versions")
    to_delete = []

    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Versions", []):
            to_delete.append({"Key": obj["Key"], "VersionId": obj["VersionId"]})
        for marker in page.get("DeleteMarkers", []):
            to_delete.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})

    if not to_delete:
        print(f"  {bucket_name}: bucket is already empty")
        return

    print(f"  {bucket_name}: deleting {len(to_delete)} object version(s)")
    if dry_run:
        return

    # Delete in batches of 1000 (S3 API limit)
    for i in range(0, len(to_delete), 1000):
        batch = to_delete[i : i + 1000]
        s3.delete_objects(Bucket=bucket_name, Delete={"Objects": batch, "Quiet": True})


def delete_bucket(s3, bucket_name: str, dry_run: bool) -> None:
    print(f"  Deleting bucket: {bucket_name}")
    if not dry_run:
        s3.delete_bucket(Bucket=bucket_name)


def find_kms_key_for_alias(kms_client, alias: str) -> str | None:
    """Return the key ARN for a given alias, or None if not found."""
    paginator = kms_client.get_paginator("list_aliases")
    for page in paginator.paginate():
        for a in page["Aliases"]:
            if a["AliasName"] == alias and "TargetKeyId" in a:
                key_meta = kms_client.describe_key(KeyId=a["TargetKeyId"])["KeyMetadata"]
                if key_meta["KeyState"] not in ("PendingDeletion", "Disabled"):
                    return key_meta["KeyArn"]
    return None


def schedule_key_deletion(kms_client, key_arn: str, dry_run: bool) -> None:
    print(f"  Scheduling KMS key deletion (pending {KMS_PENDING_WINDOW_DAYS} days): {key_arn}")
    if not dry_run:
        kms_client.schedule_key_deletion(
            KeyId=key_arn,
            PendingWindowInDays=KMS_PENDING_WINDOW_DAYS,
        )


def process_bucket(
    s3,
    kms_client,
    bucket_name: str,
    key_alias: str,
    empty: bool,
    dry_run: bool,
) -> None:
    print(f"\nProcessing: {bucket_name}")

    if not bucket_exists(s3, bucket_name):
        print(f"  Bucket not found, skipping: {bucket_name}")
        return

    if empty:
        empty_bucket(s3, bucket_name, dry_run)

    try:
        delete_bucket(s3, bucket_name, dry_run)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "BucketNotEmpty":
            print(
                f"  ERROR: {bucket_name} is not empty. Re-run with --empty to delete its contents first.",
                file=sys.stderr,
            )
            sys.exit(1)
        raise

    key_arn = find_kms_key_for_alias(kms_client, key_alias)
    if key_arn:
        schedule_key_deletion(kms_client, key_arn, dry_run)
    else:
        print(f"  No active KMS key found for alias '{key_alias}', skipping")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bucket_name", help="Name of the S3 bucket to delete")
    parser.add_argument("--empty", action="store_true", help="Delete all objects before deleting the bucket")
    parser.add_argument("--audit", action="store_true", help="Also delete the paired audit bucket and its KMS key")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing them")
    args = parser.parse_args()

    if args.dry_run:
        print("DRY RUN — no changes will be made\n")

    s3 = get_client("s3")
    kms_client = get_client("kms")

    # Data bucket: alias matches the pattern used by KMSKeyManager.create_s3_key()
    process_bucket(
        s3,
        kms_client,
        bucket_name=args.bucket_name,
        key_alias=f"alias/s3/{args.bucket_name}",
        empty=args.empty,
        dry_run=args.dry_run,
    )

    if args.audit:
        # Audit bucket name and alias match the patterns in bucket.py / kms.py
        audit_bucket_name = f"{args.bucket_name}-audit"
        process_bucket(
            s3,
            kms_client,
            bucket_name=audit_bucket_name,
            key_alias=f"alias/s3-audit/{audit_bucket_name}",
            empty=args.empty,
            dry_run=args.dry_run,
        )

    print("\nDone.")


if __name__ == "__main__":
    main()
