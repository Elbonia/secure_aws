#!/usr/bin/env python3
"""
Find and delete KMS keys that are no longer attached to any S3 bucket.

This script is a companion to the SecureAuditedS3Bucket CDK construct. It scans
KMS key aliases that match the construct's naming convention and schedules deletion
of any key whose corresponding S3 bucket no longer exists. Run it after a stack
teardown to catch keys left behind when a bucket was deleted outside of CDK, or
when a stack destroy failed partway through.

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
       kms:ListAliases, kms:DescribeKey, kms:ScheduleKeyDeletion
       s3:HeadBucket

HOW IT WORKS
------------
The construct creates KMS keys with aliases that encode the bucket name:

    alias/s3/<bucket-name>          — data bucket key
    alias/s3-audit/<bucket-name>    — audit bucket key

The script lists all aliases matching these prefixes, derives the bucket name
from the alias, and checks whether that bucket still exists. If the bucket is
gone, the key is orphaned and will be scheduled for deletion.

USAGE
-----
    python scripts/cleanup_orphaned_keys.py [options]

OPTIONS
-------
    --dry-run       Print what would be deleted without making any changes.
                    Always run this first to review before committing.

    --pending-days N
                    KMS pending-deletion window in days (7–30, default: 7).
                    The key is disabled immediately but permanently deleted
                    after this window. Cancel with:
                        aws kms cancel-key-deletion --key-id <key-id>

    --include-unaliased
                    Also schedule deletion of customer-managed keys that have
                    no alias at all. Keys without an alias are almost certainly
                    abandoned (any active service would have tagged them with an
                    alias). Use --dry-run first to review before committing.

EXAMPLES
--------
    # Preview orphaned keys without deleting anything:
    python scripts/cleanup_orphaned_keys.py --dry-run

    # Delete orphaned keys with the minimum 7-day pending window:
    python scripts/cleanup_orphaned_keys.py

    # Delete with a 30-day window for extra safety:
    python scripts/cleanup_orphaned_keys.py --pending-days 30

    # Also catch keys that have no alias at all:
    python scripts/cleanup_orphaned_keys.py --include-unaliased --dry-run
    python scripts/cleanup_orphaned_keys.py --include-unaliased

KMS DELETION NOTE
-----------------
AWS enforces a mandatory pending-deletion window (minimum 7 days). The key is
disabled immediately but not permanently deleted until the window expires.
To cancel a scheduled deletion:
    aws kms cancel-key-deletion --key-id <key-id>
"""

import argparse
import sys
import boto3
from botocore.exceptions import ClientError


# Alias prefixes used by the SecureAuditedS3Bucket construct (see kms.py)
WATCHED_ALIAS_PREFIXES = ("alias/s3/", "alias/s3-audit/")

DEFAULT_PENDING_DAYS = 7


def get_client(service: str):
    return boto3.client(service)


def bucket_exists(s3, bucket_name: str) -> bool:
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("404", "NoSuchBucket", "403"):
            # 403 means the bucket exists but we don't own it — treat as absent
            # so we don't delete keys for buckets that belong to someone else.
            return code == "403"
        raise


def iter_construct_aliases(kms_client) -> list[dict]:
    """Yield all KMS aliases that match the construct's naming convention."""
    paginator = kms_client.get_paginator("list_aliases")
    results = []
    for page in paginator.paginate():
        for alias in page["Aliases"]:
            name = alias.get("AliasName", "")
            if any(name.startswith(prefix) for prefix in WATCHED_ALIAS_PREFIXES):
                results.append(alias)
    return results


def bucket_name_from_alias(alias_name: str) -> str:
    """Derive the S3 bucket name encoded in a KMS alias."""
    for prefix in WATCHED_ALIAS_PREFIXES:
        if alias_name.startswith(prefix):
            return alias_name[len(prefix):]
    return ""


def key_is_deletable(kms_client, key_id: str) -> tuple[bool, str]:
    """Return (deletable, reason). Keys already pending deletion are skipped."""
    try:
        meta = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
    except ClientError as e:
        return False, f"could not describe key: {e}"

    state = meta["KeyState"]
    if state == "PendingDeletion":
        return False, "already pending deletion"
    if state in ("Disabled", "Unavailable"):
        return False, f"key state is {state}"
    if meta.get("KeyManager") != "CUSTOMER":
        return False, "not a customer-managed key"
    return True, ""


def iter_aliased_key_ids(kms_client) -> set[str]:
    """Return the set of all key IDs that have at least one alias."""
    paginator = kms_client.get_paginator("list_aliases")
    ids = set()
    for page in paginator.paginate():
        for alias in page["Aliases"]:
            target = alias.get("TargetKeyId")
            if target:
                ids.add(target)
    return ids


def iter_unaliased_customer_keys(kms_client) -> list[str]:
    """Return key IDs of enabled customer-managed keys that have no alias."""
    aliased = iter_aliased_key_ids(kms_client)
    paginator = kms_client.get_paginator("list_keys")
    results = []
    for page in paginator.paginate():
        for entry in page["Keys"]:
            key_id = entry["KeyId"]
            if key_id in aliased:
                continue
            try:
                meta = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError:
                continue
            if (
                meta.get("KeyManager") == "CUSTOMER"
                and meta.get("KeyState") == "Enabled"
            ):
                results.append(key_id)
    return results


def schedule_deletion(kms_client, key_id: str, pending_days: int, dry_run: bool) -> None:
    print(f"    Scheduling deletion (pending {pending_days} days): {key_id}")
    if not dry_run:
        kms_client.schedule_key_deletion(
            KeyId=key_id,
            PendingWindowInDays=pending_days,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without making any changes",
    )
    parser.add_argument(
        "--pending-days",
        type=int,
        default=DEFAULT_PENDING_DAYS,
        metavar="N",
        help=f"KMS pending-deletion window in days (7–30, default: {DEFAULT_PENDING_DAYS})",
    )
    parser.add_argument(
        "--include-unaliased",
        action="store_true",
        help="Also schedule deletion of customer-managed keys with no alias",
    )
    args = parser.parse_args()

    if not 7 <= args.pending_days <= 30:
        print("ERROR: --pending-days must be between 7 and 30", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        print("DRY RUN — no changes will be made\n")

    s3 = get_client("s3")
    kms_client = get_client("kms")

    print("Scanning KMS aliases for construct-managed keys...")
    aliases = iter_construct_aliases(kms_client)

    if not aliases:
        print("No matching KMS aliases found.")
    else:
        print(f"Found {len(aliases)} construct-managed key(s). Checking bucket status...\n")

    orphaned = 0
    skipped = 0

    for alias in aliases:
        alias_name = alias["AliasName"]
        key_id = alias.get("TargetKeyId")

        if not key_id:
            print(f"  {alias_name}: no target key, skipping")
            skipped += 1
            continue

        bucket_name = bucket_name_from_alias(alias_name)
        bucket_alive = bucket_exists(s3, bucket_name)

        if bucket_alive:
            print(f"  {alias_name}: bucket '{bucket_name}' exists — key is in use, skipping")
            skipped += 1
            continue

        # Bucket is gone — key is orphaned
        deletable, reason = key_is_deletable(kms_client, key_id)
        if not deletable:
            print(f"  {alias_name}: bucket gone but key not deletable ({reason}), skipping")
            skipped += 1
            continue

        print(f"  {alias_name}: bucket '{bucket_name}' does not exist — orphaned key")
        schedule_deletion(kms_client, key_id, args.pending_days, args.dry_run)
        orphaned += 1

    # Second pass: alias-less customer keys
    if args.include_unaliased:
        print("\nScanning for customer-managed keys with no alias...")
        unaliased = iter_unaliased_customer_keys(kms_client)

        if not unaliased:
            print("No unaliased customer-managed keys found.")
        else:
            print(f"Found {len(unaliased)} unaliased key(s).\n")
            for key_id in unaliased:
                deletable, reason = key_is_deletable(kms_client, key_id)
                if not deletable:
                    print(f"  {key_id}: not deletable ({reason}), skipping")
                    skipped += 1
                    continue
                print(f"  {key_id}: no alias — orphaned key")
                schedule_deletion(kms_client, key_id, args.pending_days, args.dry_run)
                orphaned += 1

    print(f"\nDone. {orphaned} key(s) scheduled for deletion, {skipped} skipped.")


if __name__ == "__main__":
    main()
