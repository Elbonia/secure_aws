from constructs import Construct
from aws_cdk import RemovalPolicy, aws_kms as kms
from typing import Optional

from .props import KMSProps
from ..kms import SecureKmsKey, SecureKmsKeyProps


class KMSKeyManager:
    """Creates KMS keys for S3 buckets using the SecureKmsKey construct."""

    @staticmethod
    def create_s3_key(
        scope: Construct,
        id: str,
        props: KMSProps,
        bucket_name: str,
        removal_policy: RemovalPolicy = RemovalPolicy.DESTROY,
    ) -> Optional[kms.Key]:
        if not props.enable_kms:
            return None

        alias = props.key_alias_prefix or f"s3/{bucket_name}"
        secure_key = SecureKmsKey(
            scope,
            id,
            SecureKmsKeyProps(
                alias=alias,
                rotation_enabled=props.key_rotation_enabled,
                rotation_period_days=props.key_rotation_period_days,
                description=f"KMS key for S3 bucket: {bucket_name}",
                removal_policy=removal_policy,
            ),
        )
        secure_key.grant_s3_bucket(bucket_name)
        secure_key.grant_cloudwatch_logs([
            f"/aws/s3/{bucket_name}",
            f"/aws/cloudtrail/{bucket_name}",
        ])
        return secure_key.key

    @staticmethod
    def create_audit_bucket_key(
        scope: Construct,
        id: str,
        props: KMSProps,
        audit_bucket_name: str,
        removal_policy: RemovalPolicy = RemovalPolicy.DESTROY,
    ) -> Optional[kms.Key]:
        if not props.enable_kms:
            return None

        secure_key = SecureKmsKey(
            scope,
            id,
            SecureKmsKeyProps(
                alias=f"s3-audit/{audit_bucket_name}",
                rotation_enabled=props.key_rotation_enabled,
                rotation_period_days=props.key_rotation_period_days,
                description=f"KMS key for S3 audit bucket: {audit_bucket_name}",
                removal_policy=removal_policy,
            ),
        )
        secure_key.grant_s3_bucket(audit_bucket_name)
        secure_key.grant_cloudwatch_logs([f"/aws/s3/audit/{audit_bucket_name}"])
        return secure_key.key
