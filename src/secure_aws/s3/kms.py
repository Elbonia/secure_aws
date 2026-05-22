from constructs import Construct
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_kms as kms,
    aws_iam as iam,
)
from typing import Optional, Sequence
from .props import KMSProps


class KMSKeyManager:
    """Manages KMS key creation and configuration for S3 encryption."""

    @staticmethod
    def _apply_rotation_period_if_supported(
        key: kms.Key,
        rotation_period_days: int,
    ) -> None:
        """Apply custom KMS key rotation period (365 days is AWS default, skipped for efficiency)."""
        if rotation_period_days == 365:
            return

        cfn_key = getattr(key.node, "default_child", None)
        if cfn_key is None:
            return

        # Use add_property_override (the official CDK method) to apply custom rotation period
        add_property_override = getattr(cfn_key, "add_property_override", None)
        if callable(add_property_override):
            add_property_override("RotationPeriodInDays", rotation_period_days)
            return

    @staticmethod
    def _s3_bucket_arn(scope: Construct, bucket_name: str) -> str:
        stack = Stack.of(scope)
        return f"arn:{stack.partition}:s3:::{bucket_name}"

    @staticmethod
    def _logs_service_principal(scope: Construct) -> iam.ServicePrincipal:
        region = Stack.of(scope).region
        return iam.ServicePrincipal(f"logs.{region}.amazonaws.com")

    @staticmethod
    def _log_group_arn(scope: Construct, log_group_name: str) -> str:
        stack = Stack.of(scope)
        return (
            f"arn:{stack.partition}:logs:{stack.region}:{stack.account}:"
            f"log-group:{log_group_name}"
        )

    @staticmethod
    def _add_scoped_s3_permissions(
        key: kms.Key,
        scope: Construct,
        bucket_name: str,
    ) -> None:
        stack = Stack.of(scope)
        bucket_arn = KMSKeyManager._s3_bucket_arn(scope, bucket_name)
        key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowS3ForBucketOnly",
                principals=[iam.ServicePrincipal("s3.amazonaws.com")],
                actions=["kms:Decrypt", "kms:GenerateDataKey"],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:SourceAccount": stack.account,
                        "kms:ViaService": f"s3.{stack.region}.amazonaws.com",
                    },
                    "ArnLike": {
                        "aws:SourceArn": bucket_arn,
                    },
                },
            )
        )

    @staticmethod
    def _add_scoped_logs_permissions(
        key: kms.Key,
        scope: Construct,
        log_group_names: Sequence[str],
    ) -> None:
        if not log_group_names:
            return

        stack = Stack.of(scope)
        log_group_arns = [
            KMSKeyManager._log_group_arn(scope, log_group_name)
            for log_group_name in log_group_names
        ]
        key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsForConstructLogGroups",
                principals=[KMSKeyManager._logs_service_principal(scope)],
                actions=[
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:CreateGrant",
                    "kms:DescribeKey",
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:SourceAccount": stack.account,
                        "kms:ViaService": f"logs.{stack.region}.amazonaws.com",
                    },
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": log_group_arns,
                    },
                },
            )
        )

    @staticmethod
    def create_s3_key(
        scope: Construct,
        id: str,
        props: KMSProps,
        bucket_name: str,
        enable_key_policy_audit_logging: bool = True,
    ) -> Optional[kms.Key]:
        """Create a KMS key for S3 bucket encryption with scoped permissions.

        The key policy is configured to allow only S3 and CloudWatch Logs services
        to use the key for the specific bucket and log groups.
        """
        if not props.enable_kms:
            return None

        key_description = f"KMS key for S3 bucket: {bucket_name}"
        key_alias = props.key_alias_prefix or f"s3/{bucket_name}"

        # Create KMS key with automatic rotation and 7-day deletion window
        key = kms.Key(
            scope,
            id,
            description=key_description,
            enable_key_rotation=props.key_rotation_enabled,
            pending_window=Duration.days(7),
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Apply custom rotation period if specified (AWS default is 365 days)
        if props.key_rotation_enabled:
            KMSKeyManager._apply_rotation_period_if_supported(
                key,
                props.key_rotation_period_days,
            )

        # Create user-friendly key alias for AWS Console access
        kms.Alias(
            scope,
            f"{id}-alias",
            alias_name=f"alias/{key_alias}",
            target_key=key,
        )

        # Grant S3 service access scoped to this specific bucket
        KMSKeyManager._add_scoped_s3_permissions(key, scope, bucket_name)

        # Grant CloudWatch Logs access for S3 access logs and CloudTrail events
        KMSKeyManager._add_scoped_logs_permissions(
            key,
            scope,
            [
                f"/aws/s3/{bucket_name}",
                f"/aws/cloudtrail/{bucket_name}",
            ],
        )

        return key

    @staticmethod
    def create_audit_bucket_key(
        scope: Construct,
        id: str,
        props: KMSProps,
        audit_bucket_name: str,
    ) -> Optional[kms.Key]:
        """Create a separate KMS key for the audit bucket.

        Audit buckets use their own dedicated key to maintain a clear separation
        between data encryption and audit trail encryption.
        """
        if not props.enable_kms:
            return None

        key_description = f"KMS key for S3 audit bucket: {audit_bucket_name}"
        key_alias = f"s3-audit/{audit_bucket_name}"

        # Create KMS key with automatic rotation and 7-day deletion window
        key = kms.Key(
            scope,
            id,
            description=key_description,
            enable_key_rotation=props.key_rotation_enabled,
            pending_window=Duration.days(7),
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Apply custom rotation period if specified (AWS default is 365 days)
        if props.key_rotation_enabled:
            KMSKeyManager._apply_rotation_period_if_supported(
                key,
                props.key_rotation_period_days,
            )

        # Create user-friendly key alias for AWS Console access
        kms.Alias(
            scope,
            f"{id}-alias",
            alias_name=f"alias/{key_alias}",
            target_key=key,
        )

        # Grant S3 logging service access to audit bucket
        KMSKeyManager._add_scoped_s3_permissions(key, scope, audit_bucket_name)

        # Grant CloudWatch Logs access for audit bucket logs
        KMSKeyManager._add_scoped_logs_permissions(
            key,
            scope,
            [f"/aws/s3/audit/{audit_bucket_name}"],
        )

        return key
