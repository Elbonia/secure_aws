from constructs import Construct
from aws_cdk import (
    Stack,
    Duration,
    aws_kms as kms,
    aws_iam as iam,
)
from typing import Sequence

from .props import SecureKmsKeyProps


class SecureKmsKey(Construct):
    """
    A hardened KMS key with automatic rotation and scoped service grants.

    Creates a customer-managed KMS key with:
    - Automatic key rotation (configurable period, default 90 days)
    - 7-day pending deletion window
    - Named alias for console visibility
    - Optional per-service policy grants via grant_s3_bucket() and grant_cloudwatch_logs()

    This construct is service-agnostic and can be used standalone or composed
    into higher-level constructs such as SecureAuditedS3Bucket.

    Usage::

        key = SecureKmsKey(self, "AppKey", SecureKmsKeyProps(alias="my-service/prod"))
        key.grant_cloudwatch_logs(["/aws/lambda/my-function"])
    """

    def __init__(self, scope: Construct, id: str, props: SecureKmsKeyProps) -> None:
        super().__init__(scope, id)

        self._key = kms.Key(
            self,
            "key",
            description=props.description or f"Secure KMS key: alias/{props.alias}",
            enable_key_rotation=props.rotation_enabled,
            pending_window=Duration.days(7),
            removal_policy=props.removal_policy,
        )

        if props.rotation_enabled:
            self._apply_rotation_period(props.rotation_period_days)

        kms.Alias(
            self,
            "alias",
            alias_name=f"alias/{props.alias}",
            target_key=self._key,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def key(self) -> kms.Key:
        return self._key

    @property
    def key_id(self) -> str:
        return self._key.key_id

    @property
    def key_arn(self) -> str:
        return self._key.key_arn

    def grant_s3_bucket(self, bucket_name: str) -> None:
        """Allow S3 to use this key, scoped to a single named bucket."""
        stack = Stack.of(self)
        bucket_arn = f"arn:{stack.partition}:s3:::{bucket_name}"
        self._key.add_to_resource_policy(
            iam.PolicyStatement(
                sid=f"AllowS3ForBucket{_sid_safe(bucket_name)}",
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

    def grant_cloudwatch_logs(self, log_group_names: Sequence[str]) -> None:
        """Allow CloudWatch Logs to use this key for the given log groups.

        Uses ArnLike on the encryption context ARN rather than kms:ViaService
        because CloudWatch Logs calls KMS directly (service-to-service) and does
        not set kms:ViaService in the request context.
        """
        if not log_group_names:
            return

        stack = Stack.of(self)
        # CloudWatch Logs calls KMS directly as the service principal, not on
        # behalf of an IAM principal, so kms:ViaService is NOT set. Scope using
        # ArnLike on the encryption context ARN with a wildcard so CloudFormation
        # never needs to embed an Fn::Join token inside a condition value.
        arn_pattern = f"arn:aws:logs:{stack.region}:{stack.account}:log-group:*"
        region = stack.region
        self._key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogs",
                principals=[iam.ServicePrincipal(f"logs.{region}.amazonaws.com")],
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
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": arn_pattern,
                    },
                },
            )
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_rotation_period(self, rotation_period_days: int) -> None:
        if rotation_period_days == 365:
            return
        cfn_key = getattr(self._key.node, "default_child", None)
        if cfn_key is None:
            return
        add_override = getattr(cfn_key, "add_property_override", None)
        if callable(add_override):
            add_override("RotationPeriodInDays", rotation_period_days)


def _sid_safe(name: str) -> str:
    """Strip characters that are invalid in a KMS policy Sid."""
    return "".join(c for c in name if c.isalnum())
